from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run
from phase_tool.installation import Installation
from phase_tool.mutation.guarantees import registered_profile_binding
from phase_tool.mutation.platform import HostAuthorityProvider
from phase_tool.registry import BundledRegistry

NOW = "2026-07-27T00:00:00Z"
ROOT = Path(__file__).resolve().parents[1]


def test_core_operational_lock_timeout_and_unlock_error_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fcntl
    import phase_tool.core as core_module

    path = tmp_path / "locks" / "idempotency.lock"
    holder = core_module._OperationalFileLock(path)
    holder.__enter__()
    descriptor_count = len(os.listdir("/proc/self/fd"))
    try:
        with pytest.raises(PhaseError, match="lock.acquire_timeout"):
            core_module._OperationalFileLock(path).__enter__()
        assert len(os.listdir("/proc/self/fd")) == descriptor_count
    finally:
        original_flock = fcntl.flock

        def fail_unlock(descriptor: int, operation: int) -> None:
            if operation == fcntl.LOCK_UN:
                raise OSError("unlock failed")
            original_flock(descriptor, operation)

        monkeypatch.setattr(fcntl, "flock", fail_unlock)
        holder.__exit__(None, None, None)
    assert len(os.listdir("/proc/self/fd")) == descriptor_count - 1


def exact(contract_id: str) -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()[f"{contract_id}@1.0.0"]


def tree_digest(root: Path) -> str:
    entries: list[dict[str, str | int]] = []
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(root).as_posix()):
        data = path.read_bytes()
        entries.append({"path": path.relative_to(root).as_posix(), "length": len(data), "digest": digest_bytes(data)})
    return digest_bytes(canonical_bytes(entries))


def write_append(path: Path, *, key: str = "key-1", value: int = 1) -> None:
    path.write_text(json.dumps({
        "stream_id": "alpha",
        "target_locator": "streams/alpha.jsonl",
        "record_id": "record-1",
        "expected_head": None,
        "record": {"value": value},
        "idempotency_key": key,
    }), encoding="utf-8")


def write_copy(path: Path, *, key: str = "copy-key-1") -> None:
    path.write_text(json.dumps({
        "transfer_id": "transfer-1",
        "object_id": "object-1",
        "input_binding": "payload",
        "destinations": ["objects/b", "objects/a"],
        "idempotency_key": key,
    }), encoding="utf-8")


def request(
    contract_id: str,
    candidate: Path,
    evidence: Path,
    target: Path,
    run_id: str,
    *,
    inputs: dict[str, Path] | None = None,
) -> PhaseRequest:
    binding = exact(contract_id)
    return PhaseRequest(
        contract_id=contract_id,
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths=inputs or {},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )


class _BoundaryTestInstallation(Installation):
    def qualify_authority_roots(self, root_bindings: dict[str, Path]) -> None:
        pass


def boundary_test_installation() -> Installation:
    return _BoundaryTestInstallation(
        authority_provider=HostAuthorityProvider(),
        authority_profile_binding=registered_profile_binding("phase.posix.authority.v1@1.0.0"),
    )


class _DisappearingRootInstallation(_BoundaryTestInstallation):
    def qualify_authority_roots(self, root_bindings: dict[str, Path]) -> None:
        next(iter(root_bindings.values())).rmdir()


def disappearing_root_installation() -> Installation:
    return _DisappearingRootInstallation(
        authority_provider=HostAuthorityProvider(),
        authority_profile_binding=registered_profile_binding("phase.posix.authority.v1@1.0.0"),
    )


def test_append_and_copy_share_one_core_lifecycle_and_do_not_mutate_targets(tmp_path: Path) -> None:
    core = PhaseCore()

    append_target = tmp_path / "append-target"
    append_target.mkdir()
    (append_target / "sentinel").write_bytes(b"unchanged")
    append_candidate = tmp_path / "append.json"
    write_append(append_candidate)
    append_before = tree_digest(append_target)
    append_outcome = core.run(request("fixture_append.v1", append_candidate, tmp_path / "append-evidence", append_target, "append-run"))
    assert append_outcome.exit_code == 0
    assert tree_digest(append_target) == append_before

    copy_target = tmp_path / "copy-target"
    copy_target.mkdir()
    (copy_target / "objects").mkdir()
    (copy_target / "sentinel").write_bytes(b"unchanged")
    copy_candidate = tmp_path / "copy.json"
    write_copy(copy_candidate)
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    payload = input_root / "payload.bin"
    payload.write_bytes(b"payload")
    copy_before = tree_digest(copy_target)
    copy_outcome = core.run(request("fixture_copy.v1", copy_candidate, tmp_path / "copy-evidence", copy_target, "copy-run", inputs={"payload": payload}))
    assert copy_outcome.exit_code == 0
    assert tree_digest(copy_target) == copy_before

    assert append_outcome.lifecycle == copy_outcome.lifecycle == (
        "resolve",
        "guarantees",
        "capture",
        "freeze",
        "validate",
        "plan",
        "intent",
        "receipt",
    )
    assert append_outcome.receipt["terminal_status"] == copy_outcome.receipt["terminal_status"] == "validated_planned"
    assert append_outcome.receipt["mutation_attempted"] is copy_outcome.receipt["mutation_attempted"] is False
    assert append_outcome.receipt["canonical_result"] is copy_outcome.receipt["canonical_result"] is None
    copy_inspection = inspect_run(tmp_path / "copy-evidence", "copy-run")
    assert copy_inspection["effect_plan_digest"] == copy_outcome.effect_plan_digest


def test_evidence_is_schema_valid_deterministic_and_has_no_domain_result(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    first = PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence-a", target, "same-run"))
    second = PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence-b", target, "same-run"))
    assert first.exit_code == second.exit_code == 0
    first_run = tmp_path / "evidence-a" / ".phase" / "runs" / "same-run"
    second_run = tmp_path / "evidence-b" / ".phase" / "runs" / "same-run"
    for relative in ("intent.json", "receipt.json", "attachments/effect-plan.json", "attachments/validator-results.json"):
        assert (first_run / relative).read_bytes() == (second_run / relative).read_bytes()
    assert not list(first_run.glob("*result*"))
    assert set(item.name for item in first_run.iterdir()) == {"intent.json", "receipt.json", "blobs", "attachments"}


def test_early_invalid_candidate_writes_truthful_rejection_receipt(tmp_path: Path) -> None:
    candidate = tmp_path / "invalid.json"
    candidate.write_text('{"stream_id":"alpha"}', encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    outcome = PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence", target, "rejected-run"))
    run_root = tmp_path / "evidence" / ".phase" / "runs" / "rejected-run"
    assert outcome.exit_code != 0
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["evidence"]["intent_digest"] is None
    assert not (run_root / "intent.json").exists()
    assert (run_root / "receipt.json").is_file()


def test_missing_candidate_is_a_stable_pre_mutation_rejection(tmp_path: Path) -> None:
    candidate = tmp_path / "missing-candidate.json"
    target = tmp_path / "target"
    target.mkdir()
    (target / "sentinel").write_bytes(b"unchanged")
    evidence = tmp_path / "evidence"

    response = PhaseApplication(installation=boundary_test_installation()).run(
        "execute",
        contract_binding="fixture_create.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="missing-candidate-rejection",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    schema = BundledRegistry.load().schema_document(
        "https://phase-tool.local/schemas/stage3-command-result.schema.json"
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(response.payload)
    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "candidate.input_unavailable"
    assert response.payload["error"] != "cli.failure"
    assert response.payload["blockers"] == ["candidate.input_unavailable"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] == "missing-candidate-rejection"
    assert (target / "sentinel").read_bytes() == b"unchanged"
    assert str(candidate) not in serialized
    assert "FileNotFoundError" not in serialized
    assert "No such file or directory" not in serialized
    assert "Errno" not in serialized
    run_root = evidence / ".phase" / "runs" / "missing-candidate-rejection"
    assert sorted(path.name for path in run_root.iterdir()) == ["receipt.json"]
    receipt = json.loads((run_root / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["blockers"] == ["candidate.input_unavailable"]
    assert receipt["execution_disposition"] == "not_executed"
    assert receipt["mutation_attempted"] is False
    assert receipt["evidence"]["intent_digest"] is None


def test_unavailable_declared_input_is_a_stable_pre_mutation_rejection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.json"
    write_copy(candidate)
    payload = tmp_path / "private-payload.bin"
    payload.write_bytes(b"payload")
    target = tmp_path / "target"
    target.mkdir()
    (target / "sentinel").write_bytes(b"unchanged")
    evidence = tmp_path / "evidence"
    original_open = Path.open

    def unavailable_open(path: Path, *args: object, **kwargs: object):
        if path == payload and args and args[0] == "rb":
            raise PermissionError("private host diagnostic")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", unavailable_open)
    response = PhaseApplication(installation=boundary_test_installation()).run(
        "execute",
        contract_binding="fixture_copy.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="unavailable-input-rejection",
        input_paths={"payload": payload},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    schema = BundledRegistry.load().schema_document(
        "https://phase-tool.local/schemas/stage3-command-result.schema.json"
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(response.payload)
    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "freeze.input_unavailable"
    assert response.payload["blockers"] == ["freeze.input_unavailable"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] == "unavailable-input-rejection"
    assert (target / "sentinel").read_bytes() == b"unchanged"
    assert str(payload) not in serialized
    assert "PermissionError" not in serialized
    assert "private host diagnostic" not in serialized
    run_root = evidence / ".phase" / "runs" / "unavailable-input-rejection"
    assert sorted(path.name for path in run_root.iterdir()) == ["receipt.json"]
    receipt = json.loads((run_root / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["blockers"] == ["freeze.input_unavailable"]
    assert receipt["execution_disposition"] == "not_executed"
    assert receipt["mutation_attempted"] is False
    assert receipt["evidence"]["intent_digest"] is None


def test_unavailable_root_during_separation_is_a_stable_pre_initialization_rejection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.json"
    write_copy(candidate)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"payload")
    target = tmp_path / "private-target"
    target.mkdir()
    (target / "sentinel").write_bytes(b"unchanged")
    evidence = tmp_path / "evidence"
    original_resolve = Path.resolve

    def unavailable_resolve(path: Path, *args: object, **kwargs: object) -> Path:
        if path == target:
            raise PermissionError("private root diagnostic")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", unavailable_resolve)
    response = PhaseApplication(installation=boundary_test_installation()).run(
        "execute",
        contract_binding="fixture_copy.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="root-separation-rejection",
        input_paths={"payload": payload},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    schema = BundledRegistry.load().schema_document(
        "https://phase-tool.local/schemas/stage3-command-result.schema.json"
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(response.payload)
    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "evidence.root_separation_failed"
    assert response.payload["blockers"] == ["evidence.root_separation_failed"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] is None
    assert (target / "sentinel").read_bytes() == b"unchanged"
    assert not evidence.exists()
    assert str(target) not in serialized
    assert "PermissionError" not in serialized
    assert "private root diagnostic" not in serialized


def test_regular_file_evidence_root_is_a_stable_pre_mutation_rejection(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "sentinel").write_bytes(b"unchanged")
    evidence = tmp_path / "evidence-file"
    evidence.write_bytes(b"evidence-sentinel")

    response = PhaseApplication(installation=boundary_test_installation()).run(
        "execute",
        contract_binding="fixture_create.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="evidence-file-rejection",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    schema = BundledRegistry.load().schema_document(
        "https://phase-tool.local/schemas/stage3-command-result.schema.json"
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(response.payload)
    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "evidence.initialization_failed"
    assert response.payload["error"] != "cli.failure"
    assert response.payload["blockers"] == ["evidence.initialization_failed"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] is None
    assert (target / "sentinel").read_bytes() == b"unchanged"
    assert evidence.read_bytes() == b"evidence-sentinel"
    assert str(evidence) not in serialized
    assert "FileExistsError" not in serialized
    assert "Not a directory" not in serialized
    assert "Errno" not in serialized


def test_embedded_nul_candidate_path_is_an_input_unavailable_rejection(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "sentinel").write_bytes(b"unchanged")
    evidence = tmp_path / "evidence"

    response = PhaseApplication(installation=boundary_test_installation()).run(
        "validate",
        contract_binding="fixture_append.v1@1.0.0",
        candidate_path=Path("private\0candidate.json"),
        evidence_root=evidence,
        run_id="invalid-candidate-path",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "candidate.input_unavailable"
    assert response.payload["blockers"] == ["candidate.input_unavailable"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] == "invalid-candidate-path"
    assert (target / "sentinel").read_bytes() == b"unchanged"
    assert "private" not in serialized
    assert "ValueError" not in serialized
    assert sorted(path.name for path in (evidence / ".phase" / "runs" / "invalid-candidate-path").iterdir()) == [
        "receipt.json"
    ]


@pytest.mark.parametrize("invalid_binding", ["evidence", "target"])
def test_embedded_nul_root_is_a_stable_separation_rejection(
    invalid_binding: str,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "sentinel").write_bytes(b"unchanged")
    evidence = tmp_path / "evidence"
    invalid_path = Path("private\0root")

    response = PhaseApplication(installation=boundary_test_installation()).run(
        "validate",
        contract_binding="fixture_append.v1@1.0.0",
        candidate={
            "stream_id": "alpha",
            "target_locator": "streams/alpha.jsonl",
            "record_id": "record-1",
            "expected_head": None,
            "record": {"value": 1},
            "idempotency_key": "invalid-root-key",
        },
        evidence_root=invalid_path if invalid_binding == "evidence" else evidence,
        run_id="invalid-root-path",
        input_paths={},
        root_bindings={"fixture_result_root": invalid_path if invalid_binding == "target" else target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "evidence.root_separation_failed"
    assert response.payload["blockers"] == ["evidence.root_separation_failed"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] is None
    assert (target / "sentinel").read_bytes() == b"unchanged"
    assert "private" not in serialized
    assert "ValueError" not in serialized
    assert not evidence.exists()


def test_root_disappearing_after_admission_is_a_stable_planning_rejection(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"

    response = PhaseApplication(installation=disappearing_root_installation()).run(
        "validate",
        contract_binding="fixture_append.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="disappearing-root",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "plan.root_unavailable"
    assert response.payload["blockers"] == ["plan.root_unavailable"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] == "disappearing-root"
    assert "FileNotFoundError" not in serialized
    assert "No such file" not in serialized
    assert sorted(path.name for path in (evidence / ".phase" / "runs" / "disappearing-root").iterdir()) == [
        "receipt.json"
    ]


def test_root_disappearing_before_validation_is_a_stable_rejection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import phase_tool.core as core_module

    candidate = tmp_path / "candidate.json"
    write_append(candidate, key="disappearing-validation-root-key")
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"
    original = core_module.build_idempotency_digests

    def remove_root_after_identity(*args, **kwargs):
        result = original(*args, **kwargs)
        target.rmdir()
        return result

    monkeypatch.setattr(core_module, "build_idempotency_digests", remove_root_after_identity)
    response = PhaseApplication(installation=boundary_test_installation()).run(
        "validate",
        contract_binding="fixture_append.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="disappearing-validation-root",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "validation.target_unavailable"
    assert response.payload["blockers"] == ["validation.target_unavailable"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] == "disappearing-validation-root"
    assert "FileNotFoundError" not in serialized
    assert "No such file" not in serialized
    assert sorted(path.name for path in (evidence / ".phase" / "runs" / "disappearing-validation-root").iterdir()) == [
        "receipt.json"
    ]


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (PermissionError("private target diagnostic"), "validation.observation_unavailable"),
        (ValueError("programmer-side validator defect"), "cli.failure"),
    ],
)
def test_validator_hook_normalizes_only_operational_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: Exception,
    expected_code: str,
) -> None:
    import phase_tool.validation as validation_module

    class FailingHook:
        def run_validator(self, *args, **kwargs):
            raise failure

    monkeypatch.setattr(validation_module, "load_contract_hook", lambda contract: FailingHook())
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"
    response = PhaseApplication(installation=boundary_test_installation()).run(
        "validate",
        contract_binding="fixture_append.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="validator-hook-failure",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == expected_code
    assert response.payload["mutation_attempted"] is False
    assert "private target diagnostic" not in serialized
    assert "programmer-side validator defect" not in serialized


def test_target_inspection_does_not_mask_programmer_value_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import phase_tool.validation as validation_module

    def fail_target_inspection(*args, **kwargs):
        raise ValueError("programmer-side target inspection defect")

    monkeypatch.setattr(validation_module, "inspect_target_path", fail_target_inspection)
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    response = PhaseApplication(installation=boundary_test_installation()).run(
        "validate",
        contract_binding="fixture_append.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=tmp_path / "evidence",
        run_id="target-inspection-programmer-defect",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "cli.failure"
    assert response.payload["mutation_attempted"] is False
    assert "programmer-side target inspection defect" not in serialized


def test_unavailable_nested_target_component_is_a_stable_rejection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import phase_tool.paths as paths_module

    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    unavailable = target / "streams" / "alpha.jsonl"
    original_lstat = paths_module.os.lstat

    def fail_nested_component(path):
        candidate_path = Path(path)
        if candidate_path.name == unavailable.name and candidate_path.parent.name == unavailable.parent.name:
            raise PermissionError("private nested target diagnostic")
        return original_lstat(path)

    monkeypatch.setattr(paths_module.os, "lstat", fail_nested_component)
    evidence = tmp_path / "evidence"
    before = tree_digest(target)
    response = PhaseApplication(installation=boundary_test_installation()).run(
        "validate",
        contract_binding="fixture_append.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="nested-target-unavailable",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "validation.target_unavailable"
    assert response.payload["blockers"] == ["validation.target_unavailable"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] == "nested-target-unavailable"
    assert tree_digest(target) == before
    assert sorted(path.name for path in (evidence / ".phase" / "runs" / "nested-target-unavailable").iterdir()) == ["receipt.json"]
    assert str(unavailable) not in serialized
    assert "PermissionError" not in serialized
    assert "private nested target diagnostic" not in serialized


@pytest.mark.skipif(os.name == "nt", reason="execution guarantees require POSIX")
@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        (PermissionError("private reusable-result diagnostic"), "idempotency.observation_unavailable"),
        (ValueError("programmer-side reusable-result defect"), "cli.failure"),
    ],
)
def test_reusable_result_hook_normalizes_only_operational_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: Exception,
    expected_error: str,
) -> None:
    import phase_tool.core as core_module

    class FailingReuseHook:
        def find_reusable_result(self, *args, **kwargs):
            raise failure

    monkeypatch.setattr(core_module, "load_contract_hook", lambda contract: FailingReuseHook())
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    before = tree_digest(target)
    response = PhaseApplication().run(
        "execute",
        contract_binding="fixture_append.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=f"reuse-hook-{expected_error.replace('.', '-')}",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == expected_error
    assert response.payload["mutation_attempted"] is False
    assert tree_digest(target) == before
    assert str(target) not in serialized
    assert str(failure) not in serialized


@pytest.mark.skipif(os.name == "nt", reason="execution guarantees require POSIX")
@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        (PermissionError("private inspection hook diagnostic"), "inspection.target_unavailable"),
        (ValueError("programmer-side inspection hook defect"), "cli.failure"),
    ],
)
def test_final_inspection_hook_normalizes_only_operational_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: Exception,
    expected_error: str,
) -> None:
    import phase_tool.inspection as inspection_module

    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    run_id = f"inspection-hook-{expected_error.replace('.', '-')}"
    outcome = PhaseCore().run(
        request("fixture_append.v1", candidate, evidence, target, run_id),
        execute=True,
    )
    assert outcome.exit_code == 0

    class FailingInspectionHook:
        def inspect_result(self, *args, **kwargs):
            raise failure

        def inspect_stream_result(self, *args, **kwargs):
            raise failure

    monkeypatch.setattr(inspection_module, "load_contract_hook", lambda contract: FailingInspectionHook())
    before = tree_digest(target)
    response = PhaseApplication().inspect(
        evidence_root=evidence,
        run_id=run_id,
        root_bindings={"fixture_result_root": target},
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == expected_error
    assert response.payload["mutation_attempted"] is False
    assert tree_digest(target) == before
    assert str(target) not in serialized
    assert str(failure) not in serialized


@pytest.mark.skipif(os.name == "nt", reason="execution guarantees require POSIX")
def test_final_target_helper_does_not_mask_programmer_value_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import phase_tool.inspection as inspection_module

    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    run_id = "final-target-programmer-defect"
    outcome = PhaseCore().run(
        request("fixture_append.v1", candidate, evidence, target, run_id),
        execute=True,
    )
    assert outcome.exit_code == 0

    def fail_authority_open(*args, **kwargs):
        raise ValueError("programmer-side final target defect")

    monkeypatch.setattr(inspection_module.HostAuthorityProvider, "open_authority", fail_authority_open)
    before = tree_digest(target)
    response = PhaseApplication().inspect(
        evidence_root=evidence,
        run_id=run_id,
        root_bindings={"fixture_result_root": target},
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "cli.failure"
    assert response.payload["mutation_attempted"] is False
    assert tree_digest(target) == before
    assert str(target) not in serialized
    assert "programmer-side final target defect" not in serialized


def test_embedded_nul_inspection_root_is_a_stable_rejection() -> None:
    response = PhaseApplication().inspect(
        evidence_root=Path("private\0evidence"),
        run_id="invalid-inspection-root",
        root_bindings={},
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "inspection.run_unavailable"
    assert response.payload["blockers"] == ["inspection.run_unavailable"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] is None
    assert "private" not in serialized
    assert "ValueError" not in serialized


@pytest.mark.skipif(os.name == "nt", reason="execution guarantees require POSIX")
def test_embedded_nul_inspection_target_root_is_a_stable_rejection(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    (target / "streams").mkdir()
    evidence = tmp_path / "evidence"
    outcome = PhaseCore().run(
        request("fixture_append.v1", candidate, evidence, target, "invalid-inspection-target"),
        execute=True,
    )
    assert outcome.exit_code == 0

    response = PhaseApplication().inspect(
        evidence_root=evidence,
        run_id="invalid-inspection-target",
        root_bindings={"fixture_result_root": Path("private\0target")},
    )

    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "inspection.target_mismatch"
    assert response.payload["blockers"] == ["inspection.target_mismatch"]
    assert response.payload["mutation_attempted"] is False
    assert "private" not in serialized
    assert "ValueError" not in serialized


def test_inspect_is_read_only_and_detects_tampering(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"
    outcome = PhaseCore().run(request("fixture_append.v1", candidate, evidence, target, "inspect-run"))
    assert outcome.exit_code == 0
    before = tree_digest(evidence)
    summary = inspect_run(evidence, "inspect-run")
    assert summary["terminal_status"] == "validated_planned"
    assert summary["mutation_attempted"] is False
    assert tree_digest(evidence) == before
    plan_path = evidence / ".phase" / "runs" / "inspect-run" / "attachments" / "effect-plan.json"
    plan_path.write_bytes(plan_path.read_bytes() + b" ")
    with pytest.raises(PhaseError, match="inspection.digest_mismatch"):
        inspect_run(evidence, "inspect-run")


def test_same_key_different_request_is_rejected_without_target_mutation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    target = tmp_path / "target"
    target.mkdir()
    candidate = tmp_path / "candidate.json"
    write_append(candidate, value=1)
    first = PhaseCore().run(request("fixture_append.v1", candidate, evidence, target, "run-one"))
    assert first.exit_code == 0
    write_append(candidate, value=2)
    before = tree_digest(target)
    second = PhaseCore().run(request("fixture_append.v1", candidate, evidence, target, "run-two"))
    assert second.exit_code != 0
    assert second.receipt["blockers"] == ["idempotency.same_key_conflict"]
    assert tree_digest(target) == before


def test_invalid_run_id_and_evidence_target_overlap_are_rejected_before_write(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "canary").write_bytes(b"unchanged")
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    before = tree_digest(target)
    with pytest.raises(PhaseError, match="evidence.invalid_run_id"):
        PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence", target, "../escape"))
    with pytest.raises(PhaseError, match="evidence.overlaps_target_root"):
        PhaseCore().run(request("fixture_append.v1", candidate, target / "evidence", target, "safe-run"))
    alias = target.parent / "sibling" / ".." / target.name / "evidence-alias"
    with pytest.raises(PhaseError, match="evidence.overlaps_target_root"):
        PhaseCore().run(request("fixture_append.v1", candidate, alias, target, "alias-run"))
    assert tree_digest(target) == before
    assert not (target / "evidence").exists()
    assert not (target / "evidence-alias").exists()


def test_standalone_cli_validate_plan_inspect_and_execute_refusal(tmp_path: Path) -> None:
    phase = [sys.executable, "-m", "phase_tool"]
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"
    contract = exact("fixture_append.v1")
    base = [
        *phase,
        "--contract-id", "fixture_append.v1",
        "--contract-version", "1.0.0",
        "--contract-digest", contract["package_digest"],
        "--candidate", str(candidate),
        "--evidence-root", str(evidence),
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    ]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    validate = subprocess.run([*phase, "validate", *base[len(phase):], "--run-id", "cli-validate"], capture_output=True, text=True, env=env, check=False)
    assert validate.returncode == 0, validate.stderr
    assert json.loads(validate.stdout)["terminal_status"] == "validated_planned"
    plan = subprocess.run([*phase, "plan", *base[len(phase):], "--run-id", "cli-plan"], capture_output=True, text=True, env=env, check=False)
    assert plan.returncode == 0, plan.stderr
    assert json.loads(plan.stdout)["effect_plan_digest"].startswith("sha256:")
    inspect = subprocess.run([*phase, "inspect", "--evidence-root", str(evidence), "--run-id", "cli-plan"], capture_output=True, text=True, env=env, check=False)
    assert inspect.returncode == 0, inspect.stderr
    assert json.loads(inspect.stdout)["mutation_attempted"] is False
    execute = subprocess.run([*phase, "execute"], capture_output=True, text=True, env=env, check=False)
    assert execute.returncode == 2
    assert execute.stdout == ""
    assert "mutation_execution_unavailable_in_stage_2" not in execute.stderr
    assert "--candidate" in execute.stderr
    assert "--evidence-root" in execute.stderr
    assert "--run-id" in execute.stderr
    failure = subprocess.run(
        [*phase, "inspect", "--evidence-root", str(tmp_path / "missing"), "--run-id", "missing-run"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert failure.returncode == 10, failure.stderr
    failure_output = json.loads(failure.stdout)
    failure_serialized = json.dumps(failure_output, sort_keys=True)
    assert failure_output["success"] is False
    assert failure_output["blockers"] == ["inspection.run_unavailable"]
    assert failure_output["terminal_status"] == "rejected"
    assert failure_output["execution_disposition"] == "not_executed"
    assert failure_output["mutation_attempted"] is False
    assert failure_output["run_id"] is None
    assert failure_output["error"] == "inspection.run_unavailable"
    assert str(tmp_path / "missing") not in failure_serialized
    assert "FileNotFoundError" not in failure_serialized
    assert "No such file or directory" not in failure_serialized
    assert "Errno" not in failure_serialized


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="production authority qualification is Linux-only")
def test_regular_file_write_root_is_a_stable_pre_mutation_rejection(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps({
        "operation_id": "operation-1",
        "target_locator": "objects/item.bin",
        "input_binding": "payload",
        "idempotency_key": "root-file-key",
    }), encoding="utf-8")
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"payload")
    target = tmp_path / "configured-root"
    target.write_bytes(b"root-sentinel")
    evidence = tmp_path / "evidence"

    response = PhaseApplication().run(
        "execute",
        contract_binding="fixture_create.v1@1.0.0",
        candidate_path=candidate,
        evidence_root=evidence,
        run_id="root-file-rejection",
        input_paths={"payload": payload},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )

    schema = BundledRegistry.load().schema_document(
        "https://phase-tool.local/schemas/stage3-command-result.schema.json"
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(response.payload)
    serialized = json.dumps(response.payload, sort_keys=True)
    assert response.exit_code == 10
    assert response.payload["error"] == "guarantee.profile_scope_unsupported"
    assert response.payload["blockers"] == ["guarantee.profile_scope_unsupported"]
    assert response.payload["terminal_status"] == "rejected"
    assert response.payload["execution_disposition"] == "not_executed"
    assert response.payload["mutation_attempted"] is False
    assert response.payload["run_id"] == "root-file-rejection"
    assert target.read_bytes() == b"root-sentinel"
    assert str(target) not in serialized
    assert "Not a directory" not in serialized
    run_root = evidence / ".phase" / "runs" / "root-file-rejection"
    assert sorted(path.name for path in run_root.iterdir()) == ["receipt.json"]
