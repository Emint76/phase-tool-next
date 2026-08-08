from __future__ import annotations

import ast
import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import phase_tool.evidence as evidence_module
import phase_tool.mutation.broker as broker_module
from phase_tool import __version__
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.evidence import EvidenceStore
from phase_tool.installation import host_installation
from phase_tool.inspection import inspect_run
from phase_tool.mutation import BrokerFaults
from phase_tool.mutation.content_addressed_copy import ContentAddressedCopyFaults, execute_content_addressed_copy as _execute_content_addressed_copy
from phase_tool.mutation.exclusive_create import ExclusiveCreateFaults, execute_exclusive_create as _execute_exclusive_create
from phase_tool.registry import BundledRegistry
from phase_tool.validation import ValidatorRunner

NOW = "2026-07-28T12:00:00Z"
ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "phase_tool"


def execute_content_addressed_copy(*args: object, **kwargs: object) -> dict[str, object]:
    kwargs["authority_provider"] = host_installation().authority_provider
    return _execute_content_addressed_copy(*args, **kwargs)  # type: ignore[arg-type]


def execute_exclusive_create(*args: object, **kwargs: object) -> dict[str, object]:
    kwargs["authority_provider"] = host_installation().authority_provider
    return _execute_exclusive_create(*args, **kwargs)  # type: ignore[arg-type]


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _source_locator(data: bytes) -> str:
    hex_digest = hashlib.sha256(data).hexdigest()
    return f"blobs/sha256/{hex_digest[:2]}/{hex_digest}"


def _independent_admission_digest(value: object) -> str:
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return _sha(encoded)


def _independent_source_result_id(payload: bytes) -> str:
    provenance = _candidate_value()["provenance"]
    identity = {
        "admission_contract": {"id": "source_admission.v1", "version": "1.0.0"},
        "namespace": "example",
        "logical_source_id": "source-race-logical",
        "content_digest": _sha(payload),
        "content_length": len(payload),
        "media_type": "application/pdf",
        "original_filename": "manual.pdf",
        "provenance_digest": _independent_admission_digest(provenance),
        "supersedes": None,
    }
    return "source-result-" + _independent_admission_digest(identity).removeprefix("sha256:")


def _binding(contract_id: str = "source_admission.v1") -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()[f"{contract_id}@1.0.0"]


def _candidate_value(
    *,
    logical_id: str = "source-manual-001",
    operation_id: str = "op-source-001",
    expected_digest: str | None = None,
    expected_length: int | None = None,
    filename: str | None = "manual.pdf",
    namespace: str = "example",
) -> dict[str, object]:
    return {
        "candidate_version": "1.0",
        "contract": {"id": "source_admission.v1", "version": "1.0.0"},
        "operation_id": operation_id,
        "idempotency_key": operation_id,
        "logical_source_id": logical_id,
        "asset_input": {"binding_id": "asset", "expected_digest": expected_digest, "expected_length": expected_length},
        "declared_media_type": "application/pdf",
        "original_filename": filename,
        "provenance": {
            "provenance_version": "1.0",
            "origin": {"kind": "external_uri", "locator": "https://example.invalid/manual.pdf", "label": "supplier manual"},
            "supplied_by": {"kind": "adapter", "identifier": "adapter.example"},
        },
        "placement": {"target_root_binding": "admission_result_root", "namespace": namespace},
        "supersedes": None,
        "request_metadata": {"submitted_by": "adapter.example", "correlation_id": operation_id},
    }


def _write_candidate(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _request(
    tmp_path: Path,
    *,
    run_id: str,
    payload: bytes = b"source bytes\n",
    logical_id: str = "source-manual-001",
    operation_id: str = "op-source-001",
    expected: bool = True,
) -> tuple[PhaseRequest, Path, Path, Path, bytes]:
    target = tmp_path / "target"
    (target / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)
    evidence = tmp_path / "evidence"
    source = tmp_path / f"{run_id}.bin"
    source.write_bytes(payload)
    candidate = tmp_path / f"{run_id}.json"
    _write_candidate(
        candidate,
        _candidate_value(
            logical_id=logical_id,
            operation_id=operation_id,
            expected_digest=_sha(payload) if expected else None,
            expected_length=len(payload) if expected else None,
        ),
    )
    binding = _binding()
    return (
        PhaseRequest(
            contract_id="source_admission.v1",
            contract_version="1.0.0",
            contract_digest=binding["package_digest"],
            candidate_path=candidate,
            evidence_root=evidence,
            run_id=run_id,
            input_paths={"asset": source},
            root_bindings={"admission_result_root": target},
            timestamp=NOW,
        ),
        target,
        evidence,
        source,
        payload,
    )


def test_admission_canonical_json_v1_matches_golden_vectors() -> None:
    from phase_tool.contracts.source_admission_v1 import admission_canonical_bytes

    for path in sorted((ROOT / "contracts" / "spec-candidates" / "admission-v1" / "fixtures" / "golden").glob("canonical-json-*.json")):
        vector = json.loads(path.read_text(encoding="utf-8"))
        actual = admission_canonical_bytes(vector["value"])
        assert actual.hex() == vector["canonical_utf8_hex"], path.name
        assert digest_bytes(actual) == vector["sha256_digest"], path.name


@pytest.mark.parametrize("payload", [b"hello\n", bytes([0, 1, 2, 253, 254, 255]), b""])
def test_source_execute_writes_blob_descriptor_progress_and_inspects(tmp_path: Path, payload: bytes) -> None:
    request, target, evidence, source, frozen_payload = _request(tmp_path, run_id=f"source-{len(payload)}", payload=payload)
    source_before = source.read_bytes()

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.exit_code == 0
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert outcome.receipt["execution_disposition"] == "executed"
    assert [item["effect_id"] for item in outcome.effect_plan["effects"]] == ["effect.0.blob", "effect.1.descriptor"]
    assert [item["mechanism"]["id"] for item in outcome.effect_plan["effects"]] == ["content_addressed_copy", "mechanism.exclusive_create_v1"]
    assert (target / _source_locator(frozen_payload)).read_bytes() == frozen_payload
    descriptor_ref = outcome.receipt["canonical_result"]
    descriptor = parse_json_bytes((target / descriptor_ref["locator"]).read_bytes())
    assert descriptor["content_digest"] == _sha(frozen_payload)
    assert descriptor["content_length"] == len(frozen_payload)
    assert descriptor["blob_locator"] == _source_locator(frozen_payload)
    assert descriptor["admission_run"]["run_id"] == request.run_id
    assert "receipt_digest" not in descriptor["admission_run"]
    progress = parse_json_bytes((evidence / ".phase" / "runs" / request.run_id / "attachments" / "ordered-effect-progress.json").read_bytes())
    assert progress["completed_effect_ids"] == ["effect.0.blob", "effect.1.descriptor"]
    assert progress["verified_effect_ids"] == ["effect.0.blob", "effect.1.descriptor"]
    assert progress["not_started_effect_ids"] == []
    assert source.read_bytes() == source_before
    inspected = inspect_run(evidence, request.run_id, root_bindings={"admission_result_root": target})
    assert inspected["target_verified"] is True
    exact = inspected["contract_result"]
    assert exact["reference"]["descriptor_digest"] == descriptor_ref["state"]["digest"]
    assert exact["reference"]["phase_receipt"] == {"run_id": request.run_id, "receipt_digest": outcome.receipt_digest}
    assert exact["binding"]["source_phase_receipt"] == exact["reference"]["phase_receipt"]
    assert exact["binding"]["source_content_digest"] == _sha(frozen_payload)


def test_source_validate_and_plan_do_not_mutate_target(tmp_path: Path) -> None:
    request, target, evidence, _source, payload = _request(tmp_path, run_id="source-plan", payload=b"plan only")
    before = sorted(path.relative_to(target).as_posix() for path in target.rglob("*"))

    planned = PhaseCore().run(request)

    assert planned.receipt["terminal_status"] == "validated_planned"
    assert sorted(path.relative_to(target).as_posix() for path in target.rglob("*")) == before
    assert not (target / _source_locator(payload)).exists()
    assert len(planned.effect_plan["effects"]) == 2
    progress = broker_module.ordered_progress_document(planned.effect_plan, [])
    progress_path = evidence / ".phase" / "runs" / request.run_id / "attachments" / "ordered-effect-progress.json"
    progress_path.write_bytes(canonical_bytes(progress))
    with pytest.raises(PhaseError) as inspection_error:
        inspect_run(evidence, request.run_id, root_bindings=request.root_bindings)
    assert inspection_error.value.code == "inspection.attachment_set_mismatch"
    run_root = evidence / ".phase" / "runs" / request.run_id
    receipt_path = run_root / "receipt.json"
    receipt = parse_json_bytes(receipt_path.read_bytes())
    progress_digest = digest_bytes(progress_path.read_bytes())
    receipt["evidence"]["attachment_digests"] = sorted([*receipt["evidence"]["attachment_digests"], progress_digest])
    receipt_path.write_bytes(canonical_bytes(receipt))
    assert inspect_run(evidence, request.run_id, root_bindings=request.root_bindings)["terminal_status"] == "validated_planned"
    progress["verified_effect_ids"] = [planned.effect_plan["effects"][0]["effect_id"]]
    progress_path.write_bytes(canonical_bytes(progress))
    receipt["evidence"]["attachment_digests"] = sorted(
        [item for item in receipt["evidence"]["attachment_digests"] if item != progress_digest]
        + [digest_bytes(progress_path.read_bytes())]
    )
    receipt_path.write_bytes(canonical_bytes(receipt))
    with pytest.raises(PhaseError) as claimed_progress_error:
        inspect_run(evidence, request.run_id, root_bindings=request.root_bindings)
    assert claimed_progress_error.value.code == "inspection.progress_semantic_mismatch"


def test_source_reuse_conflicts_and_recovery_matrix(tmp_path: Path) -> None:
    first_request, target, evidence, _source, payload = _request(tmp_path, run_id="source-first", payload=b"same")
    first = PhaseCore().run(first_request, execute=True)
    same = PhaseCore().run(replace(first_request, run_id="source-reuse"), execute=True)
    assert same.receipt["execution_disposition"] == "reused_existing"
    assert same.receipt["effect_receipts"] == []

    different_request, _target2, _evidence2, _source2, _payload2 = _request(
        tmp_path,
        run_id="source-conflict",
        payload=b"different",
        operation_id="op-source-001",
    )
    conflict = PhaseCore().run(different_request, execute=True)
    assert conflict.receipt["terminal_status"] == "rejected"
    assert conflict.receipt["mutation_attempted"] is False

    other_id_request, _target3, _evidence3, _source3, _payload3 = _request(
        tmp_path,
        run_id="source-other-id",
        payload=payload,
        logical_id="source-manual-002",
        operation_id="op-source-002",
    )
    other = PhaseCore().run(other_id_request, execute=True)
    assert other.receipt["terminal_status"] == "succeeded_verified"
    assert other.receipt["effect_receipts"][0]["bytes_written"] == 0
    assert other.receipt["effect_receipts"][1]["bytes_written"] > 0
    assert inspect_run(evidence, "source-first", root_bindings={"admission_result_root": target})["target_verified"] is True


def test_source_descriptor_callback_is_rejected_before_blob_mutation(tmp_path: Path) -> None:
    request, target, _evidence, _source, payload = _request(tmp_path, run_id="source-partial", payload=b"partial")
    planned = PhaseCore().run(replace(request, run_id="source-partial-plan"))
    descriptor_locator = planned.effect_plan["effects"][1]["target"]["relative_locator"]

    def create_descriptor_conflict(_intent_path: Path) -> None:
        destination = target / descriptor_locator
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"conflict")

    outcome = PhaseCore().run(request, execute=True, faults=CoreFaults(broker=BrokerFaults(before_effect={1: create_descriptor_conflict})))

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not (target / _source_locator(payload)).exists()
    assert not (target / descriptor_locator).exists()


def test_source_ordering_blocks_descriptor_after_blob_failure(tmp_path: Path) -> None:
    request, target, _evidence, _source, _payload = _request(tmp_path, run_id="source-blob-fail", payload=b"blob fail")
    outcome = PhaseCore().run(request, execute=True, faults=CoreFaults(broker=BrokerFaults(content_addressed_copy_fail_after_bytes=2)))

    assert outcome.receipt["terminal_status"] == "failed_partial"
    assert len(outcome.receipt["effect_receipts"]) == 1
    assert not any(path.name.endswith(".json") for path in target.rglob("*.json"))
    progress = parse_json_bytes((request.evidence_root / ".phase" / "runs" / request.run_id / "attachments" / "ordered-effect-progress.json").read_bytes())
    assert progress["not_started_effect_ids"] == ["effect.1.descriptor"]


def test_source_broker_preinvocation_callback_is_rejected_without_effect(tmp_path: Path) -> None:
    request, target, evidence, _source, _candidate = _request(tmp_path, run_id="run-source-prefix-corruption")

    def corrupt_descriptor_blob(intent_path: Path) -> None:
        plan = parse_json_bytes((intent_path.parent / "attachments" / "effect-plan.json").read_bytes())
        descriptor_digest = plan["effects"][1]["content_blob_digest"]
        (intent_path.parent / "blobs" / descriptor_digest.split(":", 1)[1]).write_bytes(b"corrupt")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_effect={1: corrupt_descriptor_blob})),
    )
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["effect_receipts"] == []
    assert not any(path.is_file() for path in target.rglob("*"))


def test_source_progress_is_persisted_before_first_effect_and_after_each_observed_effect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    request, target, _evidence, _source, _payload = _request(tmp_path, run_id="source-progress", payload=b"progress")
    progress_path = request.evidence_root / ".phase" / "runs" / request.run_id / "attachments" / "ordered-effect-progress.json"
    snapshots: list[dict[str, object]] = []

    original = evidence_module.replace_attachment_canonical

    def capture_progress(attachment_root: Path, file_name: str, value: object) -> tuple[Path, str]:
        if file_name == "ordered-effect-progress.json":
            snapshots.append(json.loads(json.dumps(value)))
        return original(attachment_root, file_name, value)

    monkeypatch.setattr(evidence_module, "replace_attachment_canonical", capture_progress)
    monkeypatch.setattr(broker_module, "replace_attachment_canonical", capture_progress)
    outcome = PhaseCore().run(request, execute=True)

    final_progress = parse_json_bytes(progress_path.read_bytes())
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert len(snapshots) == 3
    assert snapshots[0]["completed_effect_ids"] == []
    assert snapshots[0]["not_started_effect_ids"] == ["effect.0.blob", "effect.1.descriptor"]
    assert snapshots[1]["completed_effect_ids"] == ["effect.0.blob"]
    assert snapshots[1]["not_started_effect_ids"] == ["effect.1.descriptor"]
    assert snapshots[2]["completed_effect_ids"] == ["effect.0.blob", "effect.1.descriptor"]
    assert final_progress["completed_effect_ids"] == ["effect.0.blob", "effect.1.descriptor"]
    assert (target / outcome.receipt["canonical_result"]["locator"]).is_file()


def test_ordered_progress_blocking_validator_rejects_tampered_progress(tmp_path: Path) -> None:
    request, _target, evidence, _source, _payload = _request(tmp_path, run_id="source-progress-validator", payload=b"validator")
    outcome = PhaseCore().run(request, execute=True)
    progress_path = evidence / ".phase" / "runs" / request.run_id / "attachments" / "ordered-effect-progress.json"
    progress = parse_json_bytes(progress_path.read_bytes())
    progress["verified_effect_ids"] = []
    registry = BundledRegistry.load()
    contract = registry.resolve_contract(
        request.contract_id,
        request.contract_version,
        request.contract_digest,
        core_version=__version__,
    )
    results = ValidatorRunner(registry).run_post_operation(
        contract,
        outcome.receipt["validator_results"],
        outcome.effect_plan,
        request.root_bindings,
        run_id=request.run_id,
        timestamp=NOW,
        effect_receipts=outcome.receipt["effect_receipts"],
        ordered_progress=progress,
    )
    result = next(item for item in results if item["validator"]["id"] == "phase.ordered_effect_plan_progress_v1")
    assert result["status"] == "fail"
    assert result["blockers"] == ["validation.ordered_progress_mismatch"]
    progress_path.write_bytes(canonical_bytes(progress))
    with pytest.raises(PhaseError) as inspection_error:
        inspect_run(evidence, request.run_id, root_bindings=request.root_bindings)
    assert inspection_error.value.code == "inspection.attachment_set_mismatch"


def test_progress_write_failure_preserves_durable_effect_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    request, _target, evidence, _source, _payload = _request(tmp_path, run_id="source-progress-write-fail", payload=b"progress-failure")
    original = evidence_module.replace_attachment_canonical
    calls = 0

    def fail_second_progress_write(attachment_root: Path, file_name: str, value: object) -> tuple[Path, str]:
        nonlocal calls
        if file_name == "ordered-effect-progress.json":
            calls += 1
            if calls == 2:
                raise OSError("injected progress persistence failure")
        return original(attachment_root, file_name, value)

    monkeypatch.setattr(evidence_module, "replace_attachment_canonical", fail_second_progress_write)
    monkeypatch.setattr(broker_module, "replace_attachment_canonical", fail_second_progress_write)
    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "failed_partial"
    assert outcome.receipt["blockers"] == ["evidence.finalization_failed"]
    assert [item["effect_id"] for item in outcome.receipt["effect_receipts"]] == ["effect.0.blob"]
    run_root = evidence / ".phase" / "runs" / request.run_id
    assert parse_json_bytes((run_root / "receipt.json").read_bytes()) == outcome.receipt
    progress = parse_json_bytes((run_root / "attachments" / "ordered-effect-progress.json").read_bytes())
    assert progress["verified_effect_ids"] == ["effect.0.blob"]
    assert progress["not_started_effect_ids"] == ["effect.1.descriptor"]


@pytest.mark.parametrize("persistent_failure", [False, True])
def test_final_progress_write_failure_preserves_durable_complete_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persistent_failure: bool,
) -> None:
    request, target, evidence, _source, _payload = _request(
        tmp_path,
        run_id="source-final-progress-write-fail",
        payload=b"final-progress-failure",
    )
    original = evidence_module.replace_attachment_canonical
    calls = 0

    def fail_final_progress_write(attachment_root: Path, file_name: str, value: object) -> tuple[Path, str]:
        nonlocal calls
        if file_name == "ordered-effect-progress.json":
            calls += 1
            if calls == 3 or (persistent_failure and calls > 3):
                raise OSError("injected final progress persistence failure")
        return original(attachment_root, file_name, value)

    monkeypatch.setattr(evidence_module, "replace_attachment_canonical", fail_final_progress_write)
    monkeypatch.setattr(broker_module, "replace_attachment_canonical", fail_final_progress_write)
    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "committed_unverified"
    assert outcome.receipt["blockers"] == ["evidence.finalization_failed"]
    assert [item["effect_id"] for item in outcome.receipt["effect_receipts"]] == [
        "effect.0.blob",
        "effect.1.descriptor",
    ]
    assert (target / outcome.receipt["canonical_result"]["locator"]).is_file()
    run_root = evidence / ".phase" / "runs" / request.run_id
    assert parse_json_bytes((run_root / "attachments" / "effect-receipts.json").read_bytes()) == outcome.receipt["effect_receipts"]
    assert parse_json_bytes((run_root / "receipt.json").read_bytes()) == outcome.receipt
    inspected = inspect_run(evidence, request.run_id, root_bindings=request.root_bindings)
    assert inspected["terminal_status"] == "committed_unverified"
    if persistent_failure:
        tampered_progress = broker_module.ordered_progress_document(outcome.effect_plan, outcome.receipt["effect_receipts"])
        tampered_progress["verified_effect_ids"] = []
        progress_bytes = canonical_bytes(tampered_progress)
        (run_root / "attachments" / "ordered-effect-progress.json").write_bytes(progress_bytes)
        tampered_receipt = parse_json_bytes(canonical_bytes(outcome.receipt))
        tampered_receipt["evidence"]["attachment_digests"] = sorted(
            [*tampered_receipt["evidence"]["attachment_digests"], digest_bytes(progress_bytes)]
        )
        (run_root / "receipt.json").write_bytes(canonical_bytes(tampered_receipt))
        with pytest.raises(PhaseError) as inspection_error:
            inspect_run(evidence, request.run_id, root_bindings=request.root_bindings)
        assert inspection_error.value.code == "inspection.progress_semantic_mismatch"


def _source_worker(base: str, name: str, queue: object) -> None:
    tmp = Path(base)
    request, _target, _evidence, _source, _payload = _request(tmp, run_id=name, payload=b"race", operation_id="op-race")
    outcome = PhaseCore().run(request, execute=True)
    queue.put((outcome.receipt["terminal_status"], outcome.receipt["execution_disposition"]))  # type: ignore[attr-defined]


def _source_identity_race_worker(base: str, name: str, payload: bytes, operation_id: str, queue: object, barrier: object) -> None:
    tmp = Path(base)
    request, _target, _evidence, _source, _payload = _request(
        tmp,
        run_id=name,
        payload=payload,
        logical_id="source-race-logical",
        operation_id=operation_id,
    )
    request = replace(request, evidence_root=tmp / f"evidence-{name}")

    barrier.wait(timeout=20)  # type: ignore[attr-defined]
    outcome = PhaseCore().run(request, execute=True)
    queue.put((outcome.receipt["terminal_status"], outcome.receipt["execution_disposition"], outcome.receipt["mutation_attempted"]))  # type: ignore[attr-defined]


def test_source_concurrent_same_operation_has_one_success_and_one_conflict(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    workers = [context.Process(target=_source_worker, args=(str(tmp_path), f"race-{index}", queue)) for index in range(2)]
    for worker in workers:
        worker.start()
    outcomes = [queue.get(timeout=30) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0
    assert sorted(outcomes) == [("succeeded_verified", "executed"), ("succeeded_verified", "reused_existing")]


def test_source_concurrent_same_identity_different_content_has_one_canonical_descriptor(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    barrier = context.Barrier(2)
    workers = [
        context.Process(target=_source_identity_race_worker, args=(str(tmp_path), "identity-race-a", b"race-a", "op-race-a", queue, barrier)),
        context.Process(target=_source_identity_race_worker, args=(str(tmp_path), "identity-race-b", b"race-b", "op-race-b", queue, barrier)),
    ]
    for worker in workers:
        worker.start()
    outcomes = [queue.get(timeout=30) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0
    successes = [item for item in outcomes if item[0] == "succeeded_verified"]
    losers = [item for item in outcomes if item[0] != "succeeded_verified"]
    assert len(successes) == 1
    assert len(losers) == 1
    assert losers == [("failed_partial", "executed", True)]
    target = tmp_path / "target"
    payloads = {"identity-race-a": b"race-a", "identity-race-b": b"race-b"}
    observed: dict[str, tuple[dict[str, object], dict[str, object], str]] = {}
    for run_id, payload in payloads.items():
        evidence = tmp_path / f"evidence-{run_id}" / ".phase" / "runs"
        receipt = parse_json_bytes((evidence / run_id / "receipt.json").read_bytes())
        plan = parse_json_bytes((evidence / run_id / "attachments" / "effect-plan.json").read_bytes())
        result_id = _independent_source_result_id(payload)
        expected_locator = f"r/example/source-race-logical/{result_id}.json"
        assert [effect["effect_id"] for effect in plan["effects"]] == ["effect.0.blob", "effect.1.descriptor"]
        assert plan["effects"][0]["target"]["relative_locator"] == _source_locator(payload)
        assert plan["effects"][1]["target"]["relative_locator"] == expected_locator
        assert (target / _source_locator(payload)).read_bytes() == payload
        observed[run_id] = receipt, plan, expected_locator

    winner_id = next(run_id for run_id, (receipt, _plan, _locator) in observed.items() if receipt["terminal_status"] == "succeeded_verified")
    loser_id = next(run_id for run_id, (receipt, _plan, _locator) in observed.items() if receipt["terminal_status"] == "failed_partial")
    winner_receipt, _winner_plan, winner_locator = observed[winner_id]
    loser_receipt, _loser_plan, loser_locator = observed[loser_id]
    descriptors = list((target / "r" / "example" / "source-race-logical").glob("*.json"))
    assert len(descriptors) == 1
    assert descriptors[0] == target / winner_locator
    assert not (target / loser_locator).exists()
    descriptor_bytes = descriptors[0].read_bytes()
    descriptor = parse_json_bytes(descriptor_bytes)
    assert descriptor["logical_source_id"] == "source-race-logical"
    assert descriptor["source_result_id"] == _independent_source_result_id(payloads[winner_id])
    assert descriptor["descriptor_locator"] == winner_locator
    assert descriptor["content_digest"] == _sha(payloads[winner_id])
    assert _sha(descriptor_bytes) == winner_receipt["canonical_result"]["state"]["digest"]
    assert loser_receipt["canonical_result"] is None
    assert [effect["effect_id"] for effect in loser_receipt["effect_receipts"]] == ["effect.0.blob", "effect.1.descriptor"]
    assert [effect["status"] for effect in loser_receipt["effect_receipts"]] == ["applied_verified", "failed_no_effect"]
    loser_evidence = tmp_path / f"evidence-{loser_id}" / ".phase" / "runs"
    loser_progress = parse_json_bytes((loser_evidence / loser_id / "attachments" / "ordered-effect-progress.json").read_bytes())
    assert loser_progress["verified_effect_ids"] == ["effect.0.blob"]
    assert loser_progress["failed_effect_id"] == "effect.1.descriptor"
    assert not (target / "namespaces" / "example" / "source-results" / "source-race-logical").exists()


def test_receipt_determinism_is_scoped_to_resolved_target_root_identity(tmp_path: Path) -> None:
    seed_request, _seed_target, _seed_evidence, _source, _payload = _request(tmp_path / "seed", run_id="root-bound")
    outcomes = []
    for name in ("authority-a", "authority-b"):
        target = tmp_path / name / "target"
        (target / "blobs" / "sha256").mkdir(parents=True)
        request = replace(
            seed_request,
            evidence_root=tmp_path / name / "evidence",
            root_bindings={"admission_result_root": target},
        )
        outcomes.append(PhaseCore().run(request, execute=True))

    first, second = outcomes
    assert first.effect_plan == second.effect_plan
    assert first.receipt["effect_receipts"] == second.receipt["effect_receipts"]
    assert first.intent is not None and second.intent is not None
    intent_differences = {
        key
        for key in first.intent["idempotency"]
        if first.intent["idempotency"][key] != second.intent["idempotency"][key]
    }
    assert intent_differences == {"request_digest", "root_identities", "root_identity_digest", "scope_digest"}
    for intent in (first.intent, second.intent):
        assert intent["idempotency"]["root_identity_digest"] == profile_digest(
            "resolved-root-identity",
            intent["idempotency"]["root_identities"],
        )
    assert first.receipt_digest != second.receipt_digest
    first_receipt = json.loads(json.dumps(first.receipt))
    second_receipt = json.loads(json.dumps(second.receipt))
    assert first_receipt["evidence"]["intent_digest"] != second_receipt["evidence"]["intent_digest"]
    first_receipt["evidence"]["intent_digest"] = "<root-identity-bound>"
    second_receipt["evidence"]["intent_digest"] = "<root-identity-bound>"
    assert first_receipt == second_receipt


def test_stage6_hardened_cli_summary_and_walkthrough_values() -> None:
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    process = subprocess.run(
        [sys.executable, "scripts/stage6_cli_acceptance.py"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    compact = json.loads(process.stdout)
    assert compact["success"] is True
    assert compact["scenario_count"] == 29
    summary_path = repo / ".stage6-tmp" / "final-cli" / "stage6-cli-acceptance-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    receipt_path = repo / ".stage6-tmp" / "final-cli" / "evidence" / ".phase" / "runs" / "source-execute" / "receipt.json"
    receipt_bytes = receipt_path.read_bytes()
    repeated = subprocess.run(
        [sys.executable, "scripts/stage6_cli_acceptance.py"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert repeated.returncode == 0, repeated.stderr
    repeated_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert receipt_path.read_bytes() == receipt_bytes
    assert repeated_summary["command_matrix"]["05_execute_text"]["envelope"]["receipt_digest"] == summary["command_matrix"]["05_execute_text"]["envelope"]["receipt_digest"]
    assert summary["success"] is True
    assert summary["scenario_count"] == 29
    assert summary["failures"] == {}
    assert all(summary["checks"].values())
    assert summary["command_matrix"]["28_knowledge_execute_unavailable"]["blockers"] == ["registry.entry_not_found"]
    assert set(summary["inspection"]) >= {"source_result", "source_result_reference", "source_result_binding"}
    walkthrough = (repo / "docs" / "STAGE-6-SOURCE-ADMISSION-WALKTHROUGH.md").read_text(encoding="utf-8")
    for value in (
        "scenario_count: 29",
        summary["text_result"]["content_digest"],
        summary["inspection"]["descriptor_digest"],
        summary["text_result"]["source_result_id"],
        "captured root-identity-bound evidence",
        "not a cross-root reproducibility invariant",
    ):
        assert value in walkthrough


def test_source_active_surfaces_and_architecture_scans() -> None:
    bindings = BundledRegistry.load().contract_bindings()
    assert "source_admission.v1@1.0.0" in bindings
    assert "knowledge_admission.v1@1.0.0" in bindings
    source_forbidden = {
        "source_admission.v1",
        "knowledge_admission.v1",
        "logical_source_id",
        "original_filename",
        "declared_media_type",
        "provenance",
    }
    for relative in [
        "core.py",
        "planning/__init__.py",
        "inspection/__init__.py",
        "paths.py",
        "evidence/__init__.py",
        "mutation/broker.py",
        "mutation/content_addressed_copy.py",
        "mutation/exclusive_create.py",
        "validation/__init__.py",
        "contracts/__init__.py",
    ]:
        tree = ast.parse((PACKAGE / relative).read_text(encoding="utf-8"), filename=relative)
        literals = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        assert literals, relative
        assert source_forbidden.isdisjoint(literals), relative
    for relative in ["mutation/content_addressed_copy.py", "mutation/exclusive_create.py"]:
        tree = ast.parse((PACKAGE / relative).read_text(encoding="utf-8"), filename=relative)
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert "ensure_target_parent" not in names, relative


def test_source_contract_schema_and_hook_are_exact_registry_bound_and_code_owned() -> None:
    active_schema_bytes = (ROOT / "schemas" / "phase-contract.schema.json").read_bytes()
    bundled_schema_bytes = (PACKAGE / "data" / "schemas" / "phase-contract.schema.json").read_bytes()
    assert active_schema_bytes == bundled_schema_bytes
    phase_schema = json.loads(active_schema_bytes)
    Draft202012Validator.check_schema(phase_schema)

    contract = json.loads((ROOT / "contracts" / "source_admission.v1.json").read_text(encoding="utf-8"))
    bundled_contract = json.loads((PACKAGE / "data" / "contracts" / "source_admission.v1.json").read_text(encoding="utf-8"))
    assert contract == bundled_contract
    Draft202012Validator(phase_schema, format_checker=FormatChecker()).validate(contract)
    assert set(contract["contract_hook"]) == {"id", "version", "package_digest", "capability"}

    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["source_admission.v1@1.0.0"]
    resolved = registry.resolve_contract("source_admission.v1", "1.0.0", binding["package_digest"], core_version="1.0.0")
    assert resolved.contract_hook is not None
    assert resolved.contract_hook["id"] == "source_admission.runtime_v1"
    assert resolved.contract_hook["version"] == "1.0.0"
    assert resolved.contract_hook["capability"] == "contract_hook"
    assert resolved.contract_hook["execution_allowed"] is True
    assert "module" not in resolved.contract_hook
    assert "factory" not in resolved.contract_hook
    assert "implementation_id" in resolved.contract_hook
    loader_text = (PACKAGE / "contracts" / "__init__.py").read_text(encoding="utf-8")
    assert "import_module" not in loader_text

    with pytest.raises(PhaseError):
        registry.resolve_contract_hook({**contract["contract_hook"], "package_digest": "sha256:" + "0" * 64})
    with pytest.raises(PhaseError):
        registry.resolve_contract_hook({**contract["contract_hook"], "capability": "validator"})

    raw_path_contract = json.loads(json.dumps(contract))
    raw_path_contract["contract_hook"] = {"module": "attacker.module", "factory": "run"}
    assert list(Draft202012Validator(phase_schema, format_checker=FormatChecker()).iter_errors(raw_path_contract))


@pytest.mark.parametrize("mechanism", ["blob", "descriptor"])
def test_source_mechanisms_keep_pinned_parent_authority_during_replacement(tmp_path: Path, mechanism: str) -> None:
    target_root = tmp_path / "target"
    target_root.mkdir()
    content = b"pinned-authority\n"
    content_digest = digest_bytes(content)
    if mechanism == "blob":
        hex_digest = content_digest.split(":", 1)[1]
        locator = f"blobs/sha256/{hex_digest[:2]}/{hex_digest}"
        kind = "copy_blob"
    else:
        locator = "r/example/source-parent-race/source-result-test.json"
        kind = "exclusive_create"
    effect = {
        "effect_id": f"effect.test.{mechanism}",
        "kind": kind,
        "content_digest": content_digest,
        "content_length": len(content),
        "target": {"root_binding": "target", "relative_locator": locator},
    }
    if mechanism == "blob":
        effect["locator_policy_id"] = "content_addressed_sha256_sharded_v1"

    swap: dict[str, object] = {"succeeded": False, "blocked": False, "moved_parent": None}

    def replace_parent(target: Path) -> None:
        moved = target.parent.with_name(target.parent.name + "-moved")
        swap["moved_parent"] = moved
        try:
            target.parent.rename(moved)
        except PermissionError:
            swap["blocked"] = True
            return
        target.parent.mkdir()
        swap["succeeded"] = True

    if mechanism == "blob":
        execute = lambda: execute_content_addressed_copy(
            effect, target_root, content, run_id="run-parent-race", timestamp="2026-01-01T00:00:00Z",
            faults=ContentAddressedCopyFaults(before_exclusive_create=replace_parent),
        )
    else:
        execute = lambda: execute_exclusive_create(
            effect, target_root, content, run_id="run-parent-race", timestamp="2026-01-01T00:00:00Z",
            faults=ExclusiveCreateFaults(before_exclusive_create=replace_parent),
        )

    outcome: dict[str, object] | PhaseError
    try:
        outcome = execute()
    except PhaseError as exc:
        outcome = exc
    leaf = Path(locator).name
    if swap["succeeded"]:
        assert isinstance(outcome, PhaseError)
        assert outcome.code == "path.parent_identity_changed"
        moved_parent = swap["moved_parent"]
        assert isinstance(moved_parent, Path)
        assert not (moved_parent / leaf).exists()
        assert not target_root.joinpath(*locator.split("/")).exists()
    else:
        assert isinstance(outcome, dict)
        assert outcome["status"] == "applied_verified"
        assert swap["blocked"] is True
        assert target_root.joinpath(*locator.split("/")).read_bytes() == content


@pytest.mark.parametrize("mechanism", ["blob", "descriptor"])
def test_source_mechanisms_report_indeterminate_if_parent_binding_changes_after_write(tmp_path: Path, mechanism: str) -> None:
    if os.name == "nt":
        pytest.skip("POSIX rename semantics required")
    target_root = tmp_path / "target"
    target_root.mkdir()
    content = b"late-pinned-authority\n"
    content_digest = digest_bytes(content)
    if mechanism == "blob":
        hex_digest = content_digest.split(":", 1)[1]
        locator = f"blobs/sha256/{hex_digest[:2]}/{hex_digest}"
        kind = "copy_blob"
    else:
        locator = "r/example/source-parent-race/source-result-late.json"
        kind = "exclusive_create"
    effect: dict[str, object] = {
        "effect_id": f"effect.test.late.{mechanism}",
        "kind": kind,
        "content_digest": content_digest,
        "content_length": len(content),
        "target": {"root_binding": "target", "relative_locator": locator},
    }
    if mechanism == "blob":
        effect["locator_policy_id"] = "content_addressed_sha256_sharded_v1"
    moved_parent: Path | None = None

    def replace_parent(target: Path) -> None:
        nonlocal moved_parent
        moved_parent = target.parent.with_name(target.parent.name + "-moved")
        target.parent.rename(moved_parent)
        target.parent.mkdir()

    if mechanism == "blob":
        receipt = execute_content_addressed_copy(
            effect, target_root, content, run_id="run-late-parent-race", timestamp="2026-01-01T00:00:00Z",
            faults=ContentAddressedCopyFaults(before_readback=replace_parent),
        )
    else:
        receipt = execute_exclusive_create(
            effect, target_root, content, run_id="run-late-parent-race", timestamp="2026-01-01T00:00:00Z",
            faults=ExclusiveCreateFaults(before_readback=replace_parent),
        )

    assert receipt["status"] == "indeterminate"
    assert receipt["error"]["code"] == "path.parent_identity_changed"
    assert receipt["after"] == {"known": False, "exists": None, "digest": None, "length": None, "head_token": None}
    assert receipt["bytes_written"] == len(content)
    assert moved_parent is not None
    assert (moved_parent / Path(locator).name).read_bytes() == content
    assert not target_root.joinpath(*locator.split("/")).exists()
