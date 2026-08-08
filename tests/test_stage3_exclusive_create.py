from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.evidence import EvidenceStore
from phase_tool.installation import host_installation
from phase_tool.mutation import BrokerFaults, ExclusiveCreateFaults
from phase_tool.mutation.exclusive_create import execute_exclusive_create as _execute_exclusive_create
from phase_tool.registry import BundledRegistry

NOW = "2026-07-27T03:00:00Z"
ROOT = Path(__file__).resolve().parents[1]


def execute_exclusive_create(*args: object, **kwargs: object) -> dict[str, object]:
    kwargs["authority_provider"] = host_installation().authority_provider
    return _execute_exclusive_create(*args, **kwargs)  # type: ignore[arg-type]


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def snapshot_tree(root: Path) -> tuple[tuple[str, str, int | None, str | None], ...]:
    rows: list[tuple[str, str, int | None, str | None]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows.append((relative, "symlink", None, os.readlink(path)))
        elif path.is_dir():
            rows.append((relative, "dir", None, None))
        elif path.is_file():
            data = path.read_bytes()
            rows.append((relative, "file", len(data), _sha256(data)))
        else:
            rows.append((relative, "special", None, None))
    return tuple(rows)


def _race_worker(effect: dict[str, object], target: str, payload: bytes, barrier: object, queue: object) -> None:
    barrier.wait()  # type: ignore[attr-defined]
    receipt = execute_exclusive_create(effect, Path(target), payload, run_id=f"race-{os.getpid()}", timestamp=NOW)
    queue.put(receipt)  # type: ignore[attr-defined]


def write_create_candidate(path: Path, *, locator: str = "objects/item.bin", key: str = "create-key-1") -> None:
    path.write_text(
        json.dumps(
            {
                "operation_id": "operation-1",
                "target_locator": locator,
                "input_binding": "payload",
                "idempotency_key": key,
            }
        ),
        encoding="utf-8",
    )


def create_request(tmp_path: Path, *, run_id: str, locator: str = "objects/item.bin") -> tuple[PhaseRequest, Path, Path, bytes]:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    target = tmp_path / "target"
    target.mkdir()
    (target / "objects").mkdir()
    (target / "canary.txt").write_bytes(b"nonempty-canary")
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "candidate.json"
    write_create_candidate(candidate, locator=locator)
    payload = tmp_path / "payload.bin"
    payload_bytes = b"\x00binary\r\npayload\xff"
    payload.write_bytes(payload_bytes)
    request = PhaseRequest(
        contract_id="fixture_create.v1",
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths={"payload": payload},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )
    return request, target, evidence, payload_bytes


def test_bundled_stage3_fixture_data_matches_declared_schemas_and_bytes() -> None:
    registry = BundledRegistry.load()
    contract_binding = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    contract = registry.resolve_contract(
        "fixture_create.v1", "1.0.0", contract_binding["package_digest"], core_version="1.0.0"
    )
    candidate = json.loads((ROOT / "fixtures" / "stage3" / "create-candidate.valid.json").read_bytes())
    result = json.loads((ROOT / "fixtures" / "stage3" / "create-result.valid.json").read_bytes())
    payload = (ROOT / "fixtures" / "stage3" / "create-payload.bin").read_bytes()
    Draft202012Validator(registry.schema_document(
        contract.document["candidate"]["schema_ref"], contract.document["candidate"]["schema_digest"]
    )).validate(candidate)
    Draft202012Validator(registry.schema_document(
        contract.document["canonical_result"]["result_schema_ref"],
        contract.document["canonical_result"]["result_schema_digest"],
    )).validate(result)
    assert result == {"locator": "objects/item.bin", "digest": _sha256(payload), "length": len(payload)}


def test_fixture_create_validate_plans_one_bound_effect_without_target_mutation(tmp_path: Path) -> None:
    request, target, _evidence, payload = create_request(tmp_path, run_id="create-plan")
    before = snapshot_tree(target)

    outcome = PhaseCore().run(request)

    assert outcome.exit_code == 0
    assert outcome.receipt["terminal_status"] == "validated_planned"
    assert outcome.receipt["mutation_attempted"] is False
    assert snapshot_tree(target) == before
    assert outcome.effect_plan is not None
    assert len(outcome.effect_plan["effects"]) == 1
    effect = outcome.effect_plan["effects"][0]
    assert effect["kind"] == "exclusive_create"
    assert effect["target"] == {"root_binding": "fixture_result_root", "relative_locator": "objects/item.bin"}
    assert effect["content_source"] == {
        "kind": "frozen_input",
        "binding_id": "payload",
        "source_digest": _sha256(payload),
    }
    assert effect["content_digest"] == _sha256(payload)
    assert effect["content_length"] == len(payload)


def test_execute_exclusive_create_writes_exact_bytes_and_verified_receipts(tmp_path: Path) -> None:
    request, target, evidence, payload = create_request(tmp_path, run_id="create-success")
    before = snapshot_tree(target)

    outcome = PhaseCore().run(request, execute=True)

    destination = target / "objects" / "item.bin"
    assert outcome.exit_code == 0
    assert destination.read_bytes() == payload
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert outcome.receipt["execution_disposition"] == "executed"
    assert outcome.receipt["mutation_attempted"] is True
    assert outcome.receipt["result_state"] == "verified_result"
    assert outcome.receipt["canonical_result"]["locator"] == "objects/item.bin"
    assert outcome.receipt["canonical_result"]["state"] == {
        "exists": True,
        "digest": _sha256(payload),
        "length": len(payload),
        "head_token": None,
    }
    assert len(outcome.receipt["effect_receipts"]) == 1
    effect_receipt = outcome.receipt["effect_receipts"][0]
    assert effect_receipt["status"] == "applied_verified"
    assert effect_receipt["attempted"] is True
    assert effect_receipt["bytes_written"] == len(payload)
    assert effect_receipt["before"]["exists"] is False
    assert effect_receipt["after"]["digest"] == _sha256(payload)
    run_root = evidence / ".phase" / "runs" / "create-success"
    assert (run_root / "intent.json").is_file()
    assert (run_root / "attachments" / "effect-receipts.json").is_file()
    assert (run_root / "receipt.json").is_file()
    expected_after = tuple(sorted((*before, ("objects/item.bin", "file", len(payload), _sha256(payload)))))
    assert snapshot_tree(target) == expected_after

    registry = BundledRegistry.load()
    checks = [
        ("https://phase-tool.local/schemas/phase-intent.schema.json", json.loads((run_root / "intent.json").read_bytes())),
        ("https://phase-tool.local/schemas/effect-receipt.schema.json", json.loads((run_root / "attachments" / "effect-receipts.json").read_bytes())[0]),
        ("https://phase-tool.local/schemas/phase-receipt.schema.json", json.loads((run_root / "receipt.json").read_bytes())),
    ]
    for schema_ref, value in checks:
        Draft202012Validator(
            registry.schema_document(schema_ref),
            registry=registry.schema_registry(),
            format_checker=FormatChecker(),
        ).validate(value)


def test_executed_receipt_schema_requires_durable_intent_digest(tmp_path: Path) -> None:
    request, _target, _evidence, _payload = create_request(tmp_path, run_id="intent-schema")
    outcome = PhaseCore().run(request, execute=True)
    invalid = deepcopy(outcome.receipt)
    invalid["evidence"]["intent_digest"] = None
    registry = BundledRegistry.load()
    validator = Draft202012Validator(
        registry.schema_document("https://phase-tool.local/schemas/phase-receipt.schema.json"),
        registry=registry.schema_registry(),
        format_checker=FormatChecker(),
    )

    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_cli_validate_plan_execute_and_inspect_fixture_create(tmp_path: Path) -> None:
    request, target, evidence, payload = create_request(tmp_path, run_id="unused")
    phase = [sys.executable, "-m", "phase_tool"]
    common = [
        "--contract-id", request.contract_id,
        "--contract-version", request.contract_version,
        "--contract-digest", request.contract_digest,
        "--candidate", str(request.candidate_path),
        "--evidence-root", str(evidence),
        "--input", f"payload={request.input_paths['payload']}",
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    ]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    before = snapshot_tree(target)
    outputs: dict[str, dict[str, object]] = {}
    for command in ("validate", "plan"):
        process = subprocess.run(
            [*phase, command, *common, "--run-id", f"cli-{command}"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert process.returncode == 0, process.stderr
        outputs[command] = json.loads(process.stdout)
        assert snapshot_tree(target) == before
    execute = subprocess.run(
        [*phase, "execute", *common, "--run-id", "cli-execute"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert execute.returncode == 0, execute.stderr
    outputs["execute"] = json.loads(execute.stdout)
    assert outputs["execute"]["mutation_attempted"] is True
    assert (target / "objects" / "item.bin").read_bytes() == payload
    inspect = subprocess.run(
        [
            *phase,
            "inspect",
            "--evidence-root", str(evidence),
            "--run-id", "cli-execute",
            "--root", f"fixture_result_root={target}",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert inspect.returncode == 0, inspect.stderr
    outputs["inspect"] = json.loads(inspect.stdout)
    assert outputs["inspect"]["terminal_status"] == "succeeded_verified"
    assert outputs["validate"]["terminal_status"] == outputs["plan"]["terminal_status"] == "validated_planned"


def test_inspect_revalidates_verified_target_and_detects_target_tampering(tmp_path: Path) -> None:
    request, target, evidence, _payload = create_request(tmp_path, run_id="create-inspect")
    outcome = PhaseCore().run(request, execute=True)
    assert outcome.exit_code == 0

    from phase_tool.inspection import inspect_run

    inspected = inspect_run(evidence, "create-inspect", root_bindings={"fixture_result_root": target})
    assert inspected["terminal_status"] == "succeeded_verified"
    assert inspected["target_verified"] is True

    (target / "objects" / "item.bin").write_bytes(b"tampered")
    with pytest.raises(Exception, match="inspection.target_mismatch"):
        inspect_run(evidence, "create-inspect", root_bindings={"fixture_result_root": target})


@pytest.mark.parametrize(
    "locator",
    [
        "/absolute.bin",
        "objects/../escape.bin",
        "objects/./dot.bin",
        "objects\\backslash.bin",
        "C:/drive.bin",
        "//server/share.bin",
        "objects/CON.txt",
        "\\\\?\\C:\\device.bin",
    ],
)
def test_invalid_locators_are_rejected_without_target_mutation(tmp_path: Path, locator: str) -> None:
    request, target, _evidence, _payload = create_request(tmp_path, run_id="invalid-locator", locator=locator)
    before = snapshot_tree(target)

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.exit_code != 0
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert snapshot_tree(target) == before


def test_wrong_exact_contract_binding_is_rejected_without_target_mutation(tmp_path: Path) -> None:
    request, target, _evidence, _payload = create_request(tmp_path, run_id="wrong-binding")
    before = snapshot_tree(target)
    wrong = replace(request, contract_digest="sha256:" + "0" * 64)

    outcome = PhaseCore().run(wrong, execute=True)

    assert outcome.exit_code != 0
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert snapshot_tree(target) == before


def test_existing_different_destination_is_never_replaced(tmp_path: Path) -> None:
    request, target, _evidence, _payload = create_request(tmp_path, run_id="no-replace")
    destination = target / "objects" / "item.bin"
    destination.write_bytes(b"pre-existing-different")
    before = snapshot_tree(target)

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.exit_code != 0
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["blockers"] == ["target.destination_exists"]
    assert destination.read_bytes() == b"pre-existing-different"
    assert snapshot_tree(target) == before


def test_evidence_target_lexical_alias_is_rejected_before_write(tmp_path: Path) -> None:
    request, target, _evidence, _payload = create_request(tmp_path, run_id="alias-overlap")
    alias = target.parent / "sibling" / ".." / target.name / "evidence-alias"
    before = snapshot_tree(target)

    with pytest.raises(PhaseError, match="evidence.overlaps_target_root"):
        PhaseCore().run(replace(request, evidence_root=alias), execute=True)

    assert snapshot_tree(target) == before
    assert not (target / "evidence-alias").exists()


def test_same_key_different_request_digest_conflicts_before_mutation(tmp_path: Path) -> None:
    first, target, evidence, _payload = create_request(tmp_path, run_id="idempotency-first")
    planned = PhaseCore().run(first)
    assert planned.exit_code == 0
    before = snapshot_tree(target)
    first.input_paths["payload"].write_bytes(b"different-payload")
    second = replace(first, run_id="idempotency-second", evidence_root=evidence)

    outcome = PhaseCore().run(second, execute=True)

    assert outcome.receipt["blockers"] == ["idempotency.same_key_conflict"]
    assert outcome.receipt["mutation_attempted"] is False
    assert snapshot_tree(target) == before


def _stage2_execute_request(tmp_path: Path, contract_id: str) -> tuple[PhaseRequest, Path]:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()[f"{contract_id}@1.0.0"]
    target = tmp_path / f"{contract_id}-target"
    target.mkdir()
    (target / "canary").write_bytes(b"unchanged")
    candidate = tmp_path / f"{contract_id}.json"
    inputs: dict[str, Path] = {}
    if contract_id == "fixture_append.v1":
        (target / "streams").mkdir()
        candidate.write_text(json.dumps({
            "stream_id": "alpha",
            "target_locator": "streams/alpha.jsonl",
            "record_id": "record-1",
            "expected_head": None,
            "record": {"value": 1},
            "idempotency_key": "append-key",
        }), encoding="utf-8")
    else:
        (target / "objects").mkdir()
        candidate.write_text(json.dumps({
            "transfer_id": "transfer-1",
            "object_id": "object-1",
            "input_binding": "payload",
            "destinations": ["objects/a"],
            "idempotency_key": "copy-key",
        }), encoding="utf-8")
        payload = tmp_path / "copy-payload.bin"
        payload.write_bytes(b"copy-payload")
        inputs["payload"] = payload
    return PhaseRequest(
        contract_id=contract_id,
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=tmp_path / f"{contract_id}-evidence",
        run_id=f"{contract_id}-execute",
        input_paths=inputs,
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    ), target


def test_fixture_append_execute_is_active_in_stage4(tmp_path: Path) -> None:
    request, target = _stage2_execute_request(tmp_path, "fixture_append.v1")

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.exit_code == 0
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert outcome.receipt["mutation_attempted"] is True
    assert (target / "streams" / "alpha.jsonl").read_bytes() == b'{"value":1}\n'


def test_copy_execute_is_active_in_stage5(tmp_path: Path) -> None:
    request, target = _stage2_execute_request(tmp_path, "fixture_copy.v1")

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.exit_code == 0
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert outcome.receipt["mutation_attempted"] is True
    assert outcome.receipt["canonical_result"]["locator"].startswith("objects/")


def test_execution_persists_durable_intent_plan_and_receipt(tmp_path: Path) -> None:
    request, target, evidence, _payload = create_request(tmp_path, run_id="intent-before")
    destination = target / "objects" / "item.bin"
    outcome = PhaseCore().run(request, execute=True)
    run_root = evidence / ".phase" / "runs" / "intent-before"

    assert outcome.exit_code == 0
    assert (run_root / "intent.json").read_bytes().endswith(b"}")
    assert (run_root / "attachments" / "effect-plan.json").is_file()
    assert (run_root / "receipt.json").is_file()
    assert destination.is_file()


def test_external_write_callback_is_rejected_before_invocation(tmp_path: Path) -> None:
    request, target, _evidence, _payload = create_request(tmp_path, run_id="race-no-effect")
    destination = target / "objects" / "item.bin"

    def external_winner(_intent_path: Path) -> None:
        destination.write_bytes(b"external-winner")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_mechanism=external_winner)),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not destination.exists()


def test_real_short_writes_are_retried_until_exact_verified_result(tmp_path: Path) -> None:
    request, target, _evidence, payload = create_request(tmp_path, run_id="short-writes")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                exclusive_create=ExclusiveCreateFaults(maximum_write_size=1)
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert outcome.receipt["effect_receipts"][0]["bytes_written"] == len(payload)
    assert (target / "objects" / "item.bin").read_bytes() == payload


def test_failure_after_creation_preserves_observable_partial_file(tmp_path: Path) -> None:
    request, target, _evidence, payload = create_request(tmp_path, run_id="partial")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                exclusive_create=ExclusiveCreateFaults(fail_after_bytes=5)
            )
        ),
    )

    destination = target / "objects" / "item.bin"
    assert outcome.receipt["terminal_status"] == "failed_partial"
    assert outcome.receipt["result_state"] == "known_partial"
    assert outcome.receipt["canonical_result"] is None
    assert outcome.receipt["effect_receipts"][0]["bytes_written"] == 5
    assert destination.read_bytes() == payload[:5]


def test_readback_mismatch_is_committed_unverified_not_success(tmp_path: Path) -> None:
    request, target, _evidence, payload = create_request(tmp_path, run_id="mismatch")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                exclusive_create=ExclusiveCreateFaults(readback_override=b"mismatch")
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "committed_unverified"
    assert outcome.receipt["result_state"] == "committed_unverified"
    assert outcome.receipt["effect_receipts"][0]["status"] == "applied_unverified"
    assert (target / "objects" / "item.bin").read_bytes() == payload


def test_readback_failure_is_indeterminate_not_success(tmp_path: Path) -> None:
    request, target, _evidence, payload = create_request(tmp_path, run_id="indeterminate")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                exclusive_create=ExclusiveCreateFaults(readback_error=True)
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "indeterminate"
    assert outcome.receipt["result_state"] == "indeterminate"
    assert outcome.receipt["canonical_result"] is None
    assert outcome.receipt["effect_receipts"][0]["after"] == {
        "known": False,
        "exists": None,
        "digest": None,
        "length": None,
        "head_token": None,
    }
    assert (target / "objects" / "item.bin").read_bytes() == payload


def test_receipt_finalization_failure_leaves_intent_without_durable_receipt(tmp_path: Path) -> None:
    request, target, evidence, payload = create_request(tmp_path, run_id="receipt-failure")

    outcome = PhaseCore().run(request, execute=True, faults=CoreFaults(fail_receipt_write=True))

    run_root = evidence / ".phase" / "runs" / "receipt-failure"
    assert outcome.receipt["terminal_status"] == "committed_unverified"
    assert outcome.receipt["evidence"]["finalization_status"] == "failed"
    assert outcome.receipt_digest is None
    assert (run_root / "intent.json").is_file()
    assert (run_root / "attachments" / "effect-receipts.json").is_file()
    assert not (run_root / "receipt.json").exists()
    assert (target / "objects" / "item.bin").read_bytes() == payload

    from phase_tool.inspection import inspect_run

    inspected = inspect_run(evidence, "receipt-failure")
    assert inspected["receipt_present"] is False
    assert inspected["intent_present"] is True
    assert inspected["inspection_required"] is True
    assert inspected["terminal_status"] is None


@pytest.mark.parametrize(
    ("failure_path", "error_kind"),
    [
        ("attachments/validator-results.json", "phase"),
        ("receipt.json", "os"),
    ],
)
def test_transient_post_mutation_evidence_failure_finalizes_truthful_recovery_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_path: str,
    error_kind: str,
) -> None:
    request, target, evidence, payload = create_request(
        tmp_path,
        run_id=f"real-finalization-{error_kind}",
    )
    original = EvidenceStore.write_canonical
    injected = False

    def failing_write(store: EvidenceStore, relative: str, value: object):
        nonlocal injected
        if relative == failure_path and not injected:
            injected = True
            if error_kind == "phase":
                raise PhaseError("evidence.short_write", relative)
            raise OSError("injected evidence publication failure")
        return original(store, relative, value)

    monkeypatch.setattr(EvidenceStore, "write_canonical", failing_write)
    outcome = PhaseCore().run(request, execute=True)
    run_root = evidence / ".phase" / "runs" / request.run_id

    assert injected is True
    assert (target / "objects" / "item.bin").read_bytes() == payload
    assert outcome.receipt["terminal_status"] == "committed_unverified"
    assert outcome.receipt["execution_disposition"] == "executed"
    assert outcome.receipt["mutation_attempted"] is True
    assert outcome.receipt["result_state"] == "committed_unverified"
    assert outcome.receipt["effect_receipts"][0]["status"] == "applied_verified"
    assert outcome.receipt["evidence"]["finalization_status"] == "failed"
    assert outcome.receipt["evidence"]["required_attachments_present"] is True
    assert outcome.receipt["blockers"] == ["evidence.finalization_failed"]
    assert outcome.receipt_digest is not None
    assert (run_root / "intent.json").is_file()
    assert json.loads((run_root / "receipt.json").read_bytes()) == outcome.receipt

    from phase_tool.inspection import inspect_run

    inspected = inspect_run(evidence, request.run_id, root_bindings=request.root_bindings)
    assert inspected["receipt_present"] is True
    assert inspected["intent_present"] is True
    assert inspected["terminal_status"] == "committed_unverified"


def test_plan_cannot_expand_after_durable_intent(tmp_path: Path) -> None:
    request, target, evidence, _payload = create_request(tmp_path, run_id="plan-expansion")
    before = snapshot_tree(target)

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(mutate_plan_after_intent=True)),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["blockers"] == ["broker.plan_changed_after_intent"]
    assert (evidence / ".phase" / "runs" / "plan-expansion" / "intent.json").is_file()
    assert snapshot_tree(target) == before


def test_reparse_policy_seam_rejects_before_open(tmp_path: Path) -> None:
    request, target, _evidence, _payload = create_request(tmp_path, run_id="reparse-seam")
    before = snapshot_tree(target)

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                exclusive_create=ExclusiveCreateFaults(
                    reparse_detector=lambda path: path.name == "objects"
                )
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert snapshot_tree(target) == before


def test_two_processes_racing_exclusive_create_have_exactly_one_winner(tmp_path: Path) -> None:
    request, target, _evidence, payload = create_request(tmp_path, run_id="race-plan")
    planned = PhaseCore().run(request)
    assert planned.effect_plan is not None
    effect = planned.effect_plan["effects"][0]
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(3)
    queue = context.Queue()
    workers = [
        context.Process(target=_race_worker, args=(effect, str(target), payload, barrier, queue))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=20)
    receipts = [queue.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    statuses = sorted(item["status"] for item in receipts)
    assert statuses == ["applied_verified", "failed_no_effect"]
    assert sum(item["bytes_written"] == len(payload) for item in receipts) == 1
    assert (target / "objects" / "item.bin").read_bytes() == payload


def test_inspection_rejects_effect_receipt_set_not_equal_to_static_plan(tmp_path: Path) -> None:
    request, target, evidence, _payload = create_request(tmp_path, run_id="receipt-set")
    outcome = PhaseCore().run(request, execute=True)
    assert outcome.exit_code == 0
    run_root = evidence / ".phase" / "runs" / "receipt-set"
    effect_path = run_root / "attachments" / "effect-receipts.json"
    receipt_path = run_root / "receipt.json"
    old_effect_bytes = effect_path.read_bytes()
    effect_receipts = json.loads(old_effect_bytes)
    duplicate = dict(effect_receipts[0])
    duplicate["effect_id"] = "effect.unplanned.002"
    effect_receipts.append(duplicate)
    new_effect_bytes = json.dumps(effect_receipts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    effect_path.write_bytes(new_effect_bytes)
    receipt = json.loads(receipt_path.read_bytes())
    receipt["effect_receipts"] = effect_receipts
    old_digest = _sha256(old_effect_bytes)
    receipt["evidence"]["attachment_digests"].remove(old_digest)
    receipt["evidence"]["attachment_digests"].append(_sha256(new_effect_bytes))
    receipt["evidence"]["attachment_digests"].sort()
    receipt_path.write_bytes(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())

    from phase_tool.inspection import inspect_run

    with pytest.raises(PhaseError, match="inspection.effect_receipt_set_mismatch"):
        inspect_run(evidence, "receipt-set", root_bindings={"fixture_result_root": target})
