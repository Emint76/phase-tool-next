from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.evidence import operational_lock_path
from phase_tool.inspection import inspect_run
from phase_tool.mutation import AppendRecordFaults, BrokerFaults
from phase_tool.append_codec import absent_head_token, stream_head_token
from phase_tool.mutation.expected_head_append import append_head_token, execute_append_record
from phase_tool.mutation.platform import HostTargetAuthority
from phase_tool.registry import BundledRegistry
from phase_tool.contracts.task_journal_v1 import finalize_record

NOW = "2026-07-27T04:00:00Z"
ROOT = Path(__file__).resolve().parents[1]


def _binding(contract_id: str) -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()[f"{contract_id}@1.0.0"]


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _request(contract_id: str, candidate: Path, evidence: Path, target: Path, run_id: str) -> PhaseRequest:
    binding = _binding(contract_id)
    return PhaseRequest(
        contract_id=contract_id,
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths={},
        root_bindings={"fixture_result_root": target, "task_journal_root": target},
        timestamp=NOW,
    )


def write_append_candidate(path: Path, *, expected_head: str | None, key: str = "append-key", value: int = 1) -> bytes:
    value_obj = {
        "stream_id": "alpha",
        "target_locator": "streams/alpha.jsonl",
        "record_id": f"record-{value}",
        "expected_head": expected_head,
        "record": {"value": value},
        "idempotency_key": key,
    }
    path.write_text(json.dumps(value_obj), encoding="utf-8")
    return canonical_bytes(value_obj["record"]) + b"\n"


def write_task_candidate(path: Path, *, action: str, task_id: str = "task-1", key: str, expected_head: str | None, **extra: object) -> None:
    candidate = {"task_id": task_id, "action": action, "expected_head": expected_head, "idempotency_key": key, "operation_id": key} | extra
    path.write_text(json.dumps(candidate), encoding="utf-8")


def _lock_root(tmp_path: Path) -> Path:
    return tmp_path / "evidence" / ".phase" / "locks"


def test_literal_golden_head_token_vectors_are_independent_of_runtime_files() -> None:
    first = b'{"value":1}\n'
    second = b'{"value":2}\n'
    assert absent_head_token() == "sha256:2bd89360e314858b0b5a052910b22a13baecd6e04b470a4e9342586424213673"
    assert stream_head_token(b"") == "sha256:4326c559c44521a2682592ed02c6e3ddd5ef35b6e6cafab9e9ab60cea5c75ea4"
    assert stream_head_token(first) == "sha256:c49ada27666d10c63f10b0ff36f73fa91074dc5766b2537f36d5f08c859657f8"
    assert stream_head_token(first + second) == "sha256:10abd40f09bae2cec1152d7e46dc1424f351683e90a2f8ffb5e0ddb7da0f8f27"
    assert stream_head_token(second + first) != stream_head_token(first + second)
    with pytest.raises(PhaseError, match="input.invalid_tail"):
        stream_head_token(first[:-1])
    with pytest.raises(PhaseError, match="codec.crlf_forbidden|codec.record_crlf_forbidden"):
        stream_head_token(b'{"value":1}\r\n')
    with pytest.raises(PhaseError, match="codec.blank_record"):
        stream_head_token(b"\n")
    with pytest.raises(PhaseError, match="codec.record_noncanonical"):
        stream_head_token(b'{ "value" : 1 } \n')


def test_append_fixture_create_then_append_exact_bytes_and_no_rewrite(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    first_candidate = tmp_path / "first.json"
    first_record = write_append_candidate(first_candidate, expected_head=None, value=1)
    planned = PhaseCore().run(_request("fixture_append.v1", first_candidate, evidence, target, "first-plan"))
    assert planned.effect_plan is not None
    assert planned.effect_plan["effects"][0]["kind"] == "append_record"
    write_append_candidate(first_candidate, expected_head=None, key="append-key-execute", value=1)
    first = PhaseCore().run(_request("fixture_append.v1", first_candidate, evidence, target, "first"), execute=True)
    stream = target / "streams" / "alpha.jsonl"
    assert first.exit_code == 0
    assert first.receipt["terminal_status"] == "succeeded_verified"
    assert stream.read_bytes() == first_record
    assert first.effect_plan["effects"][0]["record_identity"] == "record-1"
    assert first.receipt["canonical_result"]["appended_record"]["record_identity"] == "record-1"
    head1 = first.receipt["canonical_result"]["state"]["head_token"]

    before = stream.read_bytes()
    second_candidate = tmp_path / "second.json"
    second_record = write_append_candidate(second_candidate, expected_head=head1, key="append-key-2", value=2)
    second = PhaseCore().run(_request("fixture_append.v1", second_candidate, evidence, target, "second"), execute=True)

    assert second.exit_code == 0
    assert stream.read_bytes() == before + second_record
    assert second.receipt["effect_receipts"][0]["before"]["length"] == len(before)
    assert second.receipt["effect_receipts"][0]["after"]["length"] == len(before) + len(second_record)
    assert second.receipt["canonical_result"]["state"]["head_token"] != head1


def test_append_plan_blob_is_durable_and_fault_tampering_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    planned_record = write_append_candidate(candidate, expected_head=None, key="blob", value=1)

    outcome = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "blob-ok"), execute=True)
    assert outcome.exit_code == 0
    run_root = evidence / ".phase" / "runs" / "blob-ok"
    intent = parse_json_bytes((run_root / "intent.json").read_bytes())
    plan = parse_json_bytes((run_root / "attachments" / "effect-plan.json").read_bytes())
    effect = plan["effects"][0]
    blob_digest = effect["content_blob_digest"]
    blob = run_root / "blobs" / blob_digest.split(":", 1)[1]
    assert effect["content_digest"] == blob_digest
    assert intent["evidence"]["content_blob_digests"] == [blob_digest]
    assert blob.read_bytes() == planned_record
    assert digest_bytes(blob.read_bytes()) == blob_digest

    for case, tamper in (
        ("plan", lambda run_root: (run_root / "attachments" / "effect-plan.json").write_bytes((run_root / "attachments" / "effect-plan.json").read_bytes() + b" ")),
        ("blob", lambda run_root: (run_root / "blobs" / _sha(planned_record).split(":", 1)[1]).write_bytes(b'{"value":999}\n')),
    ):
        target_case = tmp_path / f"target-{case}"
        (target_case / "streams").mkdir(parents=True)
        evidence_case = tmp_path / f"evidence-{case}"
        write_append_candidate(candidate, expected_head=None, key=f"blob-{case}", value=1)

        def tamper_before_mechanism(intent_path: Path, tamper=tamper) -> None:  # type: ignore[no-untyped-def]
            tamper(intent_path.parent)

        rejected = PhaseCore().run(
            _request("fixture_append.v1", candidate, evidence_case, target_case, f"blob-{case}"),
            execute=True,
            faults=CoreFaults(broker=BrokerFaults(before_mechanism=tamper_before_mechanism)),
        )
        assert rejected.receipt["terminal_status"] == "rejected"
        assert rejected.receipt["mutation_attempted"] is False
        assert rejected.receipt["blockers"] == ["broker.unsafe_fault_callback"]
        assert not (target_case / "streams" / "alpha.jsonl").exists()


def test_phase_intent_records_execution_requested_and_broker_refuses_false_execute_intent(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="intent-mode", value=1)

    planned = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "planned"), execute=False)
    assert planned.intent is not None
    assert planned.intent["execution_requested"] is False
    write_append_candidate(candidate, expected_head=None, key="intent-mode-exec", value=1)
    executed = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "executed"), execute=True)
    assert executed.intent is not None
    assert executed.intent["execution_requested"] is True

    tampered_target = tmp_path / "tampered-target"
    (tampered_target / "streams").mkdir(parents=True)
    tampered_evidence = tmp_path / "tampered-evidence"
    write_append_candidate(candidate, expected_head=None, key="intent-mode-tamper", value=1)

    def mark_dry_run(intent_path: Path) -> None:
        intent = parse_json_bytes(intent_path.read_bytes())
        intent["execution_requested"] = False
        intent_path.write_bytes(canonical_bytes(intent))

    rejected = PhaseCore().run(
        _request("fixture_append.v1", candidate, tampered_evidence, tampered_target, "tampered"),
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_mechanism=mark_dry_run)),
    )
    assert rejected.receipt["terminal_status"] == "rejected"
    assert rejected.receipt["mutation_attempted"] is False
    assert rejected.receipt["blockers"] == ["broker.unsafe_fault_callback"]


def test_broker_does_not_call_exclusive_create_for_initial_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.mutation.broker as broker_module

    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    candidate = tmp_path / "first.json"
    write_append_candidate(candidate, expected_head=None, value=1)

    def forbidden_create(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("append broker crossed exclusive_create boundary")

    monkeypatch.setattr(broker_module, "execute_exclusive_create", forbidden_create)
    outcome = PhaseCore().run(
        _request("fixture_append.v1", candidate, tmp_path / "evidence", target, "initial-boundary"),
        execute=True,
    )

    assert outcome.receipt["terminal_status"] == "succeeded_verified"


def test_append_race_callback_is_rejected_without_mutation(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    stream = target / "streams" / "alpha.jsonl"
    original = b'{"value":0}\n'
    stream.write_bytes(original)
    stale = stream_head_token(original)
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=stale, key="stale", value=2)

    def race(_intent: Path) -> None:
        stream.write_bytes(original + b'{"value":99}\n')

    outcome = PhaseCore().run(
        _request("fixture_append.v1", candidate, tmp_path / "evidence", target, "stale"),
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_mechanism=race)),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert stream.read_bytes() == original


def test_append_short_write_loop_and_partial_torn_tail_are_truthful(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(b'{"value":1}\n'),
        "content_length": len(b'{"value":1}\n'),
        "preconditions": {"expected_head": stream_head_token(b"")},
        "lock_scope": "stream.alpha",
    }
    (target / "stream.jsonl").write_bytes(b"")
    calls: list[int] = []

    def short_writer(descriptor: int, data: memoryview) -> int:
        calls.append(len(data))
        return os.write(descriptor, data[:1])

    ok = execute_append_record(
        effect,
        target,
        b'{"value":1}\n',
        run_id="short",
        timestamp=NOW,
        operational_lock_root=_lock_root(tmp_path),
        expected_head_override=stream_head_token(b""),
        faults=AppendRecordFaults(write_primitive=short_writer),
    )
    assert ok["status"] == "applied_verified"
    assert len(calls) > 1

    partial_target = tmp_path / "partial"
    partial_target.mkdir()
    (partial_target / "stream.jsonl").write_bytes(b"")
    torn = execute_append_record(
        effect,
        partial_target,
        b'{"value":1}\n',
        run_id="partial",
        timestamp=NOW,
        operational_lock_root=_lock_root(tmp_path),
        expected_head_override=stream_head_token(b""),
        faults=AppendRecordFaults(fail_after_bytes=4),
    )
    assert torn["status"] == "failed_partial"
    assert torn["bytes_written"] == 4
    assert (partial_target / "stream.jsonl").read_bytes() == b'{"va'


def test_append_uses_evidence_lock_root_and_does_not_write_target_lock_file(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    lock_root = tmp_path / "evidence" / ".phase" / "locks"
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": None},
        "lock_scope": "stream.alpha",
    }

    receipt = execute_append_record(effect, target, record, run_id="lock-root", timestamp=NOW, operational_lock_root=lock_root)

    assert receipt["status"] == "applied_verified"
    assert not (target / "stream.jsonl.lock").exists()
    assert list(lock_root.rglob("*.lock"))


def test_append_rejects_rebound_root_handle_before_target_creation(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    target_info = target.stat()
    expected_root_identity = (int(target_info.st_dev), int(target_info.st_ino))
    target.rename(tmp_path / "displaced")
    target.mkdir()
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "nested/stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": None},
        "lock_scope": "stream.alpha",
    }

    with pytest.raises(PhaseError) as exc_info:
        execute_append_record(
            effect,
            target,
            record,
            run_id="rebound-root",
            timestamp=NOW,
            operational_lock_root=_lock_root(tmp_path),
            expected_root_identity=expected_root_identity,
        )

    assert exc_info.value.code == "broker.root_identity_mismatch"
    assert not (target / "nested").exists()


def test_append_namespace_drift_after_fsync_returns_truthful_partial_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": None},
        "lock_scope": "stream.alpha",
    }
    original = HostTargetAuthority.assert_namespace_binding
    calls = 0

    def drift_after_write(authority: HostTargetAuthority) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PhaseError("path.parent_identity_changed")
        original(authority)

    monkeypatch.setattr(HostTargetAuthority, "assert_namespace_binding", drift_after_write)
    receipt = execute_append_record(
        effect,
        target,
        record,
        run_id="post-fsync-drift",
        timestamp=NOW,
        operational_lock_root=_lock_root(tmp_path),
    )

    assert calls == 2
    assert receipt["status"] == "failed_partial"
    assert receipt["attempted"] is True
    assert receipt["bytes_written"] == len(record)
    assert receipt["error"]["code"] == "path.parent_identity_changed"
    assert (target / "stream.jsonl").read_bytes() == record


def test_append_readback_uses_captured_before_bytes_not_observed_override(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    record = b'{"value":1}\n'
    existing = b'{"value":0}\n'
    (target / "stream.jsonl").write_bytes(existing)
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": stream_head_token(existing)},
        "lock_scope": "stream.alpha",
    }
    override = b'{"value":999}\n' + record

    receipt = execute_append_record(
        effect,
        target,
        record,
        run_id="readback-mismatch",
        timestamp=NOW,
        operational_lock_root=_lock_root(tmp_path),
        faults=AppendRecordFaults(readback_override=override),
    )

    assert receipt["status"] == "applied_unverified"
    assert receipt["error"]["code"] == "verification.result_mismatch"


def test_append_readback_error_and_receipt_finalization_failure_are_unverified(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="readback-error", value=1)

    readback = PhaseCore().run(
        _request("fixture_append.v1", candidate, evidence, target, "readback-error"),
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(append_record=AppendRecordFaults(readback_error=True))),
    )
    assert readback.receipt["terminal_status"] == "indeterminate"
    assert readback.receipt["effect_receipts"][0]["error"]["code"] == "verification.readback_failed"

    target2 = tmp_path / "target2"
    (target2 / "streams").mkdir(parents=True)
    evidence2 = tmp_path / "evidence2"
    write_append_candidate(candidate, expected_head=None, key="finalization-failure", value=1)
    unfinalized = PhaseCore().run(
        _request("fixture_append.v1", candidate, evidence2, target2, "finalization-failure"),
        execute=True,
        faults=CoreFaults(fail_receipt_write=True),
    )
    assert unfinalized.receipt["terminal_status"] == "committed_unverified"
    assert unfinalized.receipt_digest is None


def test_same_key_same_digest_reuses_only_verified_prior_receipt_and_revalidates_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="same", value=1)
    first = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "first"), execute=True)
    assert first.exit_code == 0
    before = (target / "streams" / "alpha.jsonl").read_bytes()

    second = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "second"), execute=True)

    assert second.exit_code == 0
    assert second.receipt["execution_disposition"] == "reused_existing"
    assert second.receipt["mutation_attempted"] is False
    assert second.receipt["prior_verified_receipt_digest"] == first.receipt_digest
    assert (target / "streams" / "alpha.jsonl").read_bytes() == before

    (target / "streams" / "alpha.jsonl").write_bytes(b"tampered\n")
    third = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "third"), execute=True)
    assert third.receipt["terminal_status"] == "rejected"
    assert third.receipt["blockers"] == ["idempotency.prior_result_changed"]


def test_same_key_same_bytes_different_resolved_target_root_does_not_reuse(tmp_path: Path) -> None:
    target_a = tmp_path / "target-a"
    target_b = tmp_path / "target-b"
    (target_a / "streams").mkdir(parents=True)
    (target_b / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="root-bound", value=1)
    first = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target_a, "root-a"), execute=True)
    assert first.exit_code == 0
    (target_b / "streams" / "alpha.jsonl").write_bytes((target_a / "streams" / "alpha.jsonl").read_bytes())

    second = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target_b, "root-b"), execute=True)

    assert second.receipt["execution_disposition"] != "reused_existing"
    assert second.receipt["terminal_status"] in {"failed_no_effect", "rejected"}


def test_same_key_same_digest_reuses_after_later_append_and_refuses_incomplete_prior(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="same", value=1)
    first = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "first"), execute=True)
    assert first.exit_code == 0
    head1 = first.receipt["canonical_result"]["state"]["head_token"]
    second_candidate = tmp_path / "second.json"
    write_append_candidate(second_candidate, expected_head=head1, key="second", value=2)
    assert PhaseCore().run(_request("fixture_append.v1", second_candidate, evidence, target, "second"), execute=True).exit_code == 0
    before_reuse = (target / "streams" / "alpha.jsonl").read_bytes()

    reused = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "reuse-after-later"), execute=True)

    assert reused.receipt["terminal_status"] == "succeeded_verified"
    assert reused.receipt["execution_disposition"] == "reused_existing"
    assert reused.receipt["mutation_attempted"] is False
    assert reused.receipt["effect_receipts"] == []
    assert (target / "streams" / "alpha.jsonl").read_bytes() == before_reuse

    (evidence / ".phase" / "runs" / "first" / "receipt.json").unlink()
    refused = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "missing-receipt"), execute=True)
    assert refused.receipt["terminal_status"] == "rejected"
    assert refused.receipt["blockers"] == ["idempotency.prior_inspection_required"]


def test_same_key_prior_planned_does_not_block_execute_but_incomplete_execute_does(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="planned", value=1)
    planned = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "prior-plan"), execute=False)
    assert planned.receipt["terminal_status"] == "validated_planned"

    executed = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "after-plan"), execute=True)
    assert executed.receipt["terminal_status"] == "succeeded_verified"
    before = (target / "streams" / "alpha.jsonl").read_bytes()

    for status in ("intent-only", "non-succeeded"):
        case_evidence = tmp_path / f"evidence-{status}"
        case_target = tmp_path / f"target-{status}"
        (case_target / "streams").mkdir(parents=True)
        write_append_candidate(candidate, expected_head=None, key=f"case-{status}", value=1)
        first = PhaseCore().run(_request("fixture_append.v1", candidate, case_evidence, case_target, "first"), execute=True)
        assert first.exit_code == 0
        if status == "intent-only":
            (case_evidence / ".phase" / "runs" / "first" / "receipt.json").unlink()
        else:
            receipt = case_evidence / ".phase" / "runs" / "first" / "receipt.json"
            payload = json.loads(receipt.read_text(encoding="utf-8"))
            payload["terminal_status"] = "failed_no_effect"
            receipt.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        unchanged = (case_target / "streams" / "alpha.jsonl").read_bytes()
        refused = PhaseCore().run(_request("fixture_append.v1", candidate, case_evidence, case_target, "retry"), execute=True)
        assert refused.receipt["terminal_status"] == "rejected"
        assert refused.receipt["blockers"] == ["idempotency.prior_inspection_required"]
        assert (case_target / "streams" / "alpha.jsonl").read_bytes() == unchanged

    assert (target / "streams" / "alpha.jsonl").read_bytes() == before


def test_same_key_different_digest_conflicts_before_mutation(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="same", value=1)
    assert PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "first"), execute=True).exit_code == 0
    before = (target / "streams" / "alpha.jsonl").read_bytes()
    write_append_candidate(candidate, expected_head=None, key="same", value=2)

    outcome = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "conflict"), execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert (target / "streams" / "alpha.jsonl").read_bytes() == before


def test_task_journal_minimal_open_event_close_and_correction_projection(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "tasks").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    open_candidate = tmp_path / "open.json"
    write_task_candidate(open_candidate, action="open", key="task-open", expected_head=None, original_instruction="Do work")
    opened = PhaseCore().run(_request("task_journal.v1", open_candidate, evidence, target, "task-open"), execute=True)
    assert opened.exit_code == 0
    stream = target / "tasks" / "task-1.jsonl"
    open_record = json.loads(stream.read_text(encoding="utf-8").splitlines()[0])
    assert open_record["record_type"] == "task_open"
    assert open_record["action"] == "open"
    assert open_record["operation_id"] == "task-open"
    assert open_record["request_digest"] == opened.intent["idempotency"]["request_digest"]
    assert open_record["request_digest"].startswith("sha256:")
    assert len(open_record["request_digest"]) == 71
    assert opened.effect_plan["effects"][0]["record_identity"] == f"task-1:1:{open_record['event_hash']}"
    assert opened.receipt["canonical_result"]["appended_record"]["record_identity"] == f"task-1:1:{open_record['event_hash']}"
    assert opened.receipt["canonical_result"]["appended_record"]["append_offset"] == 0
    assert opened.receipt["canonical_result"]["appended_record"]["record_digest"] == opened.receipt["effect_receipts"][0]["record_digest"]
    head = opened.receipt["canonical_result"]["state"]["head_token"]

    event_candidate = tmp_path / "event.json"
    write_task_candidate(event_candidate, action="event", key="task-event", expected_head=head, event_kind="note", event_payload={"text": "started"})
    event = PhaseCore().run(_request("task_journal.v1", event_candidate, evidence, target, "task-event"), execute=True)
    assert event.exit_code == 0
    event_record = json.loads(stream.read_text(encoding="utf-8").splitlines()[1])
    assert event_record["record_type"] == "task_event"
    head = event.receipt["canonical_result"]["state"]["head_token"]

    close_candidate = tmp_path / "close.json"
    write_task_candidate(close_candidate, action="close", key="task-close", expected_head=head, outcome="completed")
    closed = PhaseCore().run(_request("task_journal.v1", close_candidate, evidence, target, "task-close"), execute=True)
    assert closed.exit_code == 0
    close_record = json.loads(stream.read_text(encoding="utf-8").splitlines()[2])
    assert close_record["record_type"] == "task_close"
    head = closed.receipt["canonical_result"]["state"]["head_token"]

    correction_candidate = tmp_path / "correction.json"
    write_task_candidate(correction_candidate, action="correction", key="task-correction", expected_head=head, target_sequence=2, target_event_hash=event_record["event_hash"], reason="fix", replacement={"event_payload": {"text": "started promptly"}})
    corrected = PhaseCore().run(_request("task_journal.v1", correction_candidate, evidence, target, "task-correction"), execute=True)
    assert corrected.exit_code == 0

    from phase_tool.contracts.task_journal_v1 import project_task

    projection = project_task(stream)
    assert projection["status"] == "closed"
    assert projection["terminal_outcome"] == "completed"
    assert projection["event_count"] == 1
    assert projection["corrections"][0]["target_sequence"] == 2
    assert projection["corrections"][0]["target_event_hash"] == event_record["event_hash"]
    assert all("event_hash" in json.loads(line) for line in stream.read_text(encoding="utf-8").splitlines())


def test_task_journal_rejects_missing_or_mismatched_operation_and_correction_identity(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "tasks").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "task.json"
    candidate.write_text(json.dumps({
        "task_id": "task-1",
        "action": "open",
        "expected_head": None,
        "idempotency_key": "key-only",
        "original_instruction": "Do work",
    }), encoding="utf-8")
    missing_operation = PhaseCore().run(_request("task_journal.v1", candidate, evidence, target, "missing-operation"), execute=True)
    assert missing_operation.receipt["terminal_status"] == "rejected"

    write_task_candidate(candidate, action="open", key="open-key", expected_head=None, original_instruction="Do work")
    opened = PhaseCore().run(_request("task_journal.v1", candidate, evidence, target, "open"), execute=True)
    assert opened.exit_code == 0
    head = opened.receipt["canonical_result"]["state"]["head_token"]
    write_task_candidate(candidate, action="correction", key="bad-correction", expected_head=head, target_sequence=1, target_event_hash="sha256:" + "0" * 64, reason="fix", replacement={"x": 1})
    rejected = PhaseCore().run(_request("task_journal.v1", candidate, evidence, target, "bad-correction"), execute=True)
    assert rejected.receipt["terminal_status"] == "rejected"
    assert rejected.receipt["blockers"] == ["task_journal.correction_target_mismatch"]


def test_cli_execute_append_task_inspect_and_copy_active(tmp_path: Path) -> None:
    phase = [sys.executable, "-m", "phase_tool"]
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    (target / "tasks").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    append_candidate = tmp_path / "append.json"
    write_append_candidate(append_candidate, expected_head=None)
    append_contract = _binding("fixture_append.v1")
    append = subprocess.run(
        [
            *phase, "execute",
            "--contract-id", "fixture_append.v1",
            "--contract-version", "1.0.0",
            "--contract-digest", append_contract["package_digest"],
            "--candidate", str(append_candidate),
            "--evidence-root", str(evidence),
            "--run-id", "cli-append",
            "--root", f"fixture_result_root={target}",
            "--timestamp", NOW,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert append.returncode == 0, append.stderr
    assert json.loads(append.stdout)["terminal_status"] == "succeeded_verified"

    task_candidate = tmp_path / "task.json"
    write_task_candidate(task_candidate, action="open", key="cli-task", expected_head=None, original_instruction="x")
    task_contract = _binding("task_journal.v1")
    task = subprocess.run(
        [
            *phase, "execute",
            "--contract-id", "task_journal.v1",
            "--contract-version", "1.0.0",
            "--contract-digest", task_contract["package_digest"],
            "--candidate", str(task_candidate),
            "--evidence-root", str(evidence),
            "--run-id", "cli-task",
            "--root", f"task_journal_root={target}",
            "--timestamp", NOW,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert task.returncode == 0, task.stderr
    assert json.loads(task.stdout)["terminal_status"] == "succeeded_verified"

    inspect = subprocess.run(
        [*phase, "inspect", "--evidence-root", str(evidence), "--run-id", "cli-task", "--root", f"task_journal_root={target}"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert inspect.returncode == 0, inspect.stderr
    assert json.loads(inspect.stdout)["target_verified"] is True

    copy_candidate = tmp_path / "copy.json"
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"copy")
    copy_candidate.write_text(json.dumps({
        "transfer_id": "transfer-1",
        "object_id": "object-1",
        "input_binding": "payload",
        "destinations": ["objects/a"],
        "idempotency_key": "copy",
    }), encoding="utf-8")
    (target / "objects").mkdir()
    copy_contract = _binding("fixture_copy.v1")
    copy = subprocess.run(
        [
            *phase, "execute",
            "--contract-id", "fixture_copy.v1",
            "--contract-version", "1.0.0",
            "--contract-digest", copy_contract["package_digest"],
            "--candidate", str(copy_candidate),
            "--evidence-root", str(evidence),
            "--run-id", "cli-copy",
            "--input", f"payload={payload}",
            "--root", f"fixture_result_root={target}",
            "--timestamp", NOW,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert copy.returncode == 0, copy.stderr
    assert json.loads(copy.stdout)["terminal_status"] == "succeeded_verified"


def _append_race_worker(effect: dict[str, object], root: str, record: bytes, expected_head: str, barrier: object, queue: object) -> None:
    barrier.wait()  # type: ignore[attr-defined]
    receipt = execute_append_record(
        effect,
        Path(root),
        record,
        run_id=f"append-race-{os.getpid()}",
        timestamp=NOW,
        operational_lock_root=Path(root).parent / "evidence" / ".phase" / "locks",
        expected_head_override=expected_head,
    )
    queue.put(receipt)  # type: ignore[attr-defined]


def _phase_core_worker(contract_id: str, candidate: str, evidence: str, target: str, run_id: str, barrier: object, queue: object) -> None:
    barrier.wait()  # type: ignore[attr-defined]
    outcome = PhaseCore().run(_request(contract_id, Path(candidate), Path(evidence), Path(target), run_id), execute=True)
    queue.put({
        "run_id": run_id,
        "terminal_status": outcome.receipt["terminal_status"],
        "execution_disposition": outcome.receipt["execution_disposition"],
        "mutation_attempted": outcome.receipt["mutation_attempted"],
        "blockers": outcome.receipt["blockers"],
    })  # type: ignore[attr-defined]


def test_phase_core_two_process_same_key_same_digest_executes_once_then_reuses(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="core-race", value=1)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(3)
    queue = context.Queue()
    workers = [
        context.Process(target=_phase_core_worker, args=("fixture_append.v1", str(candidate), str(evidence), str(target), f"core-same-{index}", barrier, queue))
        for index in range(2)
    ]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=20)
    receipts = [queue.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    assert sorted((item["terminal_status"], item["execution_disposition"], item["mutation_attempted"]) for item in receipts) == [
        ("succeeded_verified", "executed", True),
        ("succeeded_verified", "reused_existing", False),
    ]
    assert (target / "streams" / "alpha.jsonl").read_bytes() == b'{"value":1}\n'


def test_phase_core_two_process_same_key_different_digest_conflicts_before_second_mutation(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    first_candidate = tmp_path / "first.json"
    second_candidate = tmp_path / "second.json"
    write_append_candidate(first_candidate, expected_head=None, key="core-conflict", value=1)
    write_append_candidate(second_candidate, expected_head=None, key="core-conflict", value=2)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(3)
    queue = context.Queue()
    workers = [
        context.Process(target=_phase_core_worker, args=("fixture_append.v1", str(path), str(evidence), str(target), run_id, barrier, queue))
        for path, run_id in ((first_candidate, "core-conflict-1"), (second_candidate, "core-conflict-2"))
    ]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=20)
    receipts = [queue.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    assert sorted((item["terminal_status"], item["execution_disposition"], item["mutation_attempted"]) for item in receipts) == [
        ("rejected", "not_executed", False),
        ("succeeded_verified", "executed", True),
    ]
    assert len((target / "streams" / "alpha.jsonl").read_bytes().splitlines()) == 1


def test_two_processes_racing_same_expected_head_have_one_append_winner(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    stream = target / "stream.jsonl"
    first = b'{"value":0}\n'
    stream.write_bytes(first)
    expected = stream_head_token(first)
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": expected},
        "lock_scope": "stream.alpha",
    }
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(3)
    queue = context.Queue()
    workers = [context.Process(target=_append_race_worker, args=(effect, str(target), record, expected, barrier, queue)) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=20)
    receipts = [queue.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    assert sorted(item["status"] for item in receipts) == ["applied_verified", "failed_no_effect"]
    assert stream.read_bytes() == first + record


def test_two_processes_racing_absent_stream_have_one_initial_append_winner(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": None},
        "lock_scope": "stream.alpha",
    }
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(3)
    queue = context.Queue()
    workers = [context.Process(target=_append_race_worker, args=(effect, str(target), record, None, barrier, queue)) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=20)
    receipts = [queue.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    assert sorted(item["status"] for item in receipts) == ["applied_verified", "failed_no_effect"]
    assert (target / "stream.jsonl").read_bytes() == record


def test_append_lock_failure_and_abandoned_lock_file_are_classified(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": None},
        "lock_scope": "stream.alpha",
    }

    failed = execute_append_record(
        effect,
        target,
        record,
        run_id="lock-fail",
        timestamp=NOW,
        operational_lock_root=_lock_root(tmp_path),
        faults=AppendRecordFaults(lock_acquire_error=True),
    )
    assert failed["status"] == "failed_no_effect"
    assert failed["error"]["code"] == "lock.acquire_failed"
    assert not (target / "stream.jsonl").exists()

    (tmp_path / "evidence" / ".phase" / "locks").mkdir(parents=True, exist_ok=True)
    recovered = execute_append_record(effect, target, record, run_id="abandoned", timestamp=NOW, operational_lock_root=_lock_root(tmp_path))
    assert recovered["status"] == "applied_verified"


def test_real_lock_acquisition_oserror_returns_terminal_no_effect_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.mutation.expected_head_append as append_module

    target = tmp_path / "target"
    target.mkdir()
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": None},
        "lock_scope": "stream.alpha",
    }

    class FailingLock(append_module._CooperativeFileLock):
        def __enter__(self) -> object:
            raise OSError("real acquire failure")

    monkeypatch.setattr(append_module, "_CooperativeFileLock", FailingLock)
    receipt = execute_append_record(effect, target, record, run_id="lock-oserror", timestamp=NOW, operational_lock_root=_lock_root(tmp_path))

    assert receipt["status"] == "failed_no_effect"
    assert receipt["error"]["code"] == "lock.acquire_failed"
    assert receipt["after"]["exists"] is False
    assert not (target / "stream.jsonl").exists()


def test_task_journal_replay_rejects_self_consistent_semantic_chain_corruption(tmp_path: Path) -> None:
    stream = tmp_path / "task.jsonl"
    open_record = {
        "task_record_version": "1.0",
        "record_type": "task_open",
        "task_id": "task-1",
        "sequence": 1,
        "action": "open",
        "operation_id": "open",
        "request_digest": "sha256:" + "1" * 64,
        "previous_head": None,
        "original_instruction": "Do work",
    }
    open_bytes = finalize_record(open_record, previous_head=None, previous_length=0)
    open_head = stream_head_token(open_bytes)
    bad_event = {
        "task_record_version": "1.0",
        "record_type": "task_event",
        "task_id": "task-2",
        "sequence": 999,
        "action": "event",
        "operation_id": "event",
        "request_digest": "sha256:" + "2" * 64,
        "previous_head": open_head,
        "event_kind": "note",
        "event_payload": {"text": "wrong task and sequence"},
    }
    stream.write_bytes(open_bytes + finalize_record(bad_event, previous_head=open_head, previous_length=len(open_bytes)))
    candidate = {
        "task_id": "task-1",
        "action": "correction",
        "expected_head": stream_head_token(stream.read_bytes()),
        "idempotency_key": "correction",
        "operation_id": "correction",
        "target_sequence": 1,
        "target_event_hash": parse_json_bytes(open_bytes.rstrip(b"\n"))["event_hash"],
        "reason": "fix",
        "replacement": {"original_instruction": "Do work now"},
    }

    from phase_tool.contracts.task_journal_v1 import validate_state

    status, code, *_ = validate_state(candidate, stream)
    assert status == "fail"
    assert code == "task_journal.sequence_gap"


def test_inspect_detects_append_evidence_and_target_tampering(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None)
    outcome = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "inspect"), execute=True)
    assert outcome.exit_code == 0
    assert inspect_run(evidence, "inspect", root_bindings={"fixture_result_root": target})["target_verified"] is True
    receipt = evidence / ".phase" / "runs" / "inspect" / "receipt.json"
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(PhaseError, match="inspection.invalid_json|inspection.digest_mismatch"):
        inspect_run(evidence, "inspect", root_bindings={"fixture_result_root": target})


def test_same_key_receiptless_planned_intent_does_not_block_execute(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "streams").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / "append.json"
    write_append_candidate(candidate, expected_head=None, key="interrupted-plan", value=1)
    planned = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "interrupted-plan"), execute=False)
    assert planned.intent is not None
    assert planned.intent["execution_requested"] is False
    (evidence / ".phase" / "runs" / "interrupted-plan" / "receipt.json").unlink()

    executed = PhaseCore().run(_request("fixture_append.v1", candidate, evidence, target, "after-interrupted-plan"), execute=True)

    assert executed.receipt["terminal_status"] == "succeeded_verified"
    assert executed.receipt["execution_disposition"] == "executed"


def test_lock_acquisition_oserror_with_unknown_observation_is_indeterminate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.mutation.expected_head_append as append_module

    target = tmp_path / "target"
    target.mkdir()
    record = b'{"value":1}\n'
    effect = {
        "effect_id": "effect.append.001",
        "kind": "append_record",
        "target": {"root_binding": "fixture_result_root", "relative_locator": "stream.jsonl"},
        "content_digest": _sha(record),
        "content_length": len(record),
        "preconditions": {"expected_head": None},
        "lock_scope": "stream.alpha",
    }

    class FailingLock(append_module._CooperativeFileLock):
        def __enter__(self) -> object:
            raise OSError("real acquire failure")

    def unavailable(_path: Path) -> dict[str, object]:
        raise OSError("observation unavailable")

    monkeypatch.setattr(append_module, "_CooperativeFileLock", FailingLock)
    monkeypatch.setattr(append_module, "_observe", unavailable)
    receipt = execute_append_record(effect, target, record, run_id="lock-unknown", timestamp=NOW, operational_lock_root=_lock_root(tmp_path))

    assert receipt["status"] == "indeterminate"
    assert receipt["before"]["known"] is False
    assert receipt["after"]["known"] is False


def test_broken_operational_lock_symlink_is_rejected_before_open(tmp_path: Path) -> None:
    lock_root = _lock_root(tmp_path)
    lock_root.mkdir(parents=True)
    digest = "sha256:" + "a" * 64
    link = lock_root / ("a" * 64 + ".lock")
    try:
        os.symlink(lock_root / "missing-target", link)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(PhaseError, match="path.link_forbidden"):
        operational_lock_path(lock_root, digest)


def test_task_journal_replay_rejects_self_consistent_record_shape_corruption(tmp_path: Path) -> None:
    stream = tmp_path / "task.jsonl"
    malformed_open = {
        "record_type": "task_open",
        "task_id": "task-1",
        "sequence": 1,
        "action": "open",
        "operation_id": "open",
        "request_digest": "sha256:" + "1" * 64,
        "previous_head": None,
        "original_instruction": "Do work",
        "unexpected": True,
    }
    stream.write_bytes(finalize_record(malformed_open, previous_head=None, previous_length=0))
    candidate = {
        "task_id": "task-1",
        "action": "event",
        "expected_head": stream_head_token(stream.read_bytes()),
        "idempotency_key": "event",
        "operation_id": "event",
        "event_kind": "note",
        "event_payload": {"text": "later"},
    }

    from phase_tool.contracts.task_journal_v1 import validate_state

    status, code, *_ = validate_state(candidate, stream)
    assert status == "fail"
    assert code == "task_journal.record_schema_invalid"
