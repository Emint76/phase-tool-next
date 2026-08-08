from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.contracts import load_contract_hook
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run
from phase_tool.mutation import BrokerFaults
from phase_tool.mutation.archive_then_publish import ArchiveThenPublishFaults
from phase_tool.registry import BundledRegistry

NOW = "2026-07-31T20:00:00Z"

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="publish_new_version.v1 requires POSIX production guarantees",
)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _archive_locator(data: bytes) -> str:
    hexdigest = hashlib.sha256(data).hexdigest()
    return f"archive/sha256/{hexdigest[:2]}/{hexdigest}"


def _binding() -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()["publish_new_version.v1@1.0.0"]


def _request(
    tmp_path: Path,
    *,
    run_id: str,
    key: str = "publish-key",
    before: bytes = b"old opaque bytes\x00\r\n",
    after: bytes = b"new opaque bytes\xff\n",
) -> tuple[PhaseRequest, Path, Path, Path, bytes, bytes]:
    target = tmp_path / "target"
    (target / "documents").mkdir(parents=True)
    current = target / "documents" / "item.bin"
    current.write_bytes(before)
    evidence = tmp_path / "evidence"
    candidate = tmp_path / f"{run_id}.json"
    candidate.write_text(
        json.dumps(
            {
                "operation_id": "publish-item",
                "target_locator": "documents/item.bin",
                "input_binding": "payload",
                "expected_current_digest": _sha(before),
                "idempotency_key": key,
            }
        ),
        encoding="utf-8",
    )
    payload = tmp_path / f"{run_id}.bin"
    payload.write_bytes(after)
    binding = _binding()
    request = PhaseRequest(
        contract_id="publish_new_version.v1",
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths={"payload": payload},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )
    return request, target, evidence, current, before, after


def test_publish_plan_is_archive_first_format_neutral_and_does_not_mutate_target(tmp_path: Path) -> None:
    request, target, evidence, current, before, after = _request(tmp_path, run_id="publish-plan")

    outcome = PhaseCore().run(request)

    assert outcome.exit_code == 0
    assert outcome.receipt["terminal_status"] == "validated_planned"
    assert outcome.receipt["mutation_attempted"] is False
    assert current.read_bytes() == before
    assert not (target / _archive_locator(before)).exists()
    assert outcome.effect_plan is not None
    assert outcome.effect_plan["operation_intent"] == "publish_new_version"
    assert outcome.effect_plan["mechanism"]["id"] == "mechanism.archive_then_publish_v1"
    assert outcome.effect_plan["effect_order"] == "static_predeclared"
    assert len(outcome.effect_plan["effects"]) == 1
    effect = outcome.effect_plan["effects"][0]
    assert effect["kind"] == "publish_new_version"
    assert effect["target"] == {"root_binding": "fixture_result_root", "relative_locator": "documents/item.bin"}
    assert effect["archive_target"] == {
        "root_binding": "fixture_result_root",
        "relative_locator": _archive_locator(before),
    }
    assert effect["preconditions"] == {
        "existence": "present",
        "expected_digest": _sha(before),
        "expected_head": None,
        "concurrency_token": _sha(before),
    }
    assert effect["archive_digest"] == _sha(before)
    assert effect["archive_length"] == len(before)
    assert effect["content_digest"] == _sha(after)
    assert effect["content_length"] == len(after)
    assert effect["content_source"]["kind"] == "frozen_input"
    registry = BundledRegistry.load()
    contract = registry.resolve_contract(
        "publish_new_version.v1",
        "1.0.0",
        request.contract_digest,
        core_version="1.0.0",
    )
    assert contract.document["operation"]["atomicity_claim"] == "none"
    serialized = json.dumps(outcome.effect_plan).lower()
    assert "markdown" not in serialized
    assert "frontmatter" not in serialized
    inspected = inspect_run(evidence, request.run_id)
    assert inspected["terminal_status"] == "validated_planned"
    assert inspected["target_verified"] is None


@pytest.mark.parametrize("receipt_present", [True, False])
def test_inspection_rejects_same_kind_effect_mechanism_not_authorized_by_contract(
    tmp_path: Path,
    receipt_present: bool,
) -> None:
    request, _target, evidence, _current, _before, _after = _request(
        tmp_path,
        run_id=f"unauthorized-effect-mechanism-{receipt_present}",
    )
    outcome = PhaseCore().run(request)
    assert outcome.exit_code == 0
    run_root = evidence / ".phase" / "runs" / request.run_id
    plan_path = run_root / "attachments" / "effect-plan.json"
    intent_path = run_root / "intent.json"
    receipt_path = run_root / "receipt.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    registry = BundledRegistry.load()
    v2_binding = registry.contract_bindings()["publish_new_version.v2@1.0.0"]
    v2_contract = registry.resolve_contract(
        v2_binding["id"],
        v2_binding["version"],
        v2_binding["package_digest"],
        core_version="1.0.0",
    )
    v2_mechanism = v2_contract.document["operation"]["mechanism"]
    plan["effects"][0]["mechanism"] = {
        "id": v2_mechanism["id"],
        "version": v2_mechanism["version"],
        "package_digest": v2_mechanism["package_digest"],
    }
    old_plan_attachment_digest = intent["evidence"]["effect_plan_attachment_digest"]
    plan_bytes = canonical_bytes(plan)
    plan_attachment_digest = digest_bytes(plan_bytes)
    plan_digest = profile_digest("effect-plan", plan)
    intent["effect_plan_digest"] = plan_digest
    intent["implementation_binding"]["effect_plan_digest"] = plan_digest
    intent["evidence"]["effect_plan_attachment_digest"] = plan_attachment_digest
    plan_path.write_bytes(plan_bytes)
    intent_path.write_bytes(canonical_bytes(intent))
    if receipt_present:
        receipt["implementation_binding"]["effect_plan_digest"] = plan_digest
        receipt["evidence"]["intent_digest"] = profile_digest("intent", intent)
        receipt["evidence"]["attachment_digests"] = [
            plan_attachment_digest if item == old_plan_attachment_digest else item
            for item in receipt["evidence"]["attachment_digests"]
        ]
        receipt_path.write_bytes(canonical_bytes(receipt))
    else:
        receipt_path.unlink()

    with pytest.raises(PhaseError) as error:
        inspect_run(evidence, request.run_id)
    assert error.value.code == "plan.effect_mechanism_not_allowed"


def test_publish_execute_archives_exact_before_then_publishes_current_and_binds_receipt(tmp_path: Path) -> None:
    request, target, evidence, current, before, after = _request(tmp_path, run_id="publish-execute")
    archive = target / _archive_locator(before)

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.exit_code == 0
    assert current.read_bytes() == after
    assert archive.read_bytes() == before
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert outcome.receipt["canonical_result"]["locator"] == "documents/item.bin"
    assert outcome.receipt["canonical_result"]["state"]["digest"] == _sha(after)
    receipt = outcome.receipt["effect_receipts"][0]
    assert receipt["kind"] == "publish_new_version"
    assert receipt["before"]["digest"] == _sha(before)
    assert receipt["after"]["digest"] == _sha(after)
    assert receipt["archive_target"]["relative_locator"] == _archive_locator(before)
    assert receipt["archive_before"]["exists"] is False
    assert receipt["archive_after"]["digest"] == _sha(before)
    inspected = inspect_run(evidence, "publish-execute", root_bindings={"fixture_result_root": target})
    assert inspected["target_verified"] is True
    assert inspected["contract_result"]["archive"]["digest"] == _sha(before)


def test_publish_stale_current_and_archive_conflict_block_before_mutation(tmp_path: Path) -> None:
    stale, _target, _evidence, current, before, _after = _request(tmp_path, run_id="stale", key="stale")
    current.write_bytes(b"unexpected current")
    rejected = PhaseCore().run(stale, execute=True)
    assert rejected.receipt["terminal_status"] == "rejected"
    assert rejected.receipt["mutation_attempted"] is False
    assert rejected.receipt["blockers"] == ["publish.state_conflict"]

    conflict, target, _evidence2, current2, before2, _after2 = _request(tmp_path / "archive-conflict-case", run_id="archive-conflict", key="archive-conflict")
    archive = target / _archive_locator(before2)
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"wrong archive")
    rejected = PhaseCore().run(conflict, execute=True)
    assert rejected.receipt["terminal_status"] == "rejected"
    assert current2.read_bytes() == before2
    assert archive.read_bytes() == b"wrong archive"


def test_publish_rejects_current_archive_locator_collision(tmp_path: Path) -> None:
    request, _target, _evidence, _current, before, _after = _request(tmp_path, run_id="locator-collision")
    candidate = parse_json_bytes(request.candidate_path.read_bytes())
    candidate["target_locator"] = _archive_locator(before)
    request.candidate_path.write_bytes(canonical_bytes(candidate))

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["publish.target_archive_collision"]


def test_publish_reuses_exact_archive_and_blocks_mismatching_reuse(tmp_path: Path) -> None:
    request, target, _evidence, current, before, after = _request(tmp_path, run_id="archive-reuse", key="archive-reuse")
    archive = target / _archive_locator(before)
    archive.parent.mkdir(parents=True)
    archive.write_bytes(before)

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert current.read_bytes() == after
    assert archive.read_bytes() == before
    assert outcome.receipt["effect_receipts"][0]["archive_before"]["digest"] == _sha(before)


def test_publish_rejects_archive_callback_before_mutation(tmp_path: Path) -> None:
    request, target, _evidence, current, before, _after = _request(tmp_path, run_id="archive-tamper-before-publish")
    archive = target / _archive_locator(before)

    def tamper_archive(_current_path: Path) -> None:
        archive.write_bytes(b"archive changed after initial verification")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(archive_then_publish=ArchiveThenPublishFaults(before_publish=tamper_archive))),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert current.read_bytes() == before
    assert not archive.exists()


@pytest.mark.parametrize("tamper", ["current", "archive"])
def test_publish_rejects_final_check_callback_before_mutation(tmp_path: Path, tamper: str) -> None:
    request, target, _evidence, current, before, _after = _request(tmp_path, run_id=f"final-race-{tamper}")
    archive = target / _archive_locator(before)

    def race(_current_path: Path) -> None:
        (current if tamper == "current" else archive).write_bytes(b"raced bytes")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                archive_then_publish=ArchiveThenPublishFaults(before_current_write=race),
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert current.read_bytes() == before
    assert not archive.exists()


def test_publish_rejects_archive_create_callback_before_mutation(tmp_path: Path) -> None:
    request, target, _evidence, current, before, _after = _request(tmp_path, run_id="archive-create-race")
    archive = target / _archive_locator(before)

    def create_exact(path: Path) -> None:
        path.write_bytes(before)

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                archive_then_publish=ArchiveThenPublishFaults(before_archive_create=create_exact),
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert current.read_bytes() == before
    assert not archive.exists()


def test_publish_failure_after_archive_is_safely_continuable_after_exact_inspection(tmp_path: Path) -> None:
    request, target, _evidence, current, before, after = _request(tmp_path, run_id="after-archive", key="after-archive")
    first = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(archive_then_publish=ArchiveThenPublishFaults(fail_after_archive=True))),
    )
    assert first.receipt["terminal_status"] == "failed_partial"
    assert current.read_bytes() == before
    assert (target / _archive_locator(before)).read_bytes() == before

    retry = PhaseCore().run(replace(request, run_id="after-archive-retry"), execute=True)

    assert retry.receipt["terminal_status"] == "succeeded_verified"
    assert current.read_bytes() == after
    assert retry.receipt["effect_receipts"][0]["archive_before"]["digest"] == _sha(before)


def test_publish_publication_without_receipt_reconciles_with_no_target_writes(tmp_path: Path) -> None:
    request, target, evidence, current, before, after = _request(tmp_path, run_id="receipt-crash", key="receipt-crash")
    first = PhaseCore().run(request, execute=True, faults=CoreFaults(fail_receipt_write=True))
    assert first.receipt["terminal_status"] == "committed_unverified"
    assert not (evidence / ".phase" / "runs" / "receipt-crash" / "receipt.json").exists()
    assert current.read_bytes() == after
    assert (target / _archive_locator(before)).read_bytes() == before

    retry = PhaseCore().run(replace(request, run_id="receipt-crash-retry"), execute=True)

    assert retry.receipt["terminal_status"] == "succeeded_verified"
    assert retry.receipt["effect_receipts"][0]["bytes_written"] == 0
    assert retry.receipt["effect_receipts"][0]["verification_refs"] == [
        "target.before",
        "archive.before",
        "publish.already_complete",
        "archive.logical_before",
    ]
    assert retry.receipt["effect_receipts"][0]["before"]["digest"] == _sha(before)
    assert retry.receipt["effect_receipts"][0]["before"]["length"] == len(before)
    assert retry.receipt["effect_receipts"][0]["after"]["digest"] == _sha(after)
    assert retry.receipt["effect_receipts"][0]["before"] != retry.receipt["effect_receipts"][0]["after"]
    assert current.read_bytes() == after


def test_publish_replays_finalized_receipt_only_after_current_and_archive_inspection(tmp_path: Path) -> None:
    request, target, _evidence, current, before, after = _request(tmp_path, run_id="finalized-replay", key="finalized-replay")
    first = PhaseCore().run(request, execute=True)
    assert first.receipt["terminal_status"] == "succeeded_verified"

    retry = PhaseCore().run(replace(request, run_id="finalized-replay-retry"), execute=True)

    assert retry.receipt["terminal_status"] == "succeeded_verified"
    assert retry.receipt["execution_disposition"] == "reused_existing"
    assert retry.receipt["prior_verified_receipt_digest"] == first.receipt_digest
    assert current.read_bytes() == after
    assert (target / _archive_locator(before)).read_bytes() == before
    inspected_first = inspect_run(request.evidence_root, request.run_id, root_bindings={"fixture_result_root": target})
    assert "state_classification" not in inspected_first
    assert "state_classification" not in inspected_first["contract_result"]
    inspected_retry = inspect_run(request.evidence_root, retry.run_id, root_bindings={"fixture_result_root": target})
    assert inspected_retry["target_verified"] is True
    assert inspected_retry["contract_result"]["archive"]["digest"] == _sha(before)

    (target / _archive_locator(before)).write_bytes(b"tampered archive")
    blocked = PhaseCore().run(replace(request, run_id="finalized-replay-after-tamper"), execute=True)
    assert blocked.receipt["terminal_status"] == "rejected"
    assert blocked.receipt["blockers"] == ["idempotency.prior_result_changed"]


def test_publish_missing_receipt_inspection_classifies_no_effect_archived_and_published(tmp_path: Path) -> None:
    no_effect, target, evidence, _current, _before, _after = _request(tmp_path / "no-effect", run_id="missing-no-effect", key="missing-no-effect")
    planned = PhaseCore().run(no_effect, execute=False)
    assert planned.receipt["execution_disposition"] == "not_executed"
    (evidence / ".phase" / "runs" / "missing-no-effect" / "receipt.json").unlink()
    inspected = inspect_run(evidence, "missing-no-effect", root_bindings={"fixture_result_root": target})
    assert inspected["state_classification"] == "no_effect_observed"

    archived, target2, evidence2, _current2, before2, _after2 = _request(tmp_path / "archived", run_id="missing-archived", key="missing-archived")
    PhaseCore().run(
        archived,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(archive_then_publish=ArchiveThenPublishFaults(fail_after_archive=True))),
    )
    (evidence2 / ".phase" / "runs" / "missing-archived" / "receipt.json").unlink()
    inspected = inspect_run(evidence2, "missing-archived", root_bindings={"fixture_result_root": target2})
    assert inspected["state_classification"] == "archived_not_published"
    assert (target2 / _archive_locator(before2)).read_bytes() == before2

    published, target3, evidence3, _current3, before3, _after3 = _request(tmp_path / "published", run_id="missing-published", key="missing-published")
    PhaseCore().run(published, execute=True, faults=CoreFaults(fail_receipt_write=True))
    inspected = inspect_run(evidence3, "missing-published", root_bindings={"fixture_result_root": target3})
    assert inspected["state_classification"] == "published_not_finalized"
    assert (target3 / _archive_locator(before3)).read_bytes() == before3


def test_publish_partial_archive_write_blocks_publication_and_retry(tmp_path: Path) -> None:
    request, target, _evidence, current, before, _after = _request(tmp_path, run_id="partial-archive", key="partial-archive")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(archive_then_publish=ArchiveThenPublishFaults(fail_after_archive_bytes=3))),
    )

    archive = target / _archive_locator(before)
    assert outcome.receipt["terminal_status"] == "failed_partial"
    assert outcome.receipt["effect_receipts"][0]["error"]["code"] == "mechanism.write_failed"
    assert current.read_bytes() == before
    assert archive.read_bytes() == before[:3]

    retry = PhaseCore().run(replace(request, run_id="partial-archive-retry"), execute=True)
    assert retry.receipt["terminal_status"] == "rejected"
    assert retry.receipt["blockers"] == ["idempotency.prior_inspection_required"]


def test_publish_tampered_receiptless_plan_or_blob_blocks_idempotent_continuation(tmp_path: Path) -> None:
    request, _target, evidence, _current, _before, _after = _request(tmp_path, run_id="tamper-receiptless", key="tamper-receiptless")
    PhaseCore().run(request, execute=True, faults=CoreFaults(fail_receipt_write=True))
    run_root = evidence / ".phase" / "runs" / "tamper-receiptless"
    plan_path = run_root / "attachments" / "effect-plan.json"
    plan = parse_json_bytes(plan_path.read_bytes())
    plan["effects"][0]["content_length"] += 1
    plan_path.write_bytes(canonical_bytes(plan))
    intent_path = run_root / "intent.json"
    intent = parse_json_bytes(intent_path.read_bytes())
    intent["effect_plan_digest"] = profile_digest("effect-plan", plan)
    intent["evidence"]["effect_plan_attachment_digest"] = digest_bytes(canonical_bytes(plan))
    intent_path.write_bytes(canonical_bytes(intent))

    blocked = PhaseCore().run(replace(request, run_id="tamper-receiptless-retry"), execute=True)
    assert blocked.receipt["terminal_status"] == "rejected"
    assert blocked.receipt["blockers"] == ["idempotency.prior_inspection_required"]

    blob_case, _target2, evidence2, _current2, _before2, _after2 = _request(tmp_path / "blob-case", run_id="tamper-blob", key="tamper-blob")
    PhaseCore().run(blob_case, execute=True, faults=CoreFaults(fail_receipt_write=True))
    blob_root = evidence2 / ".phase" / "runs" / "tamper-blob" / "blobs"
    blob_path = next(blob_root.iterdir())
    blob_path.write_bytes(b"tampered blob")

    blocked_blob = PhaseCore().run(replace(blob_case, run_id="tamper-blob-retry"), execute=True)
    assert blocked_blob.receipt["terminal_status"] == "rejected"
    assert blocked_blob.receipt["blockers"] == ["idempotency.prior_inspection_required"]


def test_publish_malformed_prior_intent_is_a_controlled_idempotency_blocker(tmp_path: Path) -> None:
    request, _target, evidence, _current, _before, _after = _request(tmp_path, run_id="malformed-intent", key="malformed-intent")
    PhaseCore().run(request, execute=True, faults=CoreFaults(fail_receipt_write=True))
    intent_path = evidence / ".phase" / "runs" / request.run_id / "intent.json"
    intent_path.write_bytes(b"{not-json")

    retry = PhaseCore().run(replace(request, run_id="malformed-intent-retry"), execute=True)

    assert retry.receipt["terminal_status"] == "rejected"
    assert retry.receipt["blockers"] == ["idempotency.prior_inspection_required"]


def test_publish_partial_current_and_ambiguous_states_block_retry(tmp_path: Path) -> None:
    request, target, _evidence, current, before, after = _request(tmp_path, run_id="partial-current", key="partial-current")
    first = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(archive_then_publish=ArchiveThenPublishFaults(fail_after_current_bytes=3))),
    )
    assert first.receipt["terminal_status"] == "failed_partial"
    assert current.read_bytes() == after[:3]
    assert (target / _archive_locator(before)).read_bytes() == before

    retry = PhaseCore().run(replace(request, run_id="partial-current-retry"), execute=True)
    assert retry.receipt["terminal_status"] == "rejected"
    assert retry.receipt["blockers"] == ["idempotency.prior_inspection_required"]

    ambiguous, target2, _evidence2, current2, before2, _after2 = _request(tmp_path / "ambiguous-case", run_id="ambiguous", key="ambiguous")
    (target2 / _archive_locator(before2)).parent.mkdir(parents=True)
    (target2 / _archive_locator(before2)).write_bytes(before2)
    current2.write_bytes(b"neither before nor after")
    blocked = PhaseCore().run(ambiguous, execute=True)
    assert blocked.receipt["terminal_status"] == "rejected"
    assert blocked.receipt["blockers"] == ["publish.state_conflict"]


def test_publish_same_key_different_request_conflicts_and_current_alone_never_synthesizes_success(tmp_path: Path) -> None:
    request, _target, _evidence, current, _before, after = _request(tmp_path, run_id="same-key", key="same-key")
    PhaseCore().run(request, execute=True)
    different_candidate = tmp_path / "same-key-different.json"
    different_payload = tmp_path / "same-key-different.bin"
    different_payload.write_bytes(b"different new bytes")
    different_candidate.write_text(
        json.dumps(
            {
                "operation_id": "publish-item",
                "target_locator": "documents/item.bin",
                "input_binding": "payload",
                "expected_current_digest": _sha(_before),
                "idempotency_key": "same-key",
            }
        ),
        encoding="utf-8",
    )
    different = replace(request, run_id="same-key-different", candidate_path=different_candidate, input_paths={"payload": different_payload})
    conflict = PhaseCore().run(different, execute=True)
    assert conflict.receipt["terminal_status"] == "rejected"
    assert conflict.receipt["blockers"] == ["idempotency.same_key_conflict"]
    assert current.read_bytes() == after

    current_only, _target3, _evidence3, current3, _before3, after3 = _request(tmp_path / "current-alone-case", run_id="current-alone", key="current-alone")
    current3.write_bytes(after3)
    rejected = PhaseCore().run(current_only, execute=True)
    assert rejected.receipt["terminal_status"] == "rejected"
    assert rejected.receipt["blockers"] == ["publish.state_conflict"]


def test_publish_inspect_detects_current_archive_plan_and_receipt_tampering(tmp_path: Path) -> None:
    request, target, evidence, current, before, after = _request(tmp_path, run_id="inspect-tamper")
    PhaseCore().run(request, execute=True)
    assert inspect_run(evidence, "inspect-tamper", root_bindings={"fixture_result_root": target})["target_verified"] is True

    current.write_bytes(b"tampered current")
    with pytest.raises(PhaseError, match="inspection.target_mismatch"):
        inspect_run(evidence, "inspect-tamper", root_bindings={"fixture_result_root": target})
    current.write_bytes(after)

    archive = target / _archive_locator(before)
    archive.write_bytes(b"tampered archive")
    with pytest.raises(PhaseError, match="inspection.target_mismatch"):
        inspect_run(evidence, "inspect-tamper", root_bindings={"fixture_result_root": target})
    archive.write_bytes(before)

    plan_path = evidence / ".phase" / "runs" / "inspect-tamper" / "attachments" / "effect-plan.json"
    plan = parse_json_bytes(plan_path.read_bytes())
    plan["effects"][0]["content_length"] += 1
    plan_path.write_bytes(canonical_bytes(plan))
    with pytest.raises(PhaseError, match="inspection.digest_mismatch"):
        inspect_run(evidence, "inspect-tamper", root_bindings={"fixture_result_root": target})


@pytest.mark.parametrize(
    ("field", "value"),
    [("status", "failed_partial"), ("attempted", False)],
)
def test_publish_receipt_inspection_requires_verified_attempted_composite_effect(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    request, target, evidence, _current, _before, _after = _request(tmp_path, run_id=f"receipt-{field}")
    PhaseCore().run(request, execute=True)
    run_root = evidence / ".phase" / "runs" / request.run_id
    receipt = parse_json_bytes((run_root / "receipt.json").read_bytes())
    plan = parse_json_bytes((run_root / "attachments" / "effect-plan.json").read_bytes())
    receipt["effect_receipts"][0][field] = value

    registry = BundledRegistry.load()
    binding = _binding()
    contract = registry.resolve_contract(
        "publish_new_version.v1",
        "1.0.0",
        binding["package_digest"],
        core_version="1.0.0",
    )
    hook = load_contract_hook(contract)
    assert hook is not None
    with pytest.raises(PhaseError, match="inspection.effect_receipts_mismatch"):
        hook.inspect_receipt_result(receipt, plan, target, registry, evidence)


def test_publish_has_no_generic_overwrite_effect_and_registry_package_mirrors_are_exact() -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["publish_new_version.v1@1.0.0"]
    contract = registry.resolve_contract("publish_new_version.v1", "1.0.0", binding["package_digest"], core_version="1.0.0")
    assert contract.document["operation"]["allowed_effects"] == ["publish_new_version"]
    assert contract.document["operation"]["mechanism"]["id"] == "mechanism.archive_then_publish_v1"
    encoded_registry = json.dumps(registry.to_document())
    assert "overwrite" not in encoded_registry
    assert "replace" not in encoded_registry
    assert "current_state" not in json.dumps(contract.document["candidate"])
    assert Path("contracts/fixtures/publish_new_version.v1.json").read_bytes() == Path("src/phase_tool/data/contracts/publish_new_version.v1.json").read_bytes()
    assert Path("schemas/publish-new-version-candidate.schema.json").read_bytes() == Path("src/phase_tool/data/schemas/publish-new-version-candidate.schema.json").read_bytes()
