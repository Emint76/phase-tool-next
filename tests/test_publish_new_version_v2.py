from __future__ import annotations

import base64
import hashlib
import json
import os
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from phase_tool.canonical import parse_json_bytes
from phase_tool.contracts.publish_new_version_v2 import PublishNewVersionV2Hook
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.installation import host_installation
from phase_tool.inspection import inspect_run
from phase_tool.mutation import BrokerFaults, ObjectStorePublishFaults
from phase_tool.mutation.object_store_publish import execute_object_store_publish as _execute_object_store_publish
from phase_tool.registry import BundledRegistry

NOW = "2026-08-03T12:00:00Z"

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="publish_new_version.v2 requires POSIX production guarantees",
)


def execute_object_store_publish(*args: object, **kwargs: object) -> dict[str, object]:
    kwargs["authority_provider"] = host_installation().authority_provider
    return _execute_object_store_publish(*args, **kwargs)  # type: ignore[arg-type]


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _object_locator(data: bytes) -> str:
    hexdigest = hashlib.sha256(data).hexdigest()
    return f"sha256/{hexdigest[:2]}/{hexdigest}"


def _binding() -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()["publish_new_version.v2@1.0.0"]


def _request(tmp_path: Path, *, run_id: str, before: bytes, content: str) -> tuple[PhaseRequest, Path, Path, Path, Path]:
    current_root = tmp_path / "current"
    objects_root = tmp_path / "external-objects"
    evidence_root = tmp_path / "external-evidence"
    current_root.mkdir(parents=True)
    objects_root.mkdir(parents=True)
    current = current_root / "docs" / "item.md"
    current.parent.mkdir(parents=True)
    current.write_bytes(before)
    candidate = tmp_path / f"{run_id}.json"
    candidate.write_text(
        json.dumps(
            {
                "operation_id": "publish-inline-item",
                "target_locator": "docs/item.md",
                "expected_current_digest": _sha(before),
                "content_utf8": content,
                "media_type": "text/markdown",
                "idempotency_key": "publish-inline-item",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    binding = _binding()
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence_root,
        run_id=run_id,
        input_paths={},
        root_bindings={"current_root": current_root, "objects_root": objects_root},
        timestamp=NOW,
    )
    return request, current_root, objects_root, evidence_root, current


def test_v2_inline_utf8_publishes_current_and_external_old_new_objects(tmp_path: Path) -> None:
    before = b"# OLD\r\n\x00"
    content = "# Новый\n\nточные UTF-8 bytes — ✓\n"
    after = content.encode("utf-8")
    request, current_root, objects_root, evidence_root, current = _request(
        tmp_path, run_id="v2-success", before=before, content=content
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.exit_code == 0
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert current.read_bytes() == after
    assert (objects_root / _object_locator(before)).read_bytes() == before
    assert (objects_root / _object_locator(after)).read_bytes() == after
    assert not (current_root / "archive").exists()
    assert not (current_root / ".phase").exists()
    assert list(current_root.rglob("*.tmp")) == []
    assert (evidence_root / ".phase" / "runs" / request.run_id / "receipt.json").is_file()
    effect = outcome.receipt["effect_receipts"][0]
    assert effect["archive_target"] == {"root_binding": "objects_root", "relative_locator": _object_locator(before)}
    assert effect["content_object_target"] == {"root_binding": "objects_root", "relative_locator": _object_locator(after)}
    assert effect["archive_after"]["digest"] == _sha(before)
    assert effect["content_object_after"]["digest"] == _sha(after)
    inspected = inspect_run(
        evidence_root,
        request.run_id,
        root_bindings={"current_root": current_root, "objects_root": objects_root},
    )
    assert inspected["target_verified"] is True
    assert inspected["contract_result"]["old_object"]["digest"] == _sha(before)
    assert inspected["contract_result"]["new_object"]["digest"] == _sha(after)


def test_v2_reuses_exact_existing_old_and_new_objects(tmp_path: Path) -> None:
    before = b"old"
    content = "new ✓"
    after = content.encode("utf-8")
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-object-reuse", before=before, content=content
    )
    for payload in (before, after):
        path = objects_root / _object_locator(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert current.read_bytes() == after
    effect = outcome.receipt["effect_receipts"][0]
    assert effect["archive_before"]["digest"] == _sha(before)
    assert effect["content_object_before"]["digest"] == _sha(after)


def test_v2_already_complete_receipt_before_is_actual_current_observation(tmp_path: Path) -> None:
    before = b"old bytes with a different length"
    content = "new"
    after = content.encode("utf-8")
    request, current_root, objects_root, evidence_root, _current = _request(
        tmp_path, run_id="v2-already-complete-setup", before=before, content=content
    )
    first = PhaseCore().run(request, execute=True)
    assert first.receipt["terminal_status"] == "succeeded_verified"
    plan = parse_json_bytes(
        (evidence_root / ".phase" / "runs" / request.run_id / "attachments" / "effect-plan.json").read_bytes()
    )

    receipt = execute_object_store_publish(
        plan["effects"][0],
        current_root,
        objects_root,
        after,
        run_id="v2-already-complete-direct",
        timestamp=NOW,
    )

    assert _sha(before) != _sha(after)
    assert len(before) != len(after)
    assert receipt["status"] == "applied_verified"
    assert receipt["before"] == {
        "known": True,
        "exists": True,
        "digest": _sha(after),
        "length": len(after),
        "head_token": None,
    }


@pytest.mark.parametrize("which", ["old", "new"])
def test_v2_rejects_conflicting_existing_object_without_current_change(tmp_path: Path, which: str) -> None:
    before = b"old bytes"
    content = "new bytes"
    after = content.encode("utf-8")
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id=f"v2-object-conflict-{which}", before=before, content=content
    )
    payload = before if which == "old" else after
    path = objects_root / _object_locator(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"conflicting bytes")

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["publish.object_conflict"]
    assert current.read_bytes() == before


def test_v2_wrong_expected_current_digest_is_stable_rejection(tmp_path: Path) -> None:
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-wrong-expected", before=b"actual", content="new"
    )
    candidate = parse_json_bytes(request.candidate_path.read_bytes())
    candidate["expected_current_digest"] = _sha(b"not actual")
    request.candidate_path.write_text(json.dumps(candidate), encoding="utf-8")

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["publish.state_conflict"]
    assert current.read_bytes() == b"actual"
    assert list(objects_root.rglob("*")) == []


def test_v2_rejects_final_revalidation_callback_before_mutation(tmp_path: Path) -> None:
    before = b"old"
    after = b"new"
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-final-drift", before=before, content=after.decode()
    )

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                object_store_publish=ObjectStorePublishFaults(
                    before_final_revalidation=lambda path: path.write_bytes(b"external drift")
                )
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert current.read_bytes() == before
    assert not (objects_root / _object_locator(before)).exists()
    assert not (objects_root / _object_locator(after)).exists()


@pytest.mark.parametrize(
    ("faults", "error_code"),
    [
        (ObjectStorePublishFaults(fail_temporary_write_after_bytes=1), "mechanism.temporary_write_failed"),
        (ObjectStorePublishFaults(fail_atomic_replace=True), "mechanism.atomic_replace_failed"),
    ],
)
def test_v2_pre_replace_failures_leave_current_old_objects_retained_and_no_temp(
    tmp_path: Path, faults: ObjectStorePublishFaults, error_code: str
) -> None:
    before = b"old"
    after = b"replacement"
    request, current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-pre-replace-failure-" + error_code.rsplit(".", 1)[-1], before=before, content=after.decode()
    )

    outcome = PhaseCore().run(request, execute=True, faults=CoreFaults(broker=BrokerFaults(object_store_publish=faults)))

    assert outcome.receipt["terminal_status"] == "failed_partial"
    assert outcome.receipt["effect_receipts"][0]["error"]["code"] == error_code
    assert current.read_bytes() == before
    assert (objects_root / _object_locator(before)).read_bytes() == before
    assert (objects_root / _object_locator(after)).read_bytes() == after
    assert list(current_root.rglob("*.phase-tmp-*")) == []


def test_v2_post_replace_readback_mismatch_is_committed_unverified(tmp_path: Path) -> None:
    before = b"old"
    after = b"new"
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-readback-mismatch", before=before, content=after.decode()
    )

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(object_store_publish=ObjectStorePublishFaults(readback_override=b"mismatching readback"))
        ),
    )

    assert outcome.receipt["terminal_status"] == "committed_unverified"
    assert outcome.receipt["effect_receipts"][0]["status"] == "applied_unverified"
    assert current.read_bytes() == after
    assert (objects_root / _object_locator(before)).read_bytes() == before
    assert (objects_root / _object_locator(after)).read_bytes() == after


def test_v2_rejects_post_replace_callback_before_mutation(tmp_path: Path) -> None:
    before = b"old"
    after = b"new"
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-post-replace-oserror", before=before, content=after.decode()
    )

    def fail_after_replace(_path: Path) -> None:
        raise OSError("injected durability failure after successful replace")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                object_store_publish=ObjectStorePublishFaults(after_replace=fail_after_replace)
            )
        ),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert current.read_bytes() == before
    assert not (objects_root / _object_locator(before)).exists()
    assert not (objects_root / _object_locator(after)).exists()


def test_v2_partial_after_objects_is_retry_safe_and_reuses_objects(tmp_path: Path) -> None:
    before = b"old"
    after = b"new"
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-after-objects", before=before, content=after.decode()
    )
    first = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(object_store_publish=ObjectStorePublishFaults(fail_after_objects=True))),
    )
    assert first.receipt["terminal_status"] == "failed_partial"
    assert current.read_bytes() == before
    assert (objects_root / _object_locator(before)).read_bytes() == before
    assert (objects_root / _object_locator(after)).read_bytes() == after

    retry = PhaseCore().run(replace(request, run_id="v2-after-objects-retry"), execute=True)

    assert retry.receipt["terminal_status"] == "succeeded_verified"
    assert current.read_bytes() == after
    effect = retry.receipt["effect_receipts"][0]
    assert effect["archive_before"]["digest"] == _sha(before)
    assert effect["content_object_before"]["digest"] == _sha(after)


@pytest.mark.parametrize("which", ["old", "new"])
def test_v2_object_write_failure_never_publishes_partial_final_and_retry_succeeds(
    tmp_path: Path, which: str
) -> None:
    before = b"old object bytes"
    after = b"new object bytes"
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id=f"v2-object-write-failure-{which}", before=before, content=after.decode()
    )
    faults = (
        ObjectStorePublishFaults(fail_old_object_write_after_bytes=3)
        if which == "old"
        else ObjectStorePublishFaults(fail_new_object_write_after_bytes=3)
    )

    first = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(object_store_publish=faults)),
    )

    failed_payload = before if which == "old" else after
    failed_final = objects_root / _object_locator(failed_payload)
    assert first.receipt["terminal_status"] == "failed_partial"
    assert not failed_final.exists() or failed_final.read_bytes() == failed_payload
    assert list(objects_root.rglob("*.phase-tmp-object-*")) == []
    assert current.read_bytes() == before

    retry = PhaseCore().run(replace(request, run_id=f"v2-object-write-retry-{which}"), execute=True)

    assert retry.receipt["terminal_status"] == "succeeded_verified"
    assert current.read_bytes() == after
    assert (objects_root / _object_locator(before)).read_bytes() == before
    assert (objects_root / _object_locator(after)).read_bytes() == after


@pytest.mark.parametrize("which", ["old", "new"])
def test_v2_preexisting_object_temporary_is_not_modified_or_removed(
    tmp_path: Path, which: str
) -> None:
    before = b"old object bytes"
    after = b"new object bytes"
    sentinel = b"foreign temporary sentinel"
    run_id = f"v2-preexisting-object-temporary-{which}"
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id=run_id, before=before, content=after.decode()
    )
    payload = before if which == "old" else after
    token = hashlib.sha256(f"{run_id}.{which}".encode("utf-8")).hexdigest()[:16]
    final = objects_root / _object_locator(payload)
    temporary = Path(str(final) + ".phase-tmp-object-" + token)
    temporary.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_bytes(sentinel)

    outcome = PhaseCore().run(request, execute=True)

    effect = outcome.receipt["effect_receipts"][0]
    assert outcome.receipt["terminal_status"] == "failed_partial"
    assert effect["status"] == "failed_partial"
    assert effect["error"]["code"] == "publish.object_temporary_conflict"
    assert temporary.read_bytes() == sentinel
    assert not final.exists()
    assert current.read_bytes() == before


def test_v2_preexisting_current_temporary_is_not_modified_or_removed(tmp_path: Path) -> None:
    before = b"old"
    after = b"new"
    sentinel = b"foreign current temporary sentinel"
    run_id = "v2-preexisting-current-temporary"
    request, current_root, _objects_root, _evidence_root, current = _request(
        tmp_path, run_id=run_id, before=before, content=after.decode()
    )
    temporary = current_root / f"docs/item.md.phase-tmp-{run_id[-32:]}"
    temporary.write_bytes(sentinel)

    outcome = PhaseCore().run(request, execute=True)

    effect = outcome.receipt["effect_receipts"][0]
    assert outcome.receipt["terminal_status"] != "succeeded_verified"
    assert effect["status"] == "failed_partial"
    assert effect["error"]["code"] == "mechanism.temporary_write_failed"
    assert temporary.read_bytes() == sentinel
    assert current.read_bytes() == before


def test_v2_path_escape_is_rejected_before_objects(tmp_path: Path) -> None:
    request, _current_root, objects_root, _evidence_root, _current = _request(
        tmp_path, run_id="v2-path-escape", before=b"old", content="new"
    )
    candidate = parse_json_bytes(request.candidate_path.read_bytes())
    candidate["target_locator"] = "../escaped.md"
    request.candidate_path.write_text(json.dumps(candidate), encoding="utf-8")

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["candidate.schema_invalid"]
    assert list(objects_root.rglob("*")) == []


def test_v2_reparse_policy_blocks_mechanism_before_object_creation(tmp_path: Path) -> None:
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-reparse", before=b"old", content="new"
    )

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(object_store_publish=ObjectStorePublishFaults(reparse_detector=lambda _path: True))
        ),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert current.read_bytes() == b"old"
    assert list(objects_root.rglob("*")) == []


def test_v2_actual_symlink_target_is_rejected_when_platform_allows_symlinks(tmp_path: Path) -> None:
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-symlink", before=b"old", content="new"
    )
    real = current.with_name("real.md")
    current.replace(real)
    try:
        current.symlink_to(real)
    except OSError:
        pytest.skip("symlink creation is not permitted on this Windows host")

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["path.link_forbidden"]
    assert real.read_bytes() == b"old"
    assert list(objects_root.rglob("*")) == []


def test_v2_rejects_inline_content_over_utf8_byte_limit(tmp_path: Path) -> None:
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-content-limit", before=b"old", content="я" * 300_000
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["publish.content_too_large"]
    assert current.read_bytes() == b"old"
    assert list(objects_root.rglob("*")) == []


def test_v2_rejects_objects_root_inside_current_root(tmp_path: Path) -> None:
    request, current_root, _objects_root, _evidence_root, current = _request(
        tmp_path, run_id="v2-overlapping-roots", before=b"old", content="new"
    )
    nested_objects = current_root / "objects"
    nested_objects.mkdir()
    request = replace(request, root_bindings={"current_root": current_root, "objects_root": nested_objects})

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["publish.objects_root_not_separate"]
    assert current.read_bytes() == b"old"
    assert list(nested_objects.rglob("*")) == []


@pytest.mark.parametrize(
    ("case", "expected_code"),
    [
        ("missing_content_object_target", "plan.content_object_target_missing"),
        ("missing_content_blob_digest", "plan.content_binding_mismatch"),
        ("missing_content_bytes_b64", "plan.content_binding_mismatch"),
        ("wrong_source_kind", "plan.source_binding_mismatch"),
        ("wrong_source_binding", "plan.source_binding_mismatch"),
        ("missing_content_digest", "plan.content_binding_mismatch"),
        ("missing_content_length", "plan.content_binding_mismatch"),
        ("missing_media_type", "plan.media_type_missing"),
        ("non_null_input_binding", "plan.source_binding_mismatch"),
        ("invalid_base64", "plan.content_encoding_invalid"),
        ("decoded_digest_mismatch", "plan.content_binding_mismatch"),
        ("decoded_length_mismatch", "plan.content_binding_mismatch"),
        ("wrong_content_object_locator", "plan.content_object_binding_mismatch"),
    ],
)
def test_v2_static_validation_rejects_incomplete_or_inconsistent_plan_before_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_code: str,
) -> None:
    request, _current_root, _objects_root, evidence_root, _current = _request(
        tmp_path, run_id=f"v2-invalid-plan-{case}", before=b"old", content="new"
    )
    original = PublishNewVersionV2Hook.build_effects

    def invalid_effects(self: PublishNewVersionV2Hook, *args: object, **kwargs: object) -> list[dict[str, object]]:
        effects = deepcopy(original(self, *args, **kwargs))
        effect = effects[0]
        effect.pop("mechanism")
        if case.startswith("missing_"):
            effect.pop(case.removeprefix("missing_"))
        elif case == "wrong_source_kind":
            effect["content_source"] = {"kind": "frozen_input", "binding_id": None, "source_digest": effect["content_digest"]}
        elif case == "wrong_source_binding":
            effect["content_source"] = {"kind": "captured_candidate", "binding_id": "unexpected", "source_digest": effect["content_digest"]}
        elif case == "non_null_input_binding":
            effect["input_binding"] = "unexpected"
        elif case == "invalid_base64":
            effect["content_bytes_b64"] = "***not-base64***"
        elif case == "decoded_digest_mismatch":
            effect["content_bytes_b64"] = base64.b64encode(b"different bytes").decode("ascii")
        elif case == "decoded_length_mismatch":
            effect["content_length"] = int(effect["content_length"]) + 1
        elif case == "wrong_content_object_locator":
            effect["content_object_target"] = {
                "root_binding": "objects_root",
                "relative_locator": _object_locator(b"different bytes"),
            }
        return effects

    monkeypatch.setattr(PublishNewVersionV2Hook, "build_effects", invalid_effects)

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == [expected_code]
    assert not (evidence_root / ".phase" / "runs" / request.run_id / "intent.json").exists()


def test_v2_inspection_accepts_executed_receipt(tmp_path: Path) -> None:
    request, current_root, objects_root, evidence_root, _current = _request(
        tmp_path, run_id="v2-inspect-executed", before=b"old", content="new"
    )
    outcome = PhaseCore().run(request, execute=True)

    inspected = inspect_run(
        evidence_root,
        request.run_id,
        root_bindings={"current_root": current_root, "objects_root": objects_root},
    )

    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert inspected["terminal_status"] == "succeeded_verified"
    assert inspected["target_verified"] is True


def test_v2_inspection_accepts_reused_existing_receipt(tmp_path: Path) -> None:
    request, current_root, objects_root, evidence_root, _current = _request(
        tmp_path, run_id="v2-inspect-reused-source", before=b"old", content="new"
    )
    first = PhaseCore().run(request, execute=True)
    repeated = PhaseCore().run(replace(request, run_id="v2-inspect-reused-receipt"), execute=True)

    inspected = inspect_run(
        evidence_root,
        "v2-inspect-reused-receipt",
        root_bindings={"current_root": current_root, "objects_root": objects_root},
    )

    assert first.receipt["terminal_status"] == "succeeded_verified"
    assert repeated.receipt["execution_disposition"] == "reused_existing"
    assert repeated.receipt["mutation_attempted"] is False
    assert inspected["execution_disposition"] == "reused_existing"
    assert inspected["target_verified"] is True


def test_v2_inspection_classifies_published_state_without_receipt(tmp_path: Path) -> None:
    request, current_root, objects_root, evidence_root, _current = _request(
        tmp_path, run_id="v2-inspect-committed-unverified", before=b"old", content="new"
    )

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(fail_receipt_write=True),
    )
    assert outcome.receipt["terminal_status"] == "committed_unverified"

    inspected = inspect_run(
        evidence_root,
        request.run_id,
        root_bindings={"current_root": current_root, "objects_root": objects_root},
    )

    assert inspected["terminal_status"] is None
    assert inspected["state_classification"] == "published_not_finalized"
    assert inspected["target_verified"] is None


@pytest.mark.parametrize("tampered", ["current", "old_object", "new_object"])
def test_v2_inspection_rejects_live_current_or_object_tamper(tmp_path: Path, tampered: str) -> None:
    before = b"old"
    after = b"new"
    request, current_root, objects_root, evidence_root, current = _request(
        tmp_path, run_id=f"v2-inspect-tamper-{tampered}", before=before, content=after.decode()
    )
    outcome = PhaseCore().run(request, execute=True)
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    targets = {
        "current": current,
        "old_object": objects_root / _object_locator(before),
        "new_object": objects_root / _object_locator(after),
    }
    targets[tampered].write_bytes(b"tampered")

    with pytest.raises(PhaseError) as caught:
        inspect_run(
            evidence_root,
            request.run_id,
            root_bindings={"current_root": current_root, "objects_root": objects_root},
        )

    assert caught.value.code == "inspection.target_mismatch"


def test_v1_and_v2_contracts_are_parallel_exact_bindings() -> None:
    bindings = BundledRegistry.load().contract_bindings()
    assert "publish_new_version.v1@1.0.0" in bindings
    assert "publish_new_version.v2@1.0.0" in bindings
    assert bindings["publish_new_version.v1@1.0.0"] != bindings["publish_new_version.v2@1.0.0"]
