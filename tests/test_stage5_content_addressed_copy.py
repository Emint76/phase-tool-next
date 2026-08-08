from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
import time
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from phase_tool.canonical import canonical_bytes, parse_json_bytes
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.installation import host_installation
from phase_tool.inspection import inspect_run
from phase_tool.mutation import BrokerFaults
from phase_tool.mutation.content_addressed_copy import ContentAddressedCopyFaults, execute_content_addressed_copy as _execute_content_addressed_copy
from phase_tool.planning import validate_static_plan
from phase_tool.registry import BundledRegistry

NOW = "2026-07-27T05:00:00Z"
ROOT = Path(__file__).resolve().parents[1]


def execute_content_addressed_copy(*args: object, **kwargs: object) -> dict[str, object]:
    kwargs["authority_provider"] = host_installation().authority_provider
    return _execute_content_addressed_copy(*args, **kwargs)  # type: ignore[arg-type]

GOLDEN_COPY_VECTORS = [
    (
        "empty",
        b"",
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "objects/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "text",
        b"content-addressed copy\n",
        "sha256:a161ef3e04b886fd37bd38518a035fe689e40fdbdaf31116fe48a1ff1ee04582",
        "objects/a161ef3e04b886fd37bd38518a035fe689e40fdbdaf31116fe48a1ff1ee04582",
    ),
    (
        "binary",
        bytes([0, 1, 2, 253, 254, 255]),
        "sha256:3f2d1552cdc7483f40dd720c80b900225dfecfd5cae7cd168d79ab6ee5959885",
        "objects/3f2d1552cdc7483f40dd720c80b900225dfecfd5cae7cd168d79ab6ee5959885",
    ),
    (
        "name-invariant-a",
        b"same bytes",
        "sha256:58100dc8fc06562ce3e578231dc948e083520ee49c4b4ee5a5a28bb4b4003feb",
        "objects/58100dc8fc06562ce3e578231dc948e083520ee49c4b4ee5a5a28bb4b4003feb",
    ),
    (
        "one-byte-delta",
        b"same byteS",
        "sha256:8e74edfc3739440be6afb39c9ed58d47033d096732e8cd972b19f7be9bc7ddf1",
        "objects/8e74edfc3739440be6afb39c9ed58d47033d096732e8cd972b19f7be9bc7ddf1",
    ),
]


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _copy_locator(data: bytes) -> str:
    return "objects/" + hashlib.sha256(data).hexdigest()


def _binding() -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()["fixture_copy.v1@1.0.0"]


def write_copy_candidate(path: Path, *, key: str = "copy-key", destination: str = "objects/user-name.bin") -> None:
    path.write_text(
        json.dumps(
            {
                "transfer_id": key,
                "object_id": "user-supplied-name",
                "input_binding": "payload",
                "destinations": [destination],
                "idempotency_key": key,
            }
        ),
        encoding="utf-8",
    )


def copy_request(tmp_path: Path, *, run_id: str, key: str = "copy-key", payload: bytes = b"copy payload") -> tuple[PhaseRequest, Path, Path, Path, bytes]:
    target = tmp_path / f"target-{run_id}"
    (target / "objects").mkdir(parents=True)
    (target / "canary.txt").write_bytes(b"unchanged")
    evidence = tmp_path / "evidence"
    candidate = tmp_path / f"{run_id}.json"
    write_copy_candidate(candidate, key=key)
    source = tmp_path / f"{run_id}.bin"
    source.write_bytes(payload)
    binding = _binding()
    request = PhaseRequest(
        contract_id="fixture_copy.v1",
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths={"payload": source},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )
    return request, target, evidence, source, payload


def _effect_for_payload(payload: bytes, *, locator: str | None = None) -> dict[str, object]:
    digest = _sha(payload)
    return {
        "effect_id": "effect.copy.001",
        "kind": "copy_blob",
        "target": {"root_binding": "fixture_result_root", "relative_locator": locator or _copy_locator(payload)},
        "input_binding": "payload",
        "content_source": {"kind": "frozen_input", "binding_id": "payload", "source_digest": digest},
        "content_digest": digest,
        "content_length": len(payload),
        "preconditions": {"existence": "absent_or_same_digest", "expected_digest": digest, "expected_head": None, "concurrency_token": None},
        "lock_scope": None,
        "durability_policy_id": "file_data_synced",
        "on_failure": "stop_and_classify",
    }


def _copy_worker(effect: dict[str, object], root: str, payload: bytes, barrier: object, queue: object) -> None:
    barrier.wait()  # type: ignore[attr-defined]
    receipt = execute_content_addressed_copy(
        effect,
        Path(root),
        payload,
        run_id=f"copy-race-{os.getpid()}",
        timestamp=NOW,
    )
    queue.put(receipt)  # type: ignore[attr-defined]


def _precreate_conflict_worker(destination: str, payload: bytes, ready: object, queue: object) -> None:
    ready.wait(timeout=20)  # type: ignore[attr-defined]
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        queue.put({"created": False, "exists": True})  # type: ignore[attr-defined]
        return
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    queue.put({"created": True, "sha256": hashlib.sha256(payload).hexdigest(), "length": len(payload)})  # type: ignore[attr-defined]


def _copy_loser_after_observation_worker(effect: dict[str, object], root: str, payload: bytes, ready: object, queue: object) -> None:
    def wait_for_conflict(target: Path) -> None:
        ready.set()  # type: ignore[attr-defined]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if target.exists():
                return
            time.sleep(0.01)
        raise TimeoutError("conflict writer did not create destination")

    receipt = execute_content_addressed_copy(
        effect,
        Path(root),
        payload,
        run_id=f"copy-loser-{os.getpid()}",
        timestamp=NOW,
        faults=ContentAddressedCopyFaults(before_exclusive_create=wait_for_conflict),
    )
    queue.put(receipt)  # type: ignore[attr-defined]


def _replace_parent_with_link_worker(root: str, outside: str, ready: object, complete: object, queue: object) -> None:
    ready.wait(timeout=20)  # type: ignore[attr-defined]
    objects = Path(root) / "objects"
    moved = Path(root) / "objects-moved"
    try:
        objects.rename(moved)
        try:
            os.symlink(Path(outside), objects, target_is_directory=True)
        except OSError:
            if os.name != "nt":
                raise
            subprocess.run(["cmd", "/c", "mklink", "/J", str(objects), str(outside)], check=True, capture_output=True)
    except OSError as exc:
        queue.put({"replaced": False, "error": type(exc).__name__})  # type: ignore[attr-defined]
        complete.set()  # type: ignore[attr-defined]
        return
    except subprocess.CalledProcessError as exc:
        queue.put({"replaced": False, "error": type(exc).__name__})  # type: ignore[attr-defined]
        complete.set()  # type: ignore[attr-defined]
        return
    queue.put({"replaced": True})  # type: ignore[attr-defined]
    complete.set()  # type: ignore[attr-defined]


def test_hard_coded_copy_digest_locator_vectors_are_name_invariant() -> None:
    observed = []
    for name, payload, digest, locator in GOLDEN_COPY_VECTORS:
        assert _sha(payload) == digest, name
        assert _copy_locator(payload) == locator, name
        observed.append((digest, locator))
    assert observed[3] != observed[4]
    assert observed[3] == (_sha(b"same bytes"), _copy_locator(b"same bytes"))


def test_copy_plan_freezes_source_blob_and_uses_digest_locator_before_intent(tmp_path: Path) -> None:
    request, _target, evidence, _source, payload = copy_request(tmp_path, run_id="copy-plan")

    outcome = PhaseCore().run(request)

    assert outcome.exit_code == 0
    assert outcome.intent is not None
    assert outcome.effect_plan is not None
    assert outcome.intent["operation"]["mechanism"]["id"] == "content_addressed_copy"
    assert len(outcome.effect_plan["effects"]) == 1
    effect = outcome.effect_plan["effects"][0]
    assert effect["kind"] == "copy_blob"
    assert effect["target"]["relative_locator"] == _copy_locator(payload)
    assert effect["target"]["relative_locator"] != "objects/user-name.bin"
    assert effect["content_digest"] == _sha(payload)
    assert effect["content_length"] == len(payload)
    assert outcome.intent["inputs"][0]["blob_digest"] == _sha(payload)
    assert (evidence / ".phase" / "runs" / "copy-plan" / "blobs" / hashlib.sha256(payload).hexdigest()).read_bytes() == payload


def test_copy_validate_and_plan_do_not_mutate_target_or_source(tmp_path: Path) -> None:
    request, target, _evidence, source, payload = copy_request(tmp_path, run_id="dry-run", payload=b"dry")
    before_tree = sorted(path.relative_to(target).as_posix() for path in target.rglob("*"))
    before_source = source.read_bytes()

    validated = PhaseCore().run(request)
    planned = PhaseCore().run(replace(request, run_id="dry-plan"))

    assert validated.receipt["terminal_status"] == "validated_planned"
    assert planned.receipt["terminal_status"] == "validated_planned"
    assert sorted(path.relative_to(target).as_posix() for path in target.rglob("*")) == before_tree
    assert source.read_bytes() == before_source == payload
    assert not (target / _copy_locator(payload)).exists()


def test_copy_source_mutation_callback_is_rejected_before_invocation(tmp_path: Path) -> None:
    request, target, _evidence, source, payload = copy_request(tmp_path, run_id="copy-execute")
    destination = target / _copy_locator(payload)

    def change_source_after_intent(_intent_path: Path) -> None:
        source.write_bytes(b"changed after freeze")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_mechanism=change_source_after_intent)),
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert source.read_bytes() == payload
    assert not destination.exists()


def test_copy_existing_identical_is_verified_reuse_and_existing_different_conflicts(tmp_path: Path) -> None:
    payload = b"same bytes"
    request, target, _evidence, _source, _payload = copy_request(tmp_path, run_id="same", payload=payload)
    destination = target / _copy_locator(payload)
    destination.write_bytes(payload)

    same = PhaseCore().run(request, execute=True)

    assert same.receipt["terminal_status"] == "succeeded_verified"
    assert same.receipt["effect_receipts"][0]["bytes_written"] == 0
    assert destination.read_bytes() == payload

    different_request, different_target, _evidence2, _source2, different_payload = copy_request(
        tmp_path,
        run_id="different",
        key="different-key",
        payload=b"different bytes",
    )
    different_destination = different_target / _copy_locator(different_payload)
    different_destination.write_bytes(b"pre-existing-different")

    conflict = PhaseCore().run(different_request, execute=True)

    assert conflict.receipt["terminal_status"] == "rejected"
    assert conflict.receipt["mutation_attempted"] is False
    assert conflict.receipt["blockers"] == ["target.same_key_conflict"]
    assert different_destination.read_bytes() == b"pre-existing-different"


def test_copy_broker_rejects_plan_or_blob_tampering_before_target_mutation(tmp_path: Path) -> None:
    payload = b"tamper checked"
    for case in ("plan", "blob", "intent", "evidence_binding"):
        request, target, _evidence, _source, _payload = copy_request(tmp_path, run_id=f"tamper-{case}", key=f"tamper-{case}", payload=payload)

        def tamper(intent_path: Path, case: str = case) -> None:
            run_root = intent_path.parent
            if case == "plan":
                plan_path = run_root / "attachments" / "effect-plan.json"
                plan = parse_json_bytes(plan_path.read_bytes())
                plan["effects"][0]["content_length"] += 1
                plan_path.write_bytes(canonical_bytes(plan))
            elif case == "blob":
                (run_root / "blobs" / hashlib.sha256(payload).hexdigest()).write_bytes(b"tampered")
            elif case == "intent":
                intent = parse_json_bytes(intent_path.read_bytes())
                intent["operation"]["mechanism"]["version"] = "9.9.9"
                intent_path.write_bytes(canonical_bytes(intent))
            else:
                intent = parse_json_bytes(intent_path.read_bytes())
                intent["inputs"][0]["binding_id"] = "other"
                intent_path.write_bytes(canonical_bytes(intent))

        outcome = PhaseCore().run(
            request,
            execute=True,
            faults=CoreFaults(broker=BrokerFaults(before_mechanism=tamper)),
        )

        assert outcome.receipt["terminal_status"] == "rejected"
        assert outcome.receipt["mutation_attempted"] is False
        assert not (target / _copy_locator(payload)).exists()


def test_copy_mechanism_rejects_malformed_bindings_and_unsafe_locators(tmp_path: Path) -> None:
    root = tmp_path / "target"
    (root / "objects").mkdir(parents=True)
    payload = b"binding"
    effect = _effect_for_payload(payload)

    for mutated, code in [
        (dict(effect) | {"content_digest": _sha(payload + b"!")}, "mechanism.content_binding_mismatch"),
        (dict(effect) | {"content_length": len(payload) + 1}, "mechanism.content_binding_mismatch"),
        (_effect_for_payload(payload, locator="objects/" + "0" * 64), "mechanism.locator_digest_mismatch"),
        (_effect_for_payload(payload, locator="../escape"), "mechanism.locator_digest_mismatch|path.traversal"),
        (_effect_for_payload(payload, locator="objects/CON.txt"), "mechanism.locator_digest_mismatch|path.windows_reserved"),
    ]:
        with pytest.raises(PhaseError, match=code):
            execute_content_addressed_copy(mutated, root, payload, run_id="direct", timestamp=NOW)
    assert not any(path.is_file() for path in root.rglob("*"))


def test_copy_mechanism_rejects_directory_link_reparse_and_special_targets(tmp_path: Path) -> None:
    root = tmp_path / "target"
    (root / "objects").mkdir(parents=True)
    payload = b"special"
    destination = root / _copy_locator(payload)
    destination.mkdir()
    receipt = execute_content_addressed_copy(_effect_for_payload(payload), root, payload, run_id="dir", timestamp=NOW)
    assert receipt["status"] == "failed_no_effect"
    assert receipt["error"]["code"] == "target.same_key_conflict"

    destination.rmdir()
    try:
        os.symlink(root / "outside", destination)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(PhaseError, match="path.link_forbidden"):
        execute_content_addressed_copy(_effect_for_payload(payload), root, payload, run_id="link", timestamp=NOW)

    destination.unlink()
    with pytest.raises(PhaseError, match="path.reparse_forbidden"):
        execute_content_addressed_copy(
            _effect_for_payload(payload),
            root,
            payload,
            run_id="reparse",
            timestamp=NOW,
            faults=ContentAddressedCopyFaults(reparse_detector=lambda path: path == destination),
        )
    assert not destination.exists()


def test_copy_short_write_loop_readback_and_no_temp_leftovers(tmp_path: Path) -> None:
    request, target, _evidence, _source, payload = copy_request(tmp_path, run_id="short", payload=b"0123456789")

    ok = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(content_addressed_copy=ContentAddressedCopyFaults(maximum_write_size=1))),
    )

    assert ok.receipt["terminal_status"] == "succeeded_verified"
    assert (target / _copy_locator(payload)).read_bytes() == payload
    assert not list(target.rglob("*.tmp"))

    partial_request, partial_target, _evidence2, _source2, _payload2 = copy_request(
        tmp_path,
        run_id="partial",
        key="partial",
        payload=payload,
    )
    failed = PhaseCore().run(
        partial_request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(content_addressed_copy=ContentAddressedCopyFaults(fail_after_bytes=3))),
    )
    assert failed.receipt["terminal_status"] == "failed_partial"
    assert failed.receipt["effect_receipts"][0]["bytes_written"] == 3
    assert not list(partial_target.rglob("*.tmp"))

    zero_request, zero_target, _evidence3, _source3, _payload3 = copy_request(tmp_path, run_id="zero", key="zero", payload=payload)

    zero = PhaseCore().run(
        zero_request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(content_addressed_copy=ContentAddressedCopyFaults(maximum_write_size=0))),
    )
    assert zero.receipt["terminal_status"] == "failed_partial"
    assert zero.receipt["effect_receipts"][0]["bytes_written"] == 0
    assert (zero_target / _copy_locator(payload)).read_bytes() == b""


def test_copy_readback_mismatch_unavailable_and_evidence_finalization_failure(tmp_path: Path) -> None:
    mismatch_request, mismatch_target, _evidence, _source, payload = copy_request(tmp_path, run_id="mismatch", payload=b"mismatch")
    mismatch = PhaseCore().run(
        mismatch_request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(content_addressed_copy=ContentAddressedCopyFaults(readback_override=b"wrong"))),
    )
    assert mismatch.receipt["terminal_status"] == "committed_unverified"
    assert mismatch.receipt["effect_receipts"][0]["status"] == "applied_unverified"
    assert (mismatch_target / _copy_locator(payload)).read_bytes() == payload

    unavailable_request, _target2, _evidence2, _source2, _payload2 = copy_request(tmp_path, run_id="unavailable", key="unavailable", payload=b"unavailable")
    unavailable = PhaseCore().run(
        unavailable_request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(content_addressed_copy=ContentAddressedCopyFaults(readback_error=True))),
    )
    assert unavailable.receipt["terminal_status"] == "indeterminate"
    assert unavailable.receipt["effect_receipts"][0]["status"] == "indeterminate"

    final_request, final_target, final_evidence, _source3, final_payload = copy_request(tmp_path, run_id="final-fail", key="final-fail", payload=b"final")
    final = PhaseCore().run(final_request, execute=True, faults=CoreFaults(fail_receipt_write=True))
    assert final.receipt["terminal_status"] == "committed_unverified"
    assert final.receipt["evidence"]["finalization_status"] == "failed"
    assert not (final_evidence / ".phase" / "runs" / "final-fail" / "receipt.json").exists()
    assert (final_target / _copy_locator(final_payload)).read_bytes() == final_payload


def test_copy_prior_exact_reuse_and_incomplete_or_partial_prior_fail_closed(tmp_path: Path) -> None:
    request, target, evidence, _source, payload = copy_request(tmp_path, run_id="prior", key="reuse", payload=b"reuse")
    first = PhaseCore().run(request, execute=True)
    second = PhaseCore().run(replace(request, run_id="prior-reuse"), execute=True)
    assert first.receipt["execution_disposition"] == "executed"
    assert second.receipt["execution_disposition"] == "reused_existing"
    assert second.receipt["mutation_attempted"] is False
    assert second.receipt["prior_verified_receipt_digest"] is not None
    assert (target / _copy_locator(payload)).read_bytes() == payload

    planned_request, _target2, _evidence2, _source2, _payload2 = copy_request(tmp_path, run_id="intent-only", key="intent-only", payload=b"intent-only")
    PhaseCore().run(planned_request)
    planned_reuse = PhaseCore().run(replace(planned_request, run_id="intent-only-retry"), execute=True)
    assert planned_reuse.receipt["terminal_status"] == "succeeded_verified"
    assert planned_reuse.receipt["execution_disposition"] == "executed"

    partial_request, _target3, _evidence3, _source3, _payload3 = copy_request(tmp_path, run_id="prior-partial", key="prior-partial", payload=b"prior-partial")
    PhaseCore().run(
        partial_request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(content_addressed_copy=ContentAddressedCopyFaults(fail_after_bytes=2))),
    )
    rejected = PhaseCore().run(replace(partial_request, run_id="prior-partial-retry"), execute=True)
    assert rejected.receipt["terminal_status"] == "rejected"
    assert rejected.receipt["blockers"] == ["idempotency.prior_inspection_required"]
    assert inspect_run(evidence, "prior", root_bindings={"fixture_result_root": target})["target_verified"] is True


def test_copy_multi_effect_plan_fails_closed_before_mutation(tmp_path: Path) -> None:
    request, target, _evidence, _source, payload = copy_request(tmp_path, run_id="multi", payload=b"multi")
    planned = PhaseCore().run(request)
    assert planned.effect_plan is not None
    multi = deepcopy(planned.effect_plan)
    multi["effects"].append(deepcopy(multi["effects"][0]))
    multi["effects"][1]["effect_id"] = "effect.copy.002"
    contract = PhaseCore().registry.resolve_contract("fixture_copy.v1", "1.0.0", _binding()["package_digest"], core_version="1.0.0")
    with pytest.raises(PhaseError, match="plan.incomplete"):
        validate_static_plan(multi, contract, {"fixture_result_root": target}, PhaseCore().registry)
    assert not (target / _copy_locator(payload)).exists()


def test_copy_destination_write_callback_is_rejected_before_invocation(tmp_path: Path) -> None:
    payload = b"race-conflict"
    request, target, _evidence, _source, _payload = copy_request(tmp_path, run_id="appears", payload=payload)
    destination = target / _copy_locator(payload)

    def create_conflict(_intent_path: Path) -> None:
        destination.write_bytes(b"conflict")

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_mechanism=create_conflict)),
    )
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert not destination.exists()


def test_copy_concurrent_create_has_one_writer_and_one_verified_identical_reuse(tmp_path: Path) -> None:
    request, target, _evidence, _source, payload = copy_request(tmp_path, run_id="race", payload=b"race bytes")
    planned = PhaseCore().run(request)
    effect = planned.effect_plan["effects"][0]
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(3)
    queue = context.Queue()
    workers = [context.Process(target=_copy_worker, args=(effect, str(target), payload, barrier, queue)) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=20)
    receipts = [queue.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    assert [item["status"] for item in receipts] == ["applied_verified", "applied_verified"]
    assert sorted(item["bytes_written"] for item in receipts) == [0, len(payload)]
    assert all(item["after"]["digest"] == _sha(payload) for item in receipts)
    assert all(item["after"]["length"] == len(payload) for item in receipts)
    assert (target / _copy_locator(payload)).read_bytes() == payload


def test_copy_adversarial_writer_race_conflict_has_no_replacement_or_leftovers(tmp_path: Path) -> None:
    payload = b"adversarial"
    conflicting_payload = b"independent conflicting writer"
    root = tmp_path / "target"
    (root / "objects").mkdir(parents=True)
    effect = _effect_for_payload(payload)
    destination = root / _copy_locator(payload)
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    queue = context.Queue()
    workers = [
        context.Process(target=_copy_loser_after_observation_worker, args=(effect, str(root), payload, ready, queue)),
        context.Process(target=_precreate_conflict_worker, args=(str(destination), conflicting_payload, ready, queue)),
    ]
    for worker in workers:
        worker.start()
    results = [queue.get(timeout=30) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    receipt = next(item for item in results if "status" in item)
    writer = next(item for item in results if "created" in item)
    assert writer == {"created": True, "sha256": hashlib.sha256(conflicting_payload).hexdigest(), "length": len(conflicting_payload)}
    assert receipt["status"] == "failed_no_effect"
    assert receipt["bytes_written"] == 0
    assert receipt["before"]["exists"] is False
    assert receipt["after"]["digest"] == _sha(conflicting_payload)
    assert destination.read_bytes() == conflicting_payload
    assert not list(root.rglob("*.tmp"))


def test_copy_parent_replacement_after_observation_cannot_redirect_write(tmp_path: Path) -> None:
    probe = tmp_path / "probe-link"
    if os.name == "nt":
        probe_result = subprocess.run(["cmd", "/c", "mklink", "/J", str(probe), str(tmp_path)], check=False, capture_output=True)
        if probe_result.returncode != 0:
            pytest.skip("directory junction creation unavailable")
        probe.rmdir()
    else:
        try:
            os.symlink(tmp_path, probe, target_is_directory=True)
            probe.unlink()
        except OSError:
            pytest.skip("directory symlink creation unavailable")
    payload = b"parent replacement"
    root = tmp_path / "target"
    outside = tmp_path / "outside"
    (root / "objects").mkdir(parents=True)
    outside.mkdir()
    effect = _effect_for_payload(payload)
    destination = root / _copy_locator(payload)
    outside_destination = outside / destination.name
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    complete = context.Event()
    queue = context.Queue()
    worker = context.Process(target=_replace_parent_with_link_worker, args=(str(root), str(outside), ready, complete, queue))

    def wait_for_replacement(_target: Path) -> None:
        ready.set()  # type: ignore[attr-defined]
        if not complete.wait(timeout=20):  # type: ignore[attr-defined]
            raise TimeoutError("parent replacement worker did not finish")

    worker.start()
    outcome: dict[str, object] | PhaseError
    try:
        outcome = execute_content_addressed_copy(
            effect,
            root,
            payload,
            run_id="parent-replacement",
            timestamp=NOW,
            faults=ContentAddressedCopyFaults(before_exclusive_create=wait_for_replacement),
        )
    except PhaseError as exc:
        outcome = exc
    replacement = queue.get(timeout=20)
    worker.join(timeout=20)
    assert worker.exitcode == 0
    if replacement["replaced"]:
        assert isinstance(outcome, PhaseError)
        assert outcome.code == "path.parent_identity_changed"
        assert not (root / "objects-moved" / destination.name).exists()
        assert not destination.exists()
    else:
        assert isinstance(outcome, dict)
        assert outcome["status"] == "applied_verified"
        assert outcome["after"]["digest"] == _sha(payload)  # type: ignore[index]
        assert outcome["after"]["length"] == len(payload)  # type: ignore[index]
        assert destination.read_bytes() == payload
    assert not outside_destination.exists()


def test_copy_parent_replacement_after_write_is_indeterminate_and_cannot_redirect(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX rename semantics required")
    payload = b"late parent replacement"
    root = tmp_path / "target"
    outside = tmp_path / "outside"
    (root / "objects").mkdir(parents=True)
    outside.mkdir()
    destination = root / _copy_locator(payload)
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    complete = context.Event()
    queue = context.Queue()
    worker = context.Process(
        target=_replace_parent_with_link_worker,
        args=(str(root), str(outside), ready, complete, queue),
    )

    def replace_before_readback(_target: Path) -> None:
        ready.set()  # type: ignore[attr-defined]
        if not complete.wait(timeout=20):  # type: ignore[attr-defined]
            raise TimeoutError("parent replacement worker did not finish")

    worker.start()
    receipt = execute_content_addressed_copy(
        _effect_for_payload(payload),
        root,
        payload,
        run_id="late-parent-replacement",
        timestamp=NOW,
        faults=ContentAddressedCopyFaults(before_readback=replace_before_readback),
    )
    replacement = queue.get(timeout=20)
    worker.join(timeout=20)
    assert worker.exitcode == 0
    assert replacement == {"replaced": True}
    assert receipt["status"] == "indeterminate"
    assert receipt["after"] == {"known": False, "exists": None, "digest": None, "length": None, "head_token": None}
    assert receipt["error"]["code"] == "path.parent_identity_changed"
    assert receipt["bytes_written"] == len(payload)
    assert (root / "objects-moved" / destination.name).read_bytes() == payload
    assert not destination.exists()
    assert not (outside / destination.name).exists()


def test_freeze_copy_and_hash_uses_exclusive_blob_publication_without_replace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from phase_tool.freeze import copy_and_hash

    source = tmp_path / "source" / "payload.bin"
    source.parent.mkdir()
    source.write_bytes(b"freeze blob")
    blob_root = tmp_path / "blobs"
    calls: list[tuple[object, ...]] = []

    def forbidden_replace(*args: object) -> None:
        calls.append(args)
        raise AssertionError("copy_and_hash must not publish via os.replace")

    monkeypatch.setattr(os, "replace", forbidden_replace)
    frozen = copy_and_hash("payload", source.parent, source.name, blob_root, frozen_at=NOW)

    assert calls == []
    assert frozen.blob_path is not None
    assert frozen.blob_path.read_bytes() == b"freeze blob"
    assert not list(blob_root.glob("*.tmp"))


def test_copy_authority_closes_pins_when_observation_or_precreate_hook_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import phase_tool.mutation.content_addressed_copy as copy_module

    payload = b"authority cleanup"
    root = tmp_path / "target"
    (root / "objects").mkdir(parents=True)
    effect = _effect_for_payload(payload)
    original_observe = copy_module.TargetAuthority.observe
    original_close = copy_module.TargetAuthority.close
    closed_with_pins: list[bool] = []

    def tracked_close(authority: object) -> None:
        closed_with_pins.append(bool(authority._handles))  # type: ignore[attr-defined]
        original_close(authority)  # type: ignore[arg-type]

    def failed_observation(_authority: object) -> dict[str, object]:
        raise PhaseError("test.observation_failed")

    monkeypatch.setattr(copy_module.TargetAuthority, "close", tracked_close)
    monkeypatch.setattr(copy_module.TargetAuthority, "observe", failed_observation)
    with pytest.raises(PhaseError, match="test.observation_failed"):
        execute_content_addressed_copy(effect, root, payload, run_id="observe-failure", timestamp=NOW)
    assert closed_with_pins == [True]

    monkeypatch.setattr(copy_module.TargetAuthority, "observe", original_observe)

    def failed_hook(_target: Path) -> None:
        raise PhaseError("test.hook_failed")

    with pytest.raises(PhaseError, match="test.hook_failed"):
        execute_content_addressed_copy(
            effect,
            root,
            payload,
            run_id="hook-failure",
            timestamp=NOW,
            faults=ContentAddressedCopyFaults(before_exclusive_create=failed_hook),
        )
    assert closed_with_pins == [True, True]


def test_copy_inspect_detects_target_evidence_receipt_tampering(tmp_path: Path) -> None:
    request, target, evidence, _source, payload = copy_request(tmp_path, run_id="inspect", payload=b"inspect bytes")
    outcome = PhaseCore().run(request, execute=True)
    assert outcome.exit_code == 0
    assert inspect_run(evidence, "inspect", root_bindings={"fixture_result_root": target})["target_verified"] is True

    (target / _copy_locator(payload)).write_bytes(b"target tamper")
    with pytest.raises(PhaseError, match="inspection.target_mismatch"):
        inspect_run(evidence, "inspect", root_bindings={"fixture_result_root": target})
    (target / _copy_locator(payload)).write_bytes(payload)

    blob = evidence / ".phase" / "runs" / "inspect" / "blobs" / hashlib.sha256(payload).hexdigest()
    blob.write_bytes(b"blob tamper")
    with pytest.raises(PhaseError, match="inspection.digest_mismatch"):
        inspect_run(evidence, "inspect", root_bindings={"fixture_result_root": target})
    blob.write_bytes(payload)

    receipt = evidence / ".phase" / "runs" / "inspect" / "receipt.json"
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(PhaseError, match="inspection.invalid_json|inspection.digest_mismatch"):
        inspect_run(evidence, "inspect", root_bindings={"fixture_result_root": target})


def test_copy_safety_rejects_evidence_overlap_and_invalid_path_components(tmp_path: Path) -> None:
    request, target, _evidence, _source, _payload = copy_request(tmp_path, run_id="overlap")
    before = sorted(path.relative_to(target).as_posix() for path in target.rglob("*"))
    with pytest.raises(PhaseError, match="evidence.overlaps_target_root"):
        PhaseCore().run(replace(request, evidence_root=target / "evidence"), execute=True)
    assert sorted(path.relative_to(target).as_posix() for path in target.rglob("*")) == before

    bad_candidate = tmp_path / "bad.json"
    write_copy_candidate(bad_candidate, key="bad", destination="objects/CON.txt")
    bad = replace(request, candidate_path=bad_candidate, run_id="bad")
    rejected = PhaseCore().run(bad, execute=True)
    assert rejected.receipt["terminal_status"] == "rejected"
    assert rejected.receipt["mutation_attempted"] is False


def test_copy_cli_acceptance_under_stage5_tmp(tmp_path: Path) -> None:
    phase = [sys.executable, "-m", "phase_tool"]
    base = ROOT / ".stage5-tmp" / "cli-acceptance"
    if base.exists():
        import shutil

        shutil.rmtree(base)
    target = base / "target"
    (target / "objects").mkdir(parents=True)
    evidence = base / "evidence"
    candidate = base / "candidate.json"
    payload = base / "payload.bin"
    payload.write_bytes(b"cli copy")
    write_copy_candidate(candidate, key="cli-copy")
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    command = [
        *phase,
        "execute",
        "--contract-id",
        "fixture_copy.v1",
        "--contract-version",
        "1.0.0",
        "--contract-digest",
        _binding()["package_digest"],
        "--candidate",
        str(candidate),
        "--evidence-root",
        str(evidence),
        "--run-id",
        "cli-copy",
        "--input",
        f"payload={payload}",
        "--root",
        f"fixture_result_root={target}",
        "--timestamp",
        NOW,
    ]

    process = subprocess.run(command, capture_output=True, text=True, env=env, check=False)

    assert process.returncode == 0, process.stderr
    output = json.loads(process.stdout)
    assert output["terminal_status"] == "succeeded_verified"
    assert (target / _copy_locator(b"cli copy")).read_bytes() == b"cli copy"


def test_stage5_hardened_cli_summary_and_walkthrough_values() -> None:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    process = subprocess.run(
        [sys.executable, "scripts/stage5_cli_acceptance.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    compact = json.loads(process.stdout)
    assert compact == {
        "scenario_count": 17,
        "success": True,
        "summary": str(ROOT / ".stage5-tmp" / "final-cli" / "stage5-cli-acceptance-summary.json"),
    }
    summary = json.loads((ROOT / ".stage5-tmp" / "final-cli" / "stage5-cli-acceptance-summary.json").read_text(encoding="utf-8"))
    expected_order = [
        "01_validate_copy",
        "02_plan_copy",
        "03_execute_new_text",
        "04_inspect_run_and_target",
        "05_prior_exact_reuse",
        "06_same_operation_key_different_request_digest_conflict",
        "07_existing_identical_no_prior",
        "08_existing_different",
        "09_binary_copy",
        "10_unsafe_locator_rejection",
        "11_corrupted_frozen_blob_rejection",
        "12_fixture_create",
        "13_fixture_append",
        "14_task_journal",
        "15_multi_effect_execution_rejection",
        "16_plan_before_destination_appears",
        "17_destination_appears_conflict",
    ]
    assert summary["success"] is True
    assert summary["command_order"] == expected_order
    assert summary["py_subprocess_path_absent"] is True
    required = {"exit", "terminal_status", "disposition", "mutation_attempted", "blockers", "artifacts", "target_tree_before", "target_tree_after"}
    for name in expected_order:
        scenario = summary["command_matrix"][name]
        assert required.issubset(scenario), name
        assert scenario["terminal_status"] is not None, name
        assert scenario["exit"] == scenario["envelope"]["exit_code"], name
    assert summary["command_matrix"]["01_validate_copy"]["target_tree_before"] == summary["command_matrix"]["01_validate_copy"]["target_tree_after"]
    assert summary["command_matrix"]["02_plan_copy"]["target_tree_before"] == summary["command_matrix"]["02_plan_copy"]["target_tree_after"]
    executed = summary["command_matrix"]["03_execute_new_text"]
    assert executed["source_before"] == executed["source_after"]
    assert executed["target_tree_before"] == []
    assert executed["target_tree_after"] == [
        {
            "length": 16,
            "path": "objects/d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb",
            "sha256": "d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb",
        }
    ]
    assert summary["command_matrix"]["05_prior_exact_reuse"]["disposition"] == "reused_existing"
    assert summary["command_matrix"]["06_same_operation_key_different_request_digest_conflict"]["blockers"] == ["idempotency.same_key_conflict"]
    callback_rejected = summary["command_matrix"]["17_destination_appears_conflict"]
    assert callback_rejected["terminal_status"] == "rejected"
    assert callback_rejected["blockers"] == ["broker.unsafe_fault_callback"]

    walkthrough = (ROOT / "docs" / "STAGE-5-CONTENT-ADDRESSED-COPY-WALKTHROUGH.md").read_text(encoding="utf-8")
    copy = summary["copy"]
    assert copy["digest"] in walkthrough
    assert str(copy["length"]) in walkthrough
    assert copy["locator"] in walkthrough
    assert executed["artifacts"]["canonical_result"]["contract"]["package_digest"] in walkthrough
    for item in executed["artifacts"]["evidence_files"]:
        assert item["path"] in walkthrough
        if item["path"] not in {"intent.json", "receipt.json"}:
            assert item["sha256"] in walkthrough
    assert "captured root-identity-bound evidence" in walkthrough
    assert "not cross-root reproducibility invariants" in walkthrough


def test_stage5_architecture_scans_keep_copy_out_of_core_and_source_admission_out() -> None:
    core_text = (ROOT / "src" / "phase_tool" / "core.py").read_text(encoding="utf-8")
    assert "content_addressed_copy" not in core_text
    assert "copy_blob" not in core_text
    scanned = [
        ROOT / "src" / "phase_tool" / "core.py",
        ROOT / "src" / "phase_tool" / "mutation" / "broker.py",
        ROOT / "src" / "phase_tool" / "mutation" / "content_addressed_copy.py",
        ROOT / "src" / "phase_tool" / "mutation" / "exclusive_create.py",
        ROOT / "src" / "phase_tool" / "mutation" / "expected_head_append.py",
    ]
    for path in scanned:
        text = path.read_text(encoding="utf-8")
        assert "source_admission" not in text
        assert "knowledge_admission" not in text
