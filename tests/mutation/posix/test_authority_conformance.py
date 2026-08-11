from __future__ import annotations

import errno
import hashlib
import json
import multiprocessing
import os
import queue
import tracemalloc
from pathlib import Path

import pytest

if os.name == "nt":
    pytest.skip("POSIX authority conformance requires POSIX", allow_module_level=True)

from phase_tool.mutation.posix import PosixAuthorityProvider
from phase_tool.mutation.posix.authority import PosixTargetRootLock
from phase_tool.mutation.content_addressed_copy import execute_content_addressed_copy
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.installation import Installation
from phase_tool.registry import BundledRegistry
from tests.mutation.common.conformance import assert_basic_authority_conformance
from tests.mutation.common.guarantee_conformance import assert_common_guarantees


def _hold_root_lock(root: str, ready: object, release: object) -> None:
    provider = PosixAuthorityProvider()
    with provider.lock_target_root(Path(root), "baseline-holder"):
        ready.set()  # type: ignore[attr-defined]
        release.wait()  # type: ignore[attr-defined]


def _hold_root_lock_until_forced_exit(root: str, ready: object, exit_now: object) -> None:
    provider = PosixAuthorityProvider()
    with provider.lock_target_root(Path(root), "crashing-holder"):
        ready.set()  # type: ignore[attr-defined]
        exit_now.wait()  # type: ignore[attr-defined]
        os._exit(0)


def _attempt_content_addressed_copy(root: str, result: object) -> None:
    content = b"lock-timeout-content"
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    effect = {
        "effect_id": "effect.lock-timeout",
        "kind": "copy_blob",
        "target": {
            "root_binding": "fixture_result_root",
            "relative_locator": "objects/" + digest.removeprefix("sha256:"),
        },
        "content_digest": digest,
        "content_length": len(content),
    }
    try:
        execute_content_addressed_copy(
            effect,
            Path(root),
            content,
            run_id="lock-timeout-contender",
            timestamp="2026-08-10T00:00:00Z",
            authority_provider=PosixAuthorityProvider(),
        )
    except PhaseError as exc:
        result.put(("phase_error", exc.code))  # type: ignore[attr-defined]
    else:
        result.put(("completed", None))  # type: ignore[attr-defined]


class _ImmediateTimeoutLock:
    def __enter__(self) -> "_ImmediateTimeoutLock":
        raise PhaseError("lock.acquire_timeout")

    def __exit__(self, *_exc: object) -> None:
        return None


def test_posix_authority_common_conformance(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    assert_basic_authority_conformance(PosixAuthorityProvider(), root)


def test_posix_observation_does_not_materialize_target_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    (root / "objects").mkdir(parents=True)
    content = b"observation-summary-only"
    (root / "objects" / "item.bin").write_bytes(content)
    authority = PosixAuthorityProvider().open_authority(root, "objects/item.bin")

    def materialization_forbidden(_descriptor: int) -> bytes:
        raise AssertionError("observe called the full-byte materialization helper")

    monkeypatch.setattr(authority_module, "_read_descriptor", materialization_forbidden)
    try:
        observed = authority.observe()
    finally:
        authority.close()

    assert observed["digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    assert observed["length"] == len(content)


@pytest.mark.parametrize(
    "content",
    [b"", b"small", b"x" * (2 * 1024 * 1024 + 17)],
    ids=["empty", "small", "large"],
)
def test_posix_observation_preserves_exact_digest_and_length(tmp_path: Path, content: bytes) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "item.bin").write_bytes(content)
    authority = PosixAuthorityProvider().open_authority(root, "item.bin")
    try:
        observed = authority.observe()
    finally:
        authority.close()

    assert observed["digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    assert observed["length"] == len(content)


def test_posix_record_stream_observation_is_descriptor_bound_and_detects_parent_rebinding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    parent = root / "streams"
    parent.mkdir(parents=True)
    content = b'{"record_id":"one"}\n'
    (parent / "events.jsonl").write_bytes(content)
    authority = PosixAuthorityProvider().open_authority(root, "streams/events.jsonl", create_parents=False)
    original_observe_stream = authority_module.observe_stream

    def rebind_after_observation(stream: object, **kwargs: object) -> object:
        observation = original_observe_stream(stream, **kwargs)  # type: ignore[arg-type]
        parent.rename(root / "detached-streams")
        parent.mkdir()
        (parent / "events.jsonl").write_bytes(b'{"record_id":"replacement"}\n')
        return observation

    monkeypatch.setattr(authority_module, "observe_stream", rebind_after_observation)
    try:
        with pytest.raises(PhaseError, match="path.parent_identity_changed"):
            authority.observe_record_stream(tail_bytes=len(content))
    finally:
        authority.close()


def test_posix_observation_detects_target_rebinding_after_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    target = root / "target.bin"
    target.write_bytes(b"original")
    replacement = root / "replacement.bin"
    replacement.write_bytes(b"replacement")
    authority = PosixAuthorityProvider().open_authority(root, target.name, create_parents=False)
    original_observe_descriptor = authority_module._observe_descriptor

    def rebind_after_read(descriptor: int) -> tuple[str, int]:
        observation = original_observe_descriptor(descriptor)
        os.replace(replacement, target)
        return observation

    monkeypatch.setattr(authority_module, "_observe_descriptor", rebind_after_read)
    try:
        with pytest.raises(PhaseError, match="path.target_identity_changed"):
            authority.observe()
    finally:
        authority.close()


def test_posix_read_only_authority_does_not_create_missing_parents(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    with pytest.raises(FileNotFoundError):
        PosixAuthorityProvider().open_authority(root, "missing/target.bin", create_parents=False)

    assert not (root / "missing").exists()


def test_posix_large_observation_memory_is_bounded_by_chunks(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "large.bin"
    chunk = b"z" * (1024 * 1024)
    expected = hashlib.sha256()
    with target.open("wb") as stream:
        for _ in range(32):
            stream.write(chunk)
            expected.update(chunk)

    authority = PosixAuthorityProvider().open_authority(root, "large.bin")
    tracemalloc.start()
    try:
        observed = authority.observe()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        authority.close()

    assert observed["digest"] == "sha256:" + expected.hexdigest()
    assert observed["length"] == 32 * 1024 * 1024
    assert peak < 8 * 1024 * 1024


def test_posix_observation_preserves_descriptor_read_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    (root / "item.bin").write_bytes(b"content")
    authority = PosixAuthorityProvider().open_authority(root, "item.bin")

    def fail_read(_descriptor: int, _size: int) -> bytes:
        raise PermissionError("injected descriptor read failure")

    monkeypatch.setattr(authority_module.os, "read", fail_read)
    try:
        with pytest.raises(PermissionError, match="injected descriptor read failure"):
            authority.observe()
    finally:
        authority.close()


def test_posix_read_bytes_remains_materialized_for_byte_consumers(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    content = b"byte-consumer-content"
    (root / "item.bin").write_bytes(content)
    authority = PosixAuthorityProvider().open_authority(root, "item.bin")
    try:
        assert authority.read_bytes() == content
    finally:
        authority.close()


def test_posix_materialized_read_enforces_a_caller_supplied_limit(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
    authority = PosixAuthorityProvider().open_authority(root, "large.bin")
    try:
        with pytest.raises(PhaseError) as captured:
            authority.read_bytes(maximum_bytes=1024 * 1024)
    finally:
        authority.close()

    assert captured.value.code == "target.read_limit_exceeded"


def test_posix_readback_without_override_does_not_materialize_target_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    content = b"readback-content"
    (root / "item.bin").write_bytes(content)
    authority = PosixAuthorityProvider().open_authority(root, "item.bin")

    def reject_materialization(_descriptor: int) -> bytes:
        raise AssertionError("readback materialized target bytes")

    monkeypatch.setattr(authority_module, "_read_descriptor", reject_materialization)
    try:
        observed = authority.readback(None)
    finally:
        authority.close()

    assert observed["digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    assert observed["length"] == len(content)


def test_content_copy_lock_contention_returns_bounded_stable_phase_error_without_mutation(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    root = tmp_path / "root"
    root.mkdir()
    ready = context.Event()
    release = context.Event()
    result = context.Queue()
    holder = context.Process(target=_hold_root_lock, args=(str(root), ready, release))
    contender = context.Process(target=_attempt_content_addressed_copy, args=(str(root), result))
    holder.start()
    assert ready.wait(10)
    contender.start()
    try:
        outcome = result.get(timeout=12)
    except queue.Empty:
        contender.terminate()
        contender.join(10)
        pytest.fail("contending production mechanism did not return a bounded Phase result")
    finally:
        release.set()
        holder.join(10)
        if contender.is_alive():
            contender.terminate()
        contender.join(10)

    assert outcome == ("phase_error", "lock.acquire_timeout")
    assert list(root.rglob("*")) == []


def test_root_lock_timeout_is_a_stable_phase_rejection_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_copy.v1@1.0.0"]
    target = tmp_path / "target"
    (target / "objects").mkdir(parents=True)
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        json.dumps(
            {
                "transfer_id": "transfer-lock-timeout",
                "object_id": "object-lock-timeout",
                "input_binding": "payload",
                "destinations": ["objects/a"],
                "idempotency_key": "copy-lock-timeout",
            }
        ),
        encoding="utf-8",
    )
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"copy-payload")
    provider = PosixAuthorityProvider()
    monkeypatch.setattr(provider, "lock_target_root", lambda _root, _scope: _ImmediateTimeoutLock())
    request = PhaseRequest(
        contract_id="fixture_copy.v1",
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=tmp_path / "evidence",
        run_id="copy-lock-timeout",
        input_paths={"payload": payload},
        root_bindings={"fixture_result_root": target},
        timestamp="2026-08-10T00:00:00Z",
    )
    core = PhaseCore(
        registry=registry,
        installation=Installation(
            authority_provider=provider,
            authority_profile_binding=provider.guarantee_profile_binding(),
        ),
    )

    outcome = core.run(request, execute=True)

    assert outcome.exit_code == 10
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["lock.acquire_timeout"]
    assert outcome.receipt["mutation_attempted"] is False
    assert list((target / "objects").iterdir()) == []


def test_posix_root_lock_closes_descriptor_when_flock_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    closed: list[int] = []
    original_close = authority_module.os.close

    def fail_flock(_descriptor: int, _operation: int) -> None:
        raise OSError("injected flock failure")

    def record_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(authority_module.fcntl, "flock", fail_flock)
    monkeypatch.setattr(authority_module.os, "close", record_close)
    lock = PosixTargetRootLock(root, "scope")

    with pytest.raises(OSError, match="injected flock failure"):
        lock.__enter__()

    assert len(closed) == 1
    assert lock._descriptor is None


def test_posix_root_lock_timeout_uses_nonblocking_flock_and_closes_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    operations: list[int] = []
    closed: list[int] = []
    original_close = authority_module.os.close

    def contend(_descriptor: int, operation: int) -> None:
        operations.append(operation)
        raise BlockingIOError(errno.EAGAIN, "contended")

    def record_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(authority_module.fcntl, "flock", contend)
    monkeypatch.setattr(authority_module.os, "close", record_close)
    lock = PosixTargetRootLock(root, "scope", timeout_seconds=0.0)

    with pytest.raises(PhaseError) as captured:
        lock.__enter__()

    assert captured.value.code == "lock.acquire_timeout"
    assert operations == [authority_module.fcntl.LOCK_EX | authority_module.fcntl.LOCK_NB]
    assert len(closed) == 1
    assert lock._descriptor is None


def test_posix_root_lock_retries_eintr_then_acquires(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    attempts = 0
    original_flock = authority_module.fcntl.flock

    def interrupt_once(descriptor: int, operation: int) -> None:
        nonlocal attempts
        if operation & authority_module.fcntl.LOCK_NB and attempts == 0:
            attempts += 1
            raise OSError(errno.EINTR, "interrupted")
        original_flock(descriptor, operation)

    monkeypatch.setattr(authority_module.fcntl, "flock", interrupt_once)
    with PosixTargetRootLock(root, "scope", timeout_seconds=1.0):
        pass

    assert attempts == 1


def test_posix_root_lock_closes_descriptor_when_unlock_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    closed: list[int] = []
    original_close = authority_module.os.close
    original_flock = authority_module.fcntl.flock

    def fail_unlock(descriptor: int, operation: int) -> None:
        if operation == authority_module.fcntl.LOCK_UN:
            raise OSError("injected unlock failure")
        original_flock(descriptor, operation)

    def record_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(authority_module.fcntl, "flock", fail_unlock)
    monkeypatch.setattr(authority_module.os, "close", record_close)
    lock = PosixTargetRootLock(root, "scope")
    lock.__enter__()

    with pytest.raises(OSError, match="injected unlock failure"):
        lock.__exit__(None, None, None)

    assert len(closed) == 1
    assert lock._descriptor is None


def test_posix_root_lock_becomes_available_when_holder_process_dies(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    root = tmp_path / "root"
    root.mkdir()
    ready = context.Event()
    exit_now = context.Event()
    holder = context.Process(target=_hold_root_lock_until_forced_exit, args=(str(root), ready, exit_now))
    holder.start()
    assert ready.wait(10)
    exit_now.set()
    holder.join(10)
    assert holder.exitcode == 0

    with PosixTargetRootLock(root, "after-holder-death", timeout_seconds=1.0):
        pass


def test_repeated_root_lock_timeouts_do_not_leak_descriptors_or_poison_future_acquisition(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    root = tmp_path / "root"
    root.mkdir()
    ready = context.Event()
    release = context.Event()
    holder = context.Process(target=_hold_root_lock, args=(str(root), ready, release))
    holder.start()
    assert ready.wait(10)
    descriptors_before = len(list(Path("/proc/self/fd").iterdir()))
    try:
        for _ in range(3):
            with pytest.raises(PhaseError) as captured:
                PosixTargetRootLock(root, "repeated-timeout", timeout_seconds=0.05).__enter__()
            assert captured.value.code == "lock.acquire_timeout"
        assert len(list(Path("/proc/self/fd").iterdir())) == descriptors_before
    finally:
        release.set()
        holder.join(10)
        if holder.is_alive():
            holder.terminate()
            holder.join(10)
    assert holder.exitcode == 0

    with PosixTargetRootLock(root, "after-timeouts", timeout_seconds=1.0):
        pass


def test_posix_production_profile_common_guarantees(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    provider = PosixAuthorityProvider()
    binding = provider.guarantee_profile_binding()
    assert binding.id == "phase.posix.authority.v1"
    assert_common_guarantees(provider, root)


def test_posix_production_profile_claims_only_executable_conformance_guarantees() -> None:
    from phase_tool.registry import BundledRegistry

    provider = PosixAuthorityProvider()
    profile = BundledRegistry.load().resolve_guarantee_profile(provider.guarantee_profile_binding().as_dict())

    assert profile["classification"] == "production"
    assert set(profile["provided_guarantees"]) == {
        "exclusive_create",
        "readback_verification",
        "cross_process_serialization",
        "namespace_bound_mutation",
        "atomic_replace",
        "namespace_metadata_flush_attempted",
    }
    assert {item["guarantee"] for item in profile["conformance"]} == set(profile["provided_guarantees"])
    assert "process_crash_recovery" not in profile["provided_guarantees"]
