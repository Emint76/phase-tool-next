from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from phase_tool import streaming
from phase_tool.candidate import capture_raw, capture_structured
from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, profile_digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.freeze import (
    copy_and_hash,
    freeze_declared_inputs,
    lock_snapshot_revalidate,
    manifest_and_hash,
    revalidate_frozen,
    revalidate_manifest,
    revalidate_snapshot,
    value_snapshot,
)
from phase_tool.paths import inspect_target_path, safe_relative_locator


_FROZEN_AT = "2026-07-27T00:00:00Z"


@pytest.mark.skipif(os.name != "posix", reason="requires the existing POSIX streaming finalization")
@pytest.mark.parametrize("length", [65_536, 0])
def test_native_expected_stream_source_bound_preserves_the_frozen_input(tmp_path, monkeypatch, length):
    source = tmp_path / "payload.bin"
    payload = b"a" * length
    source.write_bytes(payload)
    expected = (digest_bytes(payload), length)
    calls = []
    transfer = streaming.transfer

    def observed(fd, maximum, destination=None):
        calls.append((maximum, destination is not None))
        return transfer(fd, maximum, destination)

    monkeypatch.setattr(streaming, "transfer", observed)
    contract = {"operation": {"mechanism": {"id": streaming.MECHANISM_ID}},
                "input_bindings": [{"id": "payload", "required": True, "freeze_strategy": "copy_and_hash"}]}
    frozen = freeze_declared_inputs(
        contract, {}, {"payload": source}, {}, tmp_path / "blobs",
        frozen_at=_FROZEN_AT, maximum_structured_bytes=128, _native_expected_inputs={"payload": expected},
    )["payload"]
    assert calls == [(length, True), (streaming.FILE_LIMIT, False)]
    assert (frozen.digest, frozen.length) == expected
    assert frozen.streamed and frozen.frozen_at == _FROZEN_AT
    assert frozen.blob_path.read_bytes() == payload


@pytest.mark.parametrize("length", [1, 5])
def test_native_expected_stream_source_size_mismatch_refuses_before_copy(tmp_path, monkeypatch, length):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"abc")
    blobs = tmp_path / "blobs"

    def unexpected(*args, **kwargs):
        pytest.fail("stable expected-length mismatch reached the temporary copy")

    monkeypatch.setattr(streaming, "NamedTemporaryFile", unexpected)
    with pytest.raises(PhaseError, match="freeze.expected_content_mismatch") as mismatch:
        streaming.copy_and_hash_stream("payload", tmp_path, source.name, blobs, frozen_at=_FROZEN_AT,
                                      _expected_input=(digest_bytes(b"abc"), length))
    assert str(mismatch.value) == "freeze.expected_content_mismatch: payload"
    assert not list(blobs.iterdir())


def test_native_expected_stream_preserves_hard_size_refusal(tmp_path, monkeypatch):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"a")
    identity = source.stat()
    real_stat, real_fstat = Path.stat, os.fstat

    def oversized(point):
        return SimpleNamespace(st_dev=point.st_dev, st_ino=point.st_ino, st_mode=point.st_mode,
                               st_size=streaming.FILE_LIMIT + 1, st_mtime_ns=point.st_mtime_ns,
                               st_ctime_ns=point.st_ctime_ns)

    def named(path, **kwargs):
        point = real_stat(path, **kwargs)
        return oversized(point) if path == source else point

    def opened(fd):
        point = real_fstat(fd)
        same = (point.st_dev, point.st_ino) == (identity.st_dev, identity.st_ino)
        return oversized(point) if same else point

    # Model the original stable 2 GiB + 1 observation with a one-byte fixture.
    monkeypatch.setattr(Path, "stat", named)
    monkeypatch.setattr(streaming.os, "fstat", opened)
    blobs = tmp_path / "blobs"
    with pytest.raises(PhaseError, match="stream.limit_exceeded"):
        streaming.copy_and_hash_stream("payload", tmp_path, source.name, blobs, frozen_at=_FROZEN_AT,
                                      _expected_input=(digest_bytes(b"a"), 1))
    assert not list(blobs.iterdir())


def test_native_expected_stream_growth_cannot_write_past_exact_length(tmp_path, monkeypatch):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"abcdef")
    blobs = tmp_path / "blobs"
    amount = [0]
    read, transfer = os.read, streaming.transfer
    requests = []

    def grow(fd, count):
        requests.append(count)
        if len(requests) == 2:
            with source.open("ab") as writer:
                writer.write(b"g")
        return read(fd, count)

    def observe(fd, maximum, destination):
        assert maximum == 6
        return transfer(fd, maximum, destination, write_counter=amount)

    monkeypatch.setattr(streaming, "CHUNK_BYTES", 4)
    monkeypatch.setattr(streaming, "transfer", observe)
    monkeypatch.setattr(streaming.os, "read", grow)
    with pytest.raises(PhaseError, match="freeze.source_changed_during_capture"):
        streaming.copy_and_hash_stream("payload", tmp_path, source.name, blobs, frozen_at=_FROZEN_AT,
                                      _expected_input=(digest_bytes(b"abcdef"), 6))
    assert requests == [4, 3] and amount == [4]
    assert not list(blobs.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="requires rename of an open POSIX source")
def test_native_expected_stream_rejects_same_bytes_on_replaced_path(tmp_path, monkeypatch):
    source = tmp_path / "payload.bin"
    replacement = tmp_path / "replacement.bin"
    for path in (source, replacement):
        path.write_bytes(b"same")
    blobs = tmp_path / "blobs"
    transfer = streaming.transfer

    def replace_after_read(fd, maximum, destination):
        observed = transfer(fd, maximum, destination)
        os.replace(replacement, source)
        return observed

    monkeypatch.setattr(streaming, "transfer", replace_after_read)
    with pytest.raises(PhaseError, match="freeze.source_changed_during_capture"):
        streaming.copy_and_hash_stream("payload", tmp_path, source.name, blobs, frozen_at=_FROZEN_AT,
                                      _expected_input=(digest_bytes(b"same"), 4))
    assert not list(blobs.iterdir())


def test_native_expected_stream_wrong_digest_has_no_linked_blob(tmp_path):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"bad")
    blobs = tmp_path / "blobs"
    with pytest.raises(PhaseError, match="freeze.expected_content_mismatch"):
        streaming.copy_and_hash_stream("payload", tmp_path, source.name, blobs, frozen_at=_FROZEN_AT,
                                      _expected_input=(digest_bytes(b"abc"), 3))
    assert not list(blobs.iterdir())


def test_native_expected_stream_does_not_reduce_existing_blob_readback_bound(tmp_path):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"a")
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    expected = (digest_bytes(b"a"), 1)
    destination = blobs / expected[0].removeprefix("sha256:")
    destination.write_bytes(b"longer")
    with pytest.raises(PhaseError, match="freeze.blob_collision"):
        streaming.copy_and_hash_stream("payload", tmp_path, source.name, blobs, frozen_at=_FROZEN_AT,
                                      _expected_input=expected)
    assert list(blobs.iterdir()) == [destination] and destination.read_bytes() == b"longer"


@pytest.mark.skipif(os.name != "posix", reason="requires the existing POSIX streaming finalization")
@pytest.mark.parametrize("expectation", [None, ("invalid", 1), (digest_bytes(b"abc"), True)])
def test_unbound_or_invalid_stream_expectation_preserves_legacy_copy(tmp_path, monkeypatch, expectation):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"abc")
    calls = []
    transfer = streaming.transfer

    def observed(fd, maximum, destination=None):
        calls.append(maximum)
        return transfer(fd, maximum, destination)

    monkeypatch.setattr(streaming, "transfer", observed)
    frozen = streaming.copy_and_hash_stream("payload", tmp_path, source.name, tmp_path / "blobs",
                                            frozen_at=_FROZEN_AT, _expected_input=expectation)
    assert calls == [streaming.FILE_LIMIT, streaming.FILE_LIMIT]
    assert frozen.blob_path.read_bytes() == b"abc"


def test_structured_candidate_is_captured_once_and_immutable(tmp_path: Path) -> None:
    source = tmp_path / "candidate.json"
    source.write_text('{"b":2,"a":1}', encoding="utf-8")
    captured = capture_structured(source, maximum_bytes=128)
    source.write_text('{"changed":true}', encoding="utf-8")
    assert captured.canonical_bytes == b'{"a":1,"b":2}'
    assert captured.digest == profile_digest_bytes("candidate", b'{"a":1,"b":2}')
    assert dict(captured.value) == {"a": 1, "b": 2}
    with pytest.raises(TypeError):
        captured.value["a"] = 9  # type: ignore[index]


def test_candidate_capture_is_bounded_and_supports_raw_bytes(tmp_path: Path) -> None:
    source = tmp_path / "candidate.bin"
    source.write_bytes(b"abc\x00")
    assert capture_raw(source, maximum_bytes=4).captured_bytes == b"abc\x00"
    with pytest.raises(PhaseError, match="candidate.too_large"):
        capture_raw(source, maximum_bytes=3)


def test_value_snapshot_uses_canonical_profile() -> None:
    frozen = value_snapshot("binding", {"b": 2, "a": 1}, frozen_at="2026-07-27T00:00:00Z")
    assert frozen.digest == digest_bytes(b'{"a":1,"b":2}')
    assert frozen.strategy == "value_snapshot"
    assert frozen.blob_digest is None


def test_copy_and_hash_uses_only_frozen_blob_after_capture(tmp_path: Path) -> None:
    input_root = tmp_path / "inputs"
    blob_root = tmp_path / "evidence" / "blobs"
    input_root.mkdir()
    source = input_root / "payload.bin"
    source.write_bytes(b"original")
    frozen = copy_and_hash("payload", input_root, "payload.bin", blob_root, frozen_at="2026-07-27T00:00:00Z")
    source.write_bytes(b"mutated upstream")
    assert frozen.blob_path is not None
    assert frozen.blob_path.read_bytes() == b"original"
    revalidate_frozen(frozen)


def test_copy_and_hash_preserves_not_regular_file_classification(tmp_path: Path) -> None:
    source = tmp_path / "directory-input"
    source.mkdir()

    with pytest.raises(PhaseError) as error:
        copy_and_hash("payload", tmp_path, source.name, tmp_path / "blobs", frozen_at="2026-07-27T00:00:00Z")

    assert error.value.code == "freeze.not_regular_file"


def test_lock_snapshot_normalizes_only_source_filesystem_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "target"
    root.mkdir()
    source = root / "state.txt"
    source.write_bytes(b"head\n")
    original_open = Path.open

    def unavailable_open(path: Path, *args: object, **kwargs: object) -> object:
        if path == source:
            raise PermissionError("private host diagnostic")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", unavailable_open)
    with pytest.raises(PhaseError) as error:
        lock_snapshot_revalidate("current_state", root, source.name, frozen_at="2026-07-27T00:00:00Z")

    assert error.value.code == "freeze.input_unavailable"


def test_frozen_blob_tampering_is_detected(tmp_path: Path) -> None:
    root = tmp_path / "inputs"
    blobs = tmp_path / "evidence" / "blobs"
    root.mkdir()
    (root / "payload").write_bytes(b"content")
    frozen = copy_and_hash("payload", root, "payload", blobs, frozen_at="2026-07-27T00:00:00Z")
    assert frozen.blob_path is not None
    frozen.blob_path.write_bytes(b"tampered")
    with pytest.raises(PhaseError, match="freeze.blob_tampered"):
        revalidate_frozen(frozen)


def test_revalidate_frozen_normalizes_blob_read_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import phase_tool.freeze as freeze_module

    root = tmp_path / "input"
    root.mkdir()
    (root / "payload").write_bytes(b"payload")
    frozen = copy_and_hash("payload", root, "payload", tmp_path / "blobs", frozen_at="2026-07-27T00:00:00Z")

    def fail_blob_read(path: Path, maximum_bytes: int) -> bytes:
        raise PermissionError("private frozen blob diagnostic")

    monkeypatch.setattr(freeze_module, "_read_file_stable", fail_blob_read)
    with pytest.raises(PhaseError) as unavailable:
        revalidate_frozen(frozen)

    assert unavailable.value.code == "freeze.blob_unavailable"
    assert "private frozen blob diagnostic" not in str(unavailable.value)


def test_target_inspection_preserves_missing_classification_below_file_parent(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    (root / "parent").write_bytes(b"not-a-directory")

    target, exists = inspect_target_path(root, "parent/item.bin")

    assert target == root / "parent" / "item.bin"
    assert exists is False


def test_manifest_and_hash_is_deterministic_and_read_only(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "b.txt").write_bytes(b"b")
    (root / "a.txt").write_bytes(b"a")
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    first = manifest_and_hash("tree", root, frozen_at="2026-07-27T00:00:00Z")
    second = manifest_and_hash("tree", root, frozen_at="2026-07-27T00:00:00Z")
    assert first.manifest_digest == second.manifest_digest
    assert [entry["locator"] for entry in first.manifest] == ["a.txt", "b.txt"]
    assert before == {p.name: p.read_bytes() for p in root.iterdir()}


def test_lock_snapshot_detects_stale_token_without_writing_target(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    target = root / "state.txt"
    target.write_bytes(b"head-a\n")
    before = target.read_bytes()
    frozen = lock_snapshot_revalidate("current_state", root, "state.txt", frozen_at="2026-07-27T00:00:00Z")
    revalidate_snapshot(frozen, root)
    assert target.read_bytes() == before
    target.write_bytes(b"head-b\n")
    with pytest.raises(PhaseError, match="freeze.stale_snapshot"):
        revalidate_snapshot(frozen, root)


@pytest.mark.parametrize("locator", ["../escape", "/absolute", "C:/drive", "dir\\escape", "NUL.txt", "a/COM1.log", "trailing."])
def test_path_policy_rejects_traversal_and_windows_reserved_names(locator: str) -> None:
    with pytest.raises(PhaseError):
        safe_relative_locator(locator)


def test_symlink_component_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "real").mkdir()
    try:
        os.symlink(root / "real", root / "link", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(PhaseError, match="path.link_forbidden"):
        copy_and_hash("payload", root, "link/file", tmp_path / "blobs", frozen_at="2026-07-27T00:00:00Z")


def test_reparse_component_is_rejected_by_common_path_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "payload").write_bytes(b"x")
    monkeypatch.setattr("phase_tool.paths._is_reparse_point", lambda path: path.name == "payload")
    with pytest.raises(PhaseError, match="path.reparse_forbidden"):
        copy_and_hash("payload", root, "payload", tmp_path / "blobs", frozen_at="2026-07-27T00:00:00Z")


def test_copy_detects_source_mutation_during_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    root = tmp_path / "root"
    root.mkdir()
    source = root / "payload.bin"
    source.write_bytes(b"before")
    original_open = Path.open

    class MutatingReader:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __enter__(self):
            self.wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)

        def read(self, *args):
            data = self.wrapped.read(*args)
            with io.open(source, "wb") as stream:
                stream.write(b"after-change")
            return data

        def fileno(self):
            return self.wrapped.fileno()

    def patched_open(path: Path, *args, **kwargs):
        opened = original_open(path, *args, **kwargs)
        return MutatingReader(opened) if path == source and args and args[0] == "rb" else opened

    monkeypatch.setattr(Path, "open", patched_open)
    with pytest.raises(PhaseError, match="freeze.source_changed_during_capture"):
        copy_and_hash("payload", root, "payload.bin", tmp_path / "blobs", frozen_at="2026-07-27T00:00:00Z")


def test_manifest_revalidation_detects_add_remove_and_content_drift(tmp_path: Path) -> None:
    root = tmp_path / "manifest"
    root.mkdir()
    first = root / "a.txt"
    first.write_bytes(b"a")
    frozen = manifest_and_hash("bundle", root, frozen_at="2026-07-27T00:00:00Z")
    revalidate_manifest(frozen, root)
    first.write_bytes(b"changed")
    with pytest.raises(PhaseError, match="freeze.manifest_drift"):
        revalidate_manifest(frozen, root)

    first.write_bytes(b"a")
    (root / "b.txt").write_bytes(b"b")
    with pytest.raises(PhaseError, match="freeze.manifest_drift"):
        revalidate_manifest(frozen, root)

    (root / "b.txt").unlink()
    first.unlink()
    with pytest.raises(PhaseError, match="freeze.manifest_drift"):
        revalidate_manifest(frozen, root)
