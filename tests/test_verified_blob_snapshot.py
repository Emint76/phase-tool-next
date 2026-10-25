"""Qualified Linux snapshot lifetime controls; no native admission or transport."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path

import pytest

from phase_tool import streaming
from phase_tool.application import PhaseApplication
from phase_tool.errors import PhaseError
from phase_tool.installation import qualify_host_authority_roots
from phase_tool.mutation import stream_create
from phase_tool.mutation.posix.authority import PosixAuthorityProvider

pytestmark = pytest.mark.skipif(os.name != "posix", reason="qualified Linux snapshot required")


@pytest.fixture(autouse=True)
def _qualified_roots(tmp_path):
    qualify_host_authority_roots({"snapshot_input": tmp_path})


def _binding(data):
    return "sha256:" + hashlib.sha256(data).hexdigest(), len(data)


def _blob(tmp_path, data):
    blob = tmp_path / "frozen-input"
    blob.write_bytes(data)
    return blob


def _closed(fd):
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF


def _read_all(fd):
    chunks = []
    while chunk := os.read(fd, 128 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _effect(data):
    digest, length = _binding(data)
    return {"effect_id": "snapshot-effect", "kind": "exclusive_create",
            "target": {"root_binding": "phase_result_root", "relative_locator": "result.bin"},
            "content_digest": digest, "content_length": length}


class _NoTarget:
    def open_authority(self, *args, **kwargs):
        raise AssertionError("target authority opened before input validation")


def _execute(blob, expected, root, provider=None):
    effect = _effect(b"")
    effect.update(content_digest=expected[0], content_length=expected[1])
    return stream_create.execute_stream_create(effect, root, blob, run_id="snapshot-case",
        timestamp="2026-01-01T00:00:00Z",
        authority_provider=provider if provider is not None else _NoTarget())


def _record_snapshots(monkeypatch):
    opened = []
    temporary = streaming.TemporaryFile

    def record(*args, **kwargs):
        result = temporary(*args, **kwargs)
        opened.append(result.fileno())
        return result

    monkeypatch.setattr(streaming, "TemporaryFile", record)
    return opened


def test_verified_snapshot_keeps_anonymous_object_after_blob_path_replacement(tmp_path):
    data = bytes(range(256)) * 17
    blob = _blob(tmp_path, data)
    before = blob.stat()
    with streaming._verified_blob_snapshot(blob, _binding(data)) as fd:
        opened = os.fstat(fd)
        assert (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        assert opened.st_nlink == 0
        assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"unrelated replacement")
        replacement.replace(blob)
        assert _read_all(fd) == data
        assert blob.read_bytes() == b"unrelated replacement"
    _closed(fd)


def test_host_publication_consumes_same_live_verified_descriptor_then_separately_inspects(tmp_path, monkeypatch):
    from .test_publish_file import roots, arguments

    paths = roots(tmp_path)
    data = bytes(range(256)) * 8193
    (paths["source"] / "ready.zip").write_bytes(data)
    snapshot = stream_create._verified_blob_snapshot
    execute = stream_create._execute_snapshot
    held, consumed = [], []

    @contextmanager
    def tracked(*args, **kwargs):
        with snapshot(*args, **kwargs) as fd:
            held.append(fd)
            assert os.fstat(fd).st_nlink == 0
            yield fd

    def checked(effect, target_root, fd, **kwargs):
        assert held == [fd] and not consumed
        assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        consumed.append(fd)
        return execute(effect, target_root, fd, **kwargs)

    monkeypatch.setattr(stream_create, "_verified_blob_snapshot", tracked)
    monkeypatch.setattr(stream_create, "_execute_snapshot", checked)
    app = PhaseApplication()
    result = app.publish_file(**arguments(paths), publication_version="2.0").payload
    assert result["success"] and result["status"] == "verified", result
    assert held == consumed and len(held) == 1
    _closed(held[0])
    assert (paths["target"] / "result.bin").read_bytes() == data
    inspected = app.inspect(evidence_root=paths["evidence"], run_id=result["run_id"],
        root_bindings={"phase_result_root": paths["target"]}).payload
    assert inspected["success"] and inspected["target_verified"], inspected
    assert inspected["receipt_digest"] == result["receipt_digest"]


def test_existing_destination_keeps_original_bytes_and_no_effect_receipt(tmp_path, monkeypatch):
    data = b"new proposed payload"
    blob = _blob(tmp_path, data)
    root = tmp_path / "target"
    root.mkdir()
    target = root / "result.bin"
    target.write_bytes(b"keep original")
    snapshots = _record_snapshots(monkeypatch)
    receipt = _execute(blob, _binding(data), root, PosixAuthorityProvider())
    assert receipt["status"] == "failed_no_effect", receipt
    assert receipt["bytes_written"] == 0
    assert receipt["error"]["code"] == "target.destination_exists"
    assert target.read_bytes() == b"keep original" and blob.read_bytes() == data
    assert len(snapshots) == 1
    _closed(snapshots[0])


def test_wrong_copy_digest_refuses_before_target_authority(tmp_path, monkeypatch):
    blob = _blob(tmp_path, b"actual")
    expected = _binding(b"other!")
    snapshots = _record_snapshots(monkeypatch)
    with pytest.raises(PhaseError, match="mechanism.content_binding_mismatch"):
        _execute(blob, expected, tmp_path / "target")
    assert snapshots == []  # Existing precheck still precedes anonymous capture.
    monkeypatch.setattr(stream_create, "hash_file", lambda *args: expected)
    with pytest.raises(PhaseError, match="mechanism.content_binding_mismatch"):
        _execute(blob, expected, tmp_path / "target")
    assert len(snapshots) == 1  # Now the actual private copy, not a trust flag, rejects.
    _closed(snapshots[0])
    assert not (tmp_path / "target").exists()


def test_wrong_copy_length_refuses_before_target_authority(tmp_path, monkeypatch):
    data = b"same digest, different asserted length"
    blob = _blob(tmp_path, data)
    expected = (_binding(data)[0], len(data) + 1)
    monkeypatch.setattr(stream_create, "hash_file", lambda *args: expected)
    snapshots = _record_snapshots(monkeypatch)
    with pytest.raises(PhaseError, match="mechanism.content_binding_mismatch"):
        _execute(blob, expected, tmp_path / "target")
    assert len(snapshots) == 1 and not (tmp_path / "target").exists()
    _closed(snapshots[0])


def _changed_capture(tmp_path, monkeypatch, mode):
    data = b"a" * (64 * 1024 + 3)
    blob = _blob(tmp_path, data)
    transfer, read = streaming.transfer, os.read
    before = blob.stat()
    sources, snapshots, changed = [], _record_snapshots(monkeypatch), []

    def capture(source, maximum, destination=None, **kwargs):
        if destination is None:
            return transfer(source, maximum, destination, **kwargs)
        sources.append(source)

        def observed(fd, count):
            block = read(fd, count)
            if fd == source and block and not changed:
                changed.append(True)
                with blob.open("r+b") as output:
                    if mode == "grow":
                        output.seek(0, os.SEEK_END)
                        output.write(b"extra")
                    elif mode == "shrink":
                        output.truncate(1)
                    else:
                        output.seek(0)
                        output.write(b"b")
                os.utime(blob, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
            return block

        with monkeypatch.context() as patcher:
            patcher.setattr(streaming.os, "read", observed)
            return transfer(source, maximum, destination, **kwargs)

    monkeypatch.setattr(streaming, "transfer", capture)
    with pytest.raises(PhaseError, match="freeze.source_changed_during_capture"):
        _execute(blob, _binding(data), tmp_path / "target")
    assert changed == [True] and len(sources) == len(snapshots) == 1
    assert not (tmp_path / "target").exists()
    _closed(sources[0])
    _closed(snapshots[0])


def test_copy_growth_refuses_before_target_authority_and_closes_resources(tmp_path, monkeypatch):
    _changed_capture(tmp_path, monkeypatch, "grow")


def test_copy_shrink_refuses_before_target_authority_and_closes_resources(tmp_path, monkeypatch):
    _changed_capture(tmp_path, monkeypatch, "shrink")


def test_same_length_copy_drift_refuses_before_target_authority_and_closes_resources(tmp_path, monkeypatch):
    _changed_capture(tmp_path, monkeypatch, "change")


def test_copy_write_failure_closes_source_and_snapshot_before_target(tmp_path, monkeypatch):
    data = b"frozen"
    blob = _blob(tmp_path, data)
    transfer = streaming.transfer
    sources, snapshots = [], _record_snapshots(monkeypatch)
    failure = OSError(28, "injected snapshot write failure")

    def capture(source, maximum, destination=None, **kwargs):
        if destination is None:
            return transfer(source, maximum, destination, **kwargs)
        sources.append(source)

        def failed(fd, block):
            assert fd == destination
            raise failure

        with monkeypatch.context() as patcher:
            patcher.setattr(streaming.os, "write", failed)
            return transfer(source, maximum, destination, **kwargs)

    monkeypatch.setattr(streaming, "transfer", capture)
    with pytest.raises(OSError) as caught:
        _execute(blob, _binding(data), tmp_path / "target")
    assert caught.value is failure and not (tmp_path / "target").exists()
    assert len(sources) == len(snapshots) == 1
    _closed(sources[0])
    _closed(snapshots[0])


def test_short_snapshot_writes_remain_bounded_and_byte_exact(tmp_path, monkeypatch):
    data = b"x" * (streaming.CHUNK_BYTES + 17)
    blob = _blob(tmp_path, data)
    write, requests = os.write, []

    def short(fd, block):
        requests.append(len(block))
        return write(fd, block[:65521])

    monkeypatch.setattr(streaming.os, "write", short)
    with streaming._verified_blob_snapshot(blob, _binding(data)) as fd:
        assert _read_all(fd) == data
    assert requests and max(requests) <= streaming.CHUNK_BYTES
    assert blob.read_bytes() == data
    _closed(fd)


def test_rewind_failure_closes_snapshot_before_target_authority(tmp_path, monkeypatch):
    data = b"rewind"
    blob = _blob(tmp_path, data)
    snapshots = _record_snapshots(monkeypatch)
    failure = OSError("injected rewind failure")

    def failed(fd, offset, whence):
        assert snapshots == [fd] and offset == 0 and whence == os.SEEK_SET
        raise failure

    monkeypatch.setattr(streaming.os, "lseek", failed)
    with pytest.raises(OSError) as caught:
        _execute(blob, _binding(data), tmp_path / "target")
    assert caught.value is failure and not (tmp_path / "target").exists()
    assert len(snapshots) == 1
    _closed(snapshots[0])


def test_consumer_primary_exception_survives_owned_snapshot_close(tmp_path):
    data = b"consumer"
    blob = _blob(tmp_path, data)
    failure = RuntimeError("consumer failed")
    with pytest.raises(RuntimeError) as caught:
        with streaming._verified_blob_snapshot(blob, _binding(data)) as fd:
            assert _read_all(fd) == data
            raise failure
    assert caught.value is failure and blob.read_bytes() == data
    _closed(fd)
