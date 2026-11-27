"""Genuine default-I/O Linux snapshot cap tests; never native qualification."""
import errno
import hashlib
import os
import sys
from pathlib import Path

import pytest

from phase_tool import streaming
from phase_tool.errors import PhaseError

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="requires real Linux snapshot open/anonymous semantics")


def binding(data):
    return "sha256:" + hashlib.sha256(data).hexdigest(), len(data)


@pytest.mark.parametrize("expected", [
    ["sha256:" + "a" * 64, 0],
    ("sha256:" + "a" * 64,),
    ("sha256:" + "z" * 64, 0),
    ("sha256:" + "a" * 64, True),
    ("sha256:" + "a" * 64, -1),
    ("sha256:" + "a" * 64, streaming.FILE_LIMIT + 1),
])
def test_invalid_snapshot_expected_binding_opens_nothing(tmp_path, monkeypatch, expected):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid binding attempted I/O")
    monkeypatch.setattr(streaming, "TemporaryFile", forbidden)
    with pytest.raises(PhaseError, match="mechanism.content_binding_mismatch"):
        with streaming._verified_blob_snapshot(tmp_path / "absent", expected):
            raise AssertionError("invalid binding yielded")


@pytest.mark.parametrize("data", [b"", bytes(range(256)) * 257])
def test_real_private_snapshot_uses_exact_expected_cap(tmp_path, monkeypatch, data):
    blob = tmp_path / "blob"
    blob.write_bytes(data)
    transfer = streaming.transfer
    caps = []
    def record(source, maximum, destination=None, **kwargs):
        caps.append(maximum)
        return transfer(source, maximum, destination, **kwargs)
    monkeypatch.setattr(streaming, "transfer", record)
    with streaming._verified_blob_snapshot(blob, binding(data)) as fd:
        info = os.fstat(fd)
        assert info.st_size == len(data) and info.st_nlink == 0
        assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        assert os.read(fd, len(data) + 1) == data
    with pytest.raises(OSError) as closed:
        os.fstat(fd)
    assert closed.value.errno == errno.EBADF
    assert caps == [len(data)]


def test_larger_frozen_blob_refuses_before_payload_copy(tmp_path, monkeypatch):
    blob = tmp_path / "blob"
    blob.write_bytes(b"abcd")
    def forbidden(*args, **kwargs):
        raise AssertionError("oversized frozen blob reached transfer")
    monkeypatch.setattr(streaming, "transfer", forbidden)
    with pytest.raises(PhaseError, match="mechanism.content_binding_mismatch"):
        with streaming._verified_blob_snapshot(blob, binding(b"abc")):
            raise AssertionError("wrong size yielded")


def test_source_growth_extra_byte_never_reaches_private_write(tmp_path, monkeypatch):
    data = b"a" * (64 * 1024)
    blob = tmp_path / "blob"
    blob.write_bytes(data)
    read, write = os.read, os.write
    changed, written = [], []
    def growing(source, count):
        chunk = read(source, count)
        if chunk and not changed:
            with blob.open("ab") as output:
                output.write(b"extra")
            changed.append(True)
        return chunk
    def counted(destination, chunk):
        count = write(destination, chunk)
        written.append(count)
        return count
    monkeypatch.setattr(streaming.os, "read", growing)
    monkeypatch.setattr(streaming.os, "write", counted)
    with pytest.raises(PhaseError, match="freeze.source_changed_during_capture"):
        with streaming._verified_blob_snapshot(blob, binding(data)):
            raise AssertionError("growing source yielded")
    assert changed and sum(written) == len(data)


def test_source_close_failure_cannot_yield_a_valid_snapshot(tmp_path, monkeypatch):
    data = b"source-close"
    blob = tmp_path / "blob"
    blob.write_bytes(data)
    opened = []
    source_open, source_close = os.open, os.close
    def record(path, flags, *args, **kwargs):
        fd = source_open(path, flags, *args, **kwargs)
        if Path(path) == blob:
            opened.append(fd)
        return fd
    def failed(fd):
        source_close(fd)
        if fd in opened:
            raise OSError("recorded source close failure")
    monkeypatch.setattr(streaming.os, "open", record)
    monkeypatch.setattr(streaming.os, "close", failed)
    with pytest.raises(OSError, match="source close failure"):
        with streaming._verified_blob_snapshot(blob, binding(data)):
            raise AssertionError("source close error yielded")
    assert len(opened) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(opened[0])
    assert closed.value.errno == errno.EBADF


def test_nofollow_source_policy_is_unchanged(tmp_path):
    data = b"owned-symlink-target"
    target = tmp_path / "target"
    target.write_bytes(data)
    blob = tmp_path / "blob-link"
    blob.symlink_to(target.name)
    with pytest.raises(OSError) as refused:
        with streaming._verified_blob_snapshot(blob, binding(data)):
            raise AssertionError("symlink followed")
    assert refused.value.errno == errno.ELOOP
    assert target.read_bytes() == data
