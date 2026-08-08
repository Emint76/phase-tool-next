from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

if os.name == "nt":
    pytest.skip("POSIX guarantee conformance requires POSIX", allow_module_level=True)

from phase_tool.errors import PhaseError
from phase_tool.mutation.posix import PosixAuthorityProvider


def test_namespace_bound_mutation_uses_pinned_parent_and_detects_rebinding(tmp_path: Path) -> None:
    root = tmp_path / "root"
    parent = root / "objects"
    parent.mkdir(parents=True)
    provider = PosixAuthorityProvider()
    authority = provider.open_authority(root, "objects/item.bin")
    moved = root / "objects-moved"
    parent.rename(moved)
    parent.mkdir()
    try:
        descriptor = authority.open_exclusive()
        try:
            os.write(descriptor, b"pinned-parent")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        assert (moved / "item.bin").read_bytes() == b"pinned-parent"
        assert not (parent / "item.bin").exists()
        with pytest.raises(PhaseError) as error:
            authority.assert_namespace_binding()
        assert error.value.code == "path.parent_identity_changed"
    finally:
        authority.close()


def test_atomic_replace_never_exposes_missing_or_partial_destination(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    provider = PosixAuthorityProvider()
    destination_path = root / "item.bin"
    old = b"old" * 4096
    new = b"new" * 4096
    destination_path.write_bytes(old)
    destination = provider.open_authority(root, "item.bin")
    stop = threading.Event()
    observations: list[bytes] = []
    failures: list[BaseException] = []

    def observe() -> None:
        while not stop.is_set():
            try:
                observations.append(destination_path.read_bytes())
            except BaseException as exc:  # captured for assertion in the owner thread
                failures.append(exc)
                stop.set()

    reader = threading.Thread(target=observe)
    reader.start()
    try:
        for index in range(100):
            content = new if index % 2 == 0 else old
            source = provider.open_authority(root, f"replacement-{index}.bin")
            try:
                descriptor = source.open_exclusive()
                try:
                    os.write(descriptor, content)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                destination.replace_from(source)
            finally:
                source.close()
    finally:
        stop.set()
        reader.join(10)
        destination.close()

    assert not failures
    assert observations
    assert set(observations) <= {old, new}
    assert destination_path.read_bytes() in {old, new}


def test_namespace_metadata_flush_attempted_fsyncs_pinned_parent_descriptor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    authority = PosixAuthorityProvider().open_authority(root, "nested/item.bin")
    assert authority.parent_fd is not None
    expected_parent_fd = authority.parent_fd
    calls: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        calls.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    try:
        authority.fsync_parent()
    finally:
        authority.close()

    assert calls == [expected_parent_fd]
