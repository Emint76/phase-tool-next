from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from phase_tool.candidate import capture_raw, capture_structured
from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, profile_digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.freeze import (
    copy_and_hash,
    lock_snapshot_revalidate,
    manifest_and_hash,
    revalidate_frozen,
    revalidate_manifest,
    revalidate_snapshot,
    value_snapshot,
)
from phase_tool.paths import safe_relative_locator


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
