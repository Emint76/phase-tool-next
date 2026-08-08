from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.mutation import BrokerFaults, ObjectStorePublishFaults
from phase_tool.mutation.target_authority import TargetAuthority
from phase_tool.registry import BundledRegistry

NOW = "2026-08-03T12:00:00Z"


pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX parent-binding regression requires directory descriptor semantics.",
)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _object_locator(data: bytes) -> str:
    hexdigest = hashlib.sha256(data).hexdigest()
    return f"sha256/{hexdigest[:2]}/{hexdigest}"


def _binding() -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()["publish_new_version.v2@1.0.0"]


def _request(
    tmp_path: Path,
    *,
    run_id: str,
    before: bytes,
    content: str,
) -> tuple[PhaseRequest, Path, Path, Path, Path]:
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



def test_target_authority_replace_from_uses_bound_source_and_destination_parents(tmp_path: Path) -> None:
    root = tmp_path / "replace"
    source_parent = root / "source"
    destination_parent = root / "destination"
    source_parent.mkdir(parents=True)
    destination_parent.mkdir()
    (source_parent / "temporary").write_bytes(b"new")
    (destination_parent / "current").write_bytes(b"old")
    source = TargetAuthority(root, "source/temporary")
    destination = TargetAuthority(root, "destination/current")
    moved_source = root / "source-moved"
    moved_destination = root / "destination-moved"
    try:
        source_parent.rename(moved_source)
        destination_parent.rename(moved_destination)
        source_parent.mkdir()
        destination_parent.mkdir()

        destination.replace_from(source)

        assert not (moved_source / "temporary").exists()
        assert (moved_destination / "current").read_bytes() == b"new"
        assert list(source_parent.iterdir()) == []
        assert list(destination_parent.iterdir()) == []
        with pytest.raises(PhaseError, match="path.parent_identity_changed"):
            destination.assert_namespace_binding()
    finally:
        destination.close()
        source.close()


def test_target_authority_link_from_uses_bound_parents_and_creates_real_hard_link(tmp_path: Path) -> None:
    root = tmp_path / "link"
    source_parent = root / "source"
    destination_parent = root / "destination"
    source_parent.mkdir(parents=True)
    destination_parent.mkdir()
    (source_parent / "temporary").write_bytes(b"immutable object")
    source = TargetAuthority(root, "source/temporary")
    destination = TargetAuthority(root, "destination/object")
    moved_source = root / "source-moved"
    moved_destination = root / "destination-moved"
    try:
        source_parent.rename(moved_source)
        destination_parent.rename(moved_destination)
        source_parent.mkdir()
        destination_parent.mkdir()

        destination.link_from(source)

        source_file = moved_source / "temporary"
        object_file = moved_destination / "object"
        assert source_file.read_bytes() == b"immutable object"
        assert object_file.read_bytes() == b"immutable object"
        assert source_file.stat().st_ino == object_file.stat().st_ino
        assert list(source_parent.iterdir()) == []
        assert list(destination_parent.iterdir()) == []
    finally:
        destination.close()
        source.close()


def test_target_authority_link_from_never_replaces_existing_object(tmp_path: Path) -> None:
    root = tmp_path / "link-conflict"
    (root / "source").mkdir(parents=True)
    (root / "destination").mkdir()
    (root / "source" / "temporary").write_bytes(b"new bytes")
    existing = root / "destination" / "object"
    existing.write_bytes(b"existing immutable bytes")
    original_inode = existing.stat().st_ino
    source = TargetAuthority(root, "source/temporary")
    destination = TargetAuthority(root, "destination/object")
    try:
        with pytest.raises(FileExistsError):
            destination.link_from(source)
        assert existing.read_bytes() == b"existing immutable bytes"
        assert existing.stat().st_ino == original_inode
        assert (root / "source" / "temporary").read_bytes() == b"new bytes"
    finally:
        destination.close()
        source.close()


def test_target_authority_unlink_removes_bound_leaf_without_touching_replacement_namespace(tmp_path: Path) -> None:
    root = tmp_path / "unlink"
    parent = root / "parent"
    parent.mkdir(parents=True)
    (parent / "temporary").write_bytes(b"owned temporary")
    temporary = TargetAuthority(root, "parent/temporary")
    moved_parent = root / "parent-moved"
    try:
        parent.rename(moved_parent)
        parent.mkdir()
        replacement = parent / "temporary"
        replacement.write_bytes(b"replacement namespace sentinel")

        temporary.unlink()

        assert not (moved_parent / "temporary").exists()
        assert replacement.read_bytes() == b"replacement namespace sentinel"
        with pytest.raises(PhaseError, match="path.parent_identity_changed"):
            temporary.assert_namespace_binding()
    finally:
        temporary.close()


@pytest.mark.parametrize("post_replace_error", [False, True])
def test_v2_final_replace_uses_authority_and_reports_namespace_change_without_retargeting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    post_replace_error: bool,
) -> None:
    before = b"old current bytes"
    after = b"new current bytes \xe2\x9c\x93"
    run_id = "v2-parent-binding-final-replace"
    request, current_root, objects_root, _evidence_root, current = _request(
        tmp_path,
        run_id=run_id,
        before=before,
        content=after.decode("utf-8"),
    )
    original_parent = current.parent
    renamed_parent = current_root / "docs-renamed-after-authority-opened"
    temporary = current_root / f"docs/item.md.phase-tmp-{run_id[-32:]}"
    renamed_current = renamed_parent / current.name
    renamed_temporary = renamed_parent / temporary.name
    replacement_current = original_parent / current.name
    replacement_temporary = original_parent / temporary.name
    original_replace_from = TargetAuthority.replace_from
    original_fsync_parent = TargetAuthority.fsync_parent
    original_unlink = TargetAuthority.unlink
    replace_calls: list[tuple[str, str]] = []
    cleanup_calls: list[tuple[str, bool]] = []

    def replace_after_parent_rebinding(destination: TargetAuthority, source: TargetAuthority) -> None:
        assert destination.target == current
        assert source.target == temporary
        assert current.read_bytes() == before
        assert temporary.read_bytes() == after
        original_parent.rename(renamed_parent)
        original_parent.mkdir()
        assert renamed_current.read_bytes() == before
        assert renamed_temporary.read_bytes() == after
        assert not replacement_current.exists()
        assert not replacement_temporary.exists()
        original_replace_from(destination, source)
        assert not renamed_temporary.exists()
        renamed_temporary.write_bytes(b"foreign file created after replace")
        replace_calls.append((source.locator, destination.locator))

    def fail_after_replace(authority: TargetAuthority) -> None:
        original_fsync_parent(authority)
        if post_replace_error and authority.target == current:
            raise OSError("post-replace failure combined with namespace drift")

    def tracked_unlink(authority: TargetAuthority, *, missing_ok: bool = False) -> None:
        cleanup_calls.append((authority.locator, missing_ok))
        original_unlink(authority, missing_ok=missing_ok)

    monkeypatch.setattr(TargetAuthority, "replace_from", replace_after_parent_rebinding)
    monkeypatch.setattr(TargetAuthority, "fsync_parent", fail_after_replace)
    monkeypatch.setattr(TargetAuthority, "unlink", tracked_unlink)

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(object_store_publish=ObjectStorePublishFaults())),
    )

    effect = outcome.receipt["effect_receipts"][0]
    assert replace_calls == [(f"docs/{temporary.name}", "docs/item.md")]
    assert (f"docs/{temporary.name}", True) not in cleanup_calls
    assert renamed_parent.is_dir()
    assert original_parent.is_dir()
    assert renamed_current.read_bytes() == after
    assert renamed_temporary.read_bytes() == b"foreign file created after replace"
    assert not replacement_current.exists()
    assert not replacement_temporary.exists()
    assert effect["status"] == "indeterminate"
    assert effect["error"]["code"] == "path.parent_identity_changed"
    assert effect["after"]["digest"] == _sha(after)
    assert outcome.receipt["terminal_status"] == "indeterminate"
    assert (objects_root / _object_locator(before)).read_bytes() == before
    assert (objects_root / _object_locator(after)).read_bytes() == after


def test_v2_transient_parent_rebinding_remains_indeterminate_after_namespace_is_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = b"old current before transient drift"
    after = b"new current after transient drift"
    run_id = "v2-parent-binding-transient-drift"
    request, current_root, objects_root, _evidence_root, current = _request(
        tmp_path,
        run_id=run_id,
        before=before,
        content=after.decode("utf-8"),
    )
    original_parent = current.parent
    renamed_parent = current_root / "docs-transiently-renamed"
    original_replace_from = TargetAuthority.replace_from
    original_assert_namespace_binding = TargetAuthority.assert_namespace_binding
    restored = False

    def replace_after_parent_rebinding(destination: TargetAuthority, source: TargetAuthority) -> None:
        original_parent.rename(renamed_parent)
        original_parent.mkdir()
        original_replace_from(destination, source)

    def assert_and_restore_namespace(authority: TargetAuthority) -> None:
        nonlocal restored
        try:
            original_assert_namespace_binding(authority)
        except PhaseError as exc:
            if not restored and authority.target == current and exc.code == "path.parent_identity_changed":
                original_parent.rmdir()
                renamed_parent.rename(original_parent)
                restored = True
            raise

    monkeypatch.setattr(TargetAuthority, "replace_from", replace_after_parent_rebinding)
    monkeypatch.setattr(TargetAuthority, "assert_namespace_binding", assert_and_restore_namespace)

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(object_store_publish=ObjectStorePublishFaults())),
    )

    effect = outcome.receipt["effect_receipts"][0]
    assert restored is True
    assert not renamed_parent.exists()
    assert current.read_bytes() == after
    assert effect["status"] == "indeterminate"
    assert effect["error"]["code"] == "path.parent_identity_changed"
    assert outcome.receipt["terminal_status"] == "indeterminate"
    assert (objects_root / _object_locator(before)).read_bytes() == before
    assert (objects_root / _object_locator(after)).read_bytes() == after


@pytest.mark.parametrize("which", ["old", "new"])
def test_v2_object_link_uses_authorities_and_cleans_bound_temporary_after_parent_rebinding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    which: str,
) -> None:
    before = b"old object binding"
    after = b"new object binding"
    run_id = f"v2-parent-binding-object-link-{which}"
    request, _current_root, objects_root, _evidence_root, current = _request(
        tmp_path,
        run_id=run_id,
        before=before,
        content=after.decode("utf-8"),
    )
    payload = before if which == "old" else after
    token = hashlib.sha256(f"{run_id}.{which}".encode("utf-8")).hexdigest()[:16]
    final_object = objects_root / _object_locator(payload)
    original_parent = final_object.parent
    renamed_parent = original_parent.with_name(original_parent.name + f"-renamed-{which}")
    temporary = Path(str(final_object) + ".phase-tmp-object-" + token)
    renamed_final = renamed_parent / final_object.name
    renamed_temporary = renamed_parent / temporary.name
    replacement_final = original_parent / final_object.name
    replacement_temporary = original_parent / temporary.name
    original_link_from = TargetAuthority.link_from
    original_unlink = TargetAuthority.unlink
    link_calls: list[tuple[str, str, int, int]] = []
    cleanup_calls: list[tuple[str, bool]] = []

    def link_after_parent_rebinding(destination: TargetAuthority, source: TargetAuthority) -> None:
        if destination.target != final_object:
            return original_link_from(destination, source)
        assert source.target == temporary
        assert temporary.read_bytes() == payload
        original_parent.rename(renamed_parent)
        original_parent.mkdir()
        assert renamed_temporary.read_bytes() == payload
        assert not replacement_temporary.exists()
        original_link_from(destination, source)
        link_calls.append(
            (
                source.locator,
                destination.locator,
                renamed_temporary.stat().st_ino,
                renamed_final.stat().st_ino,
            )
        )

    def tracked_unlink(authority: TargetAuthority, *, missing_ok: bool = False) -> None:
        cleanup_calls.append((authority.locator, missing_ok))
        original_unlink(authority, missing_ok=missing_ok)

    monkeypatch.setattr(TargetAuthority, "link_from", link_after_parent_rebinding)
    monkeypatch.setattr(TargetAuthority, "unlink", tracked_unlink)

    outcome = PhaseCore().run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(object_store_publish=ObjectStorePublishFaults())),
    )

    effect = outcome.receipt["effect_receipts"][0]
    assert len(link_calls) == 1
    source_locator, destination_locator, source_inode, destination_inode = link_calls[0]
    assert source_locator == str(temporary.relative_to(objects_root)).replace("\\", "/")
    assert destination_locator == _object_locator(payload)
    assert source_inode == destination_inode
    assert (source_locator, True) in cleanup_calls
    assert renamed_parent.is_dir()
    assert original_parent.is_dir()
    assert renamed_final.read_bytes() == payload
    assert not renamed_temporary.exists()
    assert not replacement_final.exists()
    assert not replacement_temporary.exists()
    assert current.read_bytes() == before
    assert effect["status"] == "failed_partial"
    assert effect["error"]["code"] == "path.parent_identity_changed"
    assert outcome.receipt["terminal_status"] == "failed_partial"
    if which == "new":
        assert (objects_root / _object_locator(before)).read_bytes() == before
    else:
        assert not (objects_root / _object_locator(after)).exists()
