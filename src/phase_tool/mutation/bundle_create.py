"""Mechanism-managed local directory commit for phase_bundle_v1.

No provider guarantee is borrowed for renameat2. This mechanism qualifies its
Linux filesystem and pins the intended root/parent itself.
"""
from __future__ import annotations
import ctypes
import errno
import os
from pathlib import Path

from ..bundle import MANIFEST_NAME, OWNER_NAME, parse_manifest, verify_bundle, verify_frozen_members
from ..canonical import canonical_bytes, digest_bytes, profile_digest
from ..errors import PhaseError
from ..installation import qualify_host_authority_roots
from ..streaming import transfer
from .exclusive_create import _receipt, _unknown


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    if rename is None:
        raise PhaseError("bundle.atomic_commit_unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, "bundle destination exists")
        raise OSError(code, os.strerror(code))


def stage_name(run_id: str, effect: dict) -> str:
    identity = [run_id, effect["target"], effect["content_digest"]]
    return "phase-stage-" + digest_bytes(canonical_bytes(identity)).removeprefix("sha256:")


def _write_metadata(stage: Path, name: str, data: bytes, identity: tuple[int, int], counter: list[int]) -> None:
    from .posix.authority import PosixTargetAuthority
    authority = PosixTargetAuthority(stage, name, expected_root_identity=identity, create_parents=False)
    fd = None
    try:
        authority.assert_namespace_binding()
        fd = authority.open_exclusive()
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if not 0 < count <= len(view):
                raise OSError("metadata write made invalid progress")
            counter[0] += count
            view = view[count:]
        os.fsync(fd)
        authority.fsync_parent()
        authority.assert_namespace_binding()
    finally:
        if fd is not None:
            os.close(fd)
        authority.close()


def execute_bundle_create(effect: dict, target_root: Path, manifest_bytes: bytes,
                          blob_root: Path, *, run_id: str, timestamp: str,
                          plan_digest: str, expected_root_identity: tuple[int, int]):
    from .posix.authority import PosixTargetAuthority

    qualify_host_authority_roots({"phase_result_root": target_root})
    manifest = parse_manifest(manifest_bytes)
    if (digest_bytes(manifest_bytes), len(manifest_bytes)) != (effect["content_digest"], effect["content_length"]):
        raise PhaseError("bundle.manifest_mismatch")
    verify_frozen_members(manifest, blob_root)
    authority = PosixTargetAuthority(target_root, effect["target"]["relative_locator"],
                                    expected_root_identity=expected_root_identity, create_parents=False)
    assert authority.parent_fd is not None
    stage = authority.parent_path / stage_name(run_id, effect)
    attempted = True  # A returned mechanism receipt records this invocation.
    created = False
    published = False
    write_counter = [0]
    after = _unknown()
    before = {"known": True, "exists": authority.target.exists(), "digest": None, "length": None, "head_token": None}
    status = "indeterminate"
    error = None
    try:
        if before["exists"]:
            raise FileExistsError("bundle destination exists")
        authority.assert_namespace_binding()
        os.mkdir(stage.name, 0o700, dir_fd=authority.parent_fd)
        created = True
        stage_stat = stage.stat()
        owner = canonical_bytes({"owner_version": "1.0", "run_id": run_id,
            "plan_digest": plan_digest, "device": stage_stat.st_dev, "inode": stage_stat.st_ino})
        for name, content in ((OWNER_NAME, owner), (MANIFEST_NAME, manifest_bytes)):
            _write_metadata(stage, name, content, (stage_stat.st_dev, stage_stat.st_ino), write_counter)
        for item in manifest["members"]:
            member = PosixTargetAuthority(stage, item["path"],
                expected_root_identity=(stage_stat.st_dev, stage_stat.st_ino))
            output = None
            source = None
            try:
                member.assert_namespace_binding()
                output = member.open_exclusive()
                source = os.open(blob_root/item["digest"].removeprefix("sha256:"),
                                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                actual = transfer(source, item["length"], output, write_counter=write_counter)
                if actual != (item["digest"], item["length"]):
                    raise PhaseError("bundle.frozen_member_mismatch")
                os.fsync(output)
                member.fsync_parent()
                member.assert_namespace_binding()
            finally:
                if source is not None:
                    os.close(source)
                if output is not None:
                    os.close(output)
                member.close()
        verify_bundle(stage, effect["content_digest"], run_id=run_id, plan_digest=plan_digest)
        directories = {stage}
        for item in manifest["members"]:
            parent = (stage/item["path"]).parent
            while parent != stage:
                directories.add(parent)
                parent = parent.parent
        for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        authority.assert_namespace_binding()
        # This successful syscall is the sole consumer publication point.
        _rename_noreplace(authority.parent_fd, stage.name, authority.name)
        published = True
        authority.fsync_parent()
        verify_bundle(authority.target, effect["content_digest"], run_id=run_id, plan_digest=plan_digest)
        authority.assert_namespace_binding()
        after = {"known": True, "exists": True, "digest": effect["content_digest"],
                 "length": len(manifest_bytes), "head_token": None}
        status = "applied_verified"
    except (OSError, PhaseError) as exc:
        error = exc.code if isinstance(exc, PhaseError) else "bundle.commit_or_write_failed"
        status = ("applied_unverified" if published else "failed_partial" if created
                  else "failed_no_effect" if isinstance(exc, FileExistsError) else "indeterminate")
        if not published:
            try:
                after = {"known": True, "exists": authority.target.exists(), "digest": None, "length": None, "head_token": None}
            except OSError:
                after, status = _unknown(), "indeterminate"
        # Never delete retained staging or evidence required for recovery.
    finally:
        try:
            authority.close()
        except OSError:
            status, error = "indeterminate", "bundle.close_failed"
    return _receipt(effect, run_id=run_id, timestamp=timestamp, status=status,
        attempted=attempted, before=before, after=after, bytes_written=write_counter[0],
        verification_refs=["bundle.members.byte_verified"] if status == "applied_verified" else [],
        error_code=error)
