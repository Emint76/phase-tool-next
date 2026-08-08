from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..canonical import digest_bytes
from ..errors import PhaseError
from ..paths import _is_reparse_point
from .authority import AuthorityProvider, TargetAuthority

_MAX_CONTENT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class ArchiveThenPublishFaults:
    maximum_write_size: int | None = None
    fail_after_archive_bytes: int | None = None
    fail_after_archive: bool = False
    fail_after_current_bytes: int | None = None
    fail_after_publish_before_readback: bool = False
    readback_override: bytes | None = None
    readback_error: bool = False
    reparse_detector: Callable[[Path], bool] | None = None
    write_primitive: Callable[[int, memoryview], int] | None = None
    before_archive_create: Callable[[Path], None] | None = None
    before_publish: Callable[[Path], None] | None = None
    before_current_write: Callable[[Path], None] | None = None


class _ArchiveWriteFailure(OSError):
    def __init__(self, message: str, bytes_written: int) -> None:
        super().__init__(message)
        self.bytes_written = bytes_written


def _unknown() -> dict[str, object]:
    return {"known": False, "exists": None, "digest": None, "length": None, "head_token": None}


def _receipt(
    effect: dict[str, object],
    *,
    run_id: str,
    timestamp: str,
    status: str,
    attempted: bool,
    before: dict[str, object],
    after: dict[str, object],
    archive_before: dict[str, object],
    archive_after: dict[str, object],
    bytes_written: int | None,
    verification_refs: list[str],
    error_code: str | None,
    error_message: str | None = None,
) -> dict[str, object]:
    return {
        "effect_receipt_version": "1.0",
        "run_id": run_id,
        "effect_id": effect["effect_id"],
        "kind": effect["kind"],
        "status": status,
        "attempted": attempted,
        "before": before,
        "after": after,
        "archive_target": effect["archive_target"],
        "archive_before": archive_before,
        "archive_after": archive_after,
        "bytes_written": bytes_written,
        "verification_refs": verification_refs,
        "error": None if error_code is None else {"code": error_code, "message": error_message or error_code},
        "started_at": timestamp,
        "finished_at": timestamp,
    }


def _same(observation: dict[str, object], digest: object, length: object) -> bool:
    return observation.get("exists") is True and observation.get("digest") == digest and observation.get("length") == length


def _write_all(descriptor: int, content: bytes, writer: Callable[[int, memoryview], int], maximum_write_size: int | None, fail_after: int | None) -> int:
    written = 0
    view = memoryview(content)
    while written < len(content):
        if fail_after is not None and written >= fail_after:
            raise _ArchiveWriteFailure("injected write failure", written)
        count = len(content) - written
        if maximum_write_size is not None:
            if maximum_write_size <= 0:
                raise OSError("injected zero-length write")
            count = min(count, maximum_write_size)
        if fail_after is not None:
            count = min(count, fail_after - written)
            if count <= 0:
                raise _ArchiveWriteFailure("injected write failure", written)
        actual = writer(descriptor, view[written : written + count])
        if actual <= 0:
            raise OSError("short write made no progress")
        written += actual
    return written


def _read_current(authority: TargetAuthority) -> bytes:
    return authority.read_bytes()


def _publish_current(
    authority: TargetAuthority,
    descriptor: int,
    content: bytes,
    writer: Callable[[int, memoryview], int],
    maximum_write_size: int | None,
    fail_after: int | None,
) -> int:
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    written = _write_all(descriptor, content, writer, maximum_write_size, fail_after)
    os.fsync(descriptor)
    authority.fsync_parent()
    return written


def _create_archive(effect: dict[str, object], archive_authority: TargetAuthority, current_bytes: bytes, run_id: str, timestamp: str, faults: ArchiveThenPublishFaults) -> tuple[dict[str, object], int]:
    before = archive_authority.observe()
    if _same(before, effect["archive_digest"], effect["archive_length"]):
        return before, 0
    if before["exists"] is True:
        raise PhaseError("publish.archive_conflict", str(effect["archive_target"]))
    if faults.before_archive_create is not None:
        faults.before_archive_create(archive_authority.target)
    descriptor: int | None = None
    try:
        try:
            descriptor = archive_authority.open_exclusive()
        except FileExistsError:
            raced = archive_authority.observe()
            if _same(raced, effect["archive_digest"], effect["archive_length"]):
                return raced, 0
            raise PhaseError("publish.archive_conflict", str(effect["archive_target"]))
        written = _write_all(descriptor, current_bytes, faults.write_primitive or os.write, faults.maximum_write_size, faults.fail_after_archive_bytes)
        os.fsync(descriptor)
        archive_authority.fsync_parent()
        after = archive_authority.readback(None, descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not _same(after, effect["archive_digest"], effect["archive_length"]):
        raise PhaseError("publish.archive_verification_failed")
    del run_id, timestamp
    return after, written


def execute_archive_then_publish(
    effect: dict[str, object],
    target_root: Path,
    content: bytes,
    *,
    run_id: str,
    timestamp: str,
    faults: ArchiveThenPublishFaults | None = None,
    authority_provider: AuthorityProvider,
) -> dict[str, object]:
    active = faults or ArchiveThenPublishFaults()
    if len(content) > _MAX_CONTENT_BYTES:
        raise PhaseError("mechanism.content_too_large")
    if len(content) != effect["content_length"] or digest_bytes(content) != effect["content_digest"]:
        raise PhaseError("mechanism.content_binding_mismatch")
    if effect["target"] == effect["archive_target"]:
        raise PhaseError("publish.target_archive_collision")
    detector = active.reparse_detector or _is_reparse_point
    current_authority = authority_provider.open_authority(target_root, str(effect["target"]["relative_locator"]), detector)  # type: ignore[index]
    archive_authority = authority_provider.open_authority(target_root, str(effect["archive_target"]["relative_locator"]), detector)  # type: ignore[index]
    archive_before: dict[str, object] = _unknown()
    archive_after: dict[str, object] = _unknown()
    bytes_written = 0
    try:
        before = current_authority.observe()
        archive_before = archive_authority.observe()
        current_is_before = _same(before, effect["archive_digest"], effect["archive_length"])
        current_is_after = _same(before, effect["content_digest"], effect["content_length"])
        archive_is_exact = _same(archive_before, effect["archive_digest"], effect["archive_length"])
        if current_is_after and archive_is_exact:
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="applied_verified",
                attempted=True,
                before=archive_before,
                after=before,
                archive_before=archive_before,
                archive_after=archive_before,
                bytes_written=0,
                verification_refs=["target.before", "archive.before", "publish.already_complete", "archive.logical_before"],
                error_code=None,
            )
        if not current_is_before:
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="failed_no_effect",
                attempted=True,
                before=before,
                after=before,
                archive_before=archive_before,
                archive_after=archive_before,
                bytes_written=0,
                verification_refs=["target.before", "archive.before"],
                error_code="publish.current_mismatch",
            )
        current_bytes = _read_current(current_authority)
        if digest_bytes(current_bytes) != effect["archive_digest"] or len(current_bytes) != effect["archive_length"]:
            raise PhaseError("publish.current_changed_during_archive")
        try:
            archive_after, archive_written = _create_archive(effect, archive_authority, current_bytes, run_id, timestamp, active)
            bytes_written += archive_written
        except (_ArchiveWriteFailure, OSError, PhaseError) as exc:
            after = current_authority.observe()
            archive_after = archive_authority.observe()
            bytes_written += getattr(exc, "bytes_written", 0)
            partial_archive = archive_after.get("exists") is True and not _same(archive_after, effect["archive_digest"], effect["archive_length"])
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="failed_partial" if partial_archive else "failed_no_effect",
                attempted=True,
                before=before,
                after=after,
                archive_before=archive_before,
                archive_after=archive_after,
                bytes_written=bytes_written,
                verification_refs=["target.after", "archive.after"],
                error_code=exc.code if isinstance(exc, PhaseError) else "mechanism.write_failed",
                error_message=str(exc),
            )
        if not _same(archive_after, effect["archive_digest"], effect["archive_length"]):
            raise PhaseError("publish.archive_verification_failed")
        if active.fail_after_archive:
            after = current_authority.observe()
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="failed_partial",
                attempted=True,
                before=before,
                after=after,
                archive_before=archive_before,
                archive_after=archive_after,
                bytes_written=bytes_written,
                verification_refs=["target.after", "archive.after"],
                error_code="mechanism.write_failed",
                error_message="injected failure after archive",
            )
        if active.before_publish is not None:
            active.before_publish(current_authority.target)
        if active.before_current_write is not None:
            active.before_current_write(current_authority.target)
        archive_descriptor: int | None = None
        current_descriptor: int | None = None
        try:
            archive_descriptor = archive_authority.open_existing(deny_write_sharing=True)
            archive_after = archive_authority.readback(None, archive_descriptor)
            if not _same(archive_after, effect["archive_digest"], effect["archive_length"]):
                after = current_authority.observe()
                return _receipt(
                    effect,
                    run_id=run_id,
                    timestamp=timestamp,
                    status="failed_partial",
                    attempted=True,
                    before=before,
                    after=after,
                    archive_before=archive_before,
                    archive_after=archive_after,
                    bytes_written=bytes_written,
                    verification_refs=["target.after", "archive.pinned_before_publish"],
                    error_code="publish.archive_verification_failed",
                )
            current_descriptor = current_authority.open_existing(writable=True, deny_write_sharing=True)
            latest = current_authority.readback(None, current_descriptor)
            if not _same(latest, effect["archive_digest"], effect["archive_length"]):
                return _receipt(
                    effect,
                    run_id=run_id,
                    timestamp=timestamp,
                    status="failed_partial",
                    attempted=True,
                    before=before,
                    after=latest,
                    archive_before=archive_before,
                    archive_after=archive_after,
                    bytes_written=bytes_written,
                    verification_refs=["target.pinned_before_publish", "archive.pinned_before_publish"],
                    error_code="publish.current_verification_failed",
                )
            try:
                bytes_written += _publish_current(
                    current_authority,
                    current_descriptor,
                    content,
                    active.write_primitive or os.write,
                    active.maximum_write_size,
                    active.fail_after_current_bytes,
                )
                if active.fail_after_publish_before_readback:
                    raise OSError("injected failure after current publication")
                if active.readback_error:
                    raise OSError("injected read-back failure")
                after = current_authority.readback(active.readback_override, current_descriptor)
                archive_after = archive_authority.readback(None, archive_descriptor)
            except OSError as exc:
                try:
                    after = current_authority.readback(None, current_descriptor)
                    archive_after = archive_authority.readback(None, archive_descriptor)
                except (OSError, PhaseError):
                    after = _unknown()
                status = "failed_partial" if after.get("exists") is True else "indeterminate"
                return _receipt(
                    effect,
                    run_id=run_id,
                    timestamp=timestamp,
                    status=status,
                    attempted=True,
                    before=before,
                    after=after,
                    archive_before=archive_before,
                    archive_after=archive_after,
                    bytes_written=bytes_written,
                    verification_refs=["target.after", "archive.after"] if after["known"] else ["archive.after"],
                    error_code="mechanism.write_failed",
                    error_message=str(exc),
                )
        finally:
            if current_descriptor is not None:
                os.close(current_descriptor)
            if archive_descriptor is not None:
                os.close(archive_descriptor)
        verified = _same(after, effect["content_digest"], effect["content_length"]) and _same(archive_after, effect["archive_digest"], effect["archive_length"])
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="applied_verified" if verified else "applied_unverified",
            attempted=True,
            before=before,
            after=after,
            archive_before=archive_before,
            archive_after=archive_after,
            bytes_written=bytes_written,
            verification_refs=["target.readback", "archive.after"],
            error_code=None if verified else "verification.result_mismatch",
        )
    finally:
        archive_authority.close()
        current_authority.close()
