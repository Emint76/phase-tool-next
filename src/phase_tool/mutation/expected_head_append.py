from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..append_codec import append_head_token, absent_head_token, stream_head_token, validate_record_bytes
from ..canonical import digest_bytes
from ..evidence import operational_lock_path
from ..errors import PhaseError
from ..paths import _is_reparse_point, contained_target_path
from .platform import HostTargetAuthority

_MAX_RECORD_BYTES = 1_048_576


@dataclass(frozen=True)
class AppendRecordFaults:
    maximum_write_size: int | None = None
    fail_after_bytes: int | None = None
    readback_override: bytes | None = None
    readback_error: bool = False
    lock_acquire_error: bool = False
    write_primitive: Callable[[int, memoryview], int] | None = None


def _unknown() -> dict[str, object]:
    return {"known": False, "exists": None, "digest": None, "length": None, "head_token": None}


def _observe(path: Path) -> dict[str, object]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"known": True, "exists": False, "digest": None, "length": None, "head_token": None}
    if path.is_symlink():
        raise PhaseError("path.link_forbidden", str(path))
    if _is_reparse_point(path):
        raise PhaseError("path.reparse_forbidden", str(path))
    if not stat.S_ISREG(info.st_mode):
        return {"known": True, "exists": True, "digest": None, "length": None, "head_token": None}
    data = path.read_bytes()
    return {"known": True, "exists": True, "digest": digest_bytes(data), "length": len(data), "head_token": stream_head_token(data)}


def _receipt(
    effect: dict[str, object],
    *,
    run_id: str,
    timestamp: str,
    status: str,
    before: dict[str, object],
    after: dict[str, object],
    error_code: str | None,
    bytes_written: int | None,
    verification_refs: list[str],
    append_offset: int | None = None,
    resulting_head: str | None = None,
    operation_identity: object | None = None,
    request_digest: object | None = None,
    record_identity: object | None = None,
    record_digest: str | None = None,
    record_length: int | None = None,
    attempted: bool = True,
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
        "bytes_written": bytes_written,
        "operation_identity": operation_identity,
        "request_digest": request_digest,
        "record_identity": record_identity,
        "record_digest": record_digest,
        "record_length": record_length,
        "append_offset": append_offset,
        "resulting_head": resulting_head,
        "verification_refs": verification_refs,
        "error": None if error_code is None else {"code": error_code, "message": error_message or error_code},
        "started_at": timestamp,
        "finished_at": timestamp,
    }


class _CooperativeFileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream = None

    def __enter__(self) -> "_CooperativeFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("a+b")
        if os.name == "nt":
            import msvcrt

            self._stream.seek(0)
            msvcrt.locking(self._stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(self._stream.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *_exc: object) -> None:
        assert self._stream is not None
        if os.name == "nt":
            import msvcrt

            self._stream.seek(0)
            msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        self._stream.close()


def execute_append_record(
    effect: dict[str, object],
    target_root: Path,
    record: bytes,
    *,
    run_id: str,
    timestamp: str,
    operational_lock_root: Path,
    codec_id: str = "canonical-jsonl",
    expected_head_override: str | None = None,
    faults: AppendRecordFaults | None = None,
    expected_root_identity: tuple[int, int] | None = None,
) -> dict[str, object]:
    active = faults or AppendRecordFaults()
    validate_record_bytes(record)
    if len(record) > _MAX_RECORD_BYTES:
        raise PhaseError("mechanism.content_too_large")
    if len(record) != effect["content_length"] or digest_bytes(record) != effect["content_digest"]:
        raise PhaseError("mechanism.content_binding_mismatch")
    expected_head = expected_head_override
    if expected_head is None:
        expected_head = effect["preconditions"]["expected_head"]  # type: ignore[index]
    root_resolved = Path(target_root).resolve(strict=True)
    root_info = root_resolved.stat()
    observed_root_identity = (int(root_info.st_dev), int(root_info.st_ino))
    if expected_root_identity is not None and observed_root_identity != expected_root_identity:
        raise PhaseError("broker.root_identity_mismatch")
    locator = str(effect["target"]["relative_locator"])  # type: ignore[index]
    target = contained_target_path(root_resolved, locator)
    target_identity = digest_bytes(
        "\n".join(
            [
                os.path.normcase(str(root_resolved)),
                str(int(root_info.st_dev)),
                str(int(root_info.st_ino)),
                target.relative_to(root_resolved).as_posix(),
            ]
        ).encode("utf-8")
    )
    lock = operational_lock_path(operational_lock_root, target_identity)
    append_metadata = {
        "operation_identity": effect.get("operation_identity"),
        "request_digest": effect.get("request_digest"),
        "record_identity": effect.get("record_identity"),
        "record_digest": digest_bytes(record),
        "record_length": len(record),
    }
    if active.lock_acquire_error:
        before = {"known": True, "exists": target.exists(), "digest": None, "length": None, "head_token": None}
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="failed_no_effect",
            before=before,
            after=before,
            bytes_written=0,
            error_code="lock.acquire_failed",
            verification_refs=["lock.acquire", "target.unchanged"],
            attempted=True,
            **append_metadata,
        )
    try:
        lock_context = _CooperativeFileLock(lock)
        lock_context.__enter__()
    except OSError as exc:
        try:
            observed = _observe(target)
        except (OSError, PhaseError):
            observed = _unknown()
        status = "failed_no_effect" if observed["known"] else "indeterminate"
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status=status,
            before=observed,
            after=observed,
            bytes_written=0,
            error_code="lock.acquire_failed",
            error_message=str(exc),
            verification_refs=["lock.acquire", "target.after"] if observed["known"] else ["lock.acquire"],
            attempted=True,
            **append_metadata,
        )
    try:
        authority = HostTargetAuthority(
            root_resolved,
            locator,
            expected_root_identity=expected_root_identity,
        )
        try:
            before = _observe(target)
        except PhaseError as exc:
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="failed_no_effect",
                before=_unknown(),
                after=_unknown(),
                bytes_written=0,
                error_code="target.invalid_existing_tail" if exc.code == "input.invalid_tail" else exc.code,
                error_message=exc.message,
                verification_refs=["target.before"],
                **append_metadata,
            )
        before_bytes = authority.read_bytes() if before["exists"] is True else b""
        create_absent = expected_head is None or expected_head == absent_head_token()
        if before["exists"] is not True:
            if not create_absent:
                return _receipt(
                    effect,
                    run_id=run_id,
                    timestamp=timestamp,
                    status="failed_no_effect",
                    before=before,
                    after=before,
                    bytes_written=0,
                    error_code="target.missing",
                    verification_refs=["target.before"],
                    **append_metadata,
                )
        elif create_absent:
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="failed_no_effect",
                before=before,
                after=before,
                bytes_written=0,
                error_code="target.stale_head",
                verification_refs=["target.before"],
                **append_metadata,
            )
        elif before["head_token"] != expected_head:
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="failed_no_effect",
                before=before,
                after=before,
                bytes_written=0,
                error_code="target.stale_head",
                verification_refs=["target.before"],
                **append_metadata,
            )
        descriptor: int | None = None
        written = 0
        try:
            authority.assert_namespace_binding()
            descriptor = authority.open_exclusive() if create_absent else authority.open_existing(writable=True)
            append_offset = 0 if before["length"] is None else int(before["length"])
            os.lseek(descriptor, append_offset, os.SEEK_SET)
            view = memoryview(record)
            writer = active.write_primitive or os.write
            while written < len(record):
                if active.fail_after_bytes is not None and written >= active.fail_after_bytes:
                    raise OSError("injected failure after append")
                count = len(record) - written
                if active.maximum_write_size is not None:
                    if active.maximum_write_size <= 0:
                        raise OSError("injected zero-length write")
                    count = min(count, active.maximum_write_size)
                if active.fail_after_bytes is not None:
                    count = min(count, active.fail_after_bytes - written)
                    if count <= 0:
                        raise OSError("injected failure after append")
                actual = writer(descriptor, view[written : written + count])
                if actual <= 0:
                    raise OSError("short write made no progress")
                written += actual
            os.fsync(descriptor)
            authority.assert_namespace_binding()
        except (OSError, PhaseError) as exc:
            if descriptor is not None:
                os.close(descriptor)
                descriptor = None
            try:
                after = _observe(target)
            except (OSError, PhaseError):
                after = _unknown()
            status = "failed_partial" if written or after.get("length") != before.get("length") else "failed_no_effect"
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status=status,
                before=before,
                after=after,
                bytes_written=written,
                error_code=exc.code if isinstance(exc, PhaseError) else "mechanism.write_failed",
                error_message=str(exc),
                verification_refs=["target.after"] if after["known"] else [],
                append_offset=append_offset if "append_offset" in locals() else None,
                **append_metadata,
            )
        finally:
            if descriptor is not None:
                os.close(descriptor)
        try:
            if active.readback_error:
                raise OSError("injected read-back failure")
            data = authority.read_bytes() if active.readback_override is None else active.readback_override
            append_offset = 0 if before["length"] is None else int(before["length"])
            readback = data[append_offset : append_offset + len(record)]
            after = {"known": True, "exists": True, "digest": digest_bytes(data), "length": len(data), "head_token": stream_head_token(data)}
        except (OSError, PhaseError) as exc:
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="indeterminate",
                before=before,
                after=_unknown(),
                bytes_written=written,
                error_code="verification.readback_failed",
                error_message=str(exc),
                verification_refs=[],
                append_offset=0 if before["length"] is None else int(before["length"]),
                **append_metadata,
            )
        expected_after_head = stream_head_token(before_bytes + record)
        verified = readback == record and after["head_token"] == expected_after_head
        receipt = _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="applied_verified" if verified else "applied_unverified",
            before=before,
            after=after,
            bytes_written=written,
            error_code=None if verified else "verification.result_mismatch",
            verification_refs=["target.readback", "target.resulting_head"],
            append_offset=append_offset,
            resulting_head=after["head_token"] if isinstance(after["head_token"], str) else None,
            **append_metadata,
        )
        receipt["append_offset"] = append_offset
        receipt["resulting_head"] = after["head_token"]
        return receipt
    finally:
        if "authority" in locals():
            authority.close()
        lock_context.__exit__(None, None, None)
