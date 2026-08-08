from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..canonical import digest_bytes
from ..errors import PhaseError
from ..paths import _is_reparse_point
from .authority import AuthorityProvider

_MAX_CONTENT_BYTES = 1_048_576


@dataclass(frozen=True)
class ExclusiveCreateFaults:
    """Deterministic Stage 3 test seams; production uses the all-default value."""

    maximum_write_size: int | None = None
    fail_after_bytes: int | None = None
    readback_override: bytes | None = None
    readback_error: bool = False
    reparse_detector: Callable[[Path], bool] | None = None
    write_primitive: Callable[[int, memoryview], int] | None = None
    before_exclusive_create: Callable[[Path], None] | None = None
    before_readback: Callable[[Path], None] | None = None


def _unknown() -> dict[str, object]:
    return {"known": False, "exists": None, "digest": None, "length": None, "head_token": None}


def _observe(path: Path, reparse_detector: Callable[[Path], bool]) -> dict[str, object]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"known": True, "exists": False, "digest": None, "length": None, "head_token": None}
    if path.is_symlink():
        raise PhaseError("path.link_forbidden", str(path))
    if reparse_detector(path):
        raise PhaseError("path.reparse_forbidden", str(path))
    if not stat.S_ISREG(info.st_mode):
        return {"known": True, "exists": True, "digest": None, "length": None, "head_token": None}
    data = path.read_bytes()
    return {"known": True, "exists": True, "digest": digest_bytes(data), "length": len(data), "head_token": None}


def _receipt(
    effect: dict[str, object],
    *,
    run_id: str,
    timestamp: str,
    status: str,
    attempted: bool,
    before: dict[str, object],
    after: dict[str, object],
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
        "bytes_written": bytes_written,
        "verification_refs": verification_refs,
        "error": None if error_code is None else {"code": error_code, "message": error_message or error_code},
        "started_at": timestamp,
        "finished_at": timestamp,
    }


def execute_exclusive_create(
    effect: dict[str, object],
    target_root: Path,
    content: bytes,
    *,
    run_id: str,
    timestamp: str,
    faults: ExclusiveCreateFaults | None = None,
    authority_provider: AuthorityProvider,
) -> dict[str, object]:
    """Create one absent regular file with OS O_EXCL; never replace or clean up it."""

    active = faults or ExclusiveCreateFaults()
    if len(content) > _MAX_CONTENT_BYTES:
        raise PhaseError("mechanism.content_too_large")
    if len(content) != effect["content_length"] or digest_bytes(content) != effect["content_digest"]:
        raise PhaseError("mechanism.content_binding_mismatch")
    detector = active.reparse_detector or _is_reparse_point
    authority = authority_provider.open_authority(
        target_root,
        str(effect["target"]["relative_locator"]),  # type: ignore[index]
        detector,
    )
    target = authority.target
    before = authority.observe()
    if active.before_exclusive_create is not None:
        try:
            active.before_exclusive_create(target)
        except Exception:
            authority.close()
            raise
    try:
        authority.assert_namespace_binding()
    except Exception:
        authority.close()
        raise
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor: int | None = None
    written = 0
    try:
        descriptor = authority.open_exclusive()
        view = memoryview(content)
        writer = active.write_primitive or os.write
        while written < len(content):
            if active.fail_after_bytes is not None and written >= active.fail_after_bytes:
                raise OSError("injected failure after target creation")
            remaining = len(content) - written
            count = remaining
            if active.maximum_write_size is not None:
                if active.maximum_write_size <= 0:
                    raise OSError("injected zero-length write")
                count = min(count, active.maximum_write_size)
            if active.fail_after_bytes is not None:
                count = min(count, active.fail_after_bytes - written)
                if count <= 0:
                    raise OSError("injected failure after target creation")
            actual = writer(descriptor, view[written : written + count])
            if actual <= 0:
                raise OSError("short write made no progress")
            written += actual
        os.fsync(descriptor)
        authority.fsync_parent()
    except FileExistsError:
        after = authority.observe()
        authority.close()
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="failed_no_effect",
            attempted=True,
            before=before,
            after=after,
            bytes_written=0,
            verification_refs=["target.before", "target.after"],
            error_code="target.destination_exists",
        )
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        try:
            after = authority.observe()
        except (OSError, PhaseError):
            after = _unknown()
        authority.close()
        effect_observed = after.get("exists") is True
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="failed_partial" if effect_observed else "failed_no_effect",
            attempted=True,
            before=before,
            after=after,
            bytes_written=written,
            verification_refs=["target.after"] if after["known"] else [],
            error_code="mechanism.write_failed",
            error_message=str(exc),
        )
    try:
        if active.before_readback is not None:
            active.before_readback(target)
        if active.readback_error:
            raise OSError("injected read-back failure")
        after = authority.readback(active.readback_override, descriptor)
        authority.assert_namespace_binding()
    except (OSError, PhaseError) as exc:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        authority.close()
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="indeterminate",
            attempted=True,
            before=before,
            after=_unknown(),
            bytes_written=written,
            verification_refs=[],
            error_code=exc.code if isinstance(exc, PhaseError) else "verification.readback_failed",
            error_message=str(exc),
        )
    if descriptor is not None:
        os.close(descriptor)
        descriptor = None
    authority.close()
    verified = after["digest"] == effect["content_digest"] and after["length"] == effect["content_length"]
    return _receipt(
        effect,
        run_id=run_id,
        timestamp=timestamp,
        status="applied_verified" if verified else "applied_unverified",
        attempted=True,
        before=before,
        after=after,
        bytes_written=written,
        verification_refs=["target.readback"],
        error_code=None if verified else "verification.result_mismatch",
    )
