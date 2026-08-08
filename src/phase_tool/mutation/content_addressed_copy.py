from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..canonical import digest_bytes
from ..errors import PhaseError
from ..paths import _is_reparse_point
from .authority import AuthorityProvider
from .target_authority import TargetAuthority  # compatibility seam for existing fault-injection tests

_MAX_CONTENT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class ContentAddressedCopyFaults:
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


def _same_content(observation: dict[str, object], effect: dict[str, object]) -> bool:
    return observation.get("digest") == effect["content_digest"] and observation.get("length") == effect["content_length"]


def execute_content_addressed_copy(
    effect: dict[str, object],
    target_root: Path,
    content: bytes,
    *,
    run_id: str,
    timestamp: str,
    faults: ContentAddressedCopyFaults | None = None,
    authority_provider: AuthorityProvider,
) -> dict[str, object]:
    lock_scope = f"content-addressed-copy:{effect.get('content_digest', 'unbound')}"
    with authority_provider.lock_target_root(target_root, lock_scope):
        return _execute_content_addressed_copy_locked(
            effect,
            target_root,
            content,
            run_id=run_id,
            timestamp=timestamp,
            faults=faults,
            authority_provider=authority_provider,
        )


def _execute_content_addressed_copy_locked(
    effect: dict[str, object],
    target_root: Path,
    content: bytes,
    *,
    run_id: str,
    timestamp: str,
    faults: ContentAddressedCopyFaults | None = None,
    authority_provider: AuthorityProvider,
) -> dict[str, object]:
    active = faults or ContentAddressedCopyFaults()
    if len(content) > _MAX_CONTENT_BYTES:
        raise PhaseError("mechanism.content_too_large")
    if len(content) != effect["content_length"] or digest_bytes(content) != effect["content_digest"]:
        raise PhaseError("mechanism.content_binding_mismatch")
    hex_digest = str(effect["content_digest"]).split(":", 1)[1]
    policy = effect.get("locator_policy_id", "content_addressed_sha256_flat_v1")
    if policy == "content_addressed_sha256_sharded_v1":
        expected_locator = f"blobs/sha256/{hex_digest[:2]}/{hex_digest}"
    elif policy == "content_addressed_sha256_flat_v1":
        expected_locator = "objects/" + hex_digest
    else:
        raise PhaseError("mechanism.locator_policy_unsupported", str(policy))
    if effect["target"]["relative_locator"] != expected_locator:  # type: ignore[index]
        raise PhaseError("mechanism.locator_digest_mismatch")
    detector = active.reparse_detector or _is_reparse_point
    authority = authority_provider.open_authority(
        target_root,
        str(effect["target"]["relative_locator"]),  # type: ignore[index]
        detector,
    )
    target = authority.target
    try:
        before = authority.observe()
    except Exception:
        authority.close()
        raise
    if before["exists"] is True:
        authority.close()
        if _same_content(before, effect):
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="applied_verified",
                attempted=True,
                before=before,
                after=before,
                bytes_written=0,
                verification_refs=["target.before", "target.existing_content"],
                error_code=None,
            )
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="failed_no_effect",
            attempted=True,
            before=before,
            after=before,
            bytes_written=0,
            verification_refs=["target.before", "target.unchanged"],
            error_code="target.same_key_conflict",
        )
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
    descriptor: int | None = None
    written = 0
    try:
        descriptor = authority.open_exclusive()
        view = memoryview(content)
        writer = active.write_primitive or os.write
        while written < len(content):
            if active.fail_after_bytes is not None and written >= active.fail_after_bytes:
                raise OSError("injected failure after target creation")
            count = len(content) - written
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
        try:
            after = authority.observe()
        except Exception:
            authority.close()
            raise
        authority.close()
        if _same_content(after, effect):
            return _receipt(
                effect,
                run_id=run_id,
                timestamp=timestamp,
                status="applied_verified",
                attempted=True,
                before=before,
                after=after,
                bytes_written=0,
                verification_refs=["target.after", "target.existing_content"],
                error_code=None,
            )
        return _receipt(
            effect,
            run_id=run_id,
            timestamp=timestamp,
            status="failed_no_effect",
            attempted=True,
            before=before,
            after=after,
            bytes_written=0,
            verification_refs=["target.after"],
            error_code="target.same_key_conflict",
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
    verified = _same_content(after, effect)
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
