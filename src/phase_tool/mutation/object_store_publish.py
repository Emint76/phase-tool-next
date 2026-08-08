from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..canonical import digest_bytes
from ..errors import PhaseError
from ..paths import _is_reparse_point
from .authority import AuthorityProvider, TargetAuthority

_MAX_CONTENT_BYTES = 512 * 1024


@dataclass(frozen=True)
class ObjectStorePublishFaults:
    maximum_write_size: int | None = None
    fail_old_object_write_after_bytes: int | None = None
    fail_new_object_write_after_bytes: int | None = None
    fail_temporary_write_after_bytes: int | None = None
    fail_after_objects: bool = False
    fail_atomic_replace: bool = False
    readback_override: bytes | None = None
    before_final_revalidation: Callable[[Path], None] | None = None
    after_replace: Callable[[Path], None] | None = None
    reparse_detector: Callable[[Path], bool] | None = None


class _WriteFailure(OSError):
    def __init__(self, message: str, bytes_written: int) -> None:
        super().__init__(message)
        self.bytes_written = bytes_written


def _unknown() -> dict[str, object]:
    return {"known": False, "exists": None, "digest": None, "length": None, "head_token": None}


def _same(observation: dict[str, object], digest: object, length: object) -> bool:
    return observation.get("exists") is True and observation.get("digest") == digest and observation.get("length") == length


def _write_all(descriptor: int, content: bytes, *, maximum_write_size: int | None = None, fail_after: int | None = None) -> int:
    written = 0
    view = memoryview(content)
    while written < len(content):
        if fail_after is not None and written >= fail_after:
            raise _WriteFailure("injected write failure", written)
        count = len(content) - written
        if maximum_write_size is not None:
            if maximum_write_size <= 0:
                raise _WriteFailure("write made no progress", written)
            count = min(count, maximum_write_size)
        if fail_after is not None:
            count = min(count, fail_after - written)
        actual = os.write(descriptor, view[written : written + count])
        if actual <= 0:
            raise _WriteFailure("write made no progress", written)
        written += actual
    return written


def _receipt(
    effect: dict[str, object],
    *,
    run_id: str,
    timestamp: str,
    status: str,
    before: dict[str, object],
    after: dict[str, object],
    old_before: dict[str, object],
    old_after: dict[str, object],
    new_before: dict[str, object],
    new_after: dict[str, object],
    bytes_written: int,
    refs: list[str],
    error_code: str | None,
    error_message: str | None = None,
) -> dict[str, object]:
    return {
        "effect_receipt_version": "1.0",
        "run_id": run_id,
        "effect_id": effect["effect_id"],
        "kind": effect["kind"],
        "status": status,
        "attempted": True,
        "before": before,
        "after": after,
        "archive_target": effect["archive_target"],
        "archive_before": old_before,
        "archive_after": old_after,
        "content_object_target": effect["content_object_target"],
        "content_object_before": new_before,
        "content_object_after": new_after,
        "bytes_written": bytes_written,
        "verification_refs": refs,
        "error": None if error_code is None else {"code": error_code, "message": error_message or error_code},
        "started_at": timestamp,
        "finished_at": timestamp,
    }


def _ensure_object(
    authority: TargetAuthority,
    content: bytes,
    expected_digest: str,
    *,
    run_id: str,
    maximum_write_size: int | None,
    fail_after: int | None,
    authority_provider: AuthorityProvider,
) -> tuple[dict[str, object], dict[str, object], int]:
    expected_length = len(content)
    before = authority.observe()
    if _same(before, expected_digest, expected_length):
        authority.assert_namespace_binding()
        return before, before, 0
    if before["exists"] is True:
        raise PhaseError("publish.object_conflict", authority.locator)
    token = digest_bytes(run_id.encode("utf-8")).removeprefix("sha256:")[:16]
    temporary = authority_provider.open_authority(
        authority.root,
        authority.locator + ".phase-tmp-object-" + token,
        authority.reparse_detector,
    )
    descriptor: int | None = None
    temporary_owned = False
    written = 0
    try:
        try:
            descriptor = temporary.open_exclusive()
            temporary_owned = True
        except FileExistsError:
            raise PhaseError("publish.object_temporary_conflict", temporary.locator)
        written = _write_all(
            descriptor,
            content,
            maximum_write_size=maximum_write_size,
            fail_after=fail_after,
        )
        os.fsync(descriptor)
        staged = temporary.readback(None, descriptor)
        if not _same(staged, expected_digest, expected_length):
            raise PhaseError("publish.object_verification_failed", authority.locator)
        try:
            authority.link_from(temporary)
        except FileExistsError:
            raced = authority.observe()
            if _same(raced, expected_digest, expected_length):
                authority.assert_namespace_binding()
                return before, raced, written
            raise PhaseError("publish.object_conflict", authority.locator)
        authority.fsync_parent()
        after = authority.observe()
        authority.assert_namespace_binding()
        temporary.assert_namespace_binding()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_owned:
            temporary.unlink(missing_ok=True)
        temporary.close()
    if not _same(after, expected_digest, expected_length):
        raise PhaseError("publish.object_verification_failed", authority.locator)
    return before, after, written


def execute_object_store_publish(
    effect: dict[str, object],
    current_root: Path,
    objects_root: Path,
    content: bytes,
    *,
    run_id: str,
    timestamp: str,
    faults: ObjectStorePublishFaults | None = None,
    authority_provider: AuthorityProvider,
) -> dict[str, object]:
    active = faults or ObjectStorePublishFaults()
    if len(content) > _MAX_CONTENT_BYTES:
        raise PhaseError("mechanism.content_too_large")
    if len(content) != effect["content_length"] or digest_bytes(content) != effect["content_digest"]:
        raise PhaseError("mechanism.content_binding_mismatch")
    if effect["archive_target"]["root_binding"] == effect["target"]["root_binding"]:  # type: ignore[index]
        raise PhaseError("publish.objects_root_not_separate")
    if effect["content_object_target"]["root_binding"] != effect["archive_target"]["root_binding"]:  # type: ignore[index]
        raise PhaseError("publish.object_root_mismatch")

    detector = active.reparse_detector or _is_reparse_point
    current = authority_provider.open_authority(current_root, str(effect["target"]["relative_locator"]), detector)  # type: ignore[index]
    old_object = authority_provider.open_authority(objects_root, str(effect["archive_target"]["relative_locator"]), detector)  # type: ignore[index]
    new_object = authority_provider.open_authority(objects_root, str(effect["content_object_target"]["relative_locator"]), detector)  # type: ignore[index]
    old_before = old_after = new_before = new_after = _unknown()
    bytes_written = 0
    temporary: TargetAuthority | None = None
    temporary_owned = False
    try:
        before = current.observe()
        old_before = old_object.observe()
        new_before = new_object.observe()
        current_is_old = _same(before, effect["archive_digest"], effect["archive_length"])
        current_is_new = _same(before, effect["content_digest"], effect["content_length"])
        old_exact = _same(old_before, effect["archive_digest"], effect["archive_length"])
        new_exact = _same(new_before, effect["content_digest"], effect["content_length"])
        if current_is_new and old_exact and new_exact:
            current.assert_namespace_binding()
            old_object.assert_namespace_binding()
            new_object.assert_namespace_binding()
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp, status="applied_verified", before=before,
                after=before, old_before=old_before, old_after=old_before, new_before=new_before,
                new_after=new_before, bytes_written=0,
                refs=["current.before", "old_object.before", "new_object.before", "publish.already_complete"], error_code=None,
            )
        if not current_is_old:
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp, status="failed_no_effect", before=before,
                after=before, old_before=old_before, old_after=old_before, new_before=new_before,
                new_after=new_before, bytes_written=0, refs=["current.before", "old_object.before", "new_object.before"],
                error_code="publish.current_mismatch",
            )
        current_descriptor = current.open_existing(deny_write_sharing=True)
        try:
            current_bytes = os.read(current_descriptor, int(effect["archive_length"]) + 1)
        finally:
            os.close(current_descriptor)
        if len(current_bytes) != effect["archive_length"] or digest_bytes(current_bytes) != effect["archive_digest"]:
            raise PhaseError("publish.current_changed_during_object_capture")

        try:
            old_before, old_after, written = _ensure_object(
                old_object,
                current_bytes,
                str(effect["archive_digest"]),
                run_id=run_id + ".old",
                maximum_write_size=active.maximum_write_size,
                fail_after=active.fail_old_object_write_after_bytes,
                authority_provider=authority_provider,
            )
            bytes_written += written
            new_before, new_after, written = _ensure_object(
                new_object,
                content,
                str(effect["content_digest"]),
                run_id=run_id + ".new",
                maximum_write_size=active.maximum_write_size,
                fail_after=active.fail_new_object_write_after_bytes,
                authority_provider=authority_provider,
            )
            bytes_written += written
        except (OSError, PhaseError) as exc:
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp, status="failed_partial", before=before,
                after=current.observe(), old_before=old_before, old_after=old_object.observe(), new_before=new_before,
                new_after=new_object.observe(), bytes_written=bytes_written + int(getattr(exc, "bytes_written", 0)),
                refs=["current.after", "old_object.after", "new_object.after"],
                error_code=exc.code if isinstance(exc, PhaseError) else "mechanism.write_failed", error_message=str(exc),
            )
        if active.fail_after_objects:
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp, status="failed_partial", before=before,
                after=current.observe(), old_before=old_before, old_after=old_after, new_before=new_before,
                new_after=new_after, bytes_written=bytes_written,
                refs=["current.after", "old_object.after", "new_object.after"], error_code="mechanism.write_failed",
                error_message="injected failure after object publication",
            )

        temporary_locator = str(effect["target"]["relative_locator"]) + ".phase-tmp-" + run_id[-32:]  # type: ignore[index]
        temporary = authority_provider.open_authority(current_root, temporary_locator, detector)
        descriptor: int | None = None
        try:
            descriptor = temporary.open_exclusive()
            temporary_owned = True
            written = _write_all(
                descriptor, content, maximum_write_size=active.maximum_write_size,
                fail_after=active.fail_temporary_write_after_bytes,
            )
            bytes_written += written
            os.fsync(descriptor)
            staged = temporary.readback(None, descriptor)
            if not _same(staged, effect["content_digest"], effect["content_length"]):
                raise PhaseError("publish.temporary_verification_failed")
        except (OSError, PhaseError) as exc:
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp, status="failed_partial", before=before,
                after=current.observe(), old_before=old_before, old_after=old_after, new_before=new_before,
                new_after=new_after, bytes_written=bytes_written + int(getattr(exc, "bytes_written", 0)),
                refs=["current.after", "old_object.after", "new_object.after"],
                error_code=exc.code if isinstance(exc, PhaseError) else "mechanism.temporary_write_failed", error_message=str(exc),
            )
        finally:
            if descriptor is not None:
                os.close(descriptor)

        if active.before_final_revalidation is not None:
            active.before_final_revalidation(current.target)
        latest = current.observe()
        if not _same(latest, effect["archive_digest"], effect["archive_length"]):
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp, status="failed_partial", before=before, after=latest,
                old_before=old_before, old_after=old_after, new_before=new_before, new_after=new_after,
                bytes_written=bytes_written, refs=["current.final_revalidation", "old_object.after", "new_object.after"],
                error_code="publish.current_verification_failed",
            )
        if active.fail_atomic_replace:
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp, status="failed_partial", before=before, after=latest,
                old_before=old_before, old_after=old_after, new_before=new_before, new_after=new_after,
                bytes_written=bytes_written, refs=["current.final_revalidation", "old_object.after", "new_object.after"],
                error_code="mechanism.atomic_replace_failed",
            )
        replace_completed = False
        try:
            current.replace_from(temporary)
            replace_completed = True
            temporary_owned = False
            current.fsync_parent()
            if active.after_replace is not None:
                active.after_replace(current.target)
            after = current.readback(active.readback_override)
            observed_old = old_object.observe()
            observed_new = new_object.observe()
            current.assert_namespace_binding()
            temporary.assert_namespace_binding()
            old_object.assert_namespace_binding()
            new_object.assert_namespace_binding()
        except (OSError, PhaseError) as exc:
            namespace_error: OSError | PhaseError | None = None
            for authority in (current, temporary, old_object, new_object):
                try:
                    authority.assert_namespace_binding()
                except (OSError, PhaseError) as binding_exc:
                    namespace_error = binding_exc
                    break
            try:
                after = current.observe()
            except (OSError, PhaseError):
                after = _unknown()
            try:
                observed_old = old_object.observe()
            except (OSError, PhaseError):
                observed_old = _unknown()
            try:
                observed_new = new_object.observe()
            except (OSError, PhaseError):
                observed_new = _unknown()
            observations_known = all(item.get("known") is True for item in (after, observed_old, observed_new))
            current_is_new = _same(after, effect["content_digest"], effect["content_length"])
            objects_exact = (
                _same(observed_old, effect["archive_digest"], effect["archive_length"])
                and _same(observed_new, effect["content_digest"], effect["content_length"])
            )
            detected_namespace_error = (
                exc
                if isinstance(exc, PhaseError) and exc.code == "path.parent_identity_changed"
                else namespace_error
            )
            namespace_unverified = detected_namespace_error is not None
            if namespace_unverified or not observations_known:
                status = "indeterminate"
            elif current_is_new:
                status = "applied_unverified"
            else:
                status = "failed_partial"
            post_replace = replace_completed or current_is_new
            return _receipt(
                effect, run_id=run_id, timestamp=timestamp,
                status=status, before=before, after=after,
                old_before=old_before, old_after=observed_old, new_before=new_before, new_after=observed_new,
                bytes_written=bytes_written,
                refs=[
                    "current.after", "old_object.after", "new_object.after",
                    "publish.objects_exact" if objects_exact else "publish.objects_not_exact",
                ],
                error_code=(
                    detected_namespace_error.code
                    if isinstance(detected_namespace_error, PhaseError)
                    else "mechanism.post_replace_verification_failed"
                    if isinstance(detected_namespace_error, OSError)
                    else exc.code
                    if isinstance(exc, PhaseError)
                    else (
                        "mechanism.post_replace_verification_failed"
                        if post_replace
                        else "mechanism.atomic_replace_failed"
                    )
                ),
                error_message=str(detected_namespace_error or exc),
            )
        verified = (
            _same(after, effect["content_digest"], effect["content_length"])
            and _same(observed_old, effect["archive_digest"], effect["archive_length"])
            and _same(observed_new, effect["content_digest"], effect["content_length"])
        )
        return _receipt(
            effect, run_id=run_id, timestamp=timestamp,
            status="applied_verified" if verified else "applied_unverified", before=before, after=after,
            old_before=old_before, old_after=observed_old, new_before=new_before, new_after=observed_new,
            bytes_written=bytes_written, refs=["current.readback", "old_object.readback", "new_object.readback"],
            error_code=None if verified else "verification.result_mismatch",
        )
    finally:
        if temporary is not None:
            if temporary_owned:
                temporary.unlink(missing_ok=True)
            temporary.close()
        new_object.close()
        old_object.close()
        current.close()
