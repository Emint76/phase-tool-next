"""V2 create-only streaming mechanism. V1 bytes mechanism is unchanged."""
from __future__ import annotations

import os
from pathlib import Path

from ..errors import PhaseError
from ..streaming import FILE_LIMIT, hash_file, observe_target, transfer
from .exclusive_create import _receipt, _unknown


def execute_stream_create(effect, target_root: Path, blob: Path, *, run_id: str,
                          timestamp: str, authority_provider):
    expected = (effect["content_digest"], effect["content_length"])
    if hash_file(blob, FILE_LIMIT) != expected:
        raise PhaseError("mechanism.content_binding_mismatch")
    authority = authority_provider.open_authority(target_root, effect["target"]["relative_locator"])
    before = _unknown()
    attempted = False
    descriptor = None
    written = 0
    after = _unknown()
    status = "indeterminate"
    error = None
    try:
        before = observe_target(authority, FILE_LIMIT)
        authority.assert_namespace_binding()
        attempted = True
        descriptor = authority.open_exclusive()
        source = os.open(blob, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            actual = transfer(source, FILE_LIMIT, descriptor)
            written = actual[1]
        finally:
            os.close(source)
        if actual != expected:
            raise PhaseError("mechanism.content_binding_mismatch")
        os.fsync(descriptor)
        authority.fsync_parent()
        after = observe_target(authority, FILE_LIMIT)
        if after["digest"] != expected[0] or after["length"] != expected[1]:
            raise PhaseError("verification.result_mismatch")
        # Verify the named target is the actual object this mechanism created.
        current = authority.open_existing()
        try:
            a, b = os.fstat(descriptor), os.fstat(current)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise PhaseError("path.target_identity_changed")
        finally:
            os.close(current)
        status = "applied_verified"
    except FileExistsError:
        status, error = "failed_no_effect", "target.destination_exists"
    except (OSError, PhaseError) as exc:
        error = exc.code if isinstance(exc, PhaseError) else "mechanism.write_failed"
        if descriptor is not None:
            written = os.fstat(descriptor).st_size
        try:
            after = observe_target(authority, FILE_LIMIT)
        except (OSError, PhaseError):
            after = _unknown()
        status = "failed_partial" if descriptor is not None else "failed_no_effect"
        if not after["known"]:
            status = "indeterminate"
    finally:
        if descriptor is not None:
            os.close(descriptor)
        authority.close()
    return _receipt(effect, run_id=run_id, timestamp=timestamp, status=status,
                    attempted=attempted, before=before, after=after,
                    bytes_written=written, verification_refs=["target.stream_readback"] if after["known"] else [],
                    error_code=error)
