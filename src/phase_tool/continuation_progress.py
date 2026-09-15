"""Code-owned recovery progress, independent of broker return/finalization.

A returned rename syscall proves commit; a started syscall without a returned
success is unknown. Cleanup cannot undo either fact. This is not a durable
execution journal: immutable continuation evidence and retry verify the target.
"""
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .errors import PhaseError


class RecoveryErrorDetail(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    phase: str
    code: str
    exception_type: str
    message: str
    errno: int | None = None


class LockFinalization(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    unlock: Literal['not_attempted', 'succeeded', 'failed'] = 'not_attempted'
    close: Literal['not_attempted', 'succeeded', 'unknown'] = 'not_attempted'


@dataclass
class RecoveryProgress:
    attempted: bool = False
    effect_state: Literal['not_attempted', 'unknown', 'committed'] = 'not_attempted'
    target_verified: bool = False
    lock_finalization: LockFinalization | None = None
    errors: list[RecoveryErrorDetail] = field(default_factory=list)
    _recorded: dict[int, BaseException] = field(default_factory=dict, repr=False)

    def record_error(self, phase: str, exc: BaseException) -> None:
        if isinstance(exc, ContinuationInterrupted):
            return  # The primary and cleanup errors were already recorded.
        if id(exc) in self._recorded:
            return
        # Retain the exception itself: otherwise consecutive except blocks can
        # reuse its id and silently discard a distinct unlock/close failure.
        self._recorded[id(exc)] = exc
        prior = exc.__cause__ or exc.__context__
        if prior is not None:
            self.record_error(phase, prior)
        self.errors.append(RecoveryErrorDetail(
            phase=phase, code=exc.code if isinstance(exc, PhaseError) else 'recovery.failure',
            exception_type=type(exc).__name__, message=str(exc),
            errno=exc.errno if isinstance(exc, OSError) else None,
        ))


class ContinuationInterrupted(PhaseError):
    def __init__(self, cause, progress):
        super().__init__(cause.code if isinstance(cause, PhaseError) else 'recovery.commit_failed')
        self.mutation_attempted = progress.attempted
        self.progress = progress


class RecoveryRootLock:
    """Reuse historical acquisition, but preserve both finalization failures.

    Close is attempted even if unlock fails. A failed close is explicitly
    uncertain and is never retried: POSIX may already have reused that fd.
    Historical authority provider bytes and guarantees are not changed.
    """
    def __init__(self, target, scope, progress):
        from .mutation.posix.authority import PosixTargetRootLock
        self._lock = PosixTargetRootLock(target, scope, timeout_seconds=0)
        self.progress = progress

    def __enter__(self):
        self._lock.__enter__()
        self.progress.lock_finalization = LockFinalization()
        return self

    def __exit__(self, exc_type, exc, traceback):
        import fcntl
        import os
        progress = self.progress
        if exc is not None:
            progress.record_error('continuation', exc)
        descriptor = self._lock._descriptor
        self._lock._descriptor = None
        failed = False
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                progress.lock_finalization.unlock = 'succeeded'
            except OSError as error:
                progress.lock_finalization.unlock = 'failed'
                progress.record_error('lock_unlock', error)
                failed = True
            try:
                os.close(descriptor)
                progress.lock_finalization.close = 'succeeded'
            except OSError as error:
                progress.lock_finalization.close = 'unknown'
                progress.record_error('lock_close', error)
                failed = True
        if failed:
            cause = exc if exc is not None else PhaseError('recovery.lock_finalization_failed')
            raise ContinuationInterrupted(cause, progress) from cause
        return False
