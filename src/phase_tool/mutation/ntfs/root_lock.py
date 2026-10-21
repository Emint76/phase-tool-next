"""Internal, single-acquisition Windows root mutex; not storage admission.

A mutex serializes cooperating live workers. It is NOT a durable pending-intent
index or a crash-recovery decision: the object disappears at last handle close.
A future trusted composition must bind every coordinator for this physical root
to one qualified ext4 pending-root index, reject overlapping grants, and inspect
the original operation before allowing effects after an uncertain outcome.
"""
from __future__ import annotations

import ctypes as C
import hashlib
import json
import os
import threading
import time

from ...errors import PhaseError
from .native import NativeIO, _error_record, _require
from .mutating import NativeMutationIO
from .scoped import NativeRootGrant, NativeScopedTarget


# Finalization/handoff and accepting an already-waiting owner share one
# barrier. RLock permits _retire() within finalization without releasing it.
_REGISTRY_GUARD = threading.RLock()
_ACTIVE: dict[tuple[int, int, str], object] = {}
_QUARANTINED: set[tuple[int, str]] = set()


def root_mutex_name(grant: NativeRootGrant) -> str:
    """Stable across aliases, contracts and releases for one physical root.

    A binding label, run ID, drive/device alias, path, or implementation version
    must not partition mutual exclusion for the same qualified physical root.
    """
    _require(type(grant) is NativeRootGrant, 'ntfs.invalid_root_grant')
    identity = grant.root_identity
    value = json.dumps([grant.volume_guid, identity.volume_serial, identity.file_id],
                       ensure_ascii=True, separators=(',', ':')).encode('ascii')
    digest = hashlib.sha256(b'Phase.NTFS.RootLock.v1\0' + value).hexdigest()
    return 'Global\\Phase.NTFS.RootLock.v1.' + digest


class NativeRootMutex:
    """Thread-affine, nonrecursive lease over an existing native granted root.

    Default DACL, no inheritance, no namespace/security fallback. An abandoned
    wait grants OS ownership, but never returns a usable Phase lease. Release
    and close are each attempted once; errors remain independently observable.
    Unknown finalization quarantines this physical root in this process. The
    caller must end that operation worker and retain its durable pending intent.
    """

    def __init__(self, io: NativeIO, grant: NativeRootGrant, *, timeout_ms: int = 2000):
        _require(type(io) in (NativeIO, NativeMutationIO) and type(grant) is NativeRootGrant,
                 'ntfs.invalid_root_lock_owner')
        _require(type(timeout_ms) is int and 0 <= timeout_ms <= 5000,
                 'ntfs.invalid_root_lock_timeout')
        self.io, self.grant, self.timeout_ms = io, grant, timeout_ms
        self.name = root_mutex_name(grant)
        self._owner = (os.getpid(), threading.get_native_id())
        self._key = (*self._owner, self.name)
        self._state = 'new'
        self._scope: NativeScopedTarget | None = None
        self._handle: int | None = None
        self._owned = self._reserved = self._uncertain = self._in_call = False
        self.events: list[dict] = []
        kernel = io.kernel
        kernel.CreateMutexExW.argtypes = [C.c_void_p, C.c_wchar_p, C.c_uint32, C.c_uint32]
        kernel.CreateMutexExW.restype = C.c_void_p
        kernel.WaitForSingleObject.argtypes = [C.c_void_p, C.c_uint32]
        kernel.WaitForSingleObject.restype = C.c_uint32
        kernel.ReleaseMutex.argtypes = [C.c_void_p]
        kernel.ReleaseMutex.restype = C.c_int32

    @property
    def state(self) -> str:
        return self._state

    def _affinity(self) -> None:
        _require(self._owner == (os.getpid(), threading.get_native_id()),
                 'ntfs.root_lock_wrong_thread_or_process')

    def _reserve(self) -> None:
        with _REGISTRY_GUARD:
            _require((self._owner[0], self.name) not in _QUARANTINED,
                     'ntfs.root_lock_worker_quarantined')
            _require(self._key not in _ACTIVE, 'ntfs.recursive_root_lock_forbidden')
            _ACTIVE[self._key] = self
            self._reserved = True

    def _retire(self) -> None:
        with _REGISTRY_GUARD:
            if self._uncertain:
                _QUARANTINED.add((self._owner[0], self.name))
            if self._reserved:
                if _ACTIVE.get(self._key) is not self:
                    self._uncertain = True
                    _QUARANTINED.add((self._owner[0], self.name))
                    raise PhaseError('ntfs.root_lock_registry_corrupt')
                del _ACTIVE[self._key]
                self._reserved = False

    def _call(self, api: str, arguments: tuple, **facts):
        event = {'api': api, 'started_ns': time.monotonic_ns(), 'outcome': 'unknown', **facts}
        self.events.append(event)
        self._in_call = True
        try:
            C.set_last_error(0)
            result = getattr(self.io.kernel, api)(*arguments)
            error = C.get_last_error()
            event.update(returned_ns=time.monotonic_ns(), result=result, winerror=error,
                         outcome='returned')
            return result, error, event
        except BaseException as error:
            self._uncertain = True
            event['call_error'] = _error_record(error)
            raise
        finally:
            self._in_call = False

    def acquire(self) -> 'NativeRootMutex':
        self._affinity()
        _require(self._state == 'new', 'ntfs.root_lock_consumed')
        # Reject same-thread recursion BEFORE any root handle or mutex open.
        self._reserve()
        self._state = 'opening'
        try:
            self._scope = NativeScopedTarget(self.io, self.grant, 'phase-root-lock-anchor')
            handle, error, _ = self._call('CreateMutexExW', (None, self.name, 0, 0x00100001),
                                        name=self.name, desired_access=0x00100001,
                                        inherited=False, initial_owner=False)
            if not handle:
                raise PhaseError('ntfs.root_lock_create_failed', details={'winerror': error})
            self._handle = handle
            self._state = 'waiting'
            result, error, _ = self._call('WaitForSingleObject', (handle, self.timeout_ms),
                                        timeout_ms=self.timeout_ms)
            if result in (0, 0x80):
                self._owned = True
                if result == 0x80:
                    self._state = 'recovery_required'
                    with _REGISTRY_GUARD:
                        _QUARANTINED.add((self._owner[0], self.name))
                    raise PhaseError('ntfs.abandoned_root_lock_recovery_required',
                                     details={'wait_result': result, 'worker_must_exit': True})
            elif result == 0x102:
                raise PhaseError('ntfs.root_lock_timeout', details={'wait_result': result})
            else:
                self._uncertain = True
                raise PhaseError('ntfs.root_lock_wait_unknown',
                                 details={'wait_result': result, 'winerror': error})
            with _REGISTRY_GUARD:
                _require((self._owner[0], self.name) not in _QUARANTINED,
                         'ntfs.root_lock_worker_quarantined')
                self._scope.assert_bound()
                self._state = 'held'
            return self
        except BaseException as primary:
            try:
                self.close()
            except BaseException as finalization:
                raise PhaseError('ntfs.root_lock_acquisition_finalization_failed', details={
                    'primary_error': _error_record(primary),
                    'finalization_error': _error_record(finalization)}) from primary
            raise

    def assert_held(self) -> None:
        self._affinity()
        _require(self._state == 'held' and self._owned and self._reserved and not self._uncertain,
                 'ntfs.root_lock_not_held')
        with _REGISTRY_GUARD:
            _require(_ACTIVE.get(self._key) is self, 'ntfs.root_lock_registry_corrupt')
            _require((self._owner[0], self.name) not in _QUARANTINED,
                     'ntfs.root_lock_worker_quarantined')
            self._scope.assert_bound()

    def close(self) -> None:
        self._affinity()
        _require(not self._in_call, 'ntfs.root_lock_call_pending')
        with _REGISTRY_GUARD:
            self._finalize()

    def _finalize(self) -> None:
        _require(self._state in ('new', 'opening', 'waiting', 'held', 'recovery_required'),
                 'ntfs.root_lock_consumed')
        self._state = 'closing'
        errors = []
        if self._owned:
            self._owned = False  # Consume the release attempt, even on an unknown response.
            try:
                released, error, _ = self._call('ReleaseMutex', (self._handle,))
                if not released:
                    raise PhaseError('ntfs.root_lock_release_failed', details={'winerror': error})
            except BaseException as error:
                self._uncertain = True
                errors.append({'stage': 'release', 'error': _error_record(error)})
        if self._handle is not None:
            handle, self._handle = self._handle, None
            try:
                closed, error, _ = self._call('CloseHandle', (handle,), kind='root_mutex')
                if not closed:
                    raise PhaseError('ntfs.root_lock_close_failed', details={'winerror': error})
            except BaseException as error:
                self._uncertain = True
                errors.append({'stage': 'close', 'error': _error_record(error)})
        if self._scope is not None:
            scope, self._scope = self._scope, None
            try:
                scope.close()
            except BaseException as error:
                self._uncertain = True
                errors.append({'stage': 'scope', 'error': _error_record(error)})
        try:
            self._retire()
        except BaseException as error:
            self._uncertain = True
            errors.append({'stage': 'registry', 'error': _error_record(error)})
        self._state = 'unknown' if self._uncertain or errors else 'closed'
        if self._state == 'unknown':
            raise PhaseError('ntfs.root_lock_finalization_unknown', details={
                'errors': errors, 'finalization': 'unknown', 'worker_must_exit': True})

    def __enter__(self):
        return self.acquire()

    def __exit__(self, kind, value, tb):
        try:
            self.close()
        except BaseException as error:
            if value is not None:
                raise PhaseError('ntfs.root_lock_finalization_failed', details={
                    'primary_error': _error_record(value),
                    'finalization_error': _error_record(error)}) from value
            raise
