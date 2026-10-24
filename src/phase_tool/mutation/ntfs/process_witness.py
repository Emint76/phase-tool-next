"""Read-only witness for a creation process HANDLE retained by its spawn owner.

No spawn, OpenProcess, DuplicateHandle, close, termination, privilege change,
PID search, retry permission or persistent state. This proves this process's
exit only; a fixed worker must independently forbid descendants/handle transfer.
The trusted owner must never close/replace its process handle or mutate this
object during these calls; no caller-supplied callbacks or provider hooks.
Exact Popen support is limited to Windows CPython3.12.10 internal Handle layout;
no parent/bootstrap, installation selection or ordinary Core admission is added.
"""
from __future__ import annotations

import ctypes as C
from multiprocessing.context import SpawnProcess
import os
import subprocess
import sys
import threading
import time

from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import _require


class _FileTime(C.Structure):
    _fields_ = [('low', C.c_uint32), ('high', C.c_uint32)]

    def integer(self):
        return self.low | (self.high << 32)


class WindowsProcessWitness:
    def __init__(self, process: SpawnProcess | subprocess.Popen):
        _require(not getattr(self, '_initialization_attempted', False), 'ntfs.worker_witness_initialization_consumed')
        self._initialization_attempted = True
        _require(os.name == 'nt' and type(process) in (SpawnProcess, subprocess.Popen),
                 'ntfs.owned_creation_process_required')
        _require(type(process.pid) is int and process.pid > 0, 'ntfs.started_worker_required')
        self.process, self.pid = process, process.pid
        self._popen = type(process) is subprocess.Popen
        self._handle_object = None
        if self._popen:
            # This is CPython's actual creation handle, borrowed from its exact
            # trusted Popen owner. Never accept an arbitrary PID/handle wrapper.
            _require(sys.platform == 'win32' and sys.implementation.name == 'cpython'
                and sys.version_info[:3] == (3, 12, 10), 'ntfs.windows_cpython31210_process_required')
            handle = getattr(process, '_handle', None)
            _require(process._child_created is True and type(handle) is subprocess.Handle
                and handle.closed is False, 'ntfs.owned_popen_handle_required')
            self._handle_object = handle
            self.handle = int(handle)
        else:
            self.handle = process.sentinel
        _require(type(self.handle) is int and self.handle > 0, 'ntfs.worker_process_handle_required')
        self._owner = (os.getpid(), threading.get_ident())
        self._entered = False
        self.events = []
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.kernel.GetProcessId.argtypes = [C.c_void_p]
        self.kernel.GetProcessId.restype = C.c_uint32
        self.kernel.GetProcessTimes.argtypes = [C.c_void_p] + [C.POINTER(_FileTime)]*4
        self.kernel.GetProcessTimes.restype = C.c_int32
        self.kernel.WaitForSingleObject.argtypes = [C.c_void_p, C.c_uint32]
        self.kernel.WaitForSingleObject.restype = C.c_uint32
        self.kernel.GetExitCodeProcess.argtypes = [C.c_void_p, C.POINTER(C.c_uint32)]
        self.kernel.GetExitCodeProcess.restype = C.c_int32
        self.creation_filetime = self._identity()

    def _owned(self):
        _require(self._owner == (os.getpid(), threading.get_ident()), 'ntfs.worker_witness_owner_changed')
        _require(self.process.pid == self.pid, 'ntfs.worker_creation_handle_changed')
        if self._popen:
            _require(self.process._child_created is True
                and self.process._handle is self._handle_object
                and self._handle_object.closed is False
                and int(self._handle_object) == self.handle, 'ntfs.worker_creation_handle_changed')
        else:
            _require(self.process.sentinel == self.handle, 'ntfs.worker_creation_handle_changed')

    def _call(self, name, *arguments):
        self._owned()
        event = {'api': name, 'started_ns': time.monotonic_ns(), 'outcome': 'unknown'}
        self.events.append(event)
        C.set_last_error(0)
        result = getattr(self.kernel, name)(self.handle, *arguments)
        error = C.get_last_error()
        event.update(returned_ns=time.monotonic_ns(), result=result, winerror=error, outcome='returned')
        return result, error

    def _identity(self):
        pid, error = self._call('GetProcessId')
        if pid == 0:
            raise PhaseError('ntfs.worker_process_identity_unavailable', details={'winerror': error})
        _require(pid == self.pid, 'ntfs.worker_process_identity_mismatch')
        values = [_FileTime() for _ in range(4)]
        result, error = self._call('GetProcessTimes', *(C.byref(value) for value in values))
        if not result:
            raise PhaseError('ntfs.worker_process_times_unavailable', details={'winerror': error})
        return values[0].integer()

    def wait_for_exit(self, timeout_ms: int) -> dict:
        """Only WAIT_OBJECT_0 establishes exit; timeout never authorizes replay.

        A second read-only wait after an owner-requested termination is permitted.
        This helper does not request termination or attest effect completion.
        Creation FILETIME is diagnostic, not a unique process-birth identifier.
        """
        self._owned()
        _require(not self._entered, 'ntfs.worker_witness_reentrant_call')
        _require(type(timeout_ms) is int and 0 <= timeout_ms <= 60000, 'ntfs.worker_wait_bound')
        self._entered = True
        try:
            _require(self._identity() == self.creation_filetime, 'ntfs.worker_process_identity_mismatch')
            result, error = self._call('WaitForSingleObject', timeout_ms)
            if result not in (0, 0x102):
                raise PhaseError('ntfs.worker_process_wait_unknown', details={'wait_result': result, 'winerror': error})
            code = None
            if result == 0:
                value = C.c_uint32()
                ok, error = self._call('GetExitCodeProcess', C.byref(value))
                if not ok:
                    raise PhaseError('ntfs.worker_exit_code_unavailable', details={'winerror': error})
                code = value.value
                _require(self._identity() == self.creation_filetime, 'ntfs.worker_process_identity_mismatch')
            return parse_json_bytes(canonical_bytes({'process_witness_version': '1.0', 'pid': self.pid,
                'creation_filetime': self.creation_filetime, 'wait_result': result,
                'worker_exit_established': result == 0, 'exit_code': code,
                'scope': 'this retained creation process handle only; not descendants or effect success',
                'events': self.events}))
        finally:
            self._entered = False
