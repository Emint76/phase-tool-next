"""Transient Windows worker containment; never execution or completion evidence.

One unnamed, non-inheritable Job Object owns the existing worker process only.
The parent assigns its retained creation HANDLE before sending original data or
GO. Closing the parent's last job handle on death requests worker termination.
That event is NOT proof of exit, effect outcome, receipt, or retry permission.
No process search, spawn, replacement, named coordination or durable state.
"""
from __future__ import annotations

import ctypes as C
import os
import threading

from ...errors import PhaseError
from .native import _require
from .process_witness import WindowsProcessWitness


class _BasicLimits(C.Structure):
    _fields_ = [('PerProcessUserTimeLimit', C.c_int64),
        ('PerJobUserTimeLimit', C.c_int64), ('LimitFlags', C.c_uint32),
        ('MinimumWorkingSetSize', C.c_size_t), ('MaximumWorkingSetSize', C.c_size_t),
        ('ActiveProcessLimit', C.c_uint32), ('Affinity', C.c_size_t),
        ('PriorityClass', C.c_uint32), ('SchedulingClass', C.c_uint32)]


class _IoCounters(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ('ReadOperationCount',
        'WriteOperationCount', 'OtherOperationCount', 'ReadTransferCount',
        'WriteTransferCount', 'OtherTransferCount')]


class _ExtendedLimits(C.Structure):
    _fields_ = [('BasicLimitInformation', _BasicLimits), ('IoInfo', _IoCounters),
        ('ProcessMemoryLimit', C.c_size_t), ('JobMemoryLimit', C.c_size_t),
        ('PeakProcessMemoryUsed', C.c_size_t), ('PeakJobMemoryUsed', C.c_size_t)]


class _ProcessIds(C.Structure):
    _fields_ = [('NumberOfAssignedProcesses', C.c_uint32),
        ('NumberOfProcessIdsInList', C.c_uint32), ('ProcessIdList', C.c_size_t * 1)]


class WindowsWorkerJob:
    """Retained owner; bootstrap retains this object BEFORE initialization.

    No destructor closes an unknown job. The OS closes this non-inherited handle
    on parent death; ordinary finalization requires the exact worker exit first.
    """
    _FLAGS = 0x2000 | 0x0008  # KILL_ON_JOB_CLOSE | ACTIVE_PROCESS (no breakaway).

    def __init__(self, process):
        _require(not getattr(self, '_initialization_attempted', False),
            'ntfs.worker_job_initialization_consumed')
        self._initialization_attempted = True
        self._owner = os.getpid(), threading.get_ident()
        self._process = process
        self._state, self._value, self.events = 'initializing', None, []
        self._witness = WindowsProcessWitness(process)
        _require(self._witness._popen and C.sizeof(C.c_void_p) == 8,
            'ntfs.owned_popen_handle_required')
        self._kernel = C.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateJobObjectW': ([C.c_void_p, C.c_wchar_p], C.c_void_p),
            'SetInformationJobObject': ([C.c_void_p, C.c_int, C.c_void_p, C.c_uint32], C.c_int32),
            'QueryInformationJobObject': ([C.c_void_p, C.c_int, C.c_void_p, C.c_uint32, C.c_void_p], C.c_int32),
            'AssignProcessToJobObject': ([C.c_void_p, C.c_void_p], C.c_int32),
            'IsProcessInJob': ([C.c_void_p, C.c_void_p, C.POINTER(C.c_int32)], C.c_int32),
            'GetHandleInformation': ([C.c_void_p, C.POINTER(C.c_uint32)], C.c_int32),
            'CloseHandle': ([C.c_void_p], C.c_int32),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self._kernel, name)
            function.argtypes, function.restype = arguments, result
        self._value = self._call('CreateJobObjectW', None, None)
        self._state = 'open'
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = self._FLAGS
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        self._call('SetInformationJobObject', self._value, 9, C.byref(limits), C.sizeof(limits))
        self._check_limits()
        self._call('AssignProcessToJobObject', self._value, self._witness.handle)
        self._state = 'bound'
        self.check_bound(process)

    def _owned(self, process):
        _require(self._owner == (os.getpid(), threading.get_ident())
            and process is self._process, 'ntfs.worker_job_owner_changed')
        self._witness._owned()  # Exact live creation-HANDLE owner, never a PID lookup.

    def _call(self, name, *arguments):
        self._owned(self._process)
        C.set_last_error(0)
        result = getattr(self._kernel, name)(*arguments)
        error = C.get_last_error()
        self.events.append({'api': name, 'result': result, 'winerror': error})
        if not result:
            raise PhaseError('ntfs.worker_job_api_failed', details={'api': name, 'winerror': error})
        return result

    def _check_limits(self):
        _require(self._state in {'open', 'bound'}, 'ntfs.worker_job_unavailable')
        flags = C.c_uint32()
        self._call('GetHandleInformation', self._value, C.byref(flags))
        _require(flags.value == 0, 'ntfs.worker_job_inherited_handle')
        limits = _ExtendedLimits()
        self._call('QueryInformationJobObject', self._value, 9, C.byref(limits), C.sizeof(limits), None)
        _require(limits.BasicLimitInformation.LimitFlags == self._FLAGS
            and limits.BasicLimitInformation.ActiveProcessLimit == 1,
            'ntfs.worker_job_limits_mismatch')

    def check_bound(self, process):
        self._owned(process)
        _require(self._state == 'bound', 'ntfs.worker_job_unavailable')
        self._check_limits()
        member = C.c_int32()
        self._call('IsProcessInJob', self._witness.handle, self._value, C.byref(member))
        _require(member.value == 1, 'ntfs.worker_job_membership_mismatch')
        members = _ProcessIds()
        self._call('QueryInformationJobObject', self._value, 3, C.byref(members), C.sizeof(members), None)
        _require(members.NumberOfAssignedProcesses == members.NumberOfProcessIdsInList == 1
            and members.ProcessIdList[0] == process.pid, 'ntfs.worker_job_membership_mismatch')

    def close_after_exit(self, process):
        self._owned(process)
        _require(self._state in {'open', 'bound'}, 'ntfs.worker_job_unavailable')
        fact = self._witness.wait_for_exit(0)
        _require(fact['worker_exit_established'] is True, 'ntfs.worker_exit_not_established')
        self._state = 'closing'  # A failed close is sticky and never retried.
        try:
            self._call('CloseHandle', self._value)
        except BaseException:
            self._state = 'unknown'
            raise
        self._value, self._state = None, 'closed'
