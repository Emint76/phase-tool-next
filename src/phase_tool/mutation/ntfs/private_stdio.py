"""Endpoint custody for the exact Windows Popen owner. It never spawns a child."""

from __future__ import annotations

import io
import os

from ...errors import PhaseError
from .native import _require


_DATA_QUOTA = 4 * 1024**2
_PARENT = (1, 2, 4)
_CHILD = (0, 3, 5)


def _require_data_quota(handle):
    import ctypes as c

    query = c.WinDLL('kernel32', use_last_error=True).GetNamedPipeInfo
    pointer = c.POINTER(c.c_uint32)
    query.argtypes = (c.c_void_p, pointer, pointer, pointer, pointer)
    query.restype = c.c_int
    out_size, in_size = c.c_uint32(), c.c_uint32()
    if not query(handle, None, c.byref(out_size), c.byref(in_size), None):
        raise PhaseError('ntfs.private_pipe_quota_unavailable')
    _require(out_size.value == in_size.value == _DATA_QUOTA, 'ntfs.private_pipe_quota_mismatch')


def _private_stdio_failure(primary, secondary):
    if not secondary:
        return primary
    failures = ([primary] if primary is not None else []) + secondary
    if len(failures) == 1:
        return failures[0]
    return BaseExceptionGroup('Native private stdio setup and finalization', failures)


class _PrivateSizedStdio:
    """Retained before allocation. Raw, CRT and FileIO ownership are disjoint."""

    __slots__ = ('raw', 'fds', 'streams', 'failure')

    def __init__(self):
        self.raw = [None] * 6
        self.fds = [None] * 6
        self.streams = [None] * 6
        self.failure = None

    def prepare(self):
        import _winapi
        import msvcrt

        for offset, size in enumerate((_DATA_QUOTA, _DATA_QUOTA, 0)):
            read, write = _winapi.CreatePipe(None, size)
            valid = True
            for slot, handle in enumerate((read, write), 2 * offset):
                if type(handle) is int and handle > 0 and handle not in self.raw:
                    self.raw[slot] = handle
                else:
                    valid = False
            _require(valid, 'ntfs.private_pipe_handle_scope')
        _require(all(not os.get_handle_inheritable(handle) for handle in self.raw), 'ntfs.private_pipe_handle_scope')
        for slot in (0, 2):
            _require_data_quota(self.raw[slot])
        for slot, mode, access in zip(_PARENT, ('wb', 'rb', 'rb'),
                (os.O_WRONLY, os.O_RDONLY, os.O_RDONLY), strict=True):
            fd = msvcrt.open_osfhandle(self.raw[slot], os.O_BINARY | os.O_NOINHERIT | access)
            self.raw[slot] = None  # CRT owns the handle after successful adoption.
            self.fds[slot] = fd
            stream = io.FileIO(fd, mode, closefd=True)
            self.fds[slot] = None  # FileIO owns the supplied descriptor after success.
            self.streams[slot] = stream
            _require(not os.get_handle_inheritable(msvcrt.get_osfhandle(fd)), 'ntfs.private_pipe_handle_scope')
        return [self.raw[slot] for slot in _CHILD]

    def enable_child_inheritance(self):
        for slot in _CHILD:
            os.set_handle_inheritable(self.raw[slot], True)

    def close_child_copies(self):
        import _winapi

        failures = []
        for slot in _CHILD:
            handle = self.raw[slot]
            if handle is None:
                continue
            try:
                os.set_handle_inheritable(handle, False)
            except BaseException as error:
                failures.append(error)
            try:
                _winapi.CloseHandle(handle)
            except BaseException as error:
                failures.append(error)
            else:
                self.raw[slot] = None
        return failures

    def close_unattached_parent_streams(self):
        import _winapi

        failures = []
        for slot in _PARENT:
            try:
                if self.streams[slot] is not None:
                    self.streams[slot].close()
                    _require(self.streams[slot].closed, 'ntfs.private_pipe_close_unknown')
                    self.streams[slot] = None
                elif self.fds[slot] is not None:
                    os.close(self.fds[slot])
                    self.fds[slot] = None
                elif self.raw[slot] is not None:
                    _winapi.CloseHandle(self.raw[slot])
                    self.raw[slot] = None
            except BaseException as error:
                failures.append(error)
        return failures

    def attach(self, process):
        process.stdin, process.stdout, process.stderr = (self.streams[slot] for slot in _PARENT)
