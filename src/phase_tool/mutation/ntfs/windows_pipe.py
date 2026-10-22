"""Unselected borrowed Windows byte-pipe framing, without lifecycle authority.

The trusted entrypoint owns exact binary FileIO streams and sets PIPE_NOWAIT
before construction. It forbids concurrent I/O, close/reuse, buffering and mode
changes. Identity queries cannot defeat a hostile owner reusing the same handle.
This helper never spawns, closes, changes flags, retries an operation or writes
durable state. Its deadline bounds protocol waiting, not OS-call execution.
"""
from __future__ import annotations

import errno
import io
import os
import re
import stat
import sys
import threading
import time

from ...errors import PhaseError
from .native import _require


MAX_FRAME = 2 * 1024**2  # Control metadata, not an asset-size contract.


def _error(error: BaseException) -> dict:
    return {'type': type(error).__name__, 'code': getattr(error, 'code', None),
            'errno': getattr(error, 'errno', None), 'winerror': getattr(error, 'winerror', None),
            'message': str(error)[:2048]}


class WindowsPipeFrames:
    """One owner/thread, exact-needed reads, terminal errors never resynchronise.

    The dispatcher must mark possible_dispatch BEFORE writing any GO byte.
    Neither a complete frame, EOF, seal nor peer exit proves effect success.
    The owner supplies one absolute perf_counter_ns deadline for the exchange;
    each frame call accepts at most 30 seconds of remaining protocol time.
    """

    def __init__(self, reader: io.FileIO, writer: io.FileIO):
        _require(not getattr(self, '_initialization_attempted', False), 'ntfs.pipe_initialization_consumed')
        self._initialization_attempted = True
        self._failed = True
        self._sealed = False
        self._owner = os.getpid(), threading.get_ident()
        self._gate = threading.Lock()
        self._streams = reader, writer  # Strong refs; lifetime remains owner's duty.
        _require(sys.platform == 'win32' and sys.implementation.name == 'cpython'
                 and sys.version_info[:3] == (3, 12, 10), 'ntfs.windows_cpython31210_pipe_required')
        import ctypes
        import msvcrt
        self._ctypes, self._msvcrt = ctypes, msvcrt
        self._api = ctypes.WinDLL('kernel32', use_last_error=True)
        self._api.GetFileType.argtypes = [ctypes.c_void_p]
        self._api.GetFileType.restype = ctypes.c_uint32
        self._api.GetNamedPipeHandleStateW.argtypes = [ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        self._api.GetNamedPipeHandleStateW.restype = ctypes.c_int
        self._api.GetNamedPipeInfo.argtypes = [ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self._api.GetNamedPipeInfo.restype = ctypes.c_int
        self._identities = self._pipe(0), self._pipe(1)
        _require(self._identities[0][0] != self._identities[1][0]
                 and self._identities[0][1] != self._identities[1][1], 'ntfs.distinct_pipes_required')
        self._failed = False

    def _pipe(self, side: int) -> tuple:
        stream = self._streams[side]
        _require(type(stream) is io.FileIO and not stream.closed, 'ntfs.exact_open_fileio_required')
        _require(stream.readable() is (side == 0) and stream.writable() is (side == 1),
                 'ntfs.pipe_direction')
        fd = stream.fileno()
        facts = os.fstat(fd)
        handle = self._msvcrt.get_osfhandle(fd)
        _require(handle != -1 and stat.S_ISFIFO(facts.st_mode) and not os.isatty(fd), 'ntfs.pipe_required')
        _require(self._api.GetFileType(handle) == 3, 'ntfs.windows_pipe_type_required')
        state, flags = self._ctypes.c_uint32(), self._ctypes.c_uint32()
        if not self._api.GetNamedPipeHandleStateW(handle, self._ctypes.byref(state), None, None, None, None, 0):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        if not self._api.GetNamedPipeInfo(handle, self._ctypes.byref(flags), None, None, None):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        _require(state.value == 1 and not flags.value & 4 and os.get_blocking(fd) is False,
                 'ntfs.nonblocking_byte_pipe_required')
        return fd, handle, facts.st_dev, facts.st_ino, stat.S_IFMT(facts.st_mode), state.value, flags.value

    def _usable(self) -> None:
        _require(self._owner == (os.getpid(), threading.get_ident()), 'ntfs.pipe_owner_changed')
        _require(not self._failed and not self._sealed, 'ntfs.pipe_unavailable')

    def _identity(self, side: int) -> int:
        self._usable()
        actual = self._pipe(side)
        self._usable()
        _require(actual == self._identities[side], 'ntfs.pipe_identity_changed')
        return actual[0]

    @staticmethod
    def _time(deadline_ns: int) -> int:
        left = deadline_ns - time.perf_counter_ns()
        _require(left > 0, 'ntfs.pipe_deadline_expired')
        return left

    def _pause(self, deadline_ns: int) -> None:
        time.sleep(min(0.005, self._time(deadline_ns) / 1_000_000_000))
        self._usable()
        self._time(deadline_ns)

    def _write(self, data: bytes, deadline_ns: int, progress: dict) -> None:
        offset = 0
        while offset < len(data):
            self._time(deadline_ns)
            fd = self._identity(1)
            self._time(deadline_ns)
            try:
                count = os.write(fd, data[offset:offset + 65536])
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                progress['would_block'] += 1
                self._time(deadline_ns)
                self._pause(deadline_ns)
                continue
            _require(type(count) is int and 0 <= count <= min(65536, len(data) - offset),
                     'ntfs.pipe_invalid_write_count')
            progress['wire_bytes'] += count
            offset += count
            self._usable()
            self._time(deadline_ns)  # Including the final byte.
            if count == 0:
                progress['zero_writes'] += 1
                self._pause(deadline_ns)

    def _read(self, count: int, deadline_ns: int, progress: dict) -> bytes:
        value = bytearray()
        while len(value) < count:
            self._time(deadline_ns)
            fd = self._identity(0)
            self._time(deadline_ns)
            try:
                data = os.read(fd, min(65536, count - len(value)))
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                progress['would_block'] += 1
                self._time(deadline_ns)
                self._pause(deadline_ns)
                continue
            progress['wire_bytes'] += len(data)
            if len(bytes.fromhex(progress['prefix_hex'])) < 9:
                prefix = bytes.fromhex(progress['prefix_hex'])
                progress['prefix_hex'] = (prefix + data[:9 - len(prefix)]).hex()
            value.extend(data)
            self._usable()
            self._time(deadline_ns)
            _require(bool(data), 'ntfs.pipe_eof')
        return bytes(value)

    def _frame(self, sending: bool, raw: bytes | None, deadline_ns: int):
        progress = {'wire_bytes': 0, 'would_block': 0, 'zero_writes': 0, 'prefix_hex': ''}
        acquired, primary, answer = False, None, None
        try:
            acquired = self._gate.acquire(blocking=False)
            _require(acquired, 'ntfs.pipe_reentrant')
            _require(type(deadline_ns) is int and 0 < self._time(deadline_ns) <= 30_000_000_000,
                     'ntfs.pipe_invalid_deadline')
            self._identity(0)
            self._identity(1)
            if sending:
                _require(type(raw) is bytes and 1 <= len(raw) <= MAX_FRAME, 'ntfs.pipe_frame_limit')
                self._write(f'{len(raw):08x}\n'.encode('ascii') + raw + b'\n', deadline_ns, progress)
                answer = dict(progress)
            else:
                header = self._read(9, deadline_ns, progress)
                _require(re.fullmatch(rb'[0-9a-f]{8}\n', header) is not None, 'ntfs.pipe_invalid_header')
                length = int(header[:8], 16)
                _require(1 <= length <= MAX_FRAME, 'ntfs.pipe_frame_limit')
                value = self._read(length, deadline_ns, progress)
                _require(self._read(1, deadline_ns, progress) == b'\n', 'ntfs.pipe_invalid_terminator')
                answer = value, dict(progress)
            self._usable()
            self._time(deadline_ns)
        except BaseException as error:
            self._failed, primary = True, error
        finally:
            if acquired:
                try:
                    self._gate.release()
                except BaseException as finalization:
                    self._failed = True
                    raise PhaseError('ntfs.pipe_finalization_unknown', details={
                        'primary': None if primary is None else _error(primary),
                        'finalization': _error(finalization), 'progress': progress}) from primary
        if primary is None:
            try:
                self._usable()
                self._time(deadline_ns)
            except BaseException as error:
                self._failed, primary = True, error
        if primary is not None:
            raise PhaseError('ntfs.pipe_frame_unknown', details={'primary': _error(primary),
                'progress': progress, 'direction': 'send' if sending else 'receive',
                'effect_success_established': False, 'peer_exit_established': False}) from primary
        return answer

    def send_frame(self, raw: bytes, deadline_ns: int) -> dict:
        return self._frame(True, raw, deadline_ns)

    def receive_frame(self, deadline_ns: int) -> tuple[bytes, dict]:
        return self._frame(False, None, deadline_ns)

    def seal(self) -> None:
        was_sealed = self._sealed
        self._sealed = True
        _require(not was_sealed and not self._gate.locked()
                 and self._owner == (os.getpid(), threading.get_ident()), 'ntfs.pipe_seal_unknown')
