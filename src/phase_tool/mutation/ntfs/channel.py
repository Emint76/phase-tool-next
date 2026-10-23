"""Unselected Linux control channel; original Core evidence remains authoritative.

The isolated entrypoint exclusively owns inherited 0/1, already nonblocking
pipes. This component borrows them: no dup, close, flag changes, queue, retry or
new durable state. A logical seal never proves EOF or worker termination.
"""
from __future__ import annotations

import fcntl
import os
import re
import select
import stat
import sys
import threading
import time
from typing import Any

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from .native import NativeIdentity, _require


_MAX_FRAME = 2 * 1024**2  # Control metadata, never asset bytes.
_COMMON = {'protocol', 'version', 'channel_id', 'sequence', 'kind', 'run_id', 'intent_digest'}
_RESPONSE = _COMMON | {'ok', 'value', 'error'}
_RUN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def _primary(error: BaseException) -> dict:
    message = str(error)
    return {'type': type(error).__name__, 'code': getattr(error, 'code', None),
            'message': message[:4096], 'message_truncated': len(message) > 4096,
            'details': error.details if isinstance(error, PhaseError) else {}}


class NativeChannelError(PhaseError):
    def __init__(self, code: str, *, possible_dispatch: bool, details: dict | None = None):
        self.possible_dispatch = possible_dispatch
        super().__init__(code, details=details)


class LinuxNativeChannel:
    """Single owner, nonreentrant, once-only execution over borrowed stdio.

    Entrypoint policy forbids other readers/writers, stdout logging, fork,
    descriptor replacement or flag changes. Identity checks cannot distinguish
    every close/reopen of the same pipe and do not replace that trusted boundary.
    The 30 s deadline bounds waiting in this single-file control protocol; it
    neither cancels accepted OS work nor establishes a hard process deadline.
    """
    _PROTOCOL_VERSION = '1.0'  # Closed implementation generation; never request selected.

    def __init__(self, channel_id: str):
        _require(not getattr(self, '_initialization_attempted', False), 'ntfs.channel_initialization_consumed')
        self._initialization_attempted = True
        self._possible_dispatch = False
        self._failed = True
        self._sealed = False
        self._sequence = 0
        self._owner = (os.getpid(), threading.get_ident())
        self._gate = threading.Lock()
        self.channel_id = channel_id
        self._pipes: list[tuple[int, int, int]] = []
        try:
            _require(sys.platform.startswith('linux'), 'ntfs.linux_channel_required')
            _require(type(channel_id) is str and re.fullmatch(r'[0-9a-f]{32}', channel_id) is not None,
                     'ntfs.invalid_channel_id')
            for fd in (0, 1):
                self._pipes.append(self._pipe(fd))
            _require(self._pipes[0] != self._pipes[1], 'ntfs.distinct_channel_pipes_required')
            self._failed = False
        except BaseException as error:
            raise NativeChannelError('ntfs.channel_initialization_failed', possible_dispatch=False,
                                     details={'primary': _primary(error)}) from error

    @staticmethod
    def _pipe(fd: int) -> tuple[int, int, int]:
        facts = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        _require(stat.S_ISFIFO(facts.st_mode) and not os.isatty(fd), 'ntfs.pipe_stdio_required')
        _require(flags & os.O_ACCMODE == (os.O_RDONLY if fd == 0 else os.O_WRONLY),
                 'ntfs.channel_pipe_direction')
        _require(bool(flags & os.O_NONBLOCK), 'ntfs.channel_pipe_blocking')
        return facts.st_dev, facts.st_ino, stat.S_IFMT(facts.st_mode)

    @property
    def possible_dispatch(self) -> bool:
        return self._possible_dispatch

    def _usable(self) -> None:
        _require((os.getpid(), threading.get_ident()) == self._owner, 'ntfs.channel_owner_changed')
        _require(not self._failed and not self._sealed, 'ntfs.channel_unavailable')

    def _identity(self, fd: int) -> int:
        self._usable()
        _require(self._pipe(fd) == self._pipes[fd], 'ntfs.channel_descriptor_changed')
        return fd

    @staticmethod
    def _ready(fd: int, writing: bool, deadline: float) -> None:
        poll = select.poll()
        poll.register(fd, select.POLLOUT if writing else select.POLLIN)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise PhaseError('ntfs.channel_deadline_expired')
            if poll.poll(min(100, max(1, int(left * 1000)))):
                return

    def _write(self, data: bytes, deadline: float) -> None:
        offset = 0
        while offset < len(data):
            self._ready(self._identity(1), True, deadline)
            try:
                # Recheck after polling, immediately before the actual syscall.
                count = os.write(self._identity(1), data[offset:offset + 65536])
            except BlockingIOError:
                continue
            _require(count > 0, 'ntfs.channel_write_no_progress')
            offset += count

    def _read(self, count: int, deadline: float) -> bytes:
        _require(type(count) is int and 0 <= count <= _MAX_FRAME, 'ntfs.channel_frame_limit')
        value = bytearray()
        while len(value) < count:
            self._ready(self._identity(0), False, deadline)
            try:
                data = os.read(self._identity(0), min(65536, count - len(value)))
            except BlockingIOError:
                continue
            _require(bool(data), 'ntfs.channel_eof_unknown')
            value.extend(data)
        return bytes(value)

    @staticmethod
    def _request(kind: str, run_id: str, intent_digest: str | None, payload: dict) -> dict:
        _require(kind in {'observe_file', 'execute_file_create'}, 'ntfs.channel_operation_forbidden')
        _require(type(run_id) is str and _RUN.fullmatch(run_id) is not None, 'evidence.invalid_run_id')
        _require(type(payload) is dict, 'ntfs.channel_request_shape')
        if kind == 'execute_file_create':
            _require(type(intent_digest) is str and _DIGEST.fullmatch(intent_digest) is not None
                     and not payload, 'ntfs.invalid_intent_reference')
        else:
            _require(intent_digest is None and set(payload) == {'root_binding', 'locator', 'expected_identity'},
                     'ntfs.channel_request_shape')
            _require(type(payload['root_binding']) is str and re.fullmatch(
                r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', payload['root_binding']) is not None,
                'ntfs.invalid_root_binding')
            safe_relative_locator(payload['locator'])
            if payload['expected_identity'] is not None:
                NativeIdentity.parse(payload['expected_identity'])
        return payload

    def _exchange(self, kind: str, run_id: str, intent_digest: str | None, payload: dict[str, Any]) -> dict:
        acquired = False
        raw = None
        primary = None
        value = None
        try:
            self._usable()
            _require(self._gate.acquire(blocking=False), 'ntfs.channel_reentrant_call')
            acquired = True
            self._usable()
            self._request(kind, run_id, intent_digest, payload)
            _require(kind != 'execute_file_create' or not self._possible_dispatch, 'ntfs.channel_execution_consumed')
            common = {'protocol': 'phase.native.pipe', 'version': self._PROTOCOL_VERSION, 'channel_id': self.channel_id,
                      'sequence': self._sequence + 1, 'kind': kind, 'run_id': run_id, 'intent_digest': intent_digest}
            raw = canonical_bytes(common | payload)
            _require(0 < len(raw) <= _MAX_FRAME, 'ntfs.channel_frame_limit')
            deadline = time.monotonic() + 30.0
            self._sequence += 1
            # Conservative and sticky, before any possible mutating frame write.
            if kind == 'execute_file_create':
                self._possible_dispatch = True
            self._write(f'{len(raw):08x}\n'.encode('ascii') + raw + b'\n', deadline)
            header = self._read(9, deadline)
            _require(re.fullmatch(b'[0-9a-f]{8}\n', header) is not None, 'ntfs.channel_bad_header')
            length = int(header[:8], 16)
            _require(0 < length <= _MAX_FRAME, 'ntfs.channel_frame_limit')
            response_raw = self._read(length, deadline)
            _require(self._read(1, deadline) == b'\n', 'ntfs.channel_bad_terminator')
            response = parse_json_bytes(response_raw, maximum_bytes=_MAX_FRAME)
            _require(type(response) is dict and set(response) == _RESPONSE
                     and canonical_bytes(response) == response_raw, 'ntfs.channel_noncanonical_response')
            _require(type(response['sequence']) is int and type(response['ok']) is bool,
                     'ntfs.channel_response_shape')
            _require({key: response[key] for key in _COMMON} == common, 'ntfs.channel_response_binding_mismatch')
            if not response['ok']:
                remote = response['error']
                _require(response['value'] is None and type(remote) is dict
                         and set(remote) == {'code', 'message', 'details'} and type(remote['code']) is str
                         and type(remote['message']) is str and type(remote['details']) is dict,
                         'ntfs.channel_response_shape')
                raise PhaseError('ntfs.channel_remote_failure', details={'remote_error': remote})
            _require(response['error'] is None and type(response['value']) is dict, 'ntfs.channel_response_shape')
            self._usable()
            # This is an ACK, not a validated effect/proof or process-exit fact.
            value = response['value']
        except BaseException as error:
            self._failed = True
            primary = error
        finally:
            if acquired:
                try:
                    self._gate.release()
                except BaseException as finalization:
                    self._failed = True
                    raise NativeChannelError('ntfs.channel_gate_finalization_unknown',
                        possible_dispatch=self._possible_dispatch,
                        details={'primary': None if primary is None else _primary(primary),
                                 'finalization': _primary(finalization)}) from primary
        if primary is None:
            try:
                # A real release/signal callback may have sealed or poisoned the
                # channel after the in-gate check. Never return a positive ACK
                # over newly failed owner/sticky state; no wire retry is allowed.
                self._usable()
            except BaseException as error:
                self._failed = True
                primary = error
        if primary is not None:
            raise NativeChannelError('ntfs.channel_exchange_unknown', possible_dispatch=self._possible_dispatch,
                details={'request_digest': None if raw is None else digest_bytes(raw), 'sequence': self._sequence,
                         'primary': _primary(primary)}) from primary
        return value

    def observe_file(self, *, run_id: str, root_binding: str, locator: str,
                     expected_identity: dict | None = None) -> dict:
        return self._exchange('observe_file', run_id, None, {'root_binding': root_binding, 'locator': locator,
                              'expected_identity': expected_identity})

    def execute_file_create(self, *, run_id: str, intent_digest: str) -> dict:
        return self._exchange('execute_file_create', run_id, intent_digest, {})

    def seal(self) -> None:
        # Monotonic revocation only. No FD close, cancellation or EOF promise.
        was_sealed = self._sealed
        self._sealed = True
        try:
            _require(not was_sealed, 'ntfs.channel_already_sealed')
            _require((os.getpid(), threading.get_ident()) == self._owner, 'ntfs.channel_owner_changed')
            _require(not self._gate.locked(), 'ntfs.channel_exchange_active')
        except BaseException as error:
            self._failed = True
            raise NativeChannelError('ntfs.channel_seal_unknown', possible_dispatch=self._possible_dispatch,
                                     details={'primary': _primary(error)}) from error
