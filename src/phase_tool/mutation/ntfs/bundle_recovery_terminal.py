"""Once-only terminal framing on the same owned pipes; never heals poison.

Only fixed B2 successor code calls these after its effect/GO paths are closed.
No channel usable flag is cleared. Partial framing is retained and not retried.
"""
from __future__ import annotations
import base64
import errno
import os
import re
import threading
import time

from ...errors import PhaseError
from .native import _require
from .uncertainty import _diagnostic


def _frame_io(owner, *, sending, raw, deadline_ns, maximum_bytes, windows):
    captured = bytearray()
    progress = {'wire_bytes': 0, 'complete': False, 'direction': 'send' if sending else 'receive'}
    _require(owner._owner == (os.getpid(), threading.get_ident()) and not owner._sealed,
             'ntfs.terminal_owner_changed')
    if windows and owner._failed:
        prior = getattr(owner, '_last_frame_failure', None)
        _require(type(prior) is dict and prior.get('direction') in {'send','receive'}
                 and type(prior.get('progress')) is dict, 'ntfs.terminal_boundary_unknown')
        if prior['direction'] == ('send' if sending else 'receive'):
            progress_before = prior['progress']
            count = progress_before.get('wire_bytes')
            _require(type(count) is int and (count == 0 or
                (sending and count == progress_before.get('expected_wire_bytes'))),
                'ntfs.terminal_boundary_unknown')
    if not windows:
        _require(getattr(owner, '_terminal_read_boundary', False) is True,
                 'ntfs.terminal_boundary_unknown')
    _require(type(deadline_ns) is int and 0 < deadline_ns-time.perf_counter_ns() <= 105_000_000_000
             and type(maximum_bytes) is int and 0 < maximum_bytes <= 2*1024**2,
             'ntfs.terminal_bound')
    slot = '_terminal_send_attempted' if sending else '_terminal_read_attempted'
    _require(not getattr(owner, slot, False), 'ntfs.terminal_attempt_consumed')
    setattr(owner, slot, True)
    # A previously poisoned endpoint stays poisoned. A healthy, complete
    # terminal response may still be followed by the existing read-only role.

    def descriptor(side):
        _require(owner._owner == (os.getpid(), threading.get_ident()) and not owner._sealed,
                 'ntfs.terminal_owner_changed')
        if windows:
            value = owner._pipe(side)
            _require(value == owner._identities[side], 'ntfs.pipe_identity_changed')
            return value[0]
        _require(owner._pipe(side) == owner._pipes[side], 'ntfs.channel_descriptor_changed')
        return side

    def remaining():
        _require(time.perf_counter_ns() < deadline_ns, 'ntfs.terminal_deadline_expired')
        descriptor(0); descriptor(1)

    def read_exact(count):
        value = bytearray()
        while len(value) < count:
            remaining()
            try:
                chunk = os.read(descriptor(0), min(65536, count-len(value)))
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK): raise
                time.sleep(0.001)
                continue
            _require(type(chunk) is bytes and chunk, 'ntfs.terminal_eof_unknown')
            value.extend(chunk); captured.extend(chunk); progress['wire_bytes'] += len(chunk)
            remaining()
        return bytes(value)

    try:
        remaining()
        if sending:
            _require(type(raw) is bytes and 0 < len(raw) <= maximum_bytes, 'ntfs.terminal_frame_limit')
            framed = f'{len(raw):08x}\n'.encode()+raw+b'\n'
            while progress['wire_bytes'] < len(framed):
                remaining()
                try:
                    count = os.write(descriptor(1), framed[progress['wire_bytes']:progress['wire_bytes']+65536])
                except OSError as error:
                    if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK): raise
                    time.sleep(0.001)
                    continue
                _require(type(count) is int and count > 0, 'ntfs.terminal_write_no_progress')
                captured.extend(framed[progress['wire_bytes']:progress['wire_bytes']+count])
                progress['wire_bytes'] += count
                remaining()
            answer = None
        else:
            header = read_exact(9)
            _require(re.fullmatch(rb'[0-9a-f]{8}\n', header) is not None, 'ntfs.terminal_header_unknown')
            length = int(header[:8], 16)
            _require(0 < length <= maximum_bytes, 'ntfs.terminal_frame_limit')
            answer = read_exact(length)
            _require(read_exact(1) == b'\n', 'ntfs.terminal_terminator_unknown')
        remaining(); progress['complete'] = True
        return answer, progress
    except BaseException as error:
        owner._failed = True
        raise PhaseError('ntfs.terminal_frame_unknown', details={
            'primary': _diagnostic(error), 'progress': progress,
            'wire_prefix_base64': base64.b64encode(captured).decode(),
            'effect_success_established': False, 'peer_exit_established': False}) from error


def windows_terminal(pipe, *, sending, raw=None, deadline_ns, maximum_bytes=512*1024):
    from .windows_pipe import WindowsPipeFrames
    _require(type(pipe) is WindowsPipeFrames, 'ntfs.windows_worker_pipe_required')
    acquired = pipe._gate.acquire(blocking=False)
    _require(acquired, 'ntfs.pipe_reentrant')
    try:
        return _frame_io(pipe, sending=sending, raw=raw, deadline_ns=deadline_ns,
                         maximum_bytes=maximum_bytes, windows=True)
    finally:
        pipe._gate.release()


def linux_terminal(channel, *, deadline_ns, maximum_bytes=2*1024**2):
    from .bundle_recovery_channel import LinuxNativeBundleRecoveryChannel
    _require(type(channel) is LinuxNativeBundleRecoveryChannel and channel._gate.locked(),
             'ntfs.closed_terminal_exchange_required')
    return _frame_io(channel, sending=False, raw=None, deadline_ns=deadline_ns,
                     maximum_bytes=maximum_bytes, windows=False)
