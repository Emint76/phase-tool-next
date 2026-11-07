"""Synthetic framing/state regressions only; no Windows/NTFS qualification."""
import errno
import os
import threading
import time

import pytest

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames


def fake_boundary(monkeypatch):
    # Deliberately skip OS acquisition: all pipe identities and I/O below are
    # synthetic. Production construction/Win32 access needs the actual probe.
    frames=WindowsPipeFrames.__new__(WindowsPipeFrames)
    frames._initialization_attempted=True
    frames._failed=frames._sealed=False
    frames._owner=os.getpid(),threading.get_ident()
    frames._gate=threading.Lock()
    frames._identities=((190,290),(191,291))
    monkeypatch.setattr(frames,'_pipe',lambda side:frames._identities[side])
    return frames


def primary(error):return error.value.details['primary']['code']


def test_partial_write_keeps_exact_offset(monkeypatch):
    frames=fake_boundary(monkeypatch);sent=bytearray()
    def write(fd,raw):
        assert fd==191
        count=min(3,len(raw));sent.extend(raw[:count]);return count
    monkeypatch.setattr(os,'write',write)
    progress=frames.send_frame(b'abc\x00\r\n\x1a',time.perf_counter_ns()+1_000_000_000)
    assert bytes(sent)==b'00000007\nabc\x00\r\n\x1a\n'
    assert progress['wire_bytes']==len(sent)


def test_exact_needed_reads_do_not_consume_next_frame(monkeypatch):
    frames=fake_boundary(monkeypatch);wire=bytearray(b'00000003\nabc\n00000001\nz\n')
    def read(fd,count):
        assert fd==190 and count>0
        data=bytes(wire[:min(count,2)]);del wire[:len(data)];return data
    monkeypatch.setattr(os,'read',read)
    assert frames.receive_frame(time.perf_counter_ns()+1_000_000_000)[0]==b'abc'
    assert wire==b'00000001\nz\n'


@pytest.mark.parametrize('wire,code,count',[
    (b'00000000\n','ntfs.pipe_frame_limit',9),
    (b'00200001\n','ntfs.pipe_frame_limit',9),
    (b'0000000A\n','ntfs.pipe_invalid_header',9),
    (b'00000001\nx!','ntfs.pipe_invalid_terminator',11),
    (b'00000010\nabc','ntfs.pipe_eof',12),
])
def test_invalid_or_truncated_frame_is_terminal(monkeypatch,wire,code,count):
    frames=fake_boundary(monkeypatch);remaining=bytearray(wire);calls=[]
    def read(fd,n):
        calls.append(n);value=bytes(remaining[:n]);del remaining[:n];return value
    monkeypatch.setattr(os,'read',read)
    with pytest.raises(PhaseError) as error:frames.receive_frame(time.perf_counter_ns()+1_000_000_000)
    assert primary(error)==code and error.value.details['progress']['wire_bytes']==count
    before=list(calls)
    with pytest.raises(PhaseError) as again:frames.receive_frame(time.perf_counter_ns()+1_000_000_000)
    assert primary(again)=='ntfs.pipe_unavailable' and calls==before


def test_deadline_after_last_write_does_not_report_success(monkeypatch):
    frames=fake_boundary(monkeypatch);clock=[100]
    monkeypatch.setattr(time,'perf_counter_ns',lambda:clock[0])
    def write(fd,raw):clock[0]=1000;return len(raw)
    monkeypatch.setattr(os,'write',write)
    with pytest.raises(PhaseError) as error:frames.send_frame(b'x',1000)
    assert primary(error)=='ntfs.pipe_deadline_expired'
    assert error.value.details['progress']['wire_bytes']==11


def test_nested_call_during_identity_cannot_enter_before_gate(monkeypatch):
    frames=fake_boundary(monkeypatch);queries=[]
    def pipe(side):
        queries.append(side)
        with pytest.raises(PhaseError) as nested:frames.send_frame(b'x',time.perf_counter_ns()+1_000_000_000)
        assert primary(nested)=='ntfs.pipe_reentrant'
        return frames._identities[side]
    monkeypatch.setattr(frames,'_pipe',pipe)
    with pytest.raises(PhaseError) as error:frames.send_frame(b'x',time.perf_counter_ns()+1_000_000_000)
    assert primary(error)=='ntfs.pipe_unavailable' and queries==[0]
    assert not frames._gate.locked()


def test_nested_failure_during_final_write_is_sticky(monkeypatch):
    frames=fake_boundary(monkeypatch);writes=[]
    def write(fd,raw):
        writes.append(bytes(raw))
        with pytest.raises(PhaseError) as nested:frames.send_frame(b'z',time.perf_counter_ns()+1_000_000_000)
        assert primary(nested)=='ntfs.pipe_reentrant'
        return len(raw)
    monkeypatch.setattr(os,'write',write)
    with pytest.raises(PhaseError) as error:frames.send_frame(b'x',time.perf_counter_ns()+1_000_000_000)
    assert primary(error)=='ntfs.pipe_unavailable' and writes==[b'00000001\nx\n']
    assert error.value.details['progress']['wire_bytes']==11


def test_real_io_error_is_not_retried_as_would_block(monkeypatch):
    frames=fake_boundary(monkeypatch);writes=[]
    def write(fd,raw):writes.append(fd);raise OSError(errno.ENOSPC,'synthetic full')
    monkeypatch.setattr(os,'write',write)
    with pytest.raises(PhaseError) as error:frames.send_frame(b'x',time.perf_counter_ns()+1_000_000_000)
    assert error.value.details['primary']['errno']==errno.ENOSPC and writes==[191]


def test_reinit_does_not_clear_terminal_state(monkeypatch):
    frames=fake_boundary(monkeypatch);frames._failed=True;before=dict(frames.__dict__)
    with pytest.raises(PhaseError,match='ntfs.pipe_initialization_consumed'):frames.__init__(None,None)
    assert frames.__dict__==before


def test_seal_during_gate_release_prevents_success(monkeypatch):
    frames=fake_boundary(monkeypatch);real=frames._gate
    class ReleaseSignal:
        def acquire(self,blocking):return real.acquire(blocking=blocking)
        def locked(self):return real.locked()
        def release(self):
            real.release()
            frames.seal()  # Synthetic Python signal after the final I/O.
    frames._gate=ReleaseSignal()
    monkeypatch.setattr(os,'write',lambda fd,raw:len(raw))
    with pytest.raises(PhaseError) as error:frames.send_frame(b'x',time.perf_counter_ns()+1_000_000_000)
    assert primary(error)=='ntfs.pipe_unavailable'
    assert error.value.details['progress']['wire_bytes']==11 and not real.locked()
