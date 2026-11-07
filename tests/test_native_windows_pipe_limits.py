"""Synthetic receive-bound regressions, no Windows/NTFS I/O or admission."""
import os
import time

import pytest

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.windows_pipe import MAX_FRAME
from tests.test_native_windows_pipe import fake_boundary, primary


def test_go_limit_is_rejected_from_header_before_body_read(monkeypatch):
    frames=fake_boundary(monkeypatch);reads=[]
    def read(fd,count):reads.append(count);return b'00001001\n'
    monkeypatch.setattr(os,'read',read)
    with pytest.raises(PhaseError) as error:
        frames.receive_frame(time.perf_counter_ns()+1_000_000_000,maximum_bytes=4096)
    assert primary(error)=='ntfs.pipe_frame_limit'
    assert error.value.details['progress']['wire_bytes']==9 and reads==[9]
    with pytest.raises(PhaseError) as again:
        frames.receive_frame(time.perf_counter_ns()+1_000_000_000)
    assert primary(again)=='ntfs.pipe_unavailable' and reads==[9]


def test_exact_go_limit_and_trailer_are_accepted(monkeypatch):
    frames=fake_boundary(monkeypatch);wire=bytearray(b'00001000\n'+b'x'*4096+b'\n')
    def read(fd,count):
        value=bytes(wire[:count]);del wire[:count];return value
    monkeypatch.setattr(os,'read',read)
    value,progress=frames.receive_frame(time.perf_counter_ns()+1_000_000_000,maximum_bytes=4096)
    assert value==b'x'*4096 and progress['wire_bytes']==4106 and not wire


@pytest.mark.parametrize('maximum',[True,0,MAX_FRAME+1])
def test_invalid_or_increased_bound_is_rejected_before_pipe_query(monkeypatch,maximum):
    frames=fake_boundary(monkeypatch);queried=[]
    def pipe(side):queried.append(side);raise AssertionError('unexpected pipe query')
    monkeypatch.setattr(frames,'_pipe',pipe)
    with pytest.raises(PhaseError) as error:
        frames.receive_frame(time.perf_counter_ns()+1_000_000_000,maximum_bytes=maximum)
    assert primary(error)=='ntfs.pipe_frame_limit' and queried==[]
