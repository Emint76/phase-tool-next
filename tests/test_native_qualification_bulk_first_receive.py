"""Admitted Core waits share one deadline and keep bounded frame progress."""

import errno
import os
import threading
from types import SimpleNamespace

import pytest

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap, input_stage, parent, windows_pipe
from .test_native_qualification_inspection_deadline import clock, windows_pipe as pipe_fixture


SECOND = 10**9
CUTOFF = 901*SECOND


@pytest.mark.parametrize("qualified,first,body,wrong,expected", [
    (True, 62, None, False, None),
    (True, 62, 93, False, "ntfs.pipe_deadline_expired"),
    (True, 901, None, False, "ntfs.pipe_deadline_expired"),
    (True, 62, None, True, "ntfs.pipe_exchange_deadline_binding"),
    (False, 62, None, False, "ntfs.pipe_deadline_expired"),
])
def test_only_bound_bulk_first_byte_can_cross_frame_window(monkeypatch, clock, qualified, first, body, wrong, expected):
    pipe = pipe_fixture(monkeypatch)
    wire = bytearray(b"00000003\nabc\n")
    reached = []
    def read(fd, length):
        assert fd == 190
        reached.append(length)
        if len(reached) == 1:
            clock.ns = first*SECOND
        if body is not None and len(reached) == 3:
            clock.ns = body*SECOND
        result = bytes(wire[:length])
        del wire[:length]
        return result
    monkeypatch.setattr(os, "read", read)
    pipe._bind_qualification_exchange_deadline(CUTOFF)
    invoke = (lambda: pipe._receive_bulk_core_frame(CUTOFF-int(wrong))) if qualified else (
        lambda: pipe.receive_frame(31*SECOND))
    if expected is None:
        raw, progress = invoke()
        assert raw == b"abc" and progress["wire_bytes"] == 13 and reached == [1, 8, 3, 1]
        assert not pipe._failed
        return
    with pytest.raises(PhaseError, match="ntfs.pipe_frame_unknown") as failure:
        invoke()
    assert failure.value.__cause__.code == expected
    assert failure.value.details["effect_success_established"] is False
    assert failure.value.details["peer_exit_established"] is False and pipe._failed
    if wrong:
        assert reached == []
    before = reached[:]
    with pytest.raises(PhaseError):
        invoke()
    assert reached == before


def owner(monkeypatch, clock, *, admitted, inspection=False):
    instance = object.__new__(parent._NativeWindowsParent)
    instance._owner = os.getpid(), threading.get_ident()
    instance._failed = instance._finished = instance._bundle = False
    instance._inspection_only = inspection
    instance._file2 = True
    instance._launch = SimpleNamespace(check_runtime=lambda: None)
    monkeypatch.setattr(input_stage, "_qualification_bulk_deadline_ns", lambda launch: admitted)
    monkeypatch.setattr(parent, "_active_input_deadline_ns", lambda: CUTOFF)
    monkeypatch.setattr(parent, "_cap_input_deadline", lambda fallback: min(fallback, CUTOFF))
    monkeypatch.setattr(bootstrap, "_is_bundle_recovery_launch", lambda launch: False)
    return instance


@pytest.mark.parametrize("admitted,requested,inspection", [
    (None, CUTOFF, False), (CUTOFF, CUTOFF-1, False), (CUTOFF, CUTOFF, True), (CUTOFF, True, False),
])
def test_bulk_first_wait_requires_same_active_noninspection_deadline(monkeypatch, clock, admitted, requested, inspection):
    instance = owner(monkeypatch, clock, admitted=admitted, inspection=inspection)
    def forbidden(*args):
        raise AssertionError("rejected scope accessed the pipe")
    instance._pipe = SimpleNamespace(_receive_bulk_core_frame=forbidden, receive_frame=forbidden)
    with pytest.raises(PhaseError, match="ntfs.pipe_exchange_deadline_binding"):
        instance.serve(_bulk_core_deadline_ns=requested)
    assert instance._failed


@pytest.mark.parametrize("late_part,response_deadlines", [
    (False, [32*SECOND, 95*SECOND]),
    (True, [32*SECOND]),
])
def test_admitted_core_interframe_wait_reuses_absolute_deadline(
    monkeypatch, clock, late_part, response_deadlines,
):
    instance = owner(monkeypatch, clock, admitted=CUTOFF)
    pipe = pipe_fixture(monkeypatch)
    pipe._bind_qualification_exchange_deadline(CUTOFF)
    raw = canonical_bytes({"protocol": "phase.native.pipe", "version": "1.0", "kind": "observe_file"})
    frame = f"{len(raw):08x}\n".encode("ascii") + raw + b"\n"
    wire = bytearray(frame * 2)
    observed_response_deadlines = []

    def read(fd, length):
        assert fd == 190
        if not wire:
            clock.ns = CUTOFF
            raise BlockingIOError(errno.EAGAIN, "no next frame")
        if len(wire) == 2 * len(frame):
            clock.ns = 2*SECOND
        if len(wire) == len(frame):
            clock.ns = 65*SECOND
        if late_part and len(wire) == len(frame) - 1:
            clock.ns = 96*SECOND
            raise BlockingIOError(errno.EAGAIN, "incomplete next frame")
        data = bytes(wire[:length])
        del wire[:length]
        return data

    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(pipe, "send_frame",
        lambda raw, deadline: observed_response_deadlines.append(deadline))
    instance._pipe = pipe
    instance._request = lambda raw: ({}, {})
    with pytest.raises(PhaseError, match="ntfs.pipe_frame_unknown") as failure:
        instance.serve(_bulk_core_deadline_ns=CUTOFF)
    error = failure.value
    assert error.details["primary"]["code"] == "ntfs.pipe_deadline_expired"
    assert error.details["progress"]["wire_bytes"] == int(late_part)
    assert error._input_execute_pipe_boundary is windows_pipe._InputExecutePipeBoundary.LATER_RECEIVE
    assert instance._failed and pipe._failed
    assert observed_response_deadlines == response_deadlines


def test_ordinary_parent_keeps_default_frame_window(monkeypatch, clock):
    instance = owner(monkeypatch, clock, admitted=CUTOFF)
    events = []
    def stop(deadline):
        events.append(deadline)
        raise PhaseError("test.ordinary_frame")
    instance._pipe = SimpleNamespace(receive_frame=stop)
    with pytest.raises(PhaseError, match="test.ordinary_frame"):
        instance.serve()
    assert instance._failed and events == [31*SECOND]
