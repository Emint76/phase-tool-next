"""Exercise the real owned Linux framing with modeled clocks and pipe I/O."""
from types import SimpleNamespace
import time
from unittest.mock import Mock

import pytest

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.exchange_deadline import linux_exchange_scope
from .test_native_bundle2_prepared import CHANNEL, b2_projection, native_stage, prepared_ack, prepared_message
from . import test_native_input_stage_protocol as stage_models


SECOND = 1_000_000_000


def _clock(monkeypatch, now):
    clock = SimpleNamespace(ns=now)
    monkeypatch.setattr(time, 'monotonic_ns', lambda: clock.ns)
    monkeypatch.setattr(time, 'monotonic', lambda: clock.ns / SECOND)
    monkeypatch.setattr(time, 'perf_counter_ns', lambda: clock.ns)
    return clock


def test_input_stage_uses_one_deadline_across_frames(monkeypatch):
    clock = _clock(monkeypatch, SECOND)
    owner, pipe, restore = stage_models.FrameOwnerModels().model(b'00000001\na\n00000001\nb\n')
    try:
        absolute = 43 * SECOND
        owner._bind_qualification_exchange_deadline(absolute)
        with pytest.raises(PhaseError, match='input_stage.deadline'):
            owner._bind_qualification_exchange_deadline(absolute + SECOND)
        read = Mock(wraps=owner._read)
        monkeypatch.setattr(owner, '_read', read)
        assert owner.receive_frame(1) == b'a'
        assert [call.args[1] for call in read.call_args_list] == [31 * SECOND] * 3
        clock.ns = 33 * SECOND
        read.reset_mock()
        assert owner.receive_frame(1) == b'b'
        assert [call.args[1] for call in read.call_args_list] == [absolute] * 3
        clock.ns = absolute
        with pytest.raises(PhaseError, match='input_stage.deadline'):
            owner.send_frame(b'late')
        assert owner.failed and pipe.output == b'' and pipe.closed == []
    finally:
        restore()


def test_legacy_input_stage_bootstrap_has_no_extended_window(monkeypatch):
    clock = _clock(monkeypatch, SECOND)
    owner, pipe, restore = stage_models.FrameOwnerModels().model(b'')
    try:
        assert owner.deadline == 21 * SECOND
        clock.ns = owner.deadline
        with pytest.raises(PhaseError, match='input_stage.deadline'):
            owner.send_frame(b'legacy timeout')
        assert owner.failed and pipe.output == b'' and pipe.closed == []
    finally:
        restore()


@pytest.mark.parametrize('qualified', [False, True])
def test_file2_bulk_frame_window_uses_original_absolute_cutoff(monkeypatch, qualified):
    pytest.importorskip('fcntl')
    from phase_tool.mutation.ntfs import channel as base
    from phase_tool.mutation.ntfs.channel_v4 import LinuxNativeChannelV4

    clock = _clock(monkeypatch, SECOND)
    channel = object.__new__(LinuxNativeChannelV4)
    channel._identity = lambda fd: fd
    channel._ready = Mock()
    wire = Mock(side_effect=lambda _fd, body: len(body))
    monkeypatch.setattr(base, 'os', SimpleNamespace(write=wire))
    with linux_exchange_scope(55 * SECOND if qualified else None):
        deadline = channel._bulk_exchange_deadline()
        channel._send_frame(b'first', deadline)
        assert channel._ready.call_args.args == (1, True, 31)
        clock.ns = 34 * SECOND
        if qualified:
            channel._send_frame(b'second', deadline)
            assert channel._ready.call_args.args == (1, True, 55)
            channel._ready.side_effect = lambda *_: setattr(clock, 'ns', 55 * SECOND)
            with pytest.raises(PhaseError, match='ntfs.channel_deadline_expired'):
                channel._send_frame(b'readiness returned at the cutoff', deadline)
            assert wire.call_count == 2
        else:
            assert deadline == 31
            # The existing poll owner expires at the originally issued 30s.
            poller = Mock()
            monkeypatch.setattr(base, 'select', SimpleNamespace(poll=lambda: poller, POLLOUT=4))
            channel._ready = base.LinuxNativeChannel._ready
            with pytest.raises(PhaseError, match='ntfs.channel_deadline_expired'):
                channel._send_frame(b'legacy', deadline)
            poller.poll.assert_not_called()
            assert wire.call_count == 1


@pytest.mark.parametrize('checkpoint_late', [False, True])
def test_bundle2_preserves_terminal_without_late_positive(monkeypatch, checkpoint_late):
    pytest.importorskip('fcntl')
    from phase_tool.mutation.ntfs.bundle_recovery_channel import LinuxNativeBundleRecoveryChannel

    clock = _clock(monkeypatch, SECOND)
    channel = object.__new__(LinuxNativeBundleRecoveryChannel)
    channel.channel_id = CHANNEL
    projection = b2_projection()
    message = prepared_message(projection, CHANNEL, 123, native_stage(projection))
    ack = prepared_ack(message, 'sha256:' + '8' * 64, 'sha256:' + '9' * 64)
    channel._receive_bound = Mock(return_value={'bundle_stage': 'prepared', 'prepared': message})
    channel._write = Mock()
    response = {'completion': {}, 'owner_finalization': {'errors': []}}

    def persist(*_args, **_kwargs):
        clock.ns = 41 * SECOND if checkpoint_late else 35 * SECOND
        return ack

    def terminal(_common, end):
        assert end == (46 if checkpoint_late else 41) * SECOND
        clock.ns = 42 * SECOND
        return {'ok': True, 'error': None, 'value': response}

    channel._checkpoint = SimpleNamespace(persist=persist)
    channel._terminal_bound = terminal
    with linux_exchange_scope(41 * SECOND):
        clock.ns = 32 * SECOND
        deadline = channel._bulk_exchange_deadline()
        with pytest.raises(PhaseError, match='ntfs.channel_remote_failure') as failure:
            channel._bundle_terminal({}, deadline, projection=projection, expected_pid=123)
        assert failure.value.details['remote_error']['details']['parent_partial'] == response
        assert failure.value.details['remote_error']['details']['retry_authorized'] is False
    assert channel._failed and channel._terminal_value_bytes == canonical_bytes(response)
    assert channel._write.call_count == (0 if checkpoint_late else 1)
