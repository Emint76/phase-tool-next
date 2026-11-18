"""Exercise the fixed read-only deadline with modeled peer progress."""
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import exchange_deadline, input_stage, owner_directory_launch
from phase_tool.mutation.ntfs.inspection_mcp import _InspectionMCPCallOwner
from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames


SECOND = 1_000_000_000
CUTOFF = 901 * SECOND


@pytest.fixture
def clock(monkeypatch):
    stamp = SimpleNamespace(ns=SECOND)
    monkeypatch.setattr(time, 'perf_counter_ns', lambda: stamp.ns)
    monkeypatch.setattr(time, 'monotonic_ns', lambda: stamp.ns)
    monkeypatch.setattr(time, 'monotonic', lambda: stamp.ns / SECOND)
    return stamp


def windows_pipe(monkeypatch):
    pipe = object.__new__(WindowsPipeFrames)
    pipe._initialization_attempted = True
    pipe._failed = pipe._sealed = False
    pipe._qualification_exchange_deadline_ns = None
    pipe._owner = os.getpid(), threading.get_ident()
    pipe._gate = threading.Lock()
    pipe._identities = ((190, 290), (191, 291))
    monkeypatch.setattr(pipe, '_pipe', lambda side: pipe._identities[side])
    return pipe


@pytest.mark.parametrize('qualified, late_body', [(False, False), (True, False), (True, True)])
def test_windows_pipe_separates_cold_wait_from_partial_frame(monkeypatch, clock, qualified, late_body):
    pipe = windows_pipe(monkeypatch)
    wire = bytearray(b'00000003\nabc\n')
    reached = []

    def read(fd, size):
        assert fd == 190
        reached.append(size)
        if len(reached) == 1:
            clock.ns = 62 * SECOND
        if late_body and len(reached) == 2:
            clock.ns = 93 * SECOND
        result = bytes(wire[:size])
        del wire[:size]
        return result

    monkeypatch.setattr(os, 'read', read)
    if qualified:
        pipe._bind_qualification_exchange_deadline(CUTOFF)
        received = lambda: pipe._receive_inspection_frame(CUTOFF)
    else:
        received = lambda: pipe.receive_frame(31 * SECOND)
    if qualified and not late_body:
        raw, progress = received()
        assert raw == b'abc' and progress['wire_bytes'] == 13 and reached == [1, 8, 3, 1]
        return
    with pytest.raises(PhaseError, match='ntfs.pipe_frame_unknown') as failure:
        received()
    assert failure.value.details['primary']['code'] == 'ntfs.pipe_deadline_expired'
    assert failure.value.details['peer_exit_established'] is False
    assert failure.value.details['effect_success_established'] is False
    assert pipe._failed
    assert reached == ([1, 8] if qualified else [9])
    with pytest.raises(PhaseError):
        received()
    assert reached == ([1, 8] if qualified else [9])


@pytest.mark.parametrize('operation, accepted', [
    ({'operation': 'inspect'}, 900),
    ({'operation': 'inspect', 'receipt': 'extra'}, 900),
    ({'operation': 'recover_publication'}, 900),
    ({'operation': 'inspect'}, None),
], ids=['public-inspect', 'extra-field', 'recovery', 'unqualified'])
def test_linux_inspection_deadline_handshake_is_role_and_request_bound(monkeypatch, clock, operation, accepted):
    startup = {'config_bytes': b'fixed configuration'}
    seen = []

    def check(**actual):
        assert actual == startup
        return accepted

    monkeypatch.setattr(owner_directory_launch, '_accepted_cold_publication_seconds', check)
    invocation = {'run_id': 'inspect-run', 'channel_id': 'a'*32, 'operation_nonce': 'b'*32, 'request': operation}
    field = 'qualification_exchange_deadline_version'
    offer = {field: '1.0', 'role': 'inspect', 'invocation': invocation}

    def ready(raw):
        seen.append(parse_json_bytes(raw))

    def answer(maximum):
        assert maximum == 4096
        clock.ns += 2 * SECOND
        return canonical_bytes(seen[-1] | {'remaining_ns': 810 * SECOND})

    entry = lambda: exchange_deadline.receive_linux_invocation(offer, role='inspect', startup=startup,
        send_frame=ready, receive_frame=answer)
    if operation == {'operation': 'inspect'} and accepted == 900:
        actual, cutoff = entry()
        assert actual == invocation and cutoff == 811 * SECOND
        assert seen == [{field: '1.0', 'role': 'inspect', 'anchor_ns': SECOND,
                         'invocation_digest': digest_bytes(canonical_bytes(invocation))}]
    else:
        with pytest.raises(PhaseError, match='ntfs.linux_exchange_deadline_binding'):
            entry()
        assert seen == []


@pytest.mark.parametrize('mode', ['qualified', 'unqualified', 'embedded', 'expired'])
def test_mcp_only_standalone_uses_clock_at_caller_entry(monkeypatch, clock, mode):
    owner = object.__new__(_InspectionMCPCallOwner)
    owner._gate = threading.Lock()
    owner._unavailable = False
    owner._startup = {'config_bytes': b'fixed configuration'}
    monkeypatch.setattr(input_stage, 'os', SimpleNamespace(name='nt', getpid=os.getpid))
    mock_policy = Mock(side_effect=lambda **_: setattr(clock, 'ns', 62 * SECOND) or
        (None if mode == 'unqualified' else 900))
    monkeypatch.setattr(owner_directory_launch, '_accepted_cold_publication_seconds', mock_policy)

    def locked(run_id, request, **options):
        assert run_id == 'inspect-run' and request == {'operation': 'inspect'}
        qualified = mode in {'qualified', 'expired'}
        assert options.get('_qualification_inspection') is (True if qualified else None)
        assert input_stage._active_input_deadline_ns() == (CUTOFF if qualified else None)
        if mode == 'expired':
            clock.ns = CUTOFF
        return {'observed': True}

    owner._call_locked = locked
    if mode == 'embedded':
        assert owner._call('inspect-run', {'operation': 'inspect'}, inspection_only=True) == {'observed': True}
        mock_policy.assert_not_called()
    elif mode == 'expired':
        with pytest.raises(PhaseError, match='input_stage.deadline'):
            owner.inspect('inspect-run')
        assert owner._unavailable
    else:
        assert owner.inspect('inspect-run') == {'observed': True}
    assert input_stage._active_input_deadline_ns() is None


@pytest.mark.parametrize('mode', ['qualified', 'legacy', 'late_body'])
def test_linux_observation_has_long_wait_and_bounded_frame(monkeypatch, clock, mode):
    pytest.importorskip('fcntl')
    from phase_tool.mutation.ntfs import channel as source

    channel = object.__new__(source.LinuxNativeChannel)
    channel._owner = os.getpid(), threading.get_ident()
    channel._failed = channel._sealed = channel._possible_dispatch = False
    channel._gate = threading.Lock()
    channel._sequence = 0
    channel._inspection_only = True
    channel.channel_id = 'c'*32
    reads = []
    wire = bytearray()
    channel._identity = lambda fd: fd

    def write(fd, data):
        assert fd == 1
        request = parse_json_bytes(data[9:-1])
        assert request['kind'] == 'observe_file' and request['locator'] == 'file.bin'
        result = {key: request[key] for key in source._COMMON}
        body = canonical_bytes(result | {'ok': True, 'value': {'matches': True}, 'error': None})
        wire.extend(f'{len(body):08x}\n'.encode() + body + b'\n')
        return len(data)

    def ready(fd, writing, deadline):
        if writing:
            assert deadline == 31
            return
        reads.append(deadline)
        if len(reads) == 1:
            clock.ns = 62 * SECOND
        if mode == 'late_body' and len(reads) == 2:
            clock.ns = 93 * SECOND
        if time.monotonic() >= deadline:
            raise PhaseError('ntfs.channel_deadline_expired')

    def read(fd, size):
        assert fd == 0
        answer = bytes(wire[:size])
        del wire[:size]
        return answer

    monkeypatch.setattr(source, 'os', SimpleNamespace(read=read, write=write, getpid=os.getpid))
    channel._ready = ready
    request = dict(run_id='inspect-run', root_binding='approved', locator='file.bin')
    with exchange_deadline.linux_exchange_scope(None if mode == 'legacy' else CUTOFF):
        if mode == 'qualified':
            assert channel.observe_file(**request) == {'matches': True}
            assert reads == [901, 92, 92, 92]
        else:
            with pytest.raises(source.NativeChannelError) as failure:
                channel.observe_file(**request)
            assert failure.value.details['primary']['code'] == 'ntfs.channel_deadline_expired'
            assert failure.value.possible_dispatch is False
            assert channel._failed and reads == ([31] if mode == 'legacy' else [901, 92])
