"""Clock-domain and admission regressions for the fixed Linux launch handoff."""

import base64

import pytest

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import exchange_deadline as handoff
from phase_tool.mutation.ntfs import owner_directory_installation, owner_directory_launch

from .owner_directory_test_data import owner_document, synthetic_catalog


NS = 10**9
LINK = 'sha256:' + 'a'*64


def invocation(request):
    return {'run_id': 'time-fixture', 'channel_id': '1'*32, 'operation_nonce': '2'*32, 'request': request}


def offer(value, role='core'):
    return {handoff._FIELD: '1.0', 'role': role, 'invocation': value}


def file_request():
    return {'operation': 'execute', 'native_staged_publication_request_version': '1.0',
        'input_scope': 'approved-fixture', 'stage_header_digest': LINK,
        'source_locator': 'phase-native-input-'+'a'*32+'/payload/payload', 'source_digest': LINK,
        'source_length': 2**31, 'target_locator': 'file.bin', 'request_id': 'target',
        'members': None, 'expected_current_digest': None, 'content_utf8': None}


@pytest.fixture
def startup(monkeypatch):
    catalog = synthetic_catalog().check()
    monkeypatch.setattr(owner_directory_installation, '_fixed_owner_directory_catalog', lambda: catalog)
    owner = owner_document(catalog)
    raw = canonical_bytes(owner)
    config = dict.fromkeys(owner_directory_launch._FIELDS)
    config.update(native_launch_version='4.0', phase_wheel_digest=owner['phase_wheel_digest'],
        owner_directory_configuration_base64=base64.b64encode(raw).decode(),
        owner_directory_configuration_digest=digest_bytes(raw), qualification_cold_publication_seconds=900)

    def assemble(index, sealed=True):
        body = canonical_bytes(config if sealed else
            {key: value for key, value in config.items() if key != 'qualification_cold_publication_seconds'})
        row = owner['manifests'][index]
        return {'config_bytes': body, 'expected_config_digest': digest_bytes(body),
                'manifest_bytes': base64.b64decode(row['manifest_base64']),
                'expected_manifest_digest': row['manifest_digest']}
    return assemble


class ParentPipe:
    def __init__(self, ready, receive):
        self.sent = []
        self.ready = canonical_bytes(ready)
        self.observe = receive

    def send_frame(self, raw, deadline):
        self.sent.append((parse_json_bytes(raw), deadline))

    def receive_frame(self, deadline, *, maximum_bytes):
        assert len(self.ready) <= maximum_bytes == 4096
        self.observe()
        return self.ready, {}


def test_both_wire_delays_consume_time_without_cross_clock_comparison(startup, monkeypatch):
    value = invocation(file_request())
    anchor = 700 * NS  # Linux and QPC start at deliberately different epochs.
    ready = handoff._binding('core', value) | {'anchor_ns': anchor}
    qpc = [4000 * NS]

    def observe_ready():
        qpc[0] += 5 * NS

    monkeypatch.setattr(handoff.time, 'perf_counter_ns', lambda: qpc[0])
    pipe = ParentPipe(ready, observe_ready)
    handoff.send_linux_invocation(pipe, canonical_bytes(value), role='core', deadline_ns=4090*NS)
    sent, answer = pipe.sent
    assert sent == (offer(value), 4030 * NS)
    assert answer == (ready | {'remaining_ns': 85*NS}, 4035*NS)

    linux = iter([anchor, anchor+3*NS])  # Return leg consumed another three seconds.
    monkeypatch.setattr(handoff.time, 'monotonic_ns', lambda: next(linux))
    emitted = []
    initial, local = handoff.receive_linux_invocation(sent[0],role='core',startup=startup(1),
        send_frame=emitted.append,receive_frame=lambda limit:canonical_bytes(answer[0]))
    assert emitted == [canonical_bytes(ready)] and initial == value
    assert local == anchor + 85*NS
    assert local - (anchor+3*NS) == 82*NS


@pytest.mark.parametrize('mutate', [
    lambda answer: answer | {'remaining_ns': True},
    lambda answer: answer | {'remaining_ns': 901*NS},
    lambda answer: answer | {'invocation_digest': 'sha256:'+'b'*64},
    lambda answer: answer | {'role': 'prepare-input'},
    lambda answer: answer | {'anchor_ns': answer['anchor_ns']+1},
])
def test_foreign_or_invalid_budget_stops_before_any_owned_action(startup, monkeypatch, mutate):
    value = invocation(file_request())
    monkeypatch.setattr(handoff.time, 'monotonic_ns', lambda: 700*NS)
    frames = []
    with pytest.raises(PhaseError, match='ntfs.linux_exchange_deadline_binding'):
        handoff.receive_linux_invocation(offer(value),role='core',startup=startup(1),send_frame=frames.append,
            receive_frame=lambda limit: canonical_bytes(mutate(parse_json_bytes(frames[0]) | {'remaining_ns':10*NS})))
    assert len(frames) == 1 and handoff.linux_exchange_deadline_ns() is None


def test_default_inspection_recovery_c01_and_unsealed_launch_cannot_negotiate(startup):
    value = invocation(file_request())

    def unexpected(*_):
        pytest.fail('legacy/forbidden launch sent private timing data')

    assert handoff.receive_linux_invocation(value, role=None, startup=None,
        send_frame=unexpected, receive_frame=unexpected) == (value, None)
    for proposed, role, config in (
        (offer(value), None, None),
        (offer(value), 'core', startup(1, sealed=False)),
        (offer(value), 'core', startup(0)),
        (offer(invocation({'operation': 'recover_publication'})), 'core', startup(5)),
        (offer(invocation({'operation': 'inspect'})), 'core', startup(1)),
    ):
        with pytest.raises(PhaseError):
            handoff.receive_linux_invocation(proposed,role=role,startup=config,
                send_frame=unexpected,receive_frame=unexpected)


def test_expiry_during_confirmation_prevents_linux_scope(startup, monkeypatch):
    value = invocation(file_request())
    linux = iter([700*NS, 713*NS])
    monkeypatch.setattr(handoff.time, 'monotonic_ns', lambda: next(linux))
    frames = []
    with pytest.raises(PhaseError, match='ntfs.linux_exchange_deadline_expired'):
        handoff.receive_linux_invocation(offer(value),role='core',startup=startup(1),send_frame=frames.append,
            receive_frame=lambda limit: canonical_bytes(parse_json_bytes(frames[0]) | {'remaining_ns':13*NS}))
    assert handoff.linux_exchange_deadline_ns() is None


def test_remaining_is_taken_only_after_validated_ready(monkeypatch):
    qpc = [99*NS]
    monkeypatch.setattr(handoff.time, 'perf_counter_ns', lambda: qpc[0])
    value = invocation(file_request())
    ready = handoff._binding('core', value) | {'anchor_ns': 700*NS}

    def consume_last_second():
        qpc[0] = 100*NS

    pipe = ParentPipe(ready, consume_last_second)
    with pytest.raises(PhaseError, match='ntfs.linux_exchange_deadline_expired'):
        handoff.send_linux_invocation(pipe, canonical_bytes(value), role='core', deadline_ns=100*NS)
    assert pipe.sent == [(offer(value),100*NS)]
