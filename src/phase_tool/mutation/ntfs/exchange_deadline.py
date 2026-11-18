"""Fixed qualification clock handoff over the existing owned launch pipe."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import re
import time

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from .native import _require


_FIELD = 'qualification_exchange_deadline_version'
_ROLES = frozenset({'prepare-input', 'core', 'inspect'})
_BULK_ROLES = {'1.3': 'File2', '1.6': 'Bundle1', '1.9': 'Bundle2'}
_POLICY_NS = 900_000_000_000
_FRAME_NS = 30_000_000_000
_CONTROL = 4096
_LINUX_DEADLINE = ContextVar('phase_linux_exchange_deadline_ns', default=None)


def bulk_publication_role(manifest):
    return _BULK_ROLES.get(manifest['native_read_installation_version'])


def linux_exchange_deadline_ns():
    return _LINUX_DEADLINE.get()


def linux_frame_deadline_ns(absolute):
    return min(absolute, time.monotonic_ns() + _FRAME_NS)


def linux_frame_deadline(absolute):
    return min(absolute, time.monotonic() + 30)


@contextmanager
def linux_exchange_scope(deadline_ns):
    if deadline_ns is None:
        yield
        return
    _require(linux_exchange_deadline_ns() is None and type(deadline_ns) is int
        and 0 < deadline_ns - time.monotonic_ns() <= _POLICY_NS,
        'ntfs.linux_exchange_deadline_binding')
    token = _LINUX_DEADLINE.set(deadline_ns)
    try:
        yield
    finally:
        _LINUX_DEADLINE.reset(token)


def _control(raw):
    value = parse_json_bytes(raw, maximum_bytes=_CONTROL)
    _require(type(value) is dict and canonical_bytes(value) == raw, 'ntfs.linux_exchange_deadline_binding')
    return value


def _binding(role, invocation):
    _require(role in _ROLES and type(invocation) is dict
        and set(invocation) == {'run_id', 'channel_id', 'operation_nonce', 'request'}
        and type(invocation['run_id']) is str and 0 < len(invocation['run_id']) <= 128
        and all(type(invocation[key]) is str and re.fullmatch('[0-9a-f]{32}', invocation[key])
                for key in ('channel_id', 'operation_nonce'))
        and type(invocation['request']) is dict, 'ntfs.linux_exchange_deadline_binding')
    return {_FIELD: '1.0', 'role': role, 'invocation_digest': digest_bytes(canonical_bytes(invocation))}


def _qualify_offer(invocation, role, startup):
    from .input_stage import _require_staged_publication_request
    from .owner_directory_launch import _accepted_cold_publication_seconds

    _require(_accepted_cold_publication_seconds(**startup) == 900, 'ntfs.linux_exchange_deadline_binding')
    request = invocation['request']
    if role == 'inspect':
        _require(request == {'operation': 'inspect'}, 'ntfs.linux_exchange_deadline_binding')
        return
    manifest = parse_json_bytes(startup['manifest_bytes'])
    bulk_role = bulk_publication_role(manifest)
    _require(bulk_role is not None, 'ntfs.linux_exchange_deadline_binding')
    if role == 'core':
        _require_staged_publication_request(request, role=bulk_role)
    else:
        _require(set(request) == {'operation', 'native_input_stage_request_version', 'header'}
            and request['operation'] == 'stage_input' and request['native_input_stage_request_version'] == '1.0'
            and type(request['header']) is dict and request['header'].get('role') == bulk_role,
            'ntfs.linux_exchange_deadline_binding')


def send_linux_invocation(pipe, raw, *, role, deadline_ns):
    """Windows answers an observed Linux anchor using the original QPC cutoff."""
    from .input_stage import _windows_input_frame_deadline_ns

    invocation = parse_json_bytes(raw, maximum_bytes=2*1024**2)
    _require(canonical_bytes(invocation) == raw, 'ntfs.linux_exchange_deadline_binding')
    binding = _binding(role, invocation)
    pipe.send_frame(canonical_bytes({_FIELD: '1.0', 'role': role, 'invocation': invocation}),
        _windows_input_frame_deadline_ns(deadline_ns))
    if role == 'inspect':
        wire, _ = pipe._receive_inspection_frame(deadline_ns, maximum_bytes=_CONTROL)
    else:
        wire, _ = pipe.receive_frame(_windows_input_frame_deadline_ns(deadline_ns), maximum_bytes=_CONTROL)
    anchor = _control(wire)
    _require(set(anchor) == set(binding) | {'anchor_ns'}
        and all(anchor[key] == value for key, value in binding.items())
        and type(anchor['anchor_ns']) is int and anchor['anchor_ns'] > 0,
        'ntfs.linux_exchange_deadline_binding')
    remaining = deadline_ns - time.perf_counter_ns()
    _require(0 < remaining <= _POLICY_NS, 'ntfs.linux_exchange_deadline_expired')
    pipe.send_frame(canonical_bytes(anchor | {'remaining_ns': remaining}),
        _windows_input_frame_deadline_ns(deadline_ns))


def receive_linux_invocation(value, *, role, startup, send_frame, receive_frame):
    """Linux anchors before READY; transport latency consumes the local budget."""
    if _FIELD not in value:
        return value, None
    _require(role in _ROLES and set(value) == {_FIELD, 'role', 'invocation'}
        and value[_FIELD] == '1.0' and value['role'] == role, 'ntfs.linux_exchange_deadline_binding')
    invocation = value['invocation']
    binding = _binding(role, invocation)
    _qualify_offer(invocation, role, startup)
    anchor = time.monotonic_ns()
    ready = binding | {'anchor_ns': anchor}
    send_frame(canonical_bytes(ready))
    answer = _control(receive_frame(_CONTROL))
    _require(set(answer) == set(ready) | {'remaining_ns'}
        and all(type(answer[key]) is type(expected) and answer[key] == expected for key, expected in ready.items())
        and type(answer['remaining_ns']) is int and 0 < answer['remaining_ns'] <= _POLICY_NS,
        'ntfs.linux_exchange_deadline_binding')
    deadline_ns = anchor + answer['remaining_ns']
    _require(time.monotonic_ns() < deadline_ns, 'ntfs.linux_exchange_deadline_expired')
    return invocation, deadline_ns
