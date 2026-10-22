"""Unselected one-operation Windows worker for a future trusted Core composition.

Launch only AFTER the parent independently validates the durable original intent,
installation, native footprint, effect plan and frozen bytes. This module grants
no authority and has no CLI/service/dispatcher/spawn/retry or persistent state.
The parent must retain the exact process handle and establish exit separately.
"""
from __future__ import annotations

import os
import re
import time
from multiprocessing import connection as _connection

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from .native import NativeIdentity, _error_record, _require
from .scoped import NativeRootGrant
from .file_create import NativeFileCreateOutcomeUnavailable, execute_file_create
from .windows_pipe import WindowsPipeFrames


_CONTEXT = {'worker_protocol', 'worker_version', 'run_id', 'intent_digest',
            'effect_plan_digest', 'native_binding_digest', 'installation_digest',
            'implementation_artifact_digest', 'operation_nonce'}
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_MAX_RESULT = 512*1024


def _frame(raw: bytes, keys: set[str]) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= _MAX_RESULT, 'ntfs.worker_frame_limit')
    value = parse_json_bytes(raw, maximum_bytes=_MAX_RESULT)
    _require(type(value) is dict and set(value) == keys and canonical_bytes(value) == raw,
             'ntfs.worker_frame_shape')
    return value


def validate_worker_ready(raw: bytes, *, context: dict, grant_data: dict,
                          effect: dict, content: bytes, expected_pid: int) -> dict:
    """Correlate a READY frame against trusted parent data, without granting GO.

    The parent must already have verified the original durable Core intent and
    must obtain expected_pid from its retained creation process, not this frame.
    This parser performs no IPC, process wait, target observation or authority
    qualification. A matching readiness echo is not proof of loaded code.
    """
    binding, grant = _context(context), _grant(grant_data)
    _require(type(expected_pid) is int and expected_pid > 0, 'ntfs.worker_pid_required')
    _require(type(effect) is dict and type(content) is bytes and len(content) <= 1024**2,
             'ntfs.worker_expected_binding_shape')
    _require(effect.get('kind') == 'exclusive_create' and effect.get('content_digest') == digest_bytes(content)
        and type(effect.get('content_length')) is int and effect['content_length'] == len(content),
        'mechanism.content_binding_mismatch')
    value = _frame(raw, {'worker_ready_version', 'context', 'pid', 'grant_digest',
                         'effect_digest', 'content_digest', 'content_length'})
    _require(type(value['pid']) is int and type(value['content_length']) is int,
             'ntfs.worker_ready_binding_mismatch')
    _require(value == {'worker_ready_version': '1.0', 'context': binding,
        'pid': expected_pid, 'grant_digest': digest_bytes(canonical_bytes(grant.as_dict())),
        'effect_digest': digest_bytes(canonical_bytes(effect)),
        'content_digest': digest_bytes(content), 'content_length': len(content)},
        'ntfs.worker_ready_binding_mismatch')
    return value


def validate_worker_completion(raw: bytes, *, context: dict, grant_data: dict,
                               effect: dict, expected_pid: int) -> dict:
    """Correlate an untrusted completion; never turn it into an exit/success fact.

    The unchanged Broker must validate any effect receipt with its exact schema
    and plan. A trusted process owner must separately establish retained-HANDLE
    exit and native readback; Core owns disposition, persistence and recovery.
    Error completions are retained, including a missing effect receipt. They do
    not authorize retry, even if no target effect is reported.
    """
    binding, grant = _context(context), _grant(grant_data)
    _require(type(expected_pid) is int and expected_pid > 0, 'ntfs.worker_pid_required')
    _require(type(effect) is dict and effect.get('kind') == 'exclusive_create'
        and type(effect.get('effect_id')) is str and bool(effect['effect_id'])
        and type(effect.get('target')) is dict and set(effect['target']) == {'root_binding', 'relative_locator'}
        and effect['target']['root_binding'] == grant.binding,
        'ntfs.worker_expected_binding_shape')
    safe_relative_locator(effect['target']['relative_locator'])
    value = _frame(raw, {'worker_completion_version', 'context', 'pid', 'effect_receipt',
                         'physical_evidence', 'error', 'worker_exit_established'})
    _require(value['worker_completion_version'] == '1.0' and value['context'] == binding
        and type(value['pid']) is int and value['pid'] == expected_pid
        and value['worker_exit_established'] is False, 'ntfs.worker_completion_binding_mismatch')
    receipt, physical, error = value['effect_receipt'], value['physical_evidence'], value['error']
    if receipt is not None:
        _require(type(receipt) is dict and receipt.get('run_id') == binding['run_id']
            and receipt.get('effect_id') == effect['effect_id'] and receipt.get('kind') == effect.get('kind'),
            'ntfs.worker_receipt_binding_mismatch')
    if physical is not None:
        _require(type(physical) is dict and physical.get('native_file_create_version') == '1.0'
            and physical.get('run_id') == binding['run_id'] and physical.get('effect_id') == effect['effect_id']
            and canonical_bytes(physical.get('grant')) == canonical_bytes(grant.as_dict())
            and physical.get('locator') == effect['target'].get('relative_locator')
            and physical.get('worker_exit_established') is False, 'ntfs.worker_physical_binding_mismatch')
    if error is None:
        _require(receipt is not None and physical is not None, 'ntfs.worker_completion_incomplete')
    else:
        _require(type(error) is dict and set(error) == {'type', 'code', 'message', 'details'}
            and type(error['type']) is str and type(error['message']) is str
            and (error['code'] is None or type(error['code']) is str) and type(error['details']) is dict
            and receipt is None, 'ntfs.worker_error_binding_mismatch')
    return value


def _context(value: object) -> dict:
    _require(type(value) is dict and set(value) == _CONTEXT, 'ntfs.worker_context_shape')
    result = parse_json_bytes(canonical_bytes(value))
    _require(result['worker_protocol'] == 'phase.native.file-worker' and result['worker_version'] == '1.0',
             'ntfs.worker_protocol_unsupported')
    _require(type(result['run_id']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',
             result['run_id']) is not None, 'evidence.invalid_run_id')
    _require(type(result['operation_nonce']) is str and re.fullmatch('[0-9a-f]{32}',
             result['operation_nonce']) is not None, 'ntfs.worker_nonce_shape')
    for key in ('intent_digest', 'effect_plan_digest', 'native_binding_digest',
                'installation_digest', 'implementation_artifact_digest'):
        _require(type(result[key]) is str and _DIGEST.fullmatch(result[key]) is not None,
                 'ntfs.worker_context_digest')
    return result


def _grant(value: object) -> NativeRootGrant:
    _require(type(value) is dict and set(value) == {'root_binding', 'device', 'volume_guid',
        'volume_serial32', 'components', 'native_identity'}, 'ntfs.worker_grant_shape')
    _require(type(value['components']) is list, 'ntfs.worker_grant_shape')
    return NativeRootGrant(value['root_binding'], value['device'], value['volume_guid'],
        value['volume_serial32'], tuple(value['components']), NativeIdentity.parse(value['native_identity']))


def run_file_create_worker(pipe: object, context: dict, grant_data: dict,
                           effect: dict, content: bytes, timestamp: str) -> None:
    """Fixed target for an installation-owned Windows spawn; never self-activate.

    Arguments come only from the trusted parent, not caller-selected commands or
    an external pickle endpoint. The parent authenticates them against original
    Core evidence; structural checks here do not make caller data authoritative.
    Until one exact GO, only validate data and exchange readiness over the owned
    pipe. No NativeIO, target handle, mutex or mutable API is opened before GO.
    No child, replacement worker or second GO is permitted by this function.
    """
    _require(os.name == 'nt' and (type(pipe) is WindowsPipeFrames
        or type(pipe) is _connection.PipeConnection), 'ntfs.windows_worker_pipe_required')
    framed = type(pipe) is WindowsPipeFrames
    primary = transport_error = close_error = None
    binding = None
    completion = None
    try:
        try:
            handshake_deadline = time.perf_counter_ns() + 30_000_000_000
            binding = _context(context)
            grant = _grant(grant_data)
            _require(type(content) is bytes and len(content) <= 1024**2, 'mechanism.content_too_large')
            _require(type(effect) is dict, 'ntfs.worker_effect_shape')
            effect = parse_json_bytes(canonical_bytes(effect))
            _require(effect.get('kind') == 'exclusive_create'
                and effect.get('content_digest') == digest_bytes(content)
                and type(effect.get('content_length')) is int and effect['content_length'] == len(content),
                'mechanism.content_binding_mismatch')
            _require(type(timestamp) is str and bool(timestamp), 'ntfs.invalid_effect_timestamp')
            # A readiness record is a context echo, not independent process identity.
            # Supervisor must compare PID/times using its own creation process handle.
            ready = {'worker_ready_version': '1.0', 'context': binding, 'pid': os.getpid(),
                'grant_digest': digest_bytes(canonical_bytes(grant.as_dict())),
                'effect_digest': digest_bytes(canonical_bytes(effect)),
                'content_digest': digest_bytes(content), 'content_length': len(content)}
            if framed:
                pipe.send_frame(canonical_bytes(ready), handshake_deadline)
                raw, _progress = pipe.receive_frame(handshake_deadline, maximum_bytes=4096)
            else:
                pipe.send_bytes(canonical_bytes(ready))
                _require(pipe.poll(30), 'ntfs.worker_go_deadline')
                raw = pipe.recv_bytes(maxlength=4096)
            go = parse_json_bytes(raw, maximum_bytes=4096)
            _require(canonical_bytes(go) == raw and go == {'command': 'execute_file_create', 'context': binding},
                     'ntfs.worker_go_binding_mismatch')
            if framed:
                _require(time.perf_counter_ns() < handshake_deadline, 'ntfs.worker_go_deadline')
            effect_receipt, evidence = execute_file_create(grant, effect, content,
                run_id=binding['run_id'], timestamp=timestamp)
            completion = {'worker_completion_version': '1.0', 'context': binding, 'pid': os.getpid(),
                'effect_receipt': effect_receipt, 'physical_evidence': evidence, 'error': None,
                'worker_exit_established': False}
        except BaseException as error:
            primary = error
            completion = {'worker_completion_version': '1.0', 'pid': os.getpid(),
                'context': binding, 'effect_receipt': None,
                'physical_evidence': error.evidence if isinstance(error, NativeFileCreateOutcomeUnavailable) else None,
                'error': _error_record(error), 'worker_exit_established': False}
        raw = canonical_bytes(completion)
        _require(len(raw) <= _MAX_RESULT, 'ntfs.worker_completion_limit')
        if framed:
            # Physical execution has no protocol deadline/cancellation promise.
            # Completion gets its own finite send window after that operation.
            pipe.send_frame(raw, time.perf_counter_ns() + 30_000_000_000)
        else:
            pipe.send_bytes(raw)
    except BaseException as transport:
        transport_error = transport
    finally:
        # Attempt exactly once even if building diagnostic completion fails.
        try:
            if framed:
                pipe.seal()  # Entrypoint owns stream close; parent proves exit.
            else:
                pipe.close()
        except BaseException as finalization:
            close_error = finalization
    if transport_error is not None or close_error is not None:
        raise PhaseError('ntfs.worker_completion_or_finalization_unavailable', details={
            'primary': None if primary is None else _error_record(primary),
            'transport': None if transport_error is None else _error_record(transport_error),
            'finalization': None if close_error is None else _error_record(close_error),
            'worker_exit_established': False}) from (transport_error if transport_error is not None else close_error)
