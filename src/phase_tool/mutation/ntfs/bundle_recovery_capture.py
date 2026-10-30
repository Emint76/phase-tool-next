"""Versioned B2 terminal capture; never extends an effect/GO deadline.

Used only by the fixed recovery-capable generation. A finite terminal drain is
diagnosis after the original execute slot is consumed, not another operation.
The original providers and completion1.5 representation remain unchanged.
"""
from __future__ import annotations

import base64
import os
import time

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import _require
from .uncertainty import _diagnostic

TERMINAL_GRACE_NS = 5_000_000_000
CORE_TERMINAL_SECONDS = 70.0


def terminal_deadline_ns():
    """Reporting only: callers must have stopped all effect/GO paths first."""
    return time.perf_counter_ns() + TERMINAL_GRACE_NS


def completion_wait_deadline(effect_deadline):
    """Keep the original remaining effect wait, then only a reporting grace."""
    _require(type(effect_deadline) is int, 'ntfs.bundle_owned_deadline_required')
    return max(time.perf_counter_ns(),effect_deadline)+TERMINAL_GRACE_NS


def wire_record(raw):
    if raw is None:
        return None
    _require(type(raw) is bytes and 0 < len(raw) <= 512*1024,
             'ntfs.worker_completion_limit')
    return {'sha256': digest_bytes(raw), 'length': len(raw),
            'bytes_base64': base64.b64encode(raw).decode('ascii')}


def run_bundle_worker_capture(pipe, projection, channel_id, *, _transfer_deadline_ns):
    """Existing effect finishes/seals BEFORE a separate terminal-only window."""
    from .bundle_execution import _BundleWorkerInput, _bundle_projection_value, _bundle_ready_value
    from .bundle_effect import execute_bundle_create
    from .file_create import NativeFileCreateOutcomeUnavailable
    from .windows_pipe import WindowsPipeFrames
    from .worker import _grant
    _require(os.name == 'nt' and type(pipe) is WindowsPipeFrames,
             'ntfs.windows_worker_pipe_required')
    value = _bundle_projection_value(projection)
    context = value['context']
    primary = transport_error = close_error = None
    try:
        try:
            source = _BundleWorkerInput(pipe, projection, channel_id, _transfer_deadline_ns)
            source.first_pass()
            pipe.send_frame(canonical_bytes(_bundle_ready_value(projection, channel_id, os.getpid())),
                            _transfer_deadline_ns)
            raw, _ = pipe.receive_frame(_transfer_deadline_ns, maximum_bytes=16384)
            source.accept_go(raw)
            receipt, physical = execute_bundle_create(_grant(value['grant']), value['effect'], source,
                                                      run_id=context['run_id'], timestamp=value['timestamp'])
            completion = {'worker_completion_version': context['worker_version'], 'context': context,
                          'pid': os.getpid(), 'effect_receipt': receipt, 'physical_evidence': physical,
                          'error': None, 'worker_exit_established': False}
        except BaseException as error:
            primary = error
            completion = {'worker_completion_version': context['worker_version'], 'context': context,
                          'pid': os.getpid(), 'effect_receipt': None,
                          'physical_evidence': error.evidence if isinstance(error, NativeFileCreateOutcomeUnavailable) else None,
                          'error': _diagnostic(error), 'worker_exit_established': False}
        # execute_bundle_create has returned or unwound its native handle/mutex
        # scopes. No source, effect or GO method is reachable below this point.
        raw = canonical_bytes(completion)
        _require(len(raw) <= 512*1024, 'ntfs.worker_completion_limit')
        from .bundle_recovery_terminal import windows_terminal
        windows_terminal(pipe, sending=True, raw=raw, deadline_ns=terminal_deadline_ns())
    except BaseException as error:
        transport_error = error
    finally:
        try:
            pipe.seal()
        except BaseException as error:
            close_error = error
    if transport_error is not None or close_error is not None:
        raise PhaseError('ntfs.worker_completion_or_finalization_unavailable', details={
            'primary': None if primary is None else _diagnostic(primary),
            'transport': None if transport_error is None else _diagnostic(transport_error),
            'finalization': None if close_error is None else _diagnostic(close_error),
            'worker_exit_established': False}) from (transport_error or close_error)


def execute_original_with_capture(parent, intent_digest, *, common):
    """B2 original owner, one drain BEFORE wait; no retry or second GO."""
    from .bundle_execution import validate_bundle_worker_completion, validate_bundle_observation
    from .bundle_observation import observe_bundle
    from .process_witness import WindowsProcessWitness
    from .worker import _grant
    _require(parent._launch.manifest['native_read_installation_version'] == '1.9'
             and parent._bundle and not parent._inspection_only
             and parent._consumed and not parent._spawn_attempted,
             'ntfs.parent_execution_consumed')
    parsed = parent._launch.read_original(intent_digest)
    context = parse_json_bytes(parsed.context_bytes)
    effect = parse_json_bytes(parsed.effect_bytes)
    grant = parse_json_bytes(parsed.grant_bytes)
    _require(context['worker_version'] == '1.5' and context['run_id'] == parent._launch.run_id
             and context['intent_digest'] == intent_digest
             and context['operation_nonce'] == parent._launch.operation_nonce
             and context['installation_digest'] == parent._launch.installation_digest
             and grant == parent._launch.root_grant, 'ntfs.parent_original_binding_mismatch')
    parent._spawn_attempted = True
    parent._worker = parent._launch.spawn_worker()
    parent._worker_count = 1
    witness = pipe = completion = process_fact = None
    operation_primary = None
    operation_secondary = []
    terminal_failure = None
    closure_errors = []
    drain_attempted = terminal_read_attempted = False
    terminal_budget = None
    try:
        witness = WindowsProcessWitness(parent._worker)
        pipe = parent._launch.worker_pipe(parent._worker)
        parent._launch.send_worker_original(pipe, parsed,
            _handshake_deadline_ns=parent._file2_exchange_deadline)
        early = parent._transfer_bundle(pipe, parsed, parent._file2_exchange_deadline, common)
        terminal_budget = max(time.perf_counter_ns(),parent._file2_exchange_deadline)+int(CORE_TERMINAL_SECONDS*1_000_000_000)
        if early is None:
            from .bundle_recovery_terminal import windows_terminal
            terminal_read_attempted = True
            raw, _ = windows_terminal(pipe, sending=False, deadline_ns=completion_wait_deadline(parent._file2_exchange_deadline))
        else:
            raw = early
        parent._completion_wire = raw
        completion = validate_bundle_worker_completion(raw, context=context, grant_data=grant,
                                                       effect=effect, expected_pid=parent._worker.pid)
    except BaseException as error:
        operation_primary = error
        if terminal_budget is None:
            terminal_budget = time.perf_counter_ns()+int(CORE_TERMINAL_SECONDS*1_000_000_000)
        # An ACK relay exception may follow partial delivery. Drain exactly one
        # terminal completion before waiting, otherwise the worker pipe can fill.
        # A partial/malformed frame remains unknown; never restart its parser.
        if (pipe is not None and parent._go_attempted and parent._completion_wire is None
                and not terminal_read_attempted and getattr(parent, '_bundle_ack_relay_entered', False)):
            drain_attempted = True
            try:
                from .bundle_recovery_terminal import windows_terminal
                terminal_read_attempted = True
                raw, _ = windows_terminal(pipe, sending=False,
                    deadline_ns=min(completion_wait_deadline(parent._file2_exchange_deadline), terminal_budget))
                parent._completion_wire = raw
                completion = validate_bundle_worker_completion(raw, context=context, grant_data=grant,
                    effect=effect, expected_pid=parent._worker.pid)
            except BaseException as secondary:
                operation_secondary.append(secondary)
                if isinstance(secondary,PhaseError) and secondary.code=='ntfs.terminal_frame_unknown':
                    terminal_failure=secondary.details
    finally:
        try:
            _require(witness is not None, 'ntfs.worker_creation_witness_unavailable')
            if terminal_budget is None:
                terminal_budget = time.perf_counter_ns()+int(CORE_TERMINAL_SECONDS*1_000_000_000)
            remaining = max(0, min(60000, (terminal_budget-time.perf_counter_ns())//1_000_000))
            process_fact = witness.wait_for_exit(remaining)
            _require(process_fact['worker_exit_established'] is True
                     and type(process_fact['wait_result']) is int and process_fact['wait_result'] == 0
                     and type(process_fact['exit_code']) is int and process_fact['exit_code'] == 0,
                     'ntfs.worker_exit_not_established')
        except BaseException as error:
            closure_errors.append(error)
        if process_fact is not None and process_fact['worker_exit_established'] is True:
            try:
                parent._launch.finalize_worker(parent._worker, pipe)
                parent._worker_finalized = True
            except BaseException as error:
                closure_errors.append(error)
    partial = {'parent_execution_version': '1.5', 'context': context, 'completion': completion,
        'process_witness': process_fact, 'owner_finalization': {
            'worker_stdin': 'closed' if parent._worker_finalized else 'unknown',
            'worker_stdout': 'closed' if parent._worker_finalized else 'unknown',
            'worker_stderr': 'closed' if parent._worker_finalized else 'unknown',
            'creation_handle': 'closed' if parent._worker_finalized else 'unknown',
            'errors': [_diagnostic(error) for error in closure_errors]},
        'post_observation': None, 'ingress_state': 'consumed'}
    if operation_primary is None and not closure_errors:
        try:
            _require(completion is not None and parent._worker_finalized, 'ntfs.worker_finalization_unknown')
            partial['post_observation'] = validate_bundle_observation(
                observe_bundle(_grant(grant), effect['target']['relative_locator']),
                grant, effect['target']['relative_locator'])
            parent._launch.check_runtime()
        except BaseException as error:
            operation_primary = error
    parent._partial_bytes = canonical_bytes(partial)
    if operation_primary is not None or closure_errors:
        parent._terminal_reply_deadline = min(terminal_deadline_ns(), terminal_budget)
        raise PhaseError('ntfs.parent_execution_unresolved', details={
            'capture_version': '1.1', 'parent_partial': parse_json_bytes(parent._partial_bytes),
            'worker_ready_wire': wire_record(parent._ready_wire),
            'worker_completion_wire': wire_record(parent._completion_wire),
            'operation_primary': None if operation_primary is None else _diagnostic(operation_primary),
            'operation_secondary': [_diagnostic(error) for error in operation_secondary],
            'resource_closure_errors': [_diagnostic(error) for error in closure_errors],
            'terminal_failure': terminal_failure if terminal_failure is not None else (operation_primary.details
                if isinstance(operation_primary,PhaseError) and operation_primary.code=='ntfs.terminal_frame_unknown' else None),
            'terminal_drain_attempted': drain_attempted,
            'possible_dispatch': parent._go_attempted, 'retry_authorized': False}) from operation_primary
    parent._terminal_reply_deadline = min(terminal_deadline_ns(), terminal_budget)
    return partial
