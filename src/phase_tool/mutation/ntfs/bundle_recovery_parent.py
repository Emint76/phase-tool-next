"""One recovery worker owner and READY/GO relay on the existing parent pipes."""
from __future__ import annotations
import time

from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import _require
from .process_witness import WindowsProcessWitness
from .bundle_recovery_capture import terminal_deadline_ns, completion_wait_deadline, wire_record, CORE_TERMINAL_SECONDS
from .bundle_recovery_worker import recovery_context,validate_recovery_ready
from .uncertainty import _diagnostic


def execute_recovery(parent, value, common):
    launch=parent._launch
    context=recovery_context(value['recovery_context']);prepared=value['prepared']
    _require(launch.manifest['native_read_installation_version']=='1.9'
        and parent._consumed and not parent._spawn_attempted and not parent._inspection_only
        and context['run_id']==launch.run_id and context['intent_digest']==value['intent_digest']
        and context['installation_digest']==launch.installation_digest
        and context['operation_nonce']==launch.operation_nonce
        and context['channel_id']==launch.channel_id and context['mode']=='commit_prepared',
        'recovery.native_context_mismatch')
    from .bundle_execution import _bundle_projection_from_value,_bundle_projection_value
    recovered=launch._query_original('read_recovery',value['intent_digest'],
        _original_nonce=context['original_operation_nonce'])
    _require(type(recovered) is dict and set(recovered)=={'native_recovery_original_version',
        'projection','prepared','original_failure_digest'}
        and recovered['native_recovery_original_version']=='1.0'
        and canonical_bytes(recovered['prepared'])==canonical_bytes(prepared),
        'recovery.preparation_mismatch')
    projection=_bundle_projection_from_value(recovered['projection'])
    original=_bundle_projection_value(projection)
    _require(original['context']['operation_nonce']==context['original_operation_nonce']
        and original['context']['effect_plan_digest']==context['effect_plan_digest']
        and canonical_bytes(original['grant'])==canonical_bytes(launch.root_grant),
        'recovery.native_context_mismatch')
    deadline=time.perf_counter_ns()+30_000_000_000
    parent._spawn_attempted=True;parent._worker=launch.spawn_worker();parent._worker_count=1
    pipe=witness=ready=completion=fact=None;raw=None;primary=None;errors=[]
    terminal_read_attempted=False;ready_received=False
    budget=deadline+int(CORE_TERMINAL_SECONDS*1_000_000_000)
    try:
        witness=WindowsProcessWitness(parent._worker);pipe=launch.worker_pipe(parent._worker)
        pipe.send_frame(canonical_bytes({'native_worker_original_version':'4.0',
            'channel_id':launch.channel_id,'projection':original,'prepared':prepared,
            'recovery_context':context}),deadline)
        ready_raw,_=pipe.receive_frame(deadline,maximum_bytes=512*1024)
        candidate=parse_json_bytes(ready_raw)
        if type(candidate) is dict and candidate.get('native_recovery_completion_version')=='1.0':
            raw=ready_raw;completion=candidate
            _require(candidate.get('context')==context and type(candidate.get('pid')) is int
                and candidate['pid']==parent._worker.pid,'recovery.native_completion_mismatch')
            raise PhaseError('recovery.worker_failed_before_ready')
        ready=validate_recovery_ready(candidate,context=context,
            projection=projection,prepared=prepared,expected_pid=parent._worker.pid)
        _require(canonical_bytes(ready)==ready_raw,'recovery.native_ready_mismatch')
        ready_received=True  # Complete worker frame; safe one-way terminal drain.
        parent._pipe.send_frame(canonical_bytes(common|{'ok':True,'value':ready,'error':None}),deadline)
        go_raw,_=parent._pipe.receive_frame(deadline,maximum_bytes=16384)
        from ...canonical import digest_bytes
        expected={'native_recovery_go_version':'1.0','context':context,
            'ready_digest':digest_bytes(ready_raw)}
        _require(go_raw==canonical_bytes(expected),'recovery.native_go_mismatch')
        parent._go_attempted=True  # Sticky before any GO byte may leave.
        pipe.send_frame(go_raw,deadline)
        from .bundle_recovery_terminal import windows_terminal
        terminal_read_attempted=True
        raw,_=windows_terminal(pipe,sending=False,deadline_ns=completion_wait_deadline(deadline))
        completion=parse_json_bytes(raw,maximum_bytes=512*1024)
    except BaseException as error:
        primary=error
        if ready_received and not terminal_read_attempted:
            try:
                from .bundle_recovery_terminal import windows_terminal
                terminal_read_attempted=True
                raw,_=windows_terminal(pipe,sending=False,deadline_ns=completion_wait_deadline(deadline))
                completion=parse_json_bytes(raw,maximum_bytes=512*1024)
            except BaseException as secondary:errors.append(secondary)
    finally:
        try:
            _require(witness is not None,'ntfs.worker_creation_witness_unavailable')
            fact=witness.wait_for_exit(max(0,min(60000,(budget-time.perf_counter_ns())//1_000_000)))
            _require(fact['worker_exit_established'] is True,'ntfs.worker_exit_not_established')
        except BaseException as error:errors.append(error)
        if fact is not None and fact['worker_exit_established'] is True:
            try:launch.finalize_worker(parent._worker,pipe);parent._worker_finalized=True
            except BaseException as error:errors.append(error)
    reply={'native_recovery_parent_version':'1.0','context':context,'completion':completion,
        'completion_wire':wire_record(raw),'process_witness':fact,'owner_finalization':{
            'worker_stdin':'closed' if parent._worker_finalized else 'unknown',
            'worker_stdout':'closed' if parent._worker_finalized else 'unknown',
            'worker_stderr':'closed' if parent._worker_finalized else 'unknown',
            'creation_handle':'closed' if parent._worker_finalized else 'unknown',
            'errors':[_diagnostic(error)for error in errors]},
        'operation_primary':None if primary is None else _diagnostic(primary),
        'go_attempted':parent._go_attempted}
    parent._terminal_reply_deadline=min(terminal_deadline_ns(),budget)
    # Return exact data, including a closed negative completion; the existing
    # Core recovery owner validates facts and writes the separate observation.
    # No uncertainty is turned into an original receipt or a second GO.
    return reply
