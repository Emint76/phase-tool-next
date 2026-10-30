"""Closed remaining-commit worker. No source capture, stage creation or retry.

The same stage DELETE HANDLE and NativeRootMutex span READY/record-before-GO.
Only the fixed parent starts this role. Saved negative flags are never authority.
"""
from __future__ import annotations
import os
import time

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from .native import NativeIdentity, _require
from .worker import _grant
from .bundle_execution import _bundle_projection_value, _bundle_projection_from_value
from .bundle_observation import verify_bundle_handle
from .bundle_recovery_capture import terminal_deadline_ns
from .uncertainty import _diagnostic


def recovery_context(value):
    _require(type(value) is dict and set(value)=={'native_recovery_context_version','run_id',
        'intent_digest','effect_plan_digest','installation_digest','operation_nonce','channel_id',
        'original_operation_nonce','preparation_digest','mode'}
        and value['native_recovery_context_version']=='1.0'
        and value['mode'] in {'observe','commit_prepared'}, 'recovery.native_context_mismatch')
    import re
    for key in ('intent_digest','effect_plan_digest','installation_digest','preparation_digest'):
        _require(type(value[key]) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',value[key]) is not None,
            'recovery.native_context_mismatch')
    for key in ('operation_nonce','channel_id','original_operation_nonce'):
        _require(type(value[key]) is str and re.fullmatch(r'[0-9a-f]{32}',value[key]) is not None,
            'recovery.native_context_mismatch')
    from ...evidence import validate_run_id
    validate_run_id(value['run_id'])
    return value


def validate_recovery_ready(value, *, context, projection, prepared, expected_pid):
    from .bundle_prepared import prepared_locator
    from .bundle_execution import _validate_bundle_content
    recovery_context(context)
    projected=_bundle_projection_value(projection)
    expected=projected['context']
    _require(all(context[key]==expected[key]for key in ('run_id','intent_digest','effect_plan_digest','installation_digest'))
        and context['original_operation_nonce']==expected['operation_nonce']
        and context['preparation_digest']==digest_bytes(canonical_bytes(prepared))
        and context['mode']=='commit_prepared','recovery.native_context_mismatch')
    _require(type(value) is dict and set(value)=={'native_recovery_ready_version','context','pid',
        'selected','native','mutex_state','stage_lease'}
        and value['native_recovery_ready_version']=='1.0'
        and canonical_bytes(value['context'])==canonical_bytes(context)
        and type(expected_pid) is int and type(value['pid']) is int and value['pid']==expected_pid>0
        and value['selected'] in {'stage','target'} and value['mutex_state']=='held'
        and value['stage_lease']=='retained', 'recovery.native_ready_mismatch')
    native=value['native']
    _validate_bundle_content({'known':True,'exists':True,'digest':projection.content_digest,
        'length':projection.content_length,'head_token':None},native,projected['grant'],projection=projection)
    _require(native['stat_identity']=={'device':prepared['device'],'inode':prepared['inode']}
        and prepared['stage_locator']==prepared_locator(projection)
        and digest_bytes(canonical_bytes(prepared))==context['preparation_digest']
        and native['owner']['run_id']==context['run_id']
        and native['owner']['plan_digest']==context['effect_plan_digest'], 'recovery.preparation_mismatch')
    return value


def execute_remaining(projection, prepared, context, *, authorize):
    """Physical authority is scoped here, never in Core's POSIX projection."""
    from .mutating import NativeMutationIO
    from .root_lock import NativeRootMutex
    from .scoped import NativeScopedTarget
    from .file_create import _MutationTrace
    from .bundle_effect import _bundle_mutation_call
    value=_bundle_projection_value(projection);recovery_context(context)
    _require(value['context']['run_id']==context['run_id']
        and value['context']['intent_digest']==context['intent_digest']
        and value['context']['operation_nonce']==context['original_operation_nonce']
        and value['context']['effect_plan_digest']==context['effect_plan_digest']
        and value['context']['installation_digest']==context['installation_digest'],
        'recovery.native_context_mismatch')
    _require(context['mode']=='commit_prepared','recovery.closed_commit_role_required')
    grant=_grant(value['grant']);effect=value['effect']
    target=safe_relative_locator(effect['target']['relative_locator'])
    stage=safe_relative_locator(prepared['stage_locator'])
    _require(stage.split('/')[:-1]==target.split('/')[:-1], 'recovery.preparation_mismatch')
    io=NativeMutationIO();trace=_MutationTrace();lock=NativeRootMutex(io,grant)
    primary=None;errors=[];attempted=False;rename=None;flushed=[];ready=None;after=None;parent_identity=None
    def call(method,*args,**kwargs):
        return _bundle_mutation_call(io,trace,errors,method,*args,**kwargs)
    try:
        with lock:
            with NativeScopedTarget(io,grant,target,namespace_flush=True) as scope:
                parent_identity=scope.parent_identity.as_dict()
                try:probe=io.child(scope.parent,scope.name,directory=True)
                except PhaseError as error:
                    if error.code!='ntfs.open_failed' or error.details!={'ntstatus':'0xc0000034'}:raise
                    _require(context['mode']=='commit_prepared','recovery.unpublished_stage_retained')
                    selected='stage'
                    handle=io.child(scope.parent,stage.split('/')[-1],directory=True,rename_source=True)
                    observed_identity=None
                else:
                    selected='target'
                    with probe:observed_identity=io.identity(probe)
                    handle=io.child(scope.parent,scope.name,directory=True,rename_source=True)
                with handle:
                    identity=io.identity(handle)
                    _require(observed_identity is None or identity==observed_identity,'recovery.preparation_mismatch')
                    native=verify_bundle_handle(io,handle,expected_identity=identity,
                        expected_manifest=projection.manifest_bytes,run_id=context['run_id'],
                        plan_digest=context['effect_plan_digest'])
                    _require(io.directory_stat_identity(handle,identity)=={
                        'device':prepared['device'],'inode':prepared['inode']},'recovery.preparation_mismatch')
                    if selected=='target':scope.assert_directory_name(handle,identity)
                    else:
                        with io.observe_committed_name(scope.parent,handle,stage.split('/')[-1],
                                expected_source=identity,expected_parent=scope.parent_identity):
                            pass
                    ready={'native_recovery_ready_version':'1.0','context':context,'pid':os.getpid(),
                        'selected':selected,'native':native,'mutex_state':'held','stage_lease':'retained'}
                    validate_recovery_ready(ready,context=context,projection=projection,prepared=prepared,
                        expected_pid=os.getpid())
                    # This callback only performs the fixed READY/GO pipe exchange.
                    # Its original bounded deadline is checked again immediately
                    # before the sole effect; no terminal grace reaches this point.
                    effect_deadline=authorize(ready)
                    _require(type(effect_deadline) is int,'ntfs.bundle_owned_deadline_required')
                    scope.assert_bound();lock.assert_held()
                    verify_bundle_handle(io,handle,expected_identity=identity,
                        expected_manifest=projection.manifest_bytes,run_id=context['run_id'],
                        plan_digest=context['effect_plan_digest'])
                    if selected=='stage':
                        _require(time.perf_counter_ns()<effect_deadline,'ntfs.bundle_owned_deadline_required')
                        attempted=True  # BEFORE the only native rename call.
                        rename=call(io.rename,handle,scope.parent,scope.name,expected_source=identity,
                            expected_parent=scope.parent_identity,replace=False)
                    _require(time.perf_counter_ns()<effect_deadline,'ntfs.bundle_owned_deadline_required')
                    attempted=True  # Existing commit_prepared also finalizes an exact existing target.
                    call(io.flush_namespace,scope.parent,scope.parent_identity)
                    flushed.append('target_parent')
                    # Existing target finalization never repeats its rename.
                    after=verify_bundle_handle(io,handle,expected_identity=identity,
                        expected_manifest=projection.manifest_bytes,run_id=context['run_id'],
                        plan_digest=context['effect_plan_digest'])
                    scope.assert_directory_name(handle,identity);lock.assert_held()
    except BaseException as error:primary=error
    finally:
        try:trace.collect(io)
        except BaseException as error:errors.append(error)
        try:io.seal_mutations()
        except BaseException as error:errors.append(error)
    closed=(not io._handles and not getattr(io,'_bundle_stat_ownership_unknown',False)
        and lock.state=='closed' and io.mutation_state=='sealed' and not errors)
    return {'native_recovery_completion_version':'1.0','context':context,'pid':os.getpid(),
        'ready':ready,'after':after,'mutation_attempted':attempted,'rename':rename,'parent_identity':parent_identity,
        'namespace_flushed':flushed,'mutation_trace':trace.snapshot(),'mutex_events':lock.events,
        'mutex_state':lock.state,'mutation_session_state':io.mutation_state,
        'remaining_handle_count':len(io._handles),'unproven_handle_ownership':getattr(io,'_bundle_stat_ownership_unknown',False),
        'handle_finalization':'closed' if closed else 'unknown','primary_error':None if primary is None else _diagnostic(primary),
        'finalization_errors':[_diagnostic(e)for e in errors]}


def run_recovery_worker(launch, initial, pipe, deadline):
    from .bundle_recovery_terminal import windows_terminal
    _require(launch.manifest['native_read_installation_version']=='1.9'
        and type(initial) is dict and set(initial)=={'native_worker_original_version','channel_id',
            'projection','prepared','recovery_context'} and initial['native_worker_original_version']=='4.0',
        'recovery.closed_native_role_required')
    context=recovery_context(initial['recovery_context'])
    _require(context['run_id']==launch.run_id and context['operation_nonce']==launch.operation_nonce
        and context['channel_id']==initial['channel_id']==launch.channel_id
        and context['installation_digest']==launch.installation_digest,'recovery.native_context_mismatch')
    projection=_bundle_projection_from_value(initial['projection'])
    _require(canonical_bytes(parse_json_bytes(projection.grant_bytes))==canonical_bytes(launch.root_grant),
        'ntfs.effect_grant_mismatch')
    def authorize(ready):
        _require(time.perf_counter_ns()<deadline,'ntfs.bundle_owned_deadline_required')
        pipe.send_frame(canonical_bytes(ready),deadline)
        raw,_=pipe.receive_frame(deadline,maximum_bytes=16384)
        expected={'native_recovery_go_version':'1.0','context':context,
            'ready_digest':digest_bytes(canonical_bytes(ready))}
        _require(raw==canonical_bytes(expected),'recovery.native_go_mismatch')
        _require(time.perf_counter_ns()<deadline,'ntfs.bundle_owned_deadline_required')
        return deadline
    result=execute_remaining(projection,initial['prepared'],context,authorize=authorize)
    # All native effect/lease/mutex scopes have unwound. This is reporting only.
    windows_terminal(pipe,sending=True,raw=canonical_bytes(result),deadline_ns=terminal_deadline_ns())
    return 0
