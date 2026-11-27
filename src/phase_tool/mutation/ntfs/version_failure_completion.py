"""Explicit Version failure completion in the EXISTING parent-failure record.

No terminal receipt or target-success proof. Known synchronous API completion,
actual parent-owned creation-HANDLE witness and IO/owner closure precede any
explicit fresh classification. Historical envelopes without this exact new
capture remain unclosed; arbitrary negative flags never become permission.
"""
from __future__ import annotations
from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes
from .native import NativeIdentity,_require

_CAPTURE_KEYS={'version_failure_completion_version','context_digest','completion_digest',
    'process_witness_digest','owner_finalization_before_reporting','go_attempted'}


def capture_version_owner_completion(parent,*,go_attempted):
    """Called by actual parent BEFORE late read/report errors are conflated.

    This captures unknowns too. It does not validate, infer closure or promote
    parent/worker claims; a later verifier must affirm every required fact.
    No duplicate completion/witness payload or second IO is introduced.
    """
    return {'version_failure_completion_version':'1.1',
        'context_digest':digest_bytes(canonical_bytes(parent['context'])),
        'completion_digest':digest_bytes(canonical_bytes(parent['completion'])),
        'process_witness_digest':digest_bytes(canonical_bytes(parent['process_witness'])),
        'owner_finalization_before_reporting':parse_json_bytes(canonical_bytes(parent['owner_finalization'])),
        'go_attempted':go_attempted}


def _mutex_closed(events,expected_name):
    names=['CreateMutexExW','WaitForSingleObject','ReleaseMutex','CloseHandle']
    _require(type(events)is list and [row.get('api')for row in events]==names,'recovery.version_mutex_unclosed')
    for row in events:
        _require(row.get('outcome')=='returned'and type(row.get('result'))is int
            and type(row.get('started_ns'))is int and type(row.get('returned_ns'))is int
            and row['returned_ns']>=row['started_ns'],'recovery.version_mutex_unclosed')
    _require(events[0]['result']>0 and events[1]['result']==0 and events[2]['result']!=0 and events[3]['result']!=0
        and events[0].get('name')==expected_name and events[0].get('inherited')is False
        and events[0].get('initial_owner')is False and events[0].get('desired_access')==0x00100001
        and type(events[1].get('timeout_ms'))is int and 0<=events[1]['timeout_ms']<=5000
        and events[3].get('kind')=='root_mutex'
        and all(events[i]['returned_ns']<=events[i+1]['started_ns']for i in range(3)),
        'recovery.version_mutex_unclosed')


def _closed_synchronous_trace(physical):
    from .bundle_recovery_original import verify_trace
    records=verify_trace(physical)
    previous=-1
    for row in records:
        _require(type(row)is dict and type(row.get('started_ns'))is int and type(row.get('returned_ns'))is int
            and previous<=row['started_ns']<=row['returned_ns']
            and not any(key in row for key in('post_observation_error','post_observation_errors','close_error')),
            'recovery.version_io_unresolved')
        previous=row['returned_ns'];api=row.get('api')
        if api in{'NtCreateFile','NtSetInformationFile','NtFlushBuffersFileEx'}:
            statuses=(row.get('return_status'),row.get('io_status'))
            _require(all(type(value)is str and len(value)==10 and value.startswith('0x')
                and all(c in'0123456789abcdef'for c in value[2:])and value!='0x00000103'for value in statuses),
                'recovery.version_io_unresolved') # STATUS_PENDING is never completed synchronous IO.
            if api=='NtCreateFile':
                _require(row.get('effect_state')in{'created','opened','not_committed_by_this_call'},'recovery.version_io_unresolved')
            elif api=='NtSetInformationFile':
                _require(row.get('effect_state')in{'committed','not_committed_by_this_call'},'recovery.version_io_unresolved')
            else:_require(type(row.get('accepted'))is bool,'recovery.version_io_unresolved')
        elif api=='WriteFile':
            _require(type(row.get('succeeded'))is bool and type(row.get('requested'))is int
                and 0<row['requested']<=1024**2 and type(row.get('reported_written'))is int
                and 0<=row['reported_written']<=row['requested'] and type(row.get('offset'))is int
                and 0<=row['offset']<=2*1024**3-row['requested'],'recovery.version_io_unresolved')
            NativeIdentity.parse(row.get('object_identity'))
        elif api=='SetEndOfFile':
            _require(type(row.get('succeeded'))is bool and type(row.get('length'))is int
                and 0<=row['length']<=2*1024**3,'recovery.version_io_unresolved')
            NativeIdentity.parse(row.get('object_identity'))
        else:_require(False,'recovery.version_io_unresolved')
    return records


def _verify_nonzero_version_quiescence(parent, completion):
    """Failure-only retained creation-HANDLE closure; never target success.

    Only a delivered full receipt/physical completion reaches this function.
    Abrupt death before that frame, live owners, unknown IO and missing trace
    remain refused. No existing zero-exit success predicate is relaxed.
    """
    witness=parent['process_witness']
    _require(type(witness) is dict and witness.get('process_witness_version')=='1.0'
        and type(witness.get('pid')) is int and witness['pid']==completion['pid']
        and type(witness.get('creation_filetime')) is int and witness['creation_filetime']>0
        and type(witness.get('wait_result')) is int and witness['wait_result']==0
        and witness.get('worker_exit_established') is True
        and type(witness.get('exit_code')) is int and 0<witness['exit_code']<=0xffffffff
        and witness['exit_code']!=259,
        'recovery.original_worker_not_quiescent')
    events=witness.get('events')
    expected=['GetProcessId','GetProcessTimes','GetProcessId','GetProcessTimes',
        'WaitForSingleObject','GetExitCodeProcess','GetProcessId','GetProcessTimes']
    _require(type(events) is list and [e.get('api')for e in events]==expected,
        'recovery.original_worker_not_quiescent')
    for event in events:
        _require(event.get('outcome')=='returned' and type(event.get('started_ns')) is int
            and type(event.get('returned_ns')) is int and event['returned_ns']>=event['started_ns']
            and type(event.get('result')) is int and type(event.get('winerror')) is int,
            'recovery.original_worker_not_quiescent')
        wanted=(witness['pid'] if event['api']=='GetProcessId' else
            0 if event['api']=='WaitForSingleObject' else 1)
        _require(event['result']==wanted,'recovery.original_worker_not_quiescent')
    _require(all(events[i]['returned_ns']<=events[i+1]['started_ns']for i in range(len(events)-1)),
        'recovery.original_worker_not_quiescent')
    _require(parent.get('owner_finalization')=={'worker_stdin':'closed','worker_stdout':'closed',
        'worker_stderr':'closed','creation_handle':'closed','errors':[]},
        'recovery.original_owner_not_closed')


def verify_version_failure_completion(binding,projection,intent,plan,failure):
    """Authenticate no source by data alone; existing binding/failure checks first.

    Saved worker after-samples remain WORKER samples. No independent parent
    read is invented when a late parent observation failed. A new genuinely
    authenticated Native observation is mandatory under the existing guard.
    """
    from jsonschema import Draft202012Validator,FormatChecker
    from .failure import validate_native_parent_failure
    from .version_original_closure import version_original_role
    from .bundle_recovery_original import _wire,verify_quiescence
    from .parent_result import (validate_version1_parent_completion,validate_version2_parent_completion,
        _version1_physical_sample)
    from .worker import validate_version1_worker_ready,validate_version2_worker_ready
    role,manifest=version_original_role(binding)
    validate_native_parent_failure(binding,failure)
    from ...canonical import profile_digest
    _require(failure['run_id']==intent['run_id'] and failure['intent_digest']==profile_digest('intent',intent)
        and failure['effect_plan_digest']==intent['effect_plan_digest']
        and failure['operation_nonce']==intent['native_binding']['operation_nonce']
        and failure['outcome']=='unresolved'and failure['retry_authorized']is False,
        'recovery.version_failure_binding_mismatch')
    remote=failure['parent_error'];details=remote.get('details')
    _require(remote.get('code')=='ntfs.parent_execution_unresolved'and type(details)is dict
        and details.get('capture_version')in{'1.2','1.3'}and details.get('possible_dispatch')is True
        and details.get('retry_authorized')is False,'recovery.version_closed_capture_required')
    capture=details.get('version_closed_completion');parent=details['parent_partial']
    _require(type(capture)is dict and set(capture)==_CAPTURE_KEYS
        and (details['capture_version'],capture['version_failure_completion_version'])in{('1.2','1.0'),('1.3','1.1')}
        and capture['go_attempted']is True
        and capture['context_digest']==digest_bytes(canonical_bytes(parent['context']))
        and capture['completion_digest']==digest_bytes(canonical_bytes(parent['completion']))
        and capture['process_witness_digest']==digest_bytes(canonical_bytes(parent['process_witness'])),
        'recovery.version_closed_capture_required')
    context=parse_json_bytes(projection.context_bytes);effect=parse_json_bytes(projection.effect_bytes)
    _require(parent['context']==context and plan['effects']==[effect]
        and canonical_bytes(parent['completion'])==_wire(details['worker_completion_wire']),
        'recovery.version_failure_binding_mismatch')
    completion=parent['completion'];pid=completion['pid']
    grant=(manifest['root_grants'][0]if role=='Version1'else manifest['root_grants'])
    ready=validate_version1_worker_ready if role=='Version1'else validate_version2_worker_ready
    ready(_wire(details['worker_ready_wire']),context=context,grant_data=grant,effect=effect,
        content=projection.content_bytes,expected_pid=pid,timestamp=projection.timestamp)
    checker=validate_version1_parent_completion if role=='Version1'else validate_version2_parent_completion
    completion=checker(parent,context=context,grant_data=grant,effect=effect)
    # Only the captured, source-bound actual pre-report finalization facts are
    # used for closure. The original diagnostic and its errors stay untouched.
    closure_parent=dict(parent,owner_finalization=capture['owner_finalization_before_reporting'])
    if capture['version_failure_completion_version']=='1.1'and parent['process_witness'].get('exit_code')!=0:
        _verify_nonzero_version_quiescence(closure_parent,completion)
    else:
        verify_quiescence(closure_parent,completion)
    physical=completion['physical_evidence'];receipt=completion['effect_receipt']
    _require(receipt['started_at']==receipt['finished_at']==projection.timestamp
        and physical.get('handle_finalization')=='closed'and type(physical.get('remaining_handle_count'))is int
        and physical['remaining_handle_count']==0 and physical.get('mutation_session_state')=='sealed'
        and physical.get('finalization_errors')==[],'recovery.version_io_unresolved')
    schema=binding.registry.schema_document('https://phase-tool.local/schemas/effect-receipt.schema.json')
    Draft202012Validator(schema,registry=binding.registry.schema_registry(),format_checker=FormatChecker()).validate(receipt)
    records=_closed_synchronous_trace(physical)
    if role=='Version1':
        from .root_lock import root_mutex_name
        from .worker import _grant
        _require(physical.get('mutex_state')=='closed','recovery.version_mutex_unclosed')
        _mutex_closed(physical.get('mutex_events'),root_mutex_name(_grant(grant)))
        mutex_events=[physical['mutex_events']]
        rows={name:_version1_physical_sample(physical[field],grant,effect[key]['relative_locator'])
            for name,field,key in(('current','after','target'),('archive','archive_after','archive_target'))}
        _require(receipt['after']==rows['current']['state']and receipt['archive_after']==rows['archive']['state'],
            'recovery.version_failure_binding_mismatch')
        identities={name:row['native']['native_identity']for name,row in rows.items()}
        _require(identities['current']is None or identities['archive']is None
            or identities['current']!=identities['archive'],'ntfs.version1_current_archive_alias')
    else:
        from .version2_observation import _version2_grants,_version2_targets,validate_version2_triple
        from .root_lock import root_mutex_name
        grants=_version2_grants(grant);targets=_version2_targets(effect);mutexes=physical.get('mutexes')
        _require(type(mutexes)is list and len(mutexes)==2
            and [row.get('name')for row in mutexes]==sorted(root_mutex_name(g)for g in grants.values())
            and all(row.get('state')=='closed'for row in mutexes),'recovery.version_mutex_unclosed')
        for row in mutexes:_mutex_closed(row.get('events'),row['name'])
        mutex_events=[row['events']for row in mutexes]
        rows={name:_version1_physical_sample(physical['after'][name],grants[root].as_dict(),locator)
            for name,(root,locator)in targets.items()}
        rows=validate_version2_triple(rows,grant,effect)
        _require(all(receipt[field]==rows[name]['state']for name,field in(
            ('current','after'),('old_object','archive_after'),('new_object','content_object_after'))),
            'recovery.version_failure_binding_mismatch')
        identities={name:row['native']['native_identity']for name,row in rows.items()}
    _require(all(max(events[1]['returned_ns']for events in mutex_events)<=row['started_ns']
        <=row['returned_ns']<=min(events[2]['started_ns']for events in mutex_events)for row in records),
        'recovery.version_io_outside_mutex')
    return {'closure_kind':'validated_parent_failure_completion','target_identities':identities,
        'parent':closure_parent,'worker_after_samples':rows,'physical':physical,
        'source':'EXPLICIT_CLOSED_CAPTURE_NOT_TERMINAL_PROOF_OR_TARGET_SUCCESS'}
