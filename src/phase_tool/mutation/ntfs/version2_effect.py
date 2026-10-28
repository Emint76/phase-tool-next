"""Version2 physical objects-first publication for the fixed Windows worker.

Core owns intent, receipts and recovery. This step owns no journal or history
index. Call only after original validation and the single consumed GO. Errors
seal mutations; an unknown rename is never retried or followed by deletion.
"""
from contextlib import ExitStack

from ...canonical import digest_bytes
from ...evidence import validate_run_id
from ..object_store_publish import _receipt, _same, _unknown
from .file_create import _MutationTrace, _observe, NativeFileCreateOutcomeUnavailable
from .mutating import NativeMutationIO
from .native import NativeIdentity, _require
from .root_lock import NativeRootMutex, root_mutex_name
from .scoped import NativeScopedTarget
from .uncertainty import _diagnostic
from .version1_effect import _native_state
from .version2_observation import (_LIMIT, _version2_grants, _version2_targets,
    observe_version2_triple)


def _effect_binding(grants, effect, content):
    accepted=_version2_grants(grants)
    targets=_version2_targets(effect)
    _require(type(content) is bytes and len(content)<=_LIMIT
        and effect.get('input_binding') is None and effect.get('content_digest')==digest_bytes(content)
        and effect.get('content_blob_digest')==digest_bytes(content)
        and type(effect.get('content_length')) is int and effect['content_length']==len(content)
        and type(effect.get('archive_length')) is int and 0<=effect['archive_length']<=_LIMIT
        and effect.get('preconditions')=={'existence':'present','expected_digest':effect['archive_digest'],
            'expected_head':None,'concurrency_token':effect['archive_digest']}
        and effect.get('lock_scope')=='publish.'+digest_bytes(targets['current'][1].encode()).removeprefix('sha256:')
        and effect.get('durability_policy_id')=='file_and_directory_synced'
        and effect.get('on_failure')=='stop_and_classify','ntfs.version2_effect_binding')
    return accepted,targets


def execute_version2(grants, effect, content, *, run_id, timestamp):
    accepted,targets=_effect_binding(grants,effect,content)
    validate_run_id(run_id)
    _require(type(timestamp) is str and bool(timestamp),'ntfs.invalid_effect_timestamp')
    io,trace=NativeMutationIO(),_MutationTrace(_maximum_creates=6)
    locks=[NativeRootMutex(io,g) for g in sorted(accepted.values(),key=root_mutex_name)]
    before={name:_unknown() for name in targets};after=dict(before)
    before_native={name:None for name in targets};after_native=dict(before_native)
    secondary_errors=[];primary_error=None;error=None;status='indeterminate';written=0
    temporary_locators={};flushed=[];replace_completed=False

    def call(function,*args,_adopt_into=None,**kwargs):
        for lock in locks:lock.assert_held()
        created=None;adopted=False
        try:
            result=function(*args,**kwargs)
            if _adopt_into is not None:
                created=result
                # Register before diagnostics and any further I/O.
                _adopt_into.enter_context(created)
                adopted=True
        except BaseException:
            if created is not None and not adopted:
                try:created.close()
                except BaseException as secondary:secondary_errors.append(secondary)
            try:trace.collect(io)
            except BaseException as secondary:secondary_errors.append(secondary)
            raise  # Preserve the native/adoption primary if trace collection also failed.
        trace.collect(io)
        return result

    def observe(scope):
        # Reuse pinned observation, with the Version2 limit applied to its facts.
        state,native=_observe(scope,_maximum_bytes=_LIMIT)
        _require(not state['exists'] or state['length']<=_LIMIT,'ntfs.version2_file_too_large')
        return state,native

    def write_staged(scope,data,role,pins):
        nonlocal written
        token=digest_bytes((run_id+':'+role).encode())[7:39]
        name='phase-v2-staging-'+token
        parent_locator=targets[role][1].rsplit('/',1)[0]+'/' if '/' in targets[role][1] else ''
        temporary_locators[role]=parent_locator+name
        handle=call(io.create_exclusive,scope.parent,name,directory=False,
            expected_parent=scope.parent_identity,delete_access=True,_adopt_into=pins)
        identity=io.identity(handle)
        offset=0
        while offset<len(data):
            count=call(io.write_chunk,handle,data[offset:],offset=offset,expected=identity)
            offset+=count;written+=count
        call(io.flush_file,handle,identity)
        digest,length=io.hash_file(handle,len(data))
        facts=io.assert_object(handle,directory=False,expected=identity)
        _require(digest==digest_bytes(data) and length==facts['length']==len(data)
            and facts['links']==1,'publish.temporary_verification_failed')
        scope.assert_bound()
        return handle,identity

    try:
        with ExitStack() as owners:
            for lock in locks:owners.enter_context(lock)
            try:
                initial=observe_version2_triple(grants,effect)
                before={name:row['state'] for name,row in initial.items()}
                before_native={name:row['native'] for name,row in initial.items()}
                after=dict(before);after_native=dict(before_native)
                old_ok=_same(before['old_object'],effect['archive_digest'],effect['archive_length'])
                new_ok=_same(before['new_object'],effect['content_digest'],len(content))
                if _same(before['current'],effect['content_digest'],len(content)) and old_ok and new_ok:
                    status='applied_verified'
                elif not _same(before['current'],effect['archive_digest'],effect['archive_length']):
                    status='failed_no_effect';error={'code':'publish.current_mismatch','message':'publish.current_mismatch'}
                elif (before['old_object']['exists'] and not old_ok) or (before['new_object']['exists'] and not new_ok):
                    status='failed_no_effect';error={'code':'publish.object_conflict','message':'publish.object_conflict'}
                else:
                    with ExitStack() as pins:
                        current_scope=pins.enter_context(NativeScopedTarget(io,accepted['current_root'],
                            targets['current'][1],namespace_flush=True))
                        current_id=NativeIdentity.parse(before_native['current']['native_identity'])
                        current=pins.enter_context(current_scope.open_file(expected=current_id))
                        sampled,_=_native_state(io,current_scope,current,current_id,effect['archive_length'])
                        _require(sampled==before['current'],'publish.current_changed_during_object_capture')
                        old_content=b''.join(io.read_chunks(current,effect['archive_length']))
                        _require(len(old_content)==effect['archive_length'] and digest_bytes(old_content)==effect['archive_digest'],
                            'publish.current_changed_during_object_capture')
                        current_scope.assert_file_name(current,current_id)
                        objects={}
                        for role,data,digest in [('old_object',old_content,effect['archive_digest']),
                                                 ('new_object',content,effect['content_digest'])]:
                            # Equal old/new digests use one physical object, as
                            # specified by the existing content-addressed contract.
                            if role=='new_object' and targets[role]==targets['old_object']:
                                objects[role]=objects['old_object']
                                after[role]=after['old_object'];after_native[role]=after_native['old_object']
                                continue
                            scope=call(NativeScopedTarget,io,accepted['objects_root'],
                                targets[role][1],namespace_flush=True,
                                _create_ancestors=not before[role]['exists'],_adopt_into=pins)
                            observed,native=observe(scope)
                            _require(observed==before[role] and native==before_native[role],
                                'publish.object_changed_before_publication')
                            if observed['exists']:
                                _require(_same(observed,digest,len(data)),'publish.object_conflict')
                                identity=NativeIdentity.parse(native['native_identity'])
                                handle=pins.enter_context(scope.open_file(expected=identity))
                            else:
                                handle,identity=write_staged(scope,data,role,pins)
                                call(io.rename_noreplace,handle,scope.parent,scope.name,
                                    expected_source=identity,expected_parent=scope.parent_identity)
                                call(io.flush_namespace,scope.parent,scope.parent_identity)
                                flushed.append(role)
                            after[role],after_native[role]=_native_state(io,scope,handle,identity,len(data))
                            _require(_same(after[role],digest,len(data)),'publish.object_verification_failed')
                            objects[role]=(scope,handle,identity)
                        staged,staged_id=write_staged(current_scope,content,'current',pins)
                        latest,_=_native_state(io,current_scope,current,current_id,effect['archive_length'])
                        _require(latest==before['current'],'publish.current_verification_failed')
                        for scope,handle,identity in objects.values():scope.assert_file_name(handle,identity)
                        # The original current read handle remains pinned across
                        # the native final replace. No close-and-blind-rename fallback.
                        call(io.rename,staged,current_scope.parent,current_scope.name,
                            expected_source=staged_id,expected_parent=current_scope.parent_identity,replace=True)
                        replace_completed=True
                        call(io.flush_namespace,current_scope.parent,current_scope.parent_identity)
                        flushed.append('current')
                        after['current'],after_native['current']=_native_state(io,current_scope,staged,staged_id,len(content))
                        for role,(scope,handle,identity) in objects.items():
                            length=effect['archive_length'] if role=='old_object' else len(content)
                            after[role],after_native[role]=_native_state(io,scope,handle,identity,length)
                        verified=(_same(after['current'],effect['content_digest'],len(content))
                            and _same(after['old_object'],effect['archive_digest'],effect['archive_length'])
                            and _same(after['new_object'],effect['content_digest'],len(content)))
                        status='applied_verified' if verified else 'applied_unverified'
                        if not verified:error={'code':'verification.result_mismatch','message':'verification.result_mismatch'}
            except BaseException as caught:
                primary_error=caught;status='indeterminate';written=None
                try:io.seal_mutations()
                except BaseException as secondary:secondary_errors.append(secondary)
                after={name:_unknown() for name in targets};after_native={name:None for name in targets}
                try:
                    samples=observe_version2_triple(grants,effect)
                    after={name:row['state'] for name,row in samples.items()}
                    after_native={name:row['native'] for name,row in samples.items()}
                except BaseException as secondary:secondary_errors.append(secondary)
                raise
    except BaseException as caught:
        status='indeterminate';written=None
        if primary_error is None:primary_error=caught
        elif caught is not primary_error:secondary_errors.append(caught)
    finally:
        try:trace.collect(io)
        except BaseException as caught:secondary_errors.append(caught)
        try:io.seal_mutations()
        except BaseException as caught:secondary_errors.append(caught)
    # Pins, both mutexes and the mutation session have finished their attempts.
    # No exception formatting is allowed to interrupt that cleanup sequence.
    primary=None if primary_error is None else _diagnostic(primary_error)
    finalization_errors=[_diagnostic(caught) for caught in secondary_errors]
    if primary is not None:
        error={'code':primary['code'] or 'ntfs.native_execution_failed','message':primary['message']}
    closed=(not io._handles and all(lock.state=='closed' for lock in locks)
        and io.mutation_state=='sealed' and not finalization_errors)
    if not closed:
        status='indeterminate';error={'code':'ntfs.worker_finalization_unknown','message':'ntfs.worker_finalization_unknown'}
        after={name:_unknown() for name in targets};after_native={name:None for name in targets}
    evidence={'native_version2_effect_version':'1.0','run_id':run_id,'effect_id':effect['effect_id'],
        'grants':grants,'targets':{name:{'root_binding':binding,'relative_locator':locator}
            for name,(binding,locator) in targets.items()},'before':before_native,'after':after_native,
        'temporary_locators':temporary_locators,'namespace_flushed':flushed,'replace_completed':replace_completed,
        'mutation_trace':trace.snapshot(),'mutexes':[{'name':lock.name,'state':lock.state,'events':lock.events} for lock in locks],
        'mutation_session_state':io.mutation_state,'handle_finalization':'closed' if closed else 'unknown',
        'remaining_handle_count':len(io._handles),'primary_error':primary,'finalization_errors':finalization_errors,
        'worker_exit_established':False}
    if not all(row['known'] for row in before.values()):raise NativeFileCreateOutcomeUnavailable(evidence)
    return _receipt(effect,run_id=run_id,timestamp=timestamp,status=status,before=before['current'],after=after['current'],
        old_before=before['old_object'],old_after=after['old_object'],new_before=before['new_object'],new_after=after['new_object'],
        bytes_written=written,refs=['native.current.after','native.old_object.after','native.new_object.after'] if status=='applied_verified' else [],
        error_code=None if error is None else error['code'],error_message=None if error is None else error['message']),evidence
