"""Native bundle v1 effect in the pending existing-Core slice.

One stage, unchanged phase_bundle_v1 owner/manifest, one directory NOREPLACE
publication. No cleanup/retry, alternate evidence owner or document versions.
Only the closed authenticated bundle worker may supply its checked input role.
"""

from ...bundle import MANIFEST_NAME, OWNER_NAME, MAX_MEMBERS, MAX_DEPTH, parse_manifest
from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...paths import safe_relative_locator
from ..bundle_create import stage_name
from ..exclusive_create import _receipt, _unknown
from .bundle_observation import verify_bundle_handle, _BundleHandlePins
from .file_create import _MutationTrace, NativeFileCreateOutcomeUnavailable
from .mutating import NativeMutationIO
from .native import _require
from .root_lock import NativeRootMutex
from .scoped import NativeScopedTarget
from .uncertainty import _diagnostic


def _bundle_mutation_call(io,trace,errors,method,*args,_pins=None,**kwargs):
    created=None;adopted=False
    try:
        result=method(*args,**kwargs)
        if _pins is not None:
            created=result
            _pins.hold(created)
            adopted=True
    except BaseException:
        if created is not None and not adopted:
            try:created.close()
            except BaseException as secondary:errors.append(secondary)
        try:trace.collect(io)
        except BaseException as secondary:errors.append(secondary)
        raise  # Preserve native/adoption primary even if trace collection fails.
    trace.collect(io)
    return result


def execute_bundle_create(grant, effect, source, *, run_id, timestamp):
    from .bundle_execution import _BundleWorkerInput, _bundle_projection_value
    _require(type(source) is _BundleWorkerInput,'ntfs.original_bundle_projection_required')
    source._check()
    value=_bundle_projection_value(source.projection)
    _require(source._go_attempted and not source.complete
        and value['context']['run_id']==run_id and value['timestamp']==timestamp
        and canonical_bytes(value['grant'])==canonical_bytes(grant.as_dict())
        and canonical_bytes(value['effect'])==canonical_bytes(effect)
        and value['contract']['id'] in {'bundle_create.v1','bundle_create.v2'},'ntfs.worker_go_binding_mismatch')
    bundle2=value['context']['worker_version']=='1.5'
    manifest_raw=source.projection.manifest_bytes
    manifest=parse_manifest(manifest_raw)
    locator=safe_relative_locator(effect['target']['relative_locator'])
    plan_digest=value['context']['effect_plan_digest']
    io=NativeMutationIO();trace=_MutationTrace(_maximum_creates=MAX_MEMBERS*MAX_DEPTH+3)
    lock=NativeRootMutex(io,grant)
    before,after=_unknown(),_unknown();before_native=after_native=None
    status='indeterminate';error=None;primary=None;errors=[];written=0
    stage_id=None;stage_locator=None;rename=None;namespace_flushed=[]
    observed_before=False
    def invoke(method,*args,**kwargs):
        return _bundle_mutation_call(io,trace,errors,method,*args,**kwargs)
    def write_file(directory,name,data):
        nonlocal written
        with _BundleHandlePins() as pins:
            handle=invoke(io.create_exclusive,directory,name,directory=False,
                expected_parent=io.identity(directory),_pins=pins)
            identity=io.identity(handle);offset=0
            while offset<len(data):
                lock.assert_held()
                count=invoke(io.write_chunk,handle,data[offset:offset+256*1024],offset=offset,expected=identity)
                offset+=count;written+=count
            invoke(io.flush_file,handle,identity)
            _require(io.hash_file(handle,len(data))==(digest_bytes(data),len(data)),
                'ntfs.bundle_metadata_changed')
    try:
        with lock:
            with NativeScopedTarget(io,grant,locator,namespace_flush=True) as scope:
                # One actual bound before sample, never a POSIX projection.
                try:existing=io.child(scope.parent,scope.name,directory=True)
                except Exception as caught:
                    from ...errors import PhaseError
                    if not isinstance(caught,PhaseError) or caught.code!='ntfs.open_failed' or caught.details!={'ntstatus':'0xc0000034'}:raise
                    before={'known':True,'exists':False,'digest':None,'length':None,'head_token':None}
                    before_native={'exists':False,'native_identity':None}
                else:
                    with existing:
                        identity=io.identity(existing)
                        before_native=verify_bundle_handle(io,existing,expected_identity=identity)
                        scope.assert_directory_name(existing,identity)
                        before={'known':True,'exists':True,'digest':before_native['manifest_digest'],
                            'length':before_native['manifest_length'],'head_token':None}
                observed_before=True
                if before['exists']:
                    status='failed_no_effect';after=before.copy();after_native=before_native
                    error='target.destination_exists'
                else:
                    name=stage_name(run_id,effect)
                    stage_locator='/'.join((*locator.split('/')[:-1],name))
                    scope.assert_bound();lock.assert_held()
                    with _BundleHandlePins() as stage_pins:
                        stage=invoke(io.create_exclusive,scope.parent,name,directory=True,
                            expected_parent=scope.parent_identity,delete_access=True,_pins=stage_pins)
                        stage_id=io.identity(stage)
                        pair=io.directory_stat_identity(stage,stage_id)
                        owner=canonical_bytes({'owner_version':'1.0','run_id':run_id,
                            'plan_digest':plan_digest,'device':pair['device'],'inode':pair['inode']})
                        write_file(stage,OWNER_NAME,owner);write_file(stage,MANIFEST_NAME,manifest_raw)
                        # Existing bounded membership/depth controls determine the
                        # exact directory tree; no outside parents are provisioned.
                        directories={'' : stage}
                        expected_dirs=set()
                        for item in manifest['members']:
                            parts=item['path'].split('/')
                            expected_dirs.update('/'.join(parts[:i])for i in range(1,len(parts)))
                        with _BundleHandlePins() as children:
                            for path in sorted(expected_dirs,key=lambda x:(len(x.split('/')),x)):
                                parent,name=path.rsplit('/',1) if '/'in path else ('',path)
                                lock.assert_held();scope.assert_bound()
                                directories[path]=invoke(io.create_exclusive,
                                    directories[parent],name,directory=True,
                                    expected_parent=io.identity(directories[parent]),_pins=children)
                            for item in manifest['members']:
                                parent,name=item['path'].rsplit('/',1) if '/'in item['path'] else ('',item['path'])
                                directory=directories[parent]
                                with _BundleHandlePins() as member_pins:
                                    handle=invoke(io.create_exclusive,directory,name,directory=False,
                                        expected_parent=io.identity(directory),_pins=member_pins)
                                    identity=io.identity(handle);offset=0
                                    while True:
                                        chunk=source.next_member_chunk(item['path'])
                                        if chunk is None:break  # Empty member still owns a real created file.
                                        position=0
                                        while position<len(chunk):
                                            lock.assert_held();scope.assert_bound()
                                            count=invoke(io.write_chunk,handle,chunk[position:],offset=offset,expected=identity)
                                            position+=count;offset+=count;written+=count
                                    _require(offset==item['length'],'ntfs.bundle_member_length_mismatch')
                                    invoke(io.flush_file,handle,identity)
                                    _require(io.hash_file(handle,item['length'])==(item['digest'],item['length']),
                                        'bundle.member_mismatch')
                            source.finish_payload()  # Aggregate replay END BEFORE any consumer commit.
                            for path in sorted(directories,key=lambda x:len(x.split('/')),reverse=True):
                                directory=directories[path]
                                invoke(io.flush_namespace,directory,io.identity(directory))
                        # All member/child handles closed before directory rename.
                        stage_native=verify_bundle_handle(io,stage,expected_identity=stage_id,
                            expected_manifest=manifest_raw,run_id=run_id,plan_digest=plan_digest)
                        scope.assert_bound();lock.assert_held()
                        if bundle2:
                            # The same Core must durably save/read BOTH existing
                            # prepared records before the sole consumer commit.
                            # Root mutex and stage DELETE HANDLE remain retained.
                            source.checkpoint_prepared(stage_native)
                            scope.assert_bound();lock.assert_held()
                        # Sole publication point; no copy/delete or replacement fallback.
                        rename=invoke(io.rename,stage,scope.parent,scope.name,
                            expected_source=stage_id,expected_parent=scope.parent_identity,replace=False)
                        invoke(io.flush_namespace,scope.parent,scope.parent_identity)
                        namespace_flushed.append('target_parent')
                        after_native=verify_bundle_handle(io,stage,expected_identity=stage_id,
                            expected_manifest=manifest_raw,run_id=run_id,plan_digest=plan_digest)
                        scope.assert_directory_name(stage,stage_id);lock.assert_held()
                        after={'known':True,'exists':True,'digest':after_native['manifest_digest'],
                            'length':after_native['manifest_length'],'head_token':None}
                        status='applied_verified'
            lock.assert_held()
    except BaseException as caught:
        primary=caught;status='indeterminate';after=_unknown();after_native=None
    finally:
        # Consume only the same healthy authorized stream, without target writes.
        try:
            if not source.complete:source.finish_remaining()
        except BaseException as caught:errors.append(caught)
        try:trace.collect(io)
        except BaseException as caught:errors.append(caught)
        try:io.seal_mutations()
        except BaseException as caught:errors.append(caught)
    closed=not io._handles and not getattr(io,'_bundle_stat_ownership_unknown',False) and lock.state=='closed' and io.mutation_state=='sealed' and not errors
    if not closed:status='indeterminate';after=_unknown();after_native=None;error='ntfs.worker_finalization_unknown'
    primary_info=None if primary is None else _diagnostic(primary)
    if primary_info is not None:error=primary_info['code'] or 'ntfs.native_execution_failed'
    physical={'native_bundle_create_version':'1.1' if bundle2 else '1.0','run_id':run_id,'effect_id':effect['effect_id'],
        'grant':grant.as_dict(),'locator':locator,'before':before_native,'after':after_native,
        'stage_locator':stage_locator,'stage_identity':None if stage_id is None else stage_id.as_dict(),
        'rename':rename,'namespace_flushed':namespace_flushed,'mutation_trace':trace.snapshot(),
        'stream_binding':source.stream_facts(),'mutex_events':lock.events,'mutex_state':lock.state,
        'mutation_session_state':io.mutation_state,'handle_finalization':'closed'if closed else'unknown',
        'remaining_handle_count':len(io._handles),'unproven_handle_ownership':getattr(io,'_bundle_stat_ownership_unknown',False),
        'acknowledged_bytes_written_lower_bound':written,'primary_error':primary_info,
        'finalization_errors':[_diagnostic(e)for e in errors],'worker_exit_established':False}
    if bundle2:
        physical['prepared_checkpoint']={'message':source._prepared_message,'ack':source._prepared_ack}
    if not observed_before:
        failure=NativeFileCreateOutcomeUnavailable(physical)
        failure.primary_error=primary;failure.finalization_errors=tuple(errors)
        raise failure from primary
    receipt=_receipt(effect,run_id=run_id,timestamp=timestamp,status=status,attempted=True,
        before=before,after=after,bytes_written=None if status=='indeterminate' else written,
        verification_refs=['bundle.members.byte_verified']if status=='applied_verified'else[],
        error_code=error,error_message=error)
    return receipt,physical
