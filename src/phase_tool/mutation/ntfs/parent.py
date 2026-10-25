"""DRAFT fixed Windows owner for ONE existing Core native control channel.
Not imported/executed/admitted. Requires the accepted immutable launch boundary;
metadata/READY/ACK matches never authenticate that boundary. No journal/queue,
receipt writer, effect retry, process search, respawn, terminate or history owner.
"""
from __future__ import annotations

import os
import base64
import re
import threading
import time

from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from .native import NativeIdentity, _require
from .worker import validate_worker_ready, validate_worker_completion, _grant
from .process_witness import WindowsProcessWitness
from .windows_pipe import WindowsPipeFrames
from .file_create import observe_file
from .parent_result import _observation, _require_command_run_binding

_COMMON = {'protocol','version','channel_id','sequence','kind','run_id','intent_digest'}
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_RUN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')


def _deadline():
    return time.perf_counter_ns()+30_000_000_000


class _NativeWindowsParent:
    """Transient owner of one Core ingress and at most one physical worker.

    Only the fixed accepted bootstrap constructs launch. Requests cannot supply
    a command, callback, implementation, profile, grant or effect. The Linux RO
    endpoint obtains the original tuple from existing Core evidence and parser.
    Separate native RO calls are performed by this owner, never by the worker.
    """
    def __init__(self, launch, core_pipe):
        from .bootstrap import _NativeAcceptedLaunch
        _require(not getattr(self,'_initialization_attempted',False),
            'ntfs.parent_initialization_consumed')
        self._initialization_attempted=True
        _require(os.name=='nt' and type(launch) is _NativeAcceptedLaunch
            and type(core_pipe) is WindowsPipeFrames,'ntfs.fixed_native_parent_required')
        self._owner=os.getpid(),threading.get_ident()
        self._launch,self._pipe=launch,core_pipe
        self._sequence=0
        self._failed=False
        self._version1=launch._version1
        self._channel_version='1.2' if launch.manifest['native_read_installation_version']=='1.2' else '1.1'
        self._inspection_only=launch._inspection_only
        _require(type(self._inspection_only) is bool,'ntfs.fixed_role_required')
        self._consumed=self._inspection_only  # Read role has no unused GO slot.
        self._spawn_attempted=False
        self._go_attempted=False
        self._worker=None
        self._worker_count=0
        self._worker_finalized=False
        self._finished=False
        self._no_dispatch_finished=False
        self._partial_bytes=None
        self._ready_wire=None
        self._completion_wire=None

    def _usable(self):
        _require(self._owner==(os.getpid(),threading.get_ident())
            and not self._failed and not self._finished,'ntfs.parent_unavailable')
        self._launch.check_runtime()

    def _request(self,raw):
        self._usable()
        _require(not self._no_dispatch_finished,'ntfs.parent_finish_consumed')
        value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
        _require(type(value) is dict and canonical_bytes(value)==raw,
            'ntfs.parent_request_shape')
        kind=value.get('kind')
        # Irreversibly consume before parsing/binding/spawn/read failure. A
        # buffered/repeated GO or finish cannot restore an unused worker slot.
        if kind in {'execute_file_create','execute_version1','finish_without_execution'}:
            _require(not self._inspection_only,'ntfs.inspection_only_operation_forbidden')
            _require(not self._consumed,'ntfs.parent_execution_consumed')
            self._consumed=True
        _require(_COMMON<=set(value) and value['protocol']=='phase.native.pipe'
            and value['version']==self._channel_version and value['channel_id']==self._launch.channel_id
            and type(value['sequence']) is int and value['sequence']==self._sequence+1
            and type(value['run_id']) is str and _RUN.fullmatch(value['run_id']) is not None,
            'ntfs.parent_request_binding_mismatch')
        self._sequence=value['sequence']
        if kind=='observe_file':
            _require(set(value)==_COMMON|{'root_binding','locator','expected_identity'}
                and value['intent_digest'] is None,'ntfs.parent_request_shape')
            grant=self._launch.root_grant
            _require(value['root_binding']==grant['root_binding'],'ntfs.effect_grant_mismatch')
            locator=safe_relative_locator(value['locator'])
            expected=(None if value['expected_identity'] is None
                else NativeIdentity.parse(value['expected_identity']))
            if self._version1:
                from .version1_observation import observe_version1_file,validate_version1_observation
                answer=validate_version1_observation(observe_version1_file(_grant(grant),locator,expected=expected),grant,locator)
            else:
                answer=_observation(observe_file(_grant(grant),locator,expected=expected),grant,locator)
        elif kind in {'execute_file_create','execute_version1'}:
            _require(kind==('execute_version1' if self._version1 else 'execute_file_create'),
                'ntfs.original_closed_role_required')
            _require(set(value)==_COMMON and value['run_id']==self._launch.run_id
                and type(value['intent_digest']) is str
                and _DIGEST.fullmatch(value['intent_digest']) is not None,
                'ntfs.parent_request_binding_mismatch')
            answer=self._execute(value['intent_digest'])
        elif kind=='finish_without_execution':
            _require(set(value)==_COMMON|{'operation_nonce','installation_digest'}
                and value['run_id']==self._launch.run_id
                and value['operation_nonce']==self._launch.operation_nonce
                and value['installation_digest']==self._launch.installation_digest
                and (value['intent_digest'] is None or (type(value['intent_digest']) is str
                    and _DIGEST.fullmatch(value['intent_digest']) is not None)),
                'ntfs.parent_request_binding_mismatch')
            # Only an actual RO check may attest absence; never infer it from
            # client state or use a planned original as executing handoff data.
            self._launch.verify_no_dispatch_original(value['intent_digest'])
            _require(not self._spawn_attempted and not self._go_attempted
                and self._worker is None and self._worker_count==0,
                'ntfs.parent_finish_after_spawn')
            self._launch.check_runtime()
            self._no_dispatch_finished=True
            answer={'finish_ack_version':'1.0','run_id':self._launch.run_id,
                'intent_digest':value['intent_digest'],'operation_nonce':self._launch.operation_nonce,
                'installation_digest':self._launch.installation_digest,'ingress_state':'consumed',
                'worker_started':False,'worker_spawn_attempted':False,'worker_count':0,
                'required_resources_finalized':True}
        else:
            raise PhaseError('ntfs.parent_operation_forbidden')
        self._usable()
        return {key:value[key] for key in _COMMON},answer

    def _execute(self,intent_digest):
        _require(not self._inspection_only,'ntfs.inspection_only_operation_forbidden')
        _require(self._consumed and not self._spawn_attempted,
            'ntfs.parent_execution_consumed')
        parsed=self._launch.read_original(intent_digest)
        context=parse_json_bytes(parsed.context_bytes)
        effect=parse_json_bytes(parsed.effect_bytes)
        grant=parse_json_bytes(parsed.grant_bytes)
        _require(context['run_id']==self._launch.run_id
            and context['intent_digest']==intent_digest
            and context['operation_nonce']==self._launch.operation_nonce
            and context['installation_digest']==self._launch.installation_digest
            and grant==self._launch.root_grant,'ntfs.parent_original_binding_mismatch')
        # Consume before Popen, READY parsing or any possible GO. Failed spawn
        # is terminal too; no second worker, fallback or replacement process.
        handshake_deadline=_deadline() if self._version1 else None
        self._spawn_attempted=True
        self._worker=self._launch.spawn_worker()
        self._worker_count=1
        witness=pipe=None
        completion=process_fact=None
        primary=None
        secondary=[]
        try:
            witness=WindowsProcessWitness(self._worker)
            pipe=self._launch.worker_pipe(self._worker)
            if self._version1:
                self._launch.send_worker_original(pipe,parsed,_handshake_deadline_ns=handshake_deadline)
            else:
                self._launch.send_worker_original(pipe,parsed)
            raw,_=pipe.receive_frame(handshake_deadline if self._version1 else _deadline(),maximum_bytes=512*1024)
            self._ready_wire=raw
            from .worker import validate_version1_worker_ready,validate_version1_worker_completion
            ready_check=validate_version1_worker_ready if self._version1 else validate_worker_ready
            completion_check=validate_version1_worker_completion if self._version1 else validate_worker_completion
            ready_check(raw,context=context,grant_data=grant,effect=effect,
                content=parsed.content_bytes,expected_pid=self._worker.pid,
                **({'timestamp':parsed.timestamp} if self._version1 else {}))
            self._go_attempted=True
            pipe.send_frame(canonical_bytes({'command':'execute_version1' if self._version1 else 'execute_file_create',
                'context':context}),handshake_deadline if self._version1 else _deadline())
            raw,_=pipe.receive_frame(_deadline(),maximum_bytes=512*1024)
            self._completion_wire=raw
            completion=completion_check(raw,context=context,grant_data=grant,effect=effect,
                expected_pid=self._worker.pid)
        except BaseException as error:
            primary=error
        finally:
            try:
                _require(witness is not None,'ntfs.worker_creation_witness_unavailable')
                process_fact=witness.wait_for_exit(60000)
                _require(process_fact['worker_exit_established'] is True
                    and process_fact['wait_result']==0 and process_fact['exit_code']==0,
                    'ntfs.worker_exit_not_established')
            except BaseException as error:
                if primary is None:primary=error
                else:secondary.append(error)
            # Only the retained actual HANDLE's positive exit permits ownership
            # finalization. Unknown owners stay retained; never kill/close them
            # and report that as quiescence. The unresolved original blocks GO.
            if process_fact is not None and process_fact['worker_exit_established'] is True:
                try:
                    self._launch.finalize_worker(self._worker,pipe)
                    self._worker_finalized=True
                except BaseException as error:
                    if primary is None:primary=error
                    else:secondary.append(error)
        # Retain structured partial facts BEFORE late RO/runtime/reporting failure.
        # This is transient diagnosis, never a second receipt or success proof.
        partial={'parent_execution_version':'1.1' if self._version1 else '1.0','context':context,'completion':completion,
            'process_witness':process_fact,'owner_finalization':{
                'worker_stdin':'closed' if self._worker_finalized else 'unknown',
                'worker_stdout':'closed' if self._worker_finalized else 'unknown',
                'worker_stderr':'closed' if self._worker_finalized else 'unknown',
                'creation_handle':'closed' if self._worker_finalized else 'unknown','errors':[]},
            'post_observation':None,'ingress_state':'consumed'}
        self._partial_bytes=canonical_bytes(partial)
        if primary is None:
            try:
                _require(completion is not None and self._worker_finalized,
                    'ntfs.worker_finalization_unknown')
                if self._version1:
                    from .version1_observation import observe_version1_file
                    from .parent_result import validate_version1_pair
                    after={'observation_pair_version':'1.0',
                        'current':observe_version1_file(_grant(grant),effect['target']['relative_locator']),
                        'archive':observe_version1_file(_grant(grant),effect['archive_target']['relative_locator'])}
                    validate_version1_pair(after,grant,effect)
                else:
                    after=observe_file(_grant(grant),effect['target']['relative_locator'])
                    _observation(after,grant,effect['target']['relative_locator'])
                partial['post_observation']=after
                self._partial_bytes=canonical_bytes(partial)
                self._launch.check_runtime()
            except BaseException as error:primary=error
        if primary is not None:
            from .uncertainty import _diagnostic
            partial['owner_finalization']['errors']=[_diagnostic(primary),*[_diagnostic(e) for e in secondary]]
            self._partial_bytes=canonical_bytes(partial)
            for error in secondary:
                try:primary.add_note('Native parent secondary: '+type(error).__name__)
                except BaseException:pass
            def captured(raw):
                if raw is None:return None
                from ...canonical import digest_bytes
                return {'sha256':digest_bytes(raw),'length':len(raw),
                    'bytes_base64':base64.b64encode(raw).decode('ascii')}
            raise PhaseError('ntfs.parent_execution_unresolved',details={
                'parent_partial':parse_json_bytes(self._partial_bytes),
                'worker_ready_wire':captured(self._ready_wire),
                'worker_completion_wire':captured(self._completion_wire),
                'possible_dispatch':self._go_attempted,'retry_authorized':False}) from primary
        return partial

    def serve(self):
        """Core requests and its final serialized response share owned framing.

        Stdout is only control; no concurrent stderr result drainer or queue.
        Core's final response is delivery, not a second canonical receipt. The
        bootstrap keeps all accepted code immutable until these processes exit.
        """
        try:
            while True:
                _require(self._owner==(os.getpid(),threading.get_ident()) and not self._finished,
                    'ntfs.parent_unavailable')
                self._launch.check_runtime()
                raw,_=self._pipe.receive_frame(_deadline())
                value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
                if type(value) is dict and value.get('protocol')=='phase.native.command':
                    # Admission rejection may precede any control request. An
                    # attempted execution still requires its consumed slot.
                    _require(not self._spawn_attempted or self._consumed,
                        'ntfs.parent_execution_unresolved')
                    self._consumed=True
                    from .parent_result import _native_file_result_mode, validate_native_file_result_delivery
                    invocation=getattr(self._launch,'invocation',None)
                    request=invocation.get('request') if type(invocation) is dict else None
                    expects_result=_native_file_result_mode(request)
                    if expects_result or value.get('version')=='1.1' or 'canonical_result' in value:
                        _require(self._inspection_only and expects_result,
                            'ntfs.file_result_request_version_required')
                        from ...installation import _native_registry_for_manifest
                        registry=_native_registry_for_manifest(self._launch._manifest_bytes,
                            self._launch.installation_digest)
                        validate_native_file_result_delivery(value,request=request,
                            run_id=self._launch.run_id,channel_id=self._launch.channel_id,
                            manifest_bytes=self._launch._manifest_bytes,
                            expected_manifest_digest=self._launch.installation_digest,registry=registry)
                        _require(canonical_bytes(value)==raw,'ntfs.parent_command_binding_mismatch')
                    else:
                        _require(set(value)=={'protocol','version','channel_id','run_id','result','exit_code'}
                            and value['version']=='1.0' and value['channel_id']==self._launch.channel_id
                            and value['run_id']==self._launch.run_id
                            and type(value['result']) is dict and type(value['exit_code']) is int
                            and value['result'].get('exit_code')==value['exit_code']
                            and canonical_bytes(value)==raw,'ntfs.parent_command_binding_mismatch')
                    _require_command_run_binding(value['result'],self._launch.run_id)
                    if (value['result'].get('run_id') is None
                            and value['result'].get('stage3_command_result_version')=='1.0'):
                        # Only THIS owner can establish no native worker/GO.
                        # Even a finalized worker forbids an unscoped refusal.
                        _require(self._spawn_attempted is False and self._go_attempted is False
                            and self._worker is None and type(self._worker_count) is int
                            and self._worker_count==0,'ntfs.parent_command_binding_mismatch')
                    if self._inspection_only:
                        _require(not self._failed and self._consumed
                            and not self._spawn_attempted and not self._go_attempted
                            and self._worker is None and self._worker_count==0,
                            'ntfs.inspection_delivery_unresolved')
                        _require(value['result'].get('command')=='inspect',
                            'ntfs.parent_command_binding_mismatch')
                        from ...command_result import validate_command_result
                        from ...installation import _native_registry_for_manifest
                        validate_command_result(value['result'],_native_registry_for_manifest(
                            self._launch._manifest_bytes,self._launch.installation_digest))
                    if self._failed or (self._spawn_attempted and not self._worker_finalized):
                        result=value['result']
                        _require(result.get('stage3_command_result_version')=='1.2'
                            and result.get('success') is False
                            and result.get('inspection_required') is True
                            and result.get('retry_authorized') is False
                            and type(result.get('exit_code')) is int and result['exit_code']==40
                            and value['exit_code']==40,
                            'ntfs.parent_uncertainty_delivery_required')
                    self._finished=True
                    # Ingress is consumed. The retained process owner performs
                    # the sole strict pipe seal after it establishes actual exit.
                    # Sealing here would make that checked finalization fail.
                    return value
                _require(not self._failed,'ntfs.parent_delivery_only')
                try:
                    common,answer=self._request(raw)
                except BaseException as error:
                    # ONE closed negative response, then delivery only. Never
                    # parse another GO, retry a worker or return a positive ACK.
                    self._failed=True
                    from .uncertainty import _diagnostic
                    record=_diagnostic(error)
                    common={key:value[key] for key in _COMMON} if _COMMON<=set(value) else None
                    _require(common is not None,'ntfs.parent_request_shape')
                    details=(error.details if isinstance(error,PhaseError) else {'primary':record})
                    remote={'code':getattr(error,'code',None) or 'ntfs.parent_operation_unresolved',
                        'message':'Native parent operation unresolved; inspect original, no retry',
                        'details':details}
                    response=common|{'ok':False,'value':None,'error':remote}
                else:
                    response=common|{'ok':True,'value':answer,'error':None}
                self._pipe.send_frame(canonical_bytes(response),_deadline())
        except BaseException:
            self._failed=True
            # Never fabricate a positive ACK or recover the control stream.
            raise
