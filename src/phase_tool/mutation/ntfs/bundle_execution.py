"""Closed bundle worker/observation semantics for the pending Core slice.

One existing owner/process/GO, unchanged representation, finite stream. This is
not installed admission or a qualified storage route. Core remains evidence owner.
"""
from __future__ import annotations
import os
import base64
import re
import threading
import time
from ...bundle import MAX_MEMBERS, MAX_TOTAL_BYTES, parse_manifest, validate_members
from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from .handoff import _BundleControlProjection
from .native import NativeIdentity, _leaf, _require
from .worker import _grant, _worker_context
from .bundle_stream import _BundleTwoPassReceiver, _bundle_header, _bundle_token
from .file2_stream import _CHUNK
from .windows_pipe import WindowsPipeFrames

_BUNDLE1_CONTRACT = {'id': 'bundle_create.v1', 'version': '1.1.0', 'package_digest': 'sha256:6881c1d18034a71723df68873cf7c9762d92bd456cc586614de561a6282f6743'}
_BUNDLE1_MECHANISM = {'id': 'mechanism.bundle_create_v1', 'version': '1.1.0', 'package_digest': 'sha256:bb8dc72d3b6ff3d03352b3e033c714d6256d289cb452c81d03a66d7b930fee1d'}
_DIGEST = re.compile('sha256:[0-9a-f]{64}')
_EFFECT_FIELDS={'effect_id','kind','target','input_binding','content_source','content_digest',
    'content_length','preconditions','lock_scope','durability_policy_id','on_failure'}


def _bundle_context(value):
    return _worker_context(value,'1.4')


def _bundle_projection_value(projection):
    _require(type(projection) is _BundleControlProjection,'ntfs.original_bundle_projection_required')
    context=_bundle_context(parse_json_bytes(projection.context_bytes))
    grant=_grant(parse_json_bytes(projection.grant_bytes))
    effect=parse_json_bytes(projection.effect_bytes)
    contract=parse_json_bytes(projection.contract_bytes)
    _require(canonical_bytes(context)==projection.context_bytes
        and canonical_bytes(grant.as_dict())==projection.grant_bytes
        and canonical_bytes(effect)==projection.effect_bytes
        and canonical_bytes(contract)==projection.contract_bytes
        and contract==_BUNDLE1_CONTRACT,'ntfs.original_bundle_projection_binding')
    manifest=parse_manifest(projection.manifest_bytes)
    _require(set(effect)==_EFFECT_FIELDS and effect['kind']=='exclusive_create'
        and type(effect['effect_id']) is str and bool(effect['effect_id'])
        and type(effect['target']) is dict and set(effect['target'])=={'root_binding','relative_locator'}
        and effect['target']['root_binding']==grant.binding
        and effect['input_binding']==projection.input_binding=='payload'
        and type(effect['content_length']) is int and effect['content_length']==projection.content_length==len(projection.manifest_bytes)
        and effect['content_digest']==projection.content_digest==digest_bytes(projection.manifest_bytes)
        and effect['content_source']=={'kind':'frozen_input','binding_id':'payload','source_digest':projection.content_digest}
        and effect['preconditions']=={'existence':'absent','expected_digest':None,'expected_head':None,'concurrency_token':None}
        and effect['lock_scope'] is None and effect['durability_policy_id']=='file_data_synced'
        and effect['on_failure']=='stop_and_classify'
        and type(projection.timestamp) is str and 0<len(projection.timestamp)<=128,
        'ntfs.original_bundle_effect_required')
    safe_relative_locator(effect['target']['relative_locator'])
    for item in manifest['members']:
        for part in item['path'].split('/'):_leaf(part)
    return {'context':context,'grant':grant.as_dict(),'effect':effect,'contract':contract,
        'timestamp':projection.timestamp,'input_binding':'payload',
        'content_digest':projection.content_digest,'content_length':projection.content_length,
        'manifest_base64':base64.b64encode(projection.manifest_bytes).decode('ascii')}


def _bundle_projection_from_value(value):
    import base64
    _require(type(value) is dict and set(value)=={'context','grant','effect','contract','timestamp',
        'input_binding','content_digest','content_length','manifest_base64'},'ntfs.original_query_shape')
    _require(type(value['manifest_base64']) is str and len(value['manifest_base64'])<=1400000,
        'bundle.metadata_limit')
    manifest=base64.b64decode(value['manifest_base64'],validate=True)
    projection=_BundleControlProjection(canonical_bytes(value['context']),canonical_bytes(value['grant']),
        canonical_bytes(value['effect']),value['timestamp'],value['input_binding'],value['content_digest'],
        value['content_length'],manifest,canonical_bytes(value['contract']))
    _require(canonical_bytes(_bundle_projection_value(projection))==canonical_bytes(value),'ntfs.original_query_binding_mismatch')
    return projection


def _bundle_wire_header(projection,channel_id):
    value=_bundle_projection_value(projection);context=value['context']
    compact={k:context[k]for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
    return _bundle_header(context_bytes=canonical_bytes(compact),channel_id=channel_id,
        manifest_bytes=projection.manifest_bytes)[1]


def _bundle_ready_value(projection,channel_id,pid):
    value=_bundle_projection_value(projection)
    _require(type(pid) is int and pid>0,'ntfs.worker_pid_required')
    return {'worker_ready_version':'1.4','context':value['context'],'pid':pid,
        'grant_digest':digest_bytes(projection.grant_bytes),'effect_digest':digest_bytes(projection.effect_bytes),
        'content_digest':projection.content_digest,'content_length':projection.content_length,
        'timestamp':projection.timestamp,'ready_token':parse_json_bytes(_bundle_token(
            _bundle_wire_header(projection,channel_id),'ready'))}


def validate_bundle_worker_ready(raw,*,projection,channel_id,expected_pid):
    _require(type(raw) is bytes and 0<len(raw)<=16384,'ntfs.worker_frame_limit')
    value=parse_json_bytes(raw,maximum_bytes=16384)
    _require(canonical_bytes(value)==raw==canonical_bytes(_bundle_ready_value(projection,channel_id,expected_pid)),
        'ntfs.worker_ready_binding_mismatch')
    return value


class _BundleWorkerInput:
    """One borrowed worker pipe, exact ordered occurrences, no spool or owner."""
    def __init__(self,pipe,projection,channel_id,deadline_ns):
        _require(os.name=='nt' and type(pipe) is WindowsPipeFrames,'ntfs.windows_worker_pipe_required')
        _require(type(deadline_ns) is int and 0<deadline_ns-time.perf_counter_ns()<=30_000_000_000,
            'ntfs.worker_go_deadline')
        value=_bundle_projection_value(projection);context=value['context']
        compact={k:context[k]for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
        self._owner=os.getpid(),threading.get_ident()
        self._pipe,self._deadline=pipe,deadline_ns
        self.projection,self.channel_id=projection,channel_id
        self._context=context;self._manifest=parse_manifest(projection.manifest_bytes)
        self._receiver=_BundleTwoPassReceiver(context_bytes=canonical_bytes(compact),
            channel_id=channel_id,manifest_bytes=projection.manifest_bytes)
        self._header=_bundle_wire_header(projection,channel_id)
        self._first_attempted=self._go_attempted=False
        self._failed=self._complete=False;self._summary=None
        self._member=self._offset=self._released=0

    @property
    def complete(self):return self._complete

    def _check(self):
        _require(self._owner==(os.getpid(),threading.get_ident()) and not self._failed,
            'ntfs.bundle_source_unavailable')
        _require(time.perf_counter_ns()<self._deadline,'ntfs.pipe_deadline_expired')

    def first_pass(self):
        try:
            self._check();_require(not self._first_attempted,'ntfs.bundle_sequence_unavailable')
            self._first_attempted=True
            frames=2+sum((m['length']+_CHUNK-1)//_CHUNK+2 for m in self._manifest['members'])
            for _ in range(frames):
                raw,_=self._pipe.receive_frame(self._deadline,maximum_bytes=2*1024**2)
                _require(self._receiver.feed(raw) is None,'ntfs.bundle_first_pass_release')
            return self._receiver.ready_frame()
        except BaseException:self._failed=True;raise

    def accept_go(self,raw):
        try:
            self._check();_require(self._first_attempted and not self._go_attempted,'ntfs.bundle_sequence_unavailable')
            self._go_attempted=True
            expected={'command':'execute_bundle','context':self._context,
                'rewound_token':parse_json_bytes(_bundle_token(self._header,'rewound')),
                'go_token':parse_json_bytes(_bundle_token(self._header,'go'))}
            _require(type(raw) is bytes and 0<len(raw)<=16384 and raw==canonical_bytes(expected),
                'ntfs.worker_go_binding_mismatch')
            self._receiver.accept_rewound(canonical_bytes(expected['rewound_token']))
            self._receiver.accept_go(canonical_bytes(expected['go_token']))
        except BaseException:self._failed=True;raise

    def next_member_chunk(self,path):
        try:
            self._check()
            _require(self._go_attempted and not self._complete
                and self._member<len(self._manifest['members']),'ntfs.bundle_sequence_unavailable')
            member=self._manifest['members'][self._member]
            _require(path==member['path'],'ntfs.bundle_member_order_mismatch')
            raw,_=self._pipe.receive_frame(self._deadline,maximum_bytes=2*1024**2)
            chunk=self._receiver.feed(raw)
            if chunk is None:
                _require(self._offset==member['length'] and self._receiver._index==self._member+1,
                    'ntfs.bundle_member_incomplete')
                self._member+=1;self._offset=0
                return None
            _require(type(chunk) is tuple and len(chunk)==3 and chunk[0]==path
                and type(chunk[1]) is int and chunk[1]==self._offset
                and type(chunk[2]) is bytes and 0<len(chunk[2])<=_CHUNK
                and self._offset+len(chunk[2])<=member['length'],'ntfs.bundle_member_binding_mismatch')
            self._offset+=len(chunk[2]);self._released+=len(chunk[2])
            return chunk[2]
        except BaseException:self._failed=True;raise

    def finish_payload(self):
        try:
            self._check()
            _require(self._go_attempted and not self._complete and self._member==len(self._manifest['members']),
                'ntfs.bundle_members_incomplete')
            raw,_=self._pipe.receive_frame(self._deadline,maximum_bytes=2*1024**2)
            _require(self._receiver.feed(raw) is None,'ntfs.bundle_extra_frame')
            self._summary=self._receiver.finish();self._complete=True
            return dict(self._summary)
        except BaseException:self._failed=True;raise

    def finish_remaining(self):
        self._check()
        while self._member<len(self._manifest['members']):
            path=self._manifest['members'][self._member]['path']
            while self.next_member_chunk(path) is not None:pass
        if not self._complete:self.finish_payload()
        return dict(self._summary)

    def stream_facts(self):
        return {'protocol':'phase.native.bundle.bytes','version':'1.0',
            'header_digest':digest_bytes(self._header),'channel_id':self.channel_id,
            'manifest_digest':self.projection.content_digest,'manifest_length':self.projection.content_length,
            'member_count':len(self._manifest['members']),'total_length':self._manifest['total_length'],
            'released_bytes':self._released,'complete':self._complete,'failed':self._failed,
            'summary':None if self._summary is None else dict(self._summary)}


def run_bundle_worker(pipe,projection,channel_id,*,_transfer_deadline_ns):
    from .file_create import NativeFileCreateOutcomeUnavailable
    from .bundle_effect import execute_bundle_create
    from .uncertainty import _diagnostic
    _require(os.name=='nt' and type(pipe) is WindowsPipeFrames,'ntfs.windows_worker_pipe_required')
    value=_bundle_projection_value(projection);binding=value['context']
    primary=transport_error=close_error=None
    try:
        try:
            source=_BundleWorkerInput(pipe,projection,channel_id,_transfer_deadline_ns)
            source.first_pass()
            pipe.send_frame(canonical_bytes(_bundle_ready_value(projection,channel_id,os.getpid())),_transfer_deadline_ns)
            raw,_=pipe.receive_frame(_transfer_deadline_ns,maximum_bytes=16384)
            source.accept_go(raw)
            receipt,evidence=execute_bundle_create(_grant(value['grant']),value['effect'],source,
                run_id=binding['run_id'],timestamp=value['timestamp'])
            completion={'worker_completion_version':'1.4','context':binding,'pid':os.getpid(),
                'effect_receipt':receipt,'physical_evidence':evidence,'error':None,'worker_exit_established':False}
        except BaseException as error:
            primary=error
            completion={'worker_completion_version':'1.4','context':binding,'pid':os.getpid(),
                'effect_receipt':None,'physical_evidence':error.evidence
                    if isinstance(error,NativeFileCreateOutcomeUnavailable)else None,
                'error':_diagnostic(error),'worker_exit_established':False}
        raw=canonical_bytes(completion)
        _require(len(raw)<=512*1024,'ntfs.worker_completion_limit')
        pipe.send_frame(raw,_transfer_deadline_ns)
    except BaseException as error:transport_error=error
    finally:
        try:pipe.seal()
        except BaseException as error:close_error=error
    if transport_error is not None or close_error is not None:
        failure=PhaseError('ntfs.worker_completion_or_finalization_unavailable',details={
            'primary':None if primary is None else _diagnostic(primary),
            'transport':None if transport_error is None else _diagnostic(transport_error),
            'finalization':None if close_error is None else _diagnostic(close_error),
            'worker_exit_established':False})
        failure.primary_error=primary
        failure.transport_error=transport_error
        failure.finalization_error=close_error
        raise failure from (transport_error if transport_error is not None else close_error)


def validate_bundle_observation(raw,grant_data,locator,*,projection=None):
    grant=_grant(grant_data);locator=safe_relative_locator(locator)
    _require(type(raw) is dict and set(raw)=={'bundle_observation_version','state','native',
        'grant','locator','handles_finalized'} and raw['bundle_observation_version']=='1.0'
        and canonical_bytes(raw['grant'])==canonical_bytes(grant_data)
        and raw['locator']==locator and raw['handles_finalized'] is True,'ntfs.bundle_observer_binding_mismatch')
    state,native=raw['state'],raw['native']
    _require(type(state) is dict and set(state)=={'known','exists','digest','length','head_token'}
        and state['known'] is True and type(state['exists']) is bool and state['head_token'] is None
        and type(native) is dict and type(native.get('exists')) is bool and native['exists'] is state['exists'],
        'ntfs.bundle_observer_response_shape')
    if not state['exists']:
        _require(native=={'exists':False,'native_identity':None} and state['digest'] is None
            and state['length'] is None,'ntfs.bundle_observer_response_shape')
    else:
        _require(set(native)=={'exists','native_identity','manifest_digest','manifest_length','owner',
            'stat_identity','member_count','total_length','member_observations_digest'},'ntfs.bundle_observer_response_shape')
        identity=NativeIdentity.parse(native['native_identity'])
        _require(identity.volume_serial==grant.root_identity.volume_serial
            and type(state['length']) is int and 0<state['length']<=1024**2
            and type(native['manifest_length']) is int and native['manifest_length']==state['length']
            and type(state['digest']) is str and _DIGEST.fullmatch(state['digest']) is not None
            and native['manifest_digest']==state['digest']
            and type(native['member_count']) is int and 1<=native['member_count']<=MAX_MEMBERS
            and type(native['total_length']) is int and 0<=native['total_length']<=MAX_TOTAL_BYTES
            and type(native['member_observations_digest']) is str
            and _DIGEST.fullmatch(native['member_observations_digest']) is not None,
            'ntfs.bundle_observer_response_shape')
        pair=native['stat_identity'];owner=native['owner']
        _require(type(pair) is dict and set(pair)=={'device','inode'}
            and type(pair['device']) is int and pair['device']==identity.volume_serial
            and type(pair['inode']) is int and pair['inode']>0
            and pair['inode']==int.from_bytes(bytes.fromhex(identity.file_id),'little')
            and type(owner) is dict and set(owner)=={'owner_version','run_id','plan_digest','device','inode'}
            and owner['owner_version']=='1.0' and type(owner['device']) is int and type(owner['inode']) is int
            and owner['device']==pair['device'] and owner['inode']==pair['inode']
            and type(owner['run_id']) is str and type(owner['plan_digest']) is str
            and _DIGEST.fullmatch(owner['plan_digest']) is not None,'bundle.owner_mismatch')
        from ...evidence import validate_run_id
        validate_run_id(owner['run_id'])
        if projection is not None:
            value=_bundle_projection_value(projection);manifest=parse_manifest(projection.manifest_bytes)
            _require(state['digest']==projection.content_digest and state['length']==projection.content_length
                and owner['run_id']==value['context']['run_id']
                and owner['plan_digest']==value['context']['effect_plan_digest']
                and native['member_count']==len(manifest['members'])
                and native['total_length']==manifest['total_length'],'ntfs.bundle_result_binding_mismatch')
    return parse_json_bytes(canonical_bytes(raw))


def validate_bundle_worker_completion(raw,*,context,grant_data,effect,expected_pid):
    from .worker import _frame
    binding=_bundle_context(context);grant=_grant(grant_data)
    _require(type(expected_pid) is int and expected_pid>0,'ntfs.worker_pid_required')
    value=_frame(raw,{'worker_completion_version','context','pid','effect_receipt',
        'physical_evidence','error','worker_exit_established'})
    _require(value['worker_completion_version']=='1.4' and canonical_bytes(value['context'])==canonical_bytes(binding)
        and type(value['pid']) is int and value['pid']==expected_pid
        and value['worker_exit_established'] is False,'ntfs.worker_completion_binding_mismatch')
    receipt,physical,error=value['effect_receipt'],value['physical_evidence'],value['error']
    if receipt is not None:
        _require(type(receipt) is dict and receipt.get('run_id')==binding['run_id']
            and receipt.get('effect_id')==effect['effect_id'] and receipt.get('kind')=='exclusive_create',
            'ntfs.worker_receipt_binding_mismatch')
    if physical is not None:
        _require(type(physical) is dict and physical.get('native_bundle_create_version')=='1.0'
            and physical.get('run_id')==binding['run_id'] and physical.get('effect_id')==effect['effect_id']
            and canonical_bytes(physical.get('grant'))==canonical_bytes(grant.as_dict())
            and physical.get('locator')==effect['target']['relative_locator']
            and physical.get('worker_exit_established') is False,'ntfs.worker_physical_binding_mismatch')
    if error is None:_require(receipt is not None and physical is not None,'ntfs.worker_completion_incomplete')
    else:
        _require(type(error) is dict and set(error)=={'type','code','message','details'}
            and type(error['type']) is str and type(error['message']) is str
            and (error['code'] is None or type(error['code']) is str)
            and type(error['details']) is dict and receipt is None,'ntfs.worker_error_binding_mismatch')
    return value


def validate_bundle_parent_completion(reply,*,context,grant_data,effect):
    _bundle_context(context)
    _require(type(reply) is dict and set(reply)=={'parent_execution_version','context','completion',
        'process_witness','owner_finalization','post_observation','ingress_state'}
        and reply['parent_execution_version']=='1.4' and canonical_bytes(reply['context'])==canonical_bytes(context)
        and reply['ingress_state']=='consumed','ntfs.parent_execution_binding_mismatch')
    completion=reply['completion']
    _require(type(completion) is dict and type(completion.get('pid')) is int,'ntfs.worker_completion_binding_mismatch')
    checked=validate_bundle_worker_completion(canonical_bytes(completion),context=context,
        grant_data=grant_data,effect=effect,expected_pid=completion['pid'])
    if checked['error'] is not None:raise PhaseError('ntfs.effect_outcome_unavailable',details={'worker_error':checked['error']})
    _require(checked['effect_receipt'].get('attempted') is True
        and checked['effect_receipt'].get('started_at')==checked['effect_receipt'].get('finished_at'),
        'ntfs.worker_receipt_binding_mismatch')
    return checked


def validate_bundle_parent_finalization(reply,checked,*,grant_data,effect,projection,expected_channel_id=None):
    _bundle_projection_value(projection)
    witness=reply['process_witness']
    _require(type(witness) is dict and witness.get('process_witness_version')=='1.0'
        and type(witness.get('pid')) is int and witness['pid']==checked['pid']
        and type(witness.get('wait_result')) is int and witness['wait_result']==0
        and witness.get('worker_exit_established') is True
        and type(witness.get('exit_code')) is int and witness['exit_code']==0,'ntfs.worker_exit_not_established')
    _require(reply['owner_finalization']=={'worker_stdin':'closed','worker_stdout':'closed','worker_stderr':'closed',
        'creation_handle':'closed','errors':[]},'ntfs.worker_finalization_unknown')
    physical,receipt=checked['physical_evidence'],checked['effect_receipt']
    success=receipt['status']=='applied_verified'
    observed=validate_bundle_observation(reply['post_observation'],grant_data,
        effect['target']['relative_locator'],projection=projection if success else None)
    _require(physical['handle_finalization']=='closed' and type(physical['remaining_handle_count']) is int
        and physical['remaining_handle_count']==0 and physical['unproven_handle_ownership'] is False
        and physical['mutex_state']=='closed' and physical['mutation_session_state']=='sealed'
        and physical['finalization_errors']==[],'ntfs.worker_finalization_unknown')
    manifest=parse_manifest(projection.manifest_bytes);stream=physical['stream_binding']
    _require(type(stream) is dict and set(stream)=={'protocol','version','header_digest','channel_id',
        'manifest_digest','manifest_length','member_count','total_length','released_bytes','complete','failed','summary'}
        and stream['protocol']=='phase.native.bundle.bytes' and stream['version']=='1.0'
        and stream['complete'] is True and stream['failed'] is False
        and type(stream['manifest_length']) is int and stream['manifest_length']==projection.content_length
        and stream['manifest_digest']==projection.content_digest
        and type(stream['member_count']) is int and stream['member_count']==len(manifest['members'])
        and type(stream['total_length']) is int and type(stream['released_bytes']) is int
        and stream['total_length']==stream['released_bytes']==manifest['total_length'],
        'ntfs.bundle_replay_incomplete')
    channel=stream['channel_id']
    _require(type(channel) is str and re.fullmatch('[0-9a-f]{32}',channel) is not None
        and (expected_channel_id is None or channel==expected_channel_id),'ntfs.bundle_channel_required')
    _require(stream['header_digest']==digest_bytes(_bundle_wire_header(projection,channel))
        and canonical_bytes(stream['summary'])==canonical_bytes({'accepted_manifest_digest':projection.content_digest,
            'accepted_members':len(manifest['members']),'accepted_payload_length':manifest['total_length']}),
        'ntfs.bundle_end_mismatch')
    worker_after=validate_bundle_observation({'bundle_observation_version':'1.0','state':receipt['after'],
        'native':physical['after'],'grant':grant_data,'locator':physical['locator'],'handles_finalized':True},
        grant_data,effect['target']['relative_locator'],projection=projection if success else None)
    _require(canonical_bytes(worker_after)==canonical_bytes(observed),'ntfs.worker_observer_mismatch')
    trace=physical['mutation_trace']
    _require(type(trace) is dict and trace.get('capture_complete') is True
        and type(trace.get('unacknowledged_records_upper_bound')) is int
        and trace['unacknowledged_records_upper_bound']==0 and trace.get('capture_errors')==[],
        'ntfs.worker_physical_binding_mismatch')
    if success:
        rename=physical['rename'];identity=NativeIdentity.parse(physical['stage_identity'])
        _require(identity.as_dict()==observed['native']['native_identity']
            and type(rename) is dict and rename.get('api')=='NtSetInformationFile' and rename.get('class')==10
            and rename.get('replace_if_exists') is False and type(rename.get('rename_flags')) is int
            and rename['rename_flags']==0 and rename.get('return_status')==rename.get('io_status')=='0x00000000'
            and rename.get('effect_state')=='committed' and rename.get('source_identity')==identity.as_dict()
            and rename.get('leaf')==effect['target']['relative_locator'].split('/')[-1]
            and physical['namespace_flushed']==['target_parent'] and physical['primary_error'] is None
            and receipt['error'] is None and receipt['verification_refs']==['bundle.members.byte_verified'],
            'ntfs.worker_physical_binding_mismatch')
        expected_bytes=projection.content_length+len(canonical_bytes(observed['native']['owner']))+manifest['total_length']
        _require(type(receipt['bytes_written']) is int and type(physical['acknowledged_bytes_written_lower_bound']) is int
            and receipt['bytes_written']==physical['acknowledged_bytes_written_lower_bound']==expected_bytes
            and receipt['after']=={'known':True,'exists':True,'digest':projection.content_digest,
                'length':projection.content_length,'head_token':None},'ntfs.worker_receipt_binding_mismatch')
    return observed


def bundle_postcondition(observation,*,grant_data,effect,projection):
    """One pure projection reused by Core postvalidation and proof inspection."""
    expected=effect['content_digest']
    try:
        value=validate_bundle_observation(observation,grant_data,effect['target']['relative_locator'],projection=projection)
        _require(value['state']['exists'] is True and value['state']['digest']==expected
            and value['state']['length']==effect['content_length'],'bundle.verification_failed')
    except (PhaseError,TypeError,KeyError):
        return 'fail','bundle.verification_failed',expected,None,['bundle.verification_failed']
    return 'pass','validation.pass',expected,expected,[]
