"""UNQUALIFIED fixed file2 worker/observation semantics for the connected slice.

No public writer or admission: only the authenticated fixed installation may
reach this role. Data, hashes and READY never authenticate that installation.
The existing Core/parent own intent, gate, process lifetime, receipts and inspect.
"""
from __future__ import annotations

import os
import re
import threading
import time

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from ...streaming import FILE_LIMIT
from .handoff import _OriginalControlProjection
from .native import NativeIdentity, _require
from .worker import _file2_context, _grant
from .file2_stream import _File2TwoPassReceiver, _header, _token, _CHUNK, _MAX_FRAME
from .windows_pipe import WindowsPipeFrames


_EFFECT_FIELDS = {'effect_id','kind','target','input_binding','content_source',
    'content_digest','content_length','preconditions','lock_scope',
    'durability_policy_id','on_failure'}
_VALUE_FIELDS = {'context','grant','effect','timestamp','input_binding',
    'content_digest','content_length'}
_DIGEST = re.compile('sha256:[0-9a-f]{64}')


def _file2_effect(grant_data, effect, content_digest, content_length):
    """Closed structural correspondence, never a contract/authority substitute."""
    grant=_grant(grant_data)
    _require(type(content_length) is int and 0<=content_length<=FILE_LIMIT
        and type(content_digest) is str and _DIGEST.fullmatch(content_digest) is not None,
        'ntfs.file2_content_bound')
    _require(type(effect) is dict and set(effect)==_EFFECT_FIELDS
        and effect['kind']=='exclusive_create'
        and type(effect['effect_id']) is str and bool(effect['effect_id'])
        and type(effect['target']) is dict and set(effect['target'])=={'root_binding','relative_locator'}
        and effect['target']['root_binding']==grant.binding
        and effect['input_binding']=='payload'
        and effect['content_source']=={'kind':'frozen_input','binding_id':'payload','source_digest':content_digest}
        and type(effect['content_length']) is int and effect['content_length']==content_length
        and effect['content_digest']==content_digest
        and effect['preconditions']=={'existence':'absent','expected_digest':None,
            'expected_head':None,'concurrency_token':None}
        and effect['lock_scope'] is None and effect['durability_policy_id']=='file_data_synced'
        and effect['on_failure']=='stop_and_classify','ntfs.original_file2_effect_required')
    safe_relative_locator(effect['target']['relative_locator'])
    return grant


def _file2_projection_value(projection):
    _require(type(projection) is _OriginalControlProjection,'ntfs.original_file2_projection_required')
    for raw,maximum in ((projection.context_bytes,4096),(projection.grant_bytes,65536),
                        (projection.effect_bytes,2*1024**2)):
        _require(type(raw) is bytes and 0<len(raw)<=maximum,'ntfs.original_immutable_bytes_required')
        _require(canonical_bytes(parse_json_bytes(raw,maximum_bytes=maximum))==raw,
            'ntfs.original_noncanonical_bytes')
    context=_file2_context(parse_json_bytes(projection.context_bytes))
    grant=parse_json_bytes(projection.grant_bytes)
    effect=parse_json_bytes(projection.effect_bytes)
    _file2_effect(grant,effect,projection.content_digest,projection.content_length)
    _require(projection.input_binding=='payload' and type(projection.timestamp) is str
        and 0<len(projection.timestamp)<=128,'ntfs.worker_original_timestamp_required')
    return {'context':context,'grant':grant,'effect':effect,'timestamp':projection.timestamp,
        'input_binding':'payload','content_digest':projection.content_digest,
        'content_length':projection.content_length}


def _file2_projection_from_value(value):
    _require(type(value) is dict and set(value)==_VALUE_FIELDS,'ntfs.original_query_shape')
    projection=_OriginalControlProjection(canonical_bytes(value['context']),
        canonical_bytes(value['grant']),canonical_bytes(value['effect']),value['timestamp'],
        value['input_binding'],value['content_digest'],value['content_length'])
    _require(canonical_bytes(_file2_projection_value(projection))==canonical_bytes(value),
        'ntfs.original_query_binding_mismatch')
    return projection


def _file2_header(projection, channel_id):
    value=_file2_projection_value(projection);context=value['context']
    compact={k:context[k] for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
    return _header(context_bytes=canonical_bytes(compact),channel_id=channel_id,
        content_digest=value['content_digest'],content_length=value['content_length'])


def _file2_ready_value(projection, channel_id, pid):
    value=_file2_projection_value(projection)
    _require(type(pid) is int and pid>0,'ntfs.worker_pid_required')
    header_digest=digest_bytes(_file2_header(projection,channel_id))
    return {'worker_ready_version':'1.2','context':value['context'],'pid':pid,
        'grant_digest':digest_bytes(projection.grant_bytes),
        'effect_digest':digest_bytes(projection.effect_bytes),
        'content_digest':value['content_digest'],'content_length':value['content_length'],
        'timestamp':value['timestamp'],
        'ready_token':parse_json_bytes(_token(header_digest,'ready'))}


def validate_file2_worker_ready(raw, *, projection, channel_id, expected_pid):
    """Parent obtains expected_pid from its retained creation HANDLE, not READY."""
    _require(type(raw) is bytes and 0<len(raw)<=16384,'ntfs.worker_frame_limit')
    value=parse_json_bytes(raw,maximum_bytes=16384)
    _require(canonical_bytes(value)==raw
        and canonical_bytes(value)==canonical_bytes(_file2_ready_value(projection,channel_id,expected_pid)),
        'ntfs.worker_ready_binding_mismatch')
    return value


class _File2WorkerInput:
    """Borrowed fixed worker pipe; no path/FD/callback/limit from a request.

    Before first-pass END and exact GO, it performs data I/O only. A verified
    replay chunk is returned before any native partial write can consume it.
    It never owns/closes the pipe or claims process exit/physical success.
    """
    def __init__(self, pipe, projection, channel_id, deadline_ns):
        _require(os.name=='nt' and type(pipe) is WindowsPipeFrames,
            'ntfs.windows_worker_pipe_required')
        _require(type(deadline_ns) is int
            and 0<deadline_ns-time.perf_counter_ns()<=30_000_000_000,
            'ntfs.worker_go_deadline')
        value=_file2_projection_value(projection)
        self._owner=os.getpid(),threading.get_ident()
        self._pipe,self._deadline=pipe,deadline_ns
        self.projection,self.channel_id=projection,channel_id
        self._context=value['context'];self.content_digest=value['content_digest']
        self.content_length=value['content_length']
        compact={k:self._context[k] for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
        self._receiver=_File2TwoPassReceiver(context_bytes=canonical_bytes(compact),
            channel_id=channel_id,content_digest=self.content_digest,content_length=self.content_length)
        self._header_digest=digest_bytes(_file2_header(projection,channel_id))
        self._first_attempted=self._go_attempted=False
        self._failed=self._complete=False
        self._summary=None;self._released=0

    def _check(self):
        _require(self._owner==(os.getpid(),threading.get_ident()) and not self._failed,
            'ntfs.file2_source_unavailable')
        _require(time.perf_counter_ns()<self._deadline,'ntfs.pipe_deadline_expired')

    @property
    def complete(self):
        return self._complete

    def first_pass(self):
        try:
            self._check()
            _require(not self._first_attempted,'ntfs.file2_sequence_unavailable')
            self._first_attempted=True
            for _ in range((self.content_length+_CHUNK-1)//_CHUNK+2):
                raw,_=self._pipe.receive_frame(self._deadline,maximum_bytes=_MAX_FRAME)
                _require(self._receiver.feed(raw) is None,'ntfs.file2_sequence_unavailable')
            token=self._receiver.ready_frame()
            _require(token==_token(self._header_digest,'ready'),'ntfs.file2_ready_mismatch')
            return token
        except BaseException:
            self._failed=True
            raise

    def accept_go(self,raw):
        try:
            self._check()
            _require(self._first_attempted and not self._go_attempted,'ntfs.file2_sequence_unavailable')
            self._go_attempted=True
            _require(type(raw) is bytes and 0<len(raw)<=16384,'ntfs.worker_frame_limit')
            value=parse_json_bytes(raw,maximum_bytes=16384)
            expected={'command':'execute_file2','context':self._context,
                'rewound_token':parse_json_bytes(_token(self._header_digest,'rewound')),
                'go_token':parse_json_bytes(_token(self._header_digest,'go'))}
            _require(canonical_bytes(value)==raw==canonical_bytes(expected),'ntfs.worker_go_binding_mismatch')
            self._receiver.accept_rewound(canonical_bytes(value['rewound_token']))
            self._receiver.accept_go(canonical_bytes(value['go_token']))
        except BaseException:
            self._failed=True
            raise

    def next_chunk(self):
        try:
            self._check()
            _require(self._go_attempted and not self._complete,'ntfs.file2_sequence_unavailable')
            raw,_=self._pipe.receive_frame(self._deadline,maximum_bytes=_MAX_FRAME)
            chunk=self._receiver.feed(raw)
            if chunk is None:
                _require(self._released==self.content_length,'ntfs.file2_replay_incomplete')
                self._summary=self._receiver.finish();self._complete=True
                return None
            _require(type(chunk) is bytes and 0<len(chunk)<=_CHUNK
                and self._released+len(chunk)<=self.content_length,'ntfs.file2_chunk_bound')
            self._released+=len(chunk)
            return chunk
        except BaseException:
            self._failed=True
            raise

    def finish_remaining(self):
        """Drain only the SAME healthy replay after a native refusal/failure.

        No resynchronization after a poisoned receiver. This bounded drain lets
        the sole sender finish without a replacement pump/thread/queue. It
        performs no target operation or retry and still shares the same window.
        """
        self._check()
        if not self._complete:
            while self.next_chunk() is not None:
                pass
        return dict(self._summary)

    def stream_facts(self):
        return {'protocol':'phase.native.file2.bytes','version':'1.0',
            'header_digest':self._header_digest,'channel_id':self.channel_id,'content_digest':self.content_digest,
            'content_length':self.content_length,'released_bytes':self._released,
            'complete':self._complete,'failed':self._failed,
            'summary':None if self._summary is None else dict(self._summary)}


def validate_file2_worker_completion(raw, *, context, grant_data, effect, expected_pid):
    from .worker import _frame
    binding=_file2_context(context);grant=_file2_effect(grant_data,effect,
        effect.get('content_digest'),effect.get('content_length'))
    _require(type(expected_pid) is int and expected_pid>0,'ntfs.worker_pid_required')
    value=_frame(raw,{'worker_completion_version','context','pid','effect_receipt',
        'physical_evidence','error','worker_exit_established'})
    _require(value['worker_completion_version']=='1.2'
        and canonical_bytes(value['context'])==canonical_bytes(binding)
        and type(value['pid']) is int and value['pid']==expected_pid
        and value['worker_exit_established'] is False,'ntfs.worker_completion_binding_mismatch')
    receipt,physical,error=value['effect_receipt'],value['physical_evidence'],value['error']
    if receipt is not None:
        _require(type(receipt) is dict and receipt.get('run_id')==binding['run_id']
            and receipt.get('effect_id')==effect['effect_id'] and receipt.get('kind')=='exclusive_create',
            'ntfs.worker_receipt_binding_mismatch')
    if physical is not None:
        _require(type(physical) is dict and physical.get('native_file_create_version')=='2.0'
            and physical.get('run_id')==binding['run_id'] and physical.get('effect_id')==effect['effect_id']
            and canonical_bytes(physical.get('grant'))==canonical_bytes(grant.as_dict())
            and physical.get('locator')==effect['target']['relative_locator']
            and physical.get('worker_exit_established') is False,'ntfs.worker_physical_binding_mismatch')
    if error is None:
        _require(receipt is not None and physical is not None,'ntfs.worker_completion_incomplete')
    else:
        _require(type(error) is dict and set(error)=={'type','code','message','details'}
            and type(error['type']) is str and type(error['message']) is str
            and (error['code'] is None or type(error['code']) is str)
            and type(error['details']) is dict and receipt is None,'ntfs.worker_error_binding_mismatch')
    return value


def run_file2_worker(pipe,projection,channel_id,*,_transfer_deadline_ns):
    """One fixed authenticated-role invocation, no NativeIO until first pass + GO."""
    from .file_create import NativeFileCreateOutcomeUnavailable,execute_file2_create
    from .uncertainty import _diagnostic
    _require(os.name=='nt' and type(pipe) is WindowsPipeFrames,'ntfs.windows_worker_pipe_required')
    value=_file2_projection_value(projection)
    primary=transport_error=close_error=None
    binding=value['context'];completion=None
    try:
        try:
            source=_File2WorkerInput(pipe,projection,channel_id,_transfer_deadline_ns)
            source.first_pass()  # Full actual SHA/length/END, no native API.
            pipe.send_frame(canonical_bytes(_file2_ready_value(projection,channel_id,os.getpid())),
                _transfer_deadline_ns)
            raw,_=pipe.receive_frame(_transfer_deadline_ns,maximum_bytes=16384)
            source.accept_go(raw)
            receipt,evidence=execute_file2_create(_grant(value['grant']),value['effect'],source,
                run_id=binding['run_id'],timestamp=value['timestamp'])
            completion={'worker_completion_version':'1.2','context':binding,'pid':os.getpid(),
                'effect_receipt':receipt,'physical_evidence':evidence,'error':None,
                'worker_exit_established':False}
        except BaseException as error:
            primary=error
            completion={'worker_completion_version':'1.2','context':binding,'pid':os.getpid(),
                'effect_receipt':None,'physical_evidence':error.evidence
                    if isinstance(error,NativeFileCreateOutcomeUnavailable) else None,
                'error':_diagnostic(error),'worker_exit_established':False}
        raw=canonical_bytes(completion)
        _require(len(raw)<=512*1024,'ntfs.worker_completion_limit')
        pipe.send_frame(raw,_transfer_deadline_ns)  # SAME window; never reset per frame.
    except BaseException as error:
        transport_error=error
    finally:
        try:pipe.seal()  # Entrypoint closes; parent proves actual retained-HANDLE exit.
        except BaseException as error:close_error=error
    if transport_error is not None or close_error is not None:
        raise PhaseError('ntfs.worker_completion_or_finalization_unavailable',details={
            'primary':None if primary is None else _diagnostic(primary),
            'transport':None if transport_error is None else _diagnostic(transport_error),
            'finalization':None if close_error is None else _diagnostic(close_error),
            'worker_exit_established':False}) from (transport_error or close_error)


def validate_file2_observation(raw, grant_data, locator):
    """Fixed2GiB hash scope; larger pre-existing objects truthfully have no digest."""
    grant=_grant(grant_data);locator=safe_relative_locator(locator)
    _require(type(raw) is dict and set(raw)=={'observation_version','state','native',
        'grant','locator','handles_finalized'} and raw['observation_version']=='2.0'
        and canonical_bytes(raw['grant'])==canonical_bytes(grant_data)
        and raw['locator']==locator and raw['handles_finalized'] is True,
        'ntfs.file2_observer_binding_mismatch')
    state,native=raw['state'],raw['native']
    _require(type(state) is dict and set(state)=={'known','exists','digest','length','head_token'}
        and state['known'] is True and type(state['exists']) is bool and state['head_token'] is None
        and type(native) is dict and type(native.get('exists')) is bool
        and native['exists'] is state['exists'],'ntfs.file2_observer_response_shape')
    if state['exists']:
        _require(set(native)=={'exists','native_identity','length','digest','link_count'}
            and type(native['link_count']) is int and native['link_count']==1
            and type(state['length']) is int and state['length']>=0
            and type(native['length']) is int and native['length']==state['length']
            and native['digest']==state['digest'],'ntfs.file2_observer_response_shape')
        identity=NativeIdentity.parse(native['native_identity'])
        _require(identity.volume_serial==grant.root_identity.volume_serial,'ntfs.observer_volume_mismatch')
        if state['length']<=FILE_LIMIT:
            _require(type(state['digest']) is str and _DIGEST.fullmatch(state['digest']) is not None,
                'ntfs.observer_digest_required')
        else:
            _require(state['digest'] is None,'ntfs.file2_observer_response_shape')
    else:
        _require(native=={'exists':False,'native_identity':None}
            and state['digest'] is None and state['length'] is None,'ntfs.file2_observer_response_shape')
    return parse_json_bytes(canonical_bytes(raw))


def observe_file2_file(grant,locator,*,expected=None):
    """Actual separate native RO role; same namespace scope/hash/read API."""
    from .native import NativeIO
    from .scoped import NativeRootGrant,NativeScopedTarget
    from .file_create import _observe
    _require(type(grant) is NativeRootGrant,'ntfs.invalid_root_grant')
    locator=safe_relative_locator(locator)
    if expected is not None:
        _require(type(expected) is NativeIdentity,'ntfs.invalid_identity')
        NativeIdentity.parse(expected.as_dict())
    io=NativeIO()
    with NativeScopedTarget(io,grant,locator) as scope:
        state,proof=_observe(scope,expected=expected,_maximum_bytes=FILE_LIMIT)
    _require(not io._handles,'ntfs.observer_handle_finalization_unknown')
    return validate_file2_observation({'observation_version':'2.0','state':state,'native':proof,
        'grant':grant.as_dict(),'locator':locator,'handles_finalized':True},grant.as_dict(),locator)


def validate_file2_parent_completion(reply,*,context,grant_data,effect):
    _file2_context(context)
    _require(type(reply) is dict and set(reply)=={'parent_execution_version','context','completion',
        'process_witness','owner_finalization','post_observation','ingress_state'}
        and reply['parent_execution_version']=='1.2'
        and canonical_bytes(reply['context'])==canonical_bytes(context)
        and reply['ingress_state']=='consumed','ntfs.parent_execution_binding_mismatch')
    completion=reply['completion']
    _require(type(completion) is dict and type(completion.get('pid')) is int,
        'ntfs.worker_completion_binding_mismatch')
    checked=validate_file2_worker_completion(canonical_bytes(completion),context=context,
        grant_data=grant_data,effect=effect,expected_pid=completion['pid'])
    if checked['error'] is not None:
        raise PhaseError('ntfs.effect_outcome_unavailable',details={'worker_error':checked['error']})
    receipt=checked['effect_receipt']
    _require(receipt.get('attempted') is True
        and receipt.get('started_at')==receipt.get('finished_at'),'ntfs.worker_receipt_binding_mismatch')
    return checked


def validate_file2_parent_finalization(reply,checked,*,grant_data,effect,expected_channel_id=None):
    """Same process owner + separate full observer, new closed file2 evidence tag.

    Dispatch supplies its actual channel ID. Historical inspection reconstructs
    the captured data binding; it does not authenticate a process from a token.
    """
    witness=reply['process_witness']
    _require(type(witness) is dict and witness.get('process_witness_version')=='1.0'
        and type(witness.get('pid')) is int and witness['pid']==checked['pid']
        and type(witness.get('wait_result')) is int and witness['wait_result']==0
        and witness.get('worker_exit_established') is True
        and type(witness.get('exit_code')) is int and witness['exit_code']==0,
        'ntfs.worker_exit_not_established')
    _require(reply['owner_finalization']=={'worker_stdin':'closed','worker_stdout':'closed',
        'worker_stderr':'closed','creation_handle':'closed','errors':[]},'ntfs.worker_finalization_unknown')
    observed=validate_file2_observation(reply['post_observation'],grant_data,
        effect['target']['relative_locator'])
    physical,receipt=checked['physical_evidence'],checked['effect_receipt']
    _require(physical['handle_finalization']=='closed'
        and type(physical['remaining_handle_count']) is int and physical['remaining_handle_count']==0
        and physical['mutex_state']=='closed' and physical['mutation_session_state']=='sealed'
        and type(physical['finalization_errors']) is list and not physical['finalization_errors'],
        'ntfs.worker_finalization_unknown')
    stream=physical.get('stream_binding')
    _require(type(stream) is dict and set(stream)=={'protocol','version','header_digest','channel_id',
        'content_digest','content_length','released_bytes','complete','failed','summary'}
        and stream['protocol']=='phase.native.file2.bytes' and stream['version']=='1.0'
        and stream['complete'] is True and stream['failed'] is False
        and type(stream['content_length']) is int and type(stream['released_bytes']) is int
        and stream['released_bytes']==stream['content_length']==effect['content_length']
        and stream['content_digest']==effect['content_digest'],'ntfs.file2_replay_incomplete')
    channel_id=stream['channel_id']
    _require(type(channel_id) is str and re.fullmatch('[0-9a-f]{32}',channel_id) is not None
        and (expected_channel_id is None or channel_id==expected_channel_id),
        'ntfs.file2_channel_required')
    projection=_OriginalControlProjection(canonical_bytes(checked['context']),canonical_bytes(grant_data),
        canonical_bytes(effect),receipt['started_at'],'payload',effect['content_digest'],effect['content_length'])
    _require(stream['header_digest']==digest_bytes(_file2_header(projection,channel_id))
        and canonical_bytes(stream['summary'])==canonical_bytes({
            'accepted_content_digest':effect['content_digest'],
            'accepted_content_length':effect['content_length'],
            'accepted_chunks':(effect['content_length']+_CHUNK-1)//_CHUNK}),
        'ntfs.file2_end_mismatch')
    worker_after=validate_file2_observation({'observation_version':'2.0','state':receipt['after'],
        'native':physical['after'],'grant':physical['grant'],'locator':physical['locator'],
        'handles_finalized':True},grant_data,effect['target']['relative_locator'])
    _require(canonical_bytes(worker_after['state'])==canonical_bytes(observed['state'])
        and canonical_bytes(worker_after['native'])==canonical_bytes(observed['native']),
        'ntfs.worker_observer_mismatch')
    trace=physical['mutation_trace']
    _require(type(trace) is dict and type(trace.get('acknowledged_recorded_event_count')) is int
        and trace['acknowledged_recorded_event_count']>=1 and trace.get('capture_complete') is True
        and type(trace.get('unacknowledged_records_upper_bound')) is int
        and trace['unacknowledged_records_upper_bound']==0 and trace.get('capture_errors')==[],
        'ntfs.worker_physical_binding_mismatch')
    if receipt['status']=='applied_verified':
        _require(physical['primary_error'] is None
            and receipt['error'] is None and type(receipt['bytes_written']) is int
            and receipt['bytes_written']==effect['content_length']
            and receipt['verification_refs']==['native.file.readback']
            and receipt['after']=={'known':True,'exists':True,'digest':effect['content_digest'],
                'length':effect['content_length'],'head_token':None},'ntfs.worker_receipt_binding_mismatch')
    return observed
