"""Explicit UNCONSTRUCTED role/process shells, never a native installation.

No production qualification function/factory is patched or admitted. These
oracles call the bound method bodies with modeled admission/process boundaries;
they do NOT prove qualification, actual Windows lifetime or native effects.
Actual Core freeze/RO hash and real Linux pipes are separate component tests.
"""
import base64
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import os
from types import SimpleNamespace
import time
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator,FormatChecker

from phase_tool import streaming
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.errors import PhaseError
from phase_tool.mutation.broker import BrokerExecutionInterrupted
from phase_tool.mutation.exclusive_create import _receipt
from phase_tool.mutation.ntfs import authority,parent,file2_execution as execution,file2_stream as wire
from phase_tool.mutation.ntfs.channel import NativeChannelError
from phase_tool.mutation.ntfs.authority import _NativeFileCreateAuthority
from .test_native_file2_connected import fixture,projection,ready_literal,CHANNEL,CHUNK


pytestmark=pytest.mark.skipif(os.name!='posix',reason='actual Linux Core/snapshot components required')


def model_reply(parsed):
    """Literal data oracle, NOT an actual receipt/proof of a native operation."""
    context=parse_json_bytes(parsed.context_bytes);grant=parse_json_bytes(parsed.grant_bytes)
    effect=parse_json_bytes(parsed.effect_bytes)
    after={'known':True,'exists':True,'digest':parsed.content_digest,
        'length':parsed.content_length,'head_token':None}
    native={'exists':True,'native_identity':{'volume_serial':grant['native_identity']['volume_serial'],
        'file_id':'d'*32},'length':parsed.content_length,'digest':parsed.content_digest,'link_count':1}
    absent={'known':True,'exists':False,'digest':None,'length':None,'head_token':None}
    receipt=_receipt(effect,run_id=context['run_id'],timestamp=parsed.timestamp,status='applied_verified',
        attempted=True,before=absent,after=after,bytes_written=parsed.content_length,
        verification_refs=['native.file.readback'],error_code=None)
    header_digest=ready_literal(parsed,77)['ready_token']['header_digest']
    physical={'native_file_create_version':'2.0','run_id':context['run_id'],'effect_id':effect['effect_id'],
        'grant':grant,'locator':effect['target']['relative_locator'],'before':{'exists':False,'native_identity':None},
        'after':native,'mutation_trace':{'acknowledged_recorded_event_count':1,'capture_complete':True,
            'unacknowledged_records_upper_bound':0,'capture_errors':[]},
        'mutex_state':'closed','mutation_session_state':'sealed','handle_finalization':'closed',
        'remaining_handle_count':0,'finalization_errors':[],'primary_error':None,'worker_exit_established':False,
        'stream_binding':{'protocol':'phase.native.file2.bytes','version':'1.0',
            'header_digest':header_digest,'channel_id':CHANNEL,'content_digest':parsed.content_digest,
            'content_length':parsed.content_length,'released_bytes':parsed.content_length,
            'complete':True,'failed':False,'summary':{'accepted_content_digest':parsed.content_digest,
                'accepted_content_length':parsed.content_length,'accepted_chunks':(parsed.content_length+CHUNK-1)//CHUNK}}}
    completion={'worker_completion_version':'1.2','context':context,'pid':77,'effect_receipt':receipt,
        'physical_evidence':physical,'error':None,'worker_exit_established':False}
    observation={'observation_version':'2.0','state':after,'native':native,
        'grant':grant,'locator':effect['target']['relative_locator'],'handles_finalized':True}
    return {'parent_execution_version':'1.2','context':context,'completion':completion,
        'process_witness':{'process_witness_version':'1.0','pid':77,'wait_result':0,'exit_code':0,
            'worker_exit_established':True},'owner_finalization':{'worker_stdin':'closed','worker_stdout':'closed',
            'worker_stderr':'closed','creation_handle':'closed','errors':[]},
        'post_observation':observation,'ingress_state':'consumed'}


@pytest.mark.parametrize('fault',['none','source_close','gate_release','worker_exit','observer','timestamp',
    'remote_no_completion','remote_malformed_completion','remote_reporting_failure',
    'remote_large_valid','remote_large_no_completion','remote_large_malformed_completion'])
def test_authority_real_bound_body_retains_valid_receipt_across_late_failure(tmp_path,monkeypatch,fault):
    registry,binding,args,run,roots=fixture(tmp_path,b'x'*(CHUNK+17))
    parsed=binding.read(run_id='file2-component',intent_digest=args['expected_intent_digest'])
    intent=parse_json_bytes(args['intent_bytes']);plan=parse_json_bytes(args['plan_bytes'])
    declaration=intent['inputs'][0]
    frozen=streaming.copy_and_hash_stream('payload',roots['prep'],'payload',run/'blobs',
        frozen_at=declaration['frozen_at'])
    assert frozen.intent_record()==declaration and frozen.streamed
    reply=model_reply(parsed);original_receipt=deepcopy(reply['completion']['effect_receipt'])
    if fault=='worker_exit':reply['process_witness']['exit_code']=1
    if fault=='observer':reply['post_observation']['native']=deepcopy(reply['post_observation']['native'])|{
        'native_identity':{'volume_serial':reply['post_observation']['native']['native_identity']['volume_serial'],
            'file_id':'e'*32}}
    if fault=='timestamp':reply['completion']['effect_receipt'].update(
        started_at='2026-10-25T00:00:00Z',finished_at='2026-10-25T00:00:00Z')
    large_wire=None
    if fault.startswith('remote_large_'):
        # Synthetic native event data within the unchanged worker/frame bound.
        # It is untrusted diagnostic input, never a real Windows trace/proof.
        trace=reply['completion']['physical_evidence']['mutation_trace']
        trace.update(records=[{'api':'synthetic.event','detail':'x'*200}for _ in range(128)],
            acknowledged_recorded_event_count=128)
        large_wire=canonical_bytes(reply['completion'])
        assert 16*1024<len(large_wire)<512*1024
    if fault in('remote_no_completion','remote_large_no_completion'):reply['completion']=None
    if fault in('remote_malformed_completion','remote_large_malformed_completion'):reply['completion']={'pid':True}
    if fault=='remote_reporting_failure':
        from phase_tool.mutation.ntfs import failure
        def unavailable(*_args,**_kwargs):raise PhaseError('synthetic.negative_render_failed')
        monkeypatch.setattr(failure,'make_native_parent_failure',unavailable)
    record={'calls':0,'captured':None,'source':None}
    def execute(**values):
        record['calls']+=1;source=values['source'];record['source']=source
        assert source._state=='first-unused' and os.fstat(source._fd).st_nlink==0
        assert values['projection']==parsed
        list(source.first_frames())
        source.rewind_after_ready(canonical_bytes(ready_literal(parsed,77)['ready_token']))
        list(source.replay_frames())
        record['captured']=canonical_bytes(reply)
        if fault.startswith('remote_'):
            remote={'code':'ntfs.parent_execution_unresolved','message':'synthetic parent negative',
                'details':{'parent_partial':reply,'worker_ready_wire':None,'worker_completion_wire':None,
                    'possible_dispatch':True,'retry_authorized':False}}
            if large_wire is not None:
                remote['details']['worker_completion_wire']={
                    'sha256':digest_bytes(large_wire),'length':len(large_wire),
                    'bytes_base64':base64.b64encode(large_wire).decode('ascii')}
            # Exercise the actual channel error projection, including the
            # large machine payload used by existing negative capture.
            from phase_tool.mutation.ntfs.channel import _primary
            raw_error=PhaseError('ntfs.channel_remote_failure',details={'remote_error':remote})
            projected=_primary(raw_error)
            assert projected['details']['remote_error']==remote
            raise NativeChannelError('ntfs.channel_exchange_unknown',possible_dispatch=True,
                details={'primary':projected}) from raw_error
        if fault=='gate_release':raise NativeChannelError('ntfs.channel_gate_finalization_unknown',possible_dispatch=True)
        return deepcopy(reply)
    channel=SimpleNamespace(channel_id=CHANNEL,possible_dispatch=True,execute_file2=execute,
        captured_file2_completion=lambda:record['captured'])
    role=object.__new__(_NativeFileCreateAuthority)
    role._inspection_only=False;role._file2=True;role._version1=False;role._version2=False;role._dispatch_attempted=False
    role.read_binding=binding;role.channel=channel;role._manifest=parse_json_bytes(binding.manifest_bytes)
    context=parse_json_bytes(parsed.context_bytes);role._run_id=context['run_id'];role._operation_nonce=context['operation_nonce']
    role._response_bytes=role._failure_bytes=None;role._parent_safety_established=role._server_ingress_sealed=False
    # Deliberately modeled bound-body admission. NO installation is constructed,
    # and no real qualification function is replaced or exercised as positive.
    role.require_contract=Mock();role.require_request_roots=Mock()
    contract=registry.resolve_contract(**{'identifier':intent['contract']['id'],
        'version':intent['contract']['version'],'package_digest':intent['contract']['package_digest']},
        core_version=intent['core']['version'])
    validator=Draft202012Validator(registry.schema_document('https://phase-tool.local/schemas/effect-receipt.schema.json'),
        registry=registry.schema_registry(),format_checker=FormatChecker())
    real=wire._verified_blob_snapshot
    if fault=='source_close':
        @contextmanager
        def close_fault(*args,**kwargs):
            with real(*args,**kwargs)as fd:yield fd
            raise PhaseError('synthetic.after_actual_snapshot_close')
        monkeypatch.setattr(wire,'_verified_blob_snapshot',close_fault)
    call=lambda:role.execute(plan,contract,{'payload':frozen},{'phase_result_root':roots['target']},
        run/'intent.json',timestamp=parsed.timestamp,receipt_validator=validator,
        expected_intent_digest=args['expected_intent_digest'])
    if fault=='none':
        result=call();assert result.effect_receipts==(original_receipt,)
        assert role._parent_safety_established and role._server_ingress_sealed
    else:
        with pytest.raises(BrokerExecutionInterrupted)as caught:call()
        assert caught.value.possible_dispatch is True
        assert caught.value.effect_receipts==(() if fault in('timestamp','remote_no_completion',
            'remote_malformed_completion','remote_large_no_completion',
            'remote_large_malformed_completion') else(original_receipt,))
        assert not role._parent_safety_established and not role._server_ingress_sealed
    assert record['calls']==1 and record['source']._fd is None
    assert role._response_bytes==record['captured']
    if fault in('remote_no_completion','remote_malformed_completion','remote_large_valid',
            'remote_large_no_completion','remote_large_malformed_completion'):
        failure=parse_json_bytes(role._failure_bytes)
        assert failure['outcome']=='unresolved' and failure['retry_authorized']is False
        assert failure['parent_error']['details']['parent_partial']==reply
        if large_wire is not None:
            captured=failure['parent_error']['details']['worker_completion_wire']
            assert captured['length']==len(large_wire)and captured['sha256']==digest_bytes(large_wire)
            assert base64.b64decode(captured['bytes_base64'],validate=True)==large_wire
            assert len(role._failure_bytes)>16*1024

    if fault=='remote_reporting_failure':assert role._failure_bytes is None
    assert list(roots['target'].iterdir())==[]


@pytest.mark.parametrize('fault',['none','ready_pid','go_delivery','completion_pid','worker_exit','owner_close','observer'])
def test_parent_real_orchestration_body_uses_one_model_owner_and_sole_go(tmp_path,monkeypatch,fault):
    _,_,args,_,_=fixture(tmp_path,b'x'*(CHUNK+17));parsed=projection(args)
    context=parse_json_bytes(parsed.context_bytes);reply=model_reply(parsed);record=[]
    compact={k:context[k]for k in('run_id','intent_digest','installation_digest','operation_nonce')}
    blob=tmp_path/'protocol-only-blob';blob.write_bytes(args['blob_bytes'])
    with wire._file2_verified_source(blob,context_bytes=canonical_bytes(compact),channel_id=CHANNEL,
        content_digest=parsed.content_digest,content_length=parsed.content_length)as source:
        first=list(source.first_frames());rewind=source.rewind_after_ready(canonical_bytes(ready_literal(parsed,77)['ready_token']))
        replay=list(source.replay_frames())
    # This prebuilt protocol model does not assert a live Core/Windows channel.
    core_frames=iter([*first,rewind,*replay]);core_sent=[];worker_sent=[]
    ready=ready_literal(parsed,78 if fault=='ready_pid' else 77)
    if fault=='completion_pid':reply['completion']['pid']=78
    worker_frames=iter([canonical_bytes(ready),canonical_bytes(reply['completion'])])
    def receive_core(deadline,**_):
        record.append('core_frame');return next(core_frames),None
    def send_worker(raw,deadline):
        value=parse_json_bytes(raw);worker_sent.append(value)
        if value.get('command')=='execute_file2':
            record.append('GO')
            if fault=='go_delivery':raise PhaseError('synthetic.go_delivery_unknown')
    worker_pipe=SimpleNamespace(receive_frame=lambda *_args,**_kwargs:(next(worker_frames),None),send_frame=send_worker)
    owner=object.__new__(parent._NativeWindowsParent)
    def original(_):record.append('original_read_and_exit_MODELED');return parsed
    def spawn():
        assert record==['original_read_and_exit_MODELED'];record.append('spawn');return SimpleNamespace(pid=77)
    def finalize(*_):
        record.append('owner_close')
        if fault=='owner_close':raise PhaseError('synthetic.owner_close')
    launch=SimpleNamespace(run_id=context['run_id'],operation_nonce=context['operation_nonce'],
        installation_digest=context['installation_digest'],channel_id=CHANNEL,
        root_grant=parse_json_bytes(parsed.grant_bytes),read_original=original,spawn_worker=spawn,
        worker_pipe=lambda _:worker_pipe,send_worker_original=lambda *_args,**_kwargs:record.append('original_metadata'),
        finalize_worker=finalize,check_runtime=lambda:None)
    owner._launch=launch;owner._pipe=SimpleNamespace(receive_frame=receive_core,
        send_frame=lambda raw,*_:core_sent.append(parse_json_bytes(raw)))
    owner._file2=True;owner._version1=False;owner._version2=False;owner._bundle=False;owner._inspection_only=False;owner._consumed=True
    owner._spawn_attempted=owner._go_attempted=False;owner._worker=None;owner._worker_count=0
    owner._worker_finalized=False;owner._partial_bytes=owner._ready_wire=owner._completion_wire=None
    owner._file2_exchange_deadline=time.perf_counter_ns()+30_000_000_000
    fact=deepcopy(reply['process_witness'])
    if fault=='worker_exit':fact['exit_code']=1
    def waited(_):record.append('retained_exit_MODELED');return fact
    monkeypatch.setattr(parent,'WindowsProcessWitness',lambda _:SimpleNamespace(wait_for_exit=waited))
    def observed(*_args,**_kwargs):
        record.append('separate_RO_MODELED')
        if fault=='observer':raise PhaseError('synthetic.RO_unavailable')
        return reply['post_observation']
    monkeypatch.setattr(execution,'observe_file2_file',observed)
    common={'protocol':'phase.native.pipe','version':'1.3','channel_id':CHANNEL,
        'sequence':1,'kind':'execute_file2','run_id':context['run_id'],'intent_digest':context['intent_digest']}
    call=lambda:owner._execute(context['intent_digest'],_common=common)
    if fault=='none':
        actual=call();assert actual==reply
        checked=execution.validate_file2_parent_completion(actual,context=context,
            grant_data=launch.root_grant,effect=parse_json_bytes(parsed.effect_bytes))
        execution.validate_file2_parent_finalization(actual,checked,grant_data=launch.root_grant,
            effect=parse_json_bytes(parsed.effect_bytes),expected_channel_id=CHANNEL)
    else:
        with pytest.raises(PhaseError,match='ntfs.parent_execution_unresolved')as caught:call()
        partial=caught.value.details['parent_partial']
        assert partial['ingress_state']=='consumed'
        if fault in('worker_exit','owner_close','observer'):
            assert partial['completion']['effect_receipt']==reply['completion']['effect_receipt']
        else:assert partial['completion']is None
    assert owner._worker_count==1 and record.count('spawn')==1
    assert record[:3]==['original_read_and_exit_MODELED','spawn','original_metadata']
    gos=[v for v in worker_sent if v.get('command')=='execute_file2']
    assert len(gos)==(0 if fault=='ready_pid' else 1)
    assert owner._go_attempted is (fault!='ready_pid')
    if gos:
        assert core_sent[0]['value']['file2_stage']=='ready'
        assert gos[0]['context']==context
        assert gos[0]['rewound_token']['kind']=='rewound' and gos[0]['go_token']['kind']=='go'
    with pytest.raises(PhaseError,match='ntfs.parent_execution_consumed'):call()
    assert record.count('spawn')==1
