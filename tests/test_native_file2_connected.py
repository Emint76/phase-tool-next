"""UNQUALIFIED components over actual Linux Core/RO files and real pipes.

Host planned output is explicitly projected into synthetic native CLAIMS.
The public native qualification guard remains real and must refuse. Synthetic
peer READY/completion data do not establish a Windows worker, effect or receipt.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

import pytest

from phase_tool import evidence, installation, streaming
from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_file2_registry, _resolve_native_file_create_read_binding
from phase_tool.mutation.ntfs import file2_execution as execution, reader
from phase_tool.mutation.ntfs.channel_v4 import LinuxNativeChannelV4
from phase_tool.mutation.ntfs.handoff import _OriginalControlProjection
from phase_tool.mutation.ntfs.intent import _parse_file2_control_projection
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers
from .test_native_static_read_binding import manifest_for
from .test_native_version1_original import arguments


pytestmark=pytest.mark.skipif(not sys.platform.startswith('linux'),reason='actual Linux/ext4 components required')
CHANNEL='4'*32
CHUNK=256*1024


def fixture(tmp_path,content=b'synthetic file2 content',*,executing=True):
    """Real Host Core freeze/preconditions, never native admission or dispatch."""
    registry=_native_file2_registry()
    binding=registry.contract_bindings()['file_create.v2@1.0.0']
    roots={n:tmp_path/n for n in ('host-evidence','native-claims','prep','target')}
    for root in roots.values():root.mkdir(mode=0o700)
    installation.qualify_host_authority_roots(roots)
    candidate={'operation_id':'file2.component','target_locator':'synthetic.bin',
        'input_binding':'payload','idempotency_key':'file2-component'}
    candidate_path=roots['prep']/'candidate.json';candidate_path.write_bytes(canonical_bytes(candidate))
    source=roots['prep']/'payload';source.write_bytes(content)
    request=PhaseRequest(binding['id'],binding['version'],binding['package_digest'],candidate_path,
        roots['host-evidence'],'file2-component',{'payload':source},{'phase_result_root':roots['target']},
        timestamp='2026-10-26T00:00:00Z')
    outcome=PhaseCore(registry=registry).run(request,execute=False)
    assert outcome.exit_code==0 and outcome.receipt['terminal_status']=='validated_planned'
    assert not (roots['target']/'synthetic.bin').exists()
    host_run=roots['host-evidence']/'.phase'/'runs'/request.run_id
    pre=parse_json_bytes((host_run/'attachments'/'validator-results.json').read_bytes())
    # Structural native CLAIMS come from the historical data-only fixture.
    # Its file1 package must stay unique; actual Core planning and read-binding
    # resolution still use V6. Do not rewrite current flags or trusted packages.
    shell=buffers(BundledRegistry.load())[0]
    intent=deepcopy(outcome.intent);plan=deepcopy(outcome.effect_plan)
    intent.update(phase_intent_version='1.2',execution_requested=executing,
        native_binding=deepcopy(shell['native_binding']))
    intent['implementation_binding']=deepcopy(shell['implementation_binding'])
    intent['implementation_binding']['mechanism']=deepcopy(plan['mechanism'])
    grants=deepcopy(shell['idempotency']['root_identities'])
    root_digest=profile_digest('native-root-identity-v1',grants)
    scope={'contract':intent['contract'],'result_locator':candidate['target_locator'],
        'root_identity_digest':root_digest,'operation_intent':'create'}
    intent['idempotency'].update(root_identities=grants,root_identity_digest=root_digest,
        scope_digest=profile_digest('idempotency-scope',scope),
        request_digest=profile_digest('request',{'scope':scope,'candidate_digest':intent['candidate']['digest'],
            'inputs':intent['inputs']}))
    info=roots['native-claims'].stat()
    intent['native_binding']['evidence_identity']={'stable_id':'synthetic.file2.reader',
        'device':info.st_dev,'inode':info.st_ino}
    manifest=manifest_for(intent,roots['native-claims'])
    info=roots['prep'].stat()
    manifest.update(native_read_installation_version='1.3',preparation_root=str(roots['prep']),
        preparation_identity={'stable_id':'synthetic.file2.prep','device':info.st_dev,'inode':info.st_ino},
        root_projections={'phase_result_root':str(roots['target'])})
    raw=canonical_bytes(manifest)
    binding=_resolve_native_file_create_read_binding(manifest_bytes=raw,
        expected_manifest_digest=digest_bytes(raw),registry=registry)
    intent['native_binding']['installation']['descriptor_digest']=binding.manifest_digest
    args=arguments(registry,intent,plan,pre,content)
    run=roots['native-claims']/'.phase'/'runs'/intent['run_id']
    pre_name='pre-validator-results.json' if executing else 'validator-results.json'
    records={'intent.json':args['intent_bytes'],'attachments/effect-plan.json':args['plan_bytes'],
        'attachments/'+pre_name:args['pre_validator_bytes'],
        'blobs/'+digest_bytes(content).removeprefix('sha256:'):content}
    for name,data in records.items():
        dest=run/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);dest.write_bytes(data)
    return registry,binding,args,run,roots


def projection(args,executing=True):
    return _parse_file2_control_projection(**{k:v for k,v in args.items()if k!='blob_bytes'},
        _execution_requested=executing)


def ready_literal(parsed,pid):
    context=parse_json_bytes(parsed.context_bytes)
    compact={k:context[k]for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
    header={'protocol':'phase.native.file2.bytes','version':'1.0','kind':'header',
        'channel_id':CHANNEL,'context':compact,'content_digest':parsed.content_digest,
        'content_length':parsed.content_length,'chunk_bytes':CHUNK,
        'chunk_count':(parsed.content_length+CHUNK-1)//CHUNK}
    return {'worker_ready_version':'1.2','context':context,'pid':pid,
        'grant_digest':digest_bytes(parsed.grant_bytes),'effect_digest':digest_bytes(parsed.effect_bytes),
        'content_digest':parsed.content_digest,'content_length':parsed.content_length,
        'timestamp':parsed.timestamp,'ready_token':{'protocol':'phase.native.file2.bytes',
            'version':'1.0','kind':'ready','header_digest':digest_bytes(canonical_bytes(header))}}


def test_v6_preserves_history_and_trust_while_appending_only_new_package_and_candidate():
    old=installation._native_lifecycle_registry().to_document()
    new=_native_file2_registry().to_document()
    expected=deepcopy(old)
    next(x for x in expected['entries']if x['id']=='file_create.v2' and x.get('current'))['current']=False
    assert new['entries'][:-2]==expected['entries']
    assert new['trust_roots']==old['trust_roots']
    assert len(new['entries'])==len(old['entries'])+2
    registry=_native_file2_registry()
    descriptor=registry.resolve_guarantee_profile(registry.guarantee_profile_bindings()[
        'phase.native.ntfs.candidate.authority.v4@1.0.0'])
    assert descriptor['classification']=='qualification_candidate'
    assert descriptor['provided_guarantees']==descriptor['conformance']==[]
    assert 'phase.native.ntfs.authority.v1@1.0.0' not in registry.guarantee_profile_bindings()


@pytest.mark.parametrize('inspection',[False,True])
def test_real_guard_refuses_before_read_snapshot_channel_or_evidence(monkeypatch,inspection):
    reached=[]
    def forbidden(*args,**kwargs):reached.append(True);raise AssertionError('native admission escaped guard')
    monkeypatch.setattr(installation,'_resolve_native_file_create_read_binding',forbidden)
    monkeypatch.setattr(LinuxNativeChannelV4,'__init__',forbidden)
    monkeypatch.setattr(evidence.EvidenceStore,'__init__',forbidden)
    monkeypatch.setattr(streaming,'_verified_blob_snapshot',forbidden)
    with pytest.raises(PhaseError,match='ntfs.native_profile_not_qualified'):
        installation._native_file2_installation(manifest_bytes=b'',expected_manifest_digest=None,
            run_id=None,operation_nonce=None,channel_id=None,_inspection_only=inspection)
    assert reached==[]


@pytest.mark.parametrize('executing',[False,True])
@pytest.mark.parametrize('length',[0,CHUNK+13,1024**2+17])
def test_actual_core_frozen_original_full_ro_hash_and_projection(tmp_path,monkeypatch,executing,length):
    content=(bytes(range(256))*((length+255)//256))[:length]
    registry,binding,args,run,roots=fixture(tmp_path,content,executing=executing)
    projected=projection(args,executing)
    assert type(projected) is _OriginalControlProjection and not hasattr(projected,'content_bytes')
    assert (projected.content_digest,projected.content_length)==(digest_bytes(content),length)
    before={p.relative_to(roots['native-claims']):p.read_bytes()
        for p in roots['native-claims'].rglob('*')if p.is_file()}
    from unittest.mock import patch
    with patch.object(streaming,'hash_file',wraps=streaming.hash_file) as hashed:
        actual=(binding.read(run_id='file2-component',intent_digest=args['expected_intent_digest'])
            if executing else binding.validate_planned(run_id='file2-component',intent_digest=args['expected_intent_digest']))
    assert actual==projected if executing else actual is None
    assert hashed.call_count==1
    assert hashed.call_args.args==(run/'blobs'/digest_bytes(content).removeprefix('sha256:'),streaming.FILE_LIMIT)
    assert before=={p.relative_to(roots['native-claims']):p.read_bytes()
        for p in roots['native-claims'].rglob('*')if p.is_file()}
    assert list(roots['target'].iterdir())==[]


@pytest.mark.parametrize('fault',['missing','tail','length'])
@pytest.mark.parametrize('executing',[False,True])
def test_ro_reader_never_treats_declared_hash_as_actual_content(tmp_path,fault,executing):
    content=b'x'*(1024**2)+b'z'
    _,binding,args,run,_=fixture(tmp_path,content,executing=executing)
    assert projection(args,executing).content_length==len(content)
    blob=run/'blobs'/digest_bytes(content).removeprefix('sha256:')
    if fault=='missing':blob.unlink()
    else:blob.write_bytes(content[:-1]+b'y' if fault=='tail' else content+b'extra')
    call=binding.read if executing else binding.validate_planned
    with pytest.raises((PhaseError,FileNotFoundError)):
        call(run_id='file2-component',intent_digest=args['expected_intent_digest'])


@pytest.mark.parametrize('field,bad',[('pid',True),('pid',78),('timestamp','different'),('content_length',True)])
def test_ready_exact_expected_creation_pid_and_all_bindings(tmp_path,field,bad):
    _,_,args,_,_=fixture(tmp_path)
    parsed=projection(args)
    value=ready_literal(parsed,77)
    assert execution._file2_ready_value(parsed,CHANNEL,77)==value
    assert execution.validate_file2_worker_ready(canonical_bytes(value),projection=parsed,
        channel_id=CHANNEL,expected_pid=77)==value
    value[field]=bad
    with pytest.raises(PhaseError,match='ntfs.worker_ready_binding_mismatch'):
        execution.validate_file2_worker_ready(canonical_bytes(value),projection=parsed,
            channel_id=CHANNEL,expected_pid=77)


CLIENT=r'''
import json,os,sys
from pathlib import Path
from phase_tool.canonical import canonical_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.channel import NativeChannelError
from phase_tool.mutation.ntfs.channel_v4 import LinuxNativeChannelV4
from phase_tool.mutation.ntfs.file2_stream import _file2_verified_source
from phase_tool.mutation.ntfs.file2_execution import _file2_projection_from_value
p=_file2_projection_from_value(json.loads(Path(sys.argv[1]).read_bytes()))
cxt=parse_json_bytes(p.context_bytes);compact={k:cxt[k]for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
os.set_blocking(0,False);os.set_blocking(1,False)
c=LinuxNativeChannelV4('4'*32);result={}
real_send=c._send_frame;gates=[]
def checked_send(raw,deadline):
 gates.append(c._gate.locked());return real_send(raw,deadline)
c._send_frame=checked_send
try:
 with _file2_verified_source(Path(sys.argv[2]),context_bytes=canonical_bytes(compact),channel_id=c.channel_id,
       content_digest=p.content_digest,content_length=p.content_length) as source:
  fd=source._fd;result['anonymous_nlink']=os.fstat(fd).st_nlink
  result['answer']=c.execute_file2(run_id=cxt['run_id'],intent_digest=cxt['intent_digest'],projection=p,source=source)
  result['same_fd']=source._fd==fd;result['fd_position']=os.lseek(fd,0,os.SEEK_CUR)
except NativeChannelError as e:result['error']={'code':e.code,'possible_dispatch':e.possible_dispatch}
result['possible_dispatch']=c.possible_dispatch;result['sequence']=c._sequence
result['all_send_frames_under_one_gate']=all(gates);result['gate_released']=not c._gate.locked()
result['captured']=None if c.captured_file2_completion() is None else parse_json_bytes(c.captured_file2_completion())
sys.stderr.write(json.dumps(result,sort_keys=True))
'''


def read_frame(child,deadline):
    def exact(n):
        value=bytearray()
        while len(value)<n:
            remaining=deadline-time.monotonic();assert remaining>0,'synthetic peer timeout'
            ready,_,_=select.select([child.stdout],[],[],remaining);assert ready
            data=os.read(child.stdout.fileno(),n-len(value));assert data,'synthetic peer EOF'
            value.extend(data)
        return bytes(value)
    header=exact(9);assert header[-1:]==b'\n'
    length=int(header[:8],16);assert 0<length<=2*1024**2
    raw=exact(length);assert exact(1)==b'\n';value=json.loads(raw)
    assert canonical_bytes(value)==raw
    return value


def send_frame(child,value):
    raw=canonical_bytes(value)
    child.stdin.write(f'{len(raw):08x}\n'.encode()+raw+b'\n');child.stdin.flush()


@pytest.mark.parametrize('length',[0,CHUNK+17,1024**2+7])
@pytest.mark.parametrize('mode',['positive_data','ready_mismatch','early_terminal','negative_terminal'])
def test_real_pipes_same_fd_one_epoch_and_late_completion_capture(tmp_path,length,mode):
    content=(bytes(range(256))*((length+255)//256))[:length]
    _,_,args,run,_=fixture(tmp_path,content)
    parsed=projection(args);value=execution._file2_projection_value(parsed)
    path=tmp_path/'synthetic-projection.json';path.write_bytes(canonical_bytes(value))
    blob=run/'blobs'/digest_bytes(content).removeprefix('sha256:')
    child=subprocess.Popen([sys.executable,'-B','-c',CLIENT,str(path),str(blob)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    try:
        deadline=time.monotonic()+15
        common=read_frame(child,deadline)
        assert common['kind']=='execute_file2' and common['version']=='1.3' and common['sequence']==1
        header=read_frame(child,deadline);header_digest=digest_bytes(canonical_bytes(header))
        cxt=parse_json_bytes(parsed.context_bytes)
        assert header=={'protocol':'phase.native.file2.bytes','version':'1.0','kind':'header',
            'channel_id':CHANNEL,'context':{k:cxt[k]for k in ('run_id','intent_digest','installation_digest','operation_nonce')},
            'content_digest':digest_bytes(content),'content_length':length,'chunk_bytes':CHUNK,
            'chunk_count':(length+CHUNK-1)//CHUNK}
        count=(length+CHUNK-1)//CHUNK
        for phase in (1,2):
            observed=bytearray()
            for index in range(count):
                frame=read_frame(child,deadline)
                assert frame['pass']==phase and frame['index']==index and frame['offset']==len(observed)
                assert frame['header_digest']==header_digest
                observed.extend(base64.b64decode(frame['content_base64'],validate=True))
            end=read_frame(child,deadline)
            assert end['kind']=='end' and end['pass']==phase and end['chunk_count']==count
            assert end['header_digest']==header_digest and end['content_length']==length
            assert bytes(observed)==content and digest_bytes(observed)==end['content_digest']
            if phase==1:
                ready=ready_literal(parsed,77)
                terminal={'parent_execution_version':'synthetic-capture','not_a_receipt':True}
                if mode=='early_terminal':
                    send_frame(child,common|{'ok':True,'value':terminal,'error':None});break
                if mode=='ready_mismatch':ready['effect_digest']='sha256:'+'f'*64
                send_frame(child,common|{'ok':True,'value':{'file2_stage':'ready','worker_ready':ready},'error':None})
                if mode=='ready_mismatch':break
                rewind=read_frame(child,deadline)
                assert rewind=={'protocol':'phase.native.file2.bytes','version':'1.0',
                    'kind':'rewound','header_digest':header_digest}
        else:
            if mode=='negative_terminal':
                send_frame(child,common|{'ok':False,'value':None,'error':{'code':'ntfs.parent_execution_unresolved',
                    'message':'synthetic negative peer','details':{'parent_partial':terminal}}})
            else:send_frame(child,common|{'ok':True,'value':terminal,'error':None})
        child.wait(timeout=10)
        report=json.loads(child.stderr.read());assert child.returncode==0
        assert report['sequence']==1 and report['possible_dispatch'] is True and report['anonymous_nlink']==0
        assert report['all_send_frames_under_one_gate'] and report['gate_released']
        if mode=='positive_data':
            assert report['answer']==terminal and report['captured']==terminal
            assert report['same_fd'] and report['fd_position']==length
        else:
            assert report['error']['possible_dispatch'] is True
            assert report['captured']==(None if mode=='ready_mismatch' else terminal)
    finally:
        # Only our disposable synthetic Linux test client, never a native worker.
        if child.poll() is None:child.kill();child.wait(timeout=5)
        for stream in (child.stdin,child.stdout,child.stderr):stream.close()
