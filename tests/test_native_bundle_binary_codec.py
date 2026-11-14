"""Native Bundle member-codec and exact relay tests. Pipes and effects are models."""

from dataclasses import replace
import os
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from phase_tool.canonical import canonical_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bundle_execution as worker
from phase_tool.mutation.ntfs import bundle_stream, entrypoint
from phase_tool.mutation.ntfs.bundle_prepared import prepared_ack, prepared_message
from phase_tool.mutation.ntfs.file2_stream import _BINARY_CHUNK_TAG, _binary_chunk_frame
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract
from phase_tool.mutation.ntfs.parent import _NativeWindowsParent
from .test_native_bundle2_prepared import b2_projection, native_stage
from .test_native_bundle_protocol import CHANNEL, VALUES, frames, projection


def installed(role, *, semantic):
    project = projection() if role == 'Bundle1' else b2_projection()
    if semantic:
        project = replace(project, contract_bytes=canonical_bytes(semantic_owner_contract(role)))
    elif role == 'Bundle2':
        project = replace(project, contract_bytes=canonical_bytes(worker._BUNDLE2_CONTRACT_V2))
    contract = parse_json_bytes(project.contract_bytes)
    return project, {'native_read_installation_version': '1.6' if role == 'Bundle1' else '1.9', 'contract': contract}


def payload_frames(project, phase, binary):
    output = []
    for raw in frames(project, phase):
        value = parse_json_bytes(raw)
        if binary and value['kind'] == 'chunk':
            import base64
            raw = _binary_chunk_frame(bytes.fromhex(value['header_digest'][7:]), value['pass'],
                                      value['index'], value['offset'], base64.b64decode(value['content_base64']))
        output.append(raw)
    return output


def go_message(project):
    header = worker._bundle_wire_header(project, CHANNEL)
    return canonical_bytes({'command':'execute_bundle','context':parse_json_bytes(project.context_bytes),
        'rewound_token':parse_json_bytes(bundle_stream._bundle_token(header,'rewound')),
        'go_token':parse_json_bytes(bundle_stream._bundle_token(header,'go'))})


class Pipe:
    def __init__(self, rows):
        self.rows, self.received, self.sent = list(rows), [], []
        self.sealed = False

    def receive_frame(self, deadline, *, maximum_bytes):
        self.received.append(deadline)
        raw = self.rows.pop(0)
        assert len(raw) <= maximum_bytes
        return raw, None

    def send_frame(self, raw, deadline):
        self.sent.append((raw, deadline))

    def seal(self):
        assert not self.sealed
        self.sealed = True


@pytest.mark.parametrize('role,legacy_read', [('Bundle1',False),('Bundle2',False),('Bundle2',True)])
@pytest.mark.parametrize('semantic', [False, True])
def test_native_bundle_parent_relay_keeps_wire_controls_and_deadline(role, legacy_read, semantic):
    project,manifest=installed(role,semantic=semantic)
    if legacy_read:
        manifest['native_read_installation_version']='1.8'
    recovery_capture=role=='Bundle2' and not legacy_read
    binary=semantic and not legacy_read
    header=worker._bundle_wire_header(project,CHANNEL)
    first,replay=payload_frames(project,1,binary),payload_frames(project,2,binary)
    rewound=bundle_stream._bundle_token(header,'rewound')
    pid,deadline=123,745
    ready=canonical_bytes(worker._bundle_ready_value(project,CHANNEL,pid))
    core_inputs=first+[rewound]+replay
    worker_inputs=[ready]
    ack=None
    if role=='Bundle2':
        message=prepared_message(project,CHANNEL,pid,native_stage(project))
        worker_inputs.append(canonical_bytes(message))
        ack=canonical_bytes(prepared_ack(message,'sha256:'+'8'*64,'sha256:'+'9'*64))
        core_inputs.append(ack)
    core,windows=Pipe(core_inputs),Pipe(worker_inputs)
    parent=SimpleNamespace(_launch=SimpleNamespace(channel_id=CHANNEL,manifest=manifest),_pipe=core,
                           _worker=SimpleNamespace(pid=pid),_go_attempted=False)
    parent._relay_prepared_ack=lambda *args:_NativeWindowsParent._relay_prepared_ack(parent,*args)
    with patch('phase_tool.mutation.ntfs.bootstrap._is_bundle_recovery_launch',return_value=recovery_capture):
        _NativeWindowsParent._transfer_bundle(parent,windows,project,deadline,{'sequence':1})
    assert not core.rows and not windows.rows and parent._go_attempted
    assert [raw for raw,_ in windows.sent]==first+[go_message(project)]+replay+([ack] if ack else [])
    assert all(value==deadline for value in core.received+windows.received+[d for _,d in windows.sent+core.sent])
    assert len(core.sent)==(2 if role=='Bundle2' else 1)
    assert getattr(parent,'_bundle_ack_relay_entered',False) is recovery_capture


@pytest.mark.parametrize('role,legacy_read', [('Bundle1',False),('Bundle2',False),('Bundle2',True)])
@pytest.mark.parametrize('semantic', [False, True])
def test_native_bundle_worker_startup_drives_existing_normal_and_capture_adapters(role, legacy_read, semantic):
    project,manifest=installed(role,semantic=semantic)
    if legacy_read:
        manifest['native_read_installation_version']='1.8'
    recovery_capture=role=='Bundle2' and not legacy_read
    binary=semantic and not legacy_read
    value=worker._bundle_projection_value(project)
    context=value['context']
    launch=SimpleNamespace(manifest=manifest,channel_id=CHANNEL,run_id=context['run_id'],
        operation_nonce=context['operation_nonce'],installation_digest=context['installation_digest'],
        root_grant=value['grant'],check_runtime=Mock())
    pipe=Pipe(payload_frames(project,1,binary)+[go_message(project)]+payload_frames(project,2,binary))
    deadline=time.perf_counter_ns()+29_000_000_000
    original={'native_worker_original_version':'3.0','channel_id':CHANNEL,'projection':value}
    received=[]
    prepared=None
    if role=='Bundle2':
        prepared=prepared_message(project,CHANNEL,os.getpid(),native_stage(project))
        pipe.rows.append(canonical_bytes(prepared_ack(prepared,'sha256:'+'8'*64,'sha256:'+'9'*64)))

    def effect(grant,effect_plan,source,*,run_id,timestamp):
        assert source._deadline==deadline
        for name in VALUES:
            parts=[]
            while (chunk:=source.next_member_chunk(name)) is not None:
                parts.append(chunk)
            received.append((name,b''.join(parts)))
        source.finish_payload()
        if prepared is not None:
            source.checkpoint_prepared(native_stage(project))
        return {'modeled_receipt':True},{'modeled_native':True}

    def terminal(out,*,sending,raw,deadline_ns):
        assert recovery_capture and sending is True
        out.send_frame(raw,deadline_ns)

    with patch('phase_tool.mutation.ntfs.bootstrap._is_bundle_recovery_launch',return_value=recovery_capture), \
         patch.object(worker.os,'name','nt'),patch.object(worker,'WindowsPipeFrames',Pipe), \
         patch('phase_tool.mutation.ntfs.windows_pipe.WindowsPipeFrames',Pipe), \
         patch('phase_tool.mutation.ntfs.bundle_effect.execute_bundle_create',side_effect=effect), \
         patch('phase_tool.mutation.ntfs.bundle_recovery_terminal.windows_terminal',side_effect=terminal), \
         patch.object(entrypoint,'_close_worker_stdio') as close:
        assert entrypoint._run_bundle_worker_transfer(launch,original,pipe,deadline)==0
    assert received==list(VALUES.items()) and not pipe.rows and pipe.sealed
    assert pipe.received and all(value==deadline for value in pipe.received)
    assert pipe.sent[0][1]==deadline
    if role=='Bundle1':
        assert pipe.sent[1][1]==deadline
    else:
        assert len(pipe.sent)==3 and pipe.sent[1]==(canonical_bytes(prepared),deadline)
    if not recovery_capture:
        assert pipe.sent[-1][1]==deadline
    assert launch.check_runtime.call_count==2
    close.assert_called_once_with(None)


@pytest.mark.parametrize('role', ['Bundle1', 'Bundle2'])
def test_native_bundle_cross_scope_and_wrong_codec_stop_before_go(role):
    project,manifest=installed(role,semantic=True)
    legacy,_=installed(role,semantic=False)
    with pytest.raises(PhaseError,match='ntfs.original_bundle_projection_binding'):
        bundle_stream._bundle_binary_chunks_for_original(manifest,legacy.contract_bytes)
    altered=manifest | {'contract': manifest['contract'] | {'package_digest':'sha256:'+'a'*64}}
    assert not bundle_stream._bundle_binary_chunks_for_original(altered,project.contract_bytes)
    crossed=manifest | {'native_read_installation_version':'1.9' if role=='Bundle1' else '1.6'}
    assert not bundle_stream._bundle_binary_chunks_for_original(crossed,project.contract_bytes)
    pipe=Pipe(payload_frames(project,1,False))
    deadline=time.perf_counter_ns()+29_000_000_000
    with patch.object(worker,'WindowsPipeFrames',Pipe),patch.object(worker.os,'name','nt'):
        source=worker._BundleWorkerInput(pipe,project,CHANNEL,deadline,_binary_chunks=True)
    with pytest.raises(PhaseError):
        source.first_pass()
    with pytest.raises(PhaseError):
        source.accept_go(go_message(project))
    assert not source._go_attempted and not source.complete


@pytest.mark.parametrize('fault',['wrong_member','same_length_corruption','bad_pass','bad_offset','extra_byte'])
def test_native_bundle_binary_replay_refuses_before_releasing_faulted_chunk(fault):
    project,_=installed('Bundle2',semantic=True)
    first=payload_frames(project,1,True)
    replay=payload_frames(project,2,True)
    indexes=[index for index,raw in enumerate(replay) if raw.startswith(_BINARY_CHUNK_TAG)]
    at,other=indexes
    chunk=replay[at]
    if fault=='wrong_member':chunk=replay[other]  # Equal bytes, different occurrence.
    if fault=='same_length_corruption':chunk=chunk[:-1]+b'Z'
    if fault=='bad_pass':chunk=chunk[:37]+b'\x01'+chunk[38:]
    if fault=='bad_offset':chunk=chunk[:49]+b'\x01'+chunk[50:]
    if fault=='extra_byte':chunk+=b'Z'
    replay[at]=chunk
    pipe=Pipe(first+replay);deadline=time.perf_counter_ns()+29_000_000_000
    with patch.object(worker,'WindowsPipeFrames',Pipe),patch.object(worker.os,'name','nt'):
        source=worker._BundleWorkerInput(pipe,project,CHANNEL,deadline,_binary_chunks=True)
    source.first_pass();source.accept_go(go_message(project))
    assert source.next_member_chunk('a.bin') is None
    with pytest.raises(PhaseError):source.next_member_chunk('b.bin')
    assert source._released==0 and not source.complete
    with pytest.raises(PhaseError):source.finish_remaining()


def test_explicit_bundle_recovery_keeps_existing_version_4_path():
    original={'native_worker_original_version':'4.0'}
    launch=object();pipe=object();deadline=20
    with patch('phase_tool.mutation.ntfs.bootstrap._is_bundle_recovery_launch',return_value=True), \
         patch('phase_tool.mutation.ntfs.bundle_recovery_worker.run_recovery_worker') as run, \
         patch.object(bundle_stream,'_bundle_binary_chunks_for_original',side_effect=AssertionError) as select, \
         patch.object(entrypoint,'_close_worker_stdio') as close:
        assert entrypoint._run_bundle_worker_transfer(launch,original,pipe,deadline)==0
    run.assert_called_once_with(launch,original,pipe,deadline)
    close.assert_called_once_with(None)
    select.assert_not_called()
