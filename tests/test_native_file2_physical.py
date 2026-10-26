"""Explicit in-memory OS substitutes: algorithm regression, NOT NTFS tests.

No qualification guard is replaced and no real native API/worker is called.
The shared physical algorithm/trace/receipt accounting is the real source.
"""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from phase_tool.canonical import digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import file_create as step
from phase_tool.mutation.ntfs.native import NativeIdentity
from phase_tool.mutation.ntfs.worker import _grant
from .test_native_worker import grant


@contextmanager
def model(monkeypatch,*,file2,collision=False,trace_fault=False,drain_fault=False):
    payload=b'synthetic short native writes'
    existing=b'pre-existing object'
    effect={'effect_id':'synthetic-effect','kind':'exclusive_create',
        'target':{'root_binding':'phase_result_root','relative_locator':'synthetic.bin'},
        'content_digest':digest_bytes(payload),'content_length':len(payload)}
    state=SimpleNamespace(data=bytearray(existing)if collision else None,creates=0,writes=0,
        flushes=0,drains=0)
    identity=NativeIdentity.parse({'volume_serial':1,'file_id':'4'*32})
    class Handle:
        def __init__(self,io):self.io=io
        def __enter__(self):self.io._handles.add(self);return self
        def __exit__(self,*_):self.io._handles.remove(self)
    class IO:
        def __init__(self):self._handles=set();self.events=[];self.mutation_state='open'
        def create_exclusive(self,*_,**__):
            state.creates+=1
            self.events.append({'api':'NtCreateFile','disposition':2,
                'return_status':'0xc0000035'if collision else '0x00000000',
                'effect_state':'not_committed_by_this_call'if collision else 'committed_by_this_call',
                'output_handle_present':not collision})
            if collision:raise PhaseError('ntfs.create_failed')
            state.data=bytearray();return Handle(self)
        def identity(self,_):return identity
        def write_chunk(self,handle,content,*,offset,expected):
            assert expected==identity and self.mutation_state=='open'
            count=min(4,len(content));state.data[offset:offset+count]=content[:count];state.writes+=1
            event={'api':'synthetic.write','count':count}
            if trace_fault:event['noncanonical']=object()
            self.events.append(event);return count
        def flush_file(self,*_):state.flushes+=1
        def flush_namespace(self,*_):state.flushes+=1
        def hash_file(self,_,maximum):
            assert len(state.data)<=maximum
            return digest_bytes(state.data),len(state.data)
        def info(self,_):return {'links':1}
        def seal_mutations(self):self.mutation_state='sealed'
    class Scope:
        def __init__(self,io,_,name,**__):
            assert name=='synthetic.bin'
            self.io=io;self.name=name;self.parent='parent';self.parent_identity=identity
        def __enter__(self):return self
        def __exit__(self,*_):return False
        def assert_bound(self):pass
        def assert_file_name(self,*_):pass
    class Mutex:
        def __init__(self,*_):self.state='new';self.events=[]
        def __enter__(self):self.state='held';return self
        def __exit__(self,*_):self.state='closed'
        def assert_held(self):assert self.state=='held'
    def observe(*_,**__):
        if state.data is None:return ({'known':True,'exists':False,'digest':None,'length':None,'head_token':None},
            {'exists':False,'native_identity':None})
        return ({'known':True,'exists':True,'digest':digest_bytes(state.data),'length':len(state.data),'head_token':None},
            {'exists':True,'native_identity':identity.as_dict(),'digest':digest_bytes(state.data),
                'length':len(state.data),'link_count':1})
    class Source:
        content_length=len(payload);complete=False;issued=False
        def next_chunk(self):
            assert not self.issued;self.issued=True;return payload
        def finish_remaining(self):
            state.drains+=1
            if drain_fault:raise PhaseError('synthetic.replay_end_failed')
            self.complete=True
        def stream_facts(self):return {'synthetic_only':True,'complete':self.complete}
    with monkeypatch.context() as patcher:
        patcher.setattr(step,'NativeMutationIO',IO)
        patcher.setattr(step,'NativeScopedTarget',Scope)
        patcher.setattr(step,'NativeRootMutex',Mutex)
        patcher.setattr(step,'_observe',observe)
        yield SimpleNamespace(state=state,payload=payload,existing=existing,run=lambda:
            step._execute_bound_file_create(_grant(grant()),effect,None if file2 else payload,
                run_id='synthetic-algorithm',timestamp='2026-10-26T00:00:00Z',
                _file2_source=Source()if file2 else None))


@pytest.mark.parametrize('file2',[False,True])
def test_shared_old_and_new_algorithm_short_writes_keep_exact_locator_and_bytes(monkeypatch,file2):
    with model(monkeypatch,file2=file2)as value:
        receipt,physical=value.run()
        assert receipt['status']=='applied_verified' and receipt['bytes_written']==len(value.payload)
        assert bytes(value.state.data)==value.payload and value.state.creates==1
        assert value.state.flushes==2 and value.state.writes==(len(value.payload)+3)//4
        assert physical['locator']=='synthetic.bin'
        assert physical['native_file_create_version']==('2.0'if file2 else '1.0')


@pytest.mark.parametrize('file2',[False,True])
def test_successful_short_write_then_trace_failure_preserves_acknowledged_prefix(monkeypatch,file2):
    with model(monkeypatch,file2=file2,trace_fault=True)as value:
        receipt,physical=value.run()
        assert receipt['status']=='indeterminate' and receipt['bytes_written']==4
        assert bytes(value.state.data)==value.payload[:4] and value.state.writes==1
        assert value.state.flushes==0 and physical['mutation_trace']['capture_complete']is False
        assert physical['primary_error']is not None


@pytest.mark.parametrize('file2',[False,True])
def test_collision_does_not_overwrite_and_file2_drains_only_same_healthy_stream(monkeypatch,file2):
    with model(monkeypatch,file2=file2,collision=True)as value:
        receipt,physical=value.run()
        assert receipt['status']=='failed_no_effect' and receipt['bytes_written']==0
        assert receipt['error']['code']=='target.destination_exists'
        assert bytes(value.state.data)==value.existing and value.state.creates==1 and value.state.writes==0
        assert value.state.drains==(1 if file2 else 0)


def test_collision_then_replay_finalization_failure_remains_unknown_with_original_cause(monkeypatch):
    with model(monkeypatch,file2=True,collision=True,drain_fault=True)as value:
        receipt,physical=value.run()
        assert receipt['status']=='indeterminate' and receipt['error']['code']=='ntfs.worker_finalization_unknown'
        assert bytes(value.state.data)==value.existing and value.state.writes==0
        assert physical['effect_before_finalization']['status']=='failed_no_effect'
        assert physical['effect_before_finalization']['error']['code']=='target.destination_exists'
        assert physical['finalization_errors'][0]['code']=='synthetic.replay_end_failed'
