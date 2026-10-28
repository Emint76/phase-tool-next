"""Actual V2 algorithm with explicitly simulated IO/scopes/mutexes.

Ordering/error/ownership oracles only; no native filesystem guarantee or Core
admission is established here. NativeHandle's real error-preserving exit is used.
"""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import version2_effect as effect_module
from phase_tool.mutation.ntfs.native import NativeHandle,NativeIdentity
from phase_tool.mutation.ntfs.root_lock import root_mutex_name
from phase_tool.mutation.ntfs.version2_observation import _version2_targets
from .test_native_version2_protocol import fixture,state


@contextmanager
def algorithm(*,fault=None,close_failure=False):
    ctx,grants,effect,content,_=fixture()
    targets=_version2_targets(effect);current=targets['current']
    files={current:bytearray(b'old synthetic')}
    identities={current:NativeIdentity(1,'3'*32)}
    record=SimpleNamespace(order=[],created=[],closed=[],close_attempts=[],entered=[],stage=None,
        mutations_after_seal=0,old_pin_held=False)

    class Handle:
        def __init__(self,io,key):
            self.io,self.key,self.data,self.identity=io,key,files[key],identities[key]
            self.closed=False;io._handles.add(self)
        def __enter__(self):record.entered.append(self);return self
        def close(self):
            record.close_attempts.append(self)
            if self.closed:raise AssertionError('duplicate simulated close')
            if close_failure and self is record.stage:raise PhaseError('synthetic.close_unknown')
            self.closed=True;self.io._handles.remove(self);record.closed.append(self)
        __exit__=NativeHandle.__exit__

    class IO:
        def __init__(self):
            self.events=[];self._handles=set();self.mutation_state='open';self.trace_fault=False;record.io=self
        def event(self,kind,key):
            if self.mutation_state!='open':
                record.mutations_after_seal+=1;raise AssertionError('mutation after seal')
            record.order.append((kind,key));self.events.append({'api':'synthetic.'+kind,'target':list(key)})
        def seal_mutations(self):self.mutation_state='sealed'
        def create_exclusive(self,parent,name,**_):
            key=(parent[0],parent[1]+name);self.event('create',key)
            if key in files:raise PhaseError('synthetic.exists')
            files[key]=bytearray();identities[key]=NativeIdentity(1,format(10+len(record.created),'032x'))
            handle=Handle(self,key);record.created.append(handle);record.stage=handle
            if fault=='create_trace':self.trace_fault=True
            return handle
        def identity(self,handle):return handle.identity
        def assert_object(self,handle,**_):return {'links':1,'length':len(handle.data)}
        def hash_file(self,handle,maximum):
            data=bytes(handle.data);assert len(data)<=maximum;return digest_bytes(data),len(data)
        def read_chunks(self,handle,maximum):
            assert len(handle.data)<=maximum;yield bytes(handle.data)
        def write_chunk(self,handle,data,*,offset,expected):
            self.event('write',handle.key);assert expected==handle.identity
            handle.data[offset:offset+len(data)]=data;return len(data)
        def flush_file(self,handle,*_):self.event('flush_file',handle.key)
        def flush_namespace(self,parent,*_):self.event('flush_namespace',parent)
        def rename(self,handle,parent,name,*,replace=False,**_):
            key=(parent[0],parent[1]+name);self.event('replace' if replace else 'rename',key)
            if replace:record.old_pin_held=any(h.key==current and h is not handle and not h.closed for h in self._handles)
            if replace and fault=='rename_trace':
                self.trace_fault=True;raise PhaseError('synthetic.rename_unknown')
            if not replace and key in files:raise PhaseError('synthetic.exists')
            files[key]=files.pop(handle.key);identities[key]=identities.pop(handle.key);handle.key=key
        def rename_noreplace(self,handle,parent,name,**kwargs):return self.rename(handle,parent,name,**kwargs)

    class Scope:
        def __init__(self,io,grant,locator,**_):
            self.io,self.key=io,(grant.binding,locator)
            self.name=locator.rsplit('/',1)[-1]
            self.parent=(grant.binding,locator.rsplit('/',1)[0]+'/' if '/' in locator else '')
            self.parent_identity=grant.root_identity
            if grant.binding=='objects_root' and fault=='scope_trace':
                io.trace_fault=True;raise PhaseError('synthetic.scope_primary')
        def __enter__(self):return self
        def close(self):pass
        __exit__=NativeHandle.__exit__
        def assert_bound(self):pass
        def open_file(self,*,expected):
            assert identities[self.key]==expected;return Handle(self.io,self.key)
        def assert_file_name(self,handle,identity):assert handle.key==self.key and identities[self.key]==identity

    class Mutex:
        def __init__(self,io,grant):self.name=root_mutex_name(grant);self.state='new';self.events=[]
        def __enter__(self):self.state='held';return self
        def assert_held(self):assert self.state=='held'
        def __exit__(self,*_):self.state='closed'

    class Trace(effect_module._MutationTrace):
        def collect(self,io):
            if io.trace_fault:
                io.trace_fault=False;raise PhaseError('synthetic.trace_secondary')
            return super().collect(io)

    def observed(key):
        if key not in files:return state(None),{'exists':False,'native_identity':None}
        data=bytes(files[key]);return state(data),{'exists':True,'native_identity':identities[key].as_dict(),
            'digest':digest_bytes(data),'length':len(data),'link_count':1}
    def triple(*_,**__):
        return {name:dict(zip(('state','native'),observed(key))) for name,key in targets.items()}
    with (patch.object(effect_module,'NativeMutationIO',IO),patch.object(effect_module,'NativeScopedTarget',Scope),
          patch.object(effect_module,'NativeRootMutex',Mutex),patch.object(effect_module,'_MutationTrace',Trace),
          patch.object(effect_module,'observe_version2_triple',side_effect=triple),
          patch.object(effect_module,'_observe',side_effect=lambda scope,**_:observed(scope.key)),
          patch.object(effect_module,'_native_state',side_effect=lambda io,scope,handle,*_:observed(handle.key))):
        yield SimpleNamespace(run=lambda:effect_module.execute_version2(grants,effect,content,
            run_id=ctx['run_id'],timestamp='2026-01-01T00:00:00Z'),record=record,files=files,targets=targets)


def codes(value):
    if isinstance(value,dict):
        return ([value['code']] if isinstance(value.get('code'),str) else [])+[c for x in value.values() for c in codes(x)]
    if isinstance(value,list):return [c for x in value for c in codes(x)]
    return []


class Version2EffectFailureTests(unittest.TestCase):
    def test_objects_are_published_and_flushed_before_replace_with_old_pin_retained(self):
        with algorithm() as f:
            receipt,physical=f.run()
            self.assertEqual(receipt['status'],'applied_verified')
            order=f.record.order;replace=order.index(('replace',f.targets['current']))
            for role in ('old_object','new_object'):
                root,locator=f.targets[role]
                rename=order.index(('rename',(root,locator)))
                flushed=order.index(('flush_file',(root,physical['temporary_locators'][role])))
                parent=(root,locator.rsplit('/',1)[0]+'/')
                namespace=next(i for i,event in enumerate(order) if i>rename and event==('flush_namespace',parent))
                self.assertLess(flushed,rename);self.assertLess(rename,namespace);self.assertLess(namespace,replace)
            self.assertLess(order.index(('flush_file',('current_root',physical['temporary_locators']['current']))),replace)
            self.assertGreater(order.index(('flush_namespace',('current_root',''))),replace)
            self.assertIs(f.record.old_pin_held,True)
            self.assertEqual(physical['handle_finalization'],'closed')
            self.assertEqual(len(f.record.io._handles),0)
            self.assertEqual(len(f.record.created),3)
            self.assertEqual(set(f.record.created)&set(f.record.entered),set(f.record.created))

    def test_created_handle_is_adopted_before_failing_trace_and_closed_once(self):
        with algorithm(fault='create_trace') as f:
            receipt,physical=f.run()
            self.assertEqual(receipt['status'],'indeterminate')
            self.assertIn('synthetic.trace_secondary',codes(physical))
            self.assertEqual(len(f.record.created),1)
            handle=f.record.created[0]
            self.assertIn(handle,f.record.entered)
            self.assertEqual(f.record.closed.count(handle),1)
            self.assertEqual(f.record.close_attempts.count(handle),1)
            self.assertFalse(any(kind in {'write','rename','replace'} for kind,_ in f.record.order))
            self.assertEqual(f.record.mutations_after_seal,0)

    def test_scope_primary_is_not_replaced_by_trace_failure(self):
        with algorithm(fault='scope_trace') as f:
            receipt,physical=f.run()
            self.assertEqual(receipt['status'],'indeterminate')
            self.assertEqual(physical['primary_error']['code'],'synthetic.scope_primary')
            self.assertIn('synthetic.trace_secondary',codes(physical['finalization_errors']))
            self.assertEqual(f.record.io._handles,set())

    def test_unknown_replace_trace_and_close_failures_all_survive_without_retry(self):
        with algorithm(fault='rename_trace',close_failure=True) as f:
            receipt,physical=f.run()
            self.assertEqual(receipt['status'],'indeterminate')
            self.assertIn('synthetic.rename_unknown',codes(physical))
            self.assertIn('synthetic.trace_secondary',codes(physical))
            self.assertIn('synthetic.close_unknown',codes(physical))
            self.assertEqual(sum(kind=='replace' for kind,_ in f.record.order),1)
            self.assertEqual(f.record.mutations_after_seal,0)
            self.assertEqual(f.record.close_attempts.count(f.record.stage),1)
            self.assertIn(f.record.stage,f.record.io._handles)
            self.assertEqual(physical['handle_finalization'],'unknown')
            self.assertEqual(physical['remaining_handle_count'],1)


if __name__=='__main__':unittest.main()
