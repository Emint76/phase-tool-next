"""Physical algorithm with EXPLICIT in-memory OS/session substitutes.

Only execute_version1 and its classifier/receipt/trace code are real. These
tests establish ordering and error preservation, not Windows handle semantics,
exclusive creation, persistence, containment, native admission or qualification.
"""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import version1_effect
from phase_tool.mutation.ntfs.native import NativeIdentity
from phase_tool.mutation.ntfs.worker import _grant
from .test_native_version1_parent import fixture,grant,observed,state


@contextmanager
def algorithm_fixture(*,old=b'old',new=b'new',archive=False,complete=False,
                      fail_archive_flush=False,release_error=False,late_archive=False):
    ctx,effect,content,_=fixture(old=old,new=new,archive_exists=archive,complete=complete)
    current=effect['target']['relative_locator'];arch=effect['archive_target']['relative_locator']
    files={current:bytearray(new if complete else old)}
    if archive or complete:files[arch]=bytearray(old)
    identities={current:NativeIdentity.parse({'volume_serial':1,'file_id':'4'*32}),
        arch:NativeIdentity.parse({'volume_serial':1,'file_id':'5'*32})}
    record=SimpleNamespace(order=[],read_handle=None,truncate_handle=None,mutations_after_error=0)

    class Handle:
        def __init__(self,io,name):self.io,self.name=io,name
        def __enter__(self):self.io._handles.add(self);return self
        def __exit__(self,*_):self.io._handles.remove(self)

    class IO:
        def __init__(self):self.events=[];self._handles=set();self.mutation_state='open';record.io=self
        def event(self,kind,name):
            if self.mutation_state!='open':
                record.mutations_after_error+=1;raise AssertionError('mutation after seal')
            record.order.append((kind,name));self.events.append({'api':kind,'target':name})
        def seal_mutations(self):self.mutation_state='sealed'
        def open_writable(self,parent,name,**_):self.event('open_writable',name);return Handle(self,name)
        def create_exclusive(self,parent,name,**_):
            self.event('create',name)
            if name in files:raise PhaseError('synthetic.exists')
            files[name]=bytearray();return Handle(self,name)
        def identity(self,handle):return identities[handle.name]
        def read_chunks(self,handle,maximum):
            record.read_handle=handle
            data=bytes(files[handle.name]);assert len(data)<=maximum
            for offset in range(0,len(data),65536):yield data[offset:offset+65536]
        def write_chunk(self,handle,data,*,offset,expected):
            self.event('write',handle.name);assert identities[handle.name]==expected
            files[handle.name][offset:offset+len(data)]=data;return len(data)
        def truncate(self,handle,*,length,expected):
            self.event('truncate',handle.name);record.truncate_handle=handle
            assert length==0 and identities[handle.name]==expected;files[handle.name].clear()
        def flush_file(self,handle,expected):
            self.event('flush_file',handle.name)
            if handle.name==arch and fail_archive_flush:
                self.mutation_state='sealed';raise PhaseError('synthetic.archive_flush')
        def flush_namespace(self,parent,expected):self.event('flush_namespace',parent)
        def hash_file(self,handle,maximum):
            data=bytes(files[handle.name]);assert len(data)<=maximum
            return digest_bytes(data),len(data)
        def assert_object(self,handle,**_):return {'links':1,'length':len(files[handle.name])}

    class Scope:
        def __init__(self,io,root,name,**options):
            self.io,self.name,self.parent,self.parent_identity=io,name,name,identities[current]
            if name==arch and late_archive and name not in files:
                files[name]=bytearray(old);record.order.append(('late_archive',name))
        def __enter__(self):return self
        def __exit__(self,*_):return False
        def assert_bound(self):pass
        def assert_file_name(self,handle,identity):assert identities[handle.name]==identity
        def open_file(self,**_):return Handle(self.io,self.name)

    class Mutex:
        def __init__(self,*_):self.state='new';self.events=[]
        def __enter__(self):self.state='held';return self
        def assert_held(self):assert self.state=='held'
        def __exit__(self,*_):
            self.state='closed'
            if release_error:raise PhaseError('synthetic.release')

    def observation(name):
        data=None if name not in files else bytes(files[name])
        return observed(data,'4' if name==current else '5',name)
    with (patch.object(version1_effect,'NativeMutationIO',IO),
          patch.object(version1_effect,'NativeScopedTarget',Scope),
          patch.object(version1_effect,'NativeRootMutex',Mutex),
          patch.object(version1_effect,'observe_version1_file',side_effect=lambda _,name:observation(name)),
          patch.object(version1_effect,'_observe',side_effect=lambda scope,**_:tuple(
              observation(scope.name)[key] for key in ('state','native')))):
        yield SimpleNamespace(run=lambda:version1_effect.execute_version1(_grant(grant()),effect,content,
            run_id=ctx['run_id'],timestamp='2026-01-01T00:00:00Z'),record=record,files=files,
            current=current,archive=arch,old=old,new=new,effect=effect)


class Version1EffectAlgorithmTests(unittest.TestCase):
    def test_archive_bytes_and_both_flushes_precede_same_current_handle_truncation(self):
        with algorithm_fixture() as f:
            receipt,evidence=f.run()
            self.assertEqual(receipt['status'],'applied_verified')
            order=f.record.order;cut=order.index(('truncate',f.current))
            self.assertLess(order.index(('flush_file',f.archive)),cut)
            self.assertLess(order.index(('flush_namespace',f.archive)),cut)
            self.assertIs(f.record.read_handle,f.record.truncate_handle)
            self.assertEqual(bytes(f.files[f.archive]),f.old);self.assertEqual(bytes(f.files[f.current]),f.new)
            self.assertEqual(receipt['bytes_written'],len(f.old)+len(f.new))
            self.assertEqual(evidence['handle_finalization'],'closed')
            self.assertIs(evidence['worker_exit_established'],False)

    def test_existing_exact_archive_is_reused_without_copy_or_new_archive_writes(self):
        with algorithm_fixture(archive=True) as f:
            receipt,_=f.run();self.assertEqual(receipt['status'],'applied_verified')
            self.assertEqual(receipt['bytes_written'],len(f.new))
            self.assertFalse(any(name==f.archive and kind in {'write','create'} for kind,name in f.record.order))
            self.assertEqual(bytes(f.files[f.archive]),f.old)

    def test_already_complete_is_zero_event_existing_contract_continuation(self):
        for old,new in ((b'old',b'new'),(b'equal',b'equal'),(b'',b'')):
            with self.subTest(old=old,new=new),algorithm_fixture(old=old,new=new,complete=True) as f:
                receipt,evidence=f.run();self.assertEqual(receipt['status'],'applied_verified')
                self.assertEqual(receipt['bytes_written'],0);self.assertEqual(f.record.order,[])
                self.assertEqual(receipt['before'],state(old))
                self.assertEqual(evidence['mutation_trace']['acknowledged_recorded_event_count'],0)

    def test_archive_flush_failure_never_truncates_current_or_claims_zero_written(self):
        with algorithm_fixture(fail_archive_flush=True) as f:
            receipt,evidence=f.run();self.assertEqual(receipt['status'],'indeterminate')
            self.assertIsNone(receipt['bytes_written'])
            self.assertEqual(evidence['primary_error']['code'],'synthetic.archive_flush')
            self.assertNotIn(('truncate',f.current),f.record.order)
            self.assertEqual(bytes(f.files[f.current]),f.old);self.assertEqual(f.record.mutations_after_error,0)

    def test_primary_archive_error_survives_secondary_mutex_release_error(self):
        with algorithm_fixture(fail_archive_flush=True,release_error=True) as f:
            receipt,evidence=f.run()
            self.assertEqual(receipt['status'],'indeterminate')
            self.assertEqual(evidence['primary_error']['code'],'synthetic.archive_flush')
            self.assertIn('synthetic.release',{x['code'] for x in evidence['finalization_errors']})
            self.assertNotIn(('truncate',f.current),f.record.order)

    def test_late_archive_appearance_aborts_before_copy_or_current_truncation(self):
        with algorithm_fixture(late_archive=True) as f:
            receipt,evidence=f.run();self.assertEqual(receipt['status'],'indeterminate')
            self.assertEqual(evidence['primary_error']['code'],'publish.archive_changed_before_publication')
            self.assertNotIn(('truncate',f.current),f.record.order)
            self.assertFalse(any(kind=='write' for kind,_ in f.record.order))
