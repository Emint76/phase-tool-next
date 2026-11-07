"""Portable fault models for exact bundle failure ownership; no NTFS effects."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from phase_tool.canonical import canonical_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.native import NativeIO,NativeIdentity
from phase_tool.mutation.ntfs.bundle_observation import _BundleHandlePins
from phase_tool.mutation.ntfs.bundle_effect import _bundle_mutation_call
from phase_tool.mutation.ntfs import bundle_execution as worker
from .test_native_bundle_protocol import projection,CHANNEL


class BundleFailureOwnershipTests(unittest.TestCase):
    def test_create_handle_registered_before_trace_fault_and_closed_once(self):
        io=object.__new__(NativeIO);io._handles={}
        io.kernel=SimpleNamespace(CloseHandle=Mock(return_value=1))
        handle=io._adopt(21,directory=True);trace_error=PhaseError('injected.trace')
        trace=SimpleNamespace(collect=Mock(side_effect=trace_error));errors=[]
        with self.assertRaises(PhaseError)as caught:
            with _BundleHandlePins()as pins:
                _bundle_mutation_call(io,trace,errors,Mock(return_value=handle),_pins=pins)
        self.assertIs(caught.exception,trace_error)
        io.kernel.CloseHandle.assert_called_once_with(21)
        self.assertEqual(handle.finalization_state,'closed');self.assertEqual(io._handles,{})
        self.assertEqual(errors,[])

    def test_native_primary_survives_trace_fault_without_another_native_call(self):
        native=PhaseError('injected.native');secondary=PhaseError('injected.trace')
        call=Mock(side_effect=native);trace=SimpleNamespace(collect=Mock(side_effect=secondary));errors=[]
        with self.assertRaises(PhaseError)as caught:
            _bundle_mutation_call(object(),trace,errors,call)
        self.assertIs(caught.exception,native);self.assertEqual(errors,[secondary])
        call.assert_called_once();trace.collect.assert_called_once()

    def test_worker_retains_primary_transport_and_seal_error_after_all_closes(self):
        primary=PhaseError('injected.first_pass');transport=PhaseError('injected.send');close=PhaseError('injected.seal')
        class Pipe:
            def send_frame(self,*a):raise transport
            def seal(self):raise close
        pipe=Pipe();source=SimpleNamespace(first_pass=Mock(side_effect=primary))
        project=projection()
        with patch.object(worker,'WindowsPipeFrames',Pipe),patch.object(worker.os,'name','nt'), \
                patch.object(worker,'_BundleWorkerInput',return_value=source):
            with self.assertRaises(PhaseError)as caught:
                worker.run_bundle_worker(pipe,project,CHANNEL,_transfer_deadline_ns=1)
        failure=caught.exception
        self.assertEqual(failure.code,'ntfs.worker_completion_or_finalization_unavailable')
        self.assertIs(failure.primary_error,primary);self.assertIs(failure.transport_error,transport)
        self.assertIs(failure.finalization_error,close);self.assertIs(failure.__cause__,transport)
        self.assertFalse(failure.details['worker_exit_established']);source.first_pass.assert_called_once()

    def test_written_metadata_then_readback_fault_is_indeterminate_with_lower_bound(self):
        from phase_tool.mutation.ntfs import bundle_effect as effect_module
        project=projection();value=worker._bundle_projection_value(project)
        grant=SimpleNamespace(as_dict=lambda:value['grant'])
        class IO(NativeIO):
            def __init__(self):
                self._handles={};self.kernel=SimpleNamespace(CloseHandle=Mock(return_value=1))
                self.counter=20;self.mutation_state='active';self.ack=0
            def identity(self,h):return NativeIdentity(7,('0'*30)+format(h.value,'02x'))
            def child(self,*a,**kw):raise PhaseError('ntfs.open_failed',details={'ntstatus':'0xc0000034'})
            def create_exclusive(self,*a,directory,**kw):
                self.counter+=1;return self._adopt(self.counter,directory=directory)
            def directory_stat_identity(self,*a):return {'device':7,'inode':22}
            def write_chunk(self,h,data,**kw):self.ack+=len(data);return len(data)
            def flush_file(self,*a):pass
            def hash_file(self,*a):raise PhaseError('injected.metadata_readback')
            def seal_mutations(self):self.mutation_state='sealed'
        io=IO()
        class Lock:
            def __init__(self,*a):self.state='open';self.events=[]
            def assert_held(self):pass
            def __enter__(self):return self
            def __exit__(self,*a):self.state='closed'
        class Scope:
            def __init__(self,*a,**kw):
                self.parent=io._adopt(10,directory=True);self.parent_identity=io.identity(self.parent);self.name='bundle'
            def assert_bound(self):pass
            def __enter__(self):return self
            def __exit__(self,*a):self.parent.close()
        class Source:
            def __init__(self):self.projection=project;self._go_attempted=True;self.complete=False;self.drained=0
            def _check(self):pass
            def finish_remaining(self):self.drained+=1;self.complete=True
            def stream_facts(self):return {'model':True}
        source=Source();trace=SimpleNamespace(collect=Mock(),snapshot=Mock(return_value={}))
        with patch.object(worker,'_BundleWorkerInput',Source), \
                patch.object(effect_module,'NativeMutationIO',return_value=io), \
                patch.object(effect_module,'NativeRootMutex',Lock), \
                patch.object(effect_module,'NativeScopedTarget',Scope), \
                patch.object(effect_module,'_MutationTrace',return_value=trace):
            receipt,evidence=effect_module.execute_bundle_create(grant,value['effect'],source,
                run_id=value['context']['run_id'],timestamp=value['timestamp'])
        self.assertEqual(receipt['status'],'indeterminate');self.assertIsNone(receipt['bytes_written'])
        self.assertFalse(receipt['after']['known']);self.assertGreater(io.ack,0)
        self.assertEqual(evidence['acknowledged_bytes_written_lower_bound'],io.ack)
        self.assertEqual(evidence['primary_error']['code'],'injected.metadata_readback')
        self.assertEqual(evidence['handle_finalization'],'closed');self.assertEqual(io._handles,{})
        self.assertEqual(source.drained,1);self.assertFalse(evidence['worker_exit_established'])


if __name__=='__main__':unittest.main()
