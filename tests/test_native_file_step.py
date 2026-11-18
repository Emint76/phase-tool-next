"""Pure regression: real method/trace code with explicitly simulated OS calls.

No Windows native IO or target filesystem mutation. No qualification claim.
The bounded runner must stage and hash-check both reviewed source overlays.
"""
import ctypes
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import native, mutating, file_create


class _CFacade:
    def __getattr__(self, name):
        if name == 'get_last_error':
            return lambda: 5
        return getattr(ctypes,name)


class NativeFileStepTests(unittest.TestCase):
    def fault_io(self, *, status=0xc0000035, output=None, close_success=True):
        io = object.__new__(mutating.NativeMutationIO)
        io._init_mutation_session()
        io.events,io._handles,io._writable,io._created = [],{},set(),set()
        calls = {'create':[],'close':[]}
        def create(*args):
            calls['create'].append({'disposition':args[7],'sharing':args[6]})
            args[0]._obj.value = output
            args[3]._obj.Result.Status = ctypes.c_int32(status).value
            args[3]._obj.Information = 0
            return ctypes.c_int32(status).value
        def close(value):
            calls['close'].append(value)
            return 1 if value == 1000 or close_success else 0
        io.nt = SimpleNamespace(NtCreateFile=create)
        io.kernel = SimpleNamespace(CloseHandle=close)
        # Module-local OS seam; never patch ctypes itself or global os.stat.
        seam = patch.object(native,'C',_CFacade())
        seam.start()
        self.addCleanup(seam.stop)
        io.assert_object = lambda *args,**kwargs: {'attributes':0x10,'length':0,'links':1}
        parent = io._adopt(1000,directory=True)
        self.addCleanup(parent.close)
        identity = native.NativeIdentity(1,'00'*16)
        return io,parent,identity,calls

    def test_known_null_collision_has_denial_evidence_and_no_owned_output(self):
        io,parent,identity,calls = self.fault_io()
        with self.assertRaises(PhaseError) as caught:
            io.create_exclusive(parent,'synthetic.bin',directory=False,expected_parent=identity)
        self.assertEqual(caught.exception.code,'ntfs.create_failed')
        self.assertEqual(calls['create'],[{'disposition':2,'sharing':1}])
        self.assertEqual(calls['close'],[])
        self.assertEqual(io.events[0]['effect_state'],'not_committed_by_this_call')
        self.assertIs(io.events[0]['output_handle_present'],False)
        self.assertEqual(set(io._handles),{1000})
        self.assertEqual(io.mutation_state,'sealed')

    def test_unexpected_nonnull_denial_stays_unknown_after_successful_close(self):
        for operation in ('create','open'):
            with self.subTest(operation=operation):
                io,parent,identity,calls = self.fault_io(output=2000)
                with self.assertRaises(PhaseError) as caught:
                    if operation == 'create':
                        io.create_exclusive(parent,'synthetic.bin',directory=False,expected_parent=identity)
                    else:
                        io.open_writable(parent,'synthetic.bin',expected_parent=identity,expected=identity)
                self.assertEqual(caught.exception.code,'ntfs.'+operation+'_outcome_unknown')
                self.assertEqual(calls['close'],[2000])
                self.assertEqual(io.events[0]['effect_state'],'unknown')
                self.assertIs(io.events[0]['output_handle_present'],True)
                self.assertEqual(set(io._handles),{1000})
                self.assertEqual(io.mutation_state,'sealed')

    def test_failed_single_close_retains_unknown_handle_and_primary_outcome(self):
        io,parent,identity,calls = self.fault_io(output=2000,close_success=False)
        with self.assertRaises(PhaseError) as caught:
            io.create_exclusive(parent,'synthetic.bin',directory=False,expected_parent=identity)
        self.assertEqual(caught.exception.code,'ntfs.create_finalization_failed')
        self.assertEqual(caught.exception.details['primary_error']['code'],'ntfs.create_outcome_unknown')
        self.assertEqual(calls['close'],[2000])
        self.assertEqual(io._handles[2000].finalization_state,'unknown')
        self.assertEqual(io.events[0]['effect_state'],'unknown')
        self.assertEqual(io.events[0]['close_error']['code'],'ntfs.close_failed')
        self.assertEqual(io.mutation_state,'sealed')

    def test_success_status_without_output_is_never_created_or_usable(self):
        io,parent,identity,calls = self.fault_io(status=0,output=None)
        with self.assertRaises(PhaseError) as caught:
            io.create_exclusive(parent,'synthetic.bin',directory=False,expected_parent=identity)
        self.assertEqual(caught.exception.code,'ntfs.create_failed')
        self.assertEqual(io.events[0]['effect_state'],'unknown')
        self.assertIs(io.events[0]['output_handle_present'],False)
        self.assertEqual(calls['close'],[])
        self.assertEqual(set(io._handles),{1000})
        self.assertEqual(io.mutation_state,'sealed')

    def test_trace_retention_boundaries_preserve_exact_sequences_and_digest(self):
        for count in (64,65,128,129):
            with self.subTest(count=count):
                trace = file_create._MutationTrace()
                expected = hashlib.sha256()
                for number in range(count):
                    event = {'api':'synthetic','n':number}
                    expected.update(canonical_bytes(event)+b'\n')
                    trace.collect(SimpleNamespace(events=[event]))
                result = trace.snapshot()
                indices = list(range(count)) if count <= 128 else list(range(64))+list(range(count-64,count))
                self.assertEqual([item['n'] for item in result['records']],indices)
                self.assertEqual(result['canonical_jsonl_digest'],'sha256:'+expected.hexdigest())
                self.assertEqual(result['acknowledged_recorded_event_count'],count)
                self.assertEqual(result['omitted_middle_records'],max(0,count-128))
                self.assertIs(result['raw_records_complete'],count <= 128)
                self.assertIs(result['capture_complete'],True)

    def test_trace_more_than_old_limit_does_not_abort_event_processing(self):
        trace = file_create._MutationTrace()
        expected = hashlib.sha256()
        for number in range(5000):
            event = {'api':'synthetic','n':number}
            expected.update(canonical_bytes(event)+b'\n')
            trace.collect(SimpleNamespace(events=[event]))
        result = trace.snapshot()
        self.assertEqual(result['acknowledged_recorded_event_count'],5000)
        self.assertEqual(len(result['records']),128)
        self.assertEqual(result['omitted_middle_records'],4872)
        self.assertEqual(result['canonical_jsonl_digest'],'sha256:'+expected.hexdigest())
        self.assertIs(result['capture_complete'],True)
        self.assertIs(result['raw_records_complete'],False)

    def test_failed_serialization_revokes_complete_capture_and_never_rehashes(self):
        trace = file_create._MutationTrace()
        io = SimpleNamespace(events=[{'n':1},{'n':2},{'n':3}])
        def encode(event):
            if event['n'] == 2:
                raise OSError('synthetic diagnostic capture failure')
            return canonical_bytes(event)
        with patch.object(file_create,'canonical_bytes',encode):
            with self.assertRaises(OSError):
                trace.collect(io)
        first = trace.snapshot()
        self.assertIs(first['capture_complete'],False)
        self.assertIs(first['raw_records_complete'],False)
        self.assertIsNone(first['canonical_jsonl_digest'])
        self.assertEqual(first['acknowledged_recorded_event_count'],1)
        self.assertEqual(first['unacknowledged_records_upper_bound'],2)
        self.assertEqual(len(first['capture_errors']),1)
        self.assertEqual(io.events,[])
        trace.collect(io)
        self.assertEqual(trace.snapshot(),first)

    def test_failed_retention_bookkeeping_never_claims_complete_trace(self):
        class FailingList(list):
            def append(self,value):
                raise MemoryError('synthetic diagnostic retention failure')
        trace = file_create._MutationTrace()
        trace._first = FailingList()
        io = SimpleNamespace(events=[{'n':1},{'n':2}])
        with self.assertRaises(MemoryError):
            trace.collect(io)
        result = trace.snapshot()
        self.assertIs(result['capture_complete'],False)
        self.assertIs(result['raw_records_complete'],False)
        self.assertIsNone(result['canonical_jsonl_digest'])
        self.assertEqual(result['acknowledged_recorded_event_count'],1)
        self.assertEqual(result['unacknowledged_records_upper_bound'],1)
        self.assertEqual(result['records'],[])
        self.assertEqual(io.events,[])


if __name__ == '__main__':
    unittest.main()
