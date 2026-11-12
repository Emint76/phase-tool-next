"""Portable fault models for exact bundle failure ownership; no NTFS effects."""
from types import SimpleNamespace
import time
import unittest
from unittest.mock import Mock,patch

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
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

    def effect_boundaries(self, *, metadata_failure=False, before_failure=False, stage=None):
        """Reuse the adopted-handle model at the native I/O boundaries."""
        class IO(NativeIO):
            def __init__(self):
                self._handles = {}
                self.kernel = SimpleNamespace(CloseHandle=Mock(return_value=1))
                self.counter, self.ack, self.mutation_state = 20, 0, 'active'
                self.bodies = {}
                self.rename = Mock(side_effect=AssertionError('negative must not rename'))
                self.flush_namespace = Mock()

            def identity(self, handle):
                if stage is not None and handle.value == 21:
                    return NativeIdentity.parse(stage['native_identity'])
                return NativeIdentity(7, ('0' * 30) + format(handle.value, '02x'))

            def child(self, *args, **kwargs):
                if before_failure:
                    raise PhaseError('injected.before_sample')
                raise PhaseError('ntfs.open_failed', details={'ntstatus': '0xc0000034'})

            def create_exclusive(self, *args, directory, **kwargs):
                self.counter += 1
                self.bodies[self.counter] = bytearray()
                return self._adopt(self.counter, directory=directory)

            def directory_stat_identity(self, *args):
                return stage['stat_identity'] if stage is not None else {'device': 7, 'inode': 22}

            def write_chunk(self, handle, data, *, offset, expected):
                body = self.bodies[handle.value]
                assert offset == len(body) and self.identity(handle) == expected
                body.extend(data)
                self.ack += len(data)
                return len(data)

            def flush_file(self, *args):
                pass

            def hash_file(self, handle, length):
                if metadata_failure:
                    raise PhaseError('injected.metadata_readback')
                body = self.bodies[handle.value]
                assert len(body) == length
                return digest_bytes(bytes(body)), length

            def seal_mutations(self):
                self.mutation_state = 'sealed'

        io = IO()

        class Lock:
            def __init__(self, *args):
                self.state, self.events = 'open', []

            def assert_held(self):
                assert self.state == 'held'

            def __enter__(self):
                self.state = 'held'
                return self

            def __exit__(self, *args):
                self.state = 'closed'

        class Scope:
            def __init__(self, *args, **kwargs):
                self.parent = io._adopt(10, directory=True)
                self.parent_identity = io.identity(self.parent)
                self.name = 'bundle'

            def assert_bound(self):
                assert self.parent.value in io._handles

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.parent.close()

        trace = SimpleNamespace(collect=Mock(), snapshot=Mock(return_value={}))
        boundaries = {'NativeMutationIO': Mock(return_value=io), 'NativeRootMutex': Lock,
                      'NativeScopedTarget': Scope, '_MutationTrace': Mock(return_value=trace)}
        return io, boundaries

    def test_written_metadata_then_readback_fault_is_indeterminate_with_lower_bound(self):
        from phase_tool.mutation.ntfs import bundle_effect as effect_module
        project=projection();value=worker._bundle_projection_value(project)
        grant=SimpleNamespace(as_dict=lambda:value['grant'])
        io, boundaries = self.effect_boundaries(metadata_failure=True)
        class Source:
            def __init__(self):self.projection=project;self._go_attempted=True;self.complete=False;self.drained=0
            def _check(self):pass
            def finish_remaining(self):self.drained+=1;self.complete=True
            def stream_facts(self):return {'model':True}
        source=Source()
        with patch.object(worker,'_BundleWorkerInput',Source), patch.multiple(effect_module, **boundaries):
            receipt,evidence=effect_module.execute_bundle_create(grant,value['effect'],source,
                run_id=value['context']['run_id'],timestamp=value['timestamp'])
        self.assertEqual(receipt['status'],'indeterminate');self.assertIsNone(receipt['bytes_written'])
        self.assertFalse(receipt['after']['known']);self.assertGreater(io.ack,0)
        self.assertEqual(evidence['acknowledged_bytes_written_lower_bound'],io.ack)
        self.assertEqual(evidence['primary_error']['code'],'injected.metadata_readback')
        self.assertEqual(evidence['handle_finalization'],'closed');self.assertEqual(io._handles,{})
        self.assertEqual(source.drained,1);self.assertFalse(evidence['worker_exit_established'])

    def test_refused_prepared_ack_keeps_attempted_effect_in_actual_worker_terminal(self):
        from phase_tool.mutation.ntfs import bundle_effect, windows_pipe
        from phase_tool.mutation.ntfs.bundle_recovery_capture import run_bundle_worker_capture
        from phase_tool.mutation.ntfs.bundle_prepared import prepared_ack
        from .test_native_bundle2_prepared import b2_projection, native_stage
        from .test_native_bundle_protocol import Pipe, frames

        project = b2_projection()
        context = parse_json_bytes(project.context_bytes)
        stage = native_stage(project)
        first = frames(project, 1)
        go = canonical_bytes({'command': 'execute_bundle', 'context': context,
            'rewound_token': parse_json_bytes(worker._bundle_token(first[0], 'rewound')),
            'go_token': parse_json_bytes(worker._bundle_token(first[0], 'go'))})
        deadline = time.perf_counter_ns() + 29_000_000_000

        class AckPipe(Pipe):
            def __init__(self):
                super().__init__(first + [go] + frames(project, 2))
                self.sent = []
                self.seal = Mock()

            def send_frame(self, raw, selected_deadline):
                assert selected_deadline == deadline
                message = parse_json_bytes(raw)
                self.sent.append(message)
                if 'bundle_prepared_version' in message:
                    ack = prepared_ack(message, 'sha256:' + '8' * 64, 'sha256:' + '9' * 64)
                    original = ack['prepared_message_digest']
                    ack['prepared_message_digest'] = original[:-1] + ('1' if original[-1] == '0' else '0')
                    self.rows.append(canonical_bytes(ack))

        for before_failure in (False, True):
            with self.subTest(before_failure=before_failure):
                pipe = AckPipe()
                io, boundaries = self.effect_boundaries(before_failure=before_failure, stage=stage)
                verify_stage = Mock(return_value=stage)
                with patch.multiple(bundle_effect, verify_bundle_handle=verify_stage, **boundaries), \
                        patch.object(worker, 'WindowsPipeFrames', AckPipe), \
                        patch.object(windows_pipe, 'WindowsPipeFrames', AckPipe), \
                        patch.object(worker.os, 'name', 'nt'), \
                        patch('phase_tool.mutation.ntfs.bundle_recovery_terminal.windows_terminal') as terminal:
                    run_bundle_worker_capture(pipe, project, CHANNEL, _transfer_deadline_ns=deadline)
                terminal.assert_called_once()
                self.assertEqual(terminal.call_args.args, (pipe,))
                self.assertIs(terminal.call_args.kwargs['sending'], True)
                completion = parse_json_bytes(terminal.call_args.kwargs['raw'])
                self.assertEqual(completion['context'], context)
                self.assertIs(completion['worker_exit_established'], False)
                receipt, physical = completion['effect_receipt'], completion['physical_evidence']
                self.assertEqual(physical['namespace_flushed'], [])
                self.assertIsNone(physical['rename'])
                self.assertEqual(physical['handle_finalization'], 'closed')
                self.assertEqual(io._handles, {})
                io.rename.assert_not_called()
                self.assertNotIn(10, [call.args[0].value for call in io.flush_namespace.call_args_list])
                pipe.seal.assert_called_once_with()
                self.assertEqual(pipe.rows, [])
                if before_failure:
                    verify_stage.assert_not_called()
                    self.assertIsNone(receipt)
                    self.assertEqual(completion['error']['code'], 'ntfs.effect_outcome_unavailable')
                    self.assertEqual(physical['prepared_checkpoint'], {'message': None, 'ack': None})
                else:
                    verify_stage.assert_called_once()
                    self.assertIsNone(completion['error'])
                    self.assertEqual((receipt['attempted'], receipt['status']), (True, 'indeterminate'))
                    self.assertIs(receipt['after']['known'], False)
                    code = 'ntfs.bundle_prepared_ack_binding_mismatch'
                    self.assertEqual(physical['primary_error']['code'], code)
                    self.assertEqual(receipt['error']['code'], code)
                    self.assertEqual(physical['prepared_checkpoint'], {'message': pipe.sent[-1], 'ack': None})
                    self.assertEqual(physical['stream_binding']['complete'], True)
                    self.assertEqual(physical['stream_binding']['failed'], True)


if __name__=='__main__':unittest.main()
