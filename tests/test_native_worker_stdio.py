"""Synthetic fixed-worker controls; exact frame type has deliberately fake I/O.

No Windows handle, pipe, NativeIO, target effects, Core admission or exit proof.
Old context/grant/effect fixture functions are reused, not a second protocol.
"""
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import worker, uncertainty
from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames
from tests.test_native_worker import context, grant, EFFECT, CONTENT


class FramedNativeWorkerTests(unittest.TestCase):
    def peer(self, *, go=None, receive_error=None, send_error=None, seal_error=None):
        peer=WindowsPipeFrames.__new__(WindowsPipeFrames)
        records={'sent':[],'sends':[],'receives':[],'seals':0,'effects':0,'poisoned':False}
        raw=canonical_bytes({'command':'execute_file_create','context':context()}) if go is None else go
        def send(value,deadline):
            records['sends'].append(deadline)
            if records['poisoned']:raise PhaseError('synthetic.poisoned')
            if send_error and records['sent']:raise send_error
            records['sent'].append(value)
        def receive(deadline,*,maximum_bytes):
            records['receives'].append((deadline,maximum_bytes))
            if receive_error:
                records['poisoned']=True
                raise receive_error
            if len(raw)>maximum_bytes:
                records['poisoned']=True
                raise PhaseError('synthetic.oversized_go')
            return raw,{'synthetic':True}
        def seal():
            records['seals']+=1
            if seal_error:raise seal_error
        peer.send_frame,peer.receive_frame,peer.seal=send,receive,seal
        self.peer_records=records
        return peer

    def invoke(self, peer, *, operation_error=None, diagnostic_error=False, clock_values=(100,150,500)):
        def effect(*args,**kwargs):
            self.peer_records['effects']+=1
            if operation_error:raise operation_error
            return {'status':'indeterminate'},{'worker_exit_established':False}
        diagnostic=uncertainty._error_record
        self.diagnostic_calls=[]
        self.diagnostic_faults=[]
        def report(error):
            self.diagnostic_calls.append(error)
            if diagnostic_error and len(self.diagnostic_calls)==1:
                fault=PhaseError('synthetic.diagnostic')
                self.diagnostic_faults.append(fault)
                raise fault
            return diagnostic(error)
        clock=iter(clock_values)
        with patch.object(worker,'os',SimpleNamespace(name='nt',getpid=os.getpid)), \
             patch.object(worker,'time',SimpleNamespace(perf_counter_ns=lambda:next(clock))), \
             patch.object(worker,'execute_file_create',side_effect=effect), \
             patch.object(uncertainty,'_error_record',side_effect=report):
            worker.run_file_create_worker(peer,context(),grant(),EFFECT,CONTENT,'synthetic-time')
        return [parse_json_bytes(raw) for raw in self.peer_records['sent']]

    def test_framed_ready_go_single_effect_and_separate_completion_window(self):
        peer=self.peer();frames=self.invoke(peer);r=self.peer_records
        self.assertEqual(r['effects'],1);self.assertEqual(r['seals'],1)
        self.assertEqual(r['receives'],[(30_000_000_100,4096)])
        self.assertEqual(r['sends'],[30_000_000_100,30_000_000_500])
        self.assertEqual(frames[-1]['effect_receipt'],{'status':'indeterminate'})
        self.assertIs(frames[-1]['worker_exit_established'],False)

    def test_wrong_go_never_executes_and_seals_once(self):
        peer=self.peer(go=canonical_bytes({'command':'wrong','context':context()}))
        frames=self.invoke(peer)
        self.assertEqual((self.peer_records['effects'],self.peer_records['seals']),(0,1))
        self.assertEqual(frames[-1]['error']['code'],'ntfs.worker_go_binding_mismatch')

    def test_noncanonical_and_oversized_go_have_no_effect(self):
        for raw in (b' '+canonical_bytes({'command':'execute_file_create','context':context()}),b'x'*4097):
            with self.subTest(length=len(raw)):
                peer=self.peer(go=raw)
                if len(raw)>4096:
                    with self.assertRaises(PhaseError) as error:self.invoke(peer)
                    self.assertEqual(error.exception.details['primary']['code'],'synthetic.oversized_go')
                    self.assertEqual(error.exception.details['transport']['code'],'synthetic.poisoned')
                    self.assertEqual(len(self.peer_records['sent']),1)
                else:
                    frames=self.invoke(peer)
                    self.assertEqual(len(frames),2)
                    self.assertEqual(frames[0]['worker_ready_version'],'1.0')
                    self.assertEqual(self.peer_records['receives'],[(30_000_000_100,4096)])
                    self.assertEqual(frames[-1]['error']['code'],'ntfs.worker_go_binding_mismatch')
                self.assertEqual((self.peer_records['effects'],self.peer_records['seals']),(0,1))

    def test_receive_error_poisoning_preserves_primary_and_failed_diagnostics(self):
        for code in ('synthetic.eof','synthetic.timeout'):
            with self.subTest(code=code):
                with self.assertRaises(PhaseError) as error:self.invoke(self.peer(receive_error=PhaseError(code)))
                self.assertEqual(error.exception.details['primary']['code'],code)
                self.assertEqual(error.exception.details['transport']['code'],'synthetic.poisoned')
                self.assertEqual((self.peer_records['effects'],self.peer_records['seals']),(0,1))
                self.assertEqual(len(self.peer_records['sent']),1)

    def test_operation_error_remains_error_completion(self):
        peer=self.peer();frames=self.invoke(peer,operation_error=PhaseError('synthetic.operation'))
        self.assertEqual(frames[-1]['error']['code'],'synthetic.operation')
        self.assertIsNone(frames[-1]['effect_receipt'])
        self.assertIs(frames[-1]['worker_exit_established'],False)

    def test_handshake_deadline_after_go_validation_prevents_effect(self):
        peer=self.peer()
        frames=self.invoke(peer,clock_values=(100,30_000_000_101,40_000_000_000))
        self.assertEqual((self.peer_records['effects'],self.peer_records['seals']),(0,1))
        self.assertEqual(frames[-1]['error']['code'],'ntfs.worker_go_deadline')
        self.assertEqual(self.peer_records['sends'],[30_000_000_100,70_000_000_000])

    def test_primary_send_and_seal_failures_are_retained(self):
        peer=self.peer(send_error=PhaseError('synthetic.send'),seal_error=PhaseError('synthetic.seal'))
        with self.assertRaises(PhaseError) as error:self.invoke(peer,operation_error=PhaseError('synthetic.operation'))
        self.assertEqual({k:error.exception.details[k]['code'] for k in ('primary','transport','finalization')},
                         {'primary':'synthetic.operation','transport':'synthetic.send','finalization':'synthetic.seal'})
        self.assertEqual(self.peer_records['seals'],1)

    def test_diagnostic_failure_still_seals_borrowed_transport(self):
        primary=PhaseError('synthetic.operation')
        frames=self.invoke(self.peer(),operation_error=primary,diagnostic_error=True)
        self.assertEqual(len(self.diagnostic_calls),1)
        self.assertIs(self.diagnostic_calls[0],primary)
        self.assertEqual(len(self.diagnostic_faults),1)
        self.assertEqual(self.diagnostic_faults[0].code,'synthetic.diagnostic')
        self.assertEqual((self.peer_records['effects'],self.peer_records['seals']),(1,1))
        self.assertEqual(len(frames),2)
        self.assertEqual(frames[0]['worker_ready_version'],'1.0')
        completion=frames[1]
        self.assertEqual(completion['error']['type'],'unavailable')
        self.assertIsNone(completion['error']['code'])
        self.assertEqual(completion['error']['details'],{'reporting_error':True})
        self.assertIsNone(completion['effect_receipt'])
        self.assertIsNone(completion['physical_evidence'])
        self.assertIs(completion['worker_exit_established'],False)

    def test_diagnostic_failure_with_seal_failure_retains_raw_errors(self):
        primary=PhaseError('synthetic.operation')
        finalization=PhaseError('synthetic.seal')
        with self.assertRaises(PhaseError) as caught:
            self.invoke(self.peer(seal_error=finalization),
                operation_error=primary,diagnostic_error=True)
        unavailable=caught.exception
        self.assertEqual(unavailable.code,'ntfs.worker_completion_or_finalization_unavailable')
        self.assertIs(unavailable.primary_error,primary)
        self.assertIsNone(unavailable.transport_error)
        self.assertIs(unavailable.finalization_error,finalization)
        self.assertIs(unavailable.__cause__,finalization)
        self.assertEqual(unavailable.details['primary']['code'],'synthetic.operation')
        self.assertEqual(unavailable.details['finalization']['code'],'synthetic.seal')
        self.assertIsNone(unavailable.details['transport'])
        self.assertIs(unavailable.details['worker_exit_established'],False)
        self.assertEqual(len(self.diagnostic_faults),1)
        self.assertEqual(len(self.diagnostic_calls),3)
        self.assertIs(self.diagnostic_calls[0],primary)
        self.assertIs(self.diagnostic_calls[1],primary)
        self.assertIs(self.diagnostic_calls[2],finalization)
        frames=[parse_json_bytes(raw)for raw in self.peer_records['sent']]
        self.assertEqual(len(frames),2)
        self.assertEqual(frames[-1]['error']['type'],'unavailable')
        self.assertIsNone(frames[-1]['effect_receipt'])
        self.assertIs(frames[-1]['worker_exit_established'],False)
        self.assertEqual((self.peer_records['effects'],self.peer_records['seals']),(1,1))

    def test_wrong_type_and_subclass_are_rejected_before_transport(self):
        class Derived(WindowsPipeFrames):pass
        for peer in (object(),Derived.__new__(Derived)):
            with self.subTest(kind=type(peer).__name__), \
                 patch.object(worker,'os',SimpleNamespace(name='nt',getpid=os.getpid)), \
                 patch.object(worker._connection,'PipeConnection',type('OtherPipe',(),{}),create=True), \
                 patch.object(worker,'execute_file_create') as effect, self.assertRaises(PhaseError) as error:
                worker.run_file_create_worker(peer,context(),grant(),EFFECT,CONTENT,'x')
            self.assertEqual(error.exception.code,'ntfs.windows_worker_pipe_required');effect.assert_not_called()
