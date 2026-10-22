"""Pure worker protocol/error regressions: all peers and effects are synthetic.

No Windows HANDLE, PipeConnection transport, filesystem effect, Core admission,
qualification assertion or process-exit proof is exercised by these tests.
"""
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import worker


def context():
    return {'worker_protocol': 'phase.native.file-worker', 'worker_version': '1.0',
        'run_id': 'synthetic-worker-test', 'operation_nonce': '1'*32,
        **{key: 'sha256:'+'2'*64 for key in ('intent_digest', 'effect_plan_digest',
            'native_binding_digest', 'installation_digest', 'implementation_artifact_digest')}}


def grant():
    return {'root_binding': 'phase_result_root', 'device': '\\Device\\HarddiskVolume6',
        'volume_guid': '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\',
        'volume_serial32': 1, 'components': ['synthetic'],
        'native_identity': {'volume_serial': 1, 'file_id': '3'*32}}


CONTENT = b'synthetic-only'
EFFECT = {'kind': 'exclusive_create', 'effect_id': 'synthetic-effect',
    'content_digest': digest_bytes(CONTENT), 'content_length': len(CONTENT)}


class SyntheticPipe:
    def __init__(self, go=None, *, completion_error=None, close_error=None, ready_error=None):
        self.go = canonical_bytes({'command': 'execute_file_create', 'context': context()}) if go is None else go
        self.sent = []
        self.close_count = 0
        self.completion_error, self.close_error, self.ready_error = completion_error, close_error, ready_error

    def send_bytes(self, raw):
        if not self.sent and self.ready_error is not None:
            raise self.ready_error
        if self.sent and self.completion_error is not None:
            raise self.completion_error
        self.sent.append(raw)

    def poll(self, timeout):
        return True

    def recv_bytes(self, maxlength):
        if len(self.go) > maxlength:
            raise OSError('synthetic oversized frame')
        return self.go

    def close(self):
        self.close_count += 1
        if self.close_error is not None:
            raise self.close_error


class NativeWorkerTests(unittest.TestCase):
    def invoke(self, pipe, *, ctx=None, effect_result=None, effect_error=None):
        result = ({'status': 'indeterminate'}, {'worker_exit_established': False}) if effect_result is None else effect_result
        with patch.object(worker, 'os', SimpleNamespace(name='nt', getpid=os.getpid)), \
             patch.object(worker._connection, 'PipeConnection', SyntheticPipe, create=True), \
             patch.object(worker, 'execute_file_create', return_value=result, side_effect=effect_error) as execute:
            try:
                worker.run_file_create_worker(pipe, context() if ctx is None else ctx,
                    grant(), EFFECT, CONTENT, '2026-01-01T00:00:00Z')
            finally:
                self.executions = execute.call_count
        return [parse_json_bytes(raw) for raw in pipe.sent]

    def test_linux_import_is_available_without_windows_pipe_class(self):
        self.assertTrue(sys.platform.startswith('linux'))
        self.assertEqual(worker.__name__, 'phase_tool.mutation.ntfs.worker')
        self.assertEqual(worker._context(context()), context())

    def test_context_is_closed_and_typed(self):
        for value in (context() | {'extra': 1}, context() | {'intent_digest': True},
                      context() | {'operation_nonce': 'bad'}, context() | {'run_id': '../x'}):
            with self.assertRaises(PhaseError):
                worker._context(value)

    def test_non_windows_refuses_without_touching_peer(self):
        peer = SyntheticPipe()
        with self.assertRaises(PhaseError) as caught:
            worker.run_file_create_worker(peer, context(), grant(), EFFECT, CONTENT, 'x')
        self.assertEqual(caught.exception.code, 'ntfs.windows_worker_pipe_required')
        self.assertEqual((peer.sent, peer.close_count), ([], 0))

    def test_bad_go_never_executes(self):
        peer = SyntheticPipe(go=canonical_bytes({'command': 'wrong', 'context': context()}))
        frames = self.invoke(peer)
        self.assertEqual(self.executions, 0)
        self.assertEqual(peer.close_count, 1)
        self.assertEqual(frames[-1]['error']['code'], 'ntfs.worker_go_binding_mismatch')
        self.assertIs(frames[-1]['worker_exit_established'], False)

    def test_noncanonical_go_never_executes(self):
        peer = SyntheticPipe(go=b' '+canonical_bytes({'command': 'execute_file_create', 'context': context()}))
        self.invoke(peer)
        self.assertEqual((self.executions, peer.close_count), (0, 1))

    def test_effect_status_is_forwarded_without_self_attested_exit(self):
        peer = SyntheticPipe()
        frames = self.invoke(peer)
        self.assertEqual((self.executions, peer.close_count), (1, 1))
        self.assertEqual(frames[-1]['effect_receipt'], {'status': 'indeterminate'})
        self.assertIsNone(frames[-1]['error'])
        self.assertIs(frames[-1]['worker_exit_established'], False)

    def test_outcome_unavailable_preserves_physical_evidence(self):
        peer = SyntheticPipe()
        physical = {'worker_exit_established': False, 'synthetic': True}
        frames = self.invoke(peer, effect_error=worker.NativeFileCreateOutcomeUnavailable(physical))
        self.assertEqual(frames[-1]['physical_evidence'], physical)
        self.assertIsNone(frames[-1]['effect_receipt'])
        self.assertEqual((self.executions, peer.close_count), (1, 1))

    def test_operation_transport_and_close_errors_are_independent(self):
        peer = SyntheticPipe(completion_error=PhaseError('synthetic.transport'),
                             close_error=PhaseError('synthetic.close'))
        with self.assertRaises(PhaseError) as caught:
            self.invoke(peer, effect_error=PhaseError('synthetic.operation'))
        self.assertEqual({key: caught.exception.details[key]['code'] for key in ('primary', 'transport', 'finalization')},
            {'primary': 'synthetic.operation', 'transport': 'synthetic.transport', 'finalization': 'synthetic.close'})
        self.assertEqual(peer.close_count, 1)

    def test_diagnostic_construction_failure_still_closes(self):
        peer = SyntheticPipe(close_error=PhaseError('synthetic.close'))
        original = worker._error_record
        calls = 0
        def diagnostic(error):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise PhaseError('synthetic.diagnostic')
            return original(error)
        with patch.object(worker, '_error_record', side_effect=diagnostic), self.assertRaises(PhaseError) as caught:
            self.invoke(peer, effect_error=PhaseError('synthetic.operation'))
        self.assertEqual(caught.exception.details['primary']['code'], 'synthetic.operation')
        self.assertEqual(caught.exception.details['transport']['code'], 'synthetic.diagnostic')
        self.assertEqual(caught.exception.details['finalization']['code'], 'synthetic.close')
        self.assertEqual(peer.close_count, 1)

    def test_invalid_context_is_not_echoed(self):
        peer = SyntheticPipe()
        frames = self.invoke(peer, ctx=context() | {'unexpected': object()})
        self.assertEqual((self.executions, peer.close_count), (0, 1))
        self.assertIsNone(frames[-1]['context'])
        self.assertEqual(frames[-1]['error']['code'], 'ntfs.worker_context_shape')


if __name__ == '__main__':
    unittest.main()
