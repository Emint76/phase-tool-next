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


class NativeWorkerFrameTests(unittest.TestCase):
    """Synthetic frame attacks; no transport, HANDLE or exit proof is exercised."""

    def setUp(self):
        self.pid = 42
        self.effect = EFFECT | {'target': {'root_binding': 'phase_result_root', 'relative_locator': 'sample.txt'}}
        self.ready = {'worker_ready_version': '1.0', 'context': context(), 'pid': self.pid,
            'grant_digest': digest_bytes(canonical_bytes(grant())),
            'effect_digest': digest_bytes(canonical_bytes(self.effect)),
            'content_digest': digest_bytes(CONTENT), 'content_length': len(CONTENT)}
        self.completion = {'worker_completion_version': '1.0', 'context': context(), 'pid': self.pid,
            'effect_receipt': {'run_id': context()['run_id'], 'effect_id': self.effect['effect_id'],
                'kind': 'exclusive_create', 'status': 'indeterminate'},
            'physical_evidence': {'native_file_create_version': '1.0', 'run_id': context()['run_id'],
                'effect_id': self.effect['effect_id'], 'grant': grant(), 'locator': 'sample.txt',
                'worker_exit_established': False},
            'error': None, 'worker_exit_established': False}

    def ready_frame(self, value):
        return worker.validate_worker_ready(canonical_bytes(value), context=context(), grant_data=grant(),
            effect=self.effect, content=CONTENT, expected_pid=self.pid)

    def completion_frame(self, value):
        return worker.validate_worker_completion(canonical_bytes(value), context=context(), grant_data=grant(),
            effect=self.effect, expected_pid=self.pid)

    def test_ready_is_only_a_bound_echo_and_returns_detached_data(self):
        result = self.ready_frame(self.ready)
        self.assertEqual(result, self.ready)
        result['context']['run_id'] = 'changed'
        self.assertEqual(self.ready['context']['run_id'], context()['run_id'])
        self.assertNotIn('worker_exit_established', result)

    def test_ready_rejects_replayed_context_pid_and_byte_bindings(self):
        for field, value in [('pid', 43), ('pid', True), ('content_length', True),
                             ('grant_digest', 'sha256:'+'a'*64), ('effect_digest', 'sha256:'+'b'*64),
                             ('content_digest', 'sha256:'+'c'*64),
                             ('context', context() | {'intent_digest': 'sha256:'+'d'*64})]:
            with self.subTest(field=field, value=value), self.assertRaises(PhaseError):
                self.ready_frame(self.ready | {field: value})

    def test_ready_rejects_parent_content_mismatch(self):
        with self.assertRaises(PhaseError):
            worker.validate_worker_ready(canonical_bytes(self.ready), context=context(), grant_data=grant(),
                effect=self.effect | {'content_length': 0}, content=CONTENT, expected_pid=self.pid)

    def test_completion_preserves_indeterminate_without_attesting_exit(self):
        result = self.completion_frame(self.completion)
        self.assertEqual(result['effect_receipt']['status'], 'indeterminate')
        self.assertIs(result['worker_exit_established'], False)
        self.assertIs(result['physical_evidence']['worker_exit_established'], False)
        # Correlation is not the standard effect-receipt schema validation.
        self.assertNotIn('effect_receipt_version', result['effect_receipt'])

    def test_completion_rejects_wrong_context_pid_or_self_attested_exit(self):
        for field, value in [('context', context() | {'operation_nonce': '3'*32}),
                             ('pid', True), ('pid', 43), ('worker_exit_established', True),
                             ('worker_exit_established', 0), ('worker_completion_version', '2.0')]:
            with self.subTest(field=field, value=value), self.assertRaises(PhaseError):
                self.completion_frame(self.completion | {field: value})

    def test_completion_rejects_receipt_and_physical_cross_binding(self):
        for key, field, value in [('effect_receipt', 'run_id', 'other'),
            ('effect_receipt', 'effect_id', 'other'), ('effect_receipt', 'kind', 'replace'),
            ('physical_evidence', 'grant', grant() | {'volume_serial32': 2}),
            ('physical_evidence', 'grant', grant() | {'volume_serial32': True}),
            ('physical_evidence', 'grant', grant() | {'native_identity': grant()['native_identity'] | {'volume_serial': True}}),
            ('physical_evidence', 'locator', 'other.txt'),
            ('physical_evidence', 'effect_id', 'other'),
            ('physical_evidence', 'worker_exit_established', True)]:
            with self.subTest(key=key, field=field), self.assertRaises(PhaseError):
                self.completion_frame(self.completion | {key: self.completion[key] | {field: value}})

    def test_error_completion_preserves_unknown_and_rejects_contradictory_receipt(self):
        error = {'type': 'PhaseError', 'code': 'ntfs.effect_outcome_unavailable',
                 'message': 'synthetic-only', 'details': {'ntstatus': '0xc0000280'}}
        value = self.completion | {'error': error, 'effect_receipt': None}
        self.assertEqual(self.completion_frame(value), value)
        with self.assertRaises(PhaseError):
            self.completion_frame(self.completion | {'error': error})
        with self.assertRaises(PhaseError):
            self.completion_frame(value | {'error': error | {'unexpected': True}})
        with self.assertRaises(PhaseError):
            self.completion_frame(self.completion | {'physical_evidence': None})

    def test_frames_reject_extra_keys_noncanonical_duplicate_and_oversized_bytes(self):
        with self.assertRaises(PhaseError):
            self.ready_frame(self.ready | {'unexpected': True})
        with self.assertRaises(PhaseError):
            self.completion_frame(self.completion | {'unexpected': True})
        duplicate_pid = canonical_bytes(self.ready)[:-1] + b',"pid":42}'
        for raw in [b' '+canonical_bytes(self.ready), duplicate_pid, b'x'*(512*1024+1)]:
            with self.subTest(length=len(raw)), self.assertRaises(PhaseError):
                worker.validate_worker_ready(raw, context=context(), grant_data=grant(),
                    effect=self.effect, content=CONTENT, expected_pid=self.pid)


if __name__ == '__main__':
    unittest.main()
