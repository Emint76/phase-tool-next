"""Actual qualified ext4 Core/fault components, never native admission.

The ordinary Host executor, registry, profile and qualification remain real.
The private terminal context is exercised only as a lifecycle component on
owned synthetic ext4 objects. This does not select a native installation or
bypass a guard for NTFS. Finalizer/bootstrap/closure remain unimplemented.
Unlock/close injections below are synthetic faults; normal contention uses
existing test_native_core_original_gate's actual child/kernel observation.
"""
from dataclasses import replace
import errno
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from phase_tool import core as core_module
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.core import PhaseCore, PhaseRequest, _NativeRunContext, _OperationalFileLock
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run
from phase_tool.mutation.broker import EffectBroker, BrokerExecutionInterrupted
from phase_tool.installation import _linux_filesystem_type, qualify_host_authority_roots
from phase_tool.registry import BundledRegistry


@unittest.skipUnless(sys.platform.startswith('linux'), 'NOT_VERIFIED: actual Linux/ext4 required')
class NativeTerminalCoreExt4Tests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix='phase-terminal-component-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.target = self.root/'target'; self.target.mkdir(mode=0o700)
        self.evidence = self.root/'evidence'; self.evidence.mkdir(mode=0o700)
        try:
            qualify_host_authority_roots({'evidence': self.evidence, 'target': self.target})
            fs = _linux_filesystem_type(self.evidence)
        except PhaseError as error:
            self.skipTest('NOT_VERIFIED: actual qualification unavailable: ' + error.code)
        if fs != 'ext4':
            self.skipTest('NOT_VERIFIED: actual filesystem ' + fs)
        self.registry = BundledRegistry.load(); self.core = PhaseCore(self.registry)
        self.payload = b'synthetic-terminal-component\x00\xff\r\n'
        self.source = self.root/'source.bin'; self.source.write_bytes(self.payload)
        self.candidate = self.root/'candidate.json'
        self.candidate.write_bytes(canonical_bytes({'operation_id': 'synthetic-terminal',
            'target_locator': 'result.bin', 'input_binding': 'payload',
            'idempotency_key': 'synthetic-terminal-key'}))
        exact = self.registry.contract_bindings()['file_create.v1@1.0.0']
        self.request = PhaseRequest(exact['id'], exact['version'], exact['package_digest'],
            self.candidate, self.evidence, 'synthetic-first', {'payload': self.source},
            {'phase_result_root': self.target}, timestamp='2026-10-22T00:00:00Z')

    def deferred(self, context=None, *, execute=True, request=None):
        context = _NativeRunContext() if context is None else context
        outcome = self.core._run_lifecycle(request or self.request, execute=execute, native_ctx=context)
        return context, outcome

    def no_receipt(self, context):
        self.assertIsNotNone(context.store)
        self.assertFalse((context.store.run_root/'receipt.json').exists())
        self.assertFalse(context.publication_attempted)

    def report(self, value):
        output = os.environ.get('EVIDENCE')
        if output:
            path = Path(output)/'native-terminal-components'; path.mkdir(exist_ok=True)
            with (path/(self._testMethodName+'.json')).open('xb') as stream:
                stream.write(canonical_bytes({'scope': 'qualified ext4 lifecycle component, NOT native admission',
                    'case': self._testMethodName, **value}))

    def test_public_host_run_still_commits_and_independently_inspects(self):
        outcome = self.core.run(self.request, execute=True)
        self.assertEqual(outcome.exit_code, 0); self.assertIsNotNone(outcome.receipt_digest)
        inspected = inspect_run(self.evidence, self.request.run_id, self.registry,
            root_bindings=self.request.root_bindings)
        self.assertTrue(inspected['target_verified'])
        self.assertEqual(inspected['receipt_digest'], outcome.receipt_digest)
        self.report({'receipt': outcome.receipt, 'receipt_digest': outcome.receipt_digest,
            'inspection': inspected})

    def test_planned_draft_has_original_but_no_terminal_publication(self):
        context, outcome = self.deferred(execute=False)
        self.assertEqual(outcome.receipt['terminal_status'], 'validated_planned')
        self.assertIsNone(outcome.receipt_digest); self.assertTrue(context.intent_recording_started)
        self.assertFalse(context.broker_entered)
        self.assertTrue((context.store.run_root/'intent.json').is_file())
        self.assertFalse((self.target/'result.bin').exists()); self.no_receipt(context)
        self.report({'intent': outcome.intent, 'plan': outcome.effect_plan, 'draft': outcome.receipt})

    def test_executed_posix_component_keeps_receipt_pending_after_effect(self):
        context, outcome = self.deferred()
        self.assertEqual((self.target/'result.bin').read_bytes(), self.payload)
        self.assertTrue(context.broker_entered); self.assertTrue(context.intent_recording_started)
        self.assertEqual(outcome.receipt['terminal_status'], 'succeeded_verified')
        self.assertIsNone(outcome.receipt_digest); self.no_receipt(context)
        self.report({'intent': outcome.intent, 'plan': outcome.effect_plan, 'draft': outcome.receipt,
            'readback_digest': digest_bytes((self.target/'result.bin').read_bytes())})

    def test_pending_bytes_are_not_aliased_by_returned_dicts(self):
        context, outcome = self.deferred(execute=False)
        raw = context.prepared_bytes
        outcome.receipt['blockers'].append('synthetic.external-mutation')
        outcome.intent['run_id'] = 'synthetic-mutated'; outcome.effect_plan['effects'].clear()
        self.assertEqual(context.prepared_bytes, raw)
        view = context.prepared
        self.assertEqual(view.intent['run_id'], self.request.run_id)
        self.assertEqual(len(view.effect_plan['effects']), 1)
        self.assertNotIn('synthetic.external-mutation', view.receipt['blockers'])
        view.receipt.clear(); self.assertTrue(context.prepared.receipt)
        self.no_receipt(context)

    def test_reused_context_refuses_before_second_reservation(self):
        context, _ = self.deferred(execute=False)
        second = replace(self.request, run_id='synthetic-second')
        with self.assertRaisesRegex(PhaseError, 'ntfs.terminal_context_consumed'):
            self.deferred(context, request=second)
        self.assertFalse((self.evidence/'.phase/runs'/second.run_id).exists())
        self.no_receipt(context)

    def test_nonfresh_context_flags_refuse_before_any_store(self):
        for field in ('started', 'inner_entered', 'intent_recording_started', 'broker_entered',
                      'preparation_attempted', 'publication_attempted', 'possible_dispatch'):
            with self.subTest(field=field):
                context = _NativeRunContext(); setattr(context, field, True)
                with self.assertRaisesRegex(PhaseError, 'ntfs.terminal_context_consumed'):
                    self.deferred(context)
                self.assertFalse((self.evidence/'.phase').exists())

    def test_reuse_terminal_site_is_deferred_without_new_effect(self):
        first = self.core.run(self.request, execute=True); self.assertEqual(first.exit_code, 0)
        context, outcome = self.deferred(request=replace(self.request, run_id='synthetic-reuse'))
        self.assertEqual(outcome.receipt['execution_disposition'], 'reused_existing')
        self.assertFalse(context.broker_entered); self.assertIsNone(outcome.intent)
        self.assertEqual((self.target/'result.bin').read_bytes(), self.payload)
        self.no_receipt(context)

    def test_early_rejection_is_deferred_without_capture_or_target_effect(self):
        context, outcome = self.deferred(request=replace(self.request, contract_digest='sha256:'+'0'*64))
        self.assertEqual(outcome.receipt['terminal_status'], 'rejected')
        self.assertFalse(context.inner_entered); self.assertFalse(context.intent_recording_started)
        self.assertIsNone(outcome.intent); self.assertFalse((self.target/'result.bin').exists())
        self.no_receipt(context)

    def test_per_key_exit_fault_keeps_executed_draft_and_original_primary(self):
        primary = OSError(errno.EIO, 'synthetic per-key exit fault AFTER actual cleanup')
        real = _OperationalFileLock.__exit__
        def after_cleanup(lock, *args):
            real(lock, *args)
            if lock._checked_release:
                raise primary
        context = _NativeRunContext()
        with patch.object(_OperationalFileLock, '__exit__', after_cleanup):
            with self.assertRaises(OSError) as caught:
                self.deferred(context)
        self.assertIs(caught.exception, primary)
        self.assertEqual((self.target/'result.bin').read_bytes(), self.payload)
        self.assertEqual(context.prepared.receipt['terminal_status'], 'succeeded_verified')
        self.assertIsNone(context.prepared.receipt_digest); self.no_receipt(context)
        self.report({'synthetic_fault': str(primary), 'draft': context.prepared.receipt,
            'native_finalization': 'NOT_IMPLEMENTED; draft is not a delivered success'})

    def test_serialization_failure_after_effect_never_becomes_rejection(self):
        primary = OSError(errno.EIO, 'synthetic terminal serialization failure')
        real = _NativeRunContext.prepare
        def broken(context, store, outcome):
            with patch('phase_tool.canonical.canonical_bytes', side_effect=primary):
                return real(context, store, outcome)
        context = _NativeRunContext()
        with patch.object(_NativeRunContext, 'prepare', broken):
            with self.assertRaises(OSError) as caught:
                self.deferred(context)
        self.assertIs(caught.exception, primary); self.assertTrue(context.preparation_attempted)
        self.assertIsNone(context.prepared_bytes)
        self.assertEqual((self.target/'result.bin').read_bytes(), self.payload)
        self.assertTrue((context.store.run_root/'intent.json').is_file()); self.no_receipt(context)
        self.report({'synthetic_fault': str(primary), 'draft_present': False,
            'original_present': True, 'readback_digest': digest_bytes((self.target/'result.bin').read_bytes()),
            'disposition': 'unresolved; no no-effect receipt'})

    def test_decode_failure_after_draft_does_not_attempt_second_preparation(self):
        primary = OSError(errno.EIO, 'synthetic draft view decoding failure')
        real = _NativeRunContext.prepare
        calls = []
        def broken(context, store, outcome):
            calls.append(1)
            with patch('phase_tool.core.parse_json_bytes', side_effect=primary):
                return real(context, store, outcome)
        context = _NativeRunContext()
        with patch.object(_NativeRunContext, 'prepare', broken):
            with self.assertRaises(OSError) as caught:
                self.deferred(context)
        self.assertIs(caught.exception, primary); self.assertEqual(calls, [1])
        self.assertIsNotNone(context.prepared_bytes)
        self.assertEqual(context.prepared.intent['run_id'], self.request.run_id)
        self.no_receipt(context)

    def test_lost_reply_after_real_posix_effect_keeps_sticky_unknown_dispatch(self):
        real = EffectBroker.execute
        def lost_reply(broker, *args, **kwargs):
            completed = real(broker, *args, **kwargs)
            self.assertEqual(len(completed.effect_receipts), 1)
            self.assertEqual(completed.effect_receipts[0]['status'], 'applied_verified')
            raise BrokerExecutionInterrupted(PhaseError('transport.synthetic_reply_lost'),
                [], None, possible_dispatch=True)
        with patch.object(EffectBroker, 'execute', lost_reply):
            context, outcome = self.deferred()
        self.assertTrue(context.possible_dispatch); self.assertTrue(context.broker_entered)
        self.assertEqual((self.target/'result.bin').read_bytes(), self.payload)
        self.assertEqual(outcome.receipt['terminal_status'], 'indeterminate')
        self.assertTrue(outcome.receipt['mutation_attempted'])
        self.assertIn('broker.dispatch_outcome_unknown', outcome.receipt['blockers'])
        self.assertIsNone(outcome.receipt['canonical_result']); self.no_receipt(context)
        self.report({'fault': 'synthetic lost reply after actual POSIX effect',
            'draft': outcome.receipt, 'intent': outcome.intent,
            'readback_digest': digest_bytes((self.target/'result.bin').read_bytes())})

    def test_checked_unlock_error_still_closes_once_and_refuses_success(self):
        import fcntl
        lock = _OperationalFileLock(self.root/'synthetic.lock', _checked_release=True)
        lock.__enter__(); descriptor = lock.fileno()
        real_flock, real_close = fcntl.flock, os.close
        unlocks, closes = [], []
        def unlock(fd, op):
            if fd == descriptor and op == fcntl.LOCK_UN:
                unlocks.append(fd); raise OSError(errno.EIO, 'synthetic unlock failure')
            return real_flock(fd, op)
        def close(fd):
            closes.append(fd); return real_close(fd)
        with patch.object(fcntl, 'flock', unlock), patch.object(os, 'close', close):
            with self.assertRaisesRegex(PhaseError, 'lock.checked_finalization_unknown'):
                lock.__exit__(None, None, None)
        self.assertEqual(unlocks, [descriptor]); self.assertEqual(closes, [descriptor])
        with self.assertRaises(OSError): os.fstat(descriptor)
        with self.assertRaisesRegex(PhaseError, 'lock.checked_finalization_unknown'):
            lock.__exit__(None, None, None)

    def test_checked_close_error_is_consumed_and_primary_body_survives(self):
        lock = _OperationalFileLock(self.root/'synthetic.lock', _checked_release=True)
        lock.__enter__(); descriptor = lock.fileno(); real_close = os.close
        primary = ValueError('synthetic primary body failure'); closes = []
        def close(fd):
            closes.append(fd); real_close(fd)
            raise OSError(errno.EIO, 'synthetic close fault AFTER actual close')
        with patch.object(os, 'close', close):
            lock.__exit__(ValueError, primary, None)
            lock.__exit__(ValueError, primary, None)
        self.assertEqual(closes, [descriptor])
        self.assertTrue(any('synthetic close fault' in note for note in primary.__notes__))
        self.assertTrue(any('consumed' in note for note in primary.__notes__))

    def test_checked_rebound_name_is_refused_but_original_fd_closed(self):
        path = self.root/'synthetic.lock'; lock = _OperationalFileLock(path, _checked_release=True)
        lock.__enter__(); descriptor = lock.fileno()
        path.rename(self.root/'old.lock'); path.write_bytes(b'synthetic-replacement')
        replacement = path.stat().st_ino
        with self.assertRaisesRegex(PhaseError, 'lock.checked_finalization_unknown'):
            lock.__exit__(None, None, None)
        with self.assertRaises(OSError): os.fstat(descriptor)
        self.assertEqual(path.stat().st_ino, replacement)
        self.assertEqual(path.read_bytes(), b'synthetic-replacement')

    def test_checked_rebound_parent_is_refused_but_original_fd_closed(self):
        parent = self.root/'locks'; parent.mkdir(mode=0o700)
        lock = _OperationalFileLock(parent/'synthetic.lock', _checked_release=True)
        lock.__enter__(); descriptor = lock.fileno()
        parent.rename(self.root/'old-locks'); parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(PhaseError, 'lock.checked_finalization_unknown'):
            lock.__exit__(None, None, None)
        with self.assertRaises(OSError): os.fstat(descriptor)
        self.assertEqual(list(parent.iterdir()), [])

    def test_checked_same_inode_parent_mode_drift_is_refused(self):
        parent = self.root/'locks'; parent.mkdir(mode=0o700)
        lock = _OperationalFileLock(parent/'synthetic.lock', _checked_release=True)
        lock.__enter__(); descriptor = lock.fileno(); parent.chmod(0o722)
        try:
            with self.assertRaisesRegex(PhaseError, 'lock.checked_finalization_unknown'):
                lock.__exit__(None, None, None)
            with self.assertRaises(OSError): os.fstat(descriptor)
        finally:
            parent.chmod(0o700)

    def test_checked_foreign_reused_descriptor_is_never_unlocked_or_closed(self):
        import fcntl
        lock = _OperationalFileLock(self.root/'synthetic.lock', _checked_release=True)
        lock.__enter__(); descriptor = lock.fileno()
        other = os.open(self.root/'synthetic-other.bin', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.dup2(other, descriptor)  # Explicit FD-lifetime fault, forbidden by bootstrap.
            with patch.object(fcntl, 'flock', side_effect=AssertionError('foreign unlock')) as unlock, \
                 patch.object(os, 'close', wraps=os.close) as close:
                with self.assertRaisesRegex(PhaseError, 'lock.checked_finalization_unknown'):
                    lock.__exit__(None, None, None)
                unlock.assert_not_called(); close.assert_not_called()
            self.assertEqual(os.fstat(descriptor).st_ino, os.fstat(other).st_ino)
            os.write(descriptor, b'synthetic-still-open')
        finally:
            os.close(descriptor); os.close(other)


if __name__ == '__main__':
    unittest.main()
