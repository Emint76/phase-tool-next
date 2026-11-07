"""Pure error-envelope regressions, not authority or storage qualification."""
from pathlib import Path
from types import SimpleNamespace
import unittest

from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.command_result import validate_command_result
from phase_tool.core import _NativeRunContext
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_connected_file_create_registry
from phase_tool.mutation.ntfs.lifecycle import _keep_native_primary
from phase_tool.mutation.ntfs.native import _error_record
from phase_tool.mutation.ntfs.uncertainty import _NativeLifecycleUnresolved


class BrokenTextError(Exception):
    def __str__(self):
        raise RuntimeError('synthetic diagnostic formatting failure')


class BrokenPrepared:
    intent_recording_started = True
    proof_publication_attempted = False
    publication_attempted = True
    common_guard_finalized = False
    original_intent_digest = 'sha256:' + 'a'*64

    @property
    def prepared(self):
        raise RuntimeError('synthetic late prepared getter failure')


class NativeUncertaintyTests(unittest.TestCase):
    def make(self, primary=None, secondary=(), context=None):
        if context is None:
            context = SimpleNamespace(intent_recording_started=True,
                proof_publication_attempted=False, publication_attempted=True,
                common_guard_finalized=False, original_intent_digest='sha256:'+'a'*64,
                prepared=SimpleNamespace(effect_plan_digest='sha256:'+'b'*64))
        return _NativeLifecycleUnresolved(request=SimpleNamespace(run_id='synthetic-unresolved'),
            context=context, authority=SimpleNamespace(channel=SimpleNamespace(possible_dispatch=True)),
            primary=primary if primary is not None else RuntimeError('synthetic primary'),
            secondary=secondary)

    def test_bad_prepared_getter_preserves_independent_possible_dispatch_and_attempt(self):
        value=self.make(context=BrokenPrepared())
        state=value.diagnostic
        self.assertTrue(state['possible_dispatch'])
        self.assertTrue(state['receipt_publication_attempted'])
        self.assertEqual(state['intent_digest'],'sha256:'+'a'*64)
        self.assertIsNone(state['effect_plan_digest'])
        self.assertTrue(state['reporting_error'])

    def test_broken_primary_or_secondary_text_never_becomes_ordinary_rejection(self):
        for primary,secondary in [(BrokenTextError(),()),
                (RuntimeError('first'),(BrokenTextError(),))]:
            with self.subTest(primary=type(primary).__name__):
                value=self.make(primary,secondary)
                self.assertIs(type(value),_NativeLifecycleUnresolved)
                result=value.command_result('execute')
                self.assertIsNone(result['mutation_attempted'])
                self.assertIsNone(result['receipt_digest'])
                self.assertTrue(result['possible_dispatch'])
                self.assertTrue(result['inspection_required'])
                self.assertFalse(result['retry_authorized'])
                self.assertEqual(result['exit_code'],40)

    def test_noncanonical_diagnostics_and_nontext_notes_remain_bounded_unknowns(self):
        for unsupported in [1.5,b'bytes',Path('synthetic')]:
            with self.subTest(kind=type(unsupported).__name__):
                error=PhaseError('synthetic.primary',details={'value':unsupported})
                error.__notes__=[object(),'x'*1024]
                value=self.make(error)
                self.assertIs(type(value),_NativeLifecycleUnresolved)
                state=value.diagnostic
                self.assertEqual(state['primary']['type'],'unavailable')
                self.assertEqual(state['primary_notes'][0],'Non-text diagnostic note omitted')
                self.assertEqual(len(state['primary_notes'][1]),512)
                self.assertLessEqual(len(canonical_bytes(state)),320*1024)

    def test_snapshot_and_diagnostic_digest_do_not_change_with_source_or_reader_mutation(self):
        details={'nested':{'value':'original'}}
        error=PhaseError('synthetic.primary',details=details)
        value=self.make(error)
        before=value.command_result('execute')['diagnostic_digest']
        details['nested']['value']='changed'
        returned=value.diagnostic
        returned['primary']['details']['nested']['value']='reader-changed'
        self.assertEqual(value.command_result('execute')['diagnostic_digest'],before)
        self.assertEqual(value.diagnostic['primary']['details']['nested']['value'],'original')

    def test_large_diagnostic_is_hash_bound_and_secondary_count_is_bounded(self):
        primary=PhaseError('synthetic.large',details={'message':'x'*20000})
        value=self.make(primary,tuple(RuntimeError(str(i)) for i in range(30)))
        state=value.diagnostic
        self.assertEqual(state['primary']['type'],'oversized')
        original=canonical_bytes(_error_record(primary))
        self.assertEqual(state['primary']['details']['sha256'],digest_bytes(original))
        self.assertEqual(state['primary']['details']['length'],len(original))
        self.assertEqual(len(state['secondary']),16)
        self.assertEqual(state['secondary_omitted_count'],14)
        self.assertFalse(state['retry_authorized'])
        self.assertLessEqual(len(canonical_bytes(state)),320*1024)

    def test_closed_type_and_second_initialization_preserve_first_snapshot(self):
        value=self.make()
        before=value.command_result('execute')['diagnostic_digest']
        with self.assertRaises(TypeError):
            type('NotAnApprovedUncertainty',(_NativeLifecycleUnresolved,),{})
        with self.assertRaises(_NativeLifecycleUnresolved) as caught:
            value.__init__(request=None,context=None,authority=None,primary=None)
        self.assertIs(caught.exception,value)
        self.assertEqual(value.command_result('execute')['diagnostic_digest'],before)

    def test_actual_connected_schema_accepts_unknown_receipt_without_absence_claim(self):
        value=self.make()
        result=value.command_result('execute')
        registry=_native_connected_file_create_registry()
        validate_command_result(result,registry)
        self.assertEqual(result['stage3_command_result_version'],'1.2')
        self.assertIsNone(result['receipt_digest'])
        self.assertTrue(result['receipt_publication_attempted'])
        self.assertEqual(result['diagnostic_digest'],digest_bytes(canonical_bytes(value.diagnostic)))

    def test_original_broker_cause_survives_prepare_then_seal_failures(self):
        broker=OSError('synthetic primary worker observation failure')
        prepare=RuntimeError('synthetic later Core preparation failure')
        seal=RuntimeError('synthetic later seal failure')
        context=_NativeRunContext(broker_interruption=broker)
        secondary=[]
        self.assertIs(_keep_native_primary(context,prepare,secondary),broker)
        self.assertIs(_keep_native_primary(context,prepare,secondary),broker)
        self.assertIs(_keep_native_primary(context,broker,secondary),broker)
        secondary.append(seal)
        self.assertEqual(secondary,[prepare,seal])
        value=self.make(broker,tuple(secondary))
        self.assertIn('primary worker',value.diagnostic['primary']['message'])
        self.assertEqual([row['message'] for row in value.diagnostic['secondary']],
            [str(prepare),str(seal)])

    def test_without_broker_cause_first_error_remains_primary(self):
        primary=OSError('synthetic first')
        secondary=[]
        self.assertIs(_keep_native_primary(_NativeRunContext(),primary,secondary),primary)
        self.assertEqual(secondary,[])
