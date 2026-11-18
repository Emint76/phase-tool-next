"""Core/ext4 regression; lost transport result is simulated, not NTFS evidence.

The existing SourceAdmission contract is used only for two-effect Core/ext4
regression with synthetic bytes, not for native Source/Knowledge qualification.
No qualification predicate, provider, registry or inspector is replaced. Owned
temporary fixtures are retained; the isolated runner bounds their total size.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.evidence import validate_receipt
from phase_tool.inspection import inspect_run
from phase_tool.mutation.broker import BrokerExecutionInterrupted, EffectBroker
from phase_tool.registry import BundledRegistry


NOW = '2026-10-21T20:00:00Z'
UNKNOWN = 'broker.dispatch_outcome_unknown'
REAL_EXECUTE = EffectBroker.execute


class CoreDispatchTests(unittest.TestCase):
    def setUp(self):
        if not sys.platform.startswith('linux'):
            self.skipTest('actual qualified Linux Core required; no predicate substitution')
        base = os.environ.get('PHASE_CORE_DISPATCH_TEST_ROOT')
        self.root = Path(tempfile.mkdtemp(prefix='dispatch-case-', dir=base))
        (self.root/'.case.json').write_bytes(canonical_bytes({'case':self._testMethodName}))
        self.registry = BundledRegistry.load()
        self.target, self.evidence = self.root/'target', self.root/'evidence'
        self.target.mkdir()
        (self.target/'objects').mkdir()
        (self.target/'sentinel.bin').write_bytes(b'synthetic-unchanged')
        self.payload = b'phase-dispatch-regression\x00\xff\r\n'
        self.source = self.root/'source.bin'
        self.source.write_bytes(self.payload)
        self.candidate = self.root/'candidate.json'

    def request(self, *, copy=False):
        contract_id = 'source_admission.v1' if copy else 'file_create.v1'
        binding = self.registry.contract_bindings()[contract_id+'@1.0.0']
        if copy:
            value = {'candidate_version':'1.0',
                'contract':{'id':'source_admission.v1','version':'1.0.0'},
                'operation_id':'synthetic-operation','idempotency_key':'synthetic-operation',
                'logical_source_id':'synthetic-source',
                'asset_input':{'binding_id':'asset','expected_digest':digest_bytes(self.payload),
                               'expected_length':len(self.payload)},
                'declared_media_type':'application/octet-stream','original_filename':'synthetic.bin',
                'provenance':{'provenance_version':'1.0',
                    'origin':{'kind':'external_uri','locator':'https://example.invalid/synthetic.bin','label':'synthetic'},
                    'supplied_by':{'kind':'adapter','identifier':'adapter.synthetic'}},
                'placement':{'target_root_binding':'admission_result_root','namespace':'dispatch-regression'},
                'supersedes':None,
                'request_metadata':{'submitted_by':'adapter.synthetic','correlation_id':'synthetic-operation'}}
            root_id = 'admission_result_root'
            (self.target/'blobs/sha256').mkdir(parents=True)
        else:
            value = {'operation_id':'synthetic-operation', 'target_locator':'objects/file.bin',
                'input_binding':'payload', 'idempotency_key':'synthetic-key'}
            root_id = 'phase_result_root'
        self.candidate.write_bytes(canonical_bytes(value))
        return PhaseRequest(contract_id, '1.0.0', binding['package_digest'], self.candidate,
            self.evidence, 'first', {'asset' if copy else 'payload':self.source}, {root_id:self.target}, timestamp=NOW)

    def interrupted(self, request, *, perform=False, prefix=False, possible=True):
        def lost_response(broker, *args, **kwargs):
            receipts = []
            if perform:
                completed = REAL_EXECUTE(broker, *args, **kwargs)
                self.assertTrue(completed.effect_receipts)
                self.assertTrue(all(item['status']=='applied_verified' for item in completed.effect_receipts))
                if prefix:
                    receipts = list(completed.effect_receipts)[:1]
            raise BrokerExecutionInterrupted(PhaseError('transport.synthetic_response_lost'), receipts, None,
                possible_dispatch=possible)
        with patch.object(EffectBroker, 'execute', lost_response):
            return PhaseCore().run(request, execute=True)

    def version_request(self):
        before = b'synthetic-previous-version'
        (self.target/'documents').mkdir()
        (self.target/'documents/file.bin').write_bytes(before)
        binding = self.registry.contract_bindings()['publish_new_version.v1@1.0.0']
        self.candidate.write_bytes(canonical_bytes({'operation_id':'synthetic-version',
            'target_locator':'documents/file.bin','input_binding':'payload',
            'expected_current_digest':digest_bytes(before),'idempotency_key':'synthetic-version'}))
        return PhaseRequest('publish_new_version.v1','1.0.0',binding['package_digest'],self.candidate,
            self.evidence,'first',{'payload':self.source},{'fixture_result_root':self.target},timestamp=NOW), before

    def assert_unknown(self, outcome):
        receipt = outcome.receipt
        self.assertEqual(outcome.exit_code, 50)
        self.assertEqual(receipt['terminal_status'], 'indeterminate')
        self.assertEqual(receipt['execution_disposition'], 'executed')
        self.assertIs(receipt['mutation_attempted'], True)
        self.assertIsNone(receipt['canonical_result'])
        self.assertIs(receipt['recovery_required'], True)
        self.assertEqual(receipt['retry_disposition'], 'forbidden')
        self.assertIn(UNKNOWN, receipt['blockers'])
        self.assertIn('transport.synthetic_response_lost', receipt['blockers'])
        self.assertIsNotNone(outcome.receipt_digest)
        validate_receipt(receipt, self.registry)
        stored = parse_json_bytes((self.evidence/'.phase/runs/first/receipt.json').read_bytes())
        self.assertEqual(stored, receipt)
        self.assertEqual((self.target/'sentinel.bin').read_bytes(), b'synthetic-unchanged')

    def independent_inspect(self, request):
        program = """
import json,sys
from pathlib import Path
from phase_tool.inspection import inspect_run
print(json.dumps(inspect_run(Path(sys.argv[1]),sys.argv[2],root_bindings={sys.argv[3]:Path(sys.argv[4])})))
"""
        key, target = next(iter(request.root_bindings.items()))
        result = subprocess.run([sys.executable, '-B', '-c', program, str(self.evidence),
            request.run_id, key, str(target)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8',errors='replace'))
        self.assertLess(len(result.stdout), 64*1024)
        return json.loads(result.stdout)

    def test_dispatch_disposition_is_typed_and_legacy_default_is_false(self):
        self.assertIs(BrokerExecutionInterrupted(PhaseError('test.failure'), [], None).possible_dispatch, False)
        for value in (1, 'true', None, []):
            with self.subTest(value=value), self.assertRaisesRegex(PhaseError,'invalid_dispatch_disposition'):
                BrokerExecutionInterrupted(PhaseError('test.failure'), [], None, possible_dispatch=value)

    def test_legacy_predispatch_failure_is_not_changed_into_execution(self):
        request = self.request()
        result = self.interrupted(request, possible=False)
        self.assertEqual(result.receipt['terminal_status'], 'rejected')
        self.assertIs(result.receipt['mutation_attempted'], False)
        self.assertNotIn(UNKNOWN, result.receipt['blockers'])
        self.assertFalse((self.target/'objects/file.bin').exists())

    def test_zero_received_effects_still_indeterminate_and_cross_process_inspectable(self):
        request = self.request()
        result = self.interrupted(request)
        self.assert_unknown(result)
        self.assertEqual(result.receipt['effect_receipts'], [])
        self.assertTrue(result.receipt['evidence']['required_attachments_present'])
        self.assertFalse((self.target/'objects/file.bin').exists())
        observed = self.independent_inspect(request)
        self.assertEqual(observed['terminal_status'], 'indeterminate')
        self.assertEqual(observed['receipt_digest'], result.receipt_digest)
        self.assertIsNot(observed['target_verified'], True)

    def test_real_posix_effect_then_lost_all_receipts_is_not_rejected_or_no_effect(self):
        request = self.request()
        result = self.interrupted(request, perform=True)
        self.assert_unknown(result)
        self.assertEqual(result.receipt['effect_receipts'], [])
        self.assertEqual((self.target/'objects/file.bin').read_bytes(), self.payload)
        observed = self.independent_inspect(request)
        self.assertEqual(observed['terminal_status'], 'indeterminate')
        self.assertEqual(observed['receipt_digest'], result.receipt_digest)
        self.assertIsNot(observed['target_verified'], True)

    def test_verified_effect_receipt_does_not_discharge_unknown_worker_completion(self):
        request = self.request()
        result = self.interrupted(request, perform=True, prefix=True)
        self.assert_unknown(result)
        self.assertEqual(len(result.receipt['effect_receipts']), 1)
        self.assertEqual(result.receipt['effect_receipts'][0]['status'], 'applied_verified')
        observed = self.independent_inspect(request)
        self.assertEqual(observed['terminal_status'], 'indeterminate')
        self.assertIsNot(observed['target_verified'], True)

    def test_absent_observation_cannot_enable_same_key_retry_after_unknown_dispatch(self):
        # The real version contract has this classification hook; file_create
        # does not. Unchanged old current + no archive is observed, not closure.
        request, before = self.version_request()
        first = self.interrupted(request)
        self.assert_unknown(first)
        observed = self.independent_inspect(request)
        self.assertEqual(observed.get('state_classification'), 'no_effect_observed')
        with patch.object(EffectBroker,'execute',side_effect=AssertionError('retry reached broker')) as broker:
            retry = PhaseCore().run(replace(request,run_id='second'), execute=True)
        self.assertFalse(broker.called)
        self.assertEqual(retry.receipt['terminal_status'], 'rejected')
        self.assertEqual(retry.receipt['blockers'], ['idempotency.prior_inspection_required'])
        self.assertEqual((self.target/'documents/file.bin').read_bytes(), before)
        self.assertFalse((self.target/'archive').exists())

    def test_empty_receipt_attachment_is_strictly_verified(self):
        request = self.request()
        self.assert_unknown(self.interrupted(request))
        path = self.evidence/'.phase/runs/first/attachments/effect-receipts.json'
        self.assertEqual(parse_json_bytes(path.read_bytes()), [])
        path.write_bytes(canonical_bytes([{'synthetic':'tamper'}]))  # Owned L1 fault injection.
        with self.assertRaisesRegex(PhaseError,'effect_receipts_mismatch'):
            inspect_run(self.evidence,'first',root_bindings=request.root_bindings)

    def test_unknown_marker_exception_does_not_relax_arbitrary_empty_receipts(self):
        request = self.request()
        self.assert_unknown(self.interrupted(request))
        path = self.evidence/'.phase/runs/first/receipt.json'
        value = parse_json_bytes(path.read_bytes())
        value['blockers'].remove(UNKNOWN)
        path.write_bytes(canonical_bytes(value))  # Owned L1 fault injection; deliberately invalid binding.
        with self.assertRaisesRegex(PhaseError,'attachment_set_mismatch'):
            inspect_run(self.evidence,'first',root_bindings=request.root_bindings)

    def test_normal_file_core_receipt_and_separate_inspect_still_work(self):
        request = self.request()
        result = PhaseCore().run(request,execute=True)
        self.assertEqual(result.receipt['terminal_status'], 'succeeded_verified')
        self.assertEqual(result.exit_code, 0)
        self.assertEqual((self.target/'objects/file.bin').read_bytes(), self.payload)
        observed = self.independent_inspect(request)
        self.assertTrue(observed['target_verified'])
        self.assertEqual(observed['receipt_digest'], result.receipt_digest)

    def test_unknown_multi_effect_does_not_publish_false_not_started_final_progress(self):
        request = self.request(copy=True)
        result = self.interrupted(request)
        self.assert_unknown(result)
        self.assertEqual(len(result.effect_plan['effects']), 2)
        self.assertFalse(result.receipt['evidence']['required_attachments_present'])
        self.assertEqual(result.receipt['evidence']['finalization_status'], 'failed')
        path = self.evidence/'.phase/runs/first/attachments/ordered-effect-progress.json'
        self.assertNotIn(digest_bytes(path.read_bytes()), result.receipt['evidence']['attachment_digests'])
        self.assertEqual(self.independent_inspect(request)['terminal_status'], 'indeterminate')

    def test_unknown_next_effect_preserves_known_prefix_without_claiming_success(self):
        request = self.request(copy=True)
        result = self.interrupted(request,perform=True,prefix=True)
        self.assert_unknown(result)
        self.assertEqual(len(result.effect_plan['effects']), 2)
        self.assertEqual(len(result.receipt['effect_receipts']), 1)
        self.assertFalse(result.receipt['evidence']['required_attachments_present'])
        self.assertEqual(self.independent_inspect(request)['terminal_status'], 'indeterminate')

    def test_existing_guard_rejects_actual_unqualified_ntfs_bind_before_broker(self):
        root = os.environ.get('PHASE_TEST_UNQUALIFIED_ROOT')
        if root is None:
            self.skipTest('actual campaign NTFS bind unavailable; not a positive NTFS result')
        request = replace(self.request(), root_bindings={'phase_result_root':Path(root)})
        from phase_tool.installation import _linux_filesystem_type
        self.assertEqual(_linux_filesystem_type(Path(root)), '9p')
        with patch.object(EffectBroker,'execute',side_effect=AssertionError('guard bypassed')) as broker:
            result = PhaseCore().run(request,execute=True)
        self.assertFalse(broker.called)
        self.assertEqual(result.receipt['terminal_status'], 'rejected')
        self.assertEqual(result.receipt['blockers'], ['guarantee.profile_scope_unsupported'])
        self.assertIs(result.receipt['mutation_attempted'], False)


if __name__ == '__main__':
    unittest.main()
