"""Generic inspection attachment-inventory components, NOT native acceptance.

These Linux components write only fresh disposable canonical control files.
The real generic inspector performs schema/static-binding/pre-validator and
attachment-set checks. Only its lower native-terminal-proof verifier is
replaced by an explicitly synthetic, byte-correlated dependency projection.
No worker, NativeIO, Core execution, target observation or NTFS qualification
is exercised. The positive case must stop at a later blob-verification
sentinel: it never returns an inspected-success result.
"""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch


class _LaterBlobSentinel(Exception):
    """The inventory passed; complete original/target verification is not run."""


@unittest.skipUnless(sys.platform.startswith('linux'),
    'NOT_VERIFIED: Linux/ext4 generic-inspection component only')
class NativeBundle2InspectionInventoryTests(unittest.TestCase):
    def fixture(self, *, bundle2=True):
        # Defer Linux-only channel/provider imports, including sibling fixtures,
        # until after the explicit platform boundary. No test-directory injection.
        from phase_tool import inspection
        from phase_tool.canonical import canonical_bytes, digest_bytes, profile_digest
        from phase_tool.continuation import prepared_record
        from phase_tool.core import CORE_BINDING, PhaseCore
        from phase_tool.errors import PhaseError
        from phase_tool.evidence import validate_intent, validate_receipt
        from phase_tool.installation import (
            _NativeFileCreateReadBinding, _native_experimental_bundle1_registry,
            _native_experimental_bundle2_registry_v2, qualify_host_authority_roots,
            _linux_filesystem_type)
        from phase_tool.mutation.ntfs.channel_v4 import LinuxNativeBundleChannel
        from phase_tool.mutation.ntfs.bundle2_channel import LinuxNativeBundle2Channel
        from phase_tool.mutation.ntfs.experimental_bundle1 import _ExperimentalBundle1Admission
        from phase_tool.mutation.ntfs.experimental_bundle1_authority import _ExperimentalBundle1Authority
        from phase_tool.mutation.ntfs.experimental_bundle2_v2 import _ExperimentalBundle2AdmissionV2
        from phase_tool.mutation.ntfs.experimental_bundle2_authority_v2 import _ExperimentalBundle2AuthorityV2
        from phase_tool.prepared_binding import binding_value
        from phase_tool.validation import ValidatorRunner
        from .test_native_bundle_protocol import projection

        temporary = TemporaryDirectory(prefix='phase-inspection-prepared-component-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        evidence = root/'evidence'
        preparation = root/'preparation'
        evidence.mkdir(mode=0o700)
        preparation.mkdir(mode=0o700)
        try:
            qualify_host_authority_roots({'phase_evidence_root': evidence})
            filesystem = _linux_filesystem_type(evidence)
        except PhaseError as error:
            self.skipTest('NOT_VERIFIED: actual evidence qualification unavailable: '+error.code)
        if filesystem != 'ext4':
            self.skipTest('NOT_VERIFIED: actual evidence filesystem is '+filesystem)

        registry = (_native_experimental_bundle2_registry_v2 if bundle2
                    else _native_experimental_bundle1_registry)()
        admission_type = _ExperimentalBundle2AdmissionV2 if bundle2 else _ExperimentalBundle1Admission
        authority_type = _ExperimentalBundle2AuthorityV2 if bundle2 else _ExperimentalBundle1Authority
        channel_type = LinuxNativeBundle2Channel if bundle2 else LinuxNativeBundleChannel
        contract_binding = registry.contract_bindings()[
            'bundle_create.v2@1.2.1' if bundle2 else 'bundle_create.v1@1.1.0']
        contract = registry.resolve_contract(contract_binding['id'], contract_binding['version'],
            contract_binding['package_digest'], core_version=CORE_BINDING['version'])
        mechanism = {k: contract.document['operation']['mechanism'][k]
                     for k in ('id', 'version', 'package_digest')}
        run_id = 'prepared-inventory-component'
        timestamp = '2026-10-29T00:00:00Z'
        case = '00000000-0000-4000-8000-000000000207'
        project = projection()  # Synthetic bytes/grant data, never execution authority.
        from phase_tool.canonical import parse_json_bytes
        grant = parse_json_bytes(project.grant_bytes)
        grant['components'] = ['Phase-NTFS-Qualification', case, 'results']
        evidence_stat = evidence.stat()
        preparation_stat = preparation.stat()
        evidence_identity = {'stable_id': 'component.evidence',
            'device': evidence_stat.st_dev, 'inode': evidence_stat.st_ino}
        preparation_identity = {'stable_id': 'component.preparation',
            'device': preparation_stat.st_dev, 'inode': preparation_stat.st_ino}
        candidate = {'operation_id': run_id, 'idempotency_key': run_id,
            'target_locator': 'bundle', 'input_binding': 'payload',
            'members': [row['path'] for row in parse_json_bytes(project.manifest_bytes)['members']]}
        admission = admission_type(canonical_bytes({
            'experimental_admission_version': '1.0',
            'authorization_digest': 'sha256:6d3646ce58d6045fae41d1b22791c4f05d6cb177c343883fad86cd6ae0b0a40b',
            'contract': contract_binding, 'run_id': run_id, 'request_id': run_id,
            'target_locator': 'bundle', 'candidate_digest': digest_bytes(canonical_bytes(candidate)),
            'payload_digest': project.content_digest, 'payload_length': project.content_length,
            'windows_root': 'S:\\Phase-NTFS-Qualification\\'+case+'\\results',
            'root_grant': grant, 'evidence_identity': evidence_identity,
            'preparation_identity': preparation_identity, 'wheel_digest': 'sha256:'+'a'*64,
            'qualification': {'A05': 'NOT_VERIFIED', 'G01': 'NOT_VERIFIED'},
            'release_eligible': False}))
        profile = registry.guarantee_profile_bindings()[admission._profile]
        descriptor = registry.resolve_guarantee_profile(profile)
        implementation = descriptor['implementation']
        authority_binding = {'usage': 'provider_backed', 'profile': profile,
            'provider': {k: implementation[k] for k in ('id', 'version', 'artifact_digest')}}
        projections = {'phase_result_root': '/synthetic/unopened-inventory-target'}
        manifest = {'native_read_installation_version': admission._manifest_version,
            'installation_id': admission._installation_prefix+admission.digest[7:],
            'core': deepcopy(CORE_BINDING), 'contract': deepcopy(contract_binding),
            'registry_snapshot_digest': registry.digest, 'authority': authority_binding,
            'mechanism': mechanism,
            'composition': {'id': 'synthetic.inspection.inventory', 'version': '1.0.0',
                'artifact_graph_digest': 'sha256:'+'b'*64},
            'evidence_root': str(evidence), 'evidence_identity': evidence_identity,
            'preparation_root': str(preparation), 'preparation_identity': preparation_identity,
            'root_grants': [grant], 'root_projections': projections}
        manifest_bytes = canonical_bytes(manifest)
        binding = _NativeFileCreateReadBinding(
            manifest_bytes, digest_bytes(manifest_bytes), registry, admission)
        # A non-operational exact-type channel shell, never used for any wire.
        channel = object.__new__(channel_type)
        channel._inspection_only = True
        authority = authority_type(binding, admission.profile(binding), canonical_bytes(projections),
            channel, run_id=run_id, operation_nonce='c'*32, _inspection_only=True)

        effect = parse_json_bytes(project.effect_bytes)
        plan = {'effect_plan_version': '1.0', 'plan_id': 'plan.inspection.component',
            'run_id': run_id, 'contract': deepcopy(contract_binding), 'operation_intent': 'create',
            'mechanism': mechanism, 'write_scope_digest': 'sha256:'+'d'*64,
            'generated_at': timestamp, 'effect_order': 'static_predeclared', 'effects': [effect]}
        plan_digest = profile_digest('effect-plan', plan)
        implementation_binding = {'authority': authority_binding,
            'mechanism': mechanism, 'effect_plan_digest': plan_digest}
        runner = ValidatorRunner(registry)
        validators = [runner._result(declaration, run_id=run_id, timestamp=timestamp,
            status='pass', code='validation.pass', expected='synthetic.inventory.component',
            actual='synthetic.inventory.component', blockers=[])
            for declaration in contract.document['validators']]
        pre = deepcopy(validators)
        intent = {'phase_intent_version': '1.2', 'run_id': run_id, 'created_at': timestamp,
            'core': deepcopy(CORE_BINDING), 'registry_snapshot_digest': registry.digest,
            'contract': deepcopy(contract_binding),
            'candidate': {'input_mode': 'structured_json',
                'digest': profile_digest('candidate', candidate), 'length': len(canonical_bytes(candidate)),
                'storage': {'mode': 'inline', 'value': candidate, 'attachment_digest': None}},
            'inputs': [{'binding_id': 'payload', 'freeze_strategy': 'manifest_and_hash',
                'digest': project.content_digest, 'manifest_digest': project.content_digest,
                'blob_digest': project.content_digest, 'frozen_at': timestamp,
                'provenance_ref': None, 'revalidation_token': None}],
            'write_scope_digest': plan['write_scope_digest'],
            'operation': {'intent': 'create', 'mechanism': mechanism},
            'idempotency': {'key': run_id, 'scope_digest': 'sha256:'+'e'*64,
                'request_digest': 'sha256:'+'f'*64,
                'root_identity_digest': profile_digest('native-root-identity-v1', [grant]),
                'root_identities': [grant]},
            'effect_plan_digest': plan_digest, 'implementation_binding': implementation_binding,
            'execution_requested': True,
            'evidence': {'effect_plan_attachment_digest': digest_bytes(canonical_bytes(plan)),
                'content_blob_digests': [], 'pre_validator_results_digest': digest_bytes(canonical_bytes(pre))},
            'status': 'intent_recorded',
            'native_binding': {'native_binding_version': '1.0',
                'installation': {'id': manifest['installation_id'],
                    'descriptor_digest': binding.manifest_digest},
                'composition': manifest['composition'], 'evidence_identity': evidence_identity,
                'operation_nonce': 'c'*32}}
        after = {'known': True, 'exists': True, 'digest': project.content_digest,
            'length': project.content_length, 'head_token': None}
        effect_receipts = [{'effect_receipt_version': '1.0', 'run_id': run_id,
            'effect_id': effect['effect_id'], 'kind': effect['kind'], 'attempted': True,
            'status': 'applied_verified',
            'before': {'known': True, 'exists': False, 'digest': None, 'length': None, 'head_token': None},
            'after': after, 'bytes_written': project.content_length,
            'verification_refs': ['bundle.members.byte_verified'], 'error': None,
            'started_at': timestamp, 'finished_at': timestamp}]
        receipt = {'phase_receipt_version': '1.0', 'run_id': run_id,
            'contract': deepcopy(contract_binding), 'core': deepcopy(CORE_BINDING),
            'started_at': timestamp, 'finished_at': timestamp, 'terminal_status': 'succeeded_verified',
            'execution_disposition': 'executed', 'mutation_attempted': True,
            'result_state': 'verified_result',
            'canonical_result': PhaseCore._canonical_result(contract, effect, after, timestamp),
            'validator_results': validators, 'effect_receipts': effect_receipts,
            'implementation_binding': implementation_binding,
            'evidence': {'finalization_status': 'finalized',
                'intent_digest': profile_digest('intent', intent),
                'receipt_digest_policy_id': 'digest.phase_canonical_json_v1',
                'required_attachments_present': True, 'attachment_digests': []},
            'retry_disposition': 'safe_idempotent_retry', 'prior_verified_receipt_digest': None,
            'recovery_required': False, 'blockers': [], 'exit_code': 0}
        run = evidence/'.phase'/'runs'/run_id
        (run/'attachments').mkdir(parents=True, mode=0o700)
        (run/'blobs').mkdir(mode=0o700)
        prepared = prepared_record(intent, effect, 'phase-stage-component', device=17, inode=207)
        controls = {'effect-plan.json': plan, 'validator-results.json': validators,
            'pre-validator-results.json': pre, 'effect-receipts.json': effect_receipts,
            'prepared-stage.json': prepared,
            'native-terminal-proof.json': {'component_only': True,
                'intent_digest': receipt['evidence']['intent_digest'], 'effect_plan_digest': plan_digest}}
        for name, value in controls.items():
            (run/'attachments'/name).write_bytes(canonical_bytes(value))
        (run/'attachments'/'experimental-admission.json').write_bytes(admission.raw)
        (run/'intent.json').write_bytes(canonical_bytes(intent))
        (run/'preparation-binding.json').write_bytes(canonical_bytes(binding_value(intent, effect, prepared)))
        (run/'blobs'/project.content_digest[7:]).write_bytes(project.manifest_bytes)
        receipt['evidence']['attachment_digests'] = sorted(
            digest_bytes(path.read_bytes()) for path in (run/'attachments').iterdir())
        (run/'receipt.json').write_bytes(canonical_bytes(receipt))
        validate_intent(intent, registry)
        validate_receipt(receipt, registry)
        return SimpleNamespace(inspection=inspection, registry=registry, authority=authority,
            binding=binding, evidence=evidence, run=run, run_id=run_id, projections=projections,
            intent=intent, plan=plan, receipt=receipt, contract=contract, bundle2=bundle2)

    def snapshot(self, fixture):
        return {path.relative_to(fixture.run).as_posix(): path.read_bytes()
                for path in fixture.run.rglob('*') if path.is_file()}

    def correlated_lower_proof(self, fixture, *, omit_binding=False):
        """Synthetic lower-verifier output, correlated to real fixture bytes.

        This deliberately does NOT validate native proof, worker exit or NTFS.
        Existing prepared-record schema/binding verification is real for B2.
        The consumer's strict inventory equality is never mocked.
        """
        from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
        from phase_tool.prepared_binding import verify_prepared_binding

        def verified(binding, run, receipt):
            self.assertIs(binding, fixture.binding)
            self.assertEqual(run, fixture.run)
            self.assertEqual(receipt, fixture.receipt)
            files = self.snapshot(fixture)
            for name, raw in files.items():
                if name.endswith('.json'):
                    self.assertEqual(canonical_bytes(parse_json_bytes(raw)), raw)
            actual = {digest_bytes(raw) for name, raw in files.items()
                      if name.startswith('attachments/')}
            self.assertEqual(actual, set(receipt['evidence']['attachment_digests']))
            if fixture.bundle2:
                verify_prepared_binding(fixture.registry, fixture.contract,
                    fixture.intent, fixture.plan, fixture.run)
            immutable = {name: (digest_bytes(raw), len(raw)) for name, raw in files.items()}
            if omit_binding:
                # Deliberately incomplete dependency projection, not missing disk data.
                immutable.pop('preparation-binding.json')
            return {'attachment_digest': digest_bytes(files['attachments/native-terminal-proof.json']),
                'immutable_files': immutable, 'target_identity': None,
                'proof': parse_json_bytes(files['attachments/native-terminal-proof.json'])}
        return verified

    def assert_stops(self, fixture, expected, *, omit_binding=False, host=False):
        from phase_tool.errors import PhaseError
        before = self.snapshot(fixture)
        with (patch('phase_tool.mutation.ntfs.proof.verify_native_terminal_proof',
                    side_effect=self.correlated_lower_proof(fixture, omit_binding=omit_binding)) as proof,
                patch.object(fixture.inspection, '_verify_intent_blobs',
                    side_effect=_LaterBlobSentinel()) as later):
            if expected is _LaterBlobSentinel:
                with self.assertRaises(_LaterBlobSentinel):
                    fixture.inspection.inspect_run(fixture.evidence, fixture.run_id,
                        fixture.registry, root_bindings=fixture.projections,
                        _native_authority=fixture.authority)
                later.assert_called_once_with(fixture.run, fixture.intent, fixture.plan)
            else:
                with self.assertRaises(PhaseError) as caught:
                    fixture.inspection.inspect_run(fixture.evidence, fixture.run_id,
                        fixture.registry, root_bindings=fixture.projections,
                        _native_authority=None if host else fixture.authority)
                self.assertEqual(caught.exception.code, expected)
                later.assert_not_called()
            if host:
                proof.assert_not_called()
            else:
                proof.assert_called_once_with(fixture.binding, fixture.run, fixture.receipt)
        self.assertEqual(self.snapshot(fixture), before)

    def test_current_b2_seven_controls_reach_later_blob_sentinel_without_inspected_success(self):
        fixture = self.fixture()
        self.assertEqual(len(fixture.receipt['evidence']['attachment_digests']), 7)
        # The pre-fix inspector raises attachment_set_mismatch instead. No
        # success-shaped inspection output is supplied or accepted by this test.
        self.assert_stops(fixture, _LaterBlobSentinel)

    def test_unknown_claimed_and_actual_extra_still_fails_strict_attachment_inventory(self):
        from phase_tool.canonical import canonical_bytes, digest_bytes
        fixture = self.fixture()
        extra = canonical_bytes({'synthetic_unrecognized_attachment': True})
        (fixture.run/'attachments'/'unrecognized-component.json').write_bytes(extra)
        fixture.receipt['evidence']['attachment_digests'].append(digest_bytes(extra))
        fixture.receipt['evidence']['attachment_digests'].sort()
        (fixture.run/'receipt.json').write_bytes(canonical_bytes(fixture.receipt))
        self.assertEqual(len(fixture.receipt['evidence']['attachment_digests']), 8)
        self.assert_stops(fixture, 'inspection.attachment_set_mismatch')

    def test_prepared_stage_without_same_verified_binding_projection_is_refused(self):
        fixture = self.fixture()
        self.assertTrue((fixture.run/'preparation-binding.json').is_file())
        self.assert_stops(fixture, 'recovery.preparation_binding_mismatch', omit_binding=True)

    def test_bundle1_does_not_receive_native_bundle2_prepared_control_exemption(self):
        fixture = self.fixture(bundle2=False)
        self.assertEqual(fixture.intent['contract']['id'], 'bundle_create.v1')
        self.assert_stops(fixture, 'inspection.attachment_set_mismatch')

    def test_host_entry_cannot_use_native_proof_or_prepared_control_as_an_exemption(self):
        fixture = self.fixture()
        self.assert_stops(fixture, 'inspection.native_installation_required', host=True)


if __name__ == '__main__':
    unittest.main()
