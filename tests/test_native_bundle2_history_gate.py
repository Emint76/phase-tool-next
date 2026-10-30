"""Real ext4 inventory regression; deliberately never accepts native closure.

The existing fixture supplies qualified, disposable ext4 evidence and the real
operational lock. Only the lower terminal-proof verifier is replaced: it raises
an identifiable refusal, so reaching it proves inventory and binding selection,
not a valid proof, receipt, prepared bundle, NTFS operation or qualified route.
"""
from copy import deepcopy
import sys
import unittest
from unittest.mock import patch

from phase_tool import __version__
from phase_tool.canonical import canonical_bytes
from phase_tool.continuation import prepared_record
from phase_tool.core import _guard_native_original_intents
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_experimental_bundle2_registry_v2
from phase_tool.prepared_binding import binding_value
from . import test_native_core_original_gate as gate_fixtures


@unittest.skipUnless(sys.platform.startswith('linux'),
    'NOT_VERIFIED: actual Linux/ext4 inventory component required')
class NativeBundle2HistoryGateTests(unittest.TestCase):
    def setUp(self):
        # Compose the existing fixture without inheriting/discovering its tests.
        fixture = gate_fixtures.NativeCoreOriginalGateExt4Tests(methodName='runTest')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture
        fixture.registry = _native_experimental_bundle2_registry_v2()
        contract = fixture.registry.contract_bindings()['bundle_create.v2@1.2.1']
        resolved = fixture.registry.resolve_contract(contract['id'], contract['version'],
            contract['package_digest'], core_version=__version__)
        profile = fixture.registry.guarantee_profile_bindings()[
            'phase.native.ntfs.experiment.bundle2.authority.v1@1.0.1']
        descriptor = fixture.registry.resolve_guarantee_profile(profile)
        provider = {key: descriptor['implementation'][key]
            for key in ('id', 'version', 'artifact_digest')}
        mechanism = {key: resolved.document['operation']['mechanism'][key]
            for key in ('id', 'version', 'package_digest')}
        preparation = fixture.root.parent/'preparation'
        preparation.mkdir(mode=0o700)
        info = preparation.stat()
        fixture.manifest.update(native_read_installation_version='1.8',
            installation_id='synthetic.bundle2.inventory', contract=deepcopy(contract),
            registry_snapshot_digest=fixture.registry.digest,
            authority={'usage': 'provider_backed', 'profile': profile, 'provider': provider},
            mechanism=mechanism, preparation_root=str(preparation),
            preparation_identity={'stable_id': 'synthetic.bundle2.preparation',
                'device': info.st_dev, 'inode': info.st_ino},
            root_projections={'phase_result_root': '/synthetic/opaque-bundle2-target'})
        fixture.binding = fixture.resolve()  # Real static resolver; grants no authority.
        fixture.intent.update(contract=deepcopy(contract), phase_intent_version='1.2',
            execution_requested=True, registry_snapshot_digest=fixture.registry.digest)
        fixture.intent['native_binding']['installation'] = {
            'id': fixture.manifest['installation_id'],
            'descriptor_digest': fixture.binding.manifest_digest}
        fixture.plan.update(contract=deepcopy(contract), mechanism=deepcopy(mechanism))
        self.run = fixture.save_original()
        effect = fixture.plan['effects'][0]
        # Existing record builders, with synthetic identity claims. These are
        # not passed off as validated bundle/precondition/terminal evidence.
        prepared = prepared_record(fixture.intent, effect, '.synthetic-stage',
            device=123, inode=456)
        (self.run/'attachments'/'prepared-stage.json').write_bytes(canonical_bytes(prepared))
        (self.run/'preparation-binding.json').write_bytes(
            canonical_bytes(binding_value(fixture.intent, effect, prepared)))
        (self.run/'attachments'/'native-terminal-proof.json').write_bytes(canonical_bytes({
            'installation': deepcopy(fixture.intent['native_binding']['installation'])}))
        self.receipt = {'run_id': self.run.name, 'contract': deepcopy(contract),
            'core': deepcopy(fixture.manifest['core'])}
        (self.run/'receipt.json').write_bytes(canonical_bytes(self.receipt))

    def run_bytes(self):
        return {path.relative_to(self.run).as_posix(): path.read_bytes()
            for path in self.run.rglob('*') if path.is_file()}

    def test_exact_new_prepared_control_reaches_native_closure_but_never_yields(self):
        before = self.run_bytes()
        refusal = PhaseError('synthetic.bundle2.inventory_reached_native_closure')
        with patch('phase_tool.mutation.ntfs.proof.verify_native_terminal_proof',
                   side_effect=refusal) as verifier:
            with self.assertRaises(PhaseError) as caught:
                with _guard_native_original_intents(self.fixture.binding):
                    self.fail('synthetic terminal proof must never admit guard body')
            self.assertIs(caught.exception, refusal)
            verifier.assert_called_once_with(self.fixture.binding, self.run, self.receipt)
        self.assertEqual(self.run_bytes(), before)

    def test_foreign_tuples_and_nonexecuted_or_old_intents_refuse_before_closure(self):
        exact = deepcopy(self.fixture.intent)
        new_contract = exact['contract']
        cases = [
            ('foreign_digest', {'contract': {**new_contract, 'package_digest': 'sha256:'+'0'*64}}),
            ('mixed_old_version', {'contract': {**new_contract, 'version': '1.2.0'}}),
            ('foreign_id', {'contract': {**new_contract, 'id': 'file_create.v1'}}),
            ('old_intent_format', {'phase_intent_version': '1.1'}),
            ('not_executed', {'execution_requested': False}),
        ]
        for label, change in cases:
            with self.subTest(case=label):
                intent = deepcopy(exact)
                intent.update(change)
                (self.run/'intent.json').write_bytes(canonical_bytes(intent))
                before = self.run_bytes()
                with patch('phase_tool.mutation.ntfs.proof.verify_native_terminal_proof',
                           side_effect=PhaseError('synthetic.unexpected_native_closure')) as verifier:
                    with self.assertRaises(PhaseError) as caught:
                        with _guard_native_original_intents(self.fixture.binding):
                            self.fail('foreign prepared control reached guard body')
                    self.assertEqual(caught.exception.code, 'ntfs.original_evidence_name_unsafe')
                    verifier.assert_not_called()
                self.assertEqual(self.run_bytes(), before)


if __name__ == '__main__':
    unittest.main()
