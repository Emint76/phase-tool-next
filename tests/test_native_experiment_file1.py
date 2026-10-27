"""Pure admission negatives, not native execution or safety qualification."""
from copy import deepcopy
from dataclasses import replace
import unittest

from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import (_native_experimental_file1_registry,
    _native_registry_for_manifest, _native_qualified_profile,
    _resolve_native_file_create_read_binding)
from phase_tool.mutation.ntfs.experimental_file1 import (
    _ExperimentalFile1Admission, _experimental_admission, _is_native_authority)
from .test_native_original_intent import buffers
from .test_native_static_read_binding import manifest_for


def experiment_fixture():
    registry = _native_experimental_file1_registry()
    intent, _, _, payload, contract = buffers(registry)
    grant = deepcopy(intent['idempotency']['root_identities'][0])
    grant['components'] = ['Phase-NTFS-Qualification',
        '11111111-1111-4111-8111-111111111111', 'results']
    identity = {'stable_id': 'synthetic.experiment.evidence', 'device': 1, 'inode': 2}
    preparation = {'stable_id': 'synthetic.experiment.preparation', 'device': 1, 'inode': 3}
    doc = {'experimental_admission_version': '1.0',
        'authorization_digest': 'sha256:6d3646ce58d6045fae41d1b22791c4f05d6cb177c343883fad86cd6ae0b0a40b',
        'contract': intent['contract'], 'run_id': intent['run_id'],
        'request_id': 'synthetic-create-only', 'target_locator': 'synthetic.txt',
        'candidate_digest': digest_bytes(canonical_bytes(intent['candidate']['storage']['value'])),
        'payload_digest': digest_bytes(payload), 'payload_length': len(payload),
        'windows_root': 'S:\\Phase-NTFS-Qualification\\11111111-1111-4111-8111-111111111111\\results',
        'root_grant': grant, 'evidence_identity': identity, 'preparation_identity': preparation,
        'wheel_digest': 'sha256:' + '1'*64,
        'qualification': {'A05': 'NOT_VERIFIED', 'G01': 'NOT_VERIFIED'}, 'release_eligible': False}
    cap = _ExperimentalFile1Admission(canonical_bytes(doc))
    manifest = manifest_for(intent, '/synthetic/evidence')
    profile = registry.guarantee_profile_bindings()['phase.native.ntfs.experiment.file1@1.0.0']
    impl = registry.resolve_guarantee_profile(profile)['implementation']
    manifest.update(native_read_installation_version='1.1',
        installation_id='phase.experiment.file1.' + cap.digest[7:],
        root_grants=[grant], evidence_identity=identity, preparation_root='/synthetic/preparation',
        preparation_identity=preparation, root_projections={'phase_result_root': '/ntfs-result'},
        authority={'usage': 'provider_backed', 'profile': profile,
            'provider': {k: impl[k] for k in ('id', 'version', 'artifact_digest')}})
    raw = canonical_bytes(manifest)
    binding = replace(_resolve_native_file_create_read_binding(manifest_bytes=raw,
        expected_manifest_digest=digest_bytes(raw), registry=registry), experimental_admission=cap)
    return cap, binding, manifest, contract


class ExperimentalFile1AdmissionTests(unittest.TestCase):
    def test_fixed_descriptor_has_no_coverage_and_normal_guard_still_refuses(self):
        cap, binding, _, _ = experiment_fixture()
        profile = cap.profile(binding)
        desc = binding.registry.resolve_guarantee_profile(profile.as_dict())
        self.assertEqual(desc['provided_guarantees'], [])
        self.assertEqual(desc['conformance'], [])
        with self.assertRaises(PhaseError) as caught:
            _native_qualified_profile(binding.registry, profile.as_dict())
        self.assertEqual(caught.exception.code, 'ntfs.native_profile_not_qualified')

    def test_normal_manifest_selector_does_not_activate_experiment(self):
        _, binding, _, _ = experiment_fixture()
        with self.assertRaises(PhaseError) as caught:
            _native_registry_for_manifest(binding.manifest_bytes, binding.manifest_digest)
        self.assertEqual(caught.exception.code, 'ntfs.original_registry_mismatch')

    def test_structural_assessment_preserves_obligations_without_coverage(self):
        cap, binding, _, contract = experiment_fixture()
        op = contract.document['operation']
        result = cap.assess(binding, op['required_guarantees'], [op['mechanism']])
        self.assertEqual(set(result['mechanisms'][0]['all_of']),
            {'exclusive_create', 'readback_verification', 'cross_process_serialization'})
        self.assertNotIn('provided_guarantees', result)

    def test_changed_requirement_is_not_admitted(self):
        cap, binding, _, contract = experiment_fixture()
        op = contract.document['operation']
        for name in ('unknown-guarantee', 'atomic_replace'):
            requirements = deepcopy(op['required_guarantees'])
            requirements['mechanisms'][0]['all_of'].append(name)
            with self.subTest(name=name), self.assertRaises(PhaseError):
                cap.assess(binding, requirements, [op['mechanism']])

    def test_invalid_and_broadened_contexts_are_rejected(self):
        cap, _, _, _ = experiment_fixture()
        for field, value in [('release_eligible', True), ('authorization_digest', 'sha256:'+'0'*64),
                ('windows_root', 'C:\\synthetic'), ('payload_length', 1024**2+1),
                ('target_locator', '../outside'), ('qualification', {'A05': 'PASS', 'G01': 'PASS'}),
                ('extra', True), ('payload_length', True)]:
            doc = cap.document(); doc[field] = value
            with self.subTest(field=field, value=value), self.assertRaises((PhaseError, ValueError)):
                _ExperimentalFile1Admission(canonical_bytes(doc)).document()

    def test_context_does_not_implicitly_come_from_manifest_id(self):
        cap, binding, _, _ = experiment_fixture()
        self.assertIs(_experimental_admission(binding), cap)
        self.assertIsNone(_experimental_admission(replace(binding, experimental_admission=None)))
        with self.assertRaises(PhaseError):
            _experimental_admission(replace(binding, experimental_admission=object()))
        self.assertFalse(_is_native_authority(object()))

    def test_altered_binding_cannot_reuse_the_same_capability(self):
        cap, binding, manifest, _ = experiment_fixture()
        for field, value in [('installation_id', 'synthetic.other'),
                ('evidence_identity', {'stable_id': 'synthetic.other', 'device': 1, 'inode': 9})]:
            other = deepcopy(manifest); other[field] = value
            raw = canonical_bytes(other)
            with self.subTest(field=field), self.assertRaises(PhaseError):
                cap.check_binding(replace(binding, manifest_bytes=raw, manifest_digest=digest_bytes(raw)))

    def test_noncanonical_context_and_root_grant_alias_rejected(self):
        cap, _, _, _ = experiment_fixture()
        with self.assertRaises(PhaseError):
            _ExperimentalFile1Admission(cap.raw+b' ').document()
        doc = cap.document(); doc['root_grant']['components'][-1] = 'other'
        with self.assertRaises(PhaseError):
            _ExperimentalFile1Admission(canonical_bytes(doc)).document()


    def test_saved_original_cannot_change_target_or_payload_under_old_admission(self):
        cap, binding, _, _ = experiment_fixture()
        intent, plan, _, _, _ = buffers(binding.registry)
        cap.check_original(intent, plan)
        for changed in ('target', 'payload', 'candidate', 'run'):
            other_intent, other_plan = deepcopy(intent), deepcopy(plan)
            if changed == 'target':
                other_intent['candidate']['storage']['value']['target_locator'] = 'other.txt'
                other_plan['effects'][0]['target']['relative_locator'] = 'other.txt'
            elif changed == 'payload':
                other_intent['inputs'][0]['digest'] = other_intent['inputs'][0]['blob_digest'] = 'sha256:'+'2'*64
                other_plan['effects'][0]['content_digest'] = 'sha256:'+'2'*64
            elif changed == 'candidate':
                other_intent['candidate']['storage']['value']['operation_id'] = 'different.operation'
            else:
                other_intent['run_id'] = other_plan['run_id'] = 'different-run'
            with self.subTest(changed=changed), self.assertRaises(PhaseError) as caught:
                cap.check_original(other_intent, other_plan)
            self.assertEqual(caught.exception.code, 'ntfs.experimental_original_mismatch')


if __name__ == '__main__':
    unittest.main()
