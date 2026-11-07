"""Pure Version1 admission regressions; no native execution or qualification.

The small intent/plan dictionaries exercise only the additional capability
binding AFTER the existing parser. They are not claimed as genuine Core evidence.
"""
from copy import deepcopy
from dataclasses import fields, FrozenInstanceError, replace
from types import SimpleNamespace
import unittest
import sys
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.core import CORE_BINDING
from phase_tool.errors import PhaseError
from phase_tool.contracts.publish_new_version_v1 import archive_locator
from phase_tool.installation import (_native_experimental_version1_registry,
    _native_read_binding_for_launch, _native_qualified_profile,
    _native_registry_for_manifest, _resolve_native_file_create_read_binding)
from phase_tool.mutation.ntfs.experimental_file1 import _ExperimentalFile1Admission, _experimental_admission
from phase_tool.mutation.ntfs.experimental_file2 import _ExperimentalFile2Admission
from phase_tool.mutation.ntfs.experimental_version1 import _ExperimentalVersion1Admission, _VERSION1_CONTRACT
from .test_native_experiment_file1 import experiment_fixture


def version1_fixture():
    old, _, manifest, _ = experiment_fixture()
    registry = _native_experimental_version1_registry()
    exact = registry.contract_bindings()['publish_new_version.v1@1.0.0']
    contract = registry.resolve_contract(exact['id'], exact['version'], exact['package_digest'],
        core_version=CORE_BINDING['version'])
    before, payload = b'old synthetic version\n', b'new synthetic version\n'
    doc = old.document()
    candidate = {'operation_id': 'synthetic-version1-only', 'idempotency_key': 'synthetic-version1-only',
        'target_locator': doc['target_locator'], 'input_binding': 'payload',
        'expected_current_digest': digest_bytes(before)}
    doc.update(contract=deepcopy(exact), request_id=candidate['idempotency_key'],
        candidate_digest=digest_bytes(canonical_bytes(candidate)),
        payload_digest=digest_bytes(payload), payload_length=len(payload))
    doc['root_grant']['root_binding'] = 'fixture_result_root'
    cap = _ExperimentalVersion1Admission(canonical_bytes(doc))
    profile = registry.guarantee_profile_bindings()['phase.native.ntfs.experiment.version1.authority.v1@1.0.0']
    impl = registry.resolve_guarantee_profile(profile)['implementation']
    manifest.update(native_read_installation_version='1.2',
        installation_id='phase.experiment.version1.'+cap.digest[7:],
        contract=deepcopy(exact), registry_snapshot_digest=registry.digest,
        root_grants=[deepcopy(doc['root_grant'])],
        root_projections={'fixture_result_root': '/ntfs-result'},
        mechanism={k:contract.document['operation']['mechanism'][k]for k in ('id','version','package_digest')},
        authority={'usage':'provider_backed','profile':profile,
            'provider':{k:impl[k]for k in ('id','version','artifact_digest')}})
    raw = canonical_bytes(manifest)
    binding = replace(_resolve_native_file_create_read_binding(manifest_bytes=raw,
        expected_manifest_digest=digest_bytes(raw), registry=registry), experimental_admission=cap)
    intent = {'run_id': doc['run_id'], 'contract': deepcopy(exact),
        'candidate': {'storage': {'value': candidate}}, 'inputs': [
            {'binding_id': 'payload', 'digest': doc['payload_digest'], 'blob_digest': doc['payload_digest'],
                'freeze_strategy': 'copy_and_hash'}]}
    effect = {'kind': 'publish_new_version', 'input_binding': 'payload',
        'target': {'root_binding': 'fixture_result_root', 'relative_locator': doc['target_locator']},
        'archive_target': {'root_binding': 'fixture_result_root',
            'relative_locator': archive_locator(candidate['expected_current_digest'])},
        'archive_digest': candidate['expected_current_digest'], 'archive_length': len(before),
        'operation_identity': candidate['operation_id'],
        'preconditions': {'existence':'present', 'expected_digest':candidate['expected_current_digest'],
            'expected_head':None, 'concurrency_token':candidate['expected_current_digest']},
        'content_digest': doc['payload_digest'], 'content_length': len(payload)}
    plan = {'run_id': doc['run_id'], 'contract': deepcopy(exact), 'effects': [effect]}
    return cap, binding, contract, intent, plan


class ExperimentalVersion1AdmissionTests(unittest.TestCase):
    def test_exact_version1_selection_has_no_coverage_and_normal_startup_refuses(self):
        cap, binding, _, _, _ = version1_fixture()
        self.assertEqual(cap.document()['contract'], _VERSION1_CONTRACT)
        self.assertIs(_experimental_admission(binding), cap)
        profile = cap.profile(binding)
        desc = binding.registry.resolve_guarantee_profile(profile.as_dict())
        self.assertEqual(desc['provided_guarantees'], [])
        self.assertEqual(desc['conformance'], [])
        with self.assertRaisesRegex(PhaseError, 'ntfs.native_profile_not_qualified'):
            _native_qualified_profile(binding.registry, profile.as_dict())
        with self.assertRaises(PhaseError):
            _native_registry_for_manifest(binding.manifest_bytes, binding.manifest_digest)

    def test_all_five_exact_obligations_remain_without_certifying_coverage(self):
        cap, binding, contract, _, _ = version1_fixture()
        operation = contract.document['operation']
        result = cap.assess(binding, operation['required_guarantees'], [operation['mechanism']])
        required = {'exclusive_create','readback_verification','cross_process_serialization',
            'namespace_bound_mutation','namespace_metadata_flush_attempted'}
        self.assertEqual(set(result['mechanisms'][0]['all_of']), required)
        self.assertNotIn('provided_guarantees', result)
        self.assertEqual(_ExperimentalFile1Admission._required, _ExperimentalFile2Admission._required)
        self.assertEqual(len(_ExperimentalFile1Admission._required), 3)
        for name in required:
            other = deepcopy(operation['required_guarantees'])
            other['mechanisms'][0]['all_of'].remove(name)
            with self.subTest(missing=name), self.assertRaises(PhaseError):
                cap.assess(binding, other, [operation['mechanism']])
        other = deepcopy(operation['required_guarantees'])
        other['mechanisms'][0]['all_of'].append('atomic_replace')
        with self.assertRaises(PhaseError):
            cap.assess(binding, other, [operation['mechanism']])

    def test_capability_constants_are_frozen_not_request_fields(self):
        cap, _, _, _, _ = version1_fixture()
        self.assertEqual([f.name for f in fields(_ExperimentalVersion1Admission)], ['raw'])
        with self.assertRaises(TypeError):
            _ExperimentalVersion1Admission(cap.raw, _required=frozenset())
        for name, value in [('_required', frozenset()), ('_profile', 'other'),
                ('_maximum_payload_length', 2**63), ('raw', b'{}')]:
            with self.subTest(field=name), self.assertRaises(FrozenInstanceError):
                setattr(cap, name, value)
        doc = cap.document(); doc['provided_guarantees'] = list(cap._required)
        with self.assertRaises(PhaseError):
            _ExperimentalVersion1Admission(canonical_bytes(doc)).document()

    def test_declared_version1_range_does_not_claim_actual_boundary_execution(self):
        cap, _, _, _, _ = version1_fixture()
        for length in (0, 16*1024**2):
            doc = cap.document(); doc['payload_length'] = length
            _ExperimentalVersion1Admission(canonical_bytes(doc)).document()
        for length in (-1, True, 16*1024**2+1):
            doc = cap.document(); doc['payload_length'] = length
            with self.subTest(length=length), self.assertRaises(PhaseError):
                _ExperimentalVersion1Admission(canonical_bytes(doc)).document()

    def test_capability_binds_expected_current_and_deterministic_archive(self):
        cap, _, _, intent, plan = version1_fixture()
        cap.check_original(intent, plan)
        for changed in ('current', 'archive', 'archive_root', 'old_digest', 'before_length',
                'precondition', 'operation', 'payload', 'new_length', 'run', 'kind'):
            other, effects = deepcopy(intent), deepcopy(plan)
            effect = effects['effects'][0]
            if changed == 'current':
                other['candidate']['storage']['value']['expected_current_digest'] = 'sha256:'+'a'*64
            elif changed == 'archive': effect['archive_target']['relative_locator'] = 'other.bin'
            elif changed == 'archive_root': effect['archive_target']['root_binding'] = 'other_root'
            elif changed == 'old_digest': effect['archive_digest'] = 'sha256:'+'a'*64
            elif changed == 'before_length': effect['archive_length'] = True
            elif changed == 'precondition': effect['preconditions']['concurrency_token'] = 'sha256:'+'a'*64
            elif changed == 'operation': effect['operation_identity'] = 'other'
            elif changed == 'payload': other['inputs'][0]['blob_digest'] = 'sha256:'+'a'*64
            elif changed == 'new_length': effect['content_length'] += 1
            elif changed == 'run': other['run_id'] = 'another-run'
            else: effect['kind'] = 'exclusive_create'
            with self.subTest(changed=changed), self.assertRaises(PhaseError):
                cap.check_original(other, effects)

    def test_cross_contract_generation_or_grant_cannot_reuse_capability(self):
        cap, binding, _, _, _ = version1_fixture()
        for cls in (_ExperimentalFile1Admission, _ExperimentalFile2Admission):
            with self.subTest(cls=cls), self.assertRaises(PhaseError):
                cls(cap.raw).document()
        for name, value in [('native_read_installation_version','1.4'),
                ('installation_id','phase.experiment.other'), ('root_grants',[])]:
            other = deepcopy(__import__('json').loads(binding.manifest_bytes))
            other[name] = value; raw = canonical_bytes(other)
            with self.subTest(field=name), self.assertRaises(PhaseError):
                cap.check_binding(replace(binding, manifest_bytes=raw, manifest_digest=digest_bytes(raw)))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'authority is Linux-only')
    def test_literal_authority_class_must_match_literal_admission_class(self):
        # Pure class predicate, without constructors or physical IO. This is
        # not an authority, worker execution or qualification witness.
        from phase_tool.mutation.ntfs.authority import _NativeFileCreateAuthority
        from phase_tool.mutation.ntfs.experimental_authority import _ExperimentalFile1Authority
        from phase_tool.mutation.ntfs.experimental_file2_authority import _ExperimentalFile2Authority
        from phase_tool.mutation.ntfs.experimental_version1_authority import _ExperimentalVersion1Authority
        from phase_tool.mutation.ntfs.experimental_file1 import _is_native_authority
        _, binding, _, _, _ = version1_fixture()
        for cls in (_ExperimentalVersion1Authority, _ExperimentalFile1Authority,
                _ExperimentalFile2Authority, _NativeFileCreateAuthority):
            shape = object.__new__(cls)
            shape.read_binding = binding
            with self.subTest(cls=cls):
                self.assertEqual(_is_native_authority(shape), cls is _ExperimentalVersion1Authority)
        class Unselected(_ExperimentalVersion1Authority): pass
        shape = object.__new__(Unselected)
        shape.read_binding = binding
        self.assertFalse(_is_native_authority(shape))
        self.assertFalse(_is_native_authority(SimpleNamespace(read_binding=binding)))

    def test_unselected_subclass_fails_before_registry_or_role_construction(self):
        class Unselected(_ExperimentalVersion1Admission): pass
        cap, _, _, _, _ = version1_fixture()
        launch = SimpleNamespace(_experimental_admission_context=Unselected(cap.raw))
        with patch('phase_tool.installation._native_experimental_version1_registry') as read:
            with self.assertRaisesRegex(PhaseError, 'ntfs.experimental_admission_required'):
                _native_read_binding_for_launch(launch)
            read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
