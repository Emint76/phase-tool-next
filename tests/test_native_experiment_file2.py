"""Closed data/admission regressions; no native calls or qualification claims."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.core import CORE_BINDING
from phase_tool.errors import PhaseError
from phase_tool.installation import (_native_experimental_file2_registry,
    _native_qualified_profile, _native_registry_for_manifest,
    _resolve_native_file_create_read_binding, _native_read_binding_for_launch)
from phase_tool.mutation.ntfs.experimental_file1 import _ExperimentalFile1Admission, _experimental_admission
from phase_tool.mutation.ntfs.experimental_file2 import _ExperimentalFile2Admission, _FILE2_CONTRACT
from .test_native_experiment_file1 import experiment_fixture


def file2_fixture():
    old, _, manifest, _ = experiment_fixture()
    registry = _native_experimental_file2_registry()
    exact = registry.contract_bindings()['file_create.v2@1.0.0']
    contract = registry.resolve_contract(exact['id'],exact['version'],exact['package_digest'],
        core_version=CORE_BINDING['version'])
    doc = old.document(); doc['contract'] = deepcopy(exact)
    cap = _ExperimentalFile2Admission(canonical_bytes(doc))
    profile = registry.guarantee_profile_bindings()['phase.native.ntfs.experiment.file2.authority.v1@1.0.0']
    impl = registry.resolve_guarantee_profile(profile)['implementation']
    manifest.update(native_read_installation_version='1.3',
        installation_id='phase.experiment.file2.'+cap.digest[7:],
        contract=deepcopy(exact),registry_snapshot_digest=registry.digest,
        mechanism={k:contract.document['operation']['mechanism'][k]for k in ('id','version','package_digest')},
        authority={'usage':'provider_backed','profile':profile,
            'provider':{k:impl[k]for k in ('id','version','artifact_digest')}})
    raw = canonical_bytes(manifest)
    binding = replace(_resolve_native_file_create_read_binding(manifest_bytes=raw,
        expected_manifest_digest=digest_bytes(raw),registry=registry),experimental_admission=cap)
    return cap,binding,contract


class ExperimentalFile2AdmissionTests(unittest.TestCase):
    def test_exact_file2_context_uses_new_profile_and_preserves_normal_guard(self):
        cap,binding,contract = file2_fixture()
        self.assertEqual(cap.document()['contract'],_FILE2_CONTRACT)
        self.assertIs(_experimental_admission(binding),cap)
        profile = cap.profile(binding)
        desc = binding.registry.resolve_guarantee_profile(profile.as_dict())
        self.assertEqual(desc['provided_guarantees'],[])
        self.assertEqual(desc['conformance'],[])
        with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
            _native_qualified_profile(binding.registry,profile.as_dict())
        with self.assertRaises(PhaseError):
            _native_registry_for_manifest(binding.manifest_bytes,binding.manifest_digest)
        op = contract.document['operation']
        cap.assess(binding,op['required_guarantees'],[op['mechanism']])

    def test_class_constants_are_not_request_or_dataclass_fields(self):
        self.assertEqual([x.name for x in fields(_ExperimentalFile2Admission)],['raw'])
        cap,_,_ = file2_fixture()
        with self.assertRaises(TypeError):
            _ExperimentalFile2Admission(cap.raw,_maximum_payload_length=2**63)
        for field,value in (('_contract',{}),('_maximum_payload_length',2**63),
                ('_manifest_version','1.1'),('_profile','unselected'),('new_attribute',True)):
            with self.subTest(field=field),self.assertRaises(FrozenInstanceError):
                setattr(cap,field,value)

    def test_declared_lengths_preserve_file2_range_without_widening_file1(self):
        cap,_,_ = file2_fixture()
        for length in (0,1024**2+1,2*1024**3):
            doc=cap.document();doc['payload_length']=length
            _ExperimentalFile2Admission(canonical_bytes(doc)).document()
        for length in (-1,True,2*1024**3+1):
            doc=cap.document();doc['payload_length']=length
            with self.subTest(length=length),self.assertRaises(PhaseError):
                _ExperimentalFile2Admission(canonical_bytes(doc)).document()
        old,_,_,_=experiment_fixture()
        for length in (0,1024**2+1):
            doc=old.document();doc['payload_length']=length
            with self.assertRaises(PhaseError):
                _ExperimentalFile1Admission(canonical_bytes(doc)).document()

    def test_cross_contract_or_other_profile_cannot_reuse_capability(self):
        cap,binding,_ = file2_fixture()
        with self.assertRaises(PhaseError):
            _ExperimentalFile1Admission(cap.raw).document()
        old,_,_,_=experiment_fixture()
        with self.assertRaises(PhaseError):
            _ExperimentalFile2Admission(old.raw).document()
        manifest=deepcopy(__import__('json').loads(binding.manifest_bytes))
        manifest['native_read_installation_version']='1.1'
        raw=canonical_bytes(manifest)
        with self.assertRaises(PhaseError):
            cap.check_binding(replace(binding,manifest_bytes=raw,manifest_digest=digest_bytes(raw)))

    def test_subclass_is_refused_before_registry_read_or_launch(self):
        class Unselected(_ExperimentalFile2Admission):pass
        cap,_,_=file2_fixture()
        launch=SimpleNamespace(_experimental_admission_context=Unselected(cap.raw))
        with patch('phase_tool.installation._native_experimental_file2_registry')as read:
            with self.assertRaisesRegex(PhaseError,'ntfs.experimental_admission_required'):
                _native_read_binding_for_launch(launch)
            read.assert_not_called()


if __name__=='__main__':unittest.main()
