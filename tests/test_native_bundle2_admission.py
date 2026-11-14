"""Resolved contract -> real authority/admission regression, NOT NTFS evidence.

Only the physical ext4 evidence-root probe is replaced in this pure admission
model. The exact admission/profile/contract/registry guards run unchanged. No
Core, channel exchange, worker or Windows operation is requested.
"""
from copy import deepcopy
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from phase_tool import __version__
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import _NativeFileCreateReadBinding
from .test_native_bundle_protocol import projection


@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: Linux authority model requires fcntl')
class Bundle2AdmissionTests(unittest.TestCase):
    def model(self,*,historical=False):
        from phase_tool.installation import (_native_experimental_bundle2_registry,
            _native_experimental_bundle2_registry_v2)
        from phase_tool.mutation.ntfs.bundle2_channel import LinuxNativeBundle2Channel
        from phase_tool.mutation.ntfs.experimental_bundle2 import _ExperimentalBundle2Admission
        from phase_tool.mutation.ntfs.experimental_bundle2_v2 import _ExperimentalBundle2AdmissionV2
        from phase_tool.mutation.ntfs.experimental_bundle2_authority import _ExperimentalBundle2Authority
        from phase_tool.mutation.ntfs.experimental_bundle2_authority_v2 import _ExperimentalBundle2AuthorityV2
        registry=(_native_experimental_bundle2_registry if historical else _native_experimental_bundle2_registry_v2)()
        admission_type=_ExperimentalBundle2Admission if historical else _ExperimentalBundle2AdmissionV2
        authority_type=_ExperimentalBundle2Authority if historical else _ExperimentalBundle2AuthorityV2
        version='1.2.0' if historical else '1.2.1'
        contract=registry.contract_bindings()['bundle_create.v2@'+version]
        resolved=registry.resolve_contract(contract['id'],contract['version'],contract['package_digest'],core_version=__version__)
        case='00000000-0000-4000-8000-000000000205';run='bundle-admission-model'
        grant=parse_json_bytes(projection().grant_bytes)
        grant['components']=['Phase-NTFS-Qualification',case,'results']
        identity={'stable_id':'model-evidence','device':1,'inode':2}
        preparation={'stable_id':'model-preparation','device':1,'inode':3}
        candidate={'operation_id':run,'idempotency_key':run,'target_locator':'bundle',
            'input_binding':'payload','members':['synthetic.bin']}
        payload=projection().manifest_bytes
        admission=admission_type(canonical_bytes({'experimental_admission_version':'1.0',
            'authorization_digest':'sha256:6d3646ce58d6045fae41d1b22791c4f05d6cb177c343883fad86cd6ae0b0a40b',
            'contract':contract,'run_id':run,'request_id':run,'target_locator':'bundle',
            'candidate_digest':digest_bytes(canonical_bytes(candidate)),
            'payload_digest':digest_bytes(payload),'payload_length':len(payload),
            'windows_root':'S:\\Phase-NTFS-Qualification\\'+case+'\\results','root_grant':grant,
            'evidence_identity':identity,'preparation_identity':preparation,
            'wheel_digest':'sha256:'+'a'*64,
            'qualification':{'A05':'NOT_VERIFIED','G01':'NOT_VERIFIED'},'release_eligible':False}))
        profile=registry.guarantee_profile_bindings()[admission._profile]
        descriptor=registry.resolve_guarantee_profile(profile);implementation=descriptor['implementation']
        manifest={'native_read_installation_version':admission._manifest_version,
            'installation_id':admission._installation_prefix+admission.digest[7:],
            'contract':contract,'registry_snapshot_digest':registry.digest,
            'root_grants':[grant],'evidence_identity':identity,'preparation_identity':preparation,
            'root_projections':{'phase_result_root':'/ntfs-results'},
            'authority':{'usage':'provider_backed','profile':profile,
                'provider':{k:implementation[k]for k in ('id','version','artifact_digest')}},
            'mechanism':{k:resolved.document['operation']['mechanism'][k]for k in ('id','version','package_digest')}}
        raw=canonical_bytes(manifest)
        binding=_NativeFileCreateReadBinding(raw,digest_bytes(raw),registry,admission)
        channel=object.__new__(LinuxNativeBundle2Channel);channel._inspection_only=False
        authority=authority_type(binding,admission.profile(binding),canonical_bytes(manifest['root_projections']),
            channel,run_id=run,operation_nonce='b'*32)
        return authority,resolved,binding,admission,descriptor

    def test_real_resolved_new_contract_passes_assessment_and_old_empty_contract_still_refuses(self):
        with patch.object(_NativeFileCreateReadBinding,'check_evidence_root')as physical_probe:
            authority,contract,binding,admission,descriptor=self.model()
            result=authority.require_contract(contract)
            required={'cross_process_serialization','exclusive_create','namespace_bound_mutation',
                'namespace_metadata_flush_attempted','readback_verification'}
            self.assertEqual(set(result['mechanisms'][0]['all_of']),required)
            self.assertEqual(descriptor['provided_guarantees'],[])
            self.assertEqual(descriptor['conformance'],[])
            physical_probe.assert_called_once()
            old,old_contract,*_=self.model(historical=True)
            with self.assertRaises(PhaseError)as caught:old.require_contract(old_contract)
            self.assertEqual(caught.exception.code,'ntfs.experimental_requirements_mismatch')
            empty=deepcopy(contract.document);empty['operation']['required_guarantees']['mechanisms'][0]['all_of']=[]
            with self.assertRaises(PhaseError)as caught:
                authority.require_contract(SimpleNamespace(document=empty,package_digest=contract.package_digest))
            self.assertEqual(caught.exception.code,'ntfs.experimental_requirements_mismatch')

    def test_mixed_cap_profile_mechanism_and_ordinary_selection_remain_refused(self):
        from dataclasses import replace
        from phase_tool.installation import _native_registry_for_manifest
        with patch.object(_NativeFileCreateReadBinding,'check_evidence_root'):
            authority,contract,binding,admission,_=self.model()
            old,old_contract,old_binding,old_admission,_=self.model(historical=True)
            with self.assertRaises(PhaseError):admission.check_binding(replace(binding,experimental_admission=old_admission))
            with self.assertRaises(PhaseError):admission.profile(replace(binding,registry=old_binding.registry))
            with self.assertRaises(PhaseError):authority.require_contract(old_contract)
            mixed=deepcopy(contract.document);mixed['operation']['mechanism']['package_digest']='sha256:'+'0'*64
            with self.assertRaises(PhaseError):
                authority.require_contract(SimpleNamespace(document=mixed,package_digest=contract.package_digest))
            with self.assertRaises(PhaseError):
                _native_registry_for_manifest(binding.manifest_bytes,binding.manifest_digest)

    def test_new_snapshot_appends_only_two_bindings_and_reuses_original_mechanism(self):
        from phase_tool.installation import (_native_experimental_bundle2_registry,
            _native_experimental_bundle2_registry_v2)
        old=_native_experimental_bundle2_registry();new=_native_experimental_bundle2_registry_v2()
        self.assertEqual(new.to_document()['entries'][:159],old.to_document()['entries'])
        self.assertEqual(len(new.to_document()['entries']),161)
        self.assertEqual(new.to_document()['trust_roots'],old.to_document()['trust_roots'])
        bodies=[]
        for version,registry in [('1.2.0',old),('1.2.1',new)]:
            binding=registry.contract_bindings()['bundle_create.v2@'+version]
            bodies.append(registry.resolve_contract(binding['id'],binding['version'],binding['package_digest'],core_version=__version__).document)
        self.assertEqual(bodies[0]['operation']['mechanism'],bodies[1]['operation']['mechanism'])
        self.assertEqual(bodies[0]['operation']['required_guarantees']['mechanisms'][0]['all_of'],[])
        self.assertEqual(len(bodies[1]['operation']['required_guarantees']['mechanisms'][0]['all_of']),5)


class Bundle2LauncherDecodingTests(unittest.TestCase):
    def test_real_new_launcher_reads_projection_context_and_rejects_mixed_generations(self):
        from importlib.resources import files
        from phase_tool.mutation.ntfs.bundle_execution import _BUNDLE2_CONTRACT,_BUNDLE2_CONTRACT_V2
        template=files('phase_tool').joinpath('data/native/native_phase_experiment_bundle2_v2.py.in')
        namespace={'__name__':'source_only_launcher_model','__file__':str(template)}
        # Only stdlib imports and function definitions run; main/fixed_startup
        # remain uncalled. This is decoder evidence, not a startup/worker test.
        exec(compile(template.read_bytes(),str(template),'exec'),namespace)
        initial={'channel_id':'c'*32,'projection':{'context':{
            'run_id':'bundle-launcher-model','operation_nonce':'d'*32}}}
        before=deepcopy(initial)
        manifest={'native_read_installation_version':'1.8','contract':_BUNDLE2_CONTRACT_V2}
        decoded=namespace['worker_invocation'](manifest,initial)
        self.assertEqual(decoded,{'run_id':'bundle-launcher-model','channel_id':'c'*32,
            'operation_nonce':'d'*32,'request':initial})
        self.assertEqual(initial,before)
        for version,contract in [('1.7',_BUNDLE2_CONTRACT_V2),('1.8',_BUNDLE2_CONTRACT),('1.7',_BUNDLE2_CONTRACT)]:
            with self.subTest(version=version,contract=contract),self.assertRaises(RuntimeError):
                namespace['worker_invocation']({'native_read_installation_version':version,'contract':contract},initial)
        with self.assertRaises(KeyError):namespace['worker_invocation'](manifest,{'channel_id':'c'*32})


if __name__=='__main__':unittest.main()
