"""Fixed connected candidate remains NO-GO; no native IO or fake qualification."""
from copy import deepcopy
import hashlib
from importlib import resources as package_resources
import inspect
import unittest
from unittest.mock import patch

from phase_tool import __version__, evidence, installation
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import (_native_file_create_candidate_registry,
    _native_connected_file_create_registry, _native_file_create_installation,
    _native_qualified_profile)
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.registry import BundledRegistry, RegistrySnapshot


class NativeConnectedRegistryTests(unittest.TestCase):
    def test_new_snapshot_keeps_both_historical_generations_byte_bound(self):
        prior=_native_file_create_candidate_registry()
        connected=_native_connected_file_create_registry()
        self.assertEqual(prior.digest,'sha256:fa2a9aff5f576d15b5a71574a11bd3a7a994a38346540ff6d7e7a74335cfa2c7')
        self.assertEqual(connected.digest,'sha256:c5fe3be5e03d3be6b390135cb72e52559081c62feccb52e7db0788d8f705088b')
        old=prior.to_document()
        expected=deepcopy(old)
        for entry in expected['entries']:
            if (entry.get('kind'),entry.get('id'),entry.get('package_digest'))==(
                'contract','file_create.v1','sha256:734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09'):
                self.assertIs(entry['current'],True)
                entry['current']=False
        new=connected.to_document()
        self.assertEqual(new['entries'][:len(expected['entries'])],expected['entries'])
        self.assertEqual(len(new['entries'])-len(expected['entries']),6)
        self.assertEqual(new['trust_roots'],old['trust_roots'])
        for pin in ['sha256:e3231b5f97bb49c499a82fd1d003ddde081c9cbe31b7b10b87435526c1e15870',
                'sha256:734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09']:
            a=prior.resolve_contract('file_create.v1','1.0.0',pin,core_version=__version__)
            b=connected.resolve_contract('file_create.v1','1.0.0',pin,core_version=__version__)
            self.assertEqual(a.document,b.document)
            self.assertEqual(a.entry['package_artifacts'],b.entry['package_artifacts'])
        self.assertEqual(BundledRegistry.load().to_document()['trust_roots'],old['trust_roots'])

    def test_current_package_adds_only_three_schemas_and_reuses_original_mechanism(self):
        prior=_native_file_create_candidate_registry()
        connected=_native_connected_file_create_registry()
        old_binding=prior.contract_bindings()['file_create.v1@1.0.0']
        new_binding=connected.contract_bindings()['file_create.v1@1.0.0']
        self.assertEqual(new_binding['package_digest'],
            'sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
        a=prior.resolve_contract(old_binding['id'],old_binding['version'],old_binding['package_digest'],core_version=__version__)
        b=connected.resolve_contract(new_binding['id'],new_binding['version'],new_binding['package_digest'],core_version=__version__)
        self.assertEqual(a.document,b.document)
        old_resources={row['resource']:row['digest'] for row in a.entry['package_artifacts']}
        new_resources={row['resource']:row['digest'] for row in b.entry['package_artifacts']}
        self.assertEqual({k:v for k,v in new_resources.items() if k in old_resources},old_resources)
        self.assertEqual(set(new_resources)-set(old_resources),{
            'schemas/native-terminal-proof-1.0.schema.json',
            'schemas/stage3-command-result-1.2.schema.json',
            'schemas/native-parent-failure-1.0.schema.json'})
        self.assertEqual(dict(prior.resolve_mechanism(a.document['operation']['mechanism'])),
            dict(connected.resolve_mechanism(b.document['operation']['mechanism'])))

    def test_candidate_profile_is_explicitly_unqualified_and_pins_actual_authority_source(self):
        registry=_native_connected_file_create_registry()
        profiles=registry.guarantee_profile_bindings()
        self.assertNotIn('phase.native.ntfs.authority.v1@1.0.0',profiles)
        binding=profiles['phase.native.ntfs.candidate.authority.v1@1.0.0']
        descriptor=registry.resolve_guarantee_profile(binding)
        self.assertEqual(descriptor['classification'],'qualification_candidate')
        self.assertEqual(descriptor['provided_guarantees'],[])
        self.assertEqual(descriptor['conformance'],[])
        actual=package_resources.files('phase_tool').joinpath('mutation/ntfs/authority.py').read_bytes()
        self.assertEqual(descriptor['implementation']['artifact_digest'],digest_bytes(actual))
        with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
            _native_qualified_profile(registry,binding)

    def test_factory_refuses_even_empty_inputs_before_channel_or_evidence_reservation(self):
        # These sentinels detect forbidden calls; neither grants qualification.
        with (patch.object(installation,'_native_connected_file_create_registry',
                wraps=_native_connected_file_create_registry) as selected,
                patch.object(LinuxNativeChannelV2,'__init__',side_effect=AssertionError('channel reached')) as channel,
                patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('evidence reached')) as store):
            with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                _native_file_create_installation(manifest_bytes=b'',expected_manifest_digest=None,
                    run_id=None,operation_nonce=None,channel_id=None)
            selected.assert_called_once_with()
            channel.assert_not_called()
            store.assert_not_called()

    def test_connected_loader_has_no_request_registry_path_or_provider_selector(self):
        self.assertEqual(len(inspect.signature(_native_connected_file_create_registry).parameters),0)
        with self.assertRaises(TypeError):_native_connected_file_create_registry(path='synthetic')
        with self.assertRaises(TypeError):_native_connected_file_create_registry(BundledRegistry.load())

    def test_launcher_is_byte_exact_packaged_data_without_new_cli_entrypoint(self):
        root=package_resources.files('phase_tool')
        raw=root.joinpath('data/native/native_phase_launcher.py.in').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            'de6a39575fb2b0b9388dcd3a5590c275eaef3f8acaf2222c816ec4c4fb8a0fd0')
        self.assertIn(b'qualified lifetime immutability',raw)
        self.assertNotIn(b'sys.meta_path.insert',raw)


    def test_previous_connected_registry_bytes_and_missing_schema_failure_are_retained(self):
        resources=BundledRegistry.resources()
        raw=resources['registries/native-file-create-candidate-v2.json']
        self.assertEqual(digest_bytes(raw),'sha256:fd7e6f78790491d59f97820fa23132a95cdd89678548e441464cca728605ca2f')
        old=RegistrySnapshot.from_document(parse_json_bytes(raw),resources)
        new=_native_connected_file_create_registry()
        self.assertEqual(new.to_document()['entries'][:-1],old.to_document()['entries'])
        exact=old.guarantee_profile_bindings()['phase.native.ntfs.candidate.authority.v1@1.0.0']
        with self.assertRaises(PhaseError) as caught:old.resolve_guarantee_profile(exact)
        self.assertEqual(caught.exception.code,'registry.entry_not_found')
        self.assertIn('mutation-guarantee-profile-1.1.schema.json',str(caught.exception))
        descriptor=new.resolve_guarantee_profile(exact)
        self.assertEqual(descriptor['classification'],'qualification_candidate')
        self.assertEqual(descriptor['provided_guarantees'],[])
        self.assertEqual(descriptor['conformance'],[])
