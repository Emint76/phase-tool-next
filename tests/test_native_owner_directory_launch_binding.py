"""Real owner metadata and fixed factories; accepted runtime is NOT created."""
import base64
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import owner_directory_launch as launch
from phase_tool.mutation.ntfs import owner_directory_installation as factory
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
from tests.owner_directory_test_data import synthetic_catalog,owner_document


class OwnerLaunchBindingMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog=synthetic_catalog().check()
        cls.doc=owner_document(cls.catalog);cls.raw=canonical_bytes(cls.doc)
        cls.config={key:None for key in launch._FIELDS}
        cls.config.update(native_launch_version='4.0',phase_wheel_digest=cls.doc['phase_wheel_digest'],
            owner_directory_configuration_base64=base64.b64encode(cls.raw).decode(),
            owner_directory_configuration_digest=digest_bytes(cls.raw))

    def manifest(self,role_index):
        row=self.doc['manifests'][role_index]
        return base64.b64decode(row['manifest_base64']),row['manifest_digest']

    def test_all_six_public_source_bindings_refuse_unqualified_fixed_catalogue(self):
        self.assertIsNone(factory._NATIVE_OWNER_DIRECTORY_CATALOG_DIGEST)
        for index in range(6):
            body,digest=self.manifest(index)
            with self.subTest(index=index),self.assertRaises(PhaseError)as error:
                launch._owner_directory_launch_binding(self.config,body,digest)
            self.assertEqual(error.exception.code,'ntfs.native_profile_not_qualified')

    def test_owner_wheel_mismatch_refuses_before_catalogue_selector(self):
        config={**self.config,'phase_wheel_digest':'sha256:'+'f'*64}
        with patch.object(factory,'_fixed_owner_directory_catalog')as selector:
            with self.assertRaises(PhaseError)as error:
                launch._owner_directory_launch_binding(config,*self.manifest(0))
        self.assertEqual(error.exception.code,'ntfs.owner_directory_wheel_binding_mismatch')
        selector.assert_not_called()

    def test_qualification_timeout_is_one_optional_exact_launch4_field(self):
        body,digest=self.manifest(0)
        def selected(config,config_digest=None):
            raw=canonical_bytes(config)
            return launch._accepted_cold_publication_seconds(config_bytes=raw,
                expected_config_digest=digest_bytes(raw) if config_digest is None else config_digest,
                manifest_bytes=body,expected_manifest_digest=digest)

        self.assertIsNone(selected(self.config))
        qualified={**self.config,'qualification_cold_publication_seconds':900}
        with patch.object(factory,'_fixed_owner_directory_catalog',return_value=self.catalog)as binding:
            self.assertEqual(selected(qualified),900)
            binding.assert_called_once()
            for config in ({**qualified,'native_launch_version':'3.0'},
                    {**qualified,'foreign_field':True},
                    *({**qualified,'qualification_cold_publication_seconds':bad} for bad in (True,899,901,'900',None))):
                with self.subTest(config=config),self.assertRaises(PhaseError):
                    selected(config)
            with self.assertRaises(PhaseError):
                selected(qualified,'sha256:'+'f'*64)
            binding.assert_called_once()
        with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
            selected(qualified)

    def test_qualification_timeout_requires_the_six_closed_semantic_fixture_roles(self):
        from tests.native_staged_original14_data import prepared
        from phase_tool.mutation.ntfs.owner_directory_fixture import _kinds
        from phase_tool.mutation.ntfs.owner_semantic_fixture import _c02_alias_domain_digest

        document,fixture,manifests,graph=prepared('3.0')
        roles=_kinds()
        buffers={role:canonical_bytes(manifest) for role,manifest in manifests.items()}
        history=canonical_bytes({'history_manifest_set_version':'3.0',
            'fixture_base64':base64.b64encode(fixture).decode(),'fixture_digest':digest_bytes(fixture),
            'manifests':[{'role':role,'manifest_base64':base64.b64encode(body).decode(),
                'manifest_digest':digest_bytes(body)} for role,body in buffers.items()],
            'predecessors':[]})
        config={key:None for key in launch._FIELDS if not key.startswith('owner_directory_configuration_')}
        config.update(native_launch_version='3.0',qualification_cold_publication_seconds=900,
            phase_wheel_digest=document['wheel_digest'],artifact_graph=graph,
            history_manifest_set_base64=base64.b64encode(history).decode(),
            history_manifest_set_digest=digest_bytes(history))

        def selected(config,role,admission):
            raw=canonical_bytes(config);body=buffers[role]
            return launch._accepted_cold_publication_seconds(config_bytes=raw,
                expected_config_digest=digest_bytes(raw),manifest_bytes=body,
                expected_manifest_digest=digest_bytes(body),_experimental_admission_context=admission)

        for role,kind in roles.items():
            with self.subTest(role=role):
                self.assertEqual(selected(config,role,kind(fixture)),900)
        qualify=roles['File1'](fixture)
        for bad in ({**config,'foreign_field':True},
                {**config,'history_manifest_set_digest':'sha256:'+'7'*64},
                {**config,'phase_wheel_digest':'sha256:'+'8'*64}):
            with self.subTest(config=bad),self.assertRaises(PhaseError):
                selected(bad,'File1',qualify)
        with self.assertRaises(PhaseError):selected(config,'File1',None)
        with self.assertRaises(PhaseError):selected(config,'File1',roles['File2'](fixture))

        current=document['root_grants'][0]
        observations={leaf:{**current, 'components':[*current['components'][:-1],leaf],
            'reparse_tag':0,'all_handles_closed':True,'raw_digest':digest_bytes(leaf.encode())}
            for leaf in ('results','RESULTS')}
        for observation in observations.values():del observation['root_binding']
        alias={**document,'c02_current_root_alias':{'version':'1.0',
            'domain_digest':_c02_alias_domain_digest(document,observations),
            'no_follow_observations':observations}}
        alias_admission=roles['File1'](canonical_bytes(alias))
        self.assertIn('c02_current_root_alias',alias_admission.document())
        with self.assertRaisesRegex(PhaseError,'ntfs.owner_fixture_scope'):
            selected(config,'File1',alias_admission)

    def test_exact_type_required_and_no_new_keyword_on_legacy_typed_metadata(self):
        with self.assertRaises(PhaseError)as error:
            launch._owner_directory_installation_arguments(SimpleNamespace(_config={'native_launch_version':'3.0'}))
        self.assertEqual(error.exception.code,'ntfs.accepted_launch_binding_required')
        # Exact class created without __init__ is only a metadata vector, not
        # an accepted runtime or authenticated Native operation.
        value=object.__new__(_NativeAcceptedLaunch)
        value._config_bytes=canonical_bytes({'native_launch_version':'3.0'})
        value._owner_directory_context=None
        self.assertEqual(launch._owner_directory_installation_arguments(value),{})
        value._owner_directory_context=object()
        with self.assertRaises(PhaseError):launch._owner_directory_installation_arguments(value)

    def test_recovery_frontdoor_revalidates_exact_bundle2_role_only(self):
        # Synthetic production descriptor selection is explicitly modeled.
        # Actual metadata resolver/profile/hash checks remain genuine.
        with patch.object(factory,'_fixed_owner_directory_catalog',return_value=self.catalog)as selector:
            for index in range(6):
                args=(self.config,*self.manifest(index))
                with self.subTest(index=index):
                    if index==5:self.assertIsNone(launch._require_owner_directory_recovery_startup(*args))
                    else:
                        with self.assertRaises(PhaseError)as error:
                            launch._require_owner_directory_recovery_startup(*args)
                        self.assertEqual(error.exception.code,'ntfs.owner_directory_recovery_role_required')
        self.assertEqual(selector.call_count,6)


if __name__=='__main__':unittest.main()
