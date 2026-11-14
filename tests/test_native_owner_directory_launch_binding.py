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
