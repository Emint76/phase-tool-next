"""Pure scope parsing; lowercase is NativeIO's existing canonical form.

No actual volume query/runtime acceptance/process/NativeIO construction.
"""
from copy import deepcopy
from pathlib import Path
import unittest
from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import input_stage
from tests.native_staged_original14_data import prepared


class CanonicalVolumeScope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture,cls.fixture_raw,cls.manifests,cls.base_graph=prepared('3.0')

    def vector(self,role,guid):
        manifest=self.manifests[role]
        path=Path(r'C:\Source-Model-Never-Created')/role/'native-input-scope.json'
        scope={'native_input_scope_version':'1.0','scope_id':'canonical-volume-'+role.lower(),
            'owner_scope_id':self.fixture['owner_scope_id'],'fixture_digest':digest_bytes(self.fixture_raw),
            'installation_id':manifest['installation_id'],'contract':manifest['contract'],
            'windows_root':r'C:\Source-Model-Never-Created\inputs',
            'volume':{'device':r'\Device\HarddiskVolume6','volume_guid':guid,'volume_serial32':714582050,
                      'filesystem':'NTFS','flags':0},
            'root_identity':{'volume_serial':manifest['root_grants'][0]['native_identity']['volume_serial'],'file_id':'f'*32},
            'preparation_root':manifest['preparation_root'],'preparation_identity':manifest['preparation_identity']}
        raw=canonical_bytes(scope);graph=deepcopy(self.base_graph)
        # Native parser selects platform-specific graph; both refer to exactly
        # the same bytes in this pure fixture, independent of the host platform.
        for platform in('windows','linux'):graph[platform]['dependency_file_digests']={str(path):digest_bytes(raw)}
        config={'native_launch_version':'3.0','dependency_file_digests':{str(path):digest_bytes(raw)},'artifact_graph':graph}
        return raw,dict(config=config,manifest=manifest,scope_path=path,fixture_raw=self.fixture_raw)

    def test_all_six_accept_existing_native_lowercase_canonical_form(self):
        for role in self.manifests:
            with self.subTest(role=role):
                raw,kw=self.vector(role,'\\\\?\\volume{ba5c2916-eefe-46a6-aabc-b23fe12c95b4}\\')
                parsed,actual=input_stage._input_scope_document(raw,**kw)
                self.assertEqual(actual,role)
                self.assertEqual(parsed['volume']['volume_guid'],'\\\\?\\volume{ba5c2916-eefe-46a6-aabc-b23fe12c95b4}\\')

    def test_uppercase_inconsistent_with_exact_native_mapping_is_refused(self):
        for role in self.manifests:
            with self.subTest(role=role):
                raw,kw=self.vector(role,'\\\\?\\Volume{ba5c2916-eefe-46a6-aabc-b23fe12c95b4}\\')
                with self.assertRaisesRegex(PhaseError,'input_stage.local_ntfs_scope_required'):
                    input_stage._input_scope_document(raw,**kw)

    def test_malformed_unc_and_other_guid_forms_are_refused(self):
        for guid in('\\\\server\\share\\','\\\\?\\volume{BA5C2916-eefe-46a6-aabc-b23fe12c95b4}\\',
                     '\\\\?\\volume{ba5c2916-eefe-46a6-aabc-b23fe12c95b4}', 'C:\\'):
            with self.subTest(guid=guid):
                raw,kw=self.vector('File1',guid)
                with self.assertRaisesRegex(PhaseError,'input_stage.local_ntfs_scope_required'):
                    input_stage._input_scope_document(raw,**kw)
