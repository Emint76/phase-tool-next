"""The installed directory startup must keep the real qualification gate."""
from types import SimpleNamespace
from pathlib import Path
import runpy
import sys
from unittest import TestCase, skipUnless
from unittest.mock import patch

from phase_tool import __version__, installation
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.errors import PhaseError


class NativeDirectoryFile2StartupTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = installation._native_file2_registry()
        cls.binding = cls.registry.contract_bindings()['file_create.v2@1.0.0']

    def test_ordinary_file2_startup_refuses_current_unqualified_registry(self):
        raw = canonical_bytes({'native_read_installation_version': '1.3',
                               'registry_snapshot_digest': self.registry.digest,
                               'contract': self.binding})
        with patch.object(installation, '_resolve_native_file_create_read_binding',
                          side_effect=AssertionError('read binding reached')) as resolve:
            with self.assertRaisesRegex(PhaseError, 'ntfs.native_profile_not_qualified'):
                installation._require_qualified_native_file2_manifest(raw, digest_bytes(raw))
            resolve.assert_not_called()

    def test_manifest_cannot_replace_the_fixed_registry(self):
        raw = canonical_bytes({'native_read_installation_version': '1.3',
                               'registry_snapshot_digest': 'sha256:' + 'f' * 64,
                               'contract': self.binding})
        with self.assertRaisesRegex(PhaseError, 'ntfs.original_registry_mismatch'):
            installation._require_qualified_native_file2_manifest(raw, digest_bytes(raw))

    def test_startup_envelope_requires_explicit_closed_generation(self):
        launcher = (Path(installation.__file__).parent /
                    'data/native/native_phase_candidate_launcher_v1.py.in')
        select = runpy.run_path(str(launcher))['fixed_startup_version']
        common = dict.fromkeys(('config_base64', 'config_digest', 'manifest_base64',
                                'manifest_digest', 'dependency_roots'))
        ordinary = dict(common, native_fixed_startup_version='1.2')
        historical = dict(common, native_fixed_startup_version='1.1')
        self.assertEqual(select(ordinary), '1.2')
        self.assertEqual(select(dict(historical, experimental_admission_base64='')), '1.1')
        for invalid in (historical, dict(ordinary, experimental_admission_base64=''),
                        dict(ordinary, qualification='PASS'), common):
            with self.subTest(fields=invalid.keys()), self.assertRaises(RuntimeError):
                select(invalid)

    @skipUnless(sys.platform.startswith('linux'), 'File v2 authority runs in the Linux Core')
    def test_file2_contract_projection_reaches_the_real_coverage_check(self):
        from phase_tool.mutation.ntfs.file2_authority import _QualifiedFile2Authority

        contract = self.registry.resolve_contract(self.binding['id'], self.binding['version'],
                                                  self.binding['package_digest'], core_version=__version__)
        mechanism = contract.document['operation']['mechanism']
        manifest = {'contract': self.binding,
                    'mechanism': {key: mechanism[key] for key in ('id', 'version', 'package_digest')}}
        # Test only the pure contract comparison. The production startup and
        # coverage guards are real. This shell has no channel or authority.
        shell = SimpleNamespace(_usable=lambda: None, _manifest=manifest,
                                profile=None, registry=self.registry)
        with self.assertRaisesRegex(PhaseError, 'guarantee.profile_unavailable'):
            _QualifiedFile2Authority.require_contract(shell, contract)
        manifest['mechanism']['package_digest'] = 'sha256:' + 'f' * 64
        with self.assertRaisesRegex(PhaseError, 'ntfs.original_single_effect_required'):
            _QualifiedFile2Authority.require_contract(shell, contract)
