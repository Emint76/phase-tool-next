"""Negative native API boundary components only; NOT native qualification.

The inert exact-type shell grants no authority. No admission profile, factory,
worker or NativeIO is mocked/admitted. Host target/preparation paths must never
be touched by this unsupported combination. Ordinary Host tests stay unchanged.
"""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import importlib
import unittest
from unittest.mock import patch

from phase_tool.application import PhaseApplication
from phase_tool.errors import PhaseError
from phase_tool.installation import _NativeFileCreateInstallation


class NativeHighLevelBoundaryTests(unittest.TestCase):
    def refuse(self, kind, version):
        # Data-free shell ONLY for a negative type boundary; no constructor/authority.
        app = PhaseApplication(installation=object.__new__(_NativeFileCreateInstallation))
        adapter = importlib.import_module('phase_tool.publish_' + kind)
        args = dict(source_root=Path('/synthetic/source'), target_root=Path('/synthetic/opaque-result'),
            target_locator='document.bin', preparation_root=Path('/synthetic/preparation'),
            evidence_root=Path('/synthetic/evidence'), request_id='synthetic-native-api',
            run_id='synthetic-native-api', publication_version=version)
        if kind == 'file':
            args['source_locator'] = 'payload.bin'
        else:
            args['members'] = ['payload.bin']
        with ExitStack() as stack:
            untouched = [stack.enter_context(patch.object(adapter, name,
                side_effect=AssertionError('Host path/scratch reached'))) for name in
                ('_root', 'contained_target_path', 'TemporaryDirectory')]
            untouched.extend(stack.enter_context(patch.object(app, name,
                side_effect=AssertionError('Core/binding/inspect reached'))) for name in
                ('_binding', 'run', 'inspect'))
            qualifier = patch.object(adapter, 'qualify_host_authority_roots', side_effect=AssertionError('Host qualification reached')) if kind == 'bundle' else patch(
                'phase_tool.installation.qualify_host_authority_roots', side_effect=AssertionError('Host qualification reached'))
            untouched.append(stack.enter_context(qualifier))
            response = getattr(app, 'publish_' + kind)(**args)
            for call in untouched:
                call.assert_not_called()
        value = response.payload
        self.assertEqual(response.exit_code, 10)
        self.assertFalse(value['success'])
        self.assertEqual(value['status'], 'rejected_before_write')
        self.assertEqual(value['error'], 'ntfs.high_level_publication_unavailable')
        self.assertIs(value['mutation_attempted'], False)
        self.assertFalse(value['target_verified'])
        self.assertIsNone(value['receipt_digest'])
        expected = ('file_create.v1@1.0.0' if version == '1.0' else 'file_create.v2@1.0.0') if kind == 'file' else (
            'bundle_create.v1@1.0.0' if version == '1.0' else 'bundle_create.v2@1.1.0')
        self.assertEqual(value['contract_binding'], expected)
        # Module-level adapters also accepted duck-typed Host clients. Preserve
        # that boundary: absence of installation reaches the first Host check.
        with patch.object(adapter, '_root', side_effect=PhaseError('synthetic.host_root_reached')) as root:
            legacy = getattr(adapter, 'publish_' + kind)(SimpleNamespace(), **args)
        root.assert_called_once()
        self.assertEqual(legacy.payload['error'], 'synthetic.host_root_reached')
        self.assertEqual(legacy.exit_code, 10)

    def test_native_file_v1_refuses_before_host_io(self):
        self.refuse('file', '1.0')

    def test_native_file_v2_refuses_before_host_io(self):
        self.refuse('file', '2.0')

    def test_native_bundle_v1_refuses_before_host_io(self):
        self.refuse('bundle', '1.0')

    def test_native_bundle_v2_refuses_before_host_io(self):
        self.refuse('bundle', '2.0')
