"""Negative components only; the real native qualification guard is unmocked.

Static selector shells establish no accepted launcher, G01 or positive native
operation. Delivery/stdio shells only expose the exact early refusal result.
"""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.errors import PhaseError
from phase_tool import evidence, installation
from phase_tool.mutation.ntfs import entrypoint, preparation
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3


class NativeFilePreparationTests(unittest.TestCase):
    def request(self):
        return {'operation': 'execute',
            'native_file_publication_request_version': '1.0',
            'source_locator': 'incoming/synthetic.bin',
            'target_locator': 'synthetic/output.bin',
            'request_id': 'synthetic-request', 'expected_digest': None}

    def launch(self, request, version='1.2'):
        registry = (installation._native_inspection_file_create_registry()
            if version == '1.1' else installation._native_lifecycle_registry())
        raw = canonical_bytes({'native_read_installation_version': version,
            'registry_snapshot_digest': registry.digest,
            'contract': {'id': 'file_create.v1'}})
        return SimpleNamespace(_inspection_only=False, check_runtime=Mock(),
            invocation={'request': request}, _manifest_bytes=raw,
            installation_digest=digest_bytes(raw), run_id='synthetic-unqualified',
            operation_nonce='a'*32, channel_id='b'*32)

    def test_literal_request_reaches_real_refusal_before_preparation_core_or_channel(self):
        for version in ('1.1', '1.2'):
            with self.subTest(version=version):
                launch = self.launch(self.request(), version)
                with (patch.object(entrypoint, '_linux_stdio_identity', return_value='synthetic-stdio'),
                        patch.object(entrypoint, '_deliver_linux_frame') as deliver,
                        patch.object(preparation, '_prepare_file_publication',
                            side_effect=AssertionError('preparation reached')) as prepare,
                        patch.object(LinuxNativeChannelV2, '__init__',
                            side_effect=AssertionError('channel reached')) as channel2,
                        patch.object(LinuxNativeChannelV3, '__init__',
                            side_effect=AssertionError('channel reached')) as channel3,
                        patch.object(evidence.EvidenceStore, '__init__',
                            side_effect=AssertionError('evidence reached')) as store,
                        patch.object(PhaseApplication, 'run',
                            side_effect=AssertionError('Core reached')) as run):
                    self.assertEqual(entrypoint.run_native_core(launch), 10)
                    prepare.assert_not_called(); channel2.assert_not_called()
                    channel3.assert_not_called(); store.assert_not_called(); run.assert_not_called()
                frame, identity = deliver.call_args.args
                self.assertEqual(identity, 'synthetic-stdio')
                self.assertEqual(set(frame), {'protocol', 'version', 'channel_id',
                    'run_id', 'result', 'exit_code'})
                self.assertEqual((frame['protocol'], frame['version']),
                    ('phase.native.command', '1.0'))
                result = frame['result']
                self.assertEqual(result['error'], 'ntfs.native_profile_not_qualified')
                self.assertEqual(result['command'], 'execute')
                self.assertIs(result['success'], False)
                self.assertIs(result['mutation_attempted'], False)
                self.assertIsNone(result['receipt_digest'])

    def refused_shape(self, request):
        launch = self.launch(request)
        with (patch.object(entrypoint, '_linux_stdio_identity', return_value='synthetic-stdio'),
                patch.object(installation, '_native_registry_for_manifest',
                    side_effect=AssertionError('registry reached')) as registry,
                patch.object(preparation, '_prepare_file_publication',
                    side_effect=AssertionError('preparation reached')) as prepare,
                patch.object(entrypoint, '_deliver_linux_frame') as deliver):
            with self.assertRaisesRegex(PhaseError, 'ntfs.fixed_native_request_required'):
                entrypoint.run_native_core(launch)
            registry.assert_not_called(); prepare.assert_not_called(); deliver.assert_not_called()

    def test_new_request_grammar_rejects_unknown_fields_versions_and_types(self):
        base = self.request()
        for field in base:
            request = deepcopy(base); del request[field]
            with self.subTest(missing=field): self.refused_shape(request)
        for field in ('source_root', 'preparation_root', 'evidence_root',
                'target_root', 'candidate_path', 'registry', 'profile'):
            with self.subTest(extra=field): self.refused_shape(dict(base, **{field: '/synthetic'}))
        for field, value in [('native_file_publication_request_version', '2.0'),
                ('operation', 'plan'), ('operation', 'inspect'),
                ('source_locator', None), ('target_locator', {}),
                ('request_id', 1), ('expected_digest', False)]:
            with self.subTest(field=field, value=value):
                self.refused_shape(dict(base, **{field: value}))

    def test_old_high_level_version_name_is_not_a_native_request_discriminator(self):
        request = self.request()
        request['publication_version'] = request.pop('native_file_publication_request_version')
        self.refused_shape(request)

    def test_host_installation_cannot_enter_native_preparation(self):
        with (patch.object(preparation, 'mkdtemp', side_effect=AssertionError('scratch reached')) as scratch,
                patch.object(preparation, 'copy_and_hash', side_effect=AssertionError('source reached')) as capture):
            with self.assertRaisesRegex(PhaseError, 'ntfs.closed_native_installation_required'):
                preparation._prepare_file_publication(PhaseApplication(),
                    source_locator='synthetic.bin', target_locator='output.bin',
                    request_id='synthetic-request', expected_digest=None)
            scratch.assert_not_called(); capture.assert_not_called()
