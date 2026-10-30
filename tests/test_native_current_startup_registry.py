"""Fixed current generation selection, negative components only.

Accepted-launch shells isolate the refusal branch; they do not establish G01.
The actual qualification guard stays unmocked. No positive native operation,
channel, target/evidence I/O or receipt is authorized by these tests.
"""
from types import SimpleNamespace
import unittest
from ._native_startup_shell import startup_shell
from unittest.mock import Mock, patch

from phase_tool import command_result, evidence, installation
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.command_result import validate_command_result
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_inspection_file_create_registry
from phase_tool.mutation.ntfs import entrypoint, original_endpoint
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2


class NativeCurrentStartupRegistryTests(unittest.TestCase):
    def test_core_refuses_with_current_registry_before_channel_evidence_or_application(self):
        launch=SimpleNamespace(_inspection_only=False,check_runtime=Mock(),
            invocation={'request':{'operation':'execute','candidate_path':'/synthetic/unused.json',
                'input_paths':{},'expected_inputs':None,'maximum_candidate_bytes':1024**2}},
            _manifest_bytes=startup_shell()[0],installation_digest=startup_shell()[1],run_id='synthetic-unqualified',
            operation_nonce='a'*32,channel_id='b'*32)
        with (patch.object(installation,'_native_inspection_file_create_registry',
                    wraps=_native_inspection_file_create_registry) as selected,
                patch.object(installation,'_native_connected_file_create_registry',
                    side_effect=AssertionError('historical generation selected')) as old,
                patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-stdio'),
                patch.object(entrypoint,'_deliver_linux_frame') as deliver,
                patch.object(command_result,'validate_command_result',wraps=validate_command_result) as validate,
                patch.object(LinuxNativeChannelV2,'__init__',side_effect=AssertionError('channel reached')) as channel,
                patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('store reached')) as store,
                patch.object(PhaseApplication,'run',side_effect=AssertionError('application reached')) as app):
            self.assertEqual(entrypoint.run_native_core(launch),10)
            self.assertEqual(selected.call_count,3)
            old.assert_not_called();channel.assert_not_called();store.assert_not_called();app.assert_not_called()
            validate.assert_called_once()
            self.assertEqual(validate.call_args.args[1].digest,
                'sha256:2af8bac33feb42a583a14d6bff7b403de2ab0b63be3a962acc45807634a6ecca')
            deliver.assert_called_once()
        frame,identity=deliver.call_args.args
        self.assertEqual(identity,'synthetic-stdio')
        self.assertEqual(frame['result']['error'],'ntfs.native_profile_not_qualified')
        self.assertIs(frame['result']['success'],False)
        self.assertIs(frame['result']['mutation_attempted'],False)
        self.assertIsNone(frame['result']['receipt_digest'])

    def original_shell(self):
        launch=object.__new__(_NativeAcceptedLaunch)
        launch._invocation_bytes=canonical_bytes({'run_id':'synthetic-original','channel_id':'b'*32,
            'operation_nonce':'a'*32,'request':{}})
        launch._manifest_bytes,launch._manifest_digest=startup_shell()
        query={'native_original_query_version':'1.0','action':'verify_no_dispatch',
            'run_id':'synthetic-original','intent_digest':None,'operation_nonce':'a'*32,
            'installation_digest':launch._manifest_digest,'channel_id':'b'*32}
        return launch,query

    def test_original_endpoint_both_actions_refuse_current_unqualified_before_manifest_or_read(self):
        launch,query=self.original_shell()
        for action,digest in [('verify_no_dispatch',None),('read_executing','sha256:'+'d'*64)]:
            with self.subTest(action=action):
                query=dict(query,action=action,intent_digest=digest)
                with (patch.object(_NativeAcceptedLaunch,'check_runtime'),
                        patch.object(installation,'_native_registry_for_manifest',
                            wraps=installation._native_registry_for_manifest) as selected,
                        patch.object(installation,'_resolve_native_file_create_read_binding',
                            side_effect=AssertionError('manifest reached')) as binding,
                        patch.object(evidence,'_confirm_native_original_absent',
                            side_effect=AssertionError('evidence read reached')) as absent):
                    with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                        original_endpoint.native_original_query(launch,query)
                    selected.assert_called_once_with(*startup_shell());binding.assert_not_called();absent.assert_not_called()

    def test_original_endpoint_bad_query_refuses_before_current_registry(self):
        launch,query=self.original_shell()
        query['registry']='synthetic-untrusted-selection'
        with (patch.object(_NativeAcceptedLaunch,'check_runtime'),
                patch.object(installation,'_native_registry_for_manifest',
                    side_effect=AssertionError('registry reached')) as selected):
            with self.assertRaisesRegex(PhaseError,'ntfs.original_query_binding_mismatch'):
                original_endpoint.native_original_query(launch,query)
            selected.assert_not_called()

    def test_query11_both_actual_profile_guards_refuse_before_reader_or_literal_check(self):
        for version in ('1.1','1.2'):
            registry=(installation._native_inspection_file_create_registry() if version=='1.1'
                else installation._native_lifecycle_registry())
            launch,query=self.original_shell()
            launch._manifest_bytes=canonical_bytes({'native_read_installation_version':version,
                'registry_snapshot_digest':registry.digest,'contract':{'id':'file_create.v1'}})
            launch._manifest_digest=digest_bytes(launch._manifest_bytes)
            query.update(native_original_query_version='1.1',action='read_executing',
                intent_digest='sha256:'+'d'*64,installation_digest=launch._manifest_digest,
                publication_request={'request_id':'synthetic-create','target_locator':'synthetic.txt','expected_digest':None})
            with (self.subTest(version=version),patch.object(_NativeAcceptedLaunch,'check_runtime'),
                    patch.object(installation,'_resolve_native_file_create_read_binding',
                        side_effect=AssertionError('reader binding reached')) as binding,
                    patch.object(original_endpoint,'_require_publication_original',
                        side_effect=AssertionError('literal helper reached')) as literal):
                with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                    original_endpoint.native_original_query(launch,query)
                binding.assert_not_called();literal.assert_not_called()

    def test_query11_version1_role_refuses_before_registry_no_downgrade(self):
        launch,query=self.original_shell()
        launch._manifest_bytes=canonical_bytes({'native_read_installation_version':'1.2',
            'contract':{'id':'publish_new_version.v1'}})
        launch._manifest_digest=digest_bytes(launch._manifest_bytes)
        query.update(native_original_query_version='1.1',action='read_executing',
            intent_digest='sha256:'+'d'*64,installation_digest=launch._manifest_digest,
            publication_request={'request_id':'synthetic-create','target_locator':'synthetic.txt','expected_digest':None})
        with (patch.object(_NativeAcceptedLaunch,'check_runtime'),
                patch.object(installation,'_native_registry_for_manifest',
                    side_effect=AssertionError('registry reached')) as selected):
            with self.assertRaisesRegex(PhaseError,'ntfs.original_query_binding_mismatch'):
                original_endpoint.native_original_query(launch,query)
            selected.assert_not_called()
