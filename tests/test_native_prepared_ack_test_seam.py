"""Portable ACK relay component models, not Windows/native acceptance.

The accepted-launch shells below contain data only. They never construct a
NativeIO, process, pipe or installation; runtime identity is an explicit modeled
boundary. Source213 must preserve these sources before their first execution.
"""
import ast
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import Mock

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch,_is_bundle_recovery_launch
from phase_tool.mutation.ntfs.bundle_execution import _BUNDLE2_CONTRACT_V2
from phase_tool.mutation.ntfs.bundle_prepared import prepared_message,prepared_ack
from phase_tool.mutation.ntfs.entrypoint import run_native_parent
from phase_tool.mutation.ntfs.experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
from phase_tool.mutation.ntfs.parent import _FailFirstPreparedAck,_NativeWindowsParent
from .test_native_bundle2_prepared import b2_projection,native_stage
from .test_native_bundle_protocol import CHANNEL


def launch_shell():
    """Exact-class data shell for early role checks, never accepted startup."""
    project=replace(b2_projection(),contract_bytes=canonical_bytes(_BUNDLE2_CONTRACT_V2))
    context=parse_json_bytes(project.context_bytes)
    launch=object.__new__(_NativeAcceptedLaunch)
    launch._manifest_bytes=canonical_bytes({'native_read_installation_version':'1.9',
        'contract':_BUNDLE2_CONTRACT_V2})
    launch._invocation_bytes=canonical_bytes({'run_id':context['run_id'],'channel_id':CHANNEL,
        'operation_nonce':context['operation_nonce'],'request':{'operation':'execute'}})
    launch._inspection_only=False
    launch._experimental_admission_context=_ExperimentalBundle2AdmissionV3(b'{}')
    launch.check_runtime=Mock()  # Modeled code-identity boundary; no native/host I/O.
    launch.spawn_core=Mock(side_effect=AssertionError('portable test must not spawn Core'))
    launch.spawn_inspection=Mock(side_effect=AssertionError('portable test must not spawn inspection'))
    return launch,project


def relay_shell(launch,token=None):
    owner=object.__new__(_NativeWindowsParent)
    owner._launch=launch
    if token is not None:owner._prepared_ack_test=token
    return owner


def checkpoint(project):
    message=prepared_message(project,CHANNEL,123,native_stage(project))
    ack=canonical_bytes(prepared_ack(message,'sha256:'+'8'*64,'sha256:'+'9'*64))
    return message,ack


class PreparedAckTestSeamComponentTests(unittest.TestCase):
    def test_invalid_ack_is_rejected_before_test_fault_is_consumed(self):
        launch,project=launch_shell();token=_FailFirstPreparedAck(launch)
        owner=relay_shell(launch,token);pipe=Mock();message,raw=checkpoint(project)
        bad=parse_json_bytes(raw);bad['channel_id']='b'*32
        with self.assertRaises(PhaseError) as caught:
            owner._relay_prepared_ack(pipe,message,canonical_bytes(bad),12345)
        self.assertEqual(caught.exception.code,'ntfs.bundle_prepared_ack_binding_mismatch')
        self.assertIs(token._consumed,False)
        pipe.send_frame.assert_not_called()

    def test_validated_ack_fault_retains_context_digest_and_zero_sent_bytes(self):
        launch,project=launch_shell();token=_FailFirstPreparedAck(launch)
        owner=relay_shell(launch,token);pipe=Mock();message,raw=checkpoint(project)
        with self.assertRaises(PhaseError) as caught:
            owner._relay_prepared_ack(pipe,message,raw,12345)
        self.assertEqual(caught.exception.code,'ntfs.test_prepared_ack_delivery_failed')
        self.assertEqual(caught.exception.details,{'test_fault_version':'1.0',
            'fault':'fail_first_prepared_ack','context':message['context'],'channel_id':CHANNEL,
            'prepared_message_digest':digest_bytes(canonical_bytes(message)),
            'ack_digest':digest_bytes(raw),'bytes_sent':0,
            'ack_send_attempted':False,'fault_consumed':True})
        self.assertIs(token._consumed,True)
        pipe.send_frame.assert_not_called()
        launch.spawn_core.assert_not_called()
        launch.spawn_inspection.assert_not_called()

    def test_second_ack_attempt_refuses_without_sending_or_rearming(self):
        launch,project=launch_shell();token=_FailFirstPreparedAck(launch)
        owner=relay_shell(launch,token);pipe=Mock();message,raw=checkpoint(project)
        with self.assertRaises(PhaseError):owner._relay_prepared_ack(pipe,message,raw,12345)
        with self.assertRaises(PhaseError) as caught:
            owner._relay_prepared_ack(pipe,message,raw,99999)
        self.assertEqual(caught.exception.code,'ntfs.prepared_ack_test_consumed')
        self.assertIs(token._consumed,True)
        pipe.send_frame.assert_not_called()

    def test_default_relay_preserves_exact_ack_and_original_deadline(self):
        launch,project=launch_shell();owner=relay_shell(launch)
        pipe=Mock();message,raw=checkpoint(project);deadline=12345
        owner._relay_prepared_ack(pipe,message,raw,deadline)
        pipe.send_frame.assert_called_once_with(raw,deadline)

    def test_default_relay_still_rejects_invalid_ack_without_sending(self):
        launch,project=launch_shell();owner=relay_shell(launch)
        pipe=Mock();message,raw=checkpoint(project)
        bad=parse_json_bytes(raw);bad['prepared_message_digest']='sha256:'+'a'*64
        with self.assertRaises(PhaseError) as caught:
            owner._relay_prepared_ack(pipe,message,canonical_bytes(bad),12345)
        self.assertEqual(caught.exception.code,'ntfs.bundle_prepared_ack_binding_mismatch')
        pipe.send_frame.assert_not_called()

    def test_only_exact_experimental_1_9_original_execute_role_can_construct_fault(self):
        for kind in ('inspect','inspect_request','recover','plan','old_generation','foreign_contract','ordinary_admission','nonbundle'):
            launch,project=launch_shell()
            if kind=='inspect':launch._inspection_only=True
            elif kind in {'inspect_request','recover','plan'}:
                request=launch.invocation
                request['request']['operation']=('recover_publication' if kind=='recover' else
                    'inspect' if kind=='inspect_request' else 'plan')
                launch._invocation_bytes=canonical_bytes(request)
            elif kind in {'old_generation','foreign_contract'}:
                manifest=launch.manifest
                if kind=='old_generation':manifest['native_read_installation_version']='1.8'
                else:manifest['contract']=dict(_BUNDLE2_CONTRACT_V2,version='1.2.0')
                launch._manifest_bytes=canonical_bytes(manifest)
            elif kind=='ordinary_admission':launch._experimental_admission_context=None
            else:
                # A real nonbundle manifest is rejected by the exact generation
                # selector before the later bundle-role predicate is reachable.
                manifest=launch.manifest
                manifest['contract']=dict(_BUNDLE2_CONTRACT_V2,id='file_create.v2')
                launch._manifest_bytes=canonical_bytes(manifest)
                self.assertIs(launch._bundle,False)
            with self.subTest(role=kind),self.assertRaises(PhaseError) as caught:
                _FailFirstPreparedAck(launch)
            expected=('ntfs.experimental_admission_required' if kind in {'old_generation','foreign_contract','nonbundle'}
                else 'ntfs.prepared_ack_test_role_required')
            self.assertEqual(caught.exception.code,expected)
            launch.spawn_core.assert_not_called();launch.spawn_inspection.assert_not_called()

    def test_foreign_token_is_rejected_before_any_core_or_worker_spawn(self):
        launch,project=launch_shell()
        with self.assertRaises(PhaseError) as caught:
            run_native_parent(launch,_prepared_ack_test=Mock())
        self.assertEqual(caught.exception.code,'ntfs.prepared_ack_test_role_required')
        launch.check_runtime.assert_not_called()
        launch.spawn_core.assert_not_called();launch.spawn_inspection.assert_not_called()

    def test_token_cannot_be_reused_with_another_launch_or_recovery_request(self):
        launch,project=launch_shell();token=_FailFirstPreparedAck(launch)
        other,_=launch_shell()
        with self.assertRaises(PhaseError) as caught:
            run_native_parent(other,_prepared_ack_test=token)
        self.assertEqual(caught.exception.code,'ntfs.prepared_ack_test_role_required')
        other.spawn_core.assert_not_called();other.spawn_inspection.assert_not_called()
        invocation=launch.invocation;invocation['request']['operation']='recover_publication'
        launch._invocation_bytes=canonical_bytes(invocation)
        with self.assertRaises(PhaseError) as caught:
            run_native_parent(launch,_prepared_ack_test=token)
        self.assertEqual(caught.exception.code,'ntfs.prepared_ack_test_role_required')
        launch.spawn_core.assert_not_called();launch.spawn_inspection.assert_not_called()
        pipe=Mock();message,raw=checkpoint(project)
        with self.assertRaises(PhaseError) as caught:
            relay_shell(launch,token)._relay_prepared_ack(pipe,message,raw,12345)
        self.assertEqual(caught.exception.code,'ntfs.prepared_ack_test_role_required')
        self.assertIs(token._consumed,False);pipe.send_frame.assert_not_called()

    def test_subclasses_do_not_supply_a_callback_or_alternate_fault(self):
        launch,project=launch_shell()
        class ForeignFault(_FailFirstPreparedAck):pass
        with self.assertRaises(PhaseError) as caught:ForeignFault(launch)
        self.assertEqual(caught.exception.code,'ntfs.prepared_ack_test_role_required')
        launch.check_runtime.assert_not_called()

    def test_fixture_keeps_startup_and_actual_role_set_without_argv_normalization(self):
        root=Path(__file__).resolve().parents[1]
        ordinary=ast.parse((root/'src/phase_tool/data/native/native_phase_launcher_v4.py.in').read_bytes())
        fixture=ast.parse((root/'tests/fixtures/native_phase_prepared_ack_test_launcher_v1.py.in').read_bytes())
        normal={n.name:n for n in ordinary.body if isinstance(n,ast.FunctionDef)}
        test={n.name:n for n in fixture.body if isinstance(n,ast.FunctionDef)}
        self.assertEqual(set(normal),set(test))
        for name in normal.keys()-{'main'}:
            self.assertEqual(ast.dump(normal[name]),ast.dump(test[name]),name)
        # The original exact argv/OS-role checks precede any installation load.
        self.assertEqual([ast.dump(n) for n in normal['main'].body[:4]],
            [ast.dump(n) for n in test['main'].body[:4]])
        calls=[n for n in ast.walk(test['main']) if isinstance(n,ast.Call)
            and any(k.arg=='_prepared_ack_test' for k in n.keywords)]
        self.assertEqual(len(calls),1)
        self.assertFalse(any(isinstance(n,ast.Call) and any(k.arg=='_prepared_ack_test' for k in n.keywords)
            for n in ast.walk(normal['main'])))
        startup_check=next(n.lineno for n in ast.walk(test['main']) if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name)
            and n.func.value.id=='launch' and n.func.attr=='check_runtime')
        self.assertLess(startup_check,calls[0].lineno)


class NativeRecoveryDispatchSelectionComponentTests(unittest.TestCase):
    def test_foreign_launch_never_reads_manifest_even_with_real_context_type(self):
        class ForeignLaunch:
            _experimental_admission_context=_ExperimentalBundle2AdmissionV3(b'{}')
            @property
            def manifest(self):raise AssertionError('foreign manifest must not be read')
        self.assertIs(_is_bundle_recovery_launch(ForeignLaunch()),False)

    def test_legacy_exact_launch_without_new_context_never_reads_manifest(self):
        launch=object.__new__(_NativeAcceptedLaunch)  # No manifest field on purpose.
        self.assertIs(_is_bundle_recovery_launch(launch),False)
        launch._experimental_admission_context={'manifest_version':'1.9'}
        self.assertIs(_is_bundle_recovery_launch(launch),False)

    def test_subclass_launch_or_admission_cannot_select_successor_dispatch(self):
        class ForeignLaunch(_NativeAcceptedLaunch):pass
        launch=object.__new__(ForeignLaunch)
        launch._experimental_admission_context=_ExperimentalBundle2AdmissionV3(b'{}')
        self.assertIs(_is_bundle_recovery_launch(launch),False)
        class ForeignAdmission(_ExperimentalBundle2AdmissionV3):pass
        launch=object.__new__(_NativeAcceptedLaunch)
        launch._experimental_admission_context=ForeignAdmission(b'{}')
        self.assertIs(_is_bundle_recovery_launch(launch),False)

    def test_exact_successor_still_requires_real_generation_and_contract(self):
        for field in ('native_read_installation_version','contract'):
            launch,project=launch_shell();manifest=launch.manifest
            manifest[field]='1.8' if field=='native_read_installation_version' else {'id':'foreign'}
            launch._manifest_bytes=canonical_bytes(manifest)
            with self.subTest(field=field),self.assertRaises(PhaseError) as caught:
                _is_bundle_recovery_launch(launch)
            self.assertEqual(caught.exception.code,'ntfs.experimental_admission_required')
            launch.check_runtime.assert_not_called()

    def test_exact_successor_selection_is_not_runtime_or_qualification_acceptance(self):
        launch,project=launch_shell()
        self.assertIs(_is_bundle_recovery_launch(launch),True)
        launch.check_runtime.assert_not_called()
        launch.spawn_core.assert_not_called();launch.spawn_inspection.assert_not_called()

    def test_host_and_fixed_native_mcp_keep_separate_single_result_models(self):
        root=Path(__file__).resolve().parents[1]
        host=ast.parse((root/'src/phase_tool/mcp_server.py').read_bytes())
        native=ast.parse((root/'src/phase_tool/mutation/ntfs/bundle_recovery_mcp.py').read_bytes())
        host_fn=next(n for n in host.body if isinstance(n,ast.FunctionDef)and n.name=='phase_recover_publication')
        native_fn=next(n for n in ast.walk(native)if isinstance(n,ast.FunctionDef)and n.name=='recover')
        self.assertIsInstance(host_fn.returns,ast.Name)
        self.assertEqual(host_fn.returns.id,'RecoveryResult')
        self.assertIsInstance(native_fn.returns,ast.Name)
        self.assertEqual(native_fn.returns.id,'NativeRecoveryResult')


if __name__=='__main__':unittest.main()
