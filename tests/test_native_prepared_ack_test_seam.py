"""Portable ACK relay component models, not Windows/native acceptance.

The accepted-launch shells below contain data only. They never construct a
NativeIO, process, pipe or installation; runtime identity is an explicit modeled
boundary. Source213 must preserve these sources before their first execution.
"""
import ast
import os
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch,_is_bundle_recovery_launch
from phase_tool.mutation.ntfs.bundle_execution import _BUNDLE2_CONTRACT_V2
from phase_tool.mutation.ntfs.bundle_prepared import prepared_message,prepared_ack,validate_prepared_ack
from phase_tool.mutation.ntfs.entrypoint import run_native_parent
from phase_tool.mutation.ntfs.experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
from phase_tool.mutation.ntfs.parent import _FailFirstPreparedAck,_NativeWindowsParent
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract
from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames
from .test_native_bundle2_prepared import b2_projection,native_stage
from .test_native_bundle_protocol import CHANNEL
from ._native_startup_shell import legacy_config_bytes


def launch_shell():
    """Exact-class data shell for early role checks, never accepted startup."""
    project=replace(b2_projection(),contract_bytes=canonical_bytes(_BUNDLE2_CONTRACT_V2))
    context=parse_json_bytes(project.context_bytes)
    launch=object.__new__(_NativeAcceptedLaunch)
    launch._config_bytes=legacy_config_bytes('1.2')
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


class PreparedAckRefusalOwnerTests(unittest.TestCase):
    """Exact token and parent selector with borrowed pipe I/O modeled."""

    def refusal_owner(self):
        launch, project = launch_shell()
        contract = semantic_owner_contract('Bundle2')
        project = replace(project, contract_bytes=canonical_bytes(contract))
        launch._config_bytes = canonical_bytes({'native_launch_version': '3.0'})
        launch._manifest_bytes = canonical_bytes(dict(launch.manifest, contract=contract))
        launch._worker = SimpleNamespace(stdin=object(), stdout=object())
        token = _FailFirstPreparedAck(launch, _refuse_ack=True)
        owner = relay_shell(launch, token)
        owner._worker = launch._worker
        owner._go_attempted = owner._bundle_ack_relay_entered = True
        owner._file2_exchange_deadline = time.perf_counter_ns() + 29_000_000_000
        pipe = object.__new__(WindowsPipeFrames)
        pipe._streams = launch._worker.stdout, launch._worker.stdin
        pipe._gate = threading.Lock()
        pipe._owner = os.getpid(), threading.get_ident()
        pipe._failed = pipe._sealed = False
        pipe._last_frame_failure = None
        pipe._identities = ((4, 5), (6, 7))
        pipe._pipe = lambda side: pipe._identities[side]

        def record(data, deadline, progress):
            progress['wire_bytes'] = len(data)

        pipe._write = Mock(side_effect=record)
        return owner, token, pipe, *checkpoint(project)

    def test_direct_token_produces_inert_data_and_cannot_send_or_rearm(self):
        owner, token, pipe, message, raw = self.refusal_owner()
        self.assertFalse(hasattr(token, 'send_refusal'))
        body, details = token.refusal_frame(owner._launch, message, raw)
        self.assertIsInstance(body, bytes)
        self.assertEqual(details['refusal_frame_digest'], digest_bytes(body))
        self.assertIs(details['valid_ack_send_attempted'], False)
        with self.assertRaisesRegex(PhaseError, 'ntfs.prepared_ack_test_consumed'):
            owner._relay_prepared_ack(pipe, message, raw, owner._file2_exchange_deadline)
        pipe._write.assert_not_called()

    def test_only_current_owner_sends_one_refused_frame_on_original_deadline(self):
        owner, token, pipe, message, raw = self.refusal_owner()
        deadline = owner._file2_exchange_deadline
        with self.assertRaisesRegex(PhaseError, 'ntfs.test_prepared_ack_refusal_frame_sent') as caught:
            owner._relay_prepared_ack(pipe, message, raw, deadline)
        pipe._write.assert_called_once()
        wire, actual_deadline, progress = pipe._write.call_args.args
        body = wire[9:-1]
        self.assertEqual(wire, f'{len(body):08x}\n'.encode('ascii') + body + b'\n')
        self.assertEqual((actual_deadline, progress['wire_bytes']), (deadline, len(wire)))
        before, after = parse_json_bytes(raw), parse_json_bytes(body)
        changed = after.pop('prepared_message_digest')
        self.assertNotEqual(changed, before.pop('prepared_message_digest'))
        self.assertEqual(after, before)
        with self.assertRaisesRegex(PhaseError, 'ntfs.bundle_prepared_ack_binding_mismatch'):
            validate_prepared_ack(body, message=message)
        self.assertEqual(caught.exception.details['ack_digest'], digest_bytes(raw))
        self.assertEqual(caught.exception.details['refusal_frame_digest'], digest_bytes(body))
        self.assertEqual(caught.exception.details['wire_bytes'], len(wire))
        self.assertIs(caught.exception.details['valid_ack_send_attempted'], False)
        self.assertIs(token._consumed, True)
        with self.assertRaisesRegex(PhaseError, 'ntfs.prepared_ack_test_consumed'):
            owner._relay_prepared_ack(pipe, message, raw, deadline)
        pipe._write.assert_called_once()

    def test_refuses_unreached_or_foreign_parent_and_preserves_unused_token(self):
        for boundary in ('go', 'prepared', 'process', 'stdin', 'stdout', 'pipe', 'deadline'):
            with self.subTest(boundary=boundary):
                owner, token, pipe, message, raw = self.refusal_owner()
                actual_pipe, deadline = pipe, owner._file2_exchange_deadline
                if boundary == 'go':
                    owner._go_attempted = False
                elif boundary == 'prepared':
                    owner._bundle_ack_relay_entered = False
                elif boundary == 'process':
                    owner._worker = SimpleNamespace(stdin=pipe._streams[1], stdout=pipe._streams[0])
                elif boundary == 'stdin':
                    pipe._streams = pipe._streams[0], object()
                elif boundary == 'stdout':
                    pipe._streams = object(), pipe._streams[1]
                elif boundary == 'pipe':
                    actual_pipe = Mock()
                else:
                    deadline += 1
                with self.assertRaisesRegex(PhaseError, 'ntfs.prepared_ack_test_role_required'):
                    owner._relay_prepared_ack(actual_pipe, message, raw, deadline)
                self.assertIs(token._consumed, False)
                pipe._write.assert_not_called()
                if boundary == 'pipe':
                    actual_pipe.send_frame.assert_not_called()
        legacy, _ = launch_shell()
        with self.assertRaisesRegex(PhaseError, 'ntfs.prepared_ack_test_role_required'):
            _FailFirstPreparedAck(legacy, _refuse_ack=True)
        legacy.spawn_core.assert_not_called()

    def test_exact_expired_deadline_or_partial_transport_consumes_without_second_send(self):
        for boundary in ('expired', 'partial'):
            with self.subTest(boundary=boundary):
                owner, token, pipe, message, raw = self.refusal_owner()
                deadline = owner._file2_exchange_deadline
                expected = 0 if boundary == 'expired' else 19

                def fail_after_prefix(data, sent_deadline, progress):
                    self.assertEqual(sent_deadline, deadline)
                    progress['wire_bytes'] = expected
                    raise OSError('modeled pipe failure')

                pipe._write.side_effect = fail_after_prefix
                now = deadline if boundary == 'expired' else deadline - 1
                with patch('phase_tool.mutation.ntfs.windows_pipe.time.perf_counter_ns', return_value=now):
                    with self.assertRaisesRegex(PhaseError, 'ntfs.test_prepared_ack_refusal_unproven') as caught:
                        owner._relay_prepared_ack(pipe, message, raw, deadline)
                self.assertEqual(caught.exception.details['transport']['details']['progress']['wire_bytes'], expected)
                self.assertIs(caught.exception.details['valid_ack_send_attempted'], False)
                self.assertIs(token._consumed, True)
                with self.assertRaisesRegex(PhaseError, 'ntfs.prepared_ack_test_consumed'):
                    owner._relay_prepared_ack(pipe, message, raw, deadline)
                self.assertEqual(pipe._write.call_count, int(boundary == 'partial'))


class NativeRecoveryDispatchSelectionComponentTests(unittest.TestCase):
    def test_foreign_launch_never_reads_manifest_even_with_real_context_type(self):
        class ForeignLaunch:
            _experimental_admission_context=_ExperimentalBundle2AdmissionV3(b'{}')
            @property
            def manifest(self):raise AssertionError('foreign manifest must not be read')
        self.assertIs(_is_bundle_recovery_launch(ForeignLaunch()),False)

    def test_legacy_exact_launch_without_new_context_never_reads_manifest(self):
        launch=object.__new__(_NativeAcceptedLaunch)  # No manifest field on purpose.
        launch._config_bytes=legacy_config_bytes('1.2')
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
        launch._config_bytes=legacy_config_bytes('1.2')
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




class NativeMCPSDKLauncherComponentTests(unittest.TestCase):
    """Real fixture code; DLL/loader/OS boundaries are explicit portable models."""
    def _model(self):
        import ctypes
        import hashlib
        import importlib.machinery
        import importlib.util
        import sys
        import tempfile
        from contextlib import contextmanager
        from types import ModuleType,SimpleNamespace
        from unittest.mock import patch
        @contextmanager
        def model():
            fixture=Path(__file__).resolve().parent/'fixtures/native_phase_mcp_sdk_test_launcher_v2.py.in'
            tree=ast.parse(fixture.read_bytes())
            function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='fixed_windows_mcp_sdk_bootstrap')
            with tempfile.TemporaryDirectory(prefix='phase-sdk-bootstrap-component-')as directory:
                root=Path(directory)/'ntfs-bundle2-mcp218';sdk=root/'windows-sdk/site-packages'
                launcher=root/'artifacts/windows/launcher.py';launcher.parent.mkdir(parents=True)
                launcher.write_bytes(fixture.read_bytes())
                bodies={'win32/_win32sysloader.pyd':b'component-loader-not-a-native-binary',
                    'pywin32_system32/pywintypes312.dll':b'component-dll-not-a-native-binary'}
                files={}
                for name,body in bodies.items():
                    path=sdk/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
                    files[name]={'bytes':len(body),'sha256':digest_bytes(body)}
                manifest={'root':str(sdk),'platform':'win_amd64','python_version':'3.12.10',
                    'versions':{'pywin32':'312'},'files':files}
                manifest_raw=canonical_bytes(manifest);(root/'WINDOWS_SDK_MANIFEST_v1.json').write_bytes(manifest_raw)
                config={'dependency_file_digests':{str(sdk/name):row['sha256']for name,row in files.items()},
                    'artifact_graph':{'windows':{'runtime_manifest_digest':digest_bytes(manifest_raw)}}}
                config_raw=canonical_bytes(config);roots=[str(sdk),str(sdk/'win32'),str(sdk/'win32/lib')]
                outer={'config_digest':digest_bytes(config_raw),'dependency_roots':roots}
                cookie=object();library=object();add_directory=Mock(return_value=cookie)
                native_library=Mock(return_value=library)
                loader=ModuleType('_win32sysloader');loader.__spec__=SimpleNamespace(origin=str(sdk/'win32/_win32sysloader.pyd'))
                loader.GetModuleFilename=Mock(side_effect=[None,str(sdk/'pywin32_system32/pywintypes312.dll')])
                spec=importlib.util.spec_from_file_location('_win32sysloader',sdk/'win32/_win32sysloader.pyd',
                    loader=importlib.machinery.ExtensionFileLoader('_win32sysloader',str(sdk/'win32/_win32sysloader.pyd')))
                def need(ok):
                    if not ok:raise RuntimeError('component SDK bootstrap refusal')
                modeled_sys=SimpleNamespace(version_info=(3,12,10),path=roots,
                    meta_path=[importlib.machinery.BuiltinImporter,importlib.machinery.FrozenImporter,importlib.machinery.PathFinder],modules={})
                namespace={'__file__':str(launcher),'Path':Path,'need':need,'json':__import__('json'),
                    'hashlib':hashlib,'os':SimpleNamespace(name='nt',add_dll_directory=add_directory),'sys':modeled_sys}
                exec(compile(ast.Module(body=[function],type_ignores=[]),str(fixture),'exec'),namespace)
                # Even a guard regression reaches only these sentinels, never a DLL.
                with (patch.dict(sys.modules,{'_win32sysloader':loader}),
                        patch.object(importlib.util,'find_spec',return_value=spec),
                        patch.object(ctypes,'WinDLL',native_library,create=True)):
                    yield SimpleNamespace(call=lambda:namespace['fixed_windows_mcp_sdk_bootstrap'](outer,config_raw),
                        sdk=sdk,outer=outer,sys=modeled_sys,loader=loader,add_directory=add_directory,
                        native_library=native_library,cookie=cookie,library=library,namespace=namespace)
        return model()

    def test_exact_sdk_fixture_preserves_startup_roles_and_single_ack_fault(self):
        root=Path(__file__).resolve().parent/'fixtures'
        before=ast.parse((root/'native_phase_prepared_ack_test_launcher_v1.py.in').read_bytes())
        after=ast.parse((root/'native_phase_mcp_sdk_test_launcher_v2.py.in').read_bytes())
        old={n.name:n for n in before.body if isinstance(n,ast.FunctionDef)}
        new={n.name:n for n in after.body if isinstance(n,ast.FunctionDef)}
        self.assertEqual(set(new),set(old)|{'fixed_windows_mcp_sdk_bootstrap'})
        for name in old.keys()-{'main'}:self.assertEqual(ast.dump(old[name]),ast.dump(new[name]),name)
        main=new['main'];branch=next(n for n in main.body if isinstance(n,ast.If)
            and isinstance(n.test,ast.Compare)and isinstance(n.test.left,ast.Name)
            and n.test.left.id=='role'and isinstance(n.test.comparators[0],ast.Constant)
            and n.test.comparators[0].value=='recovery-mcp')
        bootstrap=branch.body[0]
        self.assertIsInstance(bootstrap,ast.Assign)
        self.assertEqual(bootstrap.value.func.id,'fixed_windows_mcp_sdk_bootstrap')
        self.assertIsInstance(branch.body[1],ast.ImportFrom)
        self.assertEqual(branch.body[1].module,'phase_tool.mutation.ntfs.bundle_recovery_mcp')
        branch.body.pop(0)
        self.assertEqual(ast.dump(old['main']),ast.dump(main))

    def test_pinned_dll_bootstrap_retains_exact_process_local_owners(self):
        with self._model()as model:
            self.assertEqual(model.call(),(model.cookie,model.library))
            model.add_directory.assert_called_once_with(str(model.sdk/'pywin32_system32'))
            model.native_library.assert_called_once_with(str(model.sdk/'pywin32_system32/pywintypes312.dll'),
                winmode=0x00000100|0x00000200|0x00000800)
            self.assertEqual(model.namespace['_MCP_SDK_DLL_OWNERS'],[model.cookie,model.library])
            self.assertNotIn('pywin32_system32',model.sys.modules)
            self.assertNotIn('pywin32_bootstrap',model.sys.modules)

    def test_modified_sdk_leaf_refuses_before_any_dll_or_directory_registration(self):
        with self._model()as model:
            (model.sdk/'pywin32_system32/pywintypes312.dll').write_bytes(b'foreign')
            with self.assertRaises(RuntimeError):model.call()
            model.add_directory.assert_not_called();model.native_library.assert_not_called()

    def test_foreign_already_loaded_dll_refuses_before_loading_or_registration(self):
        with self._model()as model:
            model.loader.GetModuleFilename.side_effect=None
            model.loader.GetModuleFilename.return_value=str(model.sdk/'foreign/pywintypes312.dll')
            with self.assertRaises(RuntimeError):model.call()
            model.add_directory.assert_not_called();model.native_library.assert_not_called()

    def test_namespace_preload_or_foreign_roots_never_become_an_origin_waiver(self):
        for name in ('pywin32_system32','pywin32_bootstrap','foreign_roots'):
            with self.subTest(name=name),self._model()as model:
                if name=='foreign_roots':model.outer['dependency_roots']=[str(model.sdk/'outside')]
                else:model.sys.modules[name]=object()
                with self.assertRaises(RuntimeError):model.call()
                model.add_directory.assert_not_called();model.native_library.assert_not_called()


if __name__=='__main__':unittest.main()
