"""Read-only branch/protocol components, never positive native admission.

Object shells isolate negative branches without constructing an installation.
Synthetic peer ACKs are protocol data, not receipts or physical proof. Real
pipes and negative MCP transport run only in approved Linux CI.
"""
import asyncio
from copy import deepcopy
from importlib import resources
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from phase_tool import evidence, installation
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import (_native_connected_file_create_registry,
    _native_inspection_file_create_registry, _native_file_create_installation,
    _NativeFileCreateInstallation, _NativeFileCreateReadBinding)
from phase_tool.mutation.ntfs.authority import _NativeFileCreateAuthority
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.mutation.ntfs.parent import _NativeWindowsParent
from phase_tool.mutation.ntfs import entrypoint, inspection_mcp
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers
from .test_native_static_read_binding import manifest_for


class NativeInspectionSelectionTests(unittest.TestCase):
    def test_new_snapshot_appends_one_unqualified_profile_and_preserves_old_snapshots(self):
        old = _native_connected_file_create_registry()
        new = _native_inspection_file_create_registry()
        self.assertEqual(new.to_document()['entries'][:-1], old.to_document()['entries'])
        self.assertEqual(new.to_document()['trust_roots'], old.to_document()['trust_roots'])
        descriptor = new.resolve_guarantee_profile(new.guarantee_profile_bindings()[
            'phase.native.ntfs.candidate.authority.v2@1.0.0'])
        self.assertEqual(descriptor['classification'], 'qualification_candidate')
        self.assertEqual(descriptor['provided_guarantees'], [])
        self.assertEqual(descriptor['conformance'], [])
        self.assertEqual(descriptor['implementation']['version'], '1.1.0')
        raw = resources.files('phase_tool').joinpath('mutation/ntfs/authority.py').read_bytes()
        self.assertEqual(descriptor['implementation']['artifact_digest'], digest_bytes(raw))
        self.assertNotIn('phase.native.ntfs.authority.v1@1.0.0', new.guarantee_profile_bindings())
        for version, sha in [('v1', 'fa2a9aff5f576d15b5a71574a11bd3a7a994a38346540ff6d7e7a74335cfa2c7'),
                ('v2', 'fd7e6f78790491d59f97820fa23132a95cdd89678548e441464cca728605ca2f'),
                ('v3', 'c5fe3be5e03d3be6b390135cb72e52559081c62feccb52e7db0788d8f705088b')]:
            self.assertEqual(digest_bytes(BundledRegistry.resources()[
                'registries/native-file-create-candidate-' + version + '.json']), 'sha256:' + sha)

    def test_read_factory_refuses_before_channel_evidence_and_manifest(self):
        with (patch.object(installation, '_native_inspection_file_create_registry',
                wraps=_native_inspection_file_create_registry) as selected,
                patch.object(LinuxNativeChannelV2, '__init__', side_effect=AssertionError('channel reached')) as channel,
                patch.object(evidence.EvidenceStore, '__init__', side_effect=AssertionError('store reached')) as store,
                patch.object(installation, '_resolve_native_file_create_read_binding',
                    side_effect=AssertionError('manifest reached')) as binding):
            with self.assertRaisesRegex(PhaseError, 'ntfs.native_profile_not_qualified'):
                _native_file_create_installation(manifest_bytes=b'', expected_manifest_digest=None,
                    run_id=None, operation_nonce=None, channel_id=None, _inspection_only=True)
            selected.assert_called_once_with()
            channel.assert_not_called(); store.assert_not_called(); binding.assert_not_called()

    def test_entrypoint_delivers_only_actual_preinstallation_refusal(self):
        launch = SimpleNamespace(_inspection_only=True, check_runtime=Mock(),
            invocation={'request': {'operation': 'inspect'}}, _manifest_bytes=b'',
            installation_digest=None, run_id='synthetic-known-run', operation_nonce='a'*32, channel_id='b'*32)
        with (patch.object(entrypoint, '_linux_stdio_identity', return_value='synthetic-pipes'),
                patch.object(entrypoint, '_deliver_linux_frame') as deliver,
                patch.object(LinuxNativeChannelV2, '__init__', side_effect=AssertionError('channel reached')) as channel):
            self.assertEqual(entrypoint.run_native_inspection(launch), 10)
            channel.assert_not_called(); deliver.assert_called_once()
        frame, identity = deliver.call_args.args
        self.assertEqual(identity, 'synthetic-pipes')
        self.assertEqual(frame['protocol'], 'phase.native.command')
        self.assertEqual(frame['version'], '1.0')
        self.assertFalse(frame['result']['success']); self.assertFalse(frame['result']['mutation_attempted'])
        self.assertEqual(frame['result']['error'], 'ntfs.native_profile_not_qualified')
        self.assertIsNone(frame['result']['receipt_digest'])

    def test_wrong_request_and_wrong_entrypoint_refuse_before_factories_or_stdio(self):
        launch = SimpleNamespace(_inspection_only=True, check_runtime=Mock())
        for call in (lambda: entrypoint.run_native_worker(launch, None, None),
                lambda: entrypoint.run_native_core(launch), lambda: entrypoint.run_native_original(launch)):
            with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_only_operation_forbidden'): call()
        for request in ({'operation': 'execute'}, {'operation': 'inspect', 'root': '/other'}, {}):
            launch.invocation = {'request': request}
            with (patch.object(entrypoint, '_linux_stdio_identity'),
                    patch.object(installation, '_native_file_create_installation') as factory,
                    patch.object(entrypoint, '_deliver_linux_frame') as deliver):
                with self.assertRaisesRegex(PhaseError, 'ntfs.fixed_native_request_required'):
                    entrypoint.run_native_inspection(launch)
                factory.assert_not_called(); deliver.assert_not_called()

    def test_historical_parser_keeps_original_nonce_without_fresh_channel_substitution(self):
        intent, _, _, _, _ = buffers(BundledRegistry.load())
        manifest = manifest_for(intent, '/synthetic/evidence')
        binding = _NativeFileCreateReadBinding(canonical_bytes(manifest), 'sha256:'+'c'*64, BundledRegistry.load())
        original = deepcopy(intent)
        for nonce in ('d'*32, 'e'*32):
            value = deepcopy(intent); value['native_binding']['operation_nonce'] = nonce
            native = parse_json_bytes(binding._parser_bindings(value)['installed_native_binding'])
            self.assertEqual(native['operation_nonce'], nonce)
        self.assertEqual(intent, original); self.assertNotIn('operation_nonce', manifest)


class NativeInspectionBranchTests(unittest.TestCase):
    def shell(self):
        # Never a constructed/admitted installation. Pure branch fixture only.
        value = object.__new__(_NativeFileCreateAuthority); value._inspection_only = True
        return value

    def test_all_mutating_authority_entries_refuse_before_read_or_dispatch(self):
        a = self.shell()
        calls = [lambda: a.native_binding(), lambda: a.implementation_binding(None),
            lambda: a.idempotency(None, None, None, None),
            lambda: a.plan(None, None, None, None, roots=None, run_id=None, timestamp=None, request_digest=None),
            lambda: a.execute(None, None, None, None, None, timestamp=None, receipt_validator=None, expected_intent_digest=None),
            lambda: a.expected_after_identity(None), lambda: a.prepared_physical_proof()]
        with patch.object(a, '_usable', side_effect=AssertionError('unneeded read')) as usable:
            for call in calls:
                with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_only_operation_forbidden'): call()
            usable.assert_not_called()

    def test_read_installation_cannot_enter_core_even_for_validation(self):
        value = object.__new__(_NativeFileCreateInstallation)
        value._admission_attempted = False; value.authority = self.shell()
        with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_only_operation_forbidden'):
            value.admit(None, None, execute=False, faults=None)
        self.assertTrue(value._admission_attempted)
        with self.assertRaisesRegex(PhaseError, 'ntfs.native_installation_consumed'):
            value.admit(None, None, execute=True, faults=None)

    def test_repeated_current_and_historical_observations_do_not_use_execution_slots(self):
        a = self.shell(); intent, _, _, _, _ = buffers(BundledRegistry.load())
        grant = intent['idempotency']['root_identities'][0]
        a._grant_bytes = canonical_bytes(grant); a._run_id = intent['run_id']
        a._observations = {}; a._dispatch_attempted = False
        reply = {'observation_version': '1.0', 'state': {'known': True, 'exists': False,
            'digest': None, 'length': None, 'head_token': None}, 'native': {'exists': False,
            'native_identity': None}, 'grant': grant, 'locator': 'synthetic.txt', 'handles_finalized': True}
        a.channel = SimpleNamespace(observe_file=Mock(return_value=reply))
        with patch.object(a, '_usable'):
            for run in (a._run_id, a._run_id, 'synthetic-prior', a._run_id):
                self.assertEqual(a.observe(run_id=run, root_binding='phase_result_root', locator='synthetic.txt'), reply)
        self.assertEqual(a.channel.observe_file.call_count, 4); self.assertEqual(a._observations, {})

    def seal_shell(self, channel):
        a = self.shell(); a.channel = channel; a._seal_attempted = False; a._sealed = False
        a._channel_sealed = False; a._dispatch_attempted = False
        a._owner = os.getpid(), threading.get_ident()
        return a

    def test_read_seal_only_revokes_channel_without_finish_or_original_query(self):
        c = SimpleNamespace(_usable=Mock(), possible_dispatch=False, seal=Mock(), finish_without_execution=Mock())
        a = self.seal_shell(c); a.seal(intent_digest=None)
        self.assertTrue(a._channel_sealed); self.assertTrue(a._sealed)
        c._usable.assert_called_once_with(); c.seal.assert_called_once_with()
        c.finish_without_execution.assert_not_called()
        with self.assertRaisesRegex(PhaseError, 'ntfs.native_role_seal_consumed'): a.seal(intent_digest=None)

    def test_failed_channel_or_seal_never_claims_read_completion(self):
        for where in ('_usable', 'seal'):
            c = SimpleNamespace(_usable=Mock(), possible_dispatch=False, seal=Mock(), finish_without_execution=Mock())
            getattr(c, where).side_effect = PhaseError('synthetic.read.channel.failed')
            a = self.seal_shell(c)
            with self.assertRaisesRegex(PhaseError, 'synthetic.read.channel.failed'): a.seal(intent_digest=None)
            self.assertFalse(a._channel_sealed); self.assertTrue(a._sealed)
            c.finish_without_execution.assert_not_called()

    def test_launch_rejects_core_worker_and_original_before_any_spawn(self):
        a = object.__new__(_NativeAcceptedLaunch); a._inspection_only = True
        with patch.object(a, '_spawn', side_effect=AssertionError('spawn reached')) as spawn:
            for call in (a.spawn_core, a.spawn_worker, lambda: a.read_original(None), lambda: a.verify_no_dispatch_original(None)):
                with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_only_operation_forbidden'): call()
            spawn.assert_not_called()

    def test_read_spawn_consumes_single_slot_before_fallible_spawn(self):
        a = object.__new__(_NativeAcceptedLaunch); a._inspection_only = True; a._core_spawn_attempted = False
        with (patch.object(a, '_linux_command', return_value=['synthetic-fixed-inspect']) as command,
                patch.object(a, '_spawn', side_effect=PhaseError('synthetic.spawn.failure')) as spawn):
            with self.assertRaisesRegex(PhaseError, 'synthetic.spawn.failure'): a.spawn_inspection()
            with self.assertRaisesRegex(PhaseError, 'ntfs.core_spawn_consumed'): a.spawn_inspection()
            command.assert_called_once_with('inspect'); spawn.assert_called_once_with(['synthetic-fixed-inspect'])


    def test_inspect_primary_survives_secondary_seal_error_and_seal_is_once(self):
        for primary in (RuntimeError('synthetic primary'), KeyboardInterrupt('synthetic primary')):
            application=SimpleNamespace(inspect=Mock(side_effect=primary))
            authority=SimpleNamespace(seal=Mock(side_effect=OSError('synthetic secondary')))
            with self.assertRaises(type(primary)) as caught:
                entrypoint._inspect_with_channel_seal(application,authority,evidence_root=None,
                    run_id='synthetic-read',root_bindings={})
            self.assertIs(caught.exception,primary)
            authority.seal.assert_called_once_with(intent_digest=None)
            self.assertIn('Native inspection channel seal: OSError',primary.__notes__)

    def test_seal_failure_prevents_return_of_even_a_completed_read(self):
        # Pure failing cleanup component, not a native success/admission test.
        application=SimpleNamespace(inspect=Mock(return_value=object()))
        primary=OSError('synthetic seal failed')
        authority=SimpleNamespace(seal=Mock(side_effect=primary))
        with self.assertRaises(OSError) as caught:
            entrypoint._inspect_with_channel_seal(application,authority,evidence_root=None,
                run_id='synthetic-read',root_bindings={})
        self.assertIs(caught.exception,primary);authority.seal.assert_called_once_with(intent_digest=None)



class NativeInspectionParentTests(unittest.TestCase):
    def parent(self, result):
        # Pure delivery shell: no Windows object, filesystem or spawn invoked.
        p = object.__new__(_NativeWindowsParent)
        p._owner = os.getpid(), threading.get_ident(); p._inspection_only = True
        p._consumed = True; p._finished = False; p._failed = False; p._spawn_attempted = False
        p._go_attempted = False; p._worker = None; p._worker_count = 0
        p._no_dispatch_finished = False
        p._launch = SimpleNamespace(channel_id='a'*32, run_id='synthetic-read', check_runtime=Mock())
        frame = {'protocol': 'phase.native.command', 'version': '1.0', 'channel_id': 'a'*32,
            'run_id': 'synthetic-read', 'result': result, 'exit_code': result['exit_code']}
        p._pipe = SimpleNamespace(receive_frame=Mock(return_value=(canonical_bytes(frame), None)), seal=Mock())
        return p

    def test_execute_and_finish_refused_before_original_or_worker(self):
        p = self.parent({'exit_code': 10})
        for kind in ('execute_file_create', 'finish_without_execution'):
            with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_only_operation_forbidden'):
                p._request(canonical_bytes({'kind': kind}))
        with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_only_operation_forbidden'): p._execute(None)

    def test_incomplete_success_bool_exit_and_poisoned_parent_cannot_be_delivered(self):
        incomplete = {'command': 'inspect', 'run_id': 'synthetic-read', 'exit_code': 0, 'success': True}
        for result, failed in [(incomplete, False), (dict(incomplete, exit_code=True), False),
                (PhaseApplication()._failure('inspect', PhaseError('synthetic.refused')).payload, True)]:
            p = self.parent(result); p._failed = failed
            with self.assertRaises(Exception): p.serve()
            self.assertFalse(p._finished); p._pipe.seal.assert_not_called()

    def test_valid_negative_inspect_uses_existing_schema_and_final_frame(self):
        result = PhaseApplication()._failure('inspect', PhaseError('synthetic.refused')).payload
        p = self.parent(result)
        self.assertEqual(p.serve()['result'], result)
        self.assertTrue(p._finished); p._pipe.seal.assert_called_once_with()


class NativeInspectionMCPTests(unittest.TestCase):
    def owner(self):
        return inspection_mcp._InspectionMCPCallOwner(config_bytes=b'', expected_config_digest=None,
            manifest_bytes=b'', expected_manifest_digest=None)

    def test_failed_parent_owner_is_retained_and_subsequent_call_cannot_spawn(self):
        owner = self.owner(); launch = object(); primary = RuntimeError('synthetic unknown finalization')
        with (patch.object(inspection_mcp, '_NativeAcceptedLaunch', return_value=launch) as factory,
                patch.object(inspection_mcp, 'run_native_parent', side_effect=primary) as parent):
            with self.assertRaises(RuntimeError) as caught: owner.inspect('synthetic-read')
            self.assertIs(caught.exception, primary); self.assertIs(owner._held_launch, launch)
            self.assertTrue(owner._unavailable)
            with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_mcp_unavailable'): owner.inspect('synthetic-read')
            self.assertIs(owner._held_launch, launch); factory.assert_called_once(); parent.assert_called_once_with(launch)

    def test_concurrent_call_is_refused_without_queue_or_new_launch(self):
        owner = self.owner(); owner._gate.acquire()
        try:
            with patch.object(inspection_mcp, '_NativeAcceptedLaunch') as factory:
                with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_mcp_call_active'): owner.inspect('synthetic-read')
                factory.assert_not_called()
        finally: owner._gate.release()
        self.assertFalse(owner._unavailable); self.assertIsNone(owner._held_launch)

    def test_real_sdk_stdio_only_run_id_and_unaccepted_startup_refusal(self):
        # Actual SDK transport with deliberately INVALID installation. No native
        # parent/Core is reachable; this is not an accepted native MCP canary.
        async def exchange():
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            import phase_tool
            root = Path(phase_tool.__file__).resolve(strict=True).parent.parent
            code = ("from phase_tool.mutation.ntfs.inspection_mcp import _inspection_server; "
                "_inspection_server(config_bytes=b'',expected_config_digest=None,"
                "manifest_bytes=b'',expected_manifest_digest=None).run(transport='stdio')")
            env = os.environ.copy(); env.update(PYTHONPATH=str(root), PYTHONDONTWRITEBYTECODE='1')
            async with stdio_client(StdioServerParameters(command=sys.executable, args=['-B', '-c', code], env=env)) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize(); tools = (await session.list_tools()).tools
                    self.assertEqual([tool.name for tool in tools], ['phase_inspect'])
                    self.assertEqual(set(tools[0].inputSchema['properties']), {'run_id'})
                    self.assertEqual(tools[0].inputSchema['required'], ['run_id'])
                    invalid = await session.call_tool('phase_inspect', {'run_id': '../other'})
                    self.assertTrue(invalid.isError)
                    refused = await session.call_tool('phase_inspect', {'run_id': 'synthetic-known-run'})
                    self.assertTrue(refused.isError)
                    self.assertIn('ntfs.accepted_launch_binding_required', ' '.join(getattr(c, 'text', '') for c in refused.content))
                    self.assertIsNone(refused.structuredContent)
        asyncio.run(asyncio.wait_for(exchange(), timeout=30))


# Synthetic ACK peer data exercises only real pipes/poisoning; no native grant.
CLIENT = r'''
import hashlib,json,os,sys
from pathlib import Path
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.mutation.ntfs.channel import NativeChannelError
import phase_tool.mutation.ntfs.channel_v2 as source
p=Path(source.__file__).resolve(strict=True)
root=Path(os.environ['PHASE_NATIVE_READ_SOURCE_ROOT']).resolve(strict=True)
if p!=root/'phase_tool/mutation/ntfs/channel_v2.py' or hashlib.sha256(p.read_bytes()).hexdigest()!='14b478ef00a3aa8067dfeae8511e969749704697f36dd8e50be0527fb7c171b3':
 raise RuntimeError('wrong source origin or bytes')
os.set_blocking(0,False);os.set_blocking(1,False)
c=LinuxNativeChannelV2('ab'*16,_inspection_only=True);result={};mode=sys.argv[1]
def observe():return c.observe_file(run_id='synthetic-read',root_binding='phase_result_root',locator='result.bin')
try:
 if mode=='repeat':result['first']=observe();result['second']=observe();c.seal()
 elif mode=='execute':c.execute_file_create(run_id='synthetic-read',intent_digest='sha256:'+'1'*64)
 elif mode=='finish':c.finish_without_execution(run_id='synthetic-read',intent_digest=None,operation_nonce='c'*32,installation_digest='sha256:'+'d'*64)
 elif mode=='reinit':
  try:c.__init__('ab'*16,_inspection_only=False)
  except Exception as e:result['reinit_error']=getattr(e,'code',None)
  c.execute_file_create(run_id='synthetic-read',intent_digest='sha256:'+'1'*64)
 else:observe()
except NativeChannelError as e:
 result['error']=e.code;result['details']=e.details
 try:observe()
 except NativeChannelError:result['retry_refused']=True
result['possible_dispatch']=c.possible_dispatch
sys.stderr.write(json.dumps(result,sort_keys=True))
'''


@unittest.skipUnless(sys.platform.startswith('linux'), 'real Linux pipe component required')
class NativeInspectionChannelTests(unittest.TestCase):
    def answer(self, sequence=1, ok=True):
        return {'protocol': 'phase.native.pipe', 'version': '1.1', 'channel_id': 'ab'*16,
            'sequence': sequence, 'kind': 'observe_file', 'run_id': 'synthetic-read', 'intent_digest': None,
            'ok': ok, 'value': {'synthetic_ack': True} if ok else None,
            'error': None if ok else {'code': 'synthetic.failure', 'message': 'synthetic negative', 'details': {}}}

    def start(self, mode, answers=()):
        import phase_tool
        root = Path(phase_tool.__file__).resolve(strict=True).parent.parent
        env = os.environ.copy(); env.update(PYTHONPATH=str(root), PYTHONDONTWRITEBYTECODE='1', PHASE_NATIVE_READ_SOURCE_ROOT=str(root))
        wire = b''
        for answer in answers:
            raw = canonical_bytes(answer); wire += f'{len(raw):08x}\n'.encode()+raw+b'\n'
        child = subprocess.run([sys.executable, '-B', '-c', CLIENT, mode], input=wire, capture_output=True, env=env, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        result = json.loads(child.stderr); requests = []; pending = child.stdout
        while pending:
            header, pending = pending[:9], pending[9:]; self.assertEqual(header[8:], b'\n')
            length = int(header[:8], 16); raw, pending = pending[:length], pending[length:]
            self.assertEqual(pending[:1], b'\n'); pending = pending[1:]; requests.append(parse_json_bytes(raw))
        return result, requests

    def test_execute_finish_and_reinit_denied_before_any_wire(self):
        for mode in ('execute', 'finish', 'reinit'):
            result, requests = self.start(mode)
            self.assertEqual(requests, []); self.assertFalse(result['possible_dispatch']); self.assertTrue(result['retry_refused'])
            self.assertEqual(result['details']['primary']['code'], 'ntfs.inspection_only_operation_forbidden')
            if mode == 'reinit': self.assertEqual(result['reinit_error'], 'ntfs.channel_initialization_consumed')

    def test_repeated_observation_reuses_existing_wire_and_never_dispatches(self):
        result, requests = self.start('repeat', [self.answer(1), self.answer(2)])
        self.assertEqual([r['kind'] for r in requests], ['observe_file', 'observe_file'])
        self.assertEqual([r['sequence'] for r in requests], [1, 2]); self.assertFalse(result['possible_dispatch'])
        self.assertEqual(result['first'], {'synthetic_ack': True}); self.assertEqual(result['second'], result['first'])

    def test_remote_negative_poisoning_prevents_second_request(self):
        result, requests = self.start('remote', [self.answer(ok=False)])
        self.assertEqual(len(requests), 1); self.assertTrue(result['retry_refused']); self.assertFalse(result['possible_dispatch'])
        self.assertEqual(result['error'], 'ntfs.channel_exchange_unknown')

    def test_lost_response_eof_is_never_read_success(self):
        result, requests = self.start('eof')
        self.assertEqual(len(requests), 1); self.assertNotIn('first', result)
        self.assertTrue(result['retry_refused']); self.assertFalse(result['possible_dispatch'])
