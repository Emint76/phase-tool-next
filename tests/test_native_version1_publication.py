"""Ordinary Linux components and real Host Core; never native qualification.

Native OS/process shells are explicit. The actual native qualification guard
is never patched to produce success. New preparation cannot be positively
executed until admission is qualified. No retry, key rotation or clock repair.
"""
import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from phase_tool import __version__, core, evidence, installation
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.freeze import FrozenInput
from phase_tool.inspection import inspect_run
from phase_tool.mutation.ntfs import entrypoint, inspection_mcp, preparation
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3
from phase_tool.mutation.ntfs.uncertainty import _NativeLifecycleUnresolved


class NativeVersion1PublicationTests(unittest.TestCase):
    def args(self, run='synthetic-version'):
        return {'run_id': run, 'source_locator': 'incoming/synthetic.bin',
            'target_locator': 'documents/item.bin', 'request_id': 'synthetic-version',
            'expected_current_digest': 'sha256:'+'a'*64, 'expected_digest': None}

    def owner(self):
        registry = installation._native_lifecycle_registry()
        # STATIC selector only, no accepted roots/grants/runtime authority.
        raw = canonical_bytes({'native_read_installation_version': '1.2',
            'registry_snapshot_digest': registry.digest,
            'contract': {'id': 'publish_new_version.v1'}})
        return inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',
            expected_config_digest=None, manifest_bytes=raw,
            expected_manifest_digest=digest_bytes(raw))

    def request(self):
        args = self.args()
        return inspection_mcp._version1_publication_request(**{
            k:v for k,v in args.items() if k != 'run_id'})

    def test_candidate_is_exact_existing_version1_semantics_and_archive_collision_refuses(self):
        from phase_tool.contracts.publish_new_version_v1 import archive_locator
        old = self.args()['expected_current_digest']
        candidate, raw = preparation._version1_publication_candidate(
            'synthetic-version', 'documents/item.bin', old)
        self.assertEqual(candidate, {'operation_id':'synthetic-version',
            'idempotency_key':'synthetic-version','target_locator':'documents/item.bin',
            'input_binding':'payload','expected_current_digest':old})
        self.assertEqual(raw, canonical_bytes(candidate))
        with self.assertRaisesRegex(PhaseError, 'publish.target_archive_collision'):
            preparation._version1_publication_candidate('synthetic-version',
                archive_locator(old), old)
        for request_id, target, digest in ((True,'x',old),('Bad','x',old),
                ('a'*129,'x',old),('ok','../outside',old),('ok','nul.txt',old),
                ('ok',True,old),('ok','x',None),('ok','x','sha256:'+'A'*64)):
            with self.subTest(request_id=request_id,target=target,digest=digest):
                with self.assertRaises(PhaseError):
                    preparation._version1_publication_candidate(request_id,target,digest)

    def test_raw_wire_preserves_result_and_fresh_nonces_without_automatic_inspect(self):
        owner = self.owner()
        result = PhaseApplication()._failure('execute', PhaseError('synthetic.refused')).payload
        launches = [object(), object()]
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launches) as factory,
                patch.object(inspection_mcp,'run_native_parent',
                    return_value={'result':result,'exit_code':10}) as parent,
                patch('secrets.token_hex',side_effect=['a'*32,'b'*32,'c'*32,'d'*32])):
            for expected in (None,'sha256:'+'e'*64):
                self.assertIs(owner.execute_version1_publication(**(
                    self.args()|{'expected_digest':expected})), result)
        self.assertEqual(parent.call_count,2)
        self.assertEqual([c.args[0] for c in parent.call_args_list],launches)
        requests = [parse_json_bytes(c.kwargs['invocation_bytes']) for c in factory.call_args_list]
        for call,invocation,expected in zip(factory.call_args_list,requests,
                (None,'sha256:'+'e'*64)):
            self.assertIs(call.kwargs['_inspection_only'],False)
            self.assertEqual(invocation['request'],self.request()|{'expected_digest':expected})
            self.assertEqual(invocation['run_id'],'synthetic-version')
        self.assertEqual([(v['channel_id'],v['operation_nonce'])for v in requests],
            [('a'*32,'b'*32),('c'*32,'d'*32)])
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_invalid_literals_refuse_before_gate_nonce_or_launch(self):
        class Text(str): pass
        owner = self.owner(); owner._gate = SimpleNamespace(acquire=Mock(),release=Mock())
        changes = [{'run_id':'../outside'}, {'source_locator':True},
            {'source_locator':'../outside'}, {'target_locator':'con'},
            {'request_id':Text('synthetic-version')}, {'request_id':'Bad'},
            {'expected_current_digest':None}, {'expected_current_digest':True},
            {'expected_current_digest':'sha256:'+'A'*64}, {'expected_digest':False},
            {'expected_digest':'sha256:'+'F'*64}]
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                patch('secrets.token_hex') as nonce):
            for change in changes:
                with self.subTest(change=change),self.assertRaises(PhaseError):
                    owner.execute_version1_publication(**(self.args()|change))
            with self.assertRaises(TypeError):
                owner.execute_version1_publication(**self.args(),target_root='/outside')
            factory.assert_not_called();nonce.assert_not_called()
        owner._gate.acquire.assert_not_called();owner._gate.release.assert_not_called()
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_same_existing_gate_refuses_without_queue_or_nonce(self):
        owner=self.owner();owner._gate.acquire()
        try:
            with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                    patch('secrets.token_hex') as nonce):
                with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_call_active'):
                    owner.execute_version1_publication(**self.args())
                factory.assert_not_called();nonce.assert_not_called()
        finally: owner._gate.release()

    def test_typed_uncertainty_retains_actual_launch_and_blocks_every_raw_call(self):
        owner=self.owner();launch=object()
        result=_NativeLifecycleUnresolved(request=SimpleNamespace(run_id='synthetic-version'),
            context=SimpleNamespace(intent_recording_started=True,proof_publication_attempted=False,
                publication_attempted=True,common_guard_finalized=False,
                original_intent_digest='sha256:'+'b'*64,
                prepared=SimpleNamespace(effect_plan_digest='sha256:'+'c'*64)),
            authority=SimpleNamespace(channel=SimpleNamespace(possible_dispatch=True)),
            primary=OSError('synthetic unknown worker completion')).command_result('execute')
        raw=canonical_bytes(result)
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch) as factory,
                patch.object(inspection_mcp,'run_native_parent',
                    return_value={'result':result,'exit_code':40}) as parent):
            self.assertIs(owner.execute_version1_publication(**self.args()),result)
            self.assertEqual(canonical_bytes(result),raw)
            self.assertIs(owner._held_launch,launch);self.assertTrue(owner._unavailable)
            for call in (lambda:owner.execute_version1_publication(**self.args()),
                    lambda:owner.execute_file_publication(run_id='synthetic-file',
                        source_locator='x',target_locator='y',request_id='file'),
                    lambda:owner.execute_prepared('synthetic-prepared','x',{}),
                    lambda:owner.inspect('synthetic-version')):
                with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):call()
            self.assertEqual(factory.call_count,1);self.assertEqual(parent.call_count,1)

    def test_post_handoff_error_is_not_recast_as_preparation_refusal(self):
        owner=self.owner();launch=object()
        primary=PhaseError('synthetic.core.delivery.failed')
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch),
                patch.object(inspection_mcp,'run_native_parent',side_effect=primary) as parent):
            with self.assertRaises(PhaseError) as caught:
                owner.execute_version1_publication(**self.args())
            self.assertIs(caught.exception,primary)
            self.assertIs(owner._held_launch,launch);self.assertTrue(owner._unavailable)
            with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):
                owner.inspect('synthetic-version')
            self.assertEqual(parent.call_count,1)

    def test_new_wire_selects_existing_query12_and_wrong_role_refuses(self):
        from phase_tool.mutation.ntfs.bootstrap import _original_query_request
        launch=SimpleNamespace(_version1=True,run_id='synthetic-version',
            operation_nonce='a'*32,channel_id='b'*32,installation_digest='sha256:'+'c'*64,
            invocation={'request':self.request()})
        intent='sha256:'+'d'*64
        query=_original_query_request(launch,'read_executing',intent)
        self.assertEqual(query,{'native_original_query_version':'1.2',
            'action':'read_executing','run_id':'synthetic-version','intent_digest':intent,
            'operation_nonce':'a'*32,'channel_id':'b'*32,
            'installation_digest':'sha256:'+'c'*64,'version1_publication_request':{
                k:self.request()[k]for k in('request_id','target_locator',
                    'expected_current_digest','expected_digest')}})
        launch._version1=False
        with self.assertRaisesRegex(PhaseError,'ntfs.fixed_native_request_required'):
            _original_query_request(launch,'read_executing',intent)

    def test_exact_grammar_refuses_before_registry_or_preparation(self):
        base=self.request();bad=[]
        bad.extend({k:v for k,v in base.items()if k!=missing}for missing in base)
        bad.extend(base|{k:'/outside'}for k in ('profile','registry','target_root',
            'evidence_root','candidate_path','native_file_publication_request_version'))
        bad.extend(base|{k:v}for k,v in (('operation','plan'),
            ('native_version1_publication_request_version','2.0'),
            ('source_locator',False),('expected_current_digest',None),('expected_digest',False)))
        for request in bad:
            launch=SimpleNamespace(_inspection_only=False,check_runtime=Mock(),invocation={'request':request})
            with (self.subTest(request=request),
                    patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                    patch.object(installation,'_native_registry_for_manifest',
                        side_effect=AssertionError('registry reached')) as registry,
                    patch.object(preparation,'_prepare_version1_publication',
                        side_effect=AssertionError('preparation reached')) as prepare,
                    patch.object(entrypoint,'_deliver_linux_frame') as deliver):
                with self.assertRaisesRegex(PhaseError,'ntfs.fixed_native_request_required'):
                    entrypoint.run_native_core(launch)
                registry.assert_not_called();prepare.assert_not_called();deliver.assert_not_called()

    def test_actual_native_guard_refuses_version1_and_wrong_contract_before_source_core_channel(self):
        for version,contract_id in (('1.1','file_create.v1'),
                ('1.2','publish_new_version.v1'),('1.2','file_create.v1')):
            registry=(installation._native_inspection_file_create_registry() if version=='1.1'
                else installation._native_lifecycle_registry())
            raw=canonical_bytes({'native_read_installation_version':version,
                'registry_snapshot_digest':registry.digest,'contract':{'id':contract_id}})
            launch=SimpleNamespace(_inspection_only=False,check_runtime=Mock(),
                invocation={'request':self.request()},_manifest_bytes=raw,
                installation_digest=digest_bytes(raw),run_id='synthetic-version',
                operation_nonce='a'*32,channel_id='b'*32)
            with (self.subTest(contract=contract_id),
                    patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                    patch.object(entrypoint,'_deliver_linux_frame') as deliver,
                    patch.object(preparation,'_prepare_version1_publication',
                        side_effect=AssertionError('source reached')) as prepare,
                    patch.object(LinuxNativeChannelV2,'__init__',
                        side_effect=AssertionError('channel reached')) as channel2,
                    patch.object(LinuxNativeChannelV3,'__init__',
                        side_effect=AssertionError('channel reached')) as channel3,
                    patch.object(evidence.EvidenceStore,'__init__',
                        side_effect=AssertionError('evidence reached')) as store,
                    patch.object(PhaseApplication,'run',side_effect=AssertionError('Core reached')) as run):
                self.assertEqual(entrypoint.run_native_core(launch),10)
                result=deliver.call_args.args[0]['result']
                self.assertEqual(result['error'],'ntfs.native_profile_not_qualified')
                self.assertIs(result['mutation_attempted'],False);self.assertIsNone(result['receipt_digest'])
                prepare.assert_not_called();channel2.assert_not_called();channel3.assert_not_called()
                store.assert_not_called();run.assert_not_called()

    def test_host_installation_cannot_enter_native_version_preparation(self):
        with (patch.object(preparation,'mkdtemp',side_effect=AssertionError('scratch reached')) as scratch,
                patch.object(preparation,'copy_and_hash',side_effect=AssertionError('capture reached')) as capture):
            with self.assertRaisesRegex(PhaseError,'ntfs.closed_native_installation_required'):
                preparation._prepare_version1_publication(PhaseApplication(),
                    source_locator='x',target_locator='y',request_id='version',
                    expected_current_digest='sha256:'+'a'*64,expected_digest=None)
            scratch.assert_not_called();capture.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith('linux'),'Real SDK subprocess on Linux')
    def test_real_sdk_closed_version1_tool_and_unchanged_legacy_read_only_server(self):
        legacy=inspection_mcp._inspection_server(config_bytes=b'',expected_config_digest=None,
            manifest_bytes=b'',expected_manifest_digest=None)
        self.assertEqual([t.name for t in legacy._tool_manager.list_tools()],['phase_inspect'])
        self.assertEqual(set(legacy._tool_manager.list_tools()[0].parameters['properties']),{'run_id'})
        async def exchange(factory,readonly=False):
            from mcp import ClientSession,StdioServerParameters
            from mcp.client.stdio import stdio_client
            import phase_tool
            root=Path(phase_tool.__file__).resolve(strict=True).parent.parent
            code=('from phase_tool.mutation.ntfs.inspection_mcp import '+factory+'; '+factory+
                "(config_bytes=b'',expected_config_digest=None,manifest_bytes=b'',"
                "expected_manifest_digest=None).run(transport='stdio')")
            env=os.environ.copy();env.update(PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1')
            async with stdio_client(StdioServerParameters(command=sys.executable,args=['-B','-c',code],env=env)) as (reader,writer):
                async with ClientSession(reader,writer) as session:
                    await session.initialize();tools=(await session.list_tools()).tools
                    if readonly:
                        self.assertEqual([t.name for t in tools],['phase_inspect'])
                        unknown=await session.call_tool('phase_execute_version1_publication',self.args())
                        self.assertTrue(unknown.isError)
                        refused=await session.call_tool('phase_inspect',{'run_id':'synthetic-version'})
                    else:
                        self.assertEqual([t.name for t in tools],['phase_execute_prepared',
                            'phase_execute_file_publication','phase_publish_file',
                            'phase_execute_version1_publication','phase_inspect_version1_publication','phase_inspect'])
                        schema=tools[3].inputSchema
                        self.assertEqual(set(schema['properties']),set(self.args()))
                        self.assertEqual(set(schema['required']),set(self.args())-{'expected_digest'})
                        self.assertIs(schema['additionalProperties'],False)
                        bad=[{'run_id':True},{'source_locator':1},{'target_locator':[]},
                            {'request_id':1},{'expected_current_digest':None},
                            {'expected_current_digest':True},{'expected_current_digest':'sha256:BAD'},
                            {'expected_digest':False},{'source_locator':'../outside'}]
                        bad.extend({key:'outside'}for key in ('profile','registry','provider',
                            'contract_binding','target_root','evidence_root','preparation_root',
                            'timestamp','maximum_candidate_bytes','native_version1_publication_request_version'))
                        for change in bad:
                            value=await session.call_tool('phase_execute_version1_publication',self.args()|change)
                            self.assertTrue(value.isError,change)
                            text=' '.join(getattr(c,'text','')for c in value.content)
                            self.assertNotIn('ntfs.accepted_launch_binding_required',text)
                            self.assertNotIn('ntfs.inspection_mcp_unavailable',text)
                        refused=await session.call_tool('phase_execute_version1_publication',self.args())
                    self.assertTrue(refused.isError);self.assertIsNone(refused.structuredContent)
                    self.assertIn('ntfs.accepted_launch_binding_required',
                        ' '.join(getattr(c,'text','')for c in refused.content))
                    if not readonly:
                        blocked=await session.call_tool('phase_inspect',{'run_id':'synthetic-version'})
                        self.assertTrue(blocked.isError)
                        self.assertIn('ntfs.inspection_mcp_unavailable',
                            ' '.join(getattr(c,'text','')for c in blocked.content))
        async def both():
            await exchange('_prepared_server');await exchange('_inspection_server',readonly=True)
        asyncio.run(asyncio.wait_for(both(),timeout=30))


@unittest.skipUnless(sys.platform.startswith('linux'),'Real qualified Host Core requires Linux')
class Version1HostPublicationTests(unittest.TestCase):
    def fixture(self):
        from tempfile import TemporaryDirectory
        from .test_publish_new_version import _request
        directory=TemporaryDirectory(prefix='phase-version1-host-');self.addCleanup(directory.cleanup)
        request,target,evidence_root,current,before,after=_request(Path(directory.name),
            run_id='synthetic-version',key='synthetic-version')
        candidate,raw=preparation._version1_publication_candidate('synthetic-version',
            'documents/item.bin',digest_bytes(before))
        request.candidate_path.write_bytes(raw)
        return request,target,evidence_root,current,before,after,raw

    def test_real_host_core_version_and_fresh_independent_inspect_under_explicit_process_shell(self):
        from .test_publish_new_version import _archive_locator
        request,target,evidence_root,current,before,after,raw=self.fixture()
        app=PhaseApplication();owner=NativeVersion1PublicationTests().owner()
        reader=NativeVersion1PublicationTests().owner();calls=[]
        args=NativeVersion1PublicationTests().args()|{
            'expected_current_digest':digest_bytes(before),'expected_digest':digest_bytes(after)}
        def launch(**kwargs):
            return SimpleNamespace(invocation=parse_json_bytes(kwargs['invocation_bytes']))
        def parent(value):
            invocation=value.invocation;wire=invocation['request'];calls.append(invocation)
            if wire['operation']=='execute':
                candidate,wire_raw=preparation._version1_publication_candidate(wire['request_id'],
                    wire['target_locator'],wire['expected_current_digest'])
                self.assertEqual(wire_raw,raw)
                response=app.run('execute',contract_binding='publish_new_version.v1@1.0.0',
                    candidate_path=request.candidate_path,evidence_root=evidence_root,
                    run_id=invocation['run_id'],input_paths=request.input_paths,
                    root_bindings=request.root_bindings,timestamp=request.timestamp,
                    expected_inputs={'payload':(digest_bytes(after),len(after))},
                    _expected_candidate_bytes=raw)
            else:
                response=PhaseApplication().inspect(evidence_root=evidence_root,
                    run_id=invocation['run_id'],root_bindings=request.root_bindings)
            return {'result':response.payload,'exit_code':response.exit_code}
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launch),
                patch.object(inspection_mcp,'run_native_parent',side_effect=parent)):
            ack=owner.execute_version1_publication(**args)
            self.assertTrue(ack['success'],ack);self.assertEqual(len(calls),1)
            inspected=reader.inspect(request.run_id)
        self.assertTrue(inspected['success'],inspected);self.assertTrue(inspected['target_verified'])
        self.assertEqual(inspected['receipt_digest'],ack['receipt_digest'])
        self.assertEqual([v['request']['operation']for v in calls],['execute','inspect'])
        self.assertNotEqual(calls[0]['channel_id'],calls[1]['channel_id'])
        self.assertNotEqual(calls[0]['operation_nonce'],calls[1]['operation_nonce'])
        self.assertEqual(current.read_bytes(),after)
        self.assertEqual((target/_archive_locator(before)).read_bytes(),before)
        receipt_path=evidence_root/'.phase/runs'/request.run_id/'receipt.json'
        self.assertEqual(profile_digest('receipt',parse_json_bytes(receipt_path.read_bytes())),ack['receipt_digest'])
        self.assertIsNone(owner._held_launch);self.assertIsNone(reader._held_launch)

    def test_default_clock_same_key_conflict_preserves_prior_bytes_then_exact_time_control_reuses(self):
        from .test_publish_new_version import _archive_locator
        request,target,evidence_root,current,before,after,_=self.fixture()
        initial=replace(request,timestamp=None)
        ticks=[datetime(2026,10,25,0,0,0,tzinfo=timezone.utc),
            datetime(2026,10,25,0,0,1,tzinfo=timezone.utc)]
        with patch.object(core,'datetime',SimpleNamespace(now=Mock(side_effect=ticks))) as clock:
            first=core.PhaseCore().run(initial,execute=True)
            self.assertEqual(first.exit_code,0,first.receipt)
            receipt_path=evidence_root/'.phase/runs'/initial.run_id/'receipt.json'
            original_receipt=receipt_path.read_bytes()
            original_target=current.read_bytes()
            original_archive=(target/_archive_locator(before)).read_bytes()
            conflict=core.PhaseCore().run(replace(initial,run_id='synthetic-later'),execute=True)
            self.assertEqual(clock.now.call_count,2)
        self.assertEqual(conflict.exit_code,10)
        self.assertEqual(conflict.receipt['blockers'],['idempotency.same_key_conflict'])
        self.assertEqual(conflict.receipt['execution_disposition'],'not_executed')
        self.assertIs(conflict.receipt['mutation_attempted'],False)
        self.assertEqual(conflict.receipt['effect_receipts'],[])
        self.assertIsNone(conflict.intent);self.assertIsNone(conflict.effect_plan)
        self.assertEqual(receipt_path.read_bytes(),original_receipt)
        self.assertEqual(current.read_bytes(),original_target)
        self.assertEqual((target/_archive_locator(before)).read_bytes(),original_archive)
        self.assertEqual(original_target,after);self.assertEqual(original_archive,before)
        rejected_path=evidence_root/'.phase/runs'/'synthetic-later'/'receipt.json'
        self.assertEqual(profile_digest('receipt',parse_json_bytes(rejected_path.read_bytes())),
            conflict.receipt_digest)
        self.assertFalse((rejected_path.parent/'intent.json').exists())
        # Explicit T0 is ONLY a positive fingerprint control, never a runtime
        # retry strategy. Default-clock replay above truthfully conflicts.
        repeated=core.PhaseCore().run(replace(initial,run_id='synthetic-exact-control',
            timestamp=ticks[0].isoformat().replace('+00:00','Z')),execute=True)
        self.assertEqual(repeated.exit_code,0,repeated.receipt)
        self.assertEqual(repeated.receipt['execution_disposition'],'reused_existing')
        self.assertEqual(repeated.receipt['prior_verified_receipt_digest'],first.receipt_digest)
        observed=inspect_run(evidence_root,repeated.run_id,root_bindings=request.root_bindings)
        self.assertTrue(observed['target_verified'])
        self.assertEqual(observed['contract_result']['archive']['digest'],digest_bytes(before))
        self.assertEqual(receipt_path.read_bytes(),original_receipt)
        self.assertEqual(current.read_bytes(),after)
        self.assertEqual((target/_archive_locator(before)).read_bytes(),before)

    def test_frozen_at_alone_changes_shared_request_fingerprint_not_scope(self):
        from phase_tool.planning import _idempotency_from_root_records, root_identity_records
        from phase_tool.registry import BundledRegistry
        from phase_tool.candidate import capture_structured
        # Same real captured candidate, existing contract and unchanged roots.
        request,target,_,_,_,after,_=self.fixture()
        registry=BundledRegistry.load();binding=registry.contract_bindings()['publish_new_version.v1@1.0.0']
        contract=registry.resolve_contract(binding['id'],binding['version'],binding['package_digest'],
            core_version=__version__)
        # Core's real capture API is used; no invented canonical record.
        candidate=capture_structured(request.candidate_path)
        frozen=FrozenInput('payload','copy_and_hash',digest_bytes(after),len(after),
            '2026-10-25T00:00:00Z',blob_digest=digest_bytes(after))
        kwargs={'locator':'documents/item.bin','key':'synthetic-version',
            'root_identities':root_identity_records(contract,request.root_bindings),
            'root_identity_profile':'resolved-root-identity'}
        first=_idempotency_from_root_records(contract,candidate,{'payload':frozen},**kwargs)
        later=_idempotency_from_root_records(contract,candidate,
            {'payload':replace(frozen,frozen_at='2026-10-25T00:00:01Z')},**kwargs)
        self.assertEqual(first[0],later[0]);self.assertNotEqual(first[1],later[1])
        self.assertEqual(first[2:],later[2:])
