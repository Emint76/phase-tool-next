"""Prepared MCP component regressions; never accepted native qualification.

Real SDK stdio uses invalid startup and cannot reach a native process. Composed
delivery reuses explicitly synthetic OS/runtime/process boundaries, actual
Python parent/finalizer and strict pipe seal. No qualification guard is patched.
No success/receipt for Windows, NTFS, A05 or G01 is asserted here.
"""
import ast
import asyncio
from copy import deepcopy
from importlib import resources
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from ._native_startup_shell import startup_shell
from unittest.mock import Mock, patch

from phase_tool import evidence, installation
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import entrypoint, inspection_mcp, preparation
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3
from phase_tool.mutation.ntfs.uncertainty import _NativeLifecycleUnresolved


class NativePreparedMCPTests(unittest.TestCase):
    def owner(self):
        return inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',expected_config_digest=None,
            manifest_bytes=startup_shell()[0],expected_manifest_digest=startup_shell()[1])

    def args(self,run='synthetic-prepared'):
        return {'run_id':run,'candidate_path':'/synthetic/prepared/candidate.json',
            'input_paths':{'source':'/synthetic/prepared/source.bin'},
            'expected_inputs':{'source':('sha256:'+'a'*64,17)},'maximum_candidate_bytes':1234}

    def failure(self,command='execute'):
        return PhaseApplication()._failure(command,PhaseError('synthetic.preinstallation.refused')).payload

    def unknown(self,run='synthetic-prepared'):
        return _NativeLifecycleUnresolved(request=SimpleNamespace(run_id=run),
            context=SimpleNamespace(intent_recording_started=True,proof_publication_attempted=False,
                publication_attempted=True,common_guard_finalized=False,
                original_intent_digest='sha256:'+'b'*64,
                prepared=SimpleNamespace(effect_plan_digest='sha256:'+'c'*64)),
            authority=SimpleNamespace(channel=SimpleNamespace(possible_dispatch=True)),
            primary=OSError('synthetic native completion unknown')).command_result('execute')

    def test_prepared_known_refusal_passes_exact_request_and_uses_fresh_launch(self):
        owner=self.owner();result=self.failure();launches=[object(),object()]
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launches) as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value={'result':result,'exit_code':10}) as parent,
                patch('secrets.token_hex',side_effect=['a'*32,'b'*32,'c'*32,'d'*32])):
            for _ in range(2):
                self.assertIs(owner.execute_prepared(**self.args()),result)
                self.assertIsNone(owner._held_launch);self.assertFalse(owner._unavailable)
        self.assertEqual([c.args[0] for c in parent.call_args_list],launches)
        invocations=[parse_json_bytes(c.kwargs['invocation_bytes']) for c in factory.call_args_list]
        self.assertTrue(all(c.kwargs['_inspection_only'] is False for c in factory.call_args_list))
        for invocation in invocations:
            self.assertEqual(set(invocation),{'run_id','request','channel_id','operation_nonce'})
            self.assertEqual(invocation['run_id'],'synthetic-prepared')
            self.assertEqual(invocation['request'],{'operation':'execute',
                'candidate_path':'/synthetic/prepared/candidate.json',
                'input_paths':{'source':'/synthetic/prepared/source.bin'},
                'expected_inputs':{'source':['sha256:'+'a'*64,17]},'maximum_candidate_bytes':1234})
        self.assertEqual([v['channel_id'] for v in invocations],['a'*32,'c'*32])
        self.assertEqual([v['operation_nonce'] for v in invocations],['b'*32,'d'*32])
        self.assertIsNone(result['receipt_digest']);self.assertFalse(result['mutation_attempted'])

    def test_bad_wire_shape_and_run_refuse_before_launch_or_nonce(self):
        variants=[dict(candidate_path=1),dict(input_paths={'source':1}),dict(input_paths={1:'x'}),
            dict(maximum_candidate_bytes=True),dict(maximum_candidate_bytes=1.5),
            dict(maximum_candidate_bytes=0),dict(maximum_candidate_bytes=1024**2+1),
            dict(expected_inputs={'source':['sha256:'+'a'*64,True]}),
            dict(expected_inputs={'source':['sha256:'+'a'*64,-1]}),
            dict(expected_inputs={'source':['sha256:'+'a'*64,'17']}),
            dict(expected_inputs={'source':['sha256:'+'a'*64]}),
            dict(expected_inputs={'source':[1,17]}),dict(run_id='../outside')]
        owner=self.owner()
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                patch('secrets.token_hex') as nonce):
            for change in variants:
                with self.subTest(change=change),self.assertRaises((PhaseError,ValueError)):
                    owner.execute_prepared(**(self.args()|change))
            factory.assert_not_called();nonce.assert_not_called()
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_contention_refuses_both_calls_without_nonce_or_new_launch(self):
        owner=self.owner();owner._gate.acquire()
        try:
            with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                    patch('secrets.token_hex') as nonce):
                for call in (lambda:owner.execute_prepared(**self.args()),
                            lambda:owner.execute_file_publication(**self.file_args()),
                            lambda:owner.inspect('synthetic-read')):
                    with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_call_active'):call()
                factory.assert_not_called();nonce.assert_not_called()
        finally:owner._gate.release()
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_typed_uncertainty_is_unchanged_retains_launch_and_blocks_both_tools(self):
        for nullable in (False,True):
            with self.subTest(nullable_run=nullable):
                owner=self.owner();launch=object();result=self.unknown()
                if nullable:result['run_id']=None
                before=canonical_bytes(result)
                with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch) as factory,
                        patch.object(inspection_mcp,'run_native_parent',return_value={'result':result,'exit_code':40}) as parent):
                    self.assertIs(owner.execute_prepared(**self.args()),result)
                    self.assertEqual(canonical_bytes(result),before)
                    self.assertIs(owner._held_launch,launch);self.assertTrue(owner._unavailable)
                    for call in (lambda:owner.execute_prepared(**self.args()),
                            lambda:owner.execute_file_publication(**self.file_args()),
                            lambda:owner.inspect('synthetic-read')):
                        with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):call()
                    factory.assert_called_once();parent.assert_called_once_with(launch)
                self.assertTrue(result['inspection_required']);self.assertFalse(result['retry_authorized'])
                self.assertIsNone(result['receipt_digest']);self.assertIsNone(result['mutation_attempted'])

    def test_schema_and_result_binding_faults_poison_and_retain_actual_launch(self):
        bad=self.failure();foreign=deepcopy(bad);foreign['run_id']='synthetic-foreign'
        cases=[{'result':{'success':True},'exit_code':0},
            {'result':self.failure('plan'),'exit_code':10},{'result':foreign,'exit_code':10},
            {'result':bad,'exit_code':20},{'result':bad,'exit_code':True}]
        for response in cases:
            with self.subTest(response=response):
                owner=self.owner();launch=object()
                with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch) as factory,
                        patch.object(inspection_mcp,'run_native_parent',return_value=response)):
                    with self.assertRaises(Exception):owner.execute_prepared(**self.args())
                    self.assertTrue(owner._unavailable);self.assertIs(owner._held_launch,launch)
                    with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):owner.inspect('synthetic-read')
                    factory.assert_called_once()

    def test_parent_primary_and_secondary_gate_failure_are_not_recast(self):
        owner=self.owner();launch=object();primary=OSError('synthetic parent primary')
        owner._gate=SimpleNamespace(acquire=Mock(return_value=True),
            release=Mock(side_effect=RuntimeError('synthetic secondary gate release')))
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch),
                patch.object(inspection_mcp,'run_native_parent',side_effect=primary)):
            with self.assertRaises(OSError) as caught:owner.execute_prepared(**self.args())
        self.assertIs(caught.exception,primary);self.assertIs(owner._held_launch,launch)
        self.assertTrue(owner._unavailable)
        self.assertIn('Native MCP call gate: RuntimeError',primary.__notes__)

    def test_failed_constructor_is_sticky_without_claiming_a_created_process(self):
        owner=self.owner();primary=OSError('synthetic startup refused')
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=primary) as factory,
                patch.object(inspection_mcp,'run_native_parent') as parent):
            with self.assertRaises(OSError) as caught:owner.execute_prepared(**self.args())
            self.assertIs(caught.exception,primary);self.assertIsNone(owner._held_launch)
            self.assertTrue(owner._unavailable)
            with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):owner.inspect('synthetic-read')
            factory.assert_called_once();parent.assert_not_called()

    def test_existing_read_only_call_remains_literal_and_clears_known_refusal(self):
        owner=self.owner();launch=object();result=self.failure('inspect')
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch) as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value={'result':result,'exit_code':10})):
            self.assertIs(owner.inspect('synthetic-read'),result)
        self.assertIs(factory.call_args.kwargs['_inspection_only'],True)
        self.assertEqual(parse_json_bytes(factory.call_args.kwargs['invocation_bytes'])['request'],{'operation':'inspect'})
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_real_core_guard_refuses_prepared_request_before_channel_or_evidence(self):
        # Actual installation factory/registry guard, synthetic stdio/runtime.
        # This is a real NO-GO path, never a qualified native execution.
        args=self.args();request=inspection_mcp._prepared_request(args['candidate_path'],
            args['input_paths'],args['expected_inputs'],args['maximum_candidate_bytes'])
        launch=SimpleNamespace(_inspection_only=False,check_runtime=Mock(),
            invocation={'request':request},_manifest_bytes=startup_shell()[0],installation_digest=startup_shell()[1],
            run_id=args['run_id'],operation_nonce='a'*32,channel_id='b'*32)
        with (patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                patch.object(entrypoint,'_deliver_linux_frame') as deliver,
                patch.object(LinuxNativeChannelV2,'__init__',side_effect=AssertionError('channel reached')) as channel,
                patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('evidence reached')) as store):
            self.assertEqual(entrypoint.run_native_core(launch),10)
            channel.assert_not_called();store.assert_not_called();deliver.assert_called_once()
        result=deliver.call_args.args[0]['result']
        self.assertEqual(result['error'],'ntfs.native_profile_not_qualified')
        self.assertFalse(result['success']);self.assertFalse(result['mutation_attempted'])
        self.assertIsNone(result['receipt_digest'])

    def test_composed_known_refusal_clears_only_after_actual_parent_finalizer(self):
        from .test_native_composition_delivery import NativeComposedDeliveryTests
        component=NativeComposedDeliveryTests();owner=self.owner()
        with component.delivery() as fixture:
            result=self.failure();frame=fixture.frame|{'result':result,'exit_code':10}
            fixture.pipe.receive_frame.return_value=(canonical_bytes(frame),None)
            fixture.witness.wait_for_exit.return_value={'worker_exit_established':True,'exit_code':10}
            with patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=fixture.launch):
                self.assertEqual(owner.execute_prepared(**self.args('synthetic-delivery')),result)
            component.assert_finalized_once(fixture)
            self.assertIsNone(owner._held_launch);self.assertFalse(owner._unavailable)

    def test_composed_uncertainty_keeps_launch_even_after_docker_cli_handle_closes(self):
        from .test_native_composition_delivery import NativeComposedDeliveryTests
        component=NativeComposedDeliveryTests();owner=self.owner()
        with component.delivery() as fixture:
            result=self.unknown('synthetic-delivery');frame=fixture.frame|{'result':result,'exit_code':40}
            fixture.pipe.receive_frame.return_value=(canonical_bytes(frame),None)
            fixture.witness.wait_for_exit.return_value={'worker_exit_established':True,'exit_code':40}
            with patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=fixture.launch) as factory:
                self.assertEqual(owner.execute_prepared(**self.args('synthetic-delivery')),result)
                component.assert_finalized_once(fixture)
                self.assertIs(owner._held_launch,fixture.launch);self.assertTrue(owner._unavailable)
                with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):owner.inspect('synthetic-read')
                factory.assert_called_once()

    def test_composed_delivery_primary_and_seal_failure_keep_original_owner(self):
        from .test_native_composition_delivery import NativeComposedDeliveryTests
        component=NativeComposedDeliveryTests();owner=self.owner();primary=OSError('synthetic delivery primary')
        with component.delivery(receive_error=primary,seal_failure=True) as fixture:
            with patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=fixture.launch):
                with self.assertRaises(OSError) as caught:owner.execute_prepared(**self.args('synthetic-delivery'))
            self.assertIs(caught.exception,primary);component.assert_finalized_once(fixture)
            self.assertIn('Native Core delivery finalization: PhaseError',primary.__notes__)
            self.assertIs(owner._held_launch,fixture.launch);self.assertTrue(owner._unavailable)

    def test_fixed_mcp_launcher_dispatch_precedes_binary_initial_reader(self):
        # Static fixed-role wiring, not an execution of accepted startup.
        raw=resources.files('phase_tool').joinpath('data/native/native_phase_launcher.py.in').read_bytes()
        tree=ast.parse(raw);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        receive=next(n.lineno for n in ast.walk(main) if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Name) and n.func.id=='receive_initial')
        branches={ast.literal_eval(n.test.comparators[0]):n for n in main.body
            if isinstance(n,ast.If) and isinstance(n.test,ast.Compare)
            and isinstance(n.test.left,ast.Name) and n.test.left.id=='role'
            and isinstance(n.test.ops[0],ast.Eq) and isinstance(n.test.comparators[0],ast.Constant)}
        for role,call in [('inspect-mcp','run_native_inspection_mcp'),('execute-mcp','run_native_prepared_mcp')]:
            branch=branches[role];self.assertLess(branch.lineno,receive)
            self.assertIsInstance(branch.body[-1],ast.Return)
            self.assertEqual(branch.body[-1].value.func.id,call)
        # ast.walk is breadth-first: the first role-In comparison belongs to
        # a later parent branch. Bind the actual top-level Windows-only guard.
        expected=ast.parse("need((os.name == 'nt') == (role in "
            "{'parent','inspect-parent','inspect-mcp','execute-mcp','worker'}))").body[0]
        guards=[n for n in main.body if ast.dump(n,include_attributes=False)==
            ast.dump(expected,include_attributes=False)]
        self.assertEqual(len(guards),1)
        self.assertLess(guards[0].lineno,branches['execute-mcp'].lineno)

    def file_args(self,run='synthetic-prepared'):
        return {'run_id':run,'source_locator':'incoming/synthetic.bin',
            'target_locator':'synthetic/output.bin','request_id':'synthetic-request',
            'expected_digest':None}

    def test_file_publication_preserves_raw_result_exact_wire_and_fresh_nonces(self):
        owner=self.owner();result=self.failure();launches=[object(),object()]
        args=self.file_args();del args['expected_digest']  # Exercise default None.
        nonnull='sha256:'+'e'*64
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launches) as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value={'result':result,'exit_code':10}) as parent,
                patch('secrets.token_hex',side_effect=['a'*32,'b'*32,'c'*32,'d'*32])):
            for arguments in (args,args|{'expected_digest':nonnull}):
                self.assertIs(owner.execute_file_publication(**arguments),result)
                self.assertIsNone(owner._held_launch);self.assertFalse(owner._unavailable)
        self.assertEqual([c.args[0] for c in parent.call_args_list],launches)
        invocations=[parse_json_bytes(c.kwargs['invocation_bytes']) for c in factory.call_args_list]
        for call,value,expected in zip(factory.call_args_list,invocations,(None,nonnull)):
            self.assertIs(call.kwargs['_inspection_only'],False)
            self.assertEqual(value['run_id'],args['run_id'])
            self.assertEqual(value['request'],{'operation':'execute',
                'native_file_publication_request_version':'1.0',
                'source_locator':args['source_locator'],'target_locator':args['target_locator'],
                'request_id':args['request_id'],'expected_digest':expected})
        self.assertEqual([(v['channel_id'],v['operation_nonce']) for v in invocations],
            [('a'*32,'b'*32),('c'*32,'d'*32)])

    def test_file_publication_bad_types_refuse_before_startup_without_poisoning(self):
        owner=self.owner()
        changes=[{'run_id':'../outside'},{'source_locator':1},{'target_locator':None},
            {'request_id':False},{'expected_digest':True}]
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                patch('secrets.token_hex') as nonce):
            for change in changes:
                with self.subTest(change=change),self.assertRaises((PhaseError,ValueError)):
                    owner.execute_file_publication(**(self.file_args()|change))
            factory.assert_not_called();nonce.assert_not_called()
        self.assertIsNone(owner._held_launch);self.assertFalse(owner._unavailable)

    def test_file_publication_mcp_bridge_reaches_both_real_guards_before_any_preparation(self):
        # Synthetic process/stdio delivery only; actual installation guard intact.
        for version in ('1.1','1.2'):
            registry=(installation._native_inspection_file_create_registry() if version=='1.1'
                else installation._native_lifecycle_registry())
            manifest=canonical_bytes({'native_read_installation_version':version,
                'registry_snapshot_digest':registry.digest,'contract':{'id':'file_create.v1'}})
            owner=inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',expected_config_digest=None,
                manifest_bytes=manifest,expected_manifest_digest=digest_bytes(manifest))
            def shell(**kwargs):
                invocation=parse_json_bytes(kwargs['invocation_bytes'])
                return SimpleNamespace(_inspection_only=kwargs['_inspection_only'],check_runtime=Mock(),
                    invocation=invocation,_manifest_bytes=kwargs['manifest_bytes'],
                    installation_digest=kwargs['expected_manifest_digest'],run_id=invocation['run_id'],
                    operation_nonce=invocation['operation_nonce'],channel_id=invocation['channel_id'])
            with (self.subTest(version=version),
                    patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=shell),
                    patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                    patch.object(entrypoint,'_deliver_linux_frame') as deliver,
                    patch.object(preparation,'_prepare_file_publication',side_effect=AssertionError('scratch reached')) as prepare,
                    patch.object(LinuxNativeChannelV2,'__init__',side_effect=AssertionError('channel reached')) as channel2,
                    patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel reached')) as channel3,
                    patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('evidence reached')) as store,
                    patch.object(PhaseApplication,'run',side_effect=AssertionError('Core reached')) as core):
                def parent(launch):
                    self.assertEqual(entrypoint.run_native_core(launch),10)
                    return deliver.call_args.args[0]
                with patch.object(inspection_mcp,'run_native_parent',side_effect=parent):
                    result=owner.execute_file_publication(**self.file_args())
                prepare.assert_not_called();channel2.assert_not_called();channel3.assert_not_called()
                store.assert_not_called();core.assert_not_called()
            self.assertEqual(result['error'],'ntfs.native_profile_not_qualified')
            self.assertFalse(result['success']);self.assertFalse(result['mutation_attempted'])
            self.assertIsNone(result['receipt_digest']);self.assertIsNone(owner._held_launch)

    def test_real_sdk_file_publication_schema_and_legacy_read_only_toolset(self):
        async def exchange(factory,legacy=False):
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
                    if legacy:
                        self.assertEqual([t.name for t in tools],['phase_inspect'])
                        unknown=await session.call_tool('phase_execute_file_publication',self.file_args())
                        self.assertTrue(unknown.isError)
                        # Unknown tool must not consume the read-only owner.
                        refused=await session.call_tool('phase_inspect',{'run_id':'synthetic-read'})
                    else:
                        self.assertEqual([t.name for t in tools],['phase_execute_prepared',
                            'phase_execute_file_publication','phase_publish_file','phase_execute_version1_publication','phase_inspect_version1_publication','phase_inspect'])
                        tool=tools[1];schema=tool.inputSchema
                        self.assertEqual(set(schema['properties']),set(self.file_args()))
                        self.assertEqual(set(schema['required']),{'run_id','source_locator','target_locator','request_id'})
                        self.assertIs(schema['additionalProperties'],False)
                        bad=[{'run_id':1},{'source_locator':True},{'source_locator':[]},
                            {'target_locator':None},{'target_locator':{}},{'request_id':17},
                            {'expected_digest':False},{'expected_digest':17},{'expected_digest':[]}]
                        bad.extend({key:'synthetic-forbidden'} for key in ('source_root','target_root',
                            'preparation_root','evidence_root','candidate_path','maximum_candidate_bytes',
                            'native_file_publication_request_version','publication_version','operation',
                            'contract_binding','registry','provider'))
                        for change in bad:
                            rejected=await session.call_tool(tool.name,self.file_args()|change)
                            self.assertTrue(rejected.isError,change)
                            text=' '.join(getattr(c,'text','') for c in rejected.content)
                            self.assertNotIn('ntfs.accepted_launch_binding_required',text)
                            self.assertNotIn('ntfs.inspection_mcp_unavailable',text)
                        refused=await session.call_tool(tool.name,self.file_args())
                    self.assertTrue(refused.isError);self.assertIsNone(refused.structuredContent)
                    self.assertIn('ntfs.accepted_launch_binding_required',
                        ' '.join(getattr(c,'text','') for c in refused.content))
                    if not legacy:
                        # Same finite owner remains poisoned across the existing raw APIs.
                        for name,args in [('phase_execute_prepared',self.args()),
                                ('phase_execute_file_publication',self.file_args()),
                                ('phase_inspect',{'run_id':'synthetic-read'})]:
                            blocked=await session.call_tool(name,args)
                            self.assertTrue(blocked.isError)
                            self.assertIn('ntfs.inspection_mcp_unavailable',
                                ' '.join(getattr(c,'text','') for c in blocked.content))
        async def both():
            await exchange('_prepared_server');await exchange('_inspection_server',legacy=True)
        asyncio.run(asyncio.wait_for(both(),timeout=30))

    def test_real_sdk_prepared_schema_rejects_coercion_and_selectors_before_startup(self):
        async def exchange():
            from mcp import ClientSession,StdioServerParameters
            from mcp.client.stdio import stdio_client
            import phase_tool
            root=Path(phase_tool.__file__).resolve(strict=True).parent.parent
            code=("from phase_tool.mutation.ntfs.inspection_mcp import _prepared_server; "
                "_prepared_server(config_bytes=b'',expected_config_digest=None,"
                "manifest_bytes=b'',expected_manifest_digest=None).run(transport='stdio')")
            env=os.environ.copy();env.update(PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1')
            async with stdio_client(StdioServerParameters(command=sys.executable,args=['-B','-c',code],env=env)) as (reader,writer):
                async with ClientSession(reader,writer) as session:
                    await session.initialize();tools=(await session.list_tools()).tools
                    self.assertEqual([t.name for t in tools],['phase_execute_prepared',
                        'phase_execute_file_publication','phase_publish_file','phase_execute_version1_publication','phase_inspect_version1_publication','phase_inspect'])
                    schema=tools[0].inputSchema
                    self.assertEqual(set(schema['properties']),set(self.args()))
                    self.assertEqual(set(schema['required']),{'run_id','candidate_path','input_paths'})
                    self.assertIs(schema['additionalProperties'],False)
                    self.assertTrue(all(t.inputSchema['additionalProperties'] is False for t in tools))
                    bad=[dict(run_id=17),dict(candidate_path=17),dict(input_paths={'source':17}),
                        dict(maximum_candidate_bytes=True),dict(maximum_candidate_bytes=1.5),
                        dict(maximum_candidate_bytes='1234'),dict(maximum_candidate_bytes=0),
                        dict(maximum_candidate_bytes=1024**2+1),dict(expected_inputs={'source':['a',True]}),
                        dict(expected_inputs={'source':['a',1.5]}),dict(expected_inputs={'source':['a','17']}),
                        dict(expected_inputs={'source':['a',-1]}),dict(expected_inputs={'source':['a']}),
                        dict(expected_inputs={'source':['a',1,2]}),dict(expected_inputs={'source':[17,1]})]
                    bad.extend({key:'synthetic-forbidden'} for key in
                        ('contract_binding','root_bindings','evidence_root','operation','registry','provider'))
                    for change in bad:
                        rejected=await session.call_tool('phase_execute_prepared',self.args()|change)
                        self.assertTrue(rejected.isError,change)
                        text=' '.join(getattr(c,'text','') for c in rejected.content)
                        self.assertNotIn('ntfs.accepted_launch_binding_required',text)
                        self.assertNotIn('ntfs.inspection_mcp_unavailable',text)
                    rejected=await session.call_tool('phase_inspect',{'run_id':'synthetic-read','evidence_root':'/outside'})
                    self.assertTrue(rejected.isError)
                    # If an invalid call reached startup, its owner would already
                    # be sticky-unavailable. This first valid call must instead
                    # reach the actual unchanged invalid-startup refusal.
                    refused=await session.call_tool('phase_execute_prepared',self.args())
                    self.assertTrue(refused.isError);self.assertIsNone(refused.structuredContent)
                    self.assertIn('ntfs.accepted_launch_binding_required',
                        ' '.join(getattr(c,'text','') for c in refused.content))
                    blocked=await session.call_tool('phase_inspect',{'run_id':'synthetic-read'})
                    self.assertTrue(blocked.isError)
                    self.assertIn('ntfs.inspection_mcp_unavailable',
                        ' '.join(getattr(c,'text','') for c in blocked.content))
        asyncio.run(asyncio.wait_for(exchange(),timeout=30))

    def inspection_args(self, run='synthetic-read'):
        return {'run_id':run, 'request_id':'synthetic-request', 'target_locator':'objects/result.bin',
            'expected_digest':'sha256:'+'d'*64, 'expected_receipt_digest':'sha256:'+'e'*64}

    def test_file_inspection_closed_expectations_and_legacy_shapes(self):
        from phase_tool.canonical import profile_digest
        from phase_tool.publish_file import _file_publication_candidate
        args=self.inspection_args()
        request=inspection_mcp._file_publication_inspection_request(
            args['request_id'],args['target_locator'],args['expected_digest'],args['expected_receipt_digest'])
        candidate,_=_file_publication_candidate(args['request_id'],args['target_locator'])
        self.assertEqual(entrypoint._native_file_inspection_expectations(request),{
            '_expected_candidate_digest':profile_digest('candidate',candidate),
            '_expected_frozen_input':('payload',args['expected_digest']),
            '_expected_receipt_digest':args['expected_receipt_digest']})
        no_hash=request|{'expected_digest':None}
        self.assertNotIn('_expected_frozen_input',entrypoint._native_file_inspection_expectations(no_hash))
        self.assertEqual(entrypoint._native_file_inspection_expectations({'operation':'inspect'}),{})
        bad=[request|{'native_file_publication_inspection_request_version':'2.0'},request|{'operation':'execute'},
            request|{'source_locator':'extra'}, {k:v for k,v in request.items() if k!='expected_receipt_digest'},
            request|{'native_file_publication_request_version':'1.0'}, [('operation','inspect')]]
        for value in bad:
            with self.subTest(value=value),self.assertRaisesRegex(PhaseError,'ntfs.fixed_native_request_required'):
                entrypoint._native_file_inspection_expectations(value)

    def test_prepared_inspection_uses_same_owner_and_legacy_wire(self):
        owner=self.owner();result=self.failure('inspect');launches=[object(),object()]
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launches) as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value={'result':result,'exit_code':10}),
                patch('secrets.token_hex',side_effect=['a'*32,'b'*32,'c'*32,'d'*32])):
            self.assertIs(owner.inspect_prepared(**self.inspection_args()),result)
            self.assertIs(owner.inspect_prepared('synthetic-read'),result)
        calls=factory.call_args_list
        self.assertTrue(all(c.kwargs['_inspection_only'] is True for c in calls))
        values=[parse_json_bytes(c.kwargs['invocation_bytes']) for c in calls]
        self.assertEqual(set(values[0]['request']),{'operation','native_file_publication_inspection_request_version',
            'request_id','target_locator','expected_digest','expected_receipt_digest'})
        self.assertEqual(values[0]['request']['expected_receipt_digest'],self.inspection_args()['expected_receipt_digest'])
        self.assertEqual(values[1]['request'],{'operation':'inspect'})
        self.assertEqual([v['channel_id'] for v in values],['a'*32,'c'*32])
        self.assertEqual([v['operation_nonce'] for v in values],['b'*32,'d'*32])
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_bad_file_inspection_literals_refuse_before_gate_nonce_or_launch(self):
        class Text(str):pass
        variants=[dict(request_id=None),dict(request_id=True),dict(request_id=Text('synthetic-request')),
            dict(request_id='Bad'),dict(request_id='x'*129),dict(target_locator=None),
            dict(target_locator='../outside'),dict(target_locator='nul.txt'),dict(target_locator=True),
            dict(expected_digest=True),dict(expected_digest='sha256:'+'A'*64),
            dict(expected_receipt_digest=None),dict(expected_receipt_digest='sha256:'+'z'*64),
            dict(expected_receipt_digest=True),dict(run_id='../outside')]
        owner=self.owner();owner._gate=SimpleNamespace(acquire=Mock(),release=Mock())
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                patch('secrets.token_hex') as nonce):
            for change in variants:
                with self.subTest(change=change),self.assertRaises(PhaseError):
                    owner.inspect_prepared(**(self.inspection_args()|change))
            with self.assertRaises(TypeError):owner.inspect_prepared(**self.inspection_args(),evidence_root='/outside')
            factory.assert_not_called();nonce.assert_not_called()
        owner._gate.acquire.assert_not_called();owner._gate.release.assert_not_called()
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_file_inspection_both_actual_guards_and_wrong_contract_before_factory(self):
        args=self.inspection_args()
        request=inspection_mcp._file_publication_inspection_request(args['request_id'],args['target_locator'],
            args['expected_digest'],args['expected_receipt_digest'])
        for version in ('1.1','1.2'):
            registry=(installation._native_inspection_file_create_registry() if version=='1.1'
                else installation._native_lifecycle_registry())
            manifest=canonical_bytes({'native_read_installation_version':version,
                'registry_snapshot_digest':registry.digest,
                'contract':registry.contract_bindings()['file_create.v1@1.0.0']})
            launch=SimpleNamespace(_inspection_only=True,check_runtime=Mock(),invocation={'request':request},
                _manifest_bytes=manifest,installation_digest=digest_bytes(manifest),
                run_id=args['run_id'],operation_nonce='a'*32,channel_id='b'*32)
            with (self.subTest(version=version),patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                    patch.object(entrypoint,'_deliver_linux_frame') as deliver,
                    patch.object(LinuxNativeChannelV2,'__init__',side_effect=AssertionError('channel reached')) as c2,
                    patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel reached')) as c3,
                    patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('evidence reached')) as store,
                    patch.object(PhaseApplication,'inspect',side_effect=AssertionError('reader reached')) as reader):
                self.assertEqual(entrypoint.run_native_inspection(launch),10)
                result=deliver.call_args.args[0]['result']
                self.assertEqual(result['error'],'ntfs.native_profile_not_qualified')
                c2.assert_not_called();c3.assert_not_called();store.assert_not_called();reader.assert_not_called()
            wrong=parse_json_bytes(manifest);wrong['contract']['id']='publish_new_version.v1'
            launch._manifest_bytes=canonical_bytes(wrong);launch.installation_digest=digest_bytes(launch._manifest_bytes)
            with (patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                    patch.object(installation,'_native_installation_for_manifest',side_effect=AssertionError('factory reached')) as factory):
                with self.assertRaisesRegex(PhaseError,'ntfs.original_single_effect_required'):
                    entrypoint.run_native_inspection(launch)
                factory.assert_not_called()

    def test_inspection_receipt_pin_failure_preserves_primary_and_always_seals(self):
        pin='sha256:'+'e'*64
        for receipt in (None,'sha256:'+'f'*64):
            response=SimpleNamespace(payload={'success':True,'receipt_digest':receipt})
            app=SimpleNamespace(inspect=Mock(return_value=response))
            authority=SimpleNamespace(seal=Mock(side_effect=OSError('synthetic secondary seal')))
            with self.subTest(receipt=receipt),self.assertRaisesRegex(PhaseError,'ntfs.file_publication_receipt_mismatch') as caught:
                entrypoint._inspect_with_channel_seal(app,authority,evidence_root=None,run_id='synthetic-read',
                    root_bindings={},_expected_candidate_digest='sha256:'+'d'*64,_expected_receipt_digest=pin)
            authority.seal.assert_called_once_with(intent_digest=None)
            self.assertIn('Native inspection channel seal: OSError',caught.exception.__notes__)
        primary=RuntimeError('synthetic original reader primary')
        app=SimpleNamespace(inspect=Mock(side_effect=primary));authority=SimpleNamespace(seal=Mock())
        with self.assertRaises(RuntimeError) as caught:
            entrypoint._inspect_with_channel_seal(app,authority,evidence_root=None,run_id='synthetic-read',
                root_bindings={},_expected_receipt_digest=pin)
        self.assertIs(caught.exception,primary);authority.seal.assert_called_once_with(intent_digest=None)
        failed=SimpleNamespace(payload={'success':False,'receipt_digest':None,'error':'synthetic.original.failure'})
        app=SimpleNamespace(inspect=Mock(return_value=failed));authority=SimpleNamespace(seal=Mock())
        self.assertIs(entrypoint._inspect_with_channel_seal(app,authority,evidence_root=None,
            run_id='synthetic-read',root_bindings={},_expected_receipt_digest=pin),failed)
        authority.seal.assert_called_once_with(intent_digest=None)
        app.inspect.assert_called_once_with(evidence_root=None,run_id='synthetic-read',root_bindings={})

    @unittest.skipUnless(sys.platform.startswith('linux'),'real Linux SDK transport component required')
    def test_real_sdk_prepared_inspect_optional_closed_literals_and_unary_legacy_schema(self):
        legacy=inspection_mcp._inspection_server(config_bytes=b'',expected_config_digest=None,
            manifest_bytes=b'',expected_manifest_digest=None)
        self.assertEqual([t.name for t in legacy._tool_manager.list_tools()],['phase_inspect'])
        self.assertEqual(set(legacy._tool_manager.list_tools()[0].parameters['properties']),{'run_id'})
        async def exchange():
            from mcp import ClientSession,StdioServerParameters
            from mcp.client.stdio import stdio_client
            import phase_tool
            root=Path(phase_tool.__file__).resolve(strict=True).parent.parent
            code=("from phase_tool.mutation.ntfs.inspection_mcp import _prepared_server; "
                "_prepared_server(config_bytes=b'',expected_config_digest=None,"
                "manifest_bytes=b'',expected_manifest_digest=None).run(transport='stdio')")
            env=os.environ.copy();env.update(PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1')
            async with stdio_client(StdioServerParameters(command=sys.executable,args=['-B','-c',code],env=env)) as (reader,writer):
                async with ClientSession(reader,writer) as session:
                    await session.initialize();tools=(await session.list_tools()).tools
                    self.assertEqual([t.name for t in tools],['phase_execute_prepared','phase_execute_file_publication','phase_publish_file','phase_execute_version1_publication','phase_inspect_version1_publication','phase_inspect'])
                    schema=tools[5].inputSchema
                    self.assertEqual(set(schema['properties']),set(self.inspection_args()))
                    self.assertEqual(schema['required'],['run_id']);self.assertIs(schema['additionalProperties'],False)
                    bad=[dict(request_id=17),dict(expected_digest=17),dict(expected_receipt_digest=True),
                        dict(target_locator=True),dict(request_id=None),dict(expected_receipt_digest=None),
                        dict(target_locator='../outside'),dict(evidence_root='/outside')]
                    for change in bad:
                        response=await session.call_tool('phase_inspect',self.inspection_args()|change)
                        self.assertTrue(response.isError,change)
                        text=' '.join(getattr(c,'text','') for c in response.content)
                        self.assertNotIn('ntfs.accepted_launch_binding_required',text)
                        self.assertNotIn('ntfs.inspection_mcp_unavailable',text)
                    refused=await session.call_tool('phase_inspect',self.inspection_args())
                    self.assertTrue(refused.isError);self.assertIsNone(refused.structuredContent)
                    self.assertIn('ntfs.accepted_launch_binding_required',' '.join(getattr(c,'text','') for c in refused.content))
                    blocked=await session.call_tool('phase_inspect',{'run_id':'synthetic-read'})
                    self.assertTrue(blocked.isError)
                    self.assertIn('ntfs.inspection_mcp_unavailable',' '.join(getattr(c,'text','') for c in blocked.content))
        asyncio.run(asyncio.wait_for(exchange(),timeout=30))


@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: actual qualified Linux/ext4 required')
class NativeFileInspectionHostTests(unittest.TestCase):
    """Real Host/Core fixture plus synthetic channel/process boundary, not NTFS."""
    def setUp(self):
        from tempfile import TemporaryDirectory
        from phase_tool.canonical import profile_digest
        from phase_tool.core import PhaseCore,PhaseRequest
        from phase_tool.installation import qualify_host_authority_roots,_linux_filesystem_type
        from phase_tool.registry import BundledRegistry
        from phase_tool.publish_file import _file_publication_candidate
        temp=TemporaryDirectory(prefix='phase-native-inspect-caller-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.target=self.root/'target';self.target.mkdir()
        (self.target/'objects').mkdir();self.evidence=self.root/'evidence';self.evidence.mkdir()
        qualify_host_authority_roots({'target':self.target,'evidence':self.evidence})
        self.assertEqual(_linux_filesystem_type(self.evidence),'ext4')
        self.registry=BundledRegistry.load();self.core=PhaseCore(self.registry)
        self.source=self.root/'source.bin';self.payload=b'synthetic-inspect-caller\x00\xff\r\n'
        self.source.write_bytes(self.payload);self.candidate=self.root/'candidate.json'
        _,data=_file_publication_candidate('synthetic-request','objects/result.bin');self.candidate.write_bytes(data)
        binding=self.registry.contract_bindings()['file_create.v1@1.0.0']
        self.request=PhaseRequest(binding['id'],binding['version'],binding['package_digest'],self.candidate,
            self.evidence,'synthetic-first',{'payload':self.source},{'phase_result_root':self.target},
            timestamp='2026-10-25T00:00:00Z')
        self.app=PhaseApplication(registry=self.registry)

    def execute(self,run='synthetic-first'):
        from dataclasses import replace
        result=self.core.run(replace(self.request,run_id=run),execute=True)
        self.assertEqual(result.exit_code,0,result.receipt)
        return result

    def inspect_response(self,run,receipt,**changes):
        args={'operation':'inspect','native_file_publication_inspection_request_version':'1.0',
            'request_id':'synthetic-request','target_locator':'objects/result.bin',
            'expected_digest':digest_bytes(self.payload),'expected_receipt_digest':receipt}
        args.update(changes);expected=entrypoint._native_file_inspection_expectations(args)
        authority=SimpleNamespace(seal=Mock())
        try:
            return entrypoint._inspect_with_channel_seal(self.app,authority,evidence_root=self.evidence,
                run_id=run,root_bindings=self.request.root_bindings,**expected)
        finally:authority.seal.assert_called_once_with(intent_digest=None)

    def test_actual_host_create_and_reuse_inspect_pin_current_ack_and_preserve_raw_result(self):
        first=self.execute()
        for outcome in (first,self.execute('synthetic-reuse')):
            expected=self.app.inspect(evidence_root=self.evidence,run_id=outcome.run_id,
                root_bindings=self.request.root_bindings)
            checked=self.inspect_response(outcome.run_id,outcome.receipt_digest)
            self.assertEqual(checked.payload,expected.payload);self.assertEqual(checked.exit_code,0)
            self.assertEqual(checked.payload['receipt_digest'],outcome.receipt_digest)
            if outcome.run_id=='synthetic-reuse':
                self.assertIsNone(checked.payload['intent_digest']);self.assertIsNone(checked.payload['effect_plan_digest'])
                self.assertNotEqual(outcome.receipt_digest,first.receipt_digest)

    def test_actual_host_wrong_literal_payload_or_current_receipt_fail_closed(self):
        first=self.execute();reuse=self.execute('synthetic-reuse')
        for change,code in [({'request_id':'different-request'},'inspection.captured_candidate_mismatch'),
                ({'target_locator':'objects/other.bin'},'inspection.captured_candidate_mismatch'),
                ({'expected_digest':'sha256:'+'f'*64},'inspection.captured_input_mismatch')]:
            with self.subTest(change=change):
                response=self.inspect_response(reuse.run_id,reuse.receipt_digest,**change)
                self.assertFalse(response.payload['success']);self.assertEqual(response.payload['error'],code)
        for pin in ('sha256:'+'e'*64,first.receipt_digest):
            with self.subTest(pin=pin),self.assertRaisesRegex(PhaseError,'ntfs.file_publication_receipt_mismatch'):
                self.inspect_response(reuse.run_id,pin)
        # Null expected content is no independently observed CURRENT source read.
        self.source.write_bytes(b'different-current-source-after-ACK')
        self.assertTrue(self.inspect_response(reuse.run_id,reuse.receipt_digest,expected_digest=None).payload['success'])

    def test_synthetic_fresh_read_success_does_not_clear_uncertain_execute_owner(self):
        outcome=self.execute();read=self.inspect_response(outcome.run_id,outcome.receipt_digest).payload
        old=NativePreparedMCPTests.owner(self);fresh=NativePreparedMCPTests.owner(self)
        uncertain=NativePreparedMCPTests.unknown(self,run=outcome.run_id)
        held,new=object(),object()
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=[held,new]) as factory,
                patch.object(inspection_mcp,'run_native_parent',side_effect=[
                    {'result':uncertain,'exit_code':uncertain['exit_code']},{'result':read,'exit_code':0}])):
            self.assertIs(old.execute_file_publication(run_id=outcome.run_id,source_locator='source.bin',
                target_locator='objects/result.bin',request_id='synthetic-request'),uncertain)
            self.assertTrue(old._unavailable);self.assertIs(old._held_launch,held)
            self.assertIs(fresh.inspect_prepared(run_id=outcome.run_id,request_id='synthetic-request',
                target_locator='objects/result.bin',expected_digest=digest_bytes(self.payload),
                expected_receipt_digest=outcome.receipt_digest),read)
            self.assertTrue(old._unavailable);self.assertIs(old._held_launch,held)
            with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):old.inspect(outcome.run_id)
            self.assertEqual(factory.call_count,2)


class NativeBundle2PreparedMCPRouteTests(unittest.TestCase):
    """Modeled startup/process only; genuine B2 selector and result validation.

    These component tests do not construct an accepted installation, run Core,
    create a native process or demonstrate NTFS/qualification properties.
    """
    def setup_route(self):
        from .test_native_prepared_ack_test_seam import launch_shell
        launch,_=launch_shell()
        admission=launch._experimental_admission_context
        startup=dict(config_bytes=b'',expected_config_digest=None,
            manifest_bytes=launch._manifest_bytes,expected_manifest_digest=None,
            _experimental_admission_context=admission)
        owner=inspection_mcp._InspectionMCPCallOwner(**startup)
        run=launch.invocation['run_id']
        args=NativePreparedMCPTests().args(run)
        value={'stage3_command_result_version':'1.0','command':'execute','success':True,
            'run_id':run,'terminal_status':'succeeded_verified','execution_disposition':'executed',
            'mutation_attempted':True,'effect_plan_digest':'sha256:'+'a'*64,
            'intent_digest':'sha256:'+'b'*64,'receipt_digest':'sha256:'+'c'*64,
            'blockers':[],'error':None,'exit_code':0,'target_verified':True}
        response={'protocol':'phase.native.command','version':'1.0','channel_id':launch.channel_id,
            'run_id':run,'result':value,'exit_code':0}
        registry=installation._native_experimental_bundle2_registry_v3()
        return owner,launch,args,response,registry,startup

    def test_exact_b2_execute_retains_original_result_and_checked_receipt(self):
        owner,launch,args,response,registry,_=self.setup_route()
        original=canonical_bytes(response)
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch)as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value=response)as parent,
                patch.object(installation,'_native_registry_for_launch',return_value=registry)as selection):
            self.assertIs(owner.execute_prepared(**args),response['result'])
            self.assertEqual(canonical_bytes(response),original)
            self.assertIs(factory.call_args.kwargs['_experimental_admission_context'],
                launch._experimental_admission_context)
            self.assertIs(factory.call_args.kwargs['_inspection_only'],False)
            parent.assert_called_once_with(launch);selection.assert_called_once_with(launch)
        self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_exact_b2_uncertain_execute_is_unchanged_and_keeps_actual_launch(self):
        owner,launch,args,response,registry,_=self.setup_route()
        response['result']=NativePreparedMCPTests().unknown(args['run_id'])
        response['result']['run_id']=None
        response['exit_code']=response['result']['exit_code']
        original=canonical_bytes(response['result'])
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch)as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value=response),
                patch.object(installation,'_native_registry_for_launch',return_value=registry)):
            result=owner.execute_prepared(**args)
            self.assertEqual(canonical_bytes(result),original)
            self.assertIsNone(result['receipt_digest']);self.assertFalse(result['retry_authorized'])
            self.assertTrue(owner._unavailable);self.assertIs(owner._held_launch,launch)
            with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):
                owner.execute_prepared(**args)
            factory.assert_called_once()

    def test_b2_foreign_command_run_channel_or_exit_poison_without_retry(self):
        changes=[{'result':{'command':'inspect'}},{'result':{'run_id':'synthetic-foreign'}},
            {'channel_id':'f'*32},{'run_id':'synthetic-foreign'},{'exit_code':True},
            {'exit_code':10},{'result':{'receipt_digest':'not-a-digest'}},{'extra':'field'}]
        for change in changes:
            owner,launch,args,response,registry,_=self.setup_route()
            if 'result'in change:response['result'].update(change['result'])
            else:response.update(change)
            with (self.subTest(change=change),
                    patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch)as factory,
                    patch.object(inspection_mcp,'run_native_parent',return_value=response),
                    patch.object(installation,'_native_registry_for_launch',return_value=registry)):
                with self.assertRaises(Exception):owner.execute_prepared(**args)
                self.assertTrue(owner._unavailable);self.assertIs(owner._held_launch,launch)
                with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):
                    owner.inspect(args['run_id'])
                factory.assert_called_once()

    def test_b2_prepared_server_has_only_prepared_execute_and_unary_inspect(self):
        _,_,_,_,_,startup=self.setup_route()
        with patch.object(inspection_mcp,'_NativeAcceptedLaunch')as factory:
            server=inspection_mcp._prepared_server(**startup)
            tools=server._tool_manager.list_tools()
            self.assertEqual([t.name for t in tools],['phase_execute_prepared','phase_inspect'])
            self.assertEqual(set(tools[1].parameters['properties']),{'run_id'})
            self.assertTrue(all(t.parameters['additionalProperties']is False for t in tools))
            self.assertNotIn('_experimental_admission_context',tools[0].parameters['properties'])
            factory.assert_not_called()

    def test_prepared_server_foreign_admission_fails_before_server_or_launch(self):
        from phase_tool.mutation.ntfs.experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
        class ForeignAdmission(_ExperimentalBundle2AdmissionV3):pass
        _,_,_,_,_,startup=self.setup_route()
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch')as factory,
                patch.object(inspection_mcp,'FastMCP')as server):
            for admission in (object(),{},ForeignAdmission(b'{}')):
                with self.subTest(admission=type(admission).__name__),self.assertRaisesRegex(
                        PhaseError,'ntfs.experimental_admission_required'):
                    inspection_mcp._prepared_server(**(startup|{'_experimental_admission_context':admission}))
            factory.assert_not_called();server.assert_not_called()

    def test_native_prepared_entrypoint_forwards_only_explicit_fixed_admission(self):
        _,_,_,_,_,startup=self.setup_route()
        for experimental in (False,True):
            with self.subTest(experimental=experimental),patch.object(inspection_mcp,'_prepared_server')as factory:
                supplied=startup if experimental else {k:v for k,v in startup.items()
                    if k!='_experimental_admission_context'}
                self.assertEqual(inspection_mcp.run_native_prepared_mcp(**supplied),0)
                factory.assert_called_once_with(**supplied)
                factory.return_value.run.assert_called_once_with(transport='stdio')


# Test-client projection only: the public server's bare-dict ABI is unchanged.
def _component_native_inspect_projection(result,tool,*,run_id,intent_digest,effect_plan_digest,proof_digest):
    from jsonschema import Draft202012Validator
    def require(ok,message):
        if not ok:raise ValueError(message)
    require(type(result)is dict and result['isError']is False and result['structuredContent']is None
        and tool['name']=='phase_inspect'and tool['outputSchema']is None,'exact unstructured inspect ABI')
    content=result['content']
    require(type(content)is list and len(content)==1 and content[0]['type']=='text'
        and type(content[0]['text'])is str,'one complete JSON TextContent')
    payload=parse_json_bytes(content[0]['text'].encode('utf-8'),maximum_bytes=2*1024**2)
    schema=json.loads(resources.files('phase_tool').joinpath('data/schemas/stage3-command-result-1.3.schema.json').read_bytes())
    Draft202012Validator(schema).validate(payload)
    require(payload['run_id']==run_id and payload['intent_digest']==intent_digest
        and payload['effect_plan_digest']==effect_plan_digest and payload['recovery']['proof_digest']==proof_digest,
        'exact component original/recovery bindings')
    require(payload['success']is True and payload['exit_code']==0 and payload['target_verified']is True
        and all(payload[k]is None for k in('receipt_digest','terminal_status','execution_disposition','mutation_attempted'))
        and payload['recovery']['original_receipt_preserved']is True,'positive inspection preserves missing original receipt/facts')
    return payload


class NativeRecoveryMCPABIComponentTests(unittest.TestCase):
    """Actual SDK conversion, synthetic owner; no Windows/Core/qualification claim."""
    RUN='synthetic-native-mcp-component'
    INTENT='sha256:'+'a'*64
    PLAN='sha256:'+'b'*64
    PROOF='sha256:'+'c'*64

    def inspect_payload(self):
        return {'stage3_command_result_version':'1.3','command':'inspect','success':True,
            'run_id':self.RUN,'terminal_status':None,'execution_disposition':None,'mutation_attempted':None,
            'effect_plan_digest':self.PLAN,'intent_digest':self.INTENT,'receipt_digest':None,
            'blockers':[],'error':None,'exit_code':0,'target_verified':True,
            'recovery':{'native_bundle_recovery_proof_version':'1.0','operation':'commit_prepared',
                'proof_digest':self.PROOF,'original_receipt_preserved':True}}

    def inspect_result(self,payload=None):
        return {'isError':False,'structuredContent':None,
            'content':[{'type':'text','text':json.dumps(self.inspect_payload()if payload is None else payload,indent=2)}]}

    def project(self,result,tool=None):
        return _component_native_inspect_projection(result,
            {'name':'phase_inspect','outputSchema':None}if tool is None else tool,
            run_id=self.RUN,intent_digest=self.INTENT,effect_plan_digest=self.PLAN,proof_digest=self.PROOF)

    def recovery_payload(self,*,observe=False):
        from phase_tool.recovery import NativeRecoveryResult
        values={'run_id':self.RUN,'request_id':self.RUN,'intent_digest':self.INTENT,
            'effect_plan_digest':self.PLAN,'original_receipt_digest':None,'original_terminal_status':None,
            'recovery_mode':'observe'if observe else'commit_prepared'}
        if not observe:values.update(status='verified_existing',success=True,target_verified=True,
            recovery_mutation_attempted=True,recovery_effect_state='committed',
            lock_finalization={'unlock':'succeeded','close':'succeeded'},inspection_required=False,
            observation_digest='sha256:'+'d'*64,observation_path='recovery/observations/'+'d'*64+'.json',
            commit_finalization_verified=True,exit_code=0)
        return NativeRecoveryResult(**values).model_dump(mode='json')

    def test_strict_text_projection_accepts_pretty_json_without_fabricated_structured_content(self):
        result=self.inspect_result();before=deepcopy(result)
        self.assertEqual(self.project(result),self.inspect_payload())
        self.assertEqual(result,before);self.assertIsNone(result['structuredContent'])

    def test_inspect_error_structured_wrapper_or_multiple_blocks_are_never_a_fallback(self):
        variants=[]
        for change in ({'isError':True},{'structuredContent':self.inspect_payload()},
                {'structuredContent':{'result':self.inspect_payload()}},
                {'content':[{'type':'image','text':'not text'}]},
                {'content':self.inspect_result()['content']*2}):
            variants.append(self.inspect_result()|change)
        for result in variants:
            with self.subTest(result=result),self.assertRaises(ValueError):self.project(result)
        with self.assertRaises(ValueError):
            self.project(self.inspect_result(),{'name':'phase_inspect','outputSchema':{'type':'object'}})

    def test_duplicate_float_nonfinite_or_nonobject_json_refuse_before_positive_projection(self):
        from jsonschema.exceptions import ValidationError
        texts=['{"run_id":"a","run_id":"b"}','{"exit_code":0.0}',
            '{"exit_code":NaN}','{"exit_code":Infinity}','[]','not json']
        for text in texts:
            result=self.inspect_result();result['content'][0]['text']=text
            with self.subTest(text=text),self.assertRaises((PhaseError,ValidationError)):self.project(result)

    def test_foreign_native_schema_lineage_or_original_receipt_is_rejected(self):
        from jsonschema.exceptions import ValidationError
        cases=[]
        for key,value in [('run_id','synthetic-foreign'),('intent_digest','sha256:'+'1'*64),
                ('effect_plan_digest','sha256:'+'2'*64),('receipt_digest','sha256:'+'3'*64),
                ('stage3_command_result_version','1.0'),('unexpected','field')]:
            cases.append(self.inspect_payload()|{key:value})
        wrong=self.inspect_payload();wrong['recovery']['proof_digest']='sha256:'+'4'*64;cases.append(wrong)
        for payload in cases:
            with self.subTest(payload=payload),self.assertRaises((ValueError,ValidationError)):
                self.project(self.inspect_result(payload))

    def test_real_sdk_keeps_unstructured_inspect_and_flat_typed_recovery_distinct(self):
        async def exchange():
            from mcp import ClientSession,StdioServerParameters
            from mcp.client.stdio import stdio_client
            from jsonschema import Draft202012Validator
            from phase_tool.recovery import NativeRecoveryResult
            import phase_tool
            root=Path(phase_tool.__file__).resolve(strict=True).parent.parent
            # A process-local component owner supplies explicit synthetic results.
            # Real tool decorators/closed arguments/SDK framing and conversion run;
            # no accepted startup, Core, native I/O or physical proof is simulated.
            code=("from unittest.mock import patch\n"
                "from phase_tool.application import PhaseApplication\n"
                "from phase_tool.evidence import EvidenceStore\n"
                "from phase_tool.mutation.ntfs import bundle_recovery_mcp as adapter,inspection_mcp\n"
                "from phase_tool.errors import PhaseError\n"
                'RUN='+repr(self.RUN)+'\nINSPECT='+repr(self.inspect_payload())+'\n'
                'RECOVER='+repr(self.recovery_payload())+'\nOBSERVE='+repr(self.recovery_payload(observe=True))+'\n'+
                "class ComponentOwner:\n"
                " def __init__(self,**unused):pass\n"
                " def inspect(self,run_id):\n"
                "  if run_id=='synthetic-sdk-error':raise PhaseError('synthetic.mcp_component_failure')\n"
                "  if run_id!=RUN:raise AssertionError('COMPONENT_OWNER_REACHED_INVALID')\n"
                "  return INSPECT\n"
                " def _call(self,run_id,request,*,inspection_only):\n"
                "  if run_id!=RUN or inspection_only:raise AssertionError('COMPONENT_OWNER_REACHED_INVALID')\n"
                "  return OBSERVE if request['mode']=='observe' else RECOVER\n"
                "adapter._InspectionMCPCallOwner=ComponentOwner\n"
                "with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=AssertionError('REAL_NATIVE_BOUNDARY_FORBIDDEN')),\n"
                " patch.object(inspection_mcp,'run_native_parent',side_effect=AssertionError('REAL_NATIVE_BOUNDARY_FORBIDDEN')),\n"
                " patch.object(PhaseApplication,'recover_publication',side_effect=AssertionError('REAL_CORE_BOUNDARY_FORBIDDEN')),\n"
                " patch.object(EvidenceStore,'__init__',side_effect=AssertionError('REAL_STORE_BOUNDARY_FORBIDDEN'))):\n"
                " adapter.run_native_recovery_mcp()\n")
            env=os.environ.copy();env.update(PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1')
            async with stdio_client(StdioServerParameters(command=sys.executable,args=['-B','-c',code],env=env))as(reader,writer):
                async with ClientSession(reader,writer)as session:
                    initialized=await session.initialize();self.assertTrue(initialized.protocolVersion)
                    listed=await session.list_tools();tools={t.name:t for t in listed.tools}
                    self.assertEqual(len(listed.tools),2)
                    self.assertEqual(set(tools),{'phase_recover_publication','phase_inspect'})
                    self.assertIsNone(tools['phase_inspect'].outputSchema)
                    self.assertEqual(set(tools['phase_inspect'].inputSchema['properties']),{'run_id'})
                    self.assertIsInstance(tools['phase_recover_publication'].outputSchema,dict)
                    self.assertEqual(set(tools['phase_recover_publication'].inputSchema['properties']),
                        {'run_id','request_id','expected_intent_digest','mode'})
                    self.assertTrue(all(t.inputSchema['additionalProperties']is False for t in tools.values()))
                    rejected=await session.call_tool('phase_inspect',{'run_id':self.RUN,'provider':'forbidden'})
                    self.assertTrue(rejected.isError)
                    rejected=await session.call_tool('phase_inspect',{'run_id':True})
                    self.assertTrue(rejected.isError)
                    self.assertNotIn('COMPONENT_OWNER_REACHED_INVALID',' '.join(getattr(c,'text','')for c in rejected.content))
                    recovered=await session.call_tool('phase_recover_publication',{'run_id':self.RUN,'request_id':self.RUN,
                        'expected_intent_digest':self.INTENT,'mode':'commit_prepared'})
                    actual=recovered.model_dump(mode='json',by_alias=True)
                    self.assertFalse(actual['isError']);self.assertEqual(actual['structuredContent'],self.recovery_payload())
                    self.assertNotIn('result',actual['structuredContent'])
                    self.assertEqual(len(actual['content']),1)
                    self.assertEqual(json.loads(actual['content'][0]['text']),actual['structuredContent'])
                    NativeRecoveryResult.model_validate(actual['structuredContent'])
                    schema=json.loads(resources.files('phase_tool').joinpath('data/schemas/recovery-result-1.2.schema.json').read_bytes())
                    Draft202012Validator(schema).validate(actual['structuredContent'])
                    inspected=await session.call_tool('phase_inspect',{'run_id':self.RUN})
                    # Retain the actual SDK model before any projection/validation.
                    original=inspected.model_dump(mode='json',by_alias=True)
                    self.assertEqual(self.project(original,tools['phase_inspect'].model_dump(mode='json',by_alias=True)),self.inspect_payload())
                    self.assertIsNone(original['structuredContent'])
                    negative=await session.call_tool('phase_recover_publication',{'run_id':self.RUN,'request_id':self.RUN,
                        'expected_intent_digest':self.INTENT,'mode':'observe'})
                    self.assertFalse(negative.isError) # Business-negative result, not SDK error.
                    self.assertEqual(negative.structuredContent,self.recovery_payload(observe=True))
                    self.assertFalse(negative.structuredContent['success']);self.assertEqual(negative.structuredContent['exit_code'],40)
                    sdk_error=await session.call_tool('phase_inspect',{'run_id':'synthetic-sdk-error'})
                    self.assertTrue(sdk_error.isError);self.assertIsNone(sdk_error.structuredContent)
                    with self.assertRaises(ValueError):self.project(sdk_error.model_dump(mode='json',by_alias=True))
        asyncio.run(asyncio.wait_for(exchange(),timeout=30))
