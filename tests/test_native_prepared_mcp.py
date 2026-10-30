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
