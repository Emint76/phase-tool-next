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
from unittest.mock import Mock, patch

from phase_tool import evidence
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import entrypoint, inspection_mcp
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.mutation.ntfs.uncertainty import _NativeLifecycleUnresolved


class NativePreparedMCPTests(unittest.TestCase):
    def owner(self):
        return inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',expected_config_digest=None,
            manifest_bytes=b'',expected_manifest_digest=None)

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
                for call in (lambda:owner.execute_prepared(**self.args()),lambda:owner.inspect('synthetic-read')):
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
                    for call in (lambda:owner.execute_prepared(**self.args()),lambda:owner.inspect('synthetic-read')):
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
            invocation={'request':request},_manifest_bytes=b'',installation_digest=None,
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
                    self.assertEqual([t.name for t in tools],['phase_execute_prepared','phase_inspect'])
                    schema=tools[0].inputSchema
                    self.assertEqual(set(schema['properties']),set(self.args()))
                    self.assertEqual(set(schema['required']),{'run_id','candidate_path','input_paths'})
                    self.assertIs(schema['additionalProperties'],False)
                    self.assertIs(tools[1].inputSchema['additionalProperties'],False)
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
