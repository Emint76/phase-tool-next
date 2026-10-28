"""Bound version1 inspection components; no accepted native qualification.

Protocol success tokens are synthetic, never receipts or NTFS proof. Host tests
use actual qualified Core and stored receipts. No native admission guard is
patched. No new journal, recovery, retry or timestamp repair is exercised.
"""
import asyncio
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from phase_tool import evidence,installation
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.command_result import validate_command_result
from phase_tool.core import PhaseCore
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import entrypoint,inspection_mcp,parent_result
from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3

RUN='synthetic-read'


class NativeVersion1InspectionTests(unittest.TestCase):
    def owner(self):
        from .test_native_version1_publication import NativeVersion1PublicationTests
        return NativeVersion1PublicationTests().owner()

    def args(self):
        return {'run_id':RUN,'request_id':'synthetic-version','target_locator':'documents/item.bin',
            'expected_current_digest':'sha256:'+'a'*64,'expected_digest':'sha256:'+'e'*64,
            'expected_receipt_digest':'sha256:'+'d'*64}

    def request(self,args=None):
        values=self.args()if args is None else args
        return inspection_mcp._version1_publication_inspection_request(**{
            k:v for k,v in values.items()if k!='run_id'})

    def token(self):
        # Protocol-only data, explicitly not a Core/native receipt.
        registry=installation._native_lifecycle_registry()
        value=PhaseApplication(registry=registry)._failure('inspect',PhaseError('synthetic.refused')).payload
        value.update(run_id=RUN,success=True,terminal_status='succeeded_verified',
            execution_disposition='executed',mutation_attempted=True,
            intent_digest='sha256:'+'b'*64,effect_plan_digest='sha256:'+'c'*64,
            receipt_digest=self.args()['expected_receipt_digest'],target_verified=True,
            blockers=[],error=None,exit_code=0)
        validate_command_result(value,registry)
        return value

    def parent(self,result,request=None):
        from .test_native_inspection import NativeInspectionParentTests
        value=NativeInspectionParentTests().parent(result)
        owner=self.owner()
        value._launch._manifest_bytes=owner._startup['manifest_bytes']
        value._launch.installation_digest=owner._startup['expected_manifest_digest']
        value._launch.invocation={'request':self.request()if request is None else request}
        value._version1=True;value._version2=False;value._channel_version='1.2'
        return value

    def test_separate_closed_grammar_and_exact_capture_use_prepublication_digest(self):
        from phase_tool.mutation.ntfs.preparation import _version1_publication_candidate
        args=self.args();request=self.request()
        candidate,_=_version1_publication_candidate(args['request_id'],args['target_locator'],
            args['expected_current_digest'])
        self.assertEqual(set(request),{'operation','native_version1_publication_inspection_request_version',
            'request_id','target_locator','expected_current_digest','expected_digest','expected_receipt_digest'})
        self.assertEqual(entrypoint._native_version1_inspection_expectations(request),{
            '_expected_candidate_digest':profile_digest('candidate',candidate),
            '_expected_frozen_input':('payload',args['expected_digest']),
            '_expected_receipt_digest':args['expected_receipt_digest']})
        self.assertNotIn('_expected_frozen_input',entrypoint._native_version1_inspection_expectations(
            request|{'expected_digest':None}))
        self.assertFalse(parent_result._native_file_result_mode(request))
        with self.assertRaises(PhaseError):entrypoint._native_file_inspection_expectations(request)
        self.assertEqual(entrypoint._native_file_inspection_expectations({'operation':'inspect'}),{})

    def test_invalid_literals_and_selectors_fail_before_gate_nonce_or_launch(self):
        owner=self.owner();owner._gate=SimpleNamespace(acquire=Mock(),release=Mock())
        changes=[{'run_id':'../outside'},{'request_id':True},{'request_id':'Bad'},
            {'target_locator':'con'},{'target_locator':'../outside'},{'expected_current_digest':None},
            {'expected_current_digest':'sha256:'+'A'*64},{'expected_digest':False},
            {'expected_receipt_digest':None},{'expected_receipt_digest':'sha256:'+'Z'*64}]
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as launch,
                patch('secrets.token_hex') as nonce):
            for change in changes:
                with self.subTest(change=change),self.assertRaises(PhaseError):
                    owner.inspect_version1_publication(**(self.args()|change))
            with self.assertRaises(TypeError):
                owner.inspect_version1_publication(**self.args(),source_locator='outside')
            launch.assert_not_called();nonce.assert_not_called()
        owner._gate.acquire.assert_not_called();owner._gate.release.assert_not_called()
        self.assertFalse(owner._unavailable)
        request=self.request()
        bad=[request|{'operation':'execute'},request|{'native_version1_publication_inspection_request_version':'2.0'},
            request|{'native_file_publication_inspection_request_version':'1.0'},
            {k:v for k,v in request.items()if k!='expected_current_digest'}]
        for value in bad:
            with self.subTest(request=value),self.assertRaises(PhaseError):
                entrypoint._native_version1_inspection_expectations(value)

    def test_shared_pure_delivery_pin_requires_strong_inspected_success_and_raw_failures_stay_exact(self):
        request=self.request();positive=self.token()
        for result in (positive,positive|{'execution_disposition':'reused_existing'}):
            self.assertIsNone(parent_result._require_version1_inspection_delivery(result,
                request=request,run_id=RUN,inspection_only=True))
        for change in ({'receipt_digest':'sha256:'+'f'*64},{'target_verified':None},
                {'terminal_status':'validated_planned'},{'error':'synthetic.error'},
                {'blockers':['synthetic.error']},{'exit_code':10}):
            with self.subTest(change=change),self.assertRaises(PhaseError):
                parent_result._require_version1_inspection_delivery(positive|change,
                    request=request,run_id=RUN,inspection_only=True)
        with self.assertRaisesRegex(PhaseError,'ntfs.fixed_inspection_role_required'):
            parent_result._require_version1_inspection_delivery(positive,
                request=request,run_id=RUN,inspection_only=False)
        failed=PhaseApplication()._failure('inspect',PhaseError('synthetic.original')).payload
        raw=canonical_bytes(failed)
        self.assertIsNone(parent_result._require_version1_inspection_delivery(failed,
            request=request,run_id=RUN,inspection_only=True))
        self.assertEqual(canonical_bytes(failed),raw)

    def test_parent_current_receipt_mismatch_is_rejected_before_finished(self):
        for change,ok in (({},True),({'receipt_digest':'sha256:'+'f'*64},False)):
            value=self.parent(self.token()|change)
            with self.subTest(change=change):
                if ok:
                    delivered=value.serve()
                    self.assertEqual(delivered['result'],self.token())
                    self.assertTrue(value._finished)
                else:
                    with self.assertRaisesRegex(PhaseError,'ntfs.version1_inspection_binding_mismatch'):
                        value.serve()
                    self.assertFalse(value._finished)
                value._pipe.seal.assert_not_called()

    def test_mcp_receipt_mismatch_retains_same_launch_and_poison_is_shared(self):
        owner=self.owner();launch=object()
        wrong=self.token()|{'receipt_digest':'sha256:'+'f'*64}
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch) as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value={'result':wrong,'exit_code':0}) as parent):
            with self.assertRaisesRegex(PhaseError,'ntfs.version1_inspection_binding_mismatch'):
                owner.inspect_version1_publication(**self.args())
            self.assertIs(owner._held_launch,launch);self.assertTrue(owner._unavailable)
            with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):
                owner.inspect(RUN)
            self.assertEqual(factory.call_count,1);self.assertEqual(parent.call_count,1)

    def test_bound_inspect_fresh_readonly_nonces_and_same_gate_without_queue(self):
        owner=self.owner();launches=[object(),object()];token=self.token()
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launches) as factory,
                patch.object(inspection_mcp,'run_native_parent',return_value={'result':token,'exit_code':0}),
                patch('secrets.token_hex',side_effect=['a'*32,'b'*32,'c'*32,'d'*32])):
            for _ in range(2):self.assertIs(owner.inspect_version1_publication(**self.args()),token)
        calls=factory.call_args_list;values=[parse_json_bytes(c.kwargs['invocation_bytes'])for c in calls]
        self.assertTrue(all(c.kwargs['_inspection_only']is True for c in calls))
        self.assertTrue(all(v['request']==self.request()for v in values))
        self.assertEqual([(v['channel_id'],v['operation_nonce'])for v in values],
            [('a'*32,'b'*32),('c'*32,'d'*32)])
        self.assertIsNone(owner._held_launch)
        owner._gate.acquire()
        try:
            with patch('secrets.token_hex')as nonce:
                with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_call_active'):
                    owner.inspect_version1_publication(**self.args())
                nonce.assert_not_called()
        finally:owner._gate.release()

    def test_real_native_guard_and_wrong_fixed_contract_refuse_before_reader_or_channel(self):
        request=self.request()
        registry=installation._native_lifecycle_registry()
        exact=registry.contract_bindings()['publish_new_version.v1@1.0.0']
        raw=canonical_bytes({'native_read_installation_version':'1.2',
            'registry_snapshot_digest':registry.digest,'contract':exact})
        launch=SimpleNamespace(_inspection_only=True,check_runtime=Mock(),
            invocation={'request':request},_manifest_bytes=raw,installation_digest=digest_bytes(raw),
            run_id=RUN,operation_nonce='a'*32,channel_id='b'*32)
        with (patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                patch.object(entrypoint,'_deliver_linux_frame')as deliver,
                patch.object(LinuxNativeChannelV2,'__init__',side_effect=AssertionError('channel'))as c2,
                patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel'))as c3,
                patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('evidence'))as store,
                patch.object(PhaseApplication,'inspect',side_effect=AssertionError('reader'))as reader):
            self.assertEqual(entrypoint.run_native_inspection(launch),10)
            self.assertEqual(deliver.call_args.args[0]['result']['error'],'ntfs.native_profile_not_qualified')
            c2.assert_not_called();c3.assert_not_called();store.assert_not_called();reader.assert_not_called()
        for version in ('1.1','1.2'):
            reg=(installation._native_inspection_file_create_registry()if version=='1.1'
                else installation._native_lifecycle_registry())
            bad=canonical_bytes({'native_read_installation_version':version,
                'registry_snapshot_digest':reg.digest,
                'contract':reg.contract_bindings()['file_create.v1@1.0.0']})
            launch._manifest_bytes=bad;launch.installation_digest=digest_bytes(bad)
            with (self.subTest(version=version),
                    patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
                    patch.object(installation,'_native_installation_for_manifest',
                        side_effect=AssertionError('factory reached'))as factory):
                with self.assertRaisesRegex(PhaseError,'ntfs.original_single_effect_required'):
                    entrypoint.run_native_inspection(launch)
                factory.assert_not_called()

    def test_receipt_mismatch_primary_survives_composed_secondary_seal_failure(self):
        from .test_native_composition_delivery import NativeComposedDeliveryTests
        component=NativeComposedDeliveryTests()
        with component.delivery(inspection=True,seal_failure=True)as fixture:
            args=self.args()|{'run_id':fixture.launch.run_id}
            token=self.token()|{'run_id':fixture.launch.run_id,'receipt_digest':'sha256:'+'f'*64}
            fixture.launch._invocation_bytes=canonical_bytes({'run_id':fixture.launch.run_id,
                'channel_id':'a'*32,'operation_nonce':'b'*32,'request':self.request(args)})
            owner=self.owner();fixture.launch._manifest_bytes=owner._startup['manifest_bytes']
            fixture.launch._manifest_digest=owner._startup['expected_manifest_digest']
            frame={'protocol':'phase.native.command','version':'1.0','channel_id':'a'*32,
                'run_id':fixture.launch.run_id,'result':token,'exit_code':0}
            fixture.pipe.receive_frame.return_value=canonical_bytes(frame),None
            fixture.witness.wait_for_exit.return_value={'worker_exit_established':True,'exit_code':0}
            with self.assertRaisesRegex(PhaseError,'ntfs.version1_inspection_binding_mismatch')as caught:
                entrypoint.run_native_parent(fixture.launch)
            self.assertIn('Native Core delivery finalization: PhaseError',caught.exception.__notes__)
            component.assert_finalized_once(fixture)

    @unittest.skipUnless(sys.platform.startswith('linux'),'Real Linux SDK subprocess')
    def test_real_sdk_closed_bound_inspect_and_unchanged_unary_readonly_server(self):
        async def exchange(factory,legacy=False):
            from mcp import ClientSession,StdioServerParameters
            from mcp.client.stdio import stdio_client
            import phase_tool
            root=Path(phase_tool.__file__).resolve(strict=True).parent.parent
            code=('from phase_tool.mutation.ntfs.inspection_mcp import '+factory+'; '+factory+
                "(config_bytes=b'',expected_config_digest=None,manifest_bytes=b'',"
                "expected_manifest_digest=None).run(transport='stdio')")
            env=os.environ.copy();env.update(PYTHONPATH=str(root),PYTHONDONTWRITEBYTECODE='1')
            async with stdio_client(StdioServerParameters(command=sys.executable,args=['-B','-c',code],env=env))as(reader,writer):
                async with ClientSession(reader,writer)as session:
                    await session.initialize();tools=(await session.list_tools()).tools
                    if legacy:
                        self.assertEqual([t.name for t in tools],['phase_inspect'])
                        self.assertEqual(set(tools[0].inputSchema['properties']),{'run_id'})
                        unknown=await session.call_tool('phase_inspect_version1_publication',self.args())
                        self.assertTrue(unknown.isError)
                        refused=await session.call_tool('phase_inspect',{'run_id':RUN})
                    else:
                        self.assertEqual([t.name for t in tools],['phase_execute_prepared',
                            'phase_execute_file_publication','phase_publish_file',
                            'phase_execute_version1_publication','phase_inspect_version1_publication','phase_inspect'])
                        schema=tools[4].inputSchema
                        self.assertEqual(set(schema['properties']),set(self.args()))
                        self.assertEqual(set(schema['required']),set(self.args())-{'expected_digest'})
                        self.assertIs(schema['additionalProperties'],False)
                        bad=[{'run_id':False},{'request_id':1},{'target_locator':'../outside'},
                            {'expected_current_digest':None},{'expected_digest':False},
                            {'expected_receipt_digest':True},{'expected_receipt_digest':'sha256:BAD'}]
                        bad.extend({key:'outside'}for key in('source_locator','evidence_root','registry',
                            'profile','target_root','operation','native_version1_publication_inspection_request_version'))
                        for change in bad:
                            response=await session.call_tool('phase_inspect_version1_publication',self.args()|change)
                            self.assertTrue(response.isError,change)
                            text=' '.join(getattr(c,'text','')for c in response.content)
                            self.assertNotIn('ntfs.accepted_launch_binding_required',text)
                            self.assertNotIn('ntfs.inspection_mcp_unavailable',text)
                        refused=await session.call_tool('phase_inspect_version1_publication',self.args())
                    self.assertTrue(refused.isError)
                    self.assertIn('ntfs.accepted_launch_binding_required',
                        ' '.join(getattr(c,'text','')for c in refused.content))
                    if not legacy:
                        blocked=await session.call_tool('phase_inspect',{'run_id':RUN})
                        self.assertTrue(blocked.isError)
                        self.assertIn('ntfs.inspection_mcp_unavailable',
                            ' '.join(getattr(c,'text','')for c in blocked.content))
        async def both():
            await exchange('_prepared_server');await exchange('_inspection_server',legacy=True)
        asyncio.run(asyncio.wait_for(both(),timeout=30))


@unittest.skipUnless(sys.platform.startswith('linux'),'Real qualified Host Core')
class Version1BoundInspectionHostTests(unittest.TestCase):
    def fixture(self):
        from .test_native_version1_publication import Version1HostPublicationTests
        fixture=Version1HostPublicationTests(methodName='runTest');self.addCleanup(fixture.doCleanups)
        return fixture.fixture()

    def args(self,request,before,after,receipt):
        return {'run_id':request.run_id,'request_id':'synthetic-version','target_locator':'documents/item.bin',
            'expected_current_digest':digest_bytes(before),'expected_digest':digest_bytes(after),
            'expected_receipt_digest':receipt}

    def inspect(self,request,args,seal_error=None):
        protocol=NativeVersion1InspectionTests()
        wire=protocol.request(args);authority=SimpleNamespace(seal=Mock(side_effect=seal_error))
        try:
            response=entrypoint._inspect_with_channel_seal(PhaseApplication(),authority,
                evidence_root=request.evidence_root,run_id=request.run_id,
                root_bindings=request.root_bindings,
                **entrypoint._native_version1_inspection_expectations(wire))
            parent_result._require_version1_inspection_delivery(response.payload,request=wire,
                run_id=request.run_id,inspection_only=True)
            return response
        finally:authority.seal.assert_called_once_with(intent_digest=None)

    def test_actual_host_version_and_exact_time_reuse_inspect_pin_each_current_receipt(self):
        request,target,_,current,before,after,_=self.fixture()
        first=PhaseCore().run(request,execute=True);self.assertEqual(first.exit_code,0,first.receipt)
        reused=PhaseCore().run(replace(request,run_id='synthetic-version-reuse'),execute=True)
        self.assertEqual(reused.receipt['execution_disposition'],'reused_existing')
        for outcome in(first,reused):
            req=replace(request,run_id=outcome.run_id)
            with patch('phase_tool.application.inspect_run',wraps=__import__(
                    'phase_tool.application',fromlist=['inspect_run']).inspect_run)as reader:
                result=self.inspect(req,self.args(req,before,after,outcome.receipt_digest))
                self.assertEqual(reader.call_count,1)
            ordinary=PhaseApplication().inspect(evidence_root=req.evidence_root,
                run_id=req.run_id,root_bindings=req.root_bindings)
            optional=self.inspect(req,self.args(req,before,after,outcome.receipt_digest)|{'expected_digest':None})
            self.assertEqual(optional.payload,ordinary.payload)
            self.assertEqual(result.payload,ordinary.payload)
            self.assertTrue(result.payload['success']);self.assertTrue(result.payload['target_verified'])
            self.assertEqual(result.payload['receipt_digest'],outcome.receipt_digest)
        req=replace(request,run_id=reused.run_id)
        self.assertNotEqual(first.receipt_digest,reused.receipt_digest)
        with self.assertRaisesRegex(PhaseError,'ntfs.file_publication_receipt_mismatch'):
            self.inspect(req,self.args(req,before,after,first.receipt_digest))
        from .test_publish_new_version import _archive_locator
        self.assertEqual(current.read_bytes(),after)
        self.assertEqual((target/_archive_locator(before)).read_bytes(),before)

    def test_each_caller_literal_mismatch_is_rejected_by_real_saved_core_evidence(self):
        request,_,_,_,before,after,_=self.fixture();outcome=PhaseCore().run(request,execute=True)
        self.assertEqual(outcome.exit_code,0,outcome.receipt);args=self.args(request,before,after,outcome.receipt_digest)
        for change in({'request_id':'different-version'},{'target_locator':'documents/other.bin'},
                {'expected_current_digest':digest_bytes(after)},{'expected_digest':'sha256:'+'f'*64}):
            with self.subTest(change=change):
                result=self.inspect(request,args|change)
                self.assertFalse(result.payload['success']);self.assertIsNot(result.payload['target_verified'],True)
                expected=('inspection.captured_input_mismatch'if'expected_digest'in change
                    else'inspection.captured_candidate_mismatch')
                self.assertEqual(result.payload['error'],expected)

    def test_planned_and_missing_original_are_not_success_and_seal_error_cannot_hide_receipt_mismatch(self):
        request,_,_,_,before,after,_=self.fixture()
        plan=PhaseCore().run(request,execute=False);self.assertEqual(plan.exit_code,0)
        result=self.inspect(request,self.args(request,before,after,plan.receipt_digest))
        self.assertFalse(result.payload['success'])
        self.assertEqual(result.payload['error'],'inspection.captured_request_unavailable')
        fresh=replace(request,run_id='synthetic-version-execute')
        outcome=PhaseCore().run(fresh,execute=True);self.assertEqual(outcome.exit_code,0,outcome.receipt)
        wrong=self.args(fresh,before,after,'sha256:'+'f'*64)
        with self.assertRaisesRegex(PhaseError,'ntfs.file_publication_receipt_mismatch')as caught:
            self.inspect(fresh,wrong,seal_error=OSError('synthetic secondary seal'))
        self.assertIn('Native inspection channel seal: OSError',caught.exception.__notes__)
        intent=fresh.evidence_root/'.phase/runs'/fresh.run_id/'intent.json'
        intent.unlink()  # Disposable own Host fixture only; retained receipt remains.
        missing=self.inspect(fresh,self.args(fresh,before,after,outcome.receipt_digest))
        self.assertFalse(missing.payload['success']);self.assertIsNot(missing.payload['target_verified'],True)
