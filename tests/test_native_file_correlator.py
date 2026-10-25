"""File1 two-call composition on Linux: real Host/Core and synthetic native transport.

No native qualification guard is replaced. The process/factory boundary is
synthetic; Host receipts are real only for the explicitly qualified Linux roots.
Nothing here qualifies Windows, NTFS, A05/G01 or a supported native release.
"""
import asyncio
from copy import deepcopy
import os
from pathlib import Path
import sys,threading,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.command_result import validate_command_result
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import entrypoint,inspection_mcp
from phase_tool.publish_file import (
    _native_file_publication_ack,_native_file_publication_inspected,
    _PUBLICATION_EVIDENCE_FIELDS)
from . import test_native_file_result_delivery as delivery
from . import test_native_prepared_mcp as prepared

@unittest.skipUnless(sys.platform.startswith('linux'),'Linux software composition boundary')
class NativeFilePublicationCorrelatorTests(unittest.TestCase):
    def args(self,run=delivery.RUN,**changes):
        return dict(run_id=run,source_locator='inputs/source.bin',
            target_locator='objects/result.bin',request_id='synthetic-request',
            expected_digest=digest_bytes(delivery.PAYLOAD))|changes

    def owner(self,p=None):
        p=p or delivery.protocol()
        return inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',
            expected_config_digest=None,manifest_bytes=p.raw,
            expected_manifest_digest=digest_bytes(p.raw))

    def ack(self,p):
        return p.result|{'command':'execute','target_verified':None}

    def transport(self,p,ack=None,*,inspect_error=None,inspect_change=None):
        """Factory/process substitution only; real validators/gate stay active."""
        launches=[]
        def launch(**kwargs):
            value=SimpleNamespace(invocation=parse_json_bytes(kwargs['invocation_bytes']),
                inspection_only=kwargs['_inspection_only'])
            launches.append(value);return value
        def run(value):
            inv=value.invocation;request=inv['request']
            if request['operation']=='execute':
                return {'result':ack if ack is not None else self.ack(p),
                    'exit_code':(ack if ack is not None else self.ack(p))['exit_code']}
            if inspect_error is not None:raise inspect_error
            frame=deepcopy(p.frame)
            frame.update(run_id=inv['run_id'],channel_id=inv['channel_id'])
            if inspect_change is not None:inspect_change(frame)
            return frame
        return launch,run,launches

    def invoke(self,owner,p,ack=None,**options):
        launch,run,launches=self.transport(p,ack,**options)
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launch),
              patch.object(inspection_mcp,'run_native_parent',side_effect=run) as dispatched):
            result=owner.publish_file(**self.args())
        return result,launches,dispatched

    def assert_ack(self,result,ack):
        for name in ('receipt_digest','intent_digest','effect_plan_digest',
                'execution_disposition','mutation_attempted'):
            self.assertEqual(result[name],ack[name],name)

    def test_positive_two_launches_same_gate_four_fresh_tokens_and_current_pin(self):
        p=delivery.protocol();owner=self.owner(p)
        launch,run,launches=self.transport(p)
        def guarded(value):
            self.assertFalse(owner._gate.acquire(blocking=False),'same gate must remain held')
            return run(value)
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launch),
              patch.object(inspection_mcp,'run_native_parent',side_effect=guarded) as dispatched,
              patch('secrets.token_hex',side_effect=['a'*32,'b'*32,'c'*32,'d'*32])):
            result=owner.publish_file(**self.args())
        self.assertEqual(dispatched.call_count,2)
        self.assertEqual([v.inspection_only for v in launches],[False,True])
        self.assertEqual([v.invocation['channel_id'] for v in launches],['a'*32,'c'*32])
        self.assertEqual([v.invocation['operation_nonce'] for v in launches],['b'*32,'d'*32])
        self.assertEqual(launches[1].invocation['request']['expected_receipt_digest'],delivery.ACK)
        self.assertEqual(launches[1].invocation['request']['native_file_publication_inspection_request_version'],'1.1')
        self.assertTrue(result['success']);self.assertEqual(result['status'],'verified')
        self.assertTrue(result['target_verified']);self.assertEqual(result['content_digest'],digest_bytes(delivery.PAYLOAD))
        self.assertIs(owner._publication_ack['target_verified'],None)
        self.assertIsNone(owner._held_launch);self.assertFalse(owner._unavailable)

    def test_exact_seven_field_correlation_rejects_every_mismatch(self):
        p=delivery.protocol();ack=self.ack(p)
        for field in _PUBLICATION_EVIDENCE_FIELDS:
            with self.subTest(field=field):
                result={'run_id':delivery.RUN};self.assertTrue(_native_file_publication_ack(result,ack))
                changed=deepcopy(p.result)
                changed[field]=(not changed[field]) if field=='mutation_attempted' else (None if changed[field] is not None else 'different')
                with self.assertRaisesRegex(PhaseError,'publish_file.evidence_mismatch'):
                    _native_file_publication_inspected(result,ack,changed,p.reference)
                self.assertEqual(result['status'],'committed_unverified')

    def test_typed_nullable_and_partial_ack_uncertainty_retains_actual_launch_no_inspect(self):
        p=delivery.protocol()
        typed=prepared.NativePreparedMCPTests().unknown(delivery.RUN)
        nullable=typed|{'run_id':None}
        partial=self.ack(p)|{'success':False,'exit_code':20,'error':'synthetic.partial'}
        for ack in (typed,nullable,partial):
            with self.subTest(version=ack['stage3_command_result_version'],error=ack['error']):
                validate_command_result(ack,p.registry)
                before=canonical_bytes(ack);owner=self.owner(p)
                result,launches,dispatched=self.invoke(owner,p,ack)
                self.assertFalse(result['success']);self.assertEqual(result['status'],'indeterminate')
                self.assertEqual(result['exit_code'],40);self.assertTrue(result['inspection_required'])
                self.assert_ack(result,ack);self.assertEqual(canonical_bytes(ack),before)
                self.assertIs(owner._publication_ack,ack);self.assertIs(owner._held_launch,launches[0])
                self.assertTrue(owner._unavailable);self.assertEqual(dispatched.call_count,1)
                with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                      patch.object(inspection_mcp,'run_native_parent') as parent):
                    with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):
                        owner.publish_file(**self.args())
                    with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):
                        owner.inspect(delivery.RUN)
                    factory.assert_not_called();parent.assert_not_called()

    def test_invalid_legacy_nullable_ack_is_not_projected_as_validated_evidence(self):
        from jsonschema.exceptions import ValidationError
        p=delivery.protocol();ack=self.ack(p)|{'mutation_attempted':None}
        with self.assertRaises(ValidationError):validate_command_result(ack,p.registry)
        owner=self.owner(p);result,launches,dispatched=self.invoke(owner,p,ack)
        self.assertEqual(result['status'],'indeterminate');self.assertEqual(result['exit_code'],40)
        self.assertFalse(result['success']);self.assertIsNone(owner._publication_ack)
        self.assertIsNone(result['receipt_digest']);self.assertIsNone(result['intent_digest'])
        self.assertIsNone(result['effect_plan_digest']);self.assertIsNone(result['mutation_attempted'])
        self.assertIs(owner._held_launch,launches[0]);self.assertTrue(owner._unavailable)
        self.assertEqual(dispatched.call_count,1)

    def test_known_prewrite_refusal_preserves_null_fields_and_does_not_inspect(self):
        p=delivery.protocol();ack=PhaseApplication(registry=p.registry)._failure(
            'execute',PhaseError('synthetic.refused')).payload
        owner=self.owner(p);result,launches,dispatched=self.invoke(owner,p,ack)
        self.assertEqual(result['status'],'rejected_before_write');self.assertEqual(result['exit_code'],10)
        self.assertFalse(result['inspection_required']);self.assertFalse(result['success'])
        self.assert_ack(result,ack);self.assertEqual(dispatched.call_count,1)
        self.assertIsNone(owner._held_launch);self.assertFalse(owner._unavailable)

    def test_contradictory_schema_valid_positive_ack_never_inspects_or_succeeds(self):
        for change in ({'error':'synthetic.positive-error'},{'blockers':['synthetic.blocked']},
                {'exit_code':20},{'terminal_status':'validated_planned'}):
            with self.subTest(change=change):
                p=delivery.protocol();ack=self.ack(p)|change;validate_command_result(ack,p.registry)
                result,launches,dispatched=self.invoke(self.owner(p),p,ack)
                self.assertFalse(result['success']);self.assertEqual(result['status'],'committed_unverified')
                self.assertEqual(result['error'],'publish_file.evidence_mismatch')
                self.assert_ack(result,ack);self.assertEqual(dispatched.call_count,1)

    def test_wrong_current_receipt_reference_and_expected_hash_fail_before_success(self):
        def prior(frame):frame['result']['receipt_digest']='sha256:'+'e'*64
        def wrong_owner(frame):frame['canonical_result']['owner_id']='different.owner'
        def wrong_hash(frame):frame['canonical_result']['state']['digest']='sha256:'+'e'*64
        for change in (prior,wrong_owner,wrong_hash):
            with self.subTest(change=change.__name__):
                p=delivery.protocol();owner=self.owner(p)
                result,launches,dispatched=self.invoke(owner,p,inspect_change=change)
                self.assertEqual(result['status'],'committed_unverified');self.assertEqual(result['exit_code'],30)
                self.assertFalse(result['success']);self.assertTrue(owner._unavailable)
                self.assert_ack(result,self.ack(p));self.assertEqual(dispatched.call_count,2)
                self.assertIs(owner._held_launch,launches[1])

    def test_primary_inspect_error_survives_secondary_gate_release_error(self):
        p=delivery.protocol();owner=self.owner(p);primary=PhaseError('synthetic.primary-inspection')
        owner._gate=SimpleNamespace(acquire=Mock(return_value=True),
            release=Mock(side_effect=OSError('synthetic secondary release')))
        result,launches,_=self.invoke(owner,p,inspect_error=primary)
        self.assertEqual(result['error'],'synthetic.primary-inspection');self.assertEqual(result['exit_code'],30)
        self.assert_ack(result,self.ack(p));self.assertEqual(owner._publication_ack['receipt_digest'],p.result['receipt_digest'])
        self.assertTrue(any('Native MCP call gate' in v for v in primary.__notes__))
        self.assertTrue(owner._unavailable);self.assertIs(owner._held_launch,launches[1])

    def test_returned_typed_and_nullable_ack_error_survive_release_failure(self):
        p=delivery.protocol()
        typed=prepared.NativePreparedMCPTests().unknown(delivery.RUN)
        cases=[typed,typed|{'run_id':None},
            self.ack(p)|{'success':False,'exit_code':20,'error':'synthetic.partial'}]
        for ack in cases:
            with self.subTest(error=ack['error']):
                owner=self.owner(p);owner._gate=SimpleNamespace(acquire=Mock(return_value=True),
                    release=Mock(side_effect=OSError('synthetic secondary release')))
                result,launches,dispatched=self.invoke(owner,p,ack)
                self.assertEqual(result['error'],ack['error']);self.assertEqual(result['status'],'indeterminate')
                self.assertEqual(result['exit_code'],40);self.assert_ack(result,ack)
                self.assertIs(owner._held_launch,launches[0]);self.assertEqual(dispatched.call_count,1)
                self.assertTrue(owner._unavailable);self.assertFalse(result['success'])

    def test_success_then_release_fault_suppresses_verified_and_adds_gate_error(self):
        p=delivery.protocol();owner=self.owner(p)
        owner._gate=SimpleNamespace(acquire=Mock(return_value=True),
            release=Mock(side_effect=OSError('synthetic release')))
        result,_,_=self.invoke(owner,p)
        self.assertFalse(result['success']);self.assertFalse(result['target_verified'])
        self.assertEqual(result['status'],'committed_unverified');self.assertEqual(result['exit_code'],30)
        self.assertEqual(result['error'],'publish_file.gate_finalization_failed')
        self.assert_ack(result,self.ack(p));self.assertTrue(owner._unavailable)

    def test_model_or_canonical_rendering_failure_preserves_ack_and_plain_result(self):
        from phase_tool import publish_file as publication
        for point in ('model','canonical'):
            with self.subTest(point=point):
                p=delivery.protocol();owner=self.owner(p)
                launch,run,launches=self.transport(p)
                original=inspection_mcp.canonical_bytes
                def encode(value):
                    if type(value)is dict and value.get('publish_file_result_version')=='1.0':
                        raise OSError('synthetic canonical render')
                    return original(value)
                manager=(patch.object(publication.PublishFileResult,'model_validate',side_effect=OSError('synthetic model'))
                    if point=='model' else patch.object(inspection_mcp,'canonical_bytes',side_effect=encode))
                with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launch),
                      patch.object(inspection_mcp,'run_native_parent',side_effect=run),manager):
                    result=owner.publish_file(**self.args())
                self.assertIs(type(result),dict);self.assertFalse(result['success'])
                self.assertEqual(result['status'],'committed_unverified');self.assertEqual(result['exit_code'],30)
                self.assert_ack(result,self.ack(p));self.assertTrue(owner._unavailable)
                self.assertIsNotNone(owner._publication_ack)

    def test_raw_and_highlevel_contention_refuse_without_queue_or_dispatch(self):
        p=delivery.protocol();owner=self.owner(p)
        owner._gate.acquire()
        try:
            with (patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,
                  patch('secrets.token_hex') as nonce):
                for invoke in (lambda:owner.publish_file(**self.args()),
                        lambda:owner.execute_file_publication(**self.args()),
                        lambda:owner.inspect(delivery.RUN)):
                    with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_call_active'):invoke()
                factory.assert_not_called();nonce.assert_not_called()
        finally:owner._gate.release()
        self.assertFalse(owner._unavailable)

    def test_private_retention_mode_rejects_nonexecute_before_nonce_or_dispatch(self):
        p=delivery.protocol();owner=self.owner(p)
        for request,inspection in (({'operation':'inspect'},False),({'operation':'plan'},False),
                ({'operation':'execute'},True)):
            with self.subTest(request=request),patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory:
                with self.assertRaisesRegex(PhaseError,'ntfs.publication_retention_required'):
                    owner._call_locked(delivery.RUN,request,inspection_only=inspection,_retain_launch=True)
                factory.assert_not_called()

    def test_real_native_guard_refuses_before_any_preparation_source_or_channel(self):
        from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3
        from phase_tool.mutation.ntfs import preparation
        p=delivery.protocol();owner=self.owner(p)
        def launch(**kwargs):
            return SimpleNamespace(invocation=parse_json_bytes(kwargs['invocation_bytes']),
                _manifest_bytes=p.raw,installation_digest=digest_bytes(p.raw),
                run_id=delivery.RUN,channel_id='a'*32,operation_nonce='b'*32,
                check_runtime=Mock(),_inspection_only=False)
        def run(value):
            captured=[]
            def capture(frame,identities,*,_deadline=None):
                self.assertEqual(identities,'synthetic-pipes');captured.append(frame)
            with patch.object(entrypoint,'_deliver_linux_frame',side_effect=capture):
                self.assertEqual(entrypoint.run_native_core(value),10)
            self.assertEqual(len(captured),1)
            return captured[0]
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launch),
              patch.object(inspection_mcp,'run_native_parent',side_effect=run),
              patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
              patch.object(preparation,'_prepare_file_publication',side_effect=AssertionError('source reached')) as source,
              patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel reached')) as channel):
            result=owner.publish_file(**self.args())
        self.assertEqual(result['status'],'rejected_before_write')
        self.assertEqual(result['error'],'ntfs.native_profile_not_qualified')
        source.assert_not_called();channel.assert_not_called()

    def test_real_host_core_create_reuse_and_same_inspector_under_synthetic_process(self):
        from phase_tool import application
        owner_fixture=delivery.NativeFileResultHostTests(methodName='runTest')
        self.addCleanup(owner_fixture.doCleanups);fixture=owner_fixture.fixture()
        p=delivery.protocol()
        p.manifest.update(evidence_root=str(fixture.evidence),preparation_root=str(fixture.root/'preparation'),
            root_projections={'phase_result_root':str(fixture.target)})
        p.raw=canonical_bytes(p.manifest);owner=self.owner(p);acks=[];seals=[]
        def launch(**kwargs):
            return SimpleNamespace(invocation=parse_json_bytes(kwargs['invocation_bytes']))
        def run(value):
            inv=value.invocation;request=inv['request'];run_id=inv['run_id']
            if request['operation']=='execute':
                response=fixture.app.run('execute',contract_binding='file_create.v1@1.0.0',
                    candidate_path=fixture.candidate,evidence_root=fixture.evidence,run_id=run_id,
                    input_paths={'payload':fixture.source},root_bindings=fixture.request.root_bindings,
                    timestamp='2026-10-25T00:00:00Z')
                acks.append(response.payload);return {'result':response.payload,'exit_code':response.exit_code}
            authority=SimpleNamespace(seal=Mock());seals.append(authority.seal)
            context=dict(request=request,manifest_bytes=p.raw,expected_manifest_digest=digest_bytes(p.raw),
                registry=p.registry)
            response,reference=entrypoint._inspect_with_channel_seal(fixture.app,authority,
                evidence_root=fixture.evidence,run_id=run_id,root_bindings=fixture.request.root_bindings,
                _canonical_result_context=context,**entrypoint._native_file_inspection_expectations(request))
            return dict(protocol='phase.native.command',version='1.1',channel_id=inv['channel_id'],
                run_id=run_id,result=response.payload,exit_code=response.exit_code,canonical_result=reference)
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=launch),
              patch.object(inspection_mcp,'run_native_parent',side_effect=run),
              patch.object(application,'inspect_run',wraps=application.inspect_run) as inspected):
            for run_id in ('synthetic-create','synthetic-reuse'):
                result=owner.publish_file(**self.args(run_id,expected_digest=digest_bytes(fixture.payload)))
                self.assertTrue(result['success'],result);self.assertEqual(result['status'],'verified')
                self.assertEqual(result['receipt_digest'],acks[-1]['receipt_digest'])
                self.assertEqual(result['content_digest'],digest_bytes(fixture.payload))
                self.assertEqual(result['content_length'],len(fixture.payload))
            self.assertEqual(inspected.call_count,2)
        self.assertNotEqual(acks[0]['receipt_digest'],acks[1]['receipt_digest'])
        self.assertIsNone(acks[1]['intent_digest']);self.assertIsNone(acks[1]['effect_plan_digest'])
        for seal in seals:seal.assert_called_once_with(intent_digest=None)
        self.assertEqual((fixture.target/'objects/result.bin').read_bytes(),fixture.payload)


    def test_invalid_locators_digest_and_identity_fail_before_nonce_or_launch(self):
        p=delivery.protocol();owner=self.owner(p)
        for change in ({'source_locator':'../outside'},{'target_locator':'../outside'},
                {'request_id':'INVALID ID'},{'expected_digest':'sha256:'+'F'*64}):
            with self.subTest(change=change),patch.object(inspection_mcp,'_NativeAcceptedLaunch') as factory,patch('secrets.token_hex') as nonce:
                with self.assertRaises(PhaseError):owner.publish_file(**(self.args()|change))
                factory.assert_not_called();nonce.assert_not_called()
                self.assertFalse(owner._unavailable);self.assertIsNone(owner._held_launch)

    def test_real_sdk_closed_highlevel_schema_and_legacy_unary_toolset(self):
        async def exchange(factory,legacy):
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
                    else:
                        self.assertEqual([t.name for t in tools],['phase_execute_prepared',
                            'phase_execute_file_publication','phase_publish_file','phase_execute_version1_publication','phase_inspect'])
                        schema=tools[2].inputSchema
                        self.assertEqual(set(schema['properties']),set(self.args()))
                        self.assertEqual(set(schema['required']),{'run_id','source_locator','target_locator','request_id'})
                        self.assertIs(schema['additionalProperties'],False)
                        for change in ({'run_id':1},{'source_locator':True},{'expected_digest':17},
                                {'target_root':'/forbidden'},{'provider':'forbidden'},{'contract_binding':'forbidden'}):
                            result=await session.call_tool('phase_publish_file',self.args()|change)
                            self.assertTrue(result.isError,change)
        async def both():
            await exchange('_prepared_server',False);await exchange('_inspection_server',True)
        asyncio.run(asyncio.wait_for(both(),timeout=30))

if __name__=='__main__':unittest.main()
