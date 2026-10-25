"""Native file1 result-delivery components, never NTFS qualification.

Protocol-only tokens below are synthetic data, not receipts or physical proof.
The separate Host tests use real Core/receipts on already qualified Linux/ext4.
Accepted launcher/OS/framed process facts are synthetic in composed tests; the
real native qualification guard remains closed and is never replaced.
"""
from copy import deepcopy
from types import SimpleNamespace
import sys,threading,unittest
from unittest.mock import Mock,patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.command_result import validate_command_result
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import entrypoint,inspection_mcp,parent
from phase_tool.mutation.ntfs.parent_result import (
    validate_native_file_inspection_result,validate_native_file_result_delivery)
from ._native_history_fixture import manifests
from . import test_native_prepared_mcp as host_fixtures
from . import test_native_composition_delivery as composition

RUN='synthetic-delivery'
CHANNEL='a'*32
ACK='sha256:'+'d'*64
PAYLOAD=b'synthetic-protocol-input\x00\xff'


def protocol():
    registry,(manifest,_)=manifests()
    raw=canonical_bytes(manifest)
    request=inspection_mcp._file_publication_inspection_request(
        'synthetic-request','objects/result.bin',digest_bytes(PAYLOAD),ACK,
        _include_canonical_result=True)
    result=PhaseApplication(registry=registry)._failure('inspect',PhaseError('synthetic.refused')).payload
    result.update(run_id=RUN,success=True,terminal_status='succeeded_verified',
        execution_disposition='executed',mutation_attempted=True,
        intent_digest='sha256:'+'b'*64,effect_plan_digest='sha256:'+'c'*64,
        receipt_digest=ACK,target_verified=True,blockers=[],error=None,exit_code=0)
    reference={'reference_version':'1.0','owner_id':'file.create.owner',
        'root_binding':'phase_result_root','locator':'objects/result.bin',
        'contract':deepcopy(manifest['contract']),'authority_rule':'authority.exclusive_create_v1',
        'state':{'exists':True,'digest':digest_bytes(PAYLOAD),'length':len(PAYLOAD),'head_token':None},
        'observed_at':'2026-10-01T00:00:00Z'}
    frame={'protocol':'phase.native.command','version':'1.1','channel_id':CHANNEL,
        'run_id':RUN,'result':result,'exit_code':0,'canonical_result':reference}
    context={'request':request,'run_id':RUN,'manifest_bytes':raw,
        'expected_manifest_digest':digest_bytes(raw),'registry':registry}
    return SimpleNamespace(registry=registry,manifest=manifest,raw=raw,
        request=request,result=result,reference=reference,frame=frame,context=context)


@unittest.skipUnless(sys.platform.startswith('linux'),'Linux delivery component boundary')
class NativeFileResultDeliveryTests(unittest.TestCase):
    def validate(self,p,frame=None,request=None):
        context=p.context|({'request':request} if request is not None else {})
        return validate_native_file_result_delivery(
            p.frame if frame is None else frame,channel_id=CHANNEL,**context)

    def test_closed_generation_rejects_downgrade_unsolicited_extra_and_cross_role(self):
        p=protocol()
        legacy=inspection_mcp._file_publication_inspection_request(
            'synthetic-request','objects/result.bin',digest_bytes(PAYLOAD),ACK)
        self.assertEqual(legacy['native_file_publication_inspection_request_version'],'1.0')
        self.assertEqual(set(legacy),set(p.request))
        malformed=[p.frame|{'version':'1.0'},p.frame|{'version':'1.2'},
            {k:v for k,v in p.frame.items() if k!='canonical_result'},
            p.frame|{'extra':None},p.frame|{'channel_id':'f'*32},
            p.frame|{'run_id':'different-run'}]
        for frame in malformed:
            with self.subTest(frame=frame),self.assertRaises(PhaseError):self.validate(p,frame)
        for request in (legacy,p.request|{'operation':'execute'},
                p.request|{'native_file_publication_inspection_request_version':'2.0'},
                p.request|{'extra':None}):
            with self.subTest(request=request),self.assertRaises(PhaseError):self.validate(p,request=request)
        for flag in (None,1,'yes'):
            with self.subTest(flag=flag),self.assertRaises(PhaseError):
                inspection_mcp._file_publication_inspection_request(
                    'synthetic-request','objects/result.bin',None,ACK,_include_canonical_result=flag)

    def test_schema_valid_reference_context_substitutions_fail(self):
        p=protocol()
        for field,value in (
            ('owner_id','different.owner'),('root_binding','fixture_result_root'),
            ('locator','objects/different.bin'),('authority_rule','authority.different_v1'),
            ('contract',p.reference['contract']|{'package_digest':'sha256:'+'f'*64})):
            with self.subTest(field=field),self.assertRaisesRegex(PhaseError,'ntfs.file_result_binding_mismatch'):
                self.validate(p,p.frame|{'canonical_result':p.reference|{field:value}})
        wrong=p.request|{'expected_receipt_digest':'sha256:'+'f'*64}
        with self.assertRaisesRegex(PhaseError,'ntfs.file_publication_receipt_mismatch'):
            self.validate(p,request=wrong)

    def test_state_bounds_bool_head_append_digest_and_missing_reference_fail(self):
        p=protocol()
        changes=[{'length':True},{'length':-1},{'length':1024**2+1},{'digest':None},
            {'digest':'sha256:'+'F'*64},{'exists':False},{'head_token':'unexpected-head'}]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(PhaseError):
                self.validate(p,p.frame|{'canonical_result':p.reference|{'state':p.reference['state']|change}})
        appended={'operation_identity':'other','request_digest':ACK,'record_identity':'other',
            'append_offset':0,'record_digest':ACK,'record_length':1,'resulting_head':'other'}
        with self.assertRaises(PhaseError):
            self.validate(p,p.frame|{'canonical_result':p.reference|{'appended_record':appended}})
        with self.assertRaisesRegex(PhaseError,'ntfs.file_result_required'):
            self.validate(p,p.frame|{'canonical_result':None})

    def test_schema_valid_contradictory_positive_error_and_blockers_reject_reference(self):
        p=protocol()
        for change in ({'error':'synthetic.failed'},{'blockers':['synthetic.blocked']}):
            result=p.result|change
            validate_command_result(result,p.registry)  # Establish that schema alone cannot reject it.
            with self.subTest(change=change),self.assertRaisesRegex(PhaseError,'ntfs.file_result_binding_mismatch'):
                self.validate(p,p.frame|{'result':result})

    def test_failed_null_reference_preserves_raw_failure_and_never_carries_result(self):
        p=protocol()
        failed=PhaseApplication(registry=p.registry)._failure('inspect',PhaseError('synthetic.refused')).payload
        frame=p.frame|{'result':failed,'exit_code':10,'canonical_result':None}
        before=canonical_bytes(failed)
        self.assertIsNone(self.validate(p,frame))
        self.assertEqual(canonical_bytes(failed),before)
        with self.assertRaises(PhaseError):self.validate(p,frame|{'canonical_result':p.reference})
        planned=p.result|{'terminal_status':'validated_planned','execution_disposition':'not_executed',
            'mutation_attempted':False,'target_verified':False}
        validate_command_result(planned,p.registry)
        self.assertIsNone(self.validate(p,p.frame|{'result':planned,'canonical_result':None}))
        with self.assertRaises(PhaseError):self.validate(p,p.frame|{'result':planned})

    def test_projection_is_detached_and_preserves_historical_fields_and_optional_digest(self):
        p=protocol()
        for length in (0,1024**2):
            ref=deepcopy(p.reference);ref['state']['length']=length
            checked=self.validate(p,p.frame|{'canonical_result':ref},
                request=p.request|{'expected_digest':None})
            self.assertEqual(checked,ref);self.assertIsNot(checked,ref)
            self.assertIsNot(checked['state'],ref['state'])
            ref['state']['length']=99
            self.assertEqual(checked['state']['length'],length)
            self.assertEqual(checked['observed_at'],'2026-10-01T00:00:00Z')

    def test_unpatched_qualification_refusal_delivers_new_frame_with_explicit_null(self):
        from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3
        p=protocol()
        launch=SimpleNamespace(_inspection_only=True,check_runtime=Mock(),
            invocation={'request':p.request},_manifest_bytes=p.raw,
            installation_digest=digest_bytes(p.raw),run_id=RUN,
            operation_nonce='b'*32,channel_id=CHANNEL)
        with (patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-pipes'),
              patch.object(entrypoint,'_deliver_linux_frame') as delivered,
              patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel reached')) as channel):
            self.assertEqual(entrypoint.run_native_inspection(launch),10)
        channel.assert_not_called()
        frame=delivered.call_args.args[0]
        self.assertEqual(frame['version'],'1.1')
        self.assertIsNone(frame['canonical_result'])
        self.assertEqual(frame['result']['error'],'ntfs.native_profile_not_qualified')
        self.assertIsNone(self.validate(p,frame))

    def test_real_parent_rejects_invalid_or_contradictory_result_before_finished(self):
        p=protocol();fixture_owner=composition.NativeComposedDeliveryTests()
        bad=[p.frame|{'canonical_result':p.reference|{'owner_id':'different.owner'}},
             p.frame|{'result':p.result|{'error':'synthetic.failed'}},
             p.frame|{'result':p.result|{'blockers':['synthetic.blocked']}},
             p.frame|{'version':'1.0'}]
        original_parent=parent._NativeWindowsParent
        for frame in bad:
            with self.subTest(frame=frame),fixture_owner.delivery(inspection=True) as fixture:
                fixture.launch._manifest_bytes=p.raw
                fixture.launch._manifest_digest=digest_bytes(p.raw)
                fixture.launch._invocation_bytes=canonical_bytes({'run_id':RUN,'channel_id':CHANNEL,
                    'operation_nonce':'b'*32,'request':p.request})
                fixture.pipe.receive_frame.return_value=canonical_bytes(frame),None
                fixture.witness.wait_for_exit.return_value={'worker_exit_established':True,'exit_code':0}
                instances=[]
                def construct(*args):
                    instance=original_parent(*args);instances.append(instance);return instance
                with patch.object(parent,'_NativeWindowsParent',side_effect=construct):
                    with self.assertRaises(PhaseError):entrypoint.run_native_parent(fixture.launch)
                self.assertEqual(len(instances),1);self.assertFalse(instances[0]._finished)
                self.assertTrue(instances[0]._failed)
                fixture_owner.assert_finalized_once(fixture)
                fixture.reader.assert_called_once_with();fixture.core.assert_not_called()

    def test_real_parent_accepts_valid_new_frame_and_finishes_after_validation(self):
        p=protocol();fixture_owner=composition.NativeComposedDeliveryTests()
        original_parent=parent._NativeWindowsParent
        with fixture_owner.delivery(inspection=True) as fixture:
            fixture.launch._manifest_bytes=p.raw
            fixture.launch._manifest_digest=digest_bytes(p.raw)
            fixture.launch._invocation_bytes=canonical_bytes({'run_id':RUN,'channel_id':CHANNEL,
                'operation_nonce':'b'*32,'request':p.request})
            fixture.pipe.receive_frame.return_value=canonical_bytes(p.frame),None
            fixture.witness.wait_for_exit.return_value={'worker_exit_established':True,'exit_code':0}
            instances=[]
            def construct(*args):
                instance=original_parent(*args);instances.append(instance);return instance
            with patch.object(parent,'_NativeWindowsParent',side_effect=construct):
                delivered=entrypoint.run_native_parent(fixture.launch)
            self.assertEqual(delivered,p.frame);self.assertEqual(len(instances),1)
            self.assertTrue(instances[0]._finished);self.assertFalse(instances[0]._failed)
            fixture_owner.assert_finalized_once(fixture)
            fixture.reader.assert_called_once_with();fixture.core.assert_not_called()

    def test_mcp_rejection_retains_same_launch_and_poisoned_owner_before_clear(self):
        p=protocol()
        bad=[p.frame|{'canonical_result':p.reference|{'owner_id':'different.owner'}},
             p.frame|{'result':p.result|{'error':'synthetic.failed'}},
             p.frame|{'result':p.result|{'blockers':['synthetic.blocked']}},
             p.frame|{'version':'1.0'}]
        for frame in bad:
            with self.subTest(frame=frame):
                owner=inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',expected_config_digest=None,
                    manifest_bytes=p.raw,expected_manifest_digest=digest_bytes(p.raw))
                launch=object()
                with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch) as factory,
                      patch.object(inspection_mcp,'run_native_parent',return_value=frame),
                      patch('secrets.token_hex',side_effect=[CHANNEL,'b'*32])):
                    with self.assertRaises(PhaseError):
                        owner._inspect_file_result(RUN,'synthetic-request','objects/result.bin',digest_bytes(PAYLOAD),ACK)
                    self.assertTrue(owner._unavailable);self.assertIs(owner._held_launch,launch)
                    with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_unavailable'):owner.inspect(RUN)
                    factory.assert_called_once()

    def test_mcp_result_projection_uses_same_existing_gate_without_queued_call(self):
        p=protocol()
        owner=inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',expected_config_digest=None,
            manifest_bytes=p.raw,expected_manifest_digest=digest_bytes(p.raw))
        entered=threading.Event();release=threading.Event();values=[];errors=[];launch=object()
        def deliver(_):
            entered.set()
            if not release.wait(10):raise AssertionError('controlled delivery barrier not released')
            return p.frame
        def invoke():
            try:values.append(owner._inspect_file_result(RUN,'synthetic-request','objects/result.bin',digest_bytes(PAYLOAD),ACK))
            except BaseException as error:errors.append(error)
        with (patch.object(inspection_mcp,'_NativeAcceptedLaunch',return_value=launch) as factory,
              patch.object(inspection_mcp,'run_native_parent',side_effect=deliver),
              patch('secrets.token_hex',side_effect=[CHANNEL,'b'*32])):
            thread=threading.Thread(target=invoke);thread.start()
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaisesRegex(PhaseError,'ntfs.inspection_mcp_call_active'):owner.inspect(RUN)
                self.assertIs(owner._held_launch,launch)
            finally:release.set();thread.join(15)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
            factory.assert_called_once()
        self.assertEqual(values[0][0],p.result);self.assertEqual(values[0][1],p.reference)
        self.assertIsNot(values[0][1],p.reference)
        self.assertIsNone(owner._held_launch);self.assertFalse(owner._unavailable)


@unittest.skipUnless(sys.platform.startswith('linux'),'Real qualified Linux/ext4 Host boundary')
class NativeFileResultHostTests(unittest.TestCase):
    def fixture(self,payload=None):
        fixture=host_fixtures.NativeFileInspectionHostTests(methodName='runTest')
        self.addCleanup(fixture.doCleanups);fixture.setUp()
        if payload is not None:
            fixture.payload=payload;fixture.source.write_bytes(payload)
        return fixture

    def inspect(self,f,outcome,*,request_change=None,seal_error=None):
        p=protocol();p.manifest['evidence_root']=str(f.evidence)
        p.manifest['preparation_root']=str(f.root/'preparation')
        p.manifest['root_projections']={'phase_result_root':str(f.target)}
        raw=canonical_bytes(p.manifest)
        request=p.request|{'expected_digest':digest_bytes(f.payload),'expected_receipt_digest':outcome.receipt_digest}
        request.update(request_change or {})
        context={'request':request,'manifest_bytes':raw,'expected_manifest_digest':digest_bytes(raw),'registry':p.registry}
        authority=SimpleNamespace(seal=Mock(side_effect=seal_error))
        try:
            return entrypoint._inspect_with_channel_seal(f.app,authority,evidence_root=f.evidence,
                run_id=outcome.run_id,root_bindings=f.request.root_bindings,
                _canonical_result_context=context,**entrypoint._native_file_inspection_expectations(request))
        finally:authority.seal.assert_called_once_with(intent_digest=None)

    def test_actual_host_create_reuse_current_ack_and_one_inspection(self):
        from phase_tool import application
        f=self.fixture();first=f.execute()
        for outcome in (first,f.execute('synthetic-reuse'),f.execute('synthetic-reuse-again')):
            with patch.object(application,'inspect_run',wraps=application.inspect_run) as inspected:
                response,reference=self.inspect(f,outcome)
                self.assertEqual(inspected.call_count,1)
            legacy=f.app.inspect(evidence_root=f.evidence,run_id=outcome.run_id,root_bindings=f.request.root_bindings)
            self.assertEqual(response.payload,legacy.payload)
            self.assertEqual(reference['state']['digest'],digest_bytes(f.payload))
            self.assertEqual(response.payload['receipt_digest'],outcome.receipt_digest)
            if outcome is not first:
                self.assertNotEqual(outcome.receipt_digest,first.receipt_digest)
                self.assertIsNone(response.payload['intent_digest']);self.assertIsNone(response.payload['effect_plan_digest'])
            reference['state']['length']=999
            _,fresh=self.inspect(f,outcome)
            self.assertEqual(fresh['state']['length'],len(f.payload))

    def test_fixture_overlay_multihop_projects_distinct_current_reference(self):
        # Deliberately edited disposable receipt history: parser/transport oracle,
        # not a receipt emitted by Core or authentication of an operation.
        from phase_tool import application
        from phase_tool.canonical import parse_json_bytes,profile_digest
        from phase_tool.inspection import inspect_run
        f=self.fixture();first=f.execute();second=f.execute('synthetic-second')
        third=f.execute('synthetic-third')
        receipt_path=f.evidence/'.phase'/'runs'/third.run_id/'receipt.json'
        current=parse_json_bytes(receipt_path.read_bytes())
        current['prior_verified_receipt_digest']=second.receipt_digest
        current['canonical_result']['observed_at']='2026-10-25T01:02:03Z'
        raw=canonical_bytes(current);receipt_path.write_bytes(raw)
        current_digest=profile_digest('receipt',current)
        overlay=SimpleNamespace(run_id=third.run_id,receipt_digest=current_digest)
        with (patch.object(application,'inspect_run',wraps=application.inspect_run) as outer,
              patch('phase_tool.inspection.inspect_run',wraps=inspect_run) as recursion):
            response,reference=self.inspect(f,overlay)
        self.assertEqual(outer.call_count,1);self.assertEqual(recursion.call_count,2)
        self.assertTrue(all('_include_canonical_result' not in call.kwargs for call in recursion.call_args_list))
        self.assertEqual(reference,current['canonical_result'])
        self.assertNotEqual(reference,first.receipt['canonical_result'])
        self.assertNotEqual(reference,second.receipt['canonical_result'])
        self.assertEqual(response.payload['receipt_digest'],current_digest)
        self.assertEqual(response.payload['run_id'],third.run_id)
        self.assertIsNone(response.payload['intent_digest']);self.assertIsNone(response.payload['effect_plan_digest'])
        self.assertEqual(receipt_path.read_bytes(),raw)

    def test_actual_host_empty_and_one_mib_reference_boundaries(self):
        for payload in (b'',b'x'*(1024**2)):
            with self.subTest(length=len(payload)):
                f=self.fixture(payload);outcome=f.execute()
                response,reference=self.inspect(f,outcome)
                self.assertTrue(response.payload['success']);self.assertTrue(response.payload['target_verified'])
                self.assertEqual(reference['state']['length'],len(payload))
                self.assertEqual(reference['state']['digest'],digest_bytes(payload))

    def test_actual_host_failed_assertion_stays_failed_null_and_primary_survives_seal_error(self):
        f=self.fixture();outcome=f.execute()
        response,reference=self.inspect(f,outcome,request_change={'request_id':'different-request'})
        self.assertFalse(response.payload['success']);self.assertIsNone(reference)
        self.assertEqual(response.payload['error'],'inspection.captured_candidate_mismatch')
        with self.assertRaisesRegex(PhaseError,'ntfs.file_publication_receipt_mismatch') as caught:
            self.inspect(f,outcome,request_change={'expected_receipt_digest':'sha256:'+'f'*64},
                seal_error=OSError('synthetic seal failure'))
        self.assertTrue(any('Native inspection channel seal' in text for text in caught.exception.__notes__))

    def test_reference_validation_failure_precedes_seal_and_keeps_primary_error(self):
        f=self.fixture();outcome=f.execute();p=protocol()
        p.manifest['evidence_root']=str(f.evidence)
        p.manifest['preparation_root']=str(f.root/'preparation')
        p.manifest['root_projections']={'phase_result_root':str(f.target)}
        raw=canonical_bytes(p.manifest)
        context=p.context.copy();context.pop('run_id')
        context.update(manifest_bytes=raw,expected_manifest_digest=digest_bytes(raw))
        context['request']=p.request|{'expected_receipt_digest':outcome.receipt_digest,
            'expected_digest':digest_bytes(f.payload)}
        response,reference=f.app._inspect_with_result(evidence_root=f.evidence,run_id=outcome.run_id,
            root_bindings=f.request.root_bindings,_include_canonical_result=True)
        self.assertEqual(validate_native_file_inspection_result(response.payload,reference,
            run_id=outcome.run_id,**context),reference)
        reference['owner_id']='different.owner'
        authority=SimpleNamespace(seal=Mock(side_effect=OSError('synthetic seal secondary')))
        with patch.object(f.app,'_inspect_with_result',return_value=(response,reference)):
            with self.assertRaisesRegex(PhaseError,'ntfs.file_result_binding_mismatch') as caught:
                entrypoint._inspect_with_channel_seal(f.app,authority,evidence_root=f.evidence,
                    run_id=outcome.run_id,root_bindings=f.request.root_bindings,_canonical_result_context=context)
        authority.seal.assert_called_once_with(intent_digest=None)
        self.assertTrue(any('Native inspection channel seal' in text for text in caught.exception.__notes__))


if __name__=='__main__':unittest.main()
