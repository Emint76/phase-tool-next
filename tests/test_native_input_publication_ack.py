"""Genuine result formatter/schema/finite owner; modeled OS/transport only.

No accepted installation, source Win32 handle, channel, worker or Phase run is
created. The same _call_locked still validates every modeled parent response.
"""
from copy import deepcopy
from types import SimpleNamespace
import os
import unittest
from unittest.mock import patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import input_stage,inspection_mcp
from phase_tool.mutation.ntfs.uncertainty import _NativeLifecycleUnresolved

RUN='native-input-ack-model'
HEADER='sha256:'+'a'*64


class NativeInputPublicationACKTests(unittest.TestCase):
    def setUp(self):
        # Model ONLY this product module's Windows owner boundary. The genuine
        # deadline/context/clock remain active; global os.name/Pathlib do not
        # change on Linux or Windows. No Native OS operation is modeled as real.
        self.process_os_name=os.name
        self.enterContext(patch.object(input_stage,'os',SimpleNamespace(name='nt',getpid=os.getpid)))

    def owner(self):
        # Genuine static selector correlation, intentionally no accepted roots
        # or artifact graph. The launch/runtime boundary is modeled below.
        manifest=canonical_bytes({'native_read_installation_version':'1.1',
            'registry_snapshot_digest':'sha256:2af8bac33feb42a583a14d6bff7b403de2ab0b63be3a962acc45807634a6ecca',
            'contract':{'id':'file_create.v1'}})
        return inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',expected_config_digest=None,
            manifest_bytes=manifest,expected_manifest_digest=digest_bytes(manifest))

    def result(self,command='execute',**changes):
        value=PhaseApplication._command_payload(command,success=True,run_id=RUN,
            terminal_status='succeeded_verified',execution_disposition='executed',mutation_attempted=True,
            effect_plan_digest='sha256:'+'1'*64,intent_digest='sha256:'+'2'*64,
            receipt_digest='sha256:'+'3'*64,target_verified=True if command=='inspect'else None,
            blockers=[],error=None,exit_code=0)
        value.update(changes)
        return value

    def unknown(self):
        return _NativeLifecycleUnresolved(request=SimpleNamespace(run_id=RUN),
            context=SimpleNamespace(intent_recording_started=True,proof_publication_attempted=False,
                publication_attempted=True,common_guard_finalized=False,
                original_intent_digest='sha256:'+'2'*64,
                prepared=SimpleNamespace(effect_plan_digest='sha256:'+'1'*64)),
            authority=SimpleNamespace(channel=SimpleNamespace(possible_dispatch=True)),
            primary=OSError('MODELED missing native completion')).command_result('execute')

    def invoke(self,ack,inspected=None,*,owner=None):
        owner=self.owner()if owner is None else owner
        outputs=[{'result':ack,'exit_code':ack['exit_code']}]
        if inspected is not None:outputs.append({'result':inspected,'exit_code':inspected['exit_code']})
        prepared={'source_locator':'phase-native-input-'+HEADER[7:39]+'/payload/payload',
            'header_digest':HEADER,'expected_digest':digest_bytes(b'payload'),'expected_length':7}
        # Only actual staging IO and accepted-launch/parent IO are modeled.
        # Candidate/request preparation, deadline and _call_locked are genuine.
        with (patch.object(input_stage,'run_windows_input_stage',return_value=(prepared,'File1',{},None))as stage,
              patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=[object(),object()])as launch,
              patch.object(inspection_mcp,'run_native_parent',side_effect=outputs)as parent):
            value=owner.publish_input(RUN,'owner.inputs','incoming.bin','target.bin','request-a')
        return value,owner,stage,launch,parent

    def assert_refused(self,ack,inspected=None,*,expected_calls=1):
        owner=self.owner();captured=[]
        prepared={'source_locator':'phase-native-input-'+HEADER[7:39]+'/payload/payload',
            'header_digest':HEADER,'expected_digest':digest_bytes(b'payload'),'expected_length':7}
        def parent(launch):
            value=ack if not captured else inspected;captured.append(launch)
            return {'result':value,'exit_code':value['exit_code']}
        with (patch.object(input_stage,'run_windows_input_stage',return_value=(prepared,'File1',{},None)),
              patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=[object(),object()]),
              patch.object(inspection_mcp,'run_native_parent',side_effect=parent),
              self.assertRaises(Exception)):
            owner.publish_input(RUN,'owner.inputs','incoming.bin','target.bin','request-a')
        self.assertEqual(len(captured),expected_calls)
        self.assertTrue(owner._unavailable)
        self.assertTrue(owner._gate.acquire(blocking=False));owner._gate.release()
        # No second staging/launch can occur after uncertainty; never retry.
        with (patch.object(input_stage,'run_windows_input_stage')as second_stage,
              patch.object(inspection_mcp,'run_native_parent')as second_parent,
              self.assertRaises(PhaseError)):
            owner.publish_input(RUN,'owner.inputs','incoming.bin','target.bin','request-a')
        second_stage.assert_not_called();second_parent.assert_not_called()
        return owner

    def test_genuine_v10_ack_and_receipt_inspect_without_flag_complete(self):
        ack,inspected=self.result(),self.result('inspect')
        self.assertEqual(os.name,self.process_os_name);self.assertIsNot(input_stage.os,os)
        self.assertNotIn('inspection_required',ack);self.assertNotIn('inspection_required',inspected)
        result,owner,stage,launch,parent=self.invoke(ack,inspected)
        self.assertIs(result['command_ack'],ack);self.assertIs(result['independent_inspection'],inspected)
        self.assertIs(owner._publication_ack,ack);self.assertFalse(owner._unavailable)
        self.assertIsNone(owner._held_launch);self.assertEqual(result['exit_code'],0)
        self.assertEqual(stage.call_count,1);self.assertEqual(parent.call_count,2)
        calls=[parse_json_bytes(call.kwargs['invocation_bytes'])for call in launch.call_args_list]
        self.assertEqual([row['request']['operation']for row in calls],['execute','inspect'])
        self.assertEqual(calls[1]['request'],{'operation':'inspect'})
        self.assertNotEqual(calls[0]['channel_id'],calls[1]['channel_id'])
        self.assertEqual([call.kwargs['_inspection_only']for call in launch.call_args_list],[False,True])

    def test_genuine_v10_reused_existing_still_requires_fresh_inspect(self):
        ack=self.result(execution_disposition='reused_existing',mutation_attempted=False)
        inspected=self.result('inspect',execution_disposition='reused_existing',mutation_attempted=False)
        result,owner,stage,launch,parent=self.invoke(ack,inspected)
        self.assertFalse(result['command_ack']['mutation_attempted']);self.assertEqual(parent.call_count,2)
        self.assertTrue(result['independent_inspection']['target_verified'])

    def test_real_uncertainty_payload_remains_retained_without_inspect(self):
        ack=self.unknown();result,owner,stage,launch,parent=self.invoke(ack)
        self.assertEqual(ack['stage3_command_result_version'],'1.2')
        self.assertIs(result['command_ack'],ack);self.assertIsNone(result['independent_inspection'])
        self.assertEqual(result['exit_code'],40);self.assertTrue(owner._unavailable)
        self.assertIsNotNone(owner._held_launch);self.assertEqual(parent.call_count,1)
        self.assertIsNone(ack['mutation_attempted']);self.assertFalse(result['retry_authorized'])

    def test_genuine_known_refusal_is_returned_exactly_without_success_projection(self):
        ack=PhaseApplication()._failure('execute',PhaseError('MODEL.known_refusal')).payload
        result,owner,stage,launch,parent=self.invoke(ack)
        self.assertIs(result['command_ack'],ack);self.assertEqual(result['exit_code'],10)
        self.assertIsNone(result['independent_inspection']);self.assertEqual(parent.call_count,1)
        self.assertFalse(ack['mutation_attempted']);self.assertFalse(result['retry_authorized'])

    def test_explicit_flag_or_unknown_version_never_uses_missing_flag_compatibility(self):
        for change in({'inspection_required':False},{'inspection_required':True},
                {'stage3_command_result_version':'future'},{'stage3_command_result_version':'1.3'}):
            with self.subTest(change=change):self.assert_refused(self.result(**change))

    def test_zero_exit_is_not_sufficient_for_failed_partial_or_unverified_ack(self):
        for change in({'success':False},{'terminal_status':'failed_partial'},
                {'terminal_status':'committed_unverified'},{'execution_disposition':'not_executed'},
                {'error':'MODEL.error','blockers':['MODEL.error']},
                {'intent_digest':None},{'receipt_digest':None},{'effect_plan_digest':None}):
            with self.subTest(change=change):self.assert_refused(self.result(**change))

    def test_call_locked_still_refuses_foreign_run_command_and_malformed_schema(self):
        for change in({'run_id':'foreign-run'},{'command':'inspect'},
                {'mutation_attempted':None},{'receipt_digest':'not-a-digest'},{'extra':True}):
            with self.subTest(change=change):self.assert_refused(self.result(**change))

    def test_missing_receipt_field_refused_by_unchanged_schema_before_inspection(self):
        ack=self.result();del ack['receipt_digest'];self.assert_refused(ack)

    def test_fresh_inspection_must_correlate_all_four_evidence_bindings(self):
        for field in('run_id','receipt_digest','intent_digest','effect_plan_digest'):
            with self.subTest(field=field):
                inspected=self.result('inspect');inspected[field]='other-run'if field=='run_id'else'sha256:'+'f'*64
                self.assert_refused(self.result(),inspected,expected_calls=2)

    def test_fresh_inspection_requires_verified_legacy_terminal_and_no_unknown_flags(self):
        for change in({'target_verified':False},{'target_verified':None},{'success':False},
                {'terminal_status':'failed_partial'},{'execution_disposition':'not_executed'},
                {'inspection_required':False},{'inspection_required':True},
                {'stage3_command_result_version':'future'}):
            with self.subTest(change=change):self.assert_refused(self.result(),self.result('inspect',**change),expected_calls=2)

    def test_transport_exception_keeps_actual_ack_and_unavailable_owner(self):
        owner=self.owner();ack=self.result();prepared={'source_locator':'phase-native-input-'+HEADER[7:39]+'/payload/payload',
            'header_digest':HEADER,'expected_digest':digest_bytes(b'payload'),'expected_length':7}
        with (patch.object(input_stage,'run_windows_input_stage',return_value=(prepared,'File1',{},None)),
              patch.object(inspection_mcp,'_NativeAcceptedLaunch',side_effect=[object(),object()]),
              patch.object(inspection_mcp,'run_native_parent',side_effect=[{'result':ack,'exit_code':0},OSError('MODEL.inspect_unknown')]),
              self.assertRaises(OSError)):
            owner.publish_input(RUN,'owner.inputs','incoming.bin','target.bin','request-a')
        self.assertIs(owner._publication_ack,ack);self.assertTrue(owner._unavailable);self.assertIsNotNone(owner._held_launch)


if __name__=='__main__':unittest.main()
