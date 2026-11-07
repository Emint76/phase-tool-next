"""Portable B2 exchange/negative models. These are NOT Windows NTFS evidence."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import time
import sys
import unittest
from unittest.mock import Mock,patch

from phase_tool import __version__
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_experimental_bundle2_registry,_native_registry_for_manifest
from phase_tool.mutation.ntfs import bundle_execution as worker
from phase_tool.mutation.ntfs.bundle_prepared import (
    prepared_message,validate_prepared_message,prepared_ack,validate_prepared_ack)
from .test_native_bundle_protocol import projection,frames,CHANNEL,VALUES


def b2_projection():
    original=projection();context=parse_json_bytes(original.context_bytes)
    context['worker_version']='1.5'
    return replace(original,context_bytes=canonical_bytes(context),contract_bytes=canonical_bytes(worker._BUNDLE2_CONTRACT))


def native_stage(project):
    value=worker._bundle_projection_value(project)
    serial=value['grant']['native_identity']['volume_serial']
    identifier='01000000000000000100000000000000'  # Full inode exceeds64bits.
    inode=int.from_bytes(bytes.fromhex(identifier),'little')
    return {'exists':True,'native_identity':{'volume_serial':serial,'file_id':identifier},
        'manifest_digest':project.content_digest,'manifest_length':project.content_length,
        'owner':{'owner_version':'1.0','run_id':value['context']['run_id'],
            'plan_digest':value['context']['effect_plan_digest'],'device':serial,'inode':inode},
        'stat_identity':{'device':serial,'inode':inode},'member_count':5,'total_length':10,
        'member_observations_digest':'sha256:'+'7'*64}


class Bundle2PreparedTests(unittest.TestCase):
    def test_prepared_binds_original_pid_and_full_native_identity_without_finalization_claim(self):
        project=b2_projection();native=native_stage(project)
        message=prepared_message(project,CHANNEL,123,native)
        self.assertGreater(message['native']['stat_identity']['inode'],2**64)
        self.assertEqual(message['stage_lease'],'retained')
        self.assertNotIn('handles_finalized',message)
        for field,value in [('pid',124),('stage_locator','other'),('root_mutex_state','closed')]:
            bad=deepcopy(message);bad[field]=value
            with self.subTest(field=field),self.assertRaises(PhaseError):
                validate_prepared_message(bad,projection=project,channel_id=CHANNEL,expected_pid=123)
        bad=deepcopy(message);bad['context']['operation_nonce']='b'*32
        with self.assertRaises(PhaseError):
            validate_prepared_message(bad,projection=project,channel_id=CHANNEL,expected_pid=123)

    def test_ack_cannot_be_reused_for_another_prepared_object(self):
        project=b2_projection();message=prepared_message(project,CHANNEL,123,native_stage(project))
        ack=prepared_ack(message,'sha256:'+'8'*64,'sha256:'+'9'*64)
        self.assertEqual(validate_prepared_ack(canonical_bytes(ack),message=message),ack)
        other=deepcopy(message);other['pid']=124
        with self.assertRaises(PhaseError):validate_prepared_ack(canonical_bytes(ack),message=other)
        bad=deepcopy(ack);bad['preparation_binding_digest']=None
        with self.assertRaises(PhaseError):validate_prepared_ack(canonical_bytes(bad),message=message)

    def test_worker_requires_complete_end_and_keeps_one_original_deadline_and_checkpoint(self):
        project=b2_projection();rows=frames(project,1)+frames(project,2)
        class Pipe:
            def __init__(self):self.rows=list(rows);self.sent=[];self.received=[]
            def receive_frame(self,deadline,maximum_bytes=None):
                self.received.append(deadline)
                return self.rows.pop(0),None
            def send_frame(self,raw,deadline):
                self.sent.append((raw,deadline))
                message=parse_json_bytes(raw)
                self.rows.append(canonical_bytes(prepared_ack(message,'sha256:'+'8'*64,'sha256:'+'9'*64)))
        pipe=Pipe();deadline=time.perf_counter_ns()+29_000_000_000
        with patch.object(worker,'WindowsPipeFrames',Pipe),patch.object(worker.os,'name','nt'):
            source=worker._BundleWorkerInput(pipe,project,CHANNEL,deadline)
        source.first_pass()
        source.accept_go(canonical_bytes({'command':'execute_bundle','context':parse_json_bytes(project.context_bytes),
            'rewound_token':parse_json_bytes(worker._bundle_token(source._header,'rewound')),
            'go_token':parse_json_bytes(worker._bundle_token(source._header,'go'))}))
        for name in VALUES:
            while source.next_member_chunk(name) is not None:pass
        source.finish_payload()
        source.checkpoint_prepared(native_stage(project))
        self.assertEqual(len(pipe.sent),1);self.assertTrue(all(t==deadline for t in pipe.received))
        self.assertEqual(pipe.sent[0][1],deadline)
        with self.assertRaises(PhaseError):source.checkpoint_prepared(native_stage(project))
        self.assertEqual(len(pipe.sent),1)
        # A new incomplete source may not send PREPARED before END.
        incomplete=object.__new__(worker._BundleWorkerInput)
        incomplete._check=Mock();incomplete._complete=False
        with self.assertRaises(PhaseError):incomplete.checkpoint_prepared(native_stage(project))

    @unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: Linux-only channel model requires fcntl')
    def test_core_persistence_failure_never_sends_ack_or_waits_for_positive_completion(self):
        from phase_tool.mutation.ntfs.bundle2_channel import LinuxNativeBundle2Channel
        from phase_tool.prepared_binding import NATIVE_BOUND_CONTRACT
        self.assertEqual(worker._BUNDLE2_CONTRACT,dict(zip(
            ('id','version','package_digest'),NATIVE_BOUND_CONTRACT)))
        project=b2_projection();message=prepared_message(project,CHANNEL,123,native_stage(project))
        channel=object.__new__(LinuxNativeBundle2Channel);channel.channel_id=CHANNEL
        channel._receive_bound=Mock(return_value={'bundle_stage':'prepared','prepared':message})
        channel._send_frame=Mock();error=PhaseError('injected.binding_record_write')
        channel._checkpoint=SimpleNamespace(persist=Mock(side_effect=error))
        with self.assertRaises(PhaseError)as caught:
            channel._bundle_terminal({},1,projection=project,expected_pid=123)
        self.assertIs(caught.exception,error);channel._send_frame.assert_not_called()
        channel._receive_bound.assert_called_once()
        self.assertEqual(channel._checkpoint.persist.call_args.kwargs['expected_pid'],123)

    def test_fresh_inspect_refuses_valid_but_foreign_owner_on_same_directory(self):
        from phase_tool.inspection import _verify_native_bundle_projection
        project=b2_projection();value=worker._bundle_projection_value(project)
        native=native_stage(project)
        observation={'bundle_observation_version':'1.0','state':{'known':True,'exists':True,
            'digest':project.content_digest,'length':project.content_length,'head_token':None},
            'native':native,'grant':value['grant'],'locator':'bundle','handles_finalized':True}
        authority=SimpleNamespace(read_binding=SimpleNamespace(read=Mock(return_value=project)),
            _manifest={'root_grants':[value['grant']]})
        contract=SimpleNamespace(document={'identity':{'id':'bundle_create.v2','version':'1.2.0'}},
            package_digest=worker._BUNDLE2_CONTRACT['package_digest'])
        receipt={'execution_disposition':'executed','evidence':{'intent_digest':value['context']['intent_digest']}}
        _verify_native_bundle_projection(contract,receipt,value['context']['run_id'],authority,observation,'bundle')
        for key,changed in [('run_id','another-valid-run'),('plan_digest','sha256:'+'0'*64)]:
            wrong=deepcopy(observation);wrong['native']['owner'][key]=changed
            self.assertEqual(wrong['native']['native_identity'],native['native_identity'])
            with self.subTest(key=key),self.assertRaises(PhaseError):
                _verify_native_bundle_projection(contract,receipt,value['context']['run_id'],authority,wrong,'bundle')
        authority.read_binding.read.reset_mock()
        _verify_native_bundle_projection(contract,{'execution_disposition':'reused_existing'},
            'new-reuse-run',authority,observation,'bundle')
        authority.read_binding.read.assert_not_called()

    def test_native_registry_preserves_historical_entries_and_ordinary_guard_refuses(self):
        from importlib.resources import files
        import json
        old=json.loads(files('phase_tool').joinpath('data/registries/native-bundle1-experiment-v1.json').read_bytes())
        registry=_native_experimental_bundle2_registry();new=registry.to_document()
        self.assertEqual(new['entries'][:156],old['entries']);self.assertEqual(new['trust_roots'],old['trust_roots'])
        self.assertEqual(len(new['entries']),159)
        exact=worker._BUNDLE2_CONTRACT
        contract=registry.resolve_contract(exact['id'],exact['version'],exact['package_digest'],core_version=__version__)
        self.assertEqual(contract.document['recovery']['policy'],'resume_prepared_bundle')
        profile=registry.resolve_guarantee_profile(registry.guarantee_profile_bindings()[
            'phase.native.ntfs.experiment.bundle2.authority.v1@1.0.0'])
        self.assertEqual(profile['provided_guarantees'],[]);self.assertEqual(profile['conformance'],[])
        raw=canonical_bytes({'native_read_installation_version':'1.7','contract':exact})
        with self.assertRaises(PhaseError):_native_registry_for_manifest(raw,digest_bytes(raw))


if __name__=='__main__':unittest.main()
