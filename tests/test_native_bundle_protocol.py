"""Bundle worker/proof and fixed-registry regression models, NOT NTFS results."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

from phase_tool import __version__
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_experimental_bundle1_registry,_native_registry_for_manifest
from phase_tool.mutation.ntfs.bundle_execution import (_BUNDLE1_CONTRACT,_BUNDLE1_MECHANISM,
    _BundleWorkerInput,_bundle_projection_value,_bundle_projection_from_value,_bundle_wire_header)
from phase_tool.mutation.ntfs.bundle_stream import _bundle_header,_member_headers,_bundle_end,_bundle_token
from phase_tool.mutation.ntfs.handoff import _BundleControlProjection
from phase_tool.mutation.implementation import mechanism_authority_usage,mechanism_supports_effect_kind
from phase_tool.mutation.guarantees import verify_guarantee_coverage


CHANNEL='a'*32
VALUES={'a.bin':b'','b.bin':b'alpha','c.bin':b'','nested/d.bin':b'alpha','z.bin':b''}


def projection():
    metadata=canonical_bytes({'bundle_version':'1.0','members':[
        {'path':name,'length':len(body),'digest':digest_bytes(body)}for name,body in VALUES.items()],
        'total_length':sum(map(len,VALUES.values()))})
    context={'worker_protocol':'phase.native.file-worker','worker_version':'1.4','run_id':'bundle-protocol-test',
        'intent_digest':'sha256:'+'1'*64,'effect_plan_digest':'sha256:'+'2'*64,
        'native_binding_digest':'sha256:'+'3'*64,'installation_digest':'sha256:'+'4'*64,
        'implementation_artifact_digest':'sha256:'+'5'*64,'operation_nonce':'6'*32}
    grant={'root_binding':'phase_result_root','device':r'\Device\HarddiskVolume7',
        'volume_guid':r'\\?\volume{12345678-1234-1234-1234-123456789abc}'+chr(92),
        'volume_serial32':7,'components':['Synthetic','OwnedRoot'],
        'native_identity':{'volume_serial':0x123456789abcdef0,'file_id':'7'*32}}
    effect={'effect_id':'effect.create.001','kind':'exclusive_create',
        'target':{'root_binding':'phase_result_root','relative_locator':'bundle'},'input_binding':'payload',
        'content_source':{'kind':'frozen_input','binding_id':'payload','source_digest':digest_bytes(metadata)},
        'content_digest':digest_bytes(metadata),'content_length':len(metadata),
        'preconditions':{'existence':'absent','expected_digest':None,'expected_head':None,'concurrency_token':None},
        'lock_scope':None,'durability_policy_id':'file_data_synced','on_failure':'stop_and_classify'}
    return _BundleControlProjection(canonical_bytes(context),canonical_bytes(grant),canonical_bytes(effect),
        '2026-10-29T00:00:00Z','payload',digest_bytes(metadata),len(metadata),metadata,canonical_bytes(_BUNDLE1_CONTRACT))


def frames(project,phase):
    value=_bundle_projection_value(project);context=value['context']
    compact=canonical_bytes({k:context[k]for k in ('run_id','intent_digest','installation_digest','operation_nonce')})
    manifest,header=_bundle_header(context_bytes=compact,channel_id=CHANNEL,manifest_bytes=project.manifest_bytes)
    result=[header]if phase==1 else []
    for item,child_raw in zip(manifest['members'],_member_headers(header,manifest)):
        child=parse_json_bytes(child_raw);digest=digest_bytes(child_raw)
        if phase==1:result.append(child_raw)
        body=VALUES[item['path']]
        if body:result.append(canonical_bytes({'protocol':'phase.native.file2.bytes','version':'1.0',
            'kind':'chunk','header_digest':digest,'pass':phase,'index':0,'offset':0,
            'content_base64':base64.b64encode(body).decode('ascii')}))
        result.append(canonical_bytes({'protocol':'phase.native.file2.bytes','version':'1.0','kind':'end',
            'header_digest':digest,'pass':phase,'content_digest':item['digest'],'content_length':len(body),
            'chunk_count':1 if body else 0}))
    result.append(_bundle_end(header,manifest,phase))
    return result


class Pipe:
    def __init__(self,rows):self.rows=list(rows);self.reads=0
    def receive_frame(self,deadline,maximum_bytes=None):
        self.reads+=1
        if not self.rows:raise AssertionError('Unexpected extra receive')
        raw=self.rows.pop(0)
        if maximum_bytes is not None:assert len(raw)<=maximum_bytes
        return raw,None


class BundleWorkerInputTests(unittest.TestCase):
    def source(self,project,rows):
        # Instrument only pipe/type/platform roles. This grants no real NTFS admission.
        pipe=Pipe(rows)
        with patch('phase_tool.mutation.ntfs.bundle_execution.WindowsPipeFrames',Pipe),patch('os.name','nt'):
            source=_BundleWorkerInput(pipe,project,CHANNEL,time.perf_counter_ns()+29_000_000_000)
        return pipe,source

    def go(self,source):
        return canonical_bytes({'command':'execute_bundle','context':parse_json_bytes(source.projection.context_bytes),
            'rewound_token':parse_json_bytes(_bundle_token(source._header,'rewound')),
            'go_token':parse_json_bytes(_bundle_token(source._header,'go'))})

    def test_zero_members_between_nonempty_repeated_digests_are_exact_occurrences(self):
        project=projection();pipe,source=self.source(project,frames(project,1)+frames(project,2))
        self.assertEqual(source.first_pass(),_bundle_token(source._header,'ready'))
        source.accept_go(self.go(source));actual={}
        for name in VALUES:
            chunks=[]
            while True:
                chunk=source.next_member_chunk(name)
                if chunk is None:break
                chunks.append(chunk)
            actual[name]=b''.join(chunks)
        summary=source.finish_payload()
        self.assertEqual(actual,VALUES);self.assertTrue(source.complete);self.assertEqual(pipe.rows,[])
        self.assertEqual(summary,{'accepted_manifest_digest':project.content_digest,
            'accepted_members':5,'accepted_payload_length':10})
        self.assertEqual(source.stream_facts()['released_bytes'],10)
        with self.assertRaises(PhaseError):source.accept_go(self.go(source))

    def test_wrong_original_contract_refuses_projection_before_any_stream_read(self):
        value=_bundle_projection_value(projection());value['contract']['version']='1.0.0'
        with self.assertRaisesRegex(PhaseError,'ntfs.original_bundle_projection_binding'):
            _bundle_projection_from_value(value)

    def test_wrong_occurrence_is_terminal_without_consuming_another_member(self):
        project=projection();pipe,source=self.source(project,frames(project,1)+frames(project,2))
        source.first_pass();source.accept_go(self.go(source));count=pipe.reads
        with self.assertRaisesRegex(PhaseError,'ntfs.bundle_member_order_mismatch'):
            source.next_member_chunk('nested/d.bin')
        self.assertEqual(pipe.reads,count)
        with self.assertRaises(PhaseError):source.next_member_chunk('a.bin')
        self.assertFalse(source.complete)

    def test_corrupt_aggregate_end_never_reports_completed(self):
        project=projection();replay=frames(project,2)
        bad=parse_json_bytes(replay[-1]);bad['manifest_digest']='sha256:'+'0'*64
        replay[-1]=canonical_bytes(bad)
        pipe,source=self.source(project,frames(project,1)+replay)
        source.first_pass();source.accept_go(self.go(source))
        for name in VALUES:
            while source.next_member_chunk(name) is not None:pass
        with self.assertRaises(PhaseError):source.finish_payload()
        self.assertFalse(source.complete);self.assertTrue(source._failed)
        with self.assertRaises(PhaseError):source.finish_remaining()

    def test_member_end_corruption_prevents_following_member_and_aggregate_release(self):
        project=projection();replay=frames(project,2)
        bad=parse_json_bytes(replay[2]);self.assertEqual(bad['kind'],'end');bad['content_length']=0
        replay[2]=canonical_bytes(bad)
        pipe,source=self.source(project,frames(project,1)+replay)
        source.first_pass();source.accept_go(self.go(source))
        self.assertIsNone(source.next_member_chunk('a.bin'))
        self.assertEqual(source.next_member_chunk('b.bin'),b'alpha')
        with self.assertRaises(PhaseError):source.next_member_chunk('b.bin')
        self.assertTrue(source._failed);self.assertFalse(source.complete)


class BundleRegistryBoundaryTests(unittest.TestCase):
    def test_native_binding_resolves_with_empty_candidate_guarantees_and_default_guard_refuses(self):
        registry=_native_experimental_bundle1_registry()
        contract=registry.resolve_contract(**{'identifier':_BUNDLE1_CONTRACT['id'],
            'version':_BUNDLE1_CONTRACT['version'],'package_digest':_BUNDLE1_CONTRACT['package_digest']},core_version=__version__)
        self.assertEqual(mechanism_authority_usage(_BUNDLE1_MECHANISM),'provider_backed')
        self.assertTrue(mechanism_supports_effect_kind(_BUNDLE1_MECHANISM,'exclusive_create'))
        self.assertFalse(mechanism_supports_effect_kind(_BUNDLE1_MECHANISM,'publish_new_version'))
        profile=registry.resolve_guarantee_profile(registry.guarantee_profile_bindings()[
            'phase.native.ntfs.experiment.bundle1.authority.v1@1.0.0'])
        self.assertEqual(profile['classification'],'qualification_candidate')
        self.assertEqual(profile['provided_guarantees'],[]);self.assertEqual(profile['conformance'],[])
        with self.assertRaises(PhaseError):verify_guarantee_coverage(contract.document['operation']['required_guarantees'],
            [_BUNDLE1_MECHANISM],None,registry)
        raw=canonical_bytes({'native_read_installation_version':'1.6','contract':_BUNDLE1_CONTRACT})
        with self.assertRaises(PhaseError):_native_registry_for_manifest(raw,digest_bytes(raw))

    def test_all_historical_registry_entries_and_trust_roots_are_unchanged(self):
        from importlib.resources import files
        root=files('phase_tool').joinpath('data')
        old=json.loads(root.joinpath('registries/native-version2-experiment-v3.json').read_bytes())
        new=_native_experimental_bundle1_registry().to_document()
        self.assertEqual(new['entries'][:len(old['entries'])],old['entries'])
        self.assertEqual(new['trust_roots'],old['trust_roots'])
        self.assertEqual(len(new['entries']),len(old['entries'])+3)
        registry=_native_experimental_bundle1_registry()
        for row in old['entries']:
            if row['kind']=='guarantee_profile':
                with self.subTest(profile=row['id'],version=row['version']):
                    binding={'id':row['id'],'version':row['version'],
                        'descriptor_digest':row['artifact_digest']}
                    if row['id'] in {'phase.native.ntfs.candidate.authority.v1',
                            'phase.native.ntfs.candidate.authority.v2',
                            'phase.native.ntfs.candidate.authority.v3'}:
                        # These immutable candidates require their historical
                        # matching wheels; current source must refuse them.
                        with self.assertRaises(PhaseError)as caught:
                            registry.resolve_guarantee_profile(binding)
                        self.assertEqual(caught.exception.code,
                            'guarantee_profile.implementation_digest_mismatch')
                    else:
                        registry.resolve_guarantee_profile(binding)



if __name__=='__main__':unittest.main()
