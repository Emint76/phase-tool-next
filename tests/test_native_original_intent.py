"""Pure original-buffer controls; synthetic claims never grant native authority.

No native filesystem, subprocess, Core dispatch, qualified installation or
security qualification. Existing recovery tests exercise the shared reader.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.intent import parse_original_file_create
from phase_tool.preconditions import verify_saved_precondition_results
from phase_tool.registry import BundledRegistry
from phase_tool import planning
from .test_native_intent_v12 import fixture


def buffers(registry):
    intent=fixture(registry)
    binding=intent['contract']
    contract=registry.resolve_contract(binding['id'],binding['version'],binding['package_digest'],core_version=intent['core']['version'])
    content=b'synthetic-original-intent\n'
    digest=digest_bytes(content)
    candidate={'operation_id':'synthetic.create','target_locator':'synthetic.txt',
        'input_binding':'payload','idempotency_key':'synthetic-create-only'}
    intent['candidate'].update(digest=profile_digest('candidate',candidate),length=len(canonical_bytes(candidate)),
        storage={'mode':'inline','value':candidate,'attachment_digest':None})
    intent['inputs']=[{'binding_id':'payload','freeze_strategy':'copy_and_hash','digest':digest,
        'manifest_digest':None,'blob_digest':digest,'provenance_ref':None,
        'frozen_at':intent['created_at'],'revalidation_token':None}]
    scope=canonical_digest(contract.document['write_scope'])
    intent['write_scope_digest']=scope
    effect={'effect_id':'effect.create.001','kind':'exclusive_create',
        'target':{'root_binding':'phase_result_root','relative_locator':candidate['target_locator']},
        'input_binding':'payload','content_source':{'kind':'frozen_input','binding_id':'payload','source_digest':digest},
        'content_digest':digest,'content_length':len(content),
        'preconditions':{'existence':'absent','expected_digest':None,'expected_head':None,'concurrency_token':None},
        'lock_scope':None,'durability_policy_id':'file_data_synced','on_failure':'stop_and_classify'}
    plan={'effect_plan_version':'1.0','plan_id':'plan.synthetic.create','run_id':intent['run_id'],
        'contract':deepcopy(binding),'operation_intent':'create','mechanism':deepcopy(intent['operation']['mechanism']),
        'write_scope_digest':scope,'generated_at':intent['created_at'],'effect_order':'static_predeclared','effects':[effect]}
    root_digest=profile_digest('native-root-identity-v1',intent['idempotency']['root_identities'])
    id_scope={'contract':binding,'result_locator':candidate['target_locator'],'root_identity_digest':root_digest,'operation_intent':'create'}
    intent['idempotency'].update(key=candidate['idempotency_key'],root_identity_digest=root_digest,
        scope_digest=profile_digest('idempotency-scope',id_scope),request_digest=profile_digest('request',{
            'scope':id_scope,'candidate_digest':intent['candidate']['digest'],'inputs':intent['inputs']}))
    expected={'validator.exact_binding_v1':'exact_registry_binding','fixture.create.candidate_v1':'schema_valid',
        'validator.frozen_blob_v1':digest,'validator.destination_absent_v1':'absent',
        'validator.result_digest_v1':'prior_phases_pass'}
    results=[]
    for declaration in contract.document['validators']:
        post=declaration['phase']=='post_operation'
        value=expected[declaration['binding']['id']]
        results.append({'validator_result_version':'1.0','run_id':intent['run_id'],'phase':declaration['phase'],
            'validator':{key:declaration['binding'][key] for key in ('id','version','package_digest')},
            'status':'not_reached' if post else 'pass','code':'validation.not_reached' if post else 'validation.pass',
            'blocking':declaration['blocking'],'expected':value,'actual':None if post else value,
            'observation_refs':[],'blockers':[],'started_at':intent['created_at'],'finished_at':intent['created_at']})
    return intent,plan,results,content,contract


class OriginalNativeIntentTests(unittest.TestCase):
    def setUp(self):
        self.registry=BundledRegistry.load()
        self.intent,self.plan,self.pre,self.content,self.contract=buffers(self.registry)
        self.installed={
            'installed_core_binding':canonical_bytes(self.intent['core']),
            'installed_native_binding':canonical_bytes(self.intent['native_binding']),
            'installed_root_grants':canonical_bytes(self.intent['idempotency']['root_identities']),
            'installed_implementation_binding':None}

    def arguments(self):
        # Rebind outer hashes so negative semantic cases cannot be rejected
        # merely because an attachment hash was left stale by the test.
        self.intent['effect_plan_digest']=profile_digest('effect-plan',self.plan)
        self.intent['implementation_binding']['effect_plan_digest']=self.intent['effect_plan_digest']
        self.intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(self.plan))
        self.intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(self.pre))
        installed=deepcopy(self.installed)
        installed['installed_implementation_binding']=canonical_bytes(self.intent['implementation_binding'])
        return dict(intent_bytes=canonical_bytes(self.intent),plan_bytes=canonical_bytes(self.plan),
            pre_validator_bytes=canonical_bytes(self.pre),blob_bytes=self.content,registry=self.registry,
            expected_run_id=self.intent['run_id'],expected_intent_digest=profile_digest('intent',self.intent),**installed)

    def rejected(self):
        with self.assertRaises((PhaseError,ValidationError,ValueError)):
            parse_original_file_create(**self.arguments())

    def test_consistent_original_buffers_return_only_immutable_structural_bytes(self):
        result=parse_original_file_create(**self.arguments())
        self.assertEqual(result.content_bytes,self.content)
        self.assertEqual(parse_json_bytes(result.effect_bytes),self.plan['effects'][0])
        self.assertEqual(parse_json_bytes(result.grant_bytes),self.intent['idempotency']['root_identities'][0])
        context=parse_json_bytes(result.context_bytes)
        self.assertEqual(context['intent_digest'],profile_digest('intent',self.intent))
        self.assertEqual(context['native_binding_digest'],digest_bytes(canonical_bytes(self.intent['native_binding'])))
        self.assertGreater(parse_json_bytes(result.grant_bytes)['native_identity']['volume_serial'],2**32)
        self.assertEqual(len(parse_json_bytes(result.grant_bytes)['native_identity']['file_id']),32)
        for value in vars(result).values():self.assertIn(type(value),(bytes,str))
        with self.assertRaises(FrozenInstanceError):result.timestamp='changed'

    def test_same_existing_semantic_verifier_accepts_exact_saved_claims(self):
        args=self.arguments()
        self.assertEqual(verify_saved_precondition_results(self.registry,self.contract,self.intent,self.plan,
            args['pre_validator_bytes']),digest_bytes(args['pre_validator_bytes']))

    def test_missing_duplicate_and_reordered_results_reject_with_rebound_hashes(self):
        original=deepcopy(self.pre)
        for rows in ([],original[:-1],[original[0],*original[:-1]],list(reversed(original))):
            with self.subTest(rows=rows):self.pre=rows;self.rejected()

    def test_pass_does_not_allow_wrong_builtin_semantics_with_rebound_hash(self):
        original=deepcopy(self.pre)
        for index,field,value in [(0,'code','validation.other'),(0,'expected','wrong'),
            (2,'actual','sha256:'+'f'*64),(2,'expected','sha256:'+'f'*64),
            (3,'actual','present'),(0,'observation_refs',['synthetic-unproven']),
            (0,'detail_attachment','sha256:'+'f'*64),(0,'started_at','2026-10-21T00:00:00Z'),
            (0,'finished_at','2026-10-21T00:00:00Z'),(0,'blockers',['unproven']),
            (0,'run_id','other-run'),(0,'phase','input'),(0,'blocking',False)]:
            with self.subTest(index=index,field=field):
                self.pre=deepcopy(original);self.pre[index][field]=value;self.rejected()

    def test_validator_binding_and_postoperation_placeholders_are_exact(self):
        original=deepcopy(self.pre)
        for field,value in [('status','pass'),('code','validation.pass'),('expected','wrong'),('actual','wrong')]:
            with self.subTest(field=field):
                self.pre=deepcopy(original);self.pre[-1][field]=value;self.rejected()
        self.pre=deepcopy(original);self.pre[0]['validator']['package_digest']='sha256:'+'f'*64;self.rejected()

    def test_nonpassing_saved_preconditions_cannot_authorize_operation(self):
        original=deepcopy(self.pre)
        for status in ('fail','unknown','not_reached'):
            with self.subTest(status=status):
                self.pre=deepcopy(original);self.pre[0].update(status=status,actual=None,
                    blockers=['synthetic.blocked'] if status!='not_reached' else [])
                self.rejected()

    def test_raw_and_profile_hash_domains_are_not_interchangeable(self):
        args=self.arguments();args['expected_intent_digest']=digest_bytes(args['intent_bytes'])
        with self.assertRaisesRegex(PhaseError,'ntfs.original_intent_mismatch'):parse_original_file_create(**args)
        args=self.arguments();intent=parse_json_bytes(args['intent_bytes'])
        intent['effect_plan_digest']=digest_bytes(args['plan_bytes'])
        args.update(intent_bytes=canonical_bytes(intent),expected_intent_digest=profile_digest('intent',intent))
        with self.assertRaisesRegex(PhaseError,'ntfs.original_plan_digest_mismatch'):parse_original_file_create(**args)

    def test_expected_run_and_raw_attachment_digest_are_checked(self):
        args=self.arguments();args['expected_run_id']='another-run'
        with self.assertRaisesRegex(PhaseError,'ntfs.original_intent_mismatch'):parse_original_file_create(**args)
        args=self.arguments();intent=parse_json_bytes(args['intent_bytes'])
        intent['evidence']['effect_plan_attachment_digest']='sha256:'+'f'*64
        args.update(intent_bytes=canonical_bytes(intent),expected_intent_digest=profile_digest('intent',intent))
        with self.assertRaisesRegex(PhaseError,'ntfs.original_plan_digest_mismatch'):parse_original_file_create(**args)

    def test_closed_installed_expectations_match_canonical_bytes(self):
        args=self.arguments()
        for key in ('installed_core_binding','installed_native_binding','installed_implementation_binding'):
            with self.subTest(key=key):
                changed=deepcopy(args);value=parse_json_bytes(changed[key]);value['unexpected']=True
                changed[key]=canonical_bytes(value)
                with self.assertRaisesRegex(PhaseError,'ntfs.original_installation_binding_mismatch'):
                    parse_original_file_create(**changed)
        args['installed_root_grants']=canonical_bytes([])
        with self.assertRaisesRegex(PhaseError,'ntfs.original_installed_roots_mismatch'):parse_original_file_create(**args)

    def test_mutable_control_and_blob_buffers_reject(self):
        args=self.arguments()
        for key in ('intent_bytes','plan_bytes','pre_validator_bytes','blob_bytes','installed_core_binding',
                    'installed_native_binding','installed_implementation_binding','installed_root_grants'):
            with self.subTest(key=key):
                changed=dict(args);changed[key]=bytearray(args[key])
                with self.assertRaises(PhaseError):parse_original_file_create(**changed)

    def test_control_bounds_reject_with_exact_limit_errors(self):
        args=self.arguments()
        for key,code in [('intent_bytes','candidate.too_large'),('plan_bytes','candidate.too_large'),
                         ('pre_validator_bytes','ntfs.original_precondition_bytes_required')]:
            with self.subTest(key=key):
                changed=dict(args);changed[key]=b' '*(2*1024**2+1)
                with self.assertRaises(PhaseError) as caught:parse_original_file_create(**changed)
                self.assertEqual(caught.exception.code,code)

    def test_noncanonical_bytes_reject_after_matching_attachment_hashes(self):
        args=self.arguments()
        for key in ('intent_bytes','plan_bytes'):
            with self.subTest(key=key):
                changed=dict(args);changed[key]=args[key]+b'\n'
                with self.assertRaises(PhaseError) as caught:parse_original_file_create(**changed)
                self.assertEqual(caught.exception.code,'ntfs.original_noncanonical_bytes')
        changed=dict(args);changed['pre_validator_bytes']+=b'\n'
        intent=parse_json_bytes(changed['intent_bytes'])
        intent['evidence']['pre_validator_results_digest']=digest_bytes(changed['pre_validator_bytes'])
        changed.update(intent_bytes=canonical_bytes(intent),expected_intent_digest=profile_digest('intent',intent))
        with self.assertRaisesRegex(ValueError,'incomplete results'):parse_original_file_create(**changed)

    def test_frozen_content_source_digest_and_length_are_bound(self):
        original=deepcopy(self.plan)
        for field,value in [('content_digest','sha256:'+'f'*64),('content_length',1),('content_length',True),
            ('content_source',{'kind':'frozen_input','binding_id':'payload','source_digest':'sha256:'+'f'*64}),
            ('input_binding','other')]:
            with self.subTest(field=field):
                self.plan=deepcopy(original);self.plan['effects'][0][field]=value;self.rejected()

    def test_candidate_locator_input_key_and_length_cannot_diverge(self):
        original=deepcopy(self.intent)
        for field,value in [('target_locator','other.txt'),('input_binding','other'),('idempotency_key','other')]:
            with self.subTest(field=field):
                self.intent=deepcopy(original);candidate=self.intent['candidate']['storage']['value'];candidate[field]=value
                self.intent['candidate'].update(digest=profile_digest('candidate',candidate),length=len(canonical_bytes(candidate)))
                self.rejected()
        self.intent=deepcopy(original);self.intent['candidate']['length']+=1;self.rejected()

    def test_frozen_record_and_append_blob_set_cannot_diverge(self):
        original=deepcopy(self.intent)
        for field,value in [('binding_id','other'),('freeze_strategy','value_snapshot'),('blob_digest',None),('digest','sha256:'+'f'*64)]:
            with self.subTest(field=field):
                self.intent=deepcopy(original);self.intent['inputs'][0][field]=value;self.rejected()
        self.intent=deepcopy(original);self.intent['evidence']['content_blob_digests']=[digest_bytes(self.content)];self.rejected()

    def test_single_file_effect_subset_is_not_a_new_contract_or_larger_limit(self):
        original=deepcopy(self.plan)
        for field,value in [('durability_policy_id','best_effort_local'),('lock_scope','root.lock'),
            ('preconditions',{'existence':'absent','expected_digest':None,'expected_head':None,'concurrency_token':'unproven'})]:
            with self.subTest(field=field):
                self.plan=deepcopy(original);self.plan['effects'][0][field]=value;self.rejected()
        self.plan=deepcopy(original);self.plan['effects']*=2;self.rejected()
        self.plan=deepcopy(original);self.content=b'x'*(1024**2+1)
        with self.assertRaises(PhaseError) as caught:parse_original_file_create(**self.arguments())
        self.assertEqual(caught.exception.code,'mechanism.content_too_large')

    def test_plan_run_scope_and_registry_snapshot_are_exact(self):
        original=deepcopy(self.plan)
        self.plan['run_id']='other-run';self.rejected()
        self.plan=deepcopy(original);self.plan['write_scope_digest']='sha256:'+'f'*64;self.rejected()
        self.plan=deepcopy(original);self.intent['registry_snapshot_digest']='sha256:'+'f'*64;self.rejected()

    def test_original_root_scope_request_and_full_identity_cannot_be_substituted(self):
        original=deepcopy(self.intent)
        for field in ('root_identity_digest','scope_digest','request_digest'):
            with self.subTest(field=field):
                self.intent=deepcopy(original);self.intent['idempotency'][field]='sha256:'+'f'*64;self.rejected()
        for field,value in [('volume_serial',True),('file_id','f'*16)]:
            with self.subTest(field=field):
                self.intent=deepcopy(original);self.intent['idempotency']['root_identities'][0]['native_identity'][field]=value
                self.rejected()

    def test_posix_root_validation_remains_first(self):
        sentinel=PhaseError('synthetic.root_guard')
        with patch.object(planning,'_require_roots',side_effect=sentinel) as roots, \
             patch.object(planning,'_validate_logical_plan') as logical:
            with self.assertRaisesRegex(PhaseError,'synthetic.root_guard'):
                planning.validate_static_plan({},self.contract,{},self.registry)
        roots.assert_called_once_with(self.contract,{})
        logical.assert_not_called()


if __name__=='__main__':unittest.main()
