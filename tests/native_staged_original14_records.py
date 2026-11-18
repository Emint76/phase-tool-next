"""Complete synthetic Original claims using real roles/registries and hashes.

No Core operation/authority is run. These are deliberately claimed records,
not proof that a native producer, runtime, root or operation was accepted.
"""
from copy import deepcopy
import base64
from .native_staged_original14_data import builders
from phase_tool.canonical import canonical_bytes,canonical_digest,digest_bytes,profile_digest
from phase_tool.freeze import FrozenInput
from phase_tool.planning.request_identity import request_identity_digest
from phase_tool.registry import BundledRegistry
from phase_tool.mutation.ntfs import input_stage,intent as original
from phase_tool.mutation.ntfs import owner_directory_fixture as owner
from phase_tool import installation
from tests.test_native_intent_v12 import fixture as old_native_shell

TIME='2026-11-08T00:00:00Z'

def made_data(version='3.0'):
    env=builders();return env,env['prepared'](version)

def content(role):return (b'B'*4096+b'\n')if role=='Version2'else b'complete-original14-fixture\n'

def saved_claims(contract,intent,plan):
    result=[];effect=plan['effects'][0]
    ordinary={'validator.exact_binding_v1':'exact_registry_binding','fixture.create.candidate_v1':'schema_valid',
        'bundle.candidate_v1':'schema_valid','validator.frozen_blob_v1':effect['content_digest'],
        'validator.destination_absent_v1':'absent','validator.result_digest_v1':'prior_phases_pass','bundle.result_v1':'prior_phases_pass'}
    for declaration in contract.document['validators']:
        identifier=declaration['binding']['id'];post=declaration['phase']=='post_operation'
        if identifier.startswith('publish_new_version.'):
            if identifier.endswith('_v1'):
                from phase_tool.contracts.publish_new_version_v1 import _saved_precondition_expectation
                states={'current':{'exists':True,'digest':effect['archive_digest'],'length':effect['archive_length']},
                    'archive':{'exists':False,'digest':None,'length':None}}
            else:
                from phase_tool.contracts.publish_new_version_v2 import _saved_precondition_expectation
                states={'current':{'exists':True,'digest':effect['archive_digest'],'length':effect['archive_length']},
                    'old_object':{'exists':False,'digest':None,'length':None},'new_object':{'exists':False,'digest':None,'length':None}}
            expected,actual=_saved_precondition_expectation(identifier,{'actual':states},plan)
        else:expected=ordinary[identifier];actual=None if post else expected
        result.append({'validator_result_version':'1.0','run_id':intent['run_id'],'phase':declaration['phase'],
            'validator':{k:declaration['binding'][k]for k in('id','version','package_digest')},
            'status':'not_reached'if post else'pass','code':'validation.not_reached'if post else'validation.pass',
            'blocking':declaration['blocking'],'expected':expected,'actual':actual,'observation_refs':[],'blockers':[],
            'started_at':TIME,'finished_at':TIME})
    return result

def rehash(record):
    intent,plan,pre=record['intent'],record['plan'],record['pre']
    intent['effect_plan_digest']=profile_digest('effect-plan',plan)
    intent['implementation_binding']['effect_plan_digest']=intent['effect_plan_digest']
    intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(plan))
    intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(pre))
    scope={'contract':intent['contract'],'result_locator':intent['candidate']['storage']['value']['target_locator'],
        'root_identity_digest':intent['idempotency']['root_identity_digest'],'operation_intent':intent['operation']['intent']}
    contract=record['contract']
    intent['idempotency']['scope_digest']=profile_digest('idempotency-scope',scope)
    intent['idempotency']['request_digest']=request_identity_digest(policy=contract.document['idempotency']['request_digest_policy_id'],
        scope=scope,candidate_digest=intent['candidate']['digest'],input_records=intent['inputs'])
    record['intent_digest']=profile_digest('intent',intent)
    return record

def record_for(role,data,*,suffix='source'):
    doc,raw,manifests,graph=data;kind=owner._kinds()[role];m=manifests[role]
    cap=kind(raw);body=canonical_bytes(m)
    binding=installation._native_experimental_read_binding(manifest_bytes=body,expected_manifest_digest=digest_bytes(body),admission=cap)
    selected=m['contract'];contract=binding.registry.resolve_contract(selected['id'],selected['version'],selected['package_digest'],core_version=m['core']['version'])
    run=doc['request_limits']['run_prefix']+'original14-'+role.lower()+'-'+suffix
    payload=content(role);members=['empty.bin','nested/payload.bin']if role.startswith('Bundle')else None
    before=b'A'*4096+b'\n'if role=='Version2'else b'old original14\n'
    expected_current=digest_bytes(before)if role.startswith('Version')else None
    candidate,candidate_raw=input_stage._publication_candidate(role,'original14-request-'+role.lower(),'target-'+role.lower()+('.bin'if not members else''),
        members,expected_current,payload.decode()if role=='Version2'else None)
    blobs={}
    if members:
        files={'empty.bin':b'','nested/payload.bin':payload}
        bundle={'bundle_version':'1.0','members':[{'path':name,'length':len(files[name]),'digest':digest_bytes(files[name])}for name in members],
            'total_length':sum(map(len,files.values()))}
        frozen_bytes=canonical_bytes(bundle);blobs.update({digest_bytes(b):b for b in files.values()})
    else:frozen_bytes=payload
    digest=digest_bytes(frozen_bytes)
    if role!='Version2':blobs[digest]=frozen_bytes
    else:blobs[digest_bytes(payload)]=payload
    # Produce the EXACT existing Core input representation. Deliberately no
    # invented length field: FrozenInput.intent_record does not contain one.
    inputs=[]if role=='Version2'else[FrozenInput('payload','manifest_and_hash'if members else'copy_and_hash',digest,len(frozen_bytes),TIME,
        blob_digest=digest,manifest_digest=digest if members else None).intent_record()]
    root=contract.document['canonical_result']['root_binding']
    effect={'effect_id':'effect.create.001','kind':'exclusive_create','target':{'root_binding':root,'relative_locator':candidate['target_locator']},
        'input_binding':'payload','content_source':{'kind':'frozen_input','binding_id':'payload','source_digest':digest},
        'content_digest':digest,'content_length':len(frozen_bytes),'preconditions':{'existence':'absent','expected_digest':None,'expected_head':None,'concurrency_token':None},
        'lock_scope':None,'durability_policy_id':'file_data_synced','on_failure':'stop_and_classify'}
    if role.startswith('Version'):
        effect.update(effect_id='effect.publish.001',kind='publish_new_version',ordinal=0,archive_digest=expected_current,archive_length=len(before),
            operation_identity=candidate['operation_id'],request_digest=None,
            preconditions={'existence':'present','expected_digest':expected_current,'expected_head':None,'concurrency_token':expected_current},
            lock_scope='publish.'+digest_bytes(candidate['target_locator'].encode())[7:])
        if role=='Version1':
            from phase_tool.contracts.publish_new_version_v1 import archive_locator
            effect['archive_target']={'root_binding':root,'relative_locator':archive_locator(expected_current)}
        else:
            from phase_tool.contracts.publish_new_version_v2 import object_locator
            effect.update(input_binding=None,content_source={'kind':'captured_candidate','binding_id':None,'source_digest':digest},
                archive_target={'root_binding':'objects_root','relative_locator':object_locator(expected_current)},
                content_object_target={'root_binding':'objects_root','relative_locator':object_locator(digest)},content_blob_digest=digest,
                content_bytes_b64=base64.b64encode(payload).decode(),media_type=candidate['media_type'],
                durability_policy_id='file_and_directory_synced',mechanism=deepcopy(m['mechanism']))
    operation='publish_new_version'if role.startswith('Version')else'create'
    plan={'effect_plan_version':'1.0','plan_id':'plan.original14.'+role.lower(),'run_id':run,'contract':deepcopy(selected),
        'operation_intent':operation,'mechanism':deepcopy(m['mechanism']),'write_scope_digest':canonical_digest(contract.document['write_scope']),
        'generated_at':TIME,'effect_order':'static_predeclared','effects':[effect]}
    intent=old_native_shell(BundledRegistry.load())
    intent.update(run_id=run,created_at=TIME,core=deepcopy(m['core']),registry_snapshot_digest=binding.registry.digest,contract=deepcopy(selected),
        inputs=inputs,write_scope_digest=plan['write_scope_digest'],operation={'intent':operation,'mechanism':deepcopy(m['mechanism'])},
        implementation_binding={'authority':deepcopy(m['authority']),'mechanism':deepcopy(m['mechanism']),'effect_plan_digest':None},
        native_binding={'native_binding_version':'1.0','installation':{'id':m['installation_id'],'descriptor_digest':binding.manifest_digest},
            'composition':deepcopy(m['composition']),'evidence_identity':deepcopy(m['evidence_identity']),'operation_nonce':'2'*32})
    intent['candidate']={'input_mode':'structured_json','digest':profile_digest('candidate',candidate),'length':len(candidate_raw),
        'storage':{'mode':'inline','value':candidate,'attachment_digest':None}}
    intent['idempotency'].update(key=candidate['idempotency_key'],root_identities=deepcopy(m['root_grants']),
        root_identity_digest=profile_digest('native-root-identity-v1',m['root_grants']))
    intent['evidence']['content_blob_digests']=[digest]if role=='Version2'else[]
    pre=saved_claims(contract,intent,plan)
    return rehash({'role':role,'manifest':m,'binding':binding,'admission':cap,'intent':intent,'plan':plan,'pre':pre,
        'contract':contract,'content':frozen_bytes,'blobs':blobs,'request_literals':{'request_id':candidate['idempotency_key'],
        'target_locator':candidate['target_locator'],'members':members,'expected_current_digest':expected_current,
        'content_utf8':payload.decode()if role=='Version2'else None,'source_digest':digest,'source_length':len(frozen_bytes)}})

def parse_claim(record):
    args=dict(intent_bytes=canonical_bytes(record['intent']),plan_bytes=canonical_bytes(record['plan']),
        pre_validator_bytes=canonical_bytes(record['pre']),registry=record['binding'].registry,
        expected_run_id=record['intent']['run_id'],expected_intent_digest=record['intent_digest'],
        **record['binding']._parser_bindings(record['intent']))
    role=record['role']
    if role=='File1':return original.parse_original_file_create(blob_bytes=record['content'],**args)
    if role=='Version1':return original.parse_original_version1(blob_bytes=record['content'],**args)
    if role=='Version2':return original.parse_original_version2(blob_bytes=record['content'],**args)
    if role=='File2':return original._parse_file2_control_projection(_execution_requested=True,**args)
    return original._parse_bundle_control_projection(manifest_bytes=record['content'],_execution_requested=True,**args)
