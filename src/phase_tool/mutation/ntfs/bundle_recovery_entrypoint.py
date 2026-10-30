"""Thin fixed native adapter for the existing phase_recover_publication API."""
from pathlib import Path

from ...canonical import canonical_bytes,parse_json_bytes,digest_bytes,profile_digest
from ...errors import PhaseError
from .native import _require


def validate_request(request):
    import re
    _require(type(request) is dict and set(request)=={'operation','native_bundle_recovery_request_version',
        'request_id','expected_intent_digest','mode'}
        and request['operation']=='recover_publication'
        and request['native_bundle_recovery_request_version']=='1.0'
        and request['mode'] in {'observe','commit_prepared'}
        and type(request['request_id']) is str and 0<len(request['request_id'])<=128
        and type(request['expected_intent_digest']) is str
        and re.fullmatch(r'sha256:[0-9a-f]{64}',request['expected_intent_digest']) is not None,
        'recovery.native_request_mismatch')
    return request


def validate_result(result,registry,*,request,run_id):
    from jsonschema import Draft202012Validator
    validate_request(request)
    _require(type(result) is dict and result.get('recovery_result_version')=='1.2',
        'recovery.native_result_version_required')
    schema=registry.schema_document('https://phase-tool.local/schemas/recovery-result-1.2.schema.json')
    Draft202012Validator(schema,registry=registry.schema_registry()).validate(result)
    _require(result['recovery_mode']==request['mode']
        and result['run_id']==run_id and result['request_id']==request['request_id']
        and result['intent_digest'] in {None,request['expected_intent_digest']},
        'recovery.native_result_binding_mismatch')
    if result['success']:
        _require(result['status']=='verified_existing' and result['target_verified'] is True
            and result['intent_digest']==request['expected_intent_digest']
            and result['effect_plan_digest'] is not None and result['error'] is None
            and result['exit_code']==0 and result['inspection_required'] is False
            and result['lock_finalization']=={'unlock':'succeeded','close':'succeeded'}
            and not result['error_details'] and not result['native_error_details'],
            'recovery.native_result_binding_mismatch')
    else:
        _require(result['exit_code'] in {10,40} and result['inspection_required'] is True,
            'recovery.native_result_binding_mismatch')
    if request['mode']=='commit_prepared' and result['success']:
        _require(result['commit_finalization_verified'] is True,'recovery.native_finalization_unproven')
    if request['mode']=='observe':
        _require(result['recovery_mutation_attempted'] in {False,None},
            'recovery.observe_mutation_forbidden')
    return result


def validate_delivery(value,launch):
    from ...installation import _native_registry_for_launch
    _require(type(value) is dict and set(value)=={'protocol','version','channel_id','run_id','result','exit_code'}
        and value['protocol']=='phase.native.command' and value['version']=='1.2'
        and value['channel_id']==launch.channel_id and value['run_id']==launch.run_id
        and type(value['exit_code']) is int,'recovery.native_delivery_mismatch')
    result=validate_result(value['result'],_native_registry_for_launch(launch),
        request=launch.invocation['request'],run_id=launch.run_id)
    _require(type(result['exit_code']) is int and result['exit_code']==value['exit_code'],
        'recovery.native_delivery_mismatch')
    return value


def run_recovery_core(launch):
    from ...application import PhaseApplication
    from ...installation import _native_installation_for_manifest
    from .entrypoint import _linux_stdio_identity,_deliver_linux_frame
    _require(launch.manifest['native_read_installation_version']=='1.9'
        and not launch._inspection_only,'recovery.closed_native_role_required')
    request=validate_request(launch.invocation['request']);launch.check_runtime()
    identity=_linux_stdio_identity()
    registry,installation=_native_installation_for_manifest(manifest_bytes=launch._manifest_bytes,
        expected_manifest_digest=launch.installation_digest,run_id=launch.run_id,
        operation_nonce=launch.operation_nonce,channel_id=launch.channel_id,
        _experimental_admission_context=launch._experimental_admission_context)
    app=PhaseApplication(registry=registry,installation=installation)
    response=app.recover_publication(evidence_root=Path(launch.manifest['evidence_root']),run_id=launch.run_id,
        target_root=Path(launch.manifest['root_projections']['phase_result_root']),
        request_id=request['request_id'],expected_intent_digest=request['expected_intent_digest'],mode=request['mode'])
    # Same public operation name, separately typed result. It is never relabeled
    # as a stage3 execute/inspect ACK and never overwrites the original receipt.
    validate_result(response.payload,registry,request=request,run_id=launch.run_id)
    launch.check_runtime()
    _deliver_linux_frame({'protocol':'phase.native.command','version':'1.2','channel_id':launch.channel_id,
        'run_id':launch.run_id,'result':response.payload,'exit_code':response.exit_code},identity)
    return response.exit_code


def inspect_recovered_native(authority,*,evidence_root,run_id):
    """Fresh physical bytes/owner/FID; saved recovery is immutable lineage only."""
    from .experimental_bundle2_authority_v3 import _ExperimentalBundle2AuthorityV3
    from .bundle_recovery_original import verify_original
    from .bundle_recovery import verify_saved_recovery
    from .bundle_execution import _bundle_projection_value,validate_bundle_observation
    _require(type(authority) is _ExperimentalBundle2AuthorityV3 and authority._inspection_only,
        'recovery.closed_native_inspection_required')
    binding=authority.read_binding;root=binding.check_evidence_root()
    _require(Path(evidence_root)==root,'recovery.native_request_mismatch')
    from .bundle_recovery_original import _record
    intent=_record(root/'.phase/runs'/run_id/'intent.json')
    original=verify_original(binding,run_id,intent['idempotency']['key'],
        profile_digest('intent',intent))
    proof,previous=verify_saved_recovery(binding,original)
    projected=_bundle_projection_value(original['projection'])
    observation=authority.observe(run_id=run_id,root_binding='phase_result_root',
        locator=projected['effect']['target']['relative_locator'],expected_identity=previous['native_identity'])
    current=validate_bundle_observation(observation,projected['grant'],projected['effect']['target']['relative_locator'],
        projection=original['projection'])
    _require(current['native']['native_identity']==previous['native_identity']
        and current['native']['stat_identity']==previous['stat_identity'],'recovery.preparation_mismatch')
    receipt=original['original_receipt']
    return {'run_id':run_id,
        'terminal_status':None if receipt is None else receipt['terminal_status'],
        'execution_disposition':None if receipt is None else receipt['execution_disposition'],
        'mutation_attempted':None if receipt is None else receipt['mutation_attempted'],
        'intent_digest':profile_digest('intent',intent),'effect_plan_digest':intent['effect_plan_digest'],
        'receipt_digest':None if receipt is None else profile_digest('receipt',receipt),
        'receipt_present':receipt is not None,'target_verified':True,
        'native_recovery':{'native_bundle_recovery_proof_version':'1.0','operation':proof['operation'],
            'proof_digest':digest_bytes(canonical_bytes(proof)),'original_receipt_preserved':True}}
