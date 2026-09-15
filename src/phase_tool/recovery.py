"""Explicit reconciliation, not replay, over exact Phase intent and evidence.

Original receipts and their statuses are immutable. A new versioned observation
records current verification, never fabricates an original successful execution.
"""
from __future__ import annotations
from pathlib import Path
import re
from typing import Literal
from jsonschema.exceptions import ValidationError
from pydantic import BaseModel, ConfigDict
from .canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from .errors import PhaseError
from .evidence import (_reject_existing_links, _ensure_directory_durable,
                       _write_bytes_exclusive_atomic, validate_intent, validate_run_id)
from .inspection import _verify_intent_blobs, _validate_implementation_binding
from .planning import root_identity_records, validate_static_plan, validate_plan_mechanism_authorization
from .publish_file import _root
from .streaming import read_bounded_file, REQUEST_LIMIT


class RecoveryResult(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    recovery_result_version: Literal['1.0']='1.0'
    status: Literal['verified_existing','indeterminate','rejected']='indeterminate'
    success: bool=False
    run_id: str
    request_id: str
    intent_digest: str | None=None
    effect_plan_digest: str | None=None
    original_receipt_digest: str | None=None
    original_terminal_status: str | None=None
    target_verified: bool=False
    recovery_mutation_attempted: bool=False
    inspection_required: bool=True
    observation_digest: str | None=None
    observation_path: str | None=None
    error: str | None=None
    exit_code: int=40


def read_record(path: Path) -> dict:
    _reject_existing_links(path)
    data=read_bounded_file(path,REQUEST_LIMIT)
    value=parse_json_bytes(data)
    if not isinstance(value,dict) or canonical_bytes(value)!=data:
        raise PhaseError('recovery.invalid_record')
    return value


def load_context(application, evidence_root: Path, run_id: str, target_root: Path,
                 request_id: str, expected_intent_digest: str):
    validate_run_id(run_id)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',expected_intent_digest):
        raise PhaseError('recovery.invalid_expected_digest')
    root=_root(evidence_root,existing=True)
    target=_root(target_root,existing=True)
    if root.is_relative_to(target) or target.is_relative_to(root):
        raise PhaseError('recovery.overlapping_roots')
    run=root/'.phase/runs'/run_id
    intent=read_record(run/'intent.json')
    validate_intent(intent,application.registry)
    if (intent['run_id']!=run_id or profile_digest('intent',intent)!=expected_intent_digest
        or intent['idempotency']['key']!=request_id
        or intent['candidate']['storage']['value']['operation_id']!=request_id):
        raise PhaseError('recovery.request_conflict')
    binding=intent['contract']
    if binding['id'] not in {'file_create.v1','file_create.v2','bundle_create.v1','bundle_create.v2'}:
        raise PhaseError('recovery.unsupported_contract')
    contract=application.registry.resolve_contract(binding['id'],binding['version'],binding['package_digest'],core_version=intent['core']['version'])
    plan=read_record(run/'attachments/effect-plan.json')
    validate_static_plan(plan,contract,{'phase_result_root':target},application.registry)
    validate_plan_mechanism_authorization(plan,contract,application.registry)
    if (profile_digest('effect-plan',plan)!=intent['effect_plan_digest']
        or digest_bytes(canonical_bytes(plan))!=intent['evidence']['effect_plan_attachment_digest']
        or plan['contract']!=binding or len(plan['effects'])!=1
        or intent['execution_requested'] is not True):
        raise PhaseError('recovery.plan_mismatch')
    roots={'phase_result_root':target}
    if root_identity_records(contract,roots)!=intent['idempotency']['root_identities']:
        raise PhaseError('recovery.root_identity_mismatch')
    _validate_implementation_binding(intent['implementation_binding'],plan,contract,application.registry)
    effect=plan['effects'][0]
    candidate=intent['candidate']['storage']['value']
    if (effect['target']!={'root_binding':'phase_result_root','relative_locator':candidate['target_locator']}
        or candidate['idempotency_key']!=request_id):
        raise PhaseError('recovery.plan_mismatch')
    return root,target,run,intent,plan,contract


def verify_preconditions(application, run: Path, intent: dict, plan: dict) -> str:
    """Validate the complete fixed v1 result vocabulary against original bindings.

    This is verification of saved claims, never a re-run claiming that an absent
    destination is still absent. Commit-time observations are separate.
    """
    from jsonschema import Draft202012Validator, FormatChecker
    try:
        binding = intent['contract']
        contract = application.registry.resolve_contract(binding['id'], binding['version'], binding['package_digest'], core_version=intent['core']['version'])
        resource = 'schemas/validator-result.schema.json'
        # Validator-result 1.0 is a registry schema, not a contract package
        # artifact. Its version is enforced by that unchanged closed schema.
        schema = application.registry.schema_document('https://phase-tool.local/'+resource)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        data = read_bounded_file(run/'attachments/pre-validator-results.json', REQUEST_LIMIT)
        if intent.get('phase_intent_version') == '1.1' and digest_bytes(data) != intent['evidence']['pre_validator_results_digest']:
            raise ValueError('pre-validator digest binding')
        pre = parse_json_bytes(data)
        declarations = contract.document['validators']
        if not isinstance(pre, list) or len(pre) != len(declarations) or canonical_bytes(pre) != data:
            raise ValueError('incomplete results')
        if plan['run_id'] != intent['run_id'] or plan['contract'] != binding:
            raise ValueError('plan binding')
        content_digest = plan['effects'][0]['content_digest']
        if not any(item['digest'] == content_digest for item in intent['inputs']):
            raise ValueError('input binding')
        for item, declaration in zip(pre, declarations, strict=True):
            validator.validate(item)
            expected_binding = {key: declaration['binding'][key] for key in ('id','version','package_digest')}
            if (item['validator'] != expected_binding or item['run_id'] != intent['run_id']
                or item['phase'] != declaration['phase'] or item['blocking'] != declaration['blocking']
                or item['started_at'] != intent['created_at'] or item['finished_at'] != intent['created_at']
                or item['observation_refs'] or item.get('detail_attachment') is not None or item['blockers']):
                raise ValueError('result binding')
            # These exact builtins emit no external observations/attachments.
            identifier = expected_binding['id']
            expected = {'validator.exact_binding_v1': 'exact_registry_binding',
                        'fixture.create.candidate_v1': 'schema_valid',
                        'bundle.candidate_v1': 'schema_valid',
                        'validator.frozen_blob_v1': content_digest,
                        'validator.destination_absent_v1': 'absent',
                        'validator.result_digest_v1': 'prior_phases_pass',
                        'bundle.result_v1': 'prior_phases_pass'}[identifier]
            post = declaration['phase'] == 'post_operation'
            if (item['status'] != ('not_reached' if post else 'pass')
                or item['code'] != ('validation.not_reached' if post else 'validation.pass')
                or item['expected'] != expected or item['actual'] != (None if post else expected)):
                raise ValueError('result content')
        return digest_bytes(data)
    except (PhaseError, OSError, ValueError, TypeError, KeyError, StopIteration, ValidationError) as exc:
        raise PhaseError('recovery.preconditions_not_proven') from exc


def verify_without_final_receipt(application, run: Path, target: Path, intent: dict, plan: dict) -> None:
    """Verify only these exact local formats; do not upgrade the old receipt."""
    from jsonschema import Draft202012Validator
    from .bundle import verify_bundle
    from .paths import contained_target_path
    from .streaming import hash_file
    from .evidence import evidence_file_exists
    # Existing but invalid final evidence is not a missing-receipt recovery case.
    if (run/'receipt.json').exists():
        raise PhaseError('recovery.original_verification_incomplete')
    verify_preconditions(application, run, intent, plan)
    effect=plan['effects'][0]
    destination=contained_target_path(target,effect['target']['relative_locator'])
    if plan['mechanism']['id']in {'mechanism.bundle_create_v1','mechanism.bundle_create_v2'}:
        if not destination.exists():
            raise PhaseError('recovery.unpublished_stage_retained')
        verify_bundle(destination,effect['content_digest'],run_id=intent['run_id'],plan_digest=intent['effect_plan_digest'])
    else:
        path=run/'attachments/effect-receipts.json'
        _reject_existing_links(path)
        receipts=parse_json_bytes(read_bounded_file(path,REQUEST_LIMIT))
        if not isinstance(receipts,list) or len(receipts)!=1:
            raise PhaseError('recovery.effect_not_proven')
        receipt=receipts[0]
        schema=application.registry.schema_document('https://phase-tool.local/schemas/effect-receipt.schema.json')
        Draft202012Validator(schema,registry=application.registry.schema_registry()).validate(receipt)
        if (receipt['run_id']!=intent['run_id'] or receipt['effect_id']!=effect['effect_id']
            or receipt['kind']!=effect['kind'] or receipt['status']!='applied_verified'
            or receipt['after']['digest']!=effect['content_digest'] or receipt['after']['length']!=effect['content_length']):
            raise PhaseError('recovery.effect_not_proven')
        if hash_file(destination,effect['content_length'])!=(effect['content_digest'],effect['content_length']):
            raise PhaseError('recovery.target_mismatch')


def save_observation(run: Path, result: RecoveryResult) -> None:
    value=result.model_dump(exclude={'observation_digest','observation_path'})
    data=canonical_bytes(value)
    digest=digest_bytes(data)
    directory=run/'recovery'
    _reject_existing_links(directory)
    _ensure_directory_durable(directory,parents=False)
    path=directory/(digest.removeprefix('sha256:')+'.json')
    try:
        _write_bytes_exclusive_atomic(path,data,'recovery-observation')
    except FileExistsError:
        if read_bounded_file(path,REQUEST_LIMIT)!=data:
            raise PhaseError('recovery.observation_conflict')
    result.observation_digest=digest
    result.observation_path=str(path)


def recover_publication(application, *, evidence_root: Path, run_id: str,
                        target_root: Path, request_id: str, expected_intent_digest: str,
                        mode: str = 'observe'):
    from .application import ApplicationResponse
    from .mutation.posix.authority import PosixTargetRootLock
    result=RecoveryResult(run_id=run_id,request_id=request_id)
    try:
        if mode not in {'observe','commit_prepared'}:
            raise PhaseError('recovery.unsupported_mode')
        root,target,run,intent,plan,contract=load_context(application,evidence_root,run_id,target_root,request_id,expected_intent_digest)
        if mode == 'commit_prepared':
            from .mutation import EffectBroker
            result.intent_digest=expected_intent_digest
            result.effect_plan_digest=intent['effect_plan_digest']
            original=application.inspect(evidence_root=root,run_id=run_id,root_bindings={'phase_result_root':target}).payload
            result.original_receipt_digest=original.get('receipt_digest')
            result.original_terminal_status=original.get('terminal_status')
            resumed=EffectBroker(application.registry,application.installation.authority_provider,
                application.installation.authority_profile_binding).resume_prepared_bundle(plan,contract,run/'intent.json',target,expected_intent_digest)
            result.recovery_mutation_attempted=resumed['attempted']
            result.status,result.success,result.target_verified,result.exit_code='verified_existing',True,True,0
            result.inspection_required=False
            save_observation(run,result)
            return ApplicationResponse(result.model_dump(),result.exit_code)
        with PosixTargetRootLock(target,'publication-recovery',timeout_seconds=0):
            # Re-read after locking; no cached mutable evidence or source inputs.
            root,target,run,intent,plan,contract=load_context(application,evidence_root,run_id,target_root,request_id,expected_intent_digest)
            result.intent_digest=expected_intent_digest
            result.effect_plan_digest=intent['effect_plan_digest']
            _verify_intent_blobs(run,intent,plan)
            inspected=application.inspect(evidence_root=root,run_id=run_id,root_bindings={'phase_result_root':target}).payload
            result.original_receipt_digest=inspected.get('receipt_digest')
            result.original_terminal_status=inspected.get('terminal_status')
            if not (inspected['success'] and inspected.get('target_verified') is True
                    and inspected.get('terminal_status')=='succeeded_verified'):
                verify_without_final_receipt(application,run,target,intent,plan)
            result.status,result.success,result.target_verified,result.exit_code='verified_existing',True,True,0
            result.inspection_required=False
            save_observation(run,result)
    except (PhaseError,OSError,ValueError,TypeError,KeyError,ValidationError) as exc:
        result.recovery_mutation_attempted = result.recovery_mutation_attempted or getattr(exc,'mutation_attempted',False)
        result.success=False
        result.target_verified=False
        result.inspection_required=True
        result.error=exc.code if isinstance(exc,PhaseError) else 'recovery.failure'
        result.status='rejected' if result.error in {'recovery.request_conflict','recovery.invalid_expected_digest','recovery.unsupported_contract'} else 'indeterminate'
        result.exit_code=10 if result.status=='rejected' else 40
    return ApplicationResponse(result.model_dump(),result.exit_code)
