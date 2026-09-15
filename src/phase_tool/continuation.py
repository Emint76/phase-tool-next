"""Versioned prepared-stage proofs and explicit remaining-commit lifecycle.

Called by EffectBroker under its root lock. Original run artifacts are never
replaced. The continuation intent precedes the only allowed target effect.
"""
from pathlib import Path
import os
from typing import Literal
from pydantic import BaseModel, ConfigDict
from .canonical import canonical_bytes, digest_bytes, profile_digest
from .errors import PhaseError
from .evidence import _ensure_directory_durable, _write_bytes_exclusive_atomic
from .bundle import verify_bundle
from .mutation.bundle_create import stage_name


class PreparedStage(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    prepared_stage_version: Literal['1.0'] = '1.0'
    run_id: str
    request_id: str
    request_digest: str
    original_intent_digest: str
    effect_plan_digest: str
    contract: dict[str, str]
    stage_locator: str
    device: int
    inode: int
    content_digest: str
    pre_validator_results_digest: str


class ContinuationIntent(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    continuation_intent_version: Literal['1.0'] = '1.0'
    action: Literal['commit_prepared_bundle'] = 'commit_prepared_bundle'
    original_intent_digest: str
    preparation_digest: str
    run_id: str
    request_id: str
    effect_plan_digest: str
    contract: dict[str, str]
    target: dict[str, str]
    device: int
    inode: int


class ContinuationInterrupted(PhaseError):
    def __init__(self, cause, attempted):
        super().__init__(cause.code if isinstance(cause,PhaseError) else 'recovery.commit_failed')
        self.mutation_attempted = attempted


def validate_record_schema(registry,contract,resource,value):
    from jsonschema import Draft202012Validator
    refs=[a['digest'] for a in contract.entry['package_artifacts'] if a['resource']==resource]
    if len(refs)!=1:
        raise PhaseError('recovery.record_schema_unbound')
    schema=registry.schema_document('https://phase-tool.local/'+resource,refs[0])
    if list(Draft202012Validator(schema).iter_errors(value)):
        raise PhaseError('recovery.invalid_record')


def prepared_value(intent, effect, stage, target_root):
    info = stage.stat()
    return PreparedStage(run_id=intent['run_id'],request_id=intent['idempotency']['key'],
        request_digest=intent['idempotency']['request_digest'],
        original_intent_digest=profile_digest('intent',intent),effect_plan_digest=intent['effect_plan_digest'],
        contract=intent['contract'],stage_locator=stage.relative_to(target_root).as_posix(),
        device=info.st_dev,inode=info.st_ino,content_digest=effect['content_digest'],
        pre_validator_results_digest=intent['evidence']['pre_validator_results_digest']).model_dump()


def save_prepared(intent, effect, stage, target_root, run):
    value = prepared_value(intent,effect,stage,target_root)
    data = canonical_bytes(value)
    _write_bytes_exclusive_atomic(run/'attachments/prepared-stage.json',data,'prepared-stage')


def write_or_verify(path, value):
    from .recovery import read_record
    data=canonical_bytes(value)
    try:
        _write_bytes_exclusive_atomic(path,data,'continuation')
    except FileExistsError:
        if read_record(path)!=value:
            raise PhaseError('recovery.continuation_conflict')
    return digest_bytes(data)


def continue_locked(broker, contract, plan, intent, run, target):
    from .recovery import read_record, verify_preconditions
    from .application import PhaseApplication
    from .mutation.posix.authority import PosixTargetAuthority
    from .mutation import bundle_create
    from .installation import qualify_host_authority_roots
    from .inspection import _verify_intent_blobs
    attempted=False
    try:
        if (contract.document['identity']['id'] != 'bundle_create.v2'
            or contract.document['recovery']['policy'] != 'resume_prepared_bundle'
            or intent['phase_intent_version'] != '1.1'):
            raise PhaseError('recovery.commit_not_authorized')
        qualify_host_authority_roots({'phase_result_root':target})
        _verify_intent_blobs(run,intent,plan)
        app=PhaseApplication(registry=broker.registry)
        pre_digest=verify_preconditions(app,run,intent,plan)
        if pre_digest!=intent['evidence']['pre_validator_results_digest']:
            raise PhaseError('recovery.preconditions_not_proven')
        effect=plan['effects'][0]
        if effect['preconditions'] != {'existence':'absent','expected_digest':None,'expected_head':None,'concurrency_token':None}:
            raise PhaseError('recovery.commit_preconditions_unsupported')
        prepared=read_record(run/'attachments/prepared-stage.json')
        validate_record_schema(broker.registry,contract,'schemas/prepared-stage.schema.json',prepared)
        PreparedStage.model_validate(prepared)
        roots=broker._validate_execution_roots(intent,contract,{'phase_result_root':target})
        identity=roots[os.path.normcase(str(target.absolute()))]
        authority=PosixTargetAuthority(target,effect['target']['relative_locator'],expected_root_identity=identity,create_parents=False)
        try:
            stage=authority.parent_path/stage_name(intent['run_id'],effect)
            destination=authority.target
            exists=destination.exists()
            selected=destination if exists else stage
            # Same stage inode, original plan, complete membership and byte proof
            # are required even when recognizing a prior commit.
            verify_bundle(selected,effect['content_digest'],run_id=intent['run_id'],plan_digest=intent['effect_plan_digest'])
            expected=prepared_value(intent,effect,selected,target)
            expected['stage_locator']=stage.relative_to(target).as_posix()
            if prepared != expected:
                raise PhaseError('recovery.preparation_mismatch')
            preparation_digest=digest_bytes(canonical_bytes(prepared))
            continued=ContinuationIntent(original_intent_digest=profile_digest('intent',intent),
                preparation_digest=preparation_digest,run_id=intent['run_id'],request_id=intent['idempotency']['key'],
                effect_plan_digest=intent['effect_plan_digest'],contract=intent['contract'],target=effect['target'],
                device=prepared['device'],inode=prepared['inode']).model_dump()
            directory=run/'recovery'
            _ensure_directory_durable(directory,parents=False)
            continuation_path=directory/'commit-intent.json'
            validate_record_schema(broker.registry,contract,'schemas/continuation-intent.schema.json',continued)
            if exists:
                # A normal original commit has its original intent + prepared
                # proof. A resumed commit additionally retains this exact intent.
                if continuation_path.exists() and read_record(continuation_path)!=continued:
                    raise PhaseError('recovery.continuation_conflict')
                authority.fsync_parent()
            else:
                write_or_verify(continuation_path,continued)
                if read_record(continuation_path)!=continued:
                    raise PhaseError('recovery.continuation_conflict')
                # Mechanism, not the application recovery function, owns rename.
                attempted=True
                bundle_create.commit_prepared_bundle(authority,stage,effect,intent,prepared)
            verify_bundle(destination,effect['content_digest'],run_id=intent['run_id'],plan_digest=intent['effect_plan_digest'])
            authority.assert_namespace_binding()
            receipt={'continuation_receipt_version':'1.0','original_intent_digest':profile_digest('intent',intent),
                'preparation_digest':preparation_digest,'continuation_intent_digest':digest_bytes(canonical_bytes(continued)) if continuation_path.exists() else None,
                'status':'verified_existing','target_verified':True,'effect_plan_digest':intent['effect_plan_digest']}
            receipt_digest=write_or_verify(directory/'commit-receipt.json',receipt)
            return {'attempted':attempted,'receipt_digest':receipt_digest,'receipt_path':str(directory/'commit-receipt.json')}
        finally:
            authority.close()
    except (PhaseError,OSError,ValueError,TypeError,KeyError) as exc:
        raise ContinuationInterrupted(exc,attempted) from exc
