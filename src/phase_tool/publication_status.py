"""Bounded saved-state query. Receipt presence is not current verification."""
from __future__ import annotations
from pathlib import Path
import stat
import time
from typing import Literal
from pydantic import BaseModel,ConfigDict
from jsonschema.exceptions import ValidationError
from .canonical import canonical_bytes, parse_json_bytes, profile_digest
from .errors import PhaseError
from .evidence import _reject_existing_links,validate_intent,validate_receipt,validate_run_id
from .recovery import read_record


class PublicationStatus(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    publication_status_version: Literal['1.0']='1.0'
    run_id: str
    query_succeeded: bool=True
    stage: Literal['not_observed','preparing','intent_recorded','effects_recorded','receipt_recorded']='not_observed'
    request_id: str | None=None
    intent_digest: str | None=None
    receipt_digest: str | None=None
    recorded_terminal_status: str | None=None
    recorded_mutation_attempted: bool | None=None
    verification_performed: Literal[False]=False
    target_verified: Literal[False]=False
    process_liveness: Literal['not_checked']='not_checked'
    wait_expired: bool=False
    error: str | None=None
    exit_code: int=0


def _native_record_exists(path: Path, *, directory: bool = False) -> bool:
    """Check a fixed metadata entry without following an unsafe leaf."""
    _reject_existing_links(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
        raise PhaseError('publication.status_unsafe_metadata')
    return True


def _read_native_record(path: Path) -> dict:
    from .mutation.ntfs.reader import _CONTROL_LIMIT
    from .streaming import read_bounded_file

    raw = read_bounded_file(path, _CONTROL_LIMIT)
    value = parse_json_bytes(raw, maximum_bytes=_CONTROL_LIMIT)
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise PhaseError('publication.status_invalid_record')
    return value


def publication_status(application, *, evidence_root: Path, run_id: str, wait_seconds: int=0,
        _expected_contract: dict | None = None, _expected_evidence_identity: dict | None = None):
    from .application import ApplicationResponse
    result=PublicationStatus(run_id=run_id)
    try:
        validate_run_id(run_id)
        if type(wait_seconds) is not int or not 0<=wait_seconds<=60:
            raise PhaseError('publication.invalid_wait')
        root=Path(evidence_root).absolute()
        _reject_existing_links(root)
        run=root/'.phase/runs'/run_id
        intent_path=run/'intent.json'
        effects_path=run/'attachments/effect-receipts.json'
        receipt_path=run/'receipt.json'
        native = _expected_contract is not None
        read_metadata = _read_native_record if native else read_record
        deadline=time.monotonic()+wait_seconds
        while True:
            _reject_existing_links(run)
            if native:
                result=PublicationStatus(run_id=run_id)
            run_exists = _native_record_exists(run, directory=True) if native else run.exists()
            result.stage='preparing' if run_exists else 'not_observed'
            # The producer publishes intent before its receipt. Checking the
            # receipt first avoids treating a concurrent publish as a mismatch.
            receipt_exists = _native_record_exists(receipt_path) if native else None
            intent_exists = _native_record_exists(intent_path) if native else intent_path.exists()
            if intent_exists:
                intent=read_metadata(intent_path)
                if native and (intent.get('phase_intent_version') != '1.2'
                        or intent.get('contract') != _expected_contract
                        or intent.get('registry_snapshot_digest') != application.registry.digest
                        or intent['native_binding']['evidence_identity'] != _expected_evidence_identity):
                    raise PhaseError('publication.status_contract_mismatch')
                validate_intent(intent,application.registry)
                if intent['run_id']!=run_id:
                    raise PhaseError('publication.run_mismatch')
                result.stage='intent_recorded'
                result.intent_digest=profile_digest('intent',intent)
                result.request_id=intent['idempotency']['key']
                effects_exist = _native_record_exists(effects_path) if native else effects_path.is_file()
                if effects_exist:
                    result.stage='effects_recorded'
            if not native:
                receipt_exists = receipt_path.exists()
            if receipt_exists:
                receipt=read_metadata(receipt_path)
                if native and receipt.get('contract') != _expected_contract:
                    raise PhaseError('publication.status_contract_mismatch')
                validate_receipt(receipt,application.registry)
                if receipt['run_id']!=run_id:
                    raise PhaseError('publication.run_mismatch')
                if receipt['evidence']['intent_digest']!=result.intent_digest:
                    raise PhaseError('publication.intent_mismatch')
                result.stage='receipt_recorded'
                result.receipt_digest=profile_digest('receipt',receipt)
                result.recorded_terminal_status=receipt['terminal_status']
                result.recorded_mutation_attempted=receipt['mutation_attempted']
                break
            remaining=deadline-time.monotonic()
            if remaining<=0:
                result.wait_expired=wait_seconds>0
                break
            time.sleep(min(0.1,remaining))
    except (PhaseError,OSError,ValueError,TypeError,KeyError,ValidationError) as exc:
        if _expected_contract is not None:
            result=PublicationStatus(run_id=run_id)
        result.query_succeeded=False
        result.error=exc.code if isinstance(exc,PhaseError) else 'publication.status_unavailable'
        result.exit_code=10
    return ApplicationResponse(result.model_dump(),result.exit_code)


def publication_limits():
    from .application import ApplicationResponse
    from .streaming import limits
    from .bundle import MAX_MEMBERS,MAX_TOTAL_BYTES,MAX_DEPTH
    from .publish_file import MAX_BYTES
    bundle_limits = limits() | {'total_bytes':MAX_TOTAL_BYTES,'objects':MAX_MEMBERS,'path_depth':MAX_DEPTH}
    return ApplicationResponse({'limits_version':'1.0',
        'file_v1':{'file_bytes':MAX_BYTES,'objects':1},
        'file_v2':limits(),
        'bundle_v1':dict(bundle_limits),
        'bundle_v2':dict(bundle_limits),
        'publication_versions':{'file':['1.0','2.0'],'bundle':['1.0','2.0']},
        'wait_seconds':60,
        'recovery':'observe_by_default_or_explicit_commit_prepared',
        'recovery_default_mode':'observe',
        'recovery_modes':{
            'observe':{'target_mutation':False},
            'commit_prepared':{
                'target_mutation':True,
                'target_effect':'remaining_directory_commit_only',
                'contract_bindings':['bundle_create.v2@1.1.0'],
            },
        },
        'status':{
            'semantics':'historical_metadata_only',
            'verification_performed':False,'target_verified':False,
            'target_mutation':False,'process_liveness':'not_checked',
        }})
