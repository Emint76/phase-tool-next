"""Bounded saved-state query. Receipt presence is not current verification."""
from __future__ import annotations
from pathlib import Path
import time
from typing import Literal
from pydantic import BaseModel,ConfigDict
from jsonschema.exceptions import ValidationError
from .canonical import profile_digest
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


def publication_status(application, *, evidence_root: Path, run_id: str, wait_seconds: int=0):
    from .application import ApplicationResponse
    result=PublicationStatus(run_id=run_id)
    try:
        validate_run_id(run_id)
        if type(wait_seconds) is not int or not 0<=wait_seconds<=60:
            raise PhaseError('publication.invalid_wait')
        root=Path(evidence_root).absolute()
        _reject_existing_links(root)
        run=root/'.phase/runs'/run_id
        deadline=time.monotonic()+wait_seconds
        while True:
            _reject_existing_links(run)
            result.stage='preparing' if run.exists() else 'not_observed'
            if (run/'intent.json').exists():
                intent=read_record(run/'intent.json')
                validate_intent(intent,application.registry)
                if intent['run_id']!=run_id:
                    raise PhaseError('publication.run_mismatch')
                result.stage='intent_recorded'
                result.intent_digest=profile_digest('intent',intent)
                result.request_id=intent['idempotency']['key']
                if (run/'attachments/effect-receipts.json').is_file():
                    result.stage='effects_recorded'
            if (run/'receipt.json').exists():
                receipt=read_record(run/'receipt.json')
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
        result.query_succeeded=False
        result.error=exc.code if isinstance(exc,PhaseError) else 'publication.status_unavailable'
        result.exit_code=10
    return ApplicationResponse(result.model_dump(),result.exit_code)


def publication_limits():
    from .application import ApplicationResponse
    from .streaming import limits
    from .bundle import MAX_MEMBERS,MAX_TOTAL_BYTES,MAX_DEPTH
    from .publish_file import MAX_BYTES
    return ApplicationResponse({'limits_version':'1.0',
        'file_v1':{'file_bytes':MAX_BYTES,'objects':1},
        'file_v2':limits(),
        'bundle_v1':limits() | {'total_bytes':MAX_TOTAL_BYTES,'objects':MAX_MEMBERS,'path_depth':MAX_DEPTH},
        'wait_seconds':60,'recovery':'verified_completion_only_no_target_replay'})
