"""Independent preparation checkpoint, created before original bundle commit.

The controlled run record is outside the replaceable stage and its local proof.
This is the installation's existing evidence trust boundary, not a signature or
protection against a privileged actor rewriting every independent record.
"""
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict
from .canonical import canonical_bytes, digest_bytes, profile_digest
from .errors import PhaseError
from .evidence import _write_bytes_exclusive_atomic

BINDING_RESOURCE = 'schemas/preparation-binding.schema.json'
BOUND_CONTRACT = ('bundle_create.v2', '1.1.0')


class PreparationBinding(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    preparation_binding_version: Literal['1.0'] = '1.0'
    original_intent_digest: str
    preparation_digest: str
    run_id: str
    request_id: str
    request_digest: str
    effect_plan_digest: str
    contract: dict[str, str]
    target: dict[str, str]
    pre_validator_results_digest: str


def requires_preparation_binding(intent):
    binding = intent['contract']
    return (binding['id'], binding['version']) == BOUND_CONTRACT


def binding_value(intent, effect, prepared):
    return PreparationBinding(
        original_intent_digest=profile_digest('intent', intent),
        preparation_digest=digest_bytes(canonical_bytes(prepared)),
        run_id=intent['run_id'], request_id=intent['idempotency']['key'],
        request_digest=intent['idempotency']['request_digest'],
        effect_plan_digest=intent['effect_plan_digest'], contract=intent['contract'],
        target=effect['target'],
        pre_validator_results_digest=intent['evidence']['pre_validator_results_digest'],
    ).model_dump()


def save_preparation_binding(intent, effect, prepared, run):
    """Called only after the prepared proof is durable, never during recovery."""
    if requires_preparation_binding(intent):
        from .recovery import read_record
        if read_record(run/'attachments/prepared-stage.json') != prepared:
            raise PhaseError('recovery.preparation_mismatch')
        _write_bytes_exclusive_atomic(
            run/'preparation-binding.json', canonical_bytes(binding_value(intent, effect, prepared)),
            'preparation-binding',
        )


def verify_prepared_binding(registry, contract, intent, plan, run):
    from .continuation import PreparedStage, validate_record_schema
    from .recovery import read_record
    if not requires_preparation_binding(intent):
        raise PhaseError('recovery.preparation_binding_unsupported')
    try:
        prepared = read_record(run/'attachments/prepared-stage.json')
        validate_record_schema(registry, contract, 'schemas/prepared-stage.schema.json', prepared)
        PreparedStage.model_validate(prepared)
        binding = read_record(run/'preparation-binding.json')
        validate_record_schema(registry, contract, BINDING_RESOURCE, binding)
        PreparationBinding.model_validate(binding)
        if binding != binding_value(intent, plan['effects'][0], prepared):
            raise PhaseError('recovery.preparation_binding_mismatch')
        return prepared
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise PhaseError('recovery.preparation_binding_not_proven') from exc


def verify_bound_bundle_target(registry, contract, intent, plan, run, target: Path):
    """Check the independent original identity when confirming a committed target."""
    if not requires_preparation_binding(intent):
        return  # Historical exact formats retain only their historical guarantees.
    from .continuation import prepared_value
    from .mutation.bundle_create import stage_name
    prepared = verify_prepared_binding(registry, contract, intent, plan, run)
    effect = plan['effects'][0]
    # Recover the original root from the exact plan locator, not caller metadata.
    root = target
    for _ in Path(effect['target']['relative_locator']).parts:
        root = root.parent
    expected = prepared_value(intent, effect, target, root)
    expected['stage_locator'] = (target.parent/stage_name(intent['run_id'], effect)).relative_to(root).as_posix()
    if prepared != expected:
        raise PhaseError('recovery.preparation_mismatch')
