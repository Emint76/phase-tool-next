"""Read-only reconciliation for inspect when the original receipt is absent.

The original mutation flag stays unknown. Saved recovery calls are historical
claims, not a substitute original receipt or a completeness/liveness oracle.
No lock, broker, write, fsync, recovery call, or caller-source read is permitted.
"""
from types import SimpleNamespace

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from ..canonical import canonical_bytes, digest_bytes, profile_digest
from ..errors import PhaseError
from ..evidence import _reject_existing_links


def inspect_missing_recovery(registry, evidence_root, run, intent, plan, roots):
    from ..continuation import ContinuationIntent, validate_record_schema
    from ..prepared_binding import verify_prepared_binding
    from ..recovery import load_context, read_record, verify_without_final_receipt

    result = {
        'inspection_status': 'indeterminate',
        'inspection_required': True,
        'recorded_recovery_mutation_attempted': None,
        'recovery_observations': [],
        'target_verified': None,
        'inspection_error': 'inspection.original_receipt_missing',
    }
    directory = run/'recovery'
    try:
        _reject_existing_links(directory)
        if not directory.exists():
            return result
        intent_digest = profile_digest('intent', intent)
        for path in sorted(directory.glob('*.json')):
            if path.name in {'commit-intent.json', 'commit-receipt.json'}:
                continue
            value = read_record(path)
            digest = digest_bytes(canonical_bytes(value))
            if path.name != digest.removeprefix('sha256:')+'.json':
                raise PhaseError('inspection.recovery_observation_mismatch')
            resource = {'1.1': 'recovery-result-1.1'}.get(value.get('recovery_result_version'))
            if resource is None:
                raise PhaseError('inspection.recovery_observation_mismatch')
            schema = registry.schema_document('https://phase-tool.local/schemas/'+resource+'.schema.json')
            Draft202012Validator(schema, registry=registry.schema_registry()).validate(value)
            if (value['run_id'] != intent['run_id']
                    or value['request_id'] != intent['idempotency']['key']
                    or value['intent_digest'] != intent_digest
                    or value['effect_plan_digest'] != intent['effect_plan_digest']
                    or value['original_receipt_digest'] is not None
                    or value['original_terminal_status'] is not None):
                raise PhaseError('inspection.recovery_observation_mismatch')
            result['recovery_observations'].append({'digest': digest, 'result': value})
            if value['recovery_mutation_attempted']:
                result['recorded_recovery_mutation_attempted'] = True
        # No negative aggregate: absent/incomplete observations cannot prove that
        # no recovery syscall was attempted. A no-op repeat never erases a True.
        successful = any(
            row['result']['success'] is True
            and row['result']['status'] == 'verified_existing'
            and row['result']['target_verified'] is True
            and row['result']['inspection_required'] is False
            and row['result']['exit_code'] == 0
            and row['result']['error'] is None
            and row['result']['recovery_effect_state'] == 'committed'
            and row['result']['lock_finalization'] == {'unlock': 'succeeded', 'close': 'succeeded'}
            and not row['result']['error_details']
            for row in result['recovery_observations'])
        if not successful:
            result['inspection_error'] = 'inspection.recovery_not_proven'
            return result
        if 'phase_result_root' not in roots:
            raise PhaseError('inspection.target_root_required')
        app = SimpleNamespace(registry=registry)
        _, target, checked_run, checked_intent, checked_plan, contract = load_context(
            app, evidence_root, intent['run_id'], roots['phase_result_root'],
            intent['idempotency']['key'], intent_digest)
        if checked_run != run or checked_intent != intent or checked_plan != plan:
            raise PhaseError('inspection.recovery_context_changed')
        # Exact continuation closure, not merely the existence of JSON records.
        prepared = verify_prepared_binding(registry, contract, intent, plan, run)
        preparation_digest = digest_bytes(canonical_bytes(prepared))
        expected = ContinuationIntent(
            original_intent_digest=intent_digest, preparation_digest=preparation_digest,
            run_id=intent['run_id'], request_id=intent['idempotency']['key'],
            effect_plan_digest=intent['effect_plan_digest'], contract=intent['contract'],
            target=plan['effects'][0]['target'], device=prepared['device'], inode=prepared['inode'],
        ).model_dump()
        continued = read_record(directory/'commit-intent.json')
        validate_record_schema(registry, contract, 'schemas/continuation-intent.schema.json', continued)
        if continued != expected:
            raise PhaseError('inspection.continuation_mismatch')
        receipt = read_record(directory/'commit-receipt.json')
        if receipt != {
            'continuation_receipt_version': '1.0', 'original_intent_digest': intent_digest,
            'preparation_digest': preparation_digest,
            'continuation_intent_digest': digest_bytes(canonical_bytes(continued)),
            'status': 'verified_existing', 'target_verified': True,
            'effect_plan_digest': intent['effect_plan_digest'],
        }:
            raise PhaseError('inspection.continuation_mismatch')
        # Independently re-read membership, bytes, original stage inode, bound
        # preconditions, exact plan and root identities. Never invoke recovery.
        verify_without_final_receipt(app, run, target, intent, plan)
        result.update(inspection_status='recovered_verified', inspection_required=False,
                      target_verified=True, inspection_error=None)
    except (PhaseError, OSError, ValueError, TypeError, KeyError, ValidationError) as exc:
        result['inspection_error'] = exc.code if isinstance(exc, PhaseError) else 'inspection.recovery_not_proven'
    return result
