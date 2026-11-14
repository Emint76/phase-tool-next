"""Real full native original parser with synthetic immutable buffer claims.

No authority/profile admission, worker, native filesystem, Core mutation or
historical evidence edit. An installed original's exact package selects policy.
"""
from copy import deepcopy
from datetime import datetime, timezone

import pytest
from jsonschema.exceptions import ValidationError

from phase_tool.canonical import canonical_bytes, digest_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.intent import parse_original_file_create
from phase_tool.planning.request_identity import SEMANTIC_REQUEST_POLICY
from phase_tool.registry import BundledRegistry
from .c03_policy_fixtures import policy_registry
from .test_native_original_intent import buffers


def request_oracle(intent, *, semantic):
    scope = {'contract': intent['contract'],
        'result_locator': intent['candidate']['storage']['value']['target_locator'],
        'root_identity_digest': intent['idempotency']['root_identity_digest'],
        'operation_intent': intent['operation']['intent']}
    records = deepcopy(intent['inputs'])
    if semantic:
        records = [{key: value for key, value in row.items() if key != 'frozen_at'}
                   for row in records]
    intent['idempotency']['scope_digest'] = profile_digest('idempotency-scope', scope)
    intent['idempotency']['request_digest'] = profile_digest(
        'request-semantic-v2' if semantic else 'request',
        {'scope': scope, 'candidate_digest': intent['candidate']['digest'], 'inputs': records})


def arguments(registry, intent, plan, pre, content):
    intent = deepcopy(intent)
    intent['effect_plan_digest'] = profile_digest('effect-plan', plan)
    intent['implementation_binding']['effect_plan_digest'] = intent['effect_plan_digest']
    intent['evidence']['effect_plan_attachment_digest'] = digest_bytes(canonical_bytes(plan))
    intent['evidence']['pre_validator_results_digest'] = digest_bytes(canonical_bytes(pre))
    return dict(intent_bytes=canonical_bytes(intent), plan_bytes=canonical_bytes(plan),
        pre_validator_bytes=canonical_bytes(pre), blob_bytes=content, registry=registry,
        expected_run_id=intent['run_id'], expected_intent_digest=profile_digest('intent', intent),
        installed_core_binding=canonical_bytes(intent['core']),
        installed_native_binding=canonical_bytes(intent['native_binding']),
        installed_root_grants=canonical_bytes(intent['idempotency']['root_identities']),
        installed_implementation_binding=canonical_bytes(intent['implementation_binding']))


def original_with_policy(policy, *, use_new_package):
    original = BundledRegistry.load()
    intent, plan, pre, content, _ = buffers(original)
    registry, binding = policy_registry(policy, original=original, binding=intent['contract'])
    intent['registry_snapshot_digest'] = registry.digest
    if use_new_package:
        intent['contract'] = binding
        plan['contract'] = binding
    request_oracle(intent, semantic=use_new_package and policy == SEMANTIC_REQUEST_POLICY)
    return registry, intent, plan, pre, content


def test_original_exact_legacy_package_wins_over_current_semantic_generation():
    values = original_with_policy(SEMANTIC_REQUEST_POLICY, use_new_package=False)
    registry, intent, plan, pre, content = values
    current = registry.contract_bindings()['file_create.v1@1.0.0']
    assert current != intent['contract']
    assert parse_original_file_create(**arguments(*values)).content_bytes == content
    request_oracle(intent, semantic=True)
    with pytest.raises(PhaseError, match='ntfs.original_idempotency_binding_mismatch'):
        parse_original_file_create(**arguments(registry, intent, plan, pre, content))


def test_legacy_original_still_binds_natural_acquisition_record_time():
    values = original_with_policy(SEMANTIC_REQUEST_POLICY, use_new_package=False)
    registry, intent, plan, pre, content = values
    assert parse_original_file_create(**arguments(*values)).content_bytes == content
    intent['inputs'][0]['frozen_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    # Rebind all outer hashes, deliberately keep the original request digest.
    with pytest.raises(PhaseError, match='ntfs.original_idempotency_binding_mismatch'):
        parse_original_file_create(**arguments(registry, intent, plan, pre, content))
    request_oracle(intent, semantic=False)
    assert parse_original_file_create(**arguments(registry, intent, plan, pre, content)).content_bytes == content


def test_full_original_parser_accepts_exact_semantic_package_and_retains_full_record():
    values = original_with_policy(SEMANTIC_REQUEST_POLICY, use_new_package=True)
    registry, intent, plan, pre, content = values
    first = arguments(*values)
    assert parse_original_file_create(**first).content_bytes == content
    request_digest = intent['idempotency']['request_digest']
    intent['inputs'][0]['frozen_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    second = arguments(registry, intent, plan, pre, content)
    assert first['expected_intent_digest'] != second['expected_intent_digest']
    assert intent['idempotency']['request_digest'] == request_digest
    assert parse_original_file_create(**second).content_bytes == content


def test_semantic_exact_original_rejects_old_request_formula_with_coherent_outer_hashes():
    registry, intent, plan, pre, content = original_with_policy(
        SEMANTIC_REQUEST_POLICY, use_new_package=True)
    request_oracle(intent, semantic=False)
    with pytest.raises(PhaseError, match='ntfs.original_idempotency_binding_mismatch'):
        parse_original_file_create(**arguments(registry, intent, plan, pre, content))


def test_full_original_parser_unknown_exact_policy_never_uses_current_default():
    registry, intent, plan, pre, content = original_with_policy(
        'digest.unreviewed_request_v9', use_new_package=True)
    with pytest.raises(PhaseError, match='plan.request_digest_policy_unsupported'):
        parse_original_file_create(**arguments(registry, intent, plan, pre, content))


@pytest.mark.parametrize('damage', ['missing', 'extra'])
def test_full_semantic_original_rejects_unknown_input_shape(damage):
    registry, intent, plan, pre, content = original_with_policy(
        SEMANTIC_REQUEST_POLICY, use_new_package=True)
    if damage == 'missing':
        del intent['inputs'][0]['provenance_ref']
    else:
        intent['inputs'][0]['future_record_field'] = None
    with pytest.raises((PhaseError, ValidationError)):
        parse_original_file_create(**arguments(registry, intent, plan, pre, content))
