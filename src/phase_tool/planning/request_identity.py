"""Exact-policy request identity; pure digest projection, no execution authority.

The legacy policies below deliberately share the historical full-record formula.
Their IDs are explicit because an unknown policy must never silently inherit it.
The semantic policy excludes only the acquisition time; original records and
intent/receipt hashing remain complete and unchanged.
"""
from collections.abc import Mapping

from ..canonical import profile_digest
from ..errors import PhaseError

LEGACY_REQUEST_POLICIES = frozenset({
    'digest.canonical_request_v1',
    'digest.admission_canonical_request_v1',
})
SEMANTIC_REQUEST_POLICY = 'digest.semantic_request_v2'
_INPUT_FIELDS = frozenset({
    'binding_id', 'freeze_strategy', 'digest', 'manifest_digest', 'blob_digest',
    'provenance_ref', 'frozen_at', 'revalidation_token',
})


def request_identity_digest(*, policy, scope, candidate_digest, input_records):
    if type(policy) is not str:
        raise PhaseError('plan.request_digest_policy_unsupported')
    if policy in LEGACY_REQUEST_POLICIES:
        # Historical inputs are neither normalized, rewritten nor projected.
        # Existing capture/intent schema validation remains the shape owner.
        domain, projected = 'request', input_records
    elif policy == SEMANTIC_REQUEST_POLICY:
        if type(input_records) is not list:
            raise PhaseError('plan.request_input_fields_unsupported')
        projected = []
        for record in input_records:
            if not isinstance(record, Mapping) or set(record) != _INPUT_FIELDS:
                raise PhaseError('plan.request_input_fields_unsupported')
            projected.append({key: value for key, value in record.items() if key != 'frozen_at'})
        domain = 'request-semantic-v2'
    else:
        raise PhaseError('plan.request_digest_policy_unsupported')
    return profile_digest(domain, {
        'scope': scope, 'candidate_digest': candidate_digest, 'inputs': projected,
    })
