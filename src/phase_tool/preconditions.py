"""Shared pre-validator digest binding for schema-validated intent formats."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .errors import PhaseError


def pre_validator_binding_required(intent: Mapping[str, Any]) -> bool:
    """Classify only the three schema-bound intent formats; never exempt a new one."""
    version = intent.get("phase_intent_version")
    if version == "1.0":
        return False
    if version not in ("1.1", "1.2"):
        raise PhaseError("preconditions.unsupported_intent_version")
    return True


def verify_pre_validator_binding(intent: Mapping[str, Any], actual_digest: str) -> bool:
    """Check the raw attachment digest, without upgrading historical guarantees.

    Intent 1.0 has no pre-validator binding; False denotes that absence, not a
    verified binding. Intents 1.1 and 1.2 require the exact saved bytes. Callers still
    own schema/canonical validation and any saved-result semantic checks.
    Unknown formats fail closed rather than inheriting the historical exemption.
    """
    if not pre_validator_binding_required(intent):
        return False
    evidence = intent.get("evidence")
    expected = evidence.get("pre_validator_results_digest") if isinstance(evidence, Mapping) else None
    if expected is None or actual_digest != expected:
        raise PhaseError("preconditions.digest_mismatch", "pre-validator-results.json")
    return True


def verify_saved_precondition_results(registry, contract, intent: dict, plan: dict, data: bytes) -> str:
    """Verify saved builtin claims, not current target state or dispatch authority.

    Shared by the existing recovery reader and the unselected native buffer
    parser. This is the original recovery result vocabulary, without paths or
    filesystem access. A matching digest alone does not prove result semantics.
    """
    from jsonschema import Draft202012Validator, FormatChecker
    from .canonical import canonical_bytes, digest_bytes, parse_json_bytes
    binding = intent['contract']
    resource = 'schemas/validator-result.schema.json'
    # Validator-result 1.0 is a registry schema, not a contract package
    # artifact. Its version is enforced by that unchanged closed schema.
    schema = registry.schema_document('https://phase-tool.local/'+resource)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    verify_pre_validator_binding(intent, digest_bytes(data))
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
