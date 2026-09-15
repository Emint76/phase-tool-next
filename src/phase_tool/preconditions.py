"""Shared pre-validator digest binding for schema-validated intent formats."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .errors import PhaseError


def pre_validator_binding_required(intent: Mapping[str, Any]) -> bool:
    """Classify only the two admitted intent formats; never exempt a new one."""
    version = intent.get("phase_intent_version")
    if version == "1.0":
        return False
    if version != "1.1":
        raise PhaseError("preconditions.unsupported_intent_version")
    return True


def verify_pre_validator_binding(intent: Mapping[str, Any], actual_digest: str) -> bool:
    """Check the raw attachment digest, without upgrading historical guarantees.

    Intent 1.0 has no pre-validator binding; False denotes that absence, not a
    verified binding. Intent 1.1 requires the exact saved bytes. Callers still
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
