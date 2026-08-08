from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any

from ..errors import PhaseError
from .implementation import mechanism_authority_usage


@dataclass(frozen=True)
class GuaranteeProfileBinding:
    id: str
    version: str
    descriptor_digest: str
    implementation_id: str
    implementation_version: str
    implementation_artifact_digest: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "version": self.version,
            "descriptor_digest": self.descriptor_digest,
        }


def registered_profile_binding(key: str) -> GuaranteeProfileBinding:
    from ..registry import BundledRegistry

    registry = BundledRegistry.load()
    exact = registry.guarantee_profile_bindings()[key]
    descriptor = registry.resolve_guarantee_profile(exact)
    implementation = descriptor["implementation"]
    return GuaranteeProfileBinding(
        id=exact["id"],
        version=exact["version"],
        descriptor_digest=exact["descriptor_digest"],
        implementation_id=implementation["id"],
        implementation_version=implementation["version"],
        implementation_artifact_digest=implementation["artifact_digest"],
    )


def verify_guarantee_coverage(
    requirements: Mapping[str, Any],
    mechanisms: list[Mapping[str, Any]],
    profile_binding: GuaranteeProfileBinding | None,
    registry: Any,
) -> dict[str, Any]:
    vocabulary_binding = requirements.get("vocabulary", {})
    try:
        vocabulary = registry.resolve_guarantee_vocabulary(vocabulary_binding)
    except PhaseError as exc:
        if exc.code == "registry.entry_not_found":
            raise PhaseError("guarantee.vocabulary_unsupported") from exc
        raise
    allowed = {
        (item["id"], item["version"], item["package_digest"]): item
        for item in mechanisms
    }
    mappings: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    for item in requirements.get("mechanisms", []):
        mechanism = item.get("mechanism", {})
        key = (mechanism.get("id"), mechanism.get("version"), mechanism.get("package_digest"))
        if key in mappings:
            raise PhaseError("guarantee.requirement_mechanism_duplicate", str(key[0]))
        mappings[key] = item
    missing_mappings = sorted(key[0] for key in set(allowed) - set(mappings))
    extra_mappings = sorted(key[0] for key in set(mappings) - set(allowed))
    if missing_mappings:
        raise PhaseError("guarantee.requirement_mechanism_missing", details={"mechanisms": missing_mappings})
    if extra_mappings:
        raise PhaseError("guarantee.requirement_mechanism_extra", details={"mechanisms": extra_mappings})
    required: set[str] = set()
    normalized_mappings: list[dict[str, Any]] = []
    for key in sorted(mappings):
        item = mappings[key]
        mechanism_required = set(item.get("all_of", []))
        if mechanism_authority_usage(allowed[key]) == "mechanism_managed" and mechanism_required:
            raise PhaseError("guarantee.mechanism_managed_requirements", key[0])
        required.update(mechanism_required)
        normalized_mappings.append({
            "mechanism": {"id": key[0], "version": key[1], "package_digest": key[2]},
            "all_of": sorted(mechanism_required),
        })
    vocabulary_ids = {item["id"] for item in vocabulary["guarantees"]}
    unknown = sorted(required - vocabulary_ids)
    if unknown:
        raise PhaseError("guarantee.requirement_unknown", ",".join(unknown), details={"unknown": unknown})
    if not required:
        return {
            "vocabulary": dict(requirements["vocabulary"]),
            "mechanisms": normalized_mappings,
        }
    if profile_binding is None:
        raise PhaseError("guarantee.profile_unavailable")
    try:
        profile = registry.resolve_guarantee_profile(profile_binding.as_dict())
    except PhaseError as exc:
        if exc.code == "registry.entry_not_found":
            raise PhaseError("guarantee.profile_unsupported") from exc
        raise
    if profile["vocabulary"] != vocabulary_binding:
        raise PhaseError("guarantee.vocabulary_unsupported")
    implementation = profile["implementation"]
    if (
        implementation["id"] != profile_binding.implementation_id
        or implementation["version"] != profile_binding.implementation_version
        or implementation["artifact_digest"] != profile_binding.implementation_artifact_digest
    ):
        raise PhaseError("guarantee.profile_implementation_mismatch")
    missing = sorted(required - set(profile["provided_guarantees"]))
    if missing:
        raise PhaseError("guarantee.coverage_insufficient", ",".join(missing), details={"missing": missing})
    return {
        "vocabulary": dict(requirements["vocabulary"]),
        "mechanisms": normalized_mappings,
    }
