from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from importlib import resources as package_resources
from types import MappingProxyType
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from ..canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from ..errors import PhaseError

_REGISTRY_RESOURCE = "registry.json"


def _semver(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value)
    if not match:
        raise PhaseError("registry.invalid_semver", value)
    return tuple(int(part) for part in match.groups())


@dataclass(frozen=True)
class ResolvedContract:
    document: dict[str, Any]
    package_digest: str
    registry_snapshot_digest: str
    entry: Mapping[str, Any]
    contract_hook: dict[str, Any] | None = None


class RegistrySnapshot:
    """An in-memory immutable registry snapshot. It never performs external lookup."""

    def __init__(self, document: dict[str, Any], resources: Mapping[str, bytes]) -> None:
        frozen_document = parse_json_bytes(canonical_bytes(document))
        self._document = frozen_document
        self._resources = MappingProxyType({str(name): bytes(data) for name, data in resources.items()})
        self.digest = canonical_digest(frozen_document)
        if frozen_document.get("registry_snapshot_version") != "1.0":
            raise PhaseError("registry.unsupported_snapshot")
        if not isinstance(frozen_document.get("entries"), list):
            raise PhaseError("registry.invalid_snapshot")

    @classmethod
    def from_document(cls, document: dict[str, Any], resources: Mapping[str, bytes]) -> "RegistrySnapshot":
        return cls(deepcopy(document), resources)

    def to_document(self) -> dict[str, Any]:
        return json.loads(canonical_bytes(self._document).decode("utf-8"))

    def contract_bindings(self) -> dict[str, dict[str, str]]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for entry in self._document["entries"]:
            if entry.get("kind") == "contract":
                groups.setdefault(f"{entry['id']}@{entry['version']}", []).append(entry)
        bindings: dict[str, dict[str, str]] = {}
        for exact_binding, entries in groups.items():
            current = [entry for entry in entries if entry.get("current", True) is True]
            if len(current) != 1:
                raise PhaseError("registry.entry_ambiguous", exact_binding)
            entry = current[0]
            bindings[exact_binding] = {
                "id": entry["id"],
                "version": entry["version"],
                "package_digest": entry["package_digest"],
            }
        return bindings

    def guarantee_profile_bindings(self) -> dict[str, dict[str, str]]:
        return {
            f"{entry['id']}@{entry['version']}": {
                "id": entry["id"],
                "version": entry["version"],
                "descriptor_digest": entry["artifact_digest"],
            }
            for entry in self._document["entries"]
            if entry.get("kind") == "guarantee_profile"
        }

    def resource_bytes(self, name: str) -> bytes:
        try:
            return self._resources[name]
        except KeyError as exc:
            raise PhaseError("registry.resource_missing", name) from exc

    @staticmethod
    def _entry_resource(entry: Mapping[str, Any]) -> str:
        return str(entry.get("archive_resource", entry["artifact"]))

    def _trusted_roots(self) -> set[str]:
        return {
            item["id"]
            for item in self._document.get("trust_roots", [])
            if item.get("enabled") is True and item.get("kind") == "bundled_digest_allowlist"
        }

    def _verify_entry(self, entry: dict[str, Any]) -> None:
        if entry.get("mutable") is not False:
            raise PhaseError("registry.mutable_reference", entry.get("id", "unknown"))
        if entry.get("trust_root_id") not in self._trusted_roots():
            raise PhaseError("registry.untrusted", entry.get("id", "unknown"))
        artifact = entry.get("artifact")
        expected = entry.get("artifact_digest")
        if not isinstance(artifact, str):
            raise PhaseError("registry.digest_mismatch", entry.get("id", "unknown"))
        physical_artifact = self._entry_resource(entry)
        if digest_bytes(self.resource_bytes(physical_artifact)) != expected:
            raise PhaseError("registry.digest_mismatch", entry.get("id", "unknown"))
        if entry.get("kind") in {"mechanism", "contract_hook", "guarantee_vocabulary", "guarantee_profile"}:
            descriptor = parse_json_bytes(self.resource_bytes(physical_artifact))
            if (
                descriptor.get("id") != entry.get("id")
                or descriptor.get("version") != entry.get("version")
            ):
                raise PhaseError("registry.identity_mismatch", entry.get("id", "unknown"))
            if entry.get("kind") in {"mechanism", "contract_hook"} and descriptor.get("capability") != entry.get("capability"):
                raise PhaseError("registry.identity_mismatch", entry.get("id", "unknown"))
        package_artifacts = entry.get("package_artifacts")
        if package_artifacts is not None:
            verified: list[dict[str, str]] = []
            for item in package_artifacts:
                physical_resource = item.get("archive_resource", item["resource"])
                actual = digest_bytes(self.resource_bytes(physical_resource))
                if actual != item["digest"]:
                    raise PhaseError("registry.digest_mismatch", physical_resource)
                verified.append({"resource": item["resource"], "digest": actual})
            package = {"profile": "phase_contract_package_v1", "artifacts": verified}
            if canonical_digest(package) != entry.get("package_digest"):
                raise PhaseError("registry.digest_mismatch", entry.get("id", "unknown"))

    def _exact_entries(self, *, kind: str, identifier: str, version: str, package_digest: str) -> list[dict[str, Any]]:
        return [
            entry
            for entry in self._document["entries"]
            if entry.get("kind") == kind
            and entry.get("id") == identifier
            and entry.get("version") == version
            and entry.get("package_digest") == package_digest
        ]

    def _resolve_binding(self, *, kind: str, binding: Mapping[str, Any], capability: str) -> dict[str, Any]:
        if "capability" in binding and binding.get("capability") != capability:
            raise PhaseError("registry.capability_mismatch", str(binding.get("id", "unknown")))
        matches = self._exact_entries(
            kind=kind,
            identifier=str(binding["id"]),
            version=str(binding["version"]),
            package_digest=str(binding["package_digest"]),
        )
        if not matches:
            identity_matches = [
                entry
                for entry in self._document["entries"]
                if entry.get("kind") == kind
                and entry.get("id") == binding["id"]
                and entry.get("version") == binding["version"]
                and entry.get("package_digest") == binding["package_digest"]
            ]
            if identity_matches and any(entry.get("capability") != capability for entry in identity_matches):
                raise PhaseError("registry.capability_mismatch", str(binding["id"]))
            raise PhaseError("registry.entry_not_found", str(binding["id"]))
        if len(matches) != 1:
            raise PhaseError("registry.entry_ambiguous", str(binding["id"]))
        entry = matches[0]
        if entry.get("capability") != capability:
            raise PhaseError("registry.capability_mismatch", str(binding["id"]))
        self._verify_entry(entry)
        return entry

    def _schema_entry(self, schema_ref: str, digest: str | None = None) -> dict[str, Any]:
        matches = [
            entry
            for entry in self._document["entries"]
            if entry.get("kind") == "schema"
            and entry.get("schema_ref") == schema_ref
            and (digest is None or entry.get("artifact_digest") == digest)
            and (digest is not None or entry.get("current", True) is True)
        ]
        if not matches:
            raise PhaseError("registry.entry_not_found", schema_ref)
        if len(matches) != 1:
            raise PhaseError("registry.entry_ambiguous", schema_ref)
        self._verify_entry(matches[0])
        if digest is not None and digest_bytes(self.resource_bytes(self._entry_resource(matches[0]))) != digest:
            raise PhaseError("registry.digest_mismatch", schema_ref)
        return matches[0]

    def schema_document(self, schema_ref: str, digest: str | None = None) -> dict[str, Any]:
        entry = self._schema_entry(schema_ref, digest)
        return parse_json_bytes(self.resource_bytes(self._entry_resource(entry)))

    def schema_registry(self) -> Registry:
        registry = Registry()
        for entry in self._document["entries"]:
            if entry.get("kind") != "schema" or entry.get("current", True) is not True:
                continue
            self._verify_entry(entry)
            schema = parse_json_bytes(self.resource_bytes(self._entry_resource(entry)))
            registry = registry.with_resource(entry["schema_ref"], Resource.from_contents(schema))
        return registry

    def resolve_mechanism(self, binding: Mapping[str, Any]) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(self._resolve_binding(kind="mechanism", binding=binding, capability="mutation_mechanism")))

    def resolve_guarantee_vocabulary(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        entries = [
            entry
            for entry in self._document["entries"]
            if entry.get("kind") == "guarantee_vocabulary"
            and entry.get("id") == binding.get("id")
            and entry.get("version") == binding.get("version")
            and entry.get("artifact_digest") == binding.get("descriptor_digest")
        ]
        if not entries:
            raise PhaseError("registry.entry_not_found", str(binding.get("id", "unknown")))
        if len(entries) != 1:
            raise PhaseError("registry.entry_ambiguous", str(binding.get("id", "unknown")))
        entry = entries[0]
        self._verify_entry(entry)
        vocabulary = parse_json_bytes(self.resource_bytes(self._entry_resource(entry)))
        vocabulary_schema = self.schema_document("https://phase-tool.local/schemas/mutation-guarantee-vocabulary.schema.json")
        Draft202012Validator.check_schema(vocabulary_schema)
        errors = sorted(Draft202012Validator(vocabulary_schema).iter_errors(vocabulary), key=lambda item: list(item.path))
        if errors:
            raise PhaseError("guarantee_vocabulary.schema_invalid", errors[0].message)
        ids = [item["id"] for item in vocabulary["guarantees"]]
        if len(ids) != len(set(ids)):
            raise PhaseError("guarantee_vocabulary.duplicate_id", str(vocabulary["id"]))
        return deepcopy(vocabulary)

    def resolve_guarantee_profile(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        matches = [
            entry
            for entry in self._document["entries"]
            if entry.get("kind") == "guarantee_profile"
            and entry.get("id") == binding.get("id")
            and entry.get("version") == binding.get("version")
            and entry.get("artifact_digest") == binding.get("descriptor_digest")
        ]
        if not matches:
            raise PhaseError("registry.entry_not_found", str(binding.get("id", "unknown")))
        if len(matches) != 1:
            raise PhaseError("registry.entry_ambiguous", str(binding.get("id", "unknown")))
        entry = matches[0]
        if entry.get("capability") != "mutation_authority":
            raise PhaseError("registry.capability_mismatch", str(binding.get("id", "unknown")))
        self._verify_entry(entry)
        descriptor = parse_json_bytes(self.resource_bytes(self._entry_resource(entry)))

        profile_schema = self.schema_document("https://phase-tool.local/schemas/mutation-guarantee-profile.schema.json")
        Draft202012Validator.check_schema(profile_schema)
        errors = sorted(Draft202012Validator(profile_schema).iter_errors(descriptor), key=lambda item: list(item.path))
        if errors:
            raise PhaseError("guarantee_profile.schema_invalid", errors[0].message)

        vocabulary = self.resolve_guarantee_vocabulary(descriptor["vocabulary"])
        vocabulary_ids = {item["id"] for item in vocabulary["guarantees"]}
        provided = descriptor["provided_guarantees"]
        if not set(provided) <= vocabulary_ids:
            raise PhaseError("guarantee_profile.unknown_guarantee", descriptor["id"])
        conformance = [item["guarantee"] for item in descriptor["conformance"]]
        if sorted(conformance) != sorted(provided) or len(conformance) != len(set(conformance)):
            raise PhaseError("guarantee_profile.conformance_incomplete", descriptor["id"])

        implementation = descriptor["implementation"]
        prefix = "phase_tool/"
        artifact = implementation["artifact"]
        if not artifact.startswith(prefix):
            raise PhaseError("guarantee_profile.implementation_artifact_invalid", artifact)
        implementation_bytes = package_resources.files("phase_tool").joinpath(artifact[len(prefix) :]).read_bytes()
        if digest_bytes(implementation_bytes) != implementation["artifact_digest"]:
            raise PhaseError("guarantee_profile.implementation_digest_mismatch", descriptor["id"])
        return deepcopy(descriptor)

    def resolve_contract_hook(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        entry = self._resolve_binding(kind="contract_hook", binding=binding, capability="contract_hook")
        descriptor = parse_json_bytes(self.resource_bytes(self._entry_resource(entry)))
        if descriptor.get("execution_allowed") is not True:
            raise PhaseError("contract.hook_unavailable", str(binding["id"]))
        return descriptor

    def resolve_contract(self, identifier: str, version: str, package_digest: str, *, core_version: str) -> ResolvedContract:
        matches = self._exact_entries(kind="contract", identifier=identifier, version=version, package_digest=package_digest)
        if not matches:
            raise PhaseError("registry.entry_not_found", f"{identifier}@{version}")
        if len(matches) != 1:
            raise PhaseError("registry.entry_ambiguous", f"{identifier}@{version}")
        entry = matches[0]
        self._verify_entry(entry)
        contract = parse_json_bytes(self.resource_bytes(self._entry_resource(entry)))
        if contract.get("identity", {}).get("id") != identifier or contract.get("identity", {}).get("version") != version:
            raise PhaseError("registry.identity_mismatch", identifier)

        compatibility = contract["identity"]["core_compatibility"]
        current = _semver(core_version)
        if current < _semver(compatibility["minimum"]) or current >= _semver(compatibility["maximum_exclusive"]):
            raise PhaseError("contract.core_incompatible", core_version)

        contract_schema = self.schema_document("https://phase-tool.local/schemas/phase-contract.schema.json")
        Draft202012Validator.check_schema(contract_schema)
        errors = sorted(Draft202012Validator(contract_schema, format_checker=FormatChecker()).iter_errors(contract), key=lambda item: list(item.path))
        if errors:
            raise PhaseError("contract.schema_invalid", errors[0].message)

        self._schema_entry(contract["candidate"]["schema_ref"], contract["candidate"]["schema_digest"])
        self._schema_entry(contract["canonical_result"]["result_schema_ref"], contract["canonical_result"]["result_schema_digest"])
        self._schema_entry(contract["canonical_result"]["result_reference_schema_ref"])
        self._schema_entry(contract["evidence"]["receipt_schema_ref"], contract["evidence"]["receipt_schema_digest"])

        mechanism = contract["operation"]["mechanism"]
        if mechanism.get("availability") != "bundled_v1":
            raise PhaseError("mechanism.unavailable", mechanism["id"])
        self._resolve_binding(kind="mechanism", binding=mechanism, capability="mutation_mechanism")
        for effect_mechanism in contract["operation"].get("effect_mechanisms", []):
            if effect_mechanism.get("availability") != "bundled_v1":
                raise PhaseError("mechanism.unavailable", effect_mechanism["id"])
            self._resolve_binding(kind="mechanism", binding=effect_mechanism, capability="mutation_mechanism")
        for declaration in contract["validators"]:
            self._resolve_binding(kind="validator", binding=declaration["binding"], capability="validator")
        for binding in contract["verification"]["validators"]:
            self._resolve_binding(kind="validator", binding=binding, capability="validator")
        self._resolve_binding(kind="path_policy", binding=contract["write_scope"]["default_path_policy"], capability="path_policy")
        for root in contract["write_scope"]["roots"]:
            self._resolve_binding(kind="path_policy", binding=root["path_policy"], capability="path_policy")

        hook_descriptor = self.resolve_contract_hook(contract["contract_hook"]) if "contract_hook" in contract else None
        return ResolvedContract(
            document=contract,
            package_digest=package_digest,
            registry_snapshot_digest=self.digest,
            entry=MappingProxyType(deepcopy(entry)),
            contract_hook=hook_descriptor,
        )


class BundledRegistry:
    """Loads only package resources; it has no path, import, or network resolver."""

    @staticmethod
    def resources() -> dict[str, bytes]:
        root = package_resources.files("phase_tool").joinpath("data")
        result: dict[str, bytes] = {}

        def visit(node: Any, prefix: str = "") -> None:
            for child in node.iterdir():
                name = f"{prefix}{child.name}"
                if child.is_dir():
                    visit(child, name + "/")
                elif name != _REGISTRY_RESOURCE:
                    result[name] = child.read_bytes()

        visit(root)
        return result

    @staticmethod
    def load() -> RegistrySnapshot:
        root = package_resources.files("phase_tool").joinpath("data")
        document = parse_json_bytes(root.joinpath(_REGISTRY_RESOURCE).read_bytes())
        return RegistrySnapshot.from_document(document, BundledRegistry.resources())
