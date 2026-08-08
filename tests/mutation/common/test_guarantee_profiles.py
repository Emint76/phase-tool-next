from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import pytest

from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import host_installation
from phase_tool.mutation.guarantees import GuaranteeProfileBinding
from phase_tool.registry import BundledRegistry, RegistrySnapshot

ROOT = Path(__file__).resolve().parents[3]


def _mutated_profile_registry(profile_id: str, mutate: object) -> tuple[RegistrySnapshot, dict[str, str]]:
    bundled = BundledRegistry.load()
    document = bundled.to_document()
    resources = dict(BundledRegistry.resources())
    entry = next(item for item in document["entries"] if item.get("kind") == "guarantee_profile" and item["id"] == profile_id)
    descriptor = parse_json_bytes(resources[entry["artifact"]])
    mutate(descriptor)  # type: ignore[operator]
    raw = canonical_bytes(descriptor)
    resources[entry["artifact"]] = raw
    descriptor_digest = digest_bytes(raw)
    entry["artifact_digest"] = descriptor_digest
    for artifact in entry["package_artifacts"]:
        if artifact["resource"] == entry["artifact"]:
            artifact["digest"] = descriptor_digest
    entry["package_digest"] = canonical_digest(
        {"profile": "phase_contract_package_v1", "artifacts": deepcopy(entry["package_artifacts"])}
    )
    binding = {"id": entry["id"], "version": entry["version"], "descriptor_digest": descriptor_digest}
    return RegistrySnapshot.from_document(document, resources), binding


def _mutated_vocabulary_registry(mutate: object) -> tuple[RegistrySnapshot, dict[str, str]]:
    document = BundledRegistry.load().to_document()
    resources = dict(BundledRegistry.resources())
    vocabulary_entry = next(item for item in document["entries"] if item.get("kind") == "guarantee_vocabulary")
    vocabulary = parse_json_bytes(resources[vocabulary_entry["artifact"]])
    mutate(vocabulary)  # type: ignore[operator]
    vocabulary_raw = canonical_bytes(vocabulary)
    vocabulary_digest = digest_bytes(vocabulary_raw)
    resources[vocabulary_entry["artifact"]] = vocabulary_raw
    vocabulary_entry["artifact_digest"] = vocabulary_digest
    for artifact in vocabulary_entry["package_artifacts"]:
        if artifact["resource"] == vocabulary_entry["artifact"]:
            artifact["digest"] = vocabulary_digest
    vocabulary_entry["package_digest"] = canonical_digest(
        {"profile": "phase_contract_package_v1", "artifacts": deepcopy(vocabulary_entry["package_artifacts"])}
    )

    selected_binding: dict[str, str] | None = None
    for entry in document["entries"]:
        if entry.get("kind") != "guarantee_profile":
            continue
        profile = parse_json_bytes(resources[entry["artifact"]])
        profile["vocabulary"]["descriptor_digest"] = vocabulary_digest
        profile_raw = canonical_bytes(profile)
        profile_digest = digest_bytes(profile_raw)
        resources[entry["artifact"]] = profile_raw
        entry["artifact_digest"] = profile_digest
        for artifact in entry["package_artifacts"]:
            if artifact["resource"] == entry["artifact"]:
                artifact["digest"] = profile_digest
            elif artifact["resource"] == vocabulary_entry["artifact"]:
                artifact["digest"] = vocabulary_digest
        entry["package_digest"] = canonical_digest(
            {"profile": "phase_contract_package_v1", "artifacts": deepcopy(entry["package_artifacts"])}
        )
        if entry["id"] == "phase.posix.authority.v1":
            selected_binding = {"id": entry["id"], "version": entry["version"], "descriptor_digest": profile_digest}
    assert selected_binding is not None
    return RegistrySnapshot.from_document(document, resources), selected_binding


def test_guarantee_profile_binding_is_exact_and_digest_bound() -> None:
    binding = GuaranteeProfileBinding(
        id="phase.posix.authority.v1",
        version="1.0.0",
        descriptor_digest="sha256:" + "1" * 64,
        implementation_id="phase.posix.authority",
        implementation_version="1.0.0",
        implementation_artifact_digest="sha256:" + "2" * 64,
    )

    assert binding.as_dict() == {
        "id": "phase.posix.authority.v1",
        "version": "1.0.0",
        "descriptor_digest": "sha256:" + "1" * 64,
    }


def test_bundled_guarantee_profiles_are_schema_and_digest_valid() -> None:
    registry = BundledRegistry.load()
    bindings = registry.guarantee_profile_bindings()

    assert set(bindings) == {"phase.posix.authority.v1@1.0.0"}
    posix = registry.resolve_guarantee_profile(bindings["phase.posix.authority.v1@1.0.0"])
    assert posix["classification"] == "production"


def test_profile_conformance_bindings_name_real_executable_tests() -> None:
    registry = BundledRegistry.load()

    for binding in registry.guarantee_profile_bindings().values():
        profile = registry.resolve_guarantee_profile(binding)
        for conformance in profile["conformance"]:
            relative, node_id = conformance["test_id"].split("::", 1)
            test_path = ROOT / relative
            assert test_path.is_file(), conformance["test_id"]
            functions = {
                node.name
                for node in ast.walk(ast.parse(test_path.read_text(encoding="utf-8")))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            assert node_id in functions, conformance["test_id"]


def test_wrong_profile_descriptor_digest_fails_closed() -> None:
    registry = BundledRegistry.load()
    binding = registry.guarantee_profile_bindings()["phase.posix.authority.v1@1.0.0"]
    tampered = {**binding, "descriptor_digest": "sha256:" + "0" * 64}

    with pytest.raises(PhaseError) as error:
        registry.resolve_guarantee_profile(tampered)

    assert error.value.code == "registry.entry_not_found"


def test_host_provider_exposes_its_exact_registered_profile_binding() -> None:
    registry = BundledRegistry.load()
    provider = host_installation().authority_provider

    binding = provider.guarantee_profile_binding()

    assert binding.as_dict() in registry.guarantee_profile_bindings().values()
    profile = registry.resolve_guarantee_profile(binding.as_dict())
    assert profile["implementation"]["id"] == binding.implementation_id
    assert profile["implementation"]["version"] == binding.implementation_version
    assert profile["implementation"]["artifact_digest"] == binding.implementation_artifact_digest


def test_profile_cannot_claim_unknown_guarantee() -> None:
    def mutate(descriptor: dict[str, object]) -> None:
        descriptor["provided_guarantees"].append("process_crash_recovery")  # type: ignore[union-attr]
        descriptor["conformance"].append(  # type: ignore[union-attr]
            {"guarantee": "process_crash_recovery", "test_id": "nonexistent"}
        )

    registry, binding = _mutated_profile_registry("phase.posix.authority.v1", mutate)

    with pytest.raises(PhaseError) as error:
        registry.resolve_guarantee_profile(binding)

    assert error.value.code == "guarantee_profile.schema_invalid"


def test_profile_cannot_claim_guarantee_without_exact_conformance_evidence() -> None:
    def mutate(descriptor: dict[str, object]) -> None:
        descriptor["conformance"].pop()  # type: ignore[union-attr]

    registry, binding = _mutated_profile_registry("phase.posix.authority.v1", mutate)

    with pytest.raises(PhaseError) as error:
        registry.resolve_guarantee_profile(binding)

    assert error.value.code == "guarantee_profile.schema_invalid"


def test_profile_cannot_rebind_conformance_to_nonexistent_test() -> None:
    def mutate(descriptor: dict[str, object]) -> None:
        conformance = descriptor["conformance"]
        assert isinstance(conformance, list)
        conformance[0]["test_id"] = "tests::nonexistent"  # type: ignore[index]

    registry, binding = _mutated_profile_registry("phase.posix.authority.v1", mutate)

    with pytest.raises(PhaseError) as error:
        registry.resolve_guarantee_profile(binding)

    assert error.value.code == "guarantee_profile.schema_invalid"


def test_profile_implementation_artifact_digest_mismatch_fails_closed() -> None:
    def mutate(descriptor: dict[str, object]) -> None:
        descriptor["implementation"]["artifact_digest"] = "sha256:" + "0" * 64  # type: ignore[index]

    registry, binding = _mutated_profile_registry("phase.posix.authority.v1", mutate)

    with pytest.raises(PhaseError) as error:
        registry.resolve_guarantee_profile(binding)

    assert error.value.code == "guarantee_profile.implementation_digest_mismatch"


def test_profile_identity_cannot_be_rebound_to_another_provider_identity() -> None:
    def mutate(descriptor: dict[str, object]) -> None:
        implementation = descriptor["implementation"]
        assert isinstance(implementation, dict)
        implementation["id"] = "phase.alternate.authority"

    registry, binding = _mutated_profile_registry("phase.posix.authority.v1", mutate)

    with pytest.raises(PhaseError) as error:
        registry.resolve_guarantee_profile(binding)

    assert error.value.code == "guarantee_profile.schema_invalid"


def test_vocabulary_cannot_define_one_guarantee_id_twice() -> None:
    def mutate(vocabulary: dict[str, object]) -> None:
        guarantees = vocabulary["guarantees"]
        assert isinstance(guarantees, list)
        duplicate = deepcopy(guarantees[0])
        duplicate["definition"] = "A conflicting second definition for the same identifier."
        guarantees.append(duplicate)

    registry, binding = _mutated_vocabulary_registry(mutate)

    with pytest.raises(PhaseError) as error:
        registry.resolve_guarantee_profile(binding)

    assert error.value.code == "guarantee_vocabulary.duplicate_id"
