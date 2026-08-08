from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import phase_tool.installation as installation_module
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.installation import host_installation
from phase_tool.mutation.guarantees import registered_profile_binding, verify_guarantee_coverage
from phase_tool.mutation.platform import HostAuthorityProvider
from phase_tool.registry import BundledRegistry, RegistrySnapshot


VOCABULARY = {
    "id": "phase.mutation-guarantees",
    "version": "1.0.0",
    "descriptor_digest": "sha256:f7b158004b0bf7041286269c239c381cfd60db5987c6bf2173c645d5ac146624",
}
EXCLUSIVE_CREATE = {
    "id": "mechanism.exclusive_create_v1",
    "version": "1.0.0",
    "package_digest": "sha256:79564033bced595dda6c50b139c85d350c2eabbfbe586a17cfcbe5037884411b",
}
EXPECTED_HEAD_APPEND = {
    "id": "mechanism.expected_head_append_v1",
    "version": "1.0.0",
    "package_digest": "sha256:ee49db0f5f2f67c7ec8d5b252a2ebab6384c3032364e449dc4df588ab8880d4a",
}
OBJECT_STORE_PUBLISH = {
    "id": "mechanism.object_store_publish_v2",
    "version": "1.0.0",
    "package_digest": "sha256:da9b36ae4cbe25b9b17f0d107ff8263db6b95e2407010481a1ccc8e5a5d06fd0",
}


def requirements(*guarantees: str) -> dict[str, object]:
    return {
        "vocabulary": VOCABULARY,
        "mechanisms": [{"mechanism": EXCLUSIVE_CREATE, "all_of": list(guarantees)}],
    }


def test_contract_schema_accepts_versioned_technology_neutral_requirements() -> None:
    root = Path(__file__).parents[3]
    contract = json.loads((root / "contracts" / "fixtures" / "fixture_create.v1.json").read_text(encoding="utf-8"))
    contract["operation"]["required_guarantees"] = requirements("exclusive_create", "readback_verification")

    schema = json.loads((root / "schemas" / "phase-contract.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(contract)


def test_contract_requirement_rejects_guarantee_outside_exact_vocabulary() -> None:
    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(
            requirements("future_unproved_guarantee"),
            [EXCLUSIVE_CREATE],
            registered_profile_binding("phase.posix.authority.v1@1.0.0"),
            BundledRegistry.load(),
        )

    assert error.value.code == "guarantee.requirement_unknown"
    assert error.value.details == {"unknown": ["future_unproved_guarantee"]}


def test_contract_requirement_rejects_unknown_vocabulary_version() -> None:
    unsupported = requirements("exclusive_create")
    unsupported["vocabulary"] = dict(VOCABULARY) | {"version": "9.0.0"}

    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(
            unsupported,
            [EXCLUSIVE_CREATE],
            registered_profile_binding("phase.posix.authority.v1@1.0.0"),
            BundledRegistry.load(),
        )

    assert error.value.code == "guarantee.vocabulary_unsupported"


def test_contract_requirement_rejects_tampered_vocabulary_descriptor() -> None:
    registry = BundledRegistry.load()
    document = registry.to_document()
    vocabulary_entry = next(item for item in document["entries"] if item.get("kind") == "guarantee_vocabulary")
    resources = dict(BundledRegistry.resources())
    resources[vocabulary_entry["artifact"]] += b"\n"
    tampered = RegistrySnapshot.from_document(document, resources)

    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(
            requirements("exclusive_create"),
            [EXCLUSIVE_CREATE],
            registered_profile_binding("phase.posix.authority.v1@1.0.0"),
            tampered,
        )

    assert error.value.code == "registry.digest_mismatch"


def test_contract_requirement_rejects_duplicate_mechanism_mapping() -> None:
    duplicated = requirements("exclusive_create")
    duplicated["mechanisms"] = [
        {"mechanism": EXCLUSIVE_CREATE, "all_of": ["exclusive_create"]},
        {"mechanism": EXCLUSIVE_CREATE, "all_of": ["readback_verification"]},
    ]

    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(
            duplicated,
            [EXCLUSIVE_CREATE],
            registered_profile_binding("phase.posix.authority.v1@1.0.0"),
            BundledRegistry.load(),
        )

    assert error.value.code == "guarantee.requirement_mechanism_duplicate"


@pytest.mark.parametrize(
    ("mapped", "code", "details"),
    [
        ([], "guarantee.requirement_mechanism_missing", {"mechanisms": ["mechanism.exclusive_create_v1"]}),
        (
            [
                {"mechanism": EXCLUSIVE_CREATE, "all_of": ["exclusive_create"]},
                {"mechanism": OBJECT_STORE_PUBLISH, "all_of": ["atomic_replace"]},
            ],
            "guarantee.requirement_mechanism_extra",
            {"mechanisms": ["mechanism.object_store_publish_v2"]},
        ),
    ],
)
def test_contract_requirement_rejects_missing_or_extra_mechanism_mapping(
    mapped: list[dict[str, object]],
    code: str,
    details: dict[str, list[str]],
) -> None:
    invalid = {"vocabulary": VOCABULARY, "mechanisms": mapped}

    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(
            invalid,
            [EXCLUSIVE_CREATE],
            registered_profile_binding("phase.posix.authority.v1@1.0.0"),
            BundledRegistry.load(),
        )

    assert error.value.code == code
    assert error.value.details == details


def test_mechanism_managed_requirement_cannot_claim_authority_guarantees() -> None:
    invalid = {
        "vocabulary": VOCABULARY,
        "mechanisms": [{"mechanism": EXPECTED_HEAD_APPEND, "all_of": ["cross_process_serialization"]}],
    }

    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(invalid, [EXPECTED_HEAD_APPEND], None, BundledRegistry.load())

    assert error.value.code == "guarantee.mechanism_managed_requirements"


def test_profile_implementation_disagreement_is_rejected() -> None:
    profile = registered_profile_binding("phase.posix.authority.v1@1.0.0")
    mismatched = replace(profile, implementation_artifact_digest="sha256:" + "0" * 64)

    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(
            requirements("exclusive_create"),
            [EXCLUSIVE_CREATE],
            mismatched,
            BundledRegistry.load(),
        )

    assert error.value.code == "guarantee.profile_implementation_mismatch"


def test_unknown_profile_digest_is_rejected() -> None:
    profile = registered_profile_binding("phase.posix.authority.v1@1.0.0")
    unsupported = replace(profile, descriptor_digest="sha256:" + "0" * 64)

    with pytest.raises(PhaseError) as error:
        verify_guarantee_coverage(
            requirements("exclusive_create"),
            [EXCLUSIVE_CREATE],
            unsupported,
            BundledRegistry.load(),
        )

    assert error.value.code == "guarantee.profile_unsupported"


def test_installation_profile_and_provider_report_must_agree_before_capture(tmp_path: Path) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    target = tmp_path / "target"
    target.mkdir()
    installation = host_installation()
    assert installation.authority_profile_binding is not None
    mismatched_installation = replace(
        installation,
        authority_profile_binding=replace(
            installation.authority_profile_binding,
            implementation_artifact_digest="sha256:" + "0" * 64,
        ),
    )
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=tmp_path / "candidate-must-not-be-read.json",
        evidence_root=tmp_path / "evidence",
        run_id="profile-provider-disagreement",
        input_paths={"payload": tmp_path / "payload-must-not-be-read.bin"},
        root_bindings={"fixture_result_root": target},
        timestamp="2026-08-05T00:00:00Z",
    )

    outcome = PhaseCore(installation=mismatched_installation).run(request, execute=True)

    assert outcome.receipt["blockers"] == ["guarantee.profile_provider_disagreement"]
    assert outcome.lifecycle == ("resolve", "guarantees", "receipt")
    assert outcome.intent is None
    assert outcome.effect_plan is None


def test_host_installation_selects_profile_independently_of_provider_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_key = "phase.posix.authority.v1@1.0.0"
    monkeypatch.setattr(
        HostAuthorityProvider,
        "guarantee_profile_binding",
        lambda _self: replace(registered_profile_binding(configured_key), descriptor_digest="sha256:" + "0" * 64),
    )

    installation = host_installation()

    assert installation.authority_profile_binding == registered_profile_binding(configured_key)


def test_non_linux_runtime_rejects_mutation_before_capture_or_authority_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(installation_module.sys, "platform", "unsupported-test-host")

    def forbidden_open(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("authority must not open on an unsupported runtime")

    monkeypatch.setattr(HostAuthorityProvider, "open_authority", forbidden_open)
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=tmp_path / "candidate-must-not-be-read.json",
        evidence_root=tmp_path / "evidence",
        run_id="unsupported-runtime",
        input_paths={"payload": tmp_path / "payload-must-not-be-read.bin"},
        root_bindings={"fixture_result_root": target},
        timestamp="2026-08-05T00:00:00Z",
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["blockers"] == ["platform.mutation_unsupported"]
    assert outcome.lifecycle == ("resolve", "guarantees", "receipt")
    assert outcome.intent is None
    assert outcome.effect_plan is None
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("binding_key", ["fixture_create.v1@1.0.0", "fixture_append.v1@1.0.0"])
def test_uncreated_root_is_rejected_with_receipt_before_capture(tmp_path: Path, binding_key: str) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()[binding_key]
    future_root = tmp_path / "not-created" / "result-root"
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=tmp_path / "candidate-must-not-be-read.json",
        evidence_root=tmp_path / "evidence",
        run_id="uncreated-profile-scope-root",
        input_paths={"payload": tmp_path / "payload-must-not-be-read.bin"},
        root_bindings={"fixture_result_root": future_root},
        timestamp="2026-08-05T00:00:00Z",
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["blockers"] == ["guarantee.profile_scope_unsupported"]
    assert outcome.lifecycle == ("resolve", "guarantees", "receipt")
    assert outcome.intent is None
    assert outcome.effect_plan is None
    assert not future_root.exists()


def test_unqualified_filesystem_scope_is_rejected_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(installation_module, "_linux_filesystem_type", lambda _path: "nfs")
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=tmp_path / "candidate-must-not-be-read.json",
        evidence_root=tmp_path / "evidence",
        run_id="unqualified-profile-scope",
        input_paths={"payload": tmp_path / "payload-must-not-be-read.bin"},
        root_bindings={"fixture_result_root": target},
        timestamp="2026-08-05T00:00:00Z",
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["blockers"] == ["guarantee.profile_scope_unsupported"]
    assert outcome.lifecycle == ("resolve", "guarantees", "receipt")
    assert outcome.intent is None
    assert outcome.effect_plan is None
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    assert sorted(path.name for path in run_root.iterdir()) == ["receipt.json"]
    assert list(target.iterdir()) == []


def test_mechanism_managed_unqualified_scope_is_rejected_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_append.v1@1.0.0"]
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(installation_module, "_linux_filesystem_type", lambda _path: "nfs")
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=tmp_path / "candidate-must-not-be-read.json",
        evidence_root=tmp_path / "evidence",
        run_id="mechanism-managed-unqualified-root",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp="2026-08-05T00:00:00Z",
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["blockers"] == ["guarantee.profile_scope_unsupported"]
    assert outcome.lifecycle == ("resolve", "guarantees", "receipt")
    assert outcome.intent is None
    assert outcome.effect_plan is None
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    assert sorted(path.name for path in run_root.iterdir()) == ["receipt.json"]


def test_mechanism_managed_symlink_root_is_rejected_before_capture(tmp_path: Path) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_append.v1@1.0.0"]
    actual = tmp_path / "actual-target"
    actual.mkdir()
    target = tmp_path / "target-link"
    target.symlink_to(actual, target_is_directory=True)
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=tmp_path / "candidate-must-not-be-read.json",
        evidence_root=tmp_path / "evidence",
        run_id="mechanism-managed-symlink-root",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp="2026-08-05T00:00:00Z",
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["blockers"] == ["guarantee.profile_scope_unsupported"]
    assert outcome.lifecycle == ("resolve", "guarantees", "receipt")
    assert outcome.intent is None
    assert outcome.effect_plan is None


@pytest.mark.parametrize(
    "binding_key",
    ["fixture_create.v1@1.0.0", "fixture_append.v1@1.0.0"],
)
def test_missing_write_root_cannot_bypass_scope_qualification(
    tmp_path: Path,
    binding_key: str,
) -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()[binding_key]
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=tmp_path / "candidate-must-not-be-read.json",
        evidence_root=tmp_path / "evidence",
        run_id="missing-profile-scope-root",
        input_paths={"payload": tmp_path / "payload-must-not-be-read.bin"},
        root_bindings={},
        timestamp="2026-08-05T00:00:00Z",
    )

    outcome = PhaseCore().run(request, execute=True)

    assert outcome.receipt["blockers"] == ["guarantee.profile_scope_unsupported"]
    assert outcome.lifecycle == ("resolve", "guarantees", "receipt")
    assert outcome.intent is None
    assert outcome.effect_plan is None
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    assert sorted(path.name for path in run_root.iterdir()) == ["receipt.json"]


@pytest.mark.skipif(os.name == "nt", reason="WSL scope applies to POSIX host selection")
def test_wsl_root_is_not_admitted_as_posix_production(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(installation_module, "_linux_filesystem_type", lambda _path: "ext4")
    monkeypatch.setattr(installation_module, "_is_wsl", lambda: True)

    with pytest.raises(PhaseError) as error:
        host_installation().qualify_authority_roots({"result_root": tmp_path})

    assert error.value.code == "guarantee.profile_scope_unsupported"
    assert error.value.details == {"binding_id": "result_root", "filesystem": "wsl:ext4"}


@pytest.mark.skipif(os.name == "nt", reason="Linux container classification")
def test_overlay_root_container_is_not_classified_as_wsl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(installation_module, "_linux_kernel_release", lambda: "6.6.87.2-microsoft-standard-WSL2")
    monkeypatch.setattr(installation_module, "_linux_filesystem_type", lambda path: "overlay")

    assert installation_module._is_wsl() is False


@pytest.mark.skipif(os.name == "nt", reason="Linux WSL classification")
def test_non_containerized_microsoft_kernel_is_classified_as_wsl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(installation_module, "_linux_kernel_release", lambda: "6.6.87.2-microsoft-standard-WSL2")
    monkeypatch.setattr(installation_module, "_linux_filesystem_type", lambda path: "ext4")

    assert installation_module._is_wsl() is True


@pytest.mark.skipif(os.name == "nt", reason="Linux WSL classification")
def test_marker_file_does_not_bypass_wsl_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(installation_module, "_linux_kernel_release", lambda: "6.6.87.2-microsoft-standard-WSL2")
    monkeypatch.setattr(installation_module, "_linux_filesystem_type", lambda path: "ext4")
    monkeypatch.setattr(Path, "is_file", lambda self: str(self) in {"/.dockerenv", "/run/.containerenv"})

    assert installation_module._is_wsl() is True


@pytest.mark.skipif(os.name == "nt", reason="Linux WSL classification")
def test_unreadable_kernel_release_fails_closed_as_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreadable_release() -> str:
        raise OSError("unavailable")

    monkeypatch.setattr(installation_module, "_linux_kernel_release", unreadable_release)

    assert installation_module._is_wsl() is True


@pytest.mark.skipif(os.name == "nt", reason="Linux host classification")
@pytest.mark.parametrize("release", ["", "   ", "garbled-release"])
def test_malformed_kernel_release_fails_closed(release: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(installation_module, "_linux_kernel_release", lambda: release)

    assert installation_module._is_wsl() is True


@pytest.mark.skipif(os.name == "nt", reason="Linux WSL classification")
def test_linux_scope_uses_one_wsl_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observations = iter((False, True))
    calls = 0

    def observe_wsl() -> bool:
        nonlocal calls
        calls += 1
        return next(observations)

    monkeypatch.setattr(installation_module, "_is_wsl", observe_wsl)
    monkeypatch.setattr(installation_module, "_linux_filesystem_type", lambda path: "ext4")

    installation_module.qualify_host_authority_roots({"result_root": tmp_path})

    assert calls == 1


def test_loop4_contract_and_schema_generation_remain_exactly_resolvable() -> None:
    registry = BundledRegistry.load()
    historical = registry.resolve_contract(
        "fixture_create.v1",
        "1.0.0",
        "sha256:3c9c88505eebf2427afd4bd6c5ef3730f915b3955405bd97a3408002bdb92d03",
        core_version="1.0.0",
    )
    current_binding = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    current = registry.resolve_contract(
        current_binding["id"],
        current_binding["version"],
        current_binding["package_digest"],
        core_version="1.0.0",
    )
    historical_schema = registry.schema_document(
        "https://phase-tool.local/schemas/phase-contract.schema.json",
        "sha256:b26d09bc1f562998f60ee3beb90244bbd5f0e51c9704d06bb264c5384709dadc",
    )

    assert "required_guarantees" not in historical.document["operation"]
    assert "required_guarantees" in current.document["operation"]
    assert "required_guarantees" not in historical_schema["properties"]["operation"]["properties"]
