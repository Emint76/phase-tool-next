from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.registry import BundledRegistry, RegistrySnapshot


ROOT = Path(__file__).resolve().parents[1]


def _git_index_bytes(path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f":{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def test_phase_canonical_json_v1_has_exact_bytes() -> None:
    assert canonical_bytes({"b": 2, "a": "e\u0301"}) == b'{"a":"\xc3\xa9","b":2}'
    assert canonical_digest({"b": 2, "a": "e\u0301"}) == "sha256:06c264c46ad5ada9493abd3aa2383fb205ae99d7d0bad40b03a43bfec8a1b8de"


def test_canonical_profile_rejects_float_duplicate_keys_and_excessive_nesting() -> None:
    with pytest.raises(PhaseError, match="canonical.float_forbidden"):
        canonical_bytes({"value": 1.5})
    with pytest.raises(PhaseError, match="candidate.duplicate_key"):
        parse_json_bytes(b'{"a":1,"a":2}')
    nested = b"[" * 70 + b"0" + b"]" * 70
    with pytest.raises(PhaseError, match="candidate.maximum_depth_exceeded"):
        parse_json_bytes(nested, maximum_bytes=1024)


def test_exact_bundled_contract_resolution_succeeds() -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_append.v1@1.0.0"]
    resolved = registry.resolve_contract("fixture_append.v1", "1.0.0", binding["package_digest"], core_version="1.0.0")
    assert resolved.document["identity"]["id"] == "fixture_append.v1"
    assert resolved.package_digest == binding["package_digest"]
    assert resolved.registry_snapshot_digest == registry.digest


def test_registry_digests_match_git_index_and_package_resources() -> None:
    registry = BundledRegistry.load()
    resources = BundledRegistry.resources()
    for entry in registry.to_document()["entries"]:
        artifact = entry["artifact"]
        physical_artifact = entry.get("archive_resource", artifact)
        committed = _git_index_bytes(f"src/phase_tool/data/{physical_artifact}")
        assert resources[physical_artifact] == committed, physical_artifact
        assert entry["artifact_digest"] == digest_bytes(committed), physical_artifact

        package_artifacts = entry.get("package_artifacts")
        if package_artifacts is None:
            continue
        verified = []
        for item in package_artifacts:
            physical_resource = item.get("archive_resource", item["resource"])
            committed = _git_index_bytes(f"src/phase_tool/data/{physical_resource}")
            assert resources[physical_resource] == committed, physical_resource
            assert item["digest"] == digest_bytes(committed), physical_resource
            verified.append({"resource": item["resource"], "digest": digest_bytes(committed)})
        assert entry["package_digest"] == canonical_digest(
            {"profile": "phase_contract_package_v1", "artifacts": verified}
        ), entry["id"]


def test_hash_bound_text_artifacts_are_forced_to_lf() -> None:
    registry = BundledRegistry.load().to_document()
    paths = {"src/phase_tool/data/registry.json", "fixtures/manifest.sha256"}
    paths.update(
        f"src/phase_tool/data/{entry.get('archive_resource', entry['artifact'])}"
        for entry in registry["entries"]
    )
    paths.update(
        f"src/phase_tool/data/{item.get('archive_resource', item['resource'])}"
        for entry in registry["entries"]
        for item in entry.get("package_artifacts", [])
    )
    for line in (ROOT / "fixtures" / "manifest.sha256").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            locator = line.split("  ", 1)[1]
            if Path(locator).suffix in {".json", ".md", ".sha256", ".txt"}:
                paths.add(locator)

    completed = subprocess.run(
        ["git", "check-attr", "-z", "eol", "--", *sorted(paths)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    fields = completed.stdout.decode("utf-8").split("\0")
    attributes = dict(zip(fields[0::3], fields[2::3]))
    assert attributes == {path: "lf" for path in sorted(paths)}


def test_wrong_contract_digest_and_version_fail_closed() -> None:
    registry = BundledRegistry.load()
    with pytest.raises(PhaseError) as wrong_digest:
        registry.resolve_contract("fixture_append.v1", "1.0.0", "sha256:" + "0" * 64, core_version="1.0.0")
    assert wrong_digest.value.code == "registry.entry_not_found"
    with pytest.raises(PhaseError) as wrong_version:
        registry.resolve_contract("fixture_append.v1", "9.9.9", "sha256:" + "0" * 64, core_version="1.0.0")
    assert wrong_version.value.code == "registry.entry_not_found"


def test_duplicate_contract_versions_have_one_explicit_current_binding() -> None:
    registry = BundledRegistry.load()
    document = registry.to_document()
    bindings = registry.contract_bindings()
    grouped: dict[str, list[dict[str, object]]] = {}
    for entry in document["entries"]:
        if entry.get("kind") != "contract":
            continue
        grouped.setdefault(f"{entry['id']}@{entry['version']}", []).append(entry)
    for exact_binding, entries in grouped.items():
        if len(entries) == 1:
            continue
        current = [entry for entry in entries if entry.get("current") is True]
        assert len(current) == 1, exact_binding
        assert bindings[exact_binding]["package_digest"] == current[0]["package_digest"]


def test_contract_bindings_reject_multiple_current_entries() -> None:
    document = BundledRegistry.load().to_document()
    historical = next(
        entry
        for entry in document["entries"]
        if entry.get("kind") == "contract"
        and entry.get("id") == "fixture_copy.v1"
        and entry.get("current") is False
    )
    historical["current"] = True
    snapshot = RegistrySnapshot.from_document(document, BundledRegistry.resources())
    with pytest.raises(PhaseError) as error:
        snapshot.contract_bindings()
    assert error.value.code == "registry.entry_ambiguous"


def test_contract_bindings_reject_zero_current_entries() -> None:
    document = BundledRegistry.load().to_document()
    for entry in document["entries"]:
        if entry.get("kind") == "contract" and entry.get("id") == "fixture_copy.v1":
            entry["current"] = False
    snapshot = RegistrySnapshot.from_document(document, BundledRegistry.resources())
    with pytest.raises(PhaseError) as error:
        snapshot.contract_bindings()
    assert error.value.code == "registry.entry_ambiguous"


def test_ambiguous_mutable_and_untrusted_entries_fail_closed() -> None:
    base = BundledRegistry.load().to_document()
    contract = next(x for x in base["entries"] if x["kind"] == "contract" and x["id"] == "fixture_append.v1")

    ambiguous = deepcopy(base)
    ambiguous["entries"].append(deepcopy(contract))
    with pytest.raises(PhaseError) as error:
        RegistrySnapshot.from_document(ambiguous, BundledRegistry.resources()).resolve_contract(
            contract["id"], contract["version"], contract["package_digest"], core_version="1.0.0"
        )
    assert error.value.code == "registry.entry_ambiguous"

    mutable = deepcopy(base)
    next(x for x in mutable["entries"] if x == contract)["mutable"] = True
    with pytest.raises(PhaseError) as error:
        RegistrySnapshot.from_document(mutable, BundledRegistry.resources()).resolve_contract(
            contract["id"], contract["version"], contract["package_digest"], core_version="1.0.0"
        )
    assert error.value.code == "registry.mutable_reference"

    untrusted = deepcopy(base)
    next(x for x in untrusted["entries"] if x == contract)["trust_root_id"] = "unknown.root"
    with pytest.raises(PhaseError) as error:
        RegistrySnapshot.from_document(untrusted, BundledRegistry.resources()).resolve_contract(
            contract["id"], contract["version"], contract["package_digest"], core_version="1.0.0"
        )
    assert error.value.code == "registry.untrusted"


def test_core_compatibility_and_mechanism_capability_are_enforced() -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_copy.v1@1.0.0"]
    with pytest.raises(PhaseError) as incompatible:
        registry.resolve_contract("fixture_copy.v1", "1.0.0", binding["package_digest"], core_version="2.0.0")
    assert incompatible.value.code == "contract.core_incompatible"

    document = registry.to_document()
    mechanism = next(x for x in document["entries"] if x["kind"] == "mechanism" and x["id"] == "content_addressed_copy")
    mechanism["capability"] = "validator"
    broken = RegistrySnapshot.from_document(document, BundledRegistry.resources())
    with pytest.raises(PhaseError) as capability:
        broken.resolve_contract("fixture_copy.v1", "1.0.0", binding["package_digest"], core_version="1.0.0")
    assert capability.value.code == "registry.capability_mismatch"


def test_registry_mechanism_descriptor_identity_matches_binding() -> None:
    registry = BundledRegistry.load()
    document = registry.to_document()
    resources = BundledRegistry.resources()
    for entry in document["entries"]:
        if entry.get("kind") != "mechanism":
            continue
        descriptor = parse_json_bytes(resources[entry["artifact"]])
        assert descriptor["id"] == entry["id"]
        assert descriptor["version"] == entry["version"]
        assert descriptor["capability"] == entry["capability"]


def test_fixture_copy_contract_allows_only_copy_blob() -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_copy.v1@1.0.0"]
    contract = registry.resolve_contract("fixture_copy.v1", "1.0.0", binding["package_digest"], core_version="1.0.0")
    assert contract.document["operation"]["allowed_effects"] == ["copy_blob"]


def test_untrusted_mechanism_and_artifact_drift_fail_closed() -> None:
    base = BundledRegistry.load().to_document()
    binding = BundledRegistry.load().contract_bindings()["fixture_copy.v1@1.0.0"]
    mechanism = next(x for x in base["entries"] if x["kind"] == "mechanism" and x["id"] == "content_addressed_copy")
    mechanism["trust_root_id"] = "unknown.root"
    with pytest.raises(PhaseError) as untrusted:
        RegistrySnapshot.from_document(base, BundledRegistry.resources()).resolve_contract(
            "fixture_copy.v1", "1.0.0", binding["package_digest"], core_version="1.0.0"
        )
    assert untrusted.value.code == "registry.untrusted"

    clean = BundledRegistry.load().to_document()
    contract = next(
        x
        for x in clean["entries"]
        if x["kind"] == "contract"
        and x["id"] == "fixture_copy.v1"
        and x["package_digest"] == binding["package_digest"]
    )
    resources = dict(BundledRegistry.resources())
    resources[contract["artifact"]] = resources[contract["artifact"]] + b" "
    with pytest.raises(PhaseError) as drift:
        RegistrySnapshot.from_document(clean, resources).resolve_contract(
            "fixture_copy.v1", "1.0.0", binding["package_digest"], core_version="1.0.0"
        )
    assert drift.value.code == "registry.digest_mismatch"


def test_registry_has_no_network_or_executable_coordinates() -> None:
    registry = BundledRegistry.load()
    document = registry.to_document()
    encoded = json.dumps(document).lower()
    assert all(
        entry["artifact"] in BundledRegistry.resources()
        and "://" not in entry["artifact"]
        and not entry["artifact"].startswith(("/", "\\"))
        for entry in document["entries"]
    )
    assert not hasattr(registry, "retrieve_remote")
    assert all(key not in encoded for key in ('"command"', '"shell"', '"import"', '"entry_point"', '"executable"'))
