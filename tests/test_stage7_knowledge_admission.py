from __future__ import annotations

import ast
import hashlib
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from phase_tool.canonical import canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.contracts.knowledge_admission_v1 import verify_result_reference
from phase_tool.contracts.source_admission_v1 import admission_canonical_bytes
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run
from phase_tool.mutation import BrokerFaults
from phase_tool.paths import _platform_path, contained_read_path
from phase_tool.registry import BundledRegistry

NOW = "2026-07-29T12:00:00Z"
ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "phase_tool"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _binding(contract_id: str) -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()[f"{contract_id}@1.0.0"]


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _read_target(root: Path, locator: str) -> bytes:
    path = contained_read_path(root, locator)
    with open(_platform_path(path), "rb") as stream:
        return stream.read()


def _source_candidate(payload: bytes, *, operation_id: str, logical_id: str = "source-manual-001") -> dict[str, object]:
    return {
        "candidate_version": "1.0",
        "contract": {"id": "source_admission.v1", "version": "1.0.0"},
        "operation_id": operation_id,
        "idempotency_key": operation_id,
        "logical_source_id": logical_id,
        "asset_input": {"binding_id": "asset", "expected_digest": _sha(payload), "expected_length": len(payload)},
        "declared_media_type": "application/pdf",
        "original_filename": "manual.pdf",
        "provenance": {
            "provenance_version": "1.0",
            "origin": {"kind": "external_uri", "locator": "https://example.invalid/manual.pdf", "label": "manual"},
            "supplied_by": {"kind": "adapter", "identifier": "adapter.example"},
        },
        "placement": {"target_root_binding": "admission_result_root", "namespace": "example"},
        "supersedes": None,
        "request_metadata": {"submitted_by": "adapter.example", "correlation_id": operation_id},
    }


def _admit_source(
    tmp_path: Path,
    *,
    run_id: str = "source-run",
    payload: bytes = b"source bytes\n",
    operation_id: str = "op-source-001",
    logical_id: str = "source-manual-001",
) -> tuple[Path, Path, dict[str, object]]:
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    evidence = tmp_path / "evidence"
    source = tmp_path / f"{run_id}.bin"
    candidate = tmp_path / f"{run_id}.json"
    source.write_bytes(payload)
    _write_json(candidate, _source_candidate(payload, operation_id=operation_id, logical_id=logical_id))
    request = PhaseRequest(
        contract_id="source_admission.v1",
        contract_version="1.0.0",
        contract_digest=_binding("source_admission.v1")["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths={"asset": source},
        root_bindings={"admission_result_root": target},
        timestamp=NOW,
    )
    outcome = PhaseCore().run(request, execute=True)
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    source_binding = inspect_run(evidence, run_id, root_bindings={"admission_result_root": target})["contract_result"]["binding"]
    return target, evidence, source_binding


def _knowledge_candidate(
    artifact: bytes,
    source_bindings: list[dict[str, object]],
    *,
    operation_id: str = "op-knowledge-001",
    logical_id: str = "knowledge-summary-001",
    producer_identifier: str = "producer.example",
    supersedes: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "candidate_version": "1.0",
        "contract": {"id": "knowledge_admission.v1", "version": "1.0.0"},
        "operation_id": operation_id,
        "idempotency_key": operation_id,
        "logical_knowledge_id": logical_id,
        "artifact_input": {"binding_id": "asset", "expected_digest": _sha(artifact), "expected_length": len(artifact)},
        "artifact_kind": "document",
        "artifact_format": "application/json",
        "provenance": {
            "provenance_version": "1.0",
            "source_bindings": source_bindings,
            "producer": {"kind": "tool", "identifier": producer_identifier, "version": "1.0.0"},
            "transformation": {"identifier": "transform.extract", "version": "1.0.0", "parameters_digest": _sha(b"params")},
        },
        "placement": {"target_root_binding": "admission_result_root", "namespace": "example"},
        "supersedes": supersedes,
        "request_metadata": {"submitted_by": "adapter.example", "correlation_id": operation_id},
    }


def _knowledge_request(tmp_path: Path, target: Path, evidence: Path, candidate_value: dict[str, object], artifact: bytes, *, run_id: str) -> PhaseRequest:
    asset = tmp_path / f"{run_id}.artifact"
    candidate = tmp_path / f"{run_id}.json"
    asset.write_bytes(artifact)
    _write_json(candidate, candidate_value)
    return PhaseRequest(
        contract_id="knowledge_admission.v1",
        contract_version="1.0.0",
        contract_digest=_binding("knowledge_admission.v1")["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths={"asset": asset},
        root_bindings={"admission_result_root": target},
        timestamp=NOW,
    )


def _admit_knowledge(tmp_path: Path, target: Path, evidence: Path, source_bindings: list[dict[str, object]], *, run_id: str = "knowledge-run", artifact: bytes = b'{"summary":"ok"}\n', operation_id: str = "op-knowledge-001", logical_id: str = "knowledge-summary-001") -> tuple[PhaseRequest, object]:
    candidate = _knowledge_candidate(artifact, source_bindings, operation_id=operation_id, logical_id=logical_id)
    request = _knowledge_request(tmp_path, target, evidence, candidate, artifact, run_id=run_id)
    outcome = PhaseCore().run(request, execute=True)
    return request, outcome


def test_knowledge_contract_is_exactly_activated_and_integrity_bound() -> None:
    registry = BundledRegistry.load()
    entry = registry.contract_bindings()["knowledge_admission.v1@1.0.0"]
    contract = registry.resolve_contract("knowledge_admission.v1", "1.0.0", entry["package_digest"], core_version="1.0.0")
    assert contract.document["identity"]["id"] == "knowledge_admission.v1"
    assert contract.document["identity"]["version"] == "1.0.0"
    assert contract.document["contract_hook"]["id"] == "knowledge_admission.runtime_v1"
    assert contract.contract_hook and contract.contract_hook["implementation_id"] == "builtin.knowledge_admission_v1"
    assert parse_json_bytes((ROOT / "contracts" / "knowledge_admission.v1.json").read_bytes()) == contract.document
    assert (ROOT / "schemas" / "knowledge-result.schema.json").read_bytes() == (PACKAGE / "data" / "schemas" / "knowledge-result.schema.json").read_bytes()


def test_knowledge_execute_writes_artifact_descriptor_progress_and_inspects(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b'{"summary":"stable"}\n'
    request, outcome = _admit_knowledge(tmp_path, target, evidence, [binding], artifact=artifact)
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert [effect["kind"] for effect in outcome.effect_plan["effects"]] == ["copy_blob", "exclusive_create"]
    assert [effect["effect_id"] for effect in outcome.effect_plan["effects"]] == ["effect.0.blob", "effect.1.descriptor"]
    blob_locator = outcome.effect_plan["effects"][0]["target"]["relative_locator"]
    descriptor_locator = outcome.effect_plan["effects"][1]["target"]["relative_locator"]
    assert blob_locator.startswith("blobs/sha256/")
    assert descriptor_locator.startswith("namespaces/example/knowledge-results/knowledge-summary-001/")
    assert _read_target(target, blob_locator) == artifact
    descriptor = parse_json_bytes(_read_target(target, descriptor_locator))
    assert descriptor["artifact_digest"] == _sha(artifact)
    assert descriptor["provenance"]["source_bindings"] == [binding]
    assert "receipt_digest" not in descriptor["admission_run"]
    progress = parse_json_bytes((evidence / ".phase" / "runs" / request.run_id / "attachments" / "ordered-effect-progress.json").read_bytes())
    assert progress["verified_effect_ids"] == ["effect.0.blob", "effect.1.descriptor"]
    inspected = inspect_run(evidence, request.run_id, root_bindings={"admission_result_root": target})
    assert inspected["target_verified"] is True
    assert inspected["contract_result"]["reference"]["descriptor_digest"] == outcome.receipt["canonical_result"]["state"]["digest"]
    assert inspected["contract_result"]["source_bindings"] == [binding]


def test_knowledge_validate_and_plan_do_not_mutate_target(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b"plan only"
    request = _knowledge_request(tmp_path, target, evidence, _knowledge_candidate(artifact, [binding]), artifact, run_id="knowledge-plan")
    before = sorted(path.relative_to(target).as_posix() for path in target.rglob("*"))
    outcome = PhaseCore().run(request)
    assert outcome.receipt["terminal_status"] == "validated_planned"
    assert sorted(path.relative_to(target).as_posix() for path in target.rglob("*")) == before


def test_knowledge_requires_exact_verified_source_binding(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b"rejects"
    for run_id, patch, blocker in [
        ("no-source", lambda c: c["provenance"].update({"source_bindings": []}), "candidate.schema_invalid"),
        ("source-id-only", lambda c: c["provenance"].update({"source_bindings": [{"source_result_id": binding["source_result_id"]}]}), "candidate.schema_invalid"),
        ("bad-receipt", lambda c: c["provenance"]["source_bindings"][0]["source_phase_receipt"].update({"receipt_digest": _sha(b"wrong")}), "knowledge.source_receipt_mismatch"),
    ]:
        candidate = _knowledge_candidate(artifact, [json.loads(json.dumps(binding))], operation_id=f"op-{run_id}")
        patch(candidate)
        outcome = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate, artifact, run_id=run_id), execute=True)
        assert outcome.receipt["terminal_status"] == "rejected"
        assert outcome.receipt["mutation_attempted"] is False
        assert blocker in outcome.receipt["blockers"]


def test_source_binding_callback_is_rejected_before_artifact_mutation(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b"race-artifact"
    request = _knowledge_request(tmp_path, target, evidence, _knowledge_candidate(artifact, [binding]), artifact, run_id="knowledge-source-race")

    def tamper_source(_intent_path: Path) -> None:
        path = contained_read_path(target, binding["source_descriptor_locator"])
        with open(_platform_path(path), "wb") as stream:
            stream.write(b"tampered")

    outcome = PhaseCore().run(request, execute=True, faults=CoreFaults(broker=BrokerFaults(before_mechanism=tamper_source)))
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert _read_target(target, binding["source_descriptor_locator"]) != b"tampered"
    assert not any((target / "namespaces" / "example" / "knowledge-results").glob("**/*.json"))


def test_knowledge_recomputes_source_result_identity_from_descriptor(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    forged_binding = json.loads(json.dumps(binding))
    descriptor_path = contained_read_path(target, binding["source_descriptor_locator"])
    descriptor = parse_json_bytes(_read_target(target, binding["source_descriptor_locator"]))
    descriptor["source_result_id"] = "source-result-" + "0" * 64
    forged_descriptor = admission_canonical_bytes(descriptor)
    with open(_platform_path(descriptor_path), "wb") as stream:
        stream.write(forged_descriptor)
    forged_digest = digest_bytes(forged_descriptor)
    receipt_path = evidence / ".phase" / "runs" / binding["source_phase_receipt"]["run_id"] / "receipt.json"
    receipt = parse_json_bytes(receipt_path.read_bytes())
    receipt["canonical_result"]["state"]["digest"] = forged_digest
    receipt["canonical_result"]["state"]["length"] = len(forged_descriptor)
    receipt["effect_receipts"][1]["after"]["digest"] = forged_digest
    receipt["effect_receipts"][1]["after"]["length"] = len(forged_descriptor)
    _write_json(receipt_path, receipt)
    forged_binding["source_result_id"] = descriptor["source_result_id"]
    forged_binding["source_descriptor_digest"] = forged_digest
    forged_binding["source_phase_receipt"]["receipt_digest"] = profile_digest("receipt", receipt)
    candidate = _knowledge_candidate(b"forged-source", [forged_binding], operation_id="op-forged-source")
    outcome = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate, b"forged-source", run_id="knowledge-forged-source"), execute=True)
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert "knowledge.source_result_mismatch" in outcome.receipt["blockers"]


@pytest.mark.parametrize("tamper", ["aliased_run", "internal_run", "wrong_package", "missing_attachments", "synthetic_receipt"])
def test_knowledge_authenticates_complete_source_phase_evidence(tmp_path: Path, tamper: str) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    forged = json.loads(json.dumps(binding))
    source_run = evidence / ".phase" / "runs" / "source-run"
    receipt_path = source_run / "receipt.json"
    receipt = parse_json_bytes(receipt_path.read_bytes())
    if tamper == "aliased_run":
        alias = evidence / ".phase" / "runs" / "source-alias"
        shutil.copytree(source_run, alias)
        forged["source_phase_receipt"]["run_id"] = "source-alias"
    elif tamper == "internal_run":
        receipt["run_id"] = "source-other"
        _write_json(receipt_path, receipt)
        forged["source_phase_receipt"]["receipt_digest"] = profile_digest("receipt", receipt)
    elif tamper == "wrong_package":
        receipt["contract"]["package_digest"] = "sha256:" + "0" * 64
        _write_json(receipt_path, receipt)
        forged["source_phase_receipt"]["receipt_digest"] = profile_digest("receipt", receipt)
    elif tamper == "missing_attachments":
        (source_run / "attachments" / "effect-receipts.json").unlink()
    else:
        synthetic = evidence / ".phase" / "runs" / "source-synthetic"
        synthetic.mkdir()
        receipt["run_id"] = "source-synthetic"
        for effect in receipt["effect_receipts"]:
            effect["run_id"] = "source-synthetic"
        _write_json(synthetic / "receipt.json", receipt)
        forged["source_phase_receipt"] = {"run_id": "source-synthetic", "receipt_digest": profile_digest("receipt", receipt)}
    candidate = _knowledge_candidate(b"authenticated-source", [forged], operation_id=f"op-{tamper}")
    outcome = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate, b"authenticated-source", run_id=f"knowledge-{tamper}"), execute=True)
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False


def test_exact_knowledge_result_reuses_under_a_new_operation_key(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b"canonical reuse"
    _request, first = _admit_knowledge(tmp_path, target, evidence, [binding], artifact=artifact, operation_id="op-reuse-first")
    candidate = _knowledge_candidate(artifact, [binding], operation_id="op-reuse-second")
    second = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate, artifact, run_id="knowledge-reuse-second"), execute=True)
    assert second.receipt["terminal_status"] == "succeeded_verified"
    assert second.receipt["execution_disposition"] == "reused_existing"
    assert second.receipt["mutation_attempted"] is False
    assert second.receipt["effect_receipts"] == []
    assert second.receipt["prior_verified_receipt_digest"] == first.receipt_digest


def test_knowledge_sorts_source_bindings_and_rejects_duplicates(tmp_path: Path) -> None:
    target, evidence, binding_a = _admit_source(tmp_path, run_id="source-a", payload=b"a", operation_id="op-source-a")
    _target, _evidence, binding_b = _admit_source(tmp_path, run_id="source-b", payload=b"b", operation_id="op-source-b", logical_id="source-manual-002")
    artifact = b"multi"
    request, outcome = _admit_knowledge(tmp_path, target, evidence, [binding_b, binding_a], run_id="knowledge-multi", artifact=artifact)
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    descriptor = parse_json_bytes(_read_target(target, outcome.effect_plan["effects"][1]["target"]["relative_locator"]))
    assert descriptor["provenance"]["source_bindings"] == sorted([binding_a, binding_b], key=lambda item: (item["source_result_id"], item["source_descriptor_digest"], item["source_content_digest"]))
    duplicate = _knowledge_candidate(artifact, [binding_a, binding_a], operation_id="op-duplicate")
    rejected = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, duplicate, artifact, run_id="knowledge-duplicate"), execute=True)
    assert rejected.receipt["terminal_status"] == "rejected"
    assert "knowledge.source_binding_duplicate" in rejected.receipt["blockers"]


def test_same_operation_reordered_source_set_is_the_same_canonical_request(tmp_path: Path) -> None:
    target, evidence, binding_a = _admit_source(tmp_path, run_id="source-a", payload=b"a", operation_id="op-source-a")
    _target, _evidence, binding_b = _admit_source(tmp_path, run_id="source-b", payload=b"b", operation_id="op-source-b", logical_id="source-manual-002")
    artifact = b"canonical set"
    candidate_a = _knowledge_candidate(artifact, [binding_b, binding_a], operation_id="op-canonical-set")
    first = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate_a, artifact, run_id="knowledge-set-first"), execute=True)
    assert first.receipt["terminal_status"] == "succeeded_verified"
    candidate_b = _knowledge_candidate(artifact, [binding_a, binding_b], operation_id="op-canonical-set")
    second = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate_b, artifact, run_id="knowledge-set-reordered"), execute=True)
    assert second.receipt["terminal_status"] == "succeeded_verified"
    assert second.receipt["execution_disposition"] == "reused_existing"
    assert second.receipt["prior_verified_receipt_digest"] == first.receipt_digest


def test_knowledge_reuse_and_same_logical_identity_conflicts(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b"same"
    first_request, first = _admit_knowledge(tmp_path, target, evidence, [binding], artifact=artifact)
    same = PhaseCore().run(replace(first_request, run_id="knowledge-reuse"), execute=True)
    assert same.receipt["execution_disposition"] == "reused_existing"
    assert same.receipt["effect_receipts"] == []
    different_artifact = _knowledge_candidate(b"different", [binding], operation_id="op-knowledge-002")
    conflict = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, different_artifact, b"different", run_id="knowledge-conflict-artifact"), execute=True)
    assert conflict.receipt["terminal_status"] == "rejected"
    assert "knowledge.logical_identity_conflict" in conflict.receipt["blockers"]
    changed_provenance = _knowledge_candidate(artifact, [binding], operation_id="op-knowledge-003", producer_identifier="other.producer")
    provenance_conflict = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, changed_provenance, artifact, run_id="knowledge-conflict-provenance"), execute=True)
    assert provenance_conflict.receipt["terminal_status"] == "rejected"
    assert "knowledge.logical_identity_conflict" in provenance_conflict.receipt["blockers"]


def test_same_operation_different_request_rejects_before_mutation(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b"base"
    _request, _outcome = _admit_knowledge(tmp_path, target, evidence, [binding], artifact=artifact)
    candidate = _knowledge_candidate(b"changed", [binding], operation_id="op-knowledge-001")
    outcome = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate, b"changed", run_id="knowledge-same-key-different"), execute=True)
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["blockers"] == ["idempotency.same_key_conflict"]


def test_knowledge_effect1_callback_is_rejected_before_new_blob(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    artifact = b"partial"
    request = _knowledge_request(tmp_path, target, evidence, _knowledge_candidate(artifact, [binding]), artifact, run_id="knowledge-partial")
    planned = PhaseCore().run(replace(request, run_id="knowledge-partial-plan"))
    descriptor_locator = planned.effect_plan["effects"][1]["target"]["relative_locator"]

    def create_conflict(_intent_path: Path) -> None:
        destination = target.joinpath(*descriptor_locator.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(_platform_path(destination), "wb") as stream:
            stream.write(b"conflict")

    outcome = PhaseCore().run(request, execute=True, faults=CoreFaults(broker=BrokerFaults(before_effect={1: create_conflict})))
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.joinpath(*descriptor_locator.split("/")).exists()


def test_knowledge_supersession_creates_new_result_without_rewrite(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    _request, first = _admit_knowledge(tmp_path, target, evidence, [binding], run_id="knowledge-first", artifact=b"v1", operation_id="op-k-v1", logical_id="knowledge-v1")
    prior = inspect_run(evidence, "knowledge-first", root_bindings={"admission_result_root": target})["contract_result"]["reference"]
    prior_descriptor = target / prior["descriptor_locator"]
    prior_bytes = _read_target(target, prior["descriptor_locator"])
    candidate = _knowledge_candidate(b"v2", [binding], operation_id="op-k-v2", logical_id="knowledge-v2", supersedes=prior)
    second = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate, b"v2", run_id="knowledge-second"), execute=True)
    assert second.receipt["terminal_status"] == "succeeded_verified"
    descriptor = parse_json_bytes(_read_target(target, second.effect_plan["effects"][1]["target"]["relative_locator"]))
    assert descriptor["supersedes"] == prior
    assert _read_target(target, prior["descriptor_locator"]) == prior_bytes


def test_supersedes_rejects_receipt_from_a_different_prior_result(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    _request, _first = _admit_knowledge(tmp_path, target, evidence, [binding], run_id="knowledge-prior-a", artifact=b"a", operation_id="op-prior-a", logical_id="knowledge-prior-a")
    _request, _second = _admit_knowledge(tmp_path, target, evidence, [binding], run_id="knowledge-prior-b", artifact=b"b", operation_id="op-prior-b", logical_id="knowledge-prior-b")
    prior_a = inspect_run(evidence, "knowledge-prior-a", root_bindings={"admission_result_root": target})["contract_result"]["reference"]
    prior_b = inspect_run(evidence, "knowledge-prior-b", root_bindings={"admission_result_root": target})["contract_result"]["reference"]
    mixed = json.loads(json.dumps(prior_a))
    mixed["phase_receipt"] = prior_b["phase_receipt"]
    candidate = _knowledge_candidate(b"next", [binding], operation_id="op-next", logical_id="knowledge-next", supersedes=mixed)
    outcome = PhaseCore().run(_knowledge_request(tmp_path, target, evidence, candidate, b"next", run_id="knowledge-next"), execute=True)
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert "knowledge.supersedes_mismatch" in outcome.receipt["blockers"]


def test_result_reference_recomputes_provenance_digest(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    _request, outcome = _admit_knowledge(tmp_path, target, evidence, [binding], artifact=b"provenance")
    descriptor = parse_json_bytes(_read_target(target, outcome.receipt["canonical_result"]["locator"]))
    descriptor["provenance"]["producer"]["identifier"] = "tampered.producer"
    tampered = admission_canonical_bytes(descriptor)
    try:
        verify_result_reference(descriptor, digest_bytes(tampered), target)
    except PhaseError as exc:
        assert exc.code == "knowledge.provenance_digest_mismatch"
    else:
        raise AssertionError("mismatched provenance digest was accepted")


def test_knowledge_inspection_detects_tampered_artifact_and_source_receipt(tmp_path: Path) -> None:
    target, evidence, binding = _admit_source(tmp_path)
    request, outcome = _admit_knowledge(tmp_path, target, evidence, [binding], run_id="knowledge-inspect", artifact=b"inspect")
    assert inspect_run(evidence, request.run_id, root_bindings={"admission_result_root": target})["target_verified"] is True
    (target / outcome.effect_plan["effects"][0]["target"]["relative_locator"]).write_bytes(b"tamper")
    try:
        inspect_run(evidence, request.run_id, root_bindings={"admission_result_root": target})
    except PhaseError as exc:
        assert exc.code == "knowledge.blob_mismatch"
    else:
        raise AssertionError("tampered artifact was accepted")


def _knowledge_race_worker(base: str, name: str, artifact: bytes, operation_id: str, queue: object, barrier: object) -> None:
    tmp = Path(base)
    target = tmp / "target"
    evidence = tmp / "evidence"
    binding = parse_json_bytes((tmp / "binding.json").read_bytes())
    request = _knowledge_request(tmp, target, evidence, _knowledge_candidate(artifact, [binding], operation_id=operation_id), artifact, run_id=name)

    barrier.wait(timeout=20)  # type: ignore[attr-defined]
    outcome = PhaseCore().run(request, execute=True)
    queue.put((outcome.receipt["terminal_status"], outcome.receipt["execution_disposition"], outcome.receipt["mutation_attempted"]))  # type: ignore[attr-defined]


def test_concurrent_same_logical_knowledge_id_has_one_descriptor(tmp_path: Path) -> None:
    target, _evidence, binding = _admit_source(tmp_path)
    _write_json(tmp_path / "binding.json", binding)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    barrier = context.Barrier(2)
    workers = [
        context.Process(target=_knowledge_race_worker, args=(str(tmp_path), "knowledge-race-a", b"a", "op-race-a", queue, barrier)),
        context.Process(target=_knowledge_race_worker, args=(str(tmp_path), "knowledge-race-b", b"b", "op-race-b", queue, barrier)),
    ]
    for worker in workers:
        worker.start()
    outcomes = [queue.get(timeout=30) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0
    assert len([item for item in outcomes if item[0] == "succeeded_verified"]) == 1
    assert len(list((target / "namespaces" / "example" / "knowledge-results" / "knowledge-summary-001").glob("*.json"))) == 1


def test_generic_architecture_surfaces_do_not_route_stage7_domain_fields() -> None:
    forbidden_literals = {
        "knowledge_admission.v1",
        "logical_knowledge_id",
        "artifact_kind",
        "artifact_format",
        "source_bindings",
        "producer",
        "transformation",
        "KB",
        "claim",
        "provenance",
    }
    for relative in ["core.py", "planning/__init__.py", "validation/__init__.py", "mutation/broker.py", "inspection/__init__.py"]:
        tree = ast.parse((PACKAGE / relative).read_text(encoding="utf-8"), filename=relative)
        literals = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        assert forbidden_literals.isdisjoint(literals), relative


def test_knowledge_contract_schema_registry_and_hook_are_exact_bound() -> None:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["knowledge_admission.v1@1.0.0"]
    contract = registry.resolve_contract("knowledge_admission.v1", "1.0.0", binding["package_digest"], core_version="1.0.0")
    phase_schema = parse_json_bytes((PACKAGE / "data" / "schemas" / "phase-contract.schema.json").read_bytes())
    Draft202012Validator(phase_schema, format_checker=FormatChecker()).validate(contract.document)
    package = {"profile": "phase_contract_package_v1", "artifacts": contract.entry["package_artifacts"]}
    assert canonical_digest(package) == binding["package_digest"]
    assert digest_bytes((PACKAGE / "data" / contract.entry["artifact"]).read_bytes()) == contract.entry["artifact_digest"]
    assert contract.entry["package_digest"] == BundledRegistry.load().contract_bindings()["knowledge_admission.v1@1.0.0"]["package_digest"]

    for name in (
        "knowledge-admission-candidate.schema.json",
        "knowledge-provenance.schema.json",
        "knowledge-result.schema.json",
        "knowledge-result-reference.schema.json",
    ):
        assert (ROOT / "schemas" / name).read_bytes() == (PACKAGE / "data" / "schemas" / name).read_bytes()
    source_binding_schema = "source-result-binding.schema.json"
    assert (ROOT / "schemas" / source_binding_schema).read_bytes() == (PACKAGE / "data" / "schemas" / source_binding_schema).read_bytes()
    assert (ROOT / "schemas" / source_binding_schema).read_bytes() == (
        ROOT / "contracts" / "spec-candidates" / "admission-v1" / "schemas" / source_binding_schema
    ).read_bytes()
    assert (ROOT / "contracts" / "knowledge_admission.v1.json").read_bytes() == (PACKAGE / "data" / "contracts" / "knowledge_admission.v1.json").read_bytes()


def test_stage7_candidate_package_manifest_is_exact() -> None:
    package = ROOT / "contracts" / "spec-candidates" / "admission-v1"
    manifest = package / "manifest.sha256"
    seen: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        assert relative not in seen
        parts = Path(relative).parts
        assert not Path(relative).is_absolute()
        assert ".." not in parts
        assert "\\" not in relative
        assert relative in {"README.md", "fixture-catalog.json"} or parts[0] in {"contracts", "fixtures", "schemas"}
        assert Path(relative).suffix in {".json", ".md"}
        seen.add(relative)
        assert hashlib.sha256((package / relative).read_bytes()).hexdigest() == expected, relative
    actual = {path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file() and path != manifest}
    assert seen == actual


def test_stage7_real_cli_acceptance_and_factual_walkthrough(tmp_path: Path) -> None:
    cli_root = ROOT / ".stage7-tmp" / "cli-third"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage7_cli_acceptance.py"), "--tmp-root", str(cli_root)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    envelope = json.loads(completed.stdout)
    assert envelope["success"] is True
    assert envelope["scenario_count"] == 13
    summary = parse_json_bytes(Path(envelope["summary"]).read_bytes())
    assert summary["failures"] == {}
    assert all(summary["checks"].values())
    assert summary["contract"] == {
        "id": "knowledge_admission.v1",
        "version": "1.0.0",
        "package_digest": _binding("knowledge_admission.v1")["package_digest"],
    }
    walkthrough = (ROOT / "docs" / "STAGE-7-KNOWLEDGE-ADMISSION-WALKTHROUGH.md").read_text(encoding="utf-8")
    for value in (
        "scenario_count\":13",
        summary["contract"]["package_digest"],
        summary["knowledge_result"]["artifact_digest"],
        "knowledge_result_id:",
        "descriptor_digest:",
        "receipt_digest:",
        "does not determine whether a knowledge claim is true",
        "not claimed to be a cross-root reproducibility invariant",
    ):
        assert value in walkthrough


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="production mutation runtime is Linux-only")
def test_stage7_linux_cli_acceptance_reads_deep_descriptor_paths() -> None:
    padding = 19
    components = tuple(f"segment-{index:02d}-" + "x" * padding for index in range(3))
    assert all(len(component) < 96 for component in components)
    cli_root = ROOT / ".stage7-tmp"
    for component in components:
        cli_root /= component
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage7_cli_acceptance.py"), "--tmp-root", str(cli_root)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    envelope = json.loads(completed.stdout)
    summary = parse_json_bytes(Path(envelope["summary"]).read_bytes())
    descriptor_length = summary["knowledge_result"]["descriptor_path_length"]
    assert descriptor_length >= 260
    assert completed.returncode == 0, f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
    assert envelope["success"] is True
    assert summary["success"] is True
    receipt_path = Path(envelope["summary"]).parent / "evidence" / ".phase" / "runs" / "knowledge-execute" / "receipt.json"
    canonical = parse_json_bytes(receipt_path.read_bytes())["canonical_result"]
    assert summary["knowledge_result"]["descriptor_locator"] == canonical["locator"]
    assert summary["checks"]["platform_safe_descriptor_read"] is True
