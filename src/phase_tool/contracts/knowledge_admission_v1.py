from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..canonical import digest_bytes, parse_json_bytes, profile_digest
from ..errors import PhaseError
from ..evidence import iter_run_artifacts, read_evidence_bytes, validate_receipt
from ..freeze import FrozenInput, revalidate_frozen
from ..inspection import inspect_run
from ..paths import inspect_target_path, safe_relative_locator
from ..registry import RegistrySnapshot, ResolvedContract
from .source_admission_v1 import admission_canonical_bytes, admission_digest, content_locator
from . import source_admission_v1
from .target_io import observe_target, read_target_bytes

CONTRACT_ID = "knowledge_admission.v1"
CONTRACT_VERSION = "1.0.0"
SOURCE_CONTRACT_ID = "source_admission.v1"
ROOT_BINDING = "admission_result_root"
ASSET_BINDING = "asset"
DESCRIPTOR_BINDING = "descriptor_bytes"
_LOGICAL_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MAX_DESCRIPTOR_BYTES = 1024 * 1024


def _binding_key(binding: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(binding["source_result_id"]),
        str(binding["source_descriptor_digest"]),
        str(binding["source_content_digest"]),
    )


def sorted_source_bindings(bindings: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    ordered = [dict(item) for item in sorted(bindings, key=_binding_key)]
    seen: set[tuple[str, str, str]] = set()
    for item in ordered:
        key = _binding_key(item)
        if key in seen:
            raise PhaseError("knowledge.source_binding_duplicate")
        seen.add(key)
    return ordered


def canonical_provenance(candidate: Mapping[str, Any]) -> dict[str, Any]:
    provenance = dict(candidate["provenance"])
    provenance["source_bindings"] = sorted_source_bindings(list(provenance["source_bindings"]))
    return provenance


def normalized_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(candidate)
    try:
        normalized["provenance"] = canonical_provenance(candidate)
    except (KeyError, TypeError):
        # Structural failures belong to the exact candidate-schema validator.
        return normalized
    return normalized


def provenance_digest(candidate: Mapping[str, Any]) -> str:
    return admission_digest(canonical_provenance(candidate))


def identity_projection(candidate: Mapping[str, Any], frozen: FrozenInput) -> dict[str, Any]:
    return {
        "admission_contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
        "namespace": candidate["placement"]["namespace"],
        "logical_knowledge_id": candidate["logical_knowledge_id"],
        "artifact_digest": frozen.digest,
        "artifact_length": frozen.length,
        "artifact_kind": candidate["artifact_kind"],
        "artifact_format": candidate["artifact_format"],
        "provenance_digest": provenance_digest(candidate),
        "supersedes": candidate["supersedes"],
    }


def knowledge_result_id(candidate: Mapping[str, Any], frozen: FrozenInput) -> str:
    return "knowledge-result-" + admission_digest(identity_projection(candidate, frozen)).removeprefix("sha256:")


def descriptor_locator(candidate: Mapping[str, Any], result_id: str) -> str:
    namespace = candidate["placement"]["namespace"]
    logical_id = candidate["logical_knowledge_id"]
    return safe_relative_locator(f"namespaces/{namespace}/knowledge-results/{logical_id}/{result_id}.json")


def descriptor_value(candidate: Mapping[str, Any], frozen: FrozenInput, *, run_id: str, observed_at: str) -> dict[str, Any]:
    result_id = knowledge_result_id(candidate, frozen)
    return {
        "result_schema_version": "1.0",
        "knowledge_result_id": result_id,
        "logical_knowledge_id": candidate["logical_knowledge_id"],
        "artifact_digest": frozen.digest,
        "artifact_length": frozen.length,
        "artifact_kind": candidate["artifact_kind"],
        "artifact_format": candidate["artifact_format"],
        "blob_locator": content_locator(frozen.digest),
        "descriptor_locator": descriptor_locator(candidate, result_id),
        "provenance": canonical_provenance(candidate),
        "provenance_digest": provenance_digest(candidate),
        "admission_contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
        "admission_run": {"run_id": run_id, "receipt_authority": "phase_evidence_by_run_id"},
        "observed_at": observed_at,
        "supersedes": candidate["supersedes"],
    }


def descriptor_bytes(candidate: Mapping[str, Any], frozen: FrozenInput, *, run_id: str, observed_at: str) -> bytes:
    return admission_canonical_bytes(descriptor_value(candidate, frozen, run_id=run_id, observed_at=observed_at))


def _receipt_path(evidence_root: Path, run_id: str) -> Path:
    return evidence_root / ".phase" / "runs" / run_id / "receipt.json"


def _verify_source_descriptor_identity(descriptor: Mapping[str, Any]) -> None:
    locator = str(descriptor["descriptor_locator"])
    parts = locator.split("/")
    if len(parts) != 4 or parts[0] != "r" or parts[2] != descriptor["logical_source_id"]:
        raise PhaseError("knowledge.source_result_mismatch")
    if descriptor["admission_contract"] != {"id": SOURCE_CONTRACT_ID, "version": CONTRACT_VERSION}:
        raise PhaseError("knowledge.source_contract_mismatch")
    expected_provenance = source_admission_v1.admission_digest(descriptor["provenance"])
    if descriptor["provenance_digest"] != expected_provenance:
        raise PhaseError("knowledge.source_result_mismatch")
    if descriptor["blob_locator"] != source_admission_v1.content_locator(descriptor["content_digest"]):
        raise PhaseError("knowledge.source_blob_mismatch")
    projection = {
        "admission_contract": {"id": SOURCE_CONTRACT_ID, "version": CONTRACT_VERSION},
        "namespace": parts[1],
        "logical_source_id": descriptor["logical_source_id"],
        "content_digest": descriptor["content_digest"],
        "content_length": descriptor["content_length"],
        "media_type": descriptor["media_type"],
        "original_filename": descriptor["original_filename"],
        "provenance_digest": descriptor["provenance_digest"],
        "supersedes": descriptor["supersedes"],
    }
    expected_id = "source-result-" + source_admission_v1.admission_digest(projection).removeprefix("sha256:")
    if descriptor["source_result_id"] != expected_id or parts[3] != f"{expected_id}.json":
        raise PhaseError("knowledge.source_result_mismatch")


def _verify_source_binding(binding: Mapping[str, Any], root: Path, evidence_root: Path, registry: RegistrySnapshot) -> None:
    if binding["source_contract"] != {"id": SOURCE_CONTRACT_ID, "version": CONTRACT_VERSION}:
        raise PhaseError("knowledge.source_contract_mismatch")
    descriptor_bytes_value = read_target_bytes(
        root,
        str(binding["source_descriptor_locator"]),
        maximum_bytes=_MAX_DESCRIPTOR_BYTES,
    )
    descriptor_digest = digest_bytes(descriptor_bytes_value)
    if descriptor_digest != binding["source_descriptor_digest"]:
        raise PhaseError("knowledge.source_descriptor_mismatch")
    descriptor = parse_json_bytes(descriptor_bytes_value)
    schema = registry.schema_document("https://phase-tool.local/spec-candidates/admission-v1/schemas/source-result.schema.json")
    Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).validate(descriptor)
    source_admission_v1.verify_result_reference(descriptor, descriptor_digest, root)
    _verify_source_descriptor_identity(descriptor)
    if descriptor["source_result_id"] != binding["source_result_id"]:
        raise PhaseError("knowledge.source_result_mismatch")
    if descriptor["logical_source_id"] != binding["logical_source_id"]:
        raise PhaseError("knowledge.source_result_mismatch")
    if descriptor["content_digest"] != binding["source_content_digest"]:
        raise PhaseError("knowledge.source_blob_mismatch")
    if descriptor["blob_locator"] != binding["source_blob_locator"]:
        raise PhaseError("knowledge.source_blob_mismatch")
    receipt_ref = binding["source_phase_receipt"]
    receipt_path = _receipt_path(evidence_root, str(receipt_ref["run_id"]))
    receipt = parse_json_bytes(read_evidence_bytes(receipt_path))
    if profile_digest("receipt", receipt) != receipt_ref["receipt_digest"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    validate_receipt(receipt, registry)
    if receipt["run_id"] != receipt_ref["run_id"] or descriptor["admission_run"]["run_id"] != receipt_ref["run_id"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    if receipt["terminal_status"] != "succeeded_verified":
        raise PhaseError("knowledge.source_receipt_not_verified")
    expected_source_contract = registry.contract_bindings()[f"{SOURCE_CONTRACT_ID}@{CONTRACT_VERSION}"]
    if receipt["contract"] != {"id": SOURCE_CONTRACT_ID, "version": CONTRACT_VERSION, "package_digest": expected_source_contract["package_digest"]}:
        raise PhaseError("knowledge.source_receipt_mismatch")
    canonical = receipt["canonical_result"]
    if canonical is None or canonical["locator"] != binding["source_descriptor_locator"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    if canonical["state"]["digest"] != binding["source_descriptor_digest"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    effect_by_id = {item["effect_id"]: item for item in receipt["effect_receipts"]}
    blob_effect = effect_by_id.get("effect.0.blob")
    descriptor_effect = effect_by_id.get("effect.1.descriptor")
    if blob_effect is None or descriptor_effect is None:
        raise PhaseError("knowledge.source_receipt_mismatch")
    if [item["effect_id"] for item in receipt["effect_receipts"]] != ["effect.0.blob", "effect.1.descriptor"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    if any(item["run_id"] != receipt_ref["run_id"] or item["status"] != "applied_verified" for item in receipt["effect_receipts"]):
        raise PhaseError("knowledge.source_receipt_mismatch")
    if blob_effect["kind"] != "copy_blob" or descriptor_effect["kind"] != "exclusive_create":
        raise PhaseError("knowledge.source_receipt_mismatch")
    if blob_effect["after"]["digest"] != binding["source_content_digest"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    if descriptor_effect["after"]["digest"] != binding["source_descriptor_digest"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    try:
        inspected = inspect_run(evidence_root, str(receipt_ref["run_id"]), registry=registry, root_bindings={ROOT_BINDING: root})
    except (OSError, PhaseError) as exc:
        raise PhaseError("knowledge.source_receipt_mismatch") from exc
    if inspected["run_id"] != receipt_ref["run_id"] or inspected["receipt_digest"] != receipt_ref["receipt_digest"]:
        raise PhaseError("knowledge.source_receipt_mismatch")
    if inspected["terminal_status"] != "succeeded_verified" or inspected["target_verified"] is not True:
        raise PhaseError("knowledge.source_receipt_mismatch")


def _verify_all_source_bindings(candidate: Mapping[str, Any], root: Path, evidence_root: Path, registry: RegistrySnapshot) -> None:
    bindings = sorted_source_bindings(list(candidate["provenance"]["source_bindings"]))
    for binding in bindings:
        _verify_source_binding(binding, root, evidence_root, registry)


def _verify_supersedes(reference: Mapping[str, Any], root: Path, evidence_root: Path, registry: RegistrySnapshot) -> None:
    data = read_target_bytes(root, str(reference["descriptor_locator"]), maximum_bytes=_MAX_DESCRIPTOR_BYTES)
    descriptor_digest = digest_bytes(data)
    if descriptor_digest != reference["descriptor_digest"]:
        raise PhaseError("knowledge.supersedes_mismatch")
    descriptor = parse_json_bytes(data)
    verify_result_reference(descriptor, descriptor_digest, root, registry=registry)
    if descriptor["knowledge_result_id"] != reference["knowledge_result_id"]:
        raise PhaseError("knowledge.supersedes_mismatch")
    receipt_ref = reference["phase_receipt"]
    receipt = parse_json_bytes(read_evidence_bytes(_receipt_path(evidence_root, str(receipt_ref["run_id"]))))
    if profile_digest("receipt", receipt) != receipt_ref["receipt_digest"]:
        raise PhaseError("knowledge.supersedes_mismatch")
    validate_receipt(receipt, registry)
    if receipt["terminal_status"] != "succeeded_verified":
        raise PhaseError("knowledge.supersedes_mismatch")
    if receipt["run_id"] != receipt_ref["run_id"]:
        raise PhaseError("knowledge.supersedes_mismatch")
    contract = receipt["contract"]
    expected_contract = registry.contract_bindings()[f"{CONTRACT_ID}@{CONTRACT_VERSION}"]
    if contract != {"id": CONTRACT_ID, "version": CONTRACT_VERSION, "package_digest": expected_contract["package_digest"]}:
        raise PhaseError("knowledge.supersedes_mismatch")
    canonical = receipt["canonical_result"]
    if canonical is None or canonical["locator"] != reference["descriptor_locator"]:
        raise PhaseError("knowledge.supersedes_mismatch")
    if canonical["state"]["digest"] != reference["descriptor_digest"]:
        raise PhaseError("knowledge.supersedes_mismatch")
    if descriptor["admission_run"]["run_id"] != receipt_ref["run_id"]:
        raise PhaseError("knowledge.supersedes_mismatch")
    try:
        inspected = inspect_run(evidence_root, str(receipt_ref["run_id"]), registry=registry, root_bindings={ROOT_BINDING: root})
    except (OSError, PhaseError) as exc:
        raise PhaseError("knowledge.supersedes_mismatch") from exc
    if inspected["receipt_digest"] != receipt_ref["receipt_digest"] or inspected["target_verified"] is not True:
        raise PhaseError("knowledge.supersedes_mismatch")


def validate_candidate(
    value: Mapping[str, Any],
    schema: Mapping[str, Any],
    registry: RegistrySnapshot,
    frozen_inputs: Mapping[str, FrozenInput],
    root_bindings: Mapping[str, Path],
    evidence_root: Path | None,
) -> tuple[str, str, Any, Any, list[str]]:
    errors = sorted(
        Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        return "fail", "candidate.schema_invalid", "schema_valid", errors[0].message, ["candidate.schema_invalid"]
    if evidence_root is not None:
        current_digest = admission_digest(value)
        for intent_path in iter_run_artifacts(Path(evidence_root) / ".phase" / "runs", "intent.json"):
            try:
                prior = parse_json_bytes(read_evidence_bytes(intent_path))
                prior_value = prior.get("candidate", {}).get("storage", {}).get("value")
            except (OSError, PhaseError) as exc:
                raise PhaseError("knowledge.evidence_unreadable", intent_path.parent.name) from exc
            if not isinstance(prior_value, Mapping):
                continue
            if prior_value.get("contract") != {"id": CONTRACT_ID, "version": CONTRACT_VERSION}:
                continue
            if prior_value.get("idempotency_key") == value["idempotency_key"] and admission_digest(prior_value) != current_digest:
                return "fail", "idempotency.same_key_conflict", value["idempotency_key"], "different_request", ["idempotency.same_key_conflict"]
    if value["operation_id"] != value["idempotency_key"]:
        return "fail", "knowledge.operation_key_mismatch", "operation_id_equals_idempotency_key", "mismatch", ["knowledge.operation_key_mismatch"]
    frozen = frozen_inputs.get(ASSET_BINDING)
    if frozen is None:
        return "fail", "input.required_missing", ASSET_BINDING, None, ["input.required_missing"]
    try:
        revalidate_frozen(frozen)
        if value["artifact_input"]["expected_digest"] is not None and value["artifact_input"]["expected_digest"] != frozen.digest:
            raise PhaseError("knowledge.expected_digest_mismatch")
        if value["artifact_input"]["expected_length"] is not None and value["artifact_input"]["expected_length"] != frozen.length:
            raise PhaseError("knowledge.expected_length_mismatch")
        if not _LOGICAL_ID.fullmatch(value["logical_knowledge_id"]):
            raise PhaseError("knowledge.logical_id_invalid")
        root = Path(root_bindings[ROOT_BINDING])
        if evidence_root is None:
            raise PhaseError("knowledge.evidence_root_missing")
        _verify_all_source_bindings(value, root, Path(evidence_root), registry)
        if value["supersedes"] is not None:
            _verify_supersedes(value["supersedes"], root, Path(evidence_root), registry)
    except (KeyError, OSError, PhaseError) as exc:
        code = exc.code if isinstance(exc, PhaseError) else "knowledge.binding_unavailable"
        return "fail", code, "knowledge_candidate_valid", "invalid", [code]
    return "pass", "validation.pass", "knowledge_candidate_valid", "knowledge_candidate_valid", []


def validate_preconditions(value: Mapping[str, Any], frozen: FrozenInput, root: Path) -> tuple[str, str, Any, Any, list[str]]:
    result_id = knowledge_result_id(value, frozen)
    desc_locator = descriptor_locator(value, result_id)
    blob_locator = content_locator(frozen.digest)
    try:
        _blob, blob_exists = inspect_target_path(root, blob_locator)
        blob_observation = observe_target(root, blob_locator) if blob_exists else None
        blob_ok = blob_observation is not None and (
            blob_observation["digest"] == frozen.digest and blob_observation["length"] == frozen.length
        )
        _descriptor, descriptor_exists = inspect_target_path(root, desc_locator)
    except PhaseError as exc:
        return "fail", exc.code, "safe_placement", str(exc), [exc.code]
    logical_dir = root / "namespaces" / value["placement"]["namespace"] / "knowledge-results" / value["logical_knowledge_id"]
    if logical_dir.is_dir():
        for existing in sorted(logical_dir.glob("*.json")):
            if existing.name == f"{result_id}.json":
                continue
            return "fail", "knowledge.logical_identity_conflict", result_id, existing.name, ["knowledge.logical_identity_conflict"]
    if descriptor_exists:
        data = read_target_bytes(root, desc_locator, maximum_bytes=_MAX_DESCRIPTOR_BYTES)
        descriptor_value_existing = parse_json_bytes(data)
        expected = descriptor_bytes(value, frozen, run_id=descriptor_value_existing["admission_run"]["run_id"], observed_at=descriptor_value_existing["observed_at"])
        if digest_bytes(data) != digest_bytes(expected):
            return "fail", "target.same_key_conflict", "expected_descriptor", desc_locator, ["target.same_key_conflict"]
        if not blob_ok:
            return "fail", "knowledge.canonical_result_incomplete", "descriptor_and_blob", "descriptor_only", ["knowledge.canonical_result_incomplete"]
    if blob_exists and not blob_ok:
        return "fail", "target.same_key_conflict", frozen.digest, blob_locator, ["target.same_key_conflict"]
    return "pass", "validation.pass", {"blob": "absent_or_same", "descriptor": "absent_or_same"}, {"blob": blob_exists, "descriptor": descriptor_exists}, []


def build_effects(contract: ResolvedContract, value: Mapping[str, Any], frozen: FrozenInput, *, run_id: str, generated_at: str) -> list[dict[str, Any]]:
    desc_bytes = descriptor_bytes(value, frozen, run_id=run_id, observed_at=generated_at)
    desc_digest = digest_bytes(desc_bytes)
    desc_b64 = base64.b64encode(desc_bytes).decode("ascii")
    content_mechanism, descriptor_mechanism = contract.document["operation"]["effect_mechanisms"]
    return [
        {
            "ordinal": 0,
            "effect_id": "effect.0.blob",
            "kind": "copy_blob",
            "mechanism": {key: content_mechanism[key] for key in ("id", "version", "package_digest")},
            "target": {"root_binding": ROOT_BINDING, "relative_locator": content_locator(frozen.digest)},
            "input_binding": ASSET_BINDING,
            "content_source": {"kind": "frozen_input", "binding_id": ASSET_BINDING, "source_digest": frozen.digest},
            "content_digest": frozen.digest,
            "content_length": frozen.length,
            "locator_policy_id": "content_addressed_sha256_sharded_v1",
            "preconditions": {"existence": "absent_or_same_digest", "expected_digest": frozen.digest, "expected_head": None, "concurrency_token": None},
            "lock_scope": None,
            "durability_policy_id": "file_data_synced",
            "on_failure": "stop_and_classify",
        },
        {
            "ordinal": 1,
            "effect_id": "effect.1.descriptor",
            "kind": "exclusive_create",
            "mechanism": {key: descriptor_mechanism[key] for key in ("id", "version", "package_digest")},
            "target": {"root_binding": ROOT_BINDING, "relative_locator": descriptor_locator(value, knowledge_result_id(value, frozen))},
            "input_binding": DESCRIPTOR_BINDING,
            "content_source": {"kind": "frozen_input", "binding_id": DESCRIPTOR_BINDING, "source_digest": desc_digest},
            "content_digest": desc_digest,
            "content_blob_digest": desc_digest,
            "content_length": len(desc_bytes),
            "content_bytes_b64": desc_b64,
            "preconditions": {"existence": "absent", "expected_digest": None, "expected_head": None, "concurrency_token": None},
            "lock_scope": "logical." + admission_digest({"namespace": value["placement"]["namespace"], "logical_id": value["logical_knowledge_id"]}).removeprefix("sha256:"),
            "durability_policy_id": "file_data_synced",
            "on_failure": "stop_and_classify",
        },
    ]


def verify_result_reference(
    descriptor: Mapping[str, Any],
    descriptor_digest: str,
    root: Path,
    receipt_digest: str | None = None,
    registry: RegistrySnapshot | None = None,
) -> None:
    schema_keys = {"knowledge_result_id", "logical_knowledge_id", "artifact_digest", "artifact_length", "blob_locator", "descriptor_locator"}
    if not schema_keys.issubset(descriptor):
        raise PhaseError("knowledge.result_invalid")
    blob_observation = observe_target(root, str(descriptor["blob_locator"]))
    if (
        blob_observation["digest"] != descriptor["artifact_digest"]
        or blob_observation["length"] != descriptor["artifact_length"]
    ):
        raise PhaseError("knowledge.blob_mismatch")
    if descriptor_digest != digest_bytes(admission_canonical_bytes(dict(descriptor))):
        raise PhaseError("knowledge.descriptor_mismatch")
    if descriptor["provenance_digest"] != admission_digest(descriptor["provenance"]):
        raise PhaseError("knowledge.provenance_digest_mismatch")
    locator_parts = str(descriptor["descriptor_locator"]).split("/")
    if len(locator_parts) != 5 or locator_parts[0] != "namespaces" or locator_parts[2] != "knowledge-results":
        raise PhaseError("knowledge.descriptor_locator_mismatch")
    if locator_parts[3] != descriptor["logical_knowledge_id"] or locator_parts[4] != f"{descriptor['knowledge_result_id']}.json":
        raise PhaseError("knowledge.descriptor_locator_mismatch")
    if descriptor["knowledge_result_id"] != "knowledge-result-" + admission_digest(
        {
            "admission_contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
            "namespace": str(descriptor["descriptor_locator"]).split("/")[1],
            "logical_knowledge_id": descriptor["logical_knowledge_id"],
            "artifact_digest": descriptor["artifact_digest"],
            "artifact_length": descriptor["artifact_length"],
            "artifact_kind": descriptor["artifact_kind"],
            "artifact_format": descriptor["artifact_format"],
            "provenance_digest": descriptor["provenance_digest"],
            "supersedes": descriptor["supersedes"],
        }
    ).removeprefix("sha256:"):
        raise PhaseError("knowledge.result_id_mismatch")


def derived_result_documents(descriptor: Mapping[str, Any], descriptor_digest: str, receipt_digest: str, registry: RegistrySnapshot) -> dict[str, Any]:
    run_id = descriptor["admission_run"]["run_id"]
    reference = {
        "reference_version": "1.0",
        "knowledge_result_id": descriptor["knowledge_result_id"],
        "logical_knowledge_id": descriptor["logical_knowledge_id"],
        "artifact_digest": descriptor["artifact_digest"],
        "blob_locator": descriptor["blob_locator"],
        "descriptor_digest": descriptor_digest,
        "descriptor_locator": descriptor["descriptor_locator"],
        "contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
        "phase_receipt": {"run_id": run_id, "receipt_digest": receipt_digest},
    }
    schema = registry.schema_document("https://phase-tool.local/spec-candidates/admission-v1/schemas/knowledge-result-reference.schema.json")
    Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).validate(reference)
    return {"reference": reference, "source_bindings": descriptor["provenance"]["source_bindings"]}


class KnowledgeAdmissionHook:
    def normalize_candidate(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return normalized_candidate(value)

    def idempotency_locator(self, value: Mapping[str, Any], frozen_inputs: Mapping[str, FrozenInput], *, default: Any) -> Any:
        frozen = frozen_inputs.get(ASSET_BINDING)
        if frozen is None:
            return default
        try:
            return descriptor_locator(value, knowledge_result_id(value, frozen))
        except (KeyError, TypeError, PhaseError):
            return default

    def find_reusable_result(
        self,
        value: Mapping[str, Any],
        frozen_inputs: Mapping[str, FrozenInput],
        root_bindings: Mapping[str, Path],
        evidence_root: Path,
        registry: RegistrySnapshot,
    ) -> tuple[dict[str, Any], str] | None:
        frozen = frozen_inputs.get(ASSET_BINDING)
        if frozen is None:
            return None
        root = Path(root_bindings[ROOT_BINDING])
        locator = descriptor_locator(value, knowledge_result_id(value, frozen))
        _descriptor_path, exists = inspect_target_path(root, locator)
        if not exists:
            return None
        data = read_target_bytes(root, locator, maximum_bytes=_MAX_DESCRIPTOR_BYTES)
        descriptor = parse_json_bytes(data)
        expected = descriptor_bytes(value, frozen, run_id=descriptor["admission_run"]["run_id"], observed_at=descriptor["observed_at"])
        if data != expected:
            raise PhaseError("knowledge.canonical_result_mismatch")
        descriptor_digest = digest_bytes(data)
        verify_result_reference(descriptor, descriptor_digest, root, registry=registry)
        prior_run_id = str(descriptor["admission_run"]["run_id"])
        inspected = inspect_run(evidence_root, prior_run_id, registry=registry, root_bindings={ROOT_BINDING: root})
        if inspected["terminal_status"] != "succeeded_verified" or inspected["target_verified"] is not True:
            raise PhaseError("knowledge.prior_result_unverified")
        receipt = parse_json_bytes(read_evidence_bytes(_receipt_path(evidence_root, prior_run_id)))
        receipt_digest = profile_digest("receipt", receipt)
        if inspected["receipt_digest"] != receipt_digest:
            raise PhaseError("knowledge.prior_result_unverified")
        canonical = receipt["canonical_result"]
        if canonical is None or canonical["locator"] != locator or canonical["state"]["digest"] != descriptor_digest:
            raise PhaseError("knowledge.prior_result_unverified")
        return receipt, receipt_digest

    def build_effects(
        self,
        contract: ResolvedContract,
        value: Mapping[str, Any],
        frozen_inputs: Mapping[str, FrozenInput],
        *,
        run_id: str,
        generated_at: str,
        root_bindings: Mapping[str, Path] | None = None,
    ) -> list[dict[str, Any]]:
        del root_bindings
        frozen = frozen_inputs.get(ASSET_BINDING)
        if frozen is None:
            raise PhaseError("input.required_missing", ASSET_BINDING)
        revalidate_frozen(frozen)
        return build_effects(contract, value, frozen, run_id=run_id, generated_at=generated_at)

    def run_validator(
        self,
        identifier: str,
        contract: ResolvedContract,
        value: Mapping[str, Any],
        frozen_inputs: Mapping[str, FrozenInput],
        root_bindings: Mapping[str, Path],
        registry: RegistrySnapshot,
        evidence_root: Path | None = None,
    ) -> tuple[str, str, Any, Any, list[str]] | None:
        if identifier == "knowledge_admission.candidate_v1":
            schema = registry.schema_document(contract.document["candidate"]["schema_ref"], contract.document["candidate"]["schema_digest"])
            return validate_candidate(value, schema, registry, frozen_inputs, root_bindings, evidence_root)
        if identifier in {"knowledge_admission.identity_v1", "knowledge_admission.provenance_v1", "knowledge_admission.source_binding_v1", "admission.canonical_json_v1"}:
            try:
                if identifier == "knowledge_admission.source_binding_v1":
                    _verify_all_source_bindings(value, Path(root_bindings[ROOT_BINDING]), Path(evidence_root), registry)  # type: ignore[arg-type]
                canonical_provenance(value)
            except (KeyError, OSError, TypeError, PhaseError) as exc:
                code = exc.code if isinstance(exc, PhaseError) else "knowledge.binding_unavailable"
                return "fail", code, identifier, "invalid", [code]
            return "pass", "validation.pass", identifier, identifier, []
        if identifier == "knowledge_admission.placement_v1":
            frozen = frozen_inputs.get(ASSET_BINDING)
            if frozen is None:
                return "fail", "input.required_missing", ASSET_BINDING, None, ["input.required_missing"]
            try:
                root = Path(root_bindings[contract.document["canonical_result"]["root_binding"]])
                return validate_preconditions(value, frozen, root)
            except KeyError as exc:
                raise PhaseError("plan.root_binding_missing", ROOT_BINDING) from exc
        return None

    def before_effect(
        self,
        value: object,
        contract: ResolvedContract,
        effect: Mapping[str, Any],
        frozen_inputs: Mapping[str, FrozenInput],
        target_root: Path,
        evidence_root: Path | None = None,
        root_bindings: Mapping[str, Path] | None = None,
    ) -> None:
        del root_bindings
        if not isinstance(value, Mapping):
            return
        if evidence_root is None:
            raise PhaseError("knowledge.evidence_root_missing")
        registry = getattr(self, "_registry", None)
        if registry is None:
            raise PhaseError("knowledge.registry_unavailable")
        _verify_all_source_bindings(value, target_root, Path(evidence_root), registry)
        frozen = frozen_inputs.get(ASSET_BINDING)
        if frozen is None:
            raise PhaseError("input.required_missing", ASSET_BINDING)
        status, code, _expected, _actual, _blockers = validate_preconditions(value, frozen, target_root)
        if status != "pass":
            raise PhaseError(code)

    def run_post_validator(
        self,
        identifier: str,
        contract: ResolvedContract,
        effect_plan: Mapping[str, Any],
        root_bindings: Mapping[str, Path],
        evidence_root: Path | None = None,
    ) -> tuple[str, str, Any, Any, list[str]] | None:
        if identifier != "knowledge_admission.result_v1":
            return None
        root_id = effect_plan["effects"][-1]["target"]["root_binding"]
        try:
            root = Path(root_bindings[root_id])
            locator = effect_plan["effects"][-1]["target"]["relative_locator"]
            expected_digest = effect_plan["effects"][-1]["content_digest"]
            data = read_target_bytes(
                root,
                locator,
                maximum_bytes=int(effect_plan["effects"][-1]["content_length"]),
            )
            actual_digest = digest_bytes(data)
            descriptor = parse_json_bytes(data)
            verify_result_reference(descriptor, actual_digest, root)
            blockers = [] if actual_digest == expected_digest else ["verification.result_mismatch"]
        except (KeyError, OSError, PhaseError):
            locator = effect_plan["effects"][-1]["target"]["relative_locator"]
            expected_digest = effect_plan["effects"][-1]["content_digest"]
            actual_digest = None
            blockers = ["verification.target_unavailable"]
        return (
            "pass" if not blockers else "fail",
            "validation.pass" if not blockers else blockers[0],
            {"locator": locator, "digest": expected_digest},
            {"locator": locator, "digest": actual_digest},
            blockers,
        )

    def inspect_result(
        self,
        data: bytes,
        descriptor_digest: str,
        root: Path,
        receipt_digest: str | None,
        registry: RegistrySnapshot,
        evidence_root: Path | None = None,
    ) -> dict[str, Any]:
        descriptor = parse_json_bytes(data)
        verify_result_reference(descriptor, descriptor_digest, root, receipt_digest, registry)
        result_schema = registry.schema_document("https://phase-tool.local/spec-candidates/admission-v1/schemas/knowledge-result.schema.json")
        Draft202012Validator(result_schema, registry=registry.schema_registry(), format_checker=FormatChecker()).validate(descriptor)
        if receipt_digest is None:
            raise PhaseError("knowledge.receipt_digest_missing")
        if evidence_root is not None:
            _verify_all_source_bindings({"provenance": descriptor["provenance"]}, root, Path(evidence_root), registry)
        return derived_result_documents(descriptor, descriptor_digest, receipt_digest, registry)


def create_contract_hook() -> KnowledgeAdmissionHook:
    return KnowledgeAdmissionHook()
