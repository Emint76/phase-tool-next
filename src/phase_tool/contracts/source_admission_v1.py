from __future__ import annotations

import base64
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..canonical import digest_bytes, parse_json_bytes, profile_digest
from ..errors import PhaseError
from ..freeze import FrozenInput, revalidate_frozen
from ..paths import inspect_target_path, safe_relative_locator
from ..registry import RegistrySnapshot, ResolvedContract
from .target_io import observe_target, read_target_bytes

CONTRACT_ID = "source_admission.v1"
CONTRACT_VERSION = "1.0.0"
ROOT_BINDING = "admission_result_root"
ASSET_BINDING = "asset"
DESCRIPTOR_BINDING = "descriptor_bytes"
_SAFE_INT = 9_007_199_254_740_991
_MAX_DESCRIPTOR_BYTES = 1024 * 1024
_LOGICAL_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


def _check_admission_value(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int) and not isinstance(item, bool):
            if item < -_SAFE_INT or item > _SAFE_INT:
                raise PhaseError("admission.integer_out_of_range")
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise PhaseError("admission.nonfinite_forbidden")
            raise PhaseError("admission.float_forbidden")
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise PhaseError("admission.unicode_not_nfc")
            continue
        if isinstance(item, Mapping):
            seen: set[str] = set()
            for key, child in item.items():
                if not isinstance(key, str):
                    raise PhaseError("admission.non_string_key")
                if unicodedata.normalize("NFC", key) != key:
                    raise PhaseError("admission.unicode_not_nfc")
                if key in seen:
                    raise PhaseError("admission.duplicate_key")
                seen.add(key)
                stack.append(child)
            continue
        if isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray, memoryview, str)):
            stack.extend(item)
            continue
        raise PhaseError("admission.unsupported_type", type(item).__name__)


def _escape_string(value: str) -> str:
    parts = ['"']
    for char in value:
        code = ord(char)
        if char == '"':
            parts.append('\\"')
        elif char == "\\":
            parts.append("\\\\")
        elif char == "\b":
            parts.append("\\b")
        elif char == "\t":
            parts.append("\\t")
        elif char == "\n":
            parts.append("\\n")
        elif char == "\f":
            parts.append("\\f")
        elif char == "\r":
            parts.append("\\r")
        elif code < 0x20:
            parts.append(f"\\u{code:04x}")
        else:
            parts.append(char)
    parts.append('"')
    return "".join(parts)


def _emit(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_emit(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda pair: [ord(ch) for ch in pair[0]])
        return "{" + ",".join(f"{_escape_string(key)}:{_emit(item)}" for key, item in items) + "}"
    raise PhaseError("admission.unsupported_type", type(value).__name__)


def admission_canonical_bytes(value: Any) -> bytes:
    _check_admission_value(value)
    return (_emit(value) + "\n").encode("utf-8")


def admission_digest(value: Any) -> str:
    return digest_bytes(admission_canonical_bytes(value))


def content_locator(content_digest: str) -> str:
    hex_digest = content_digest.removeprefix("sha256:")
    return safe_relative_locator(f"blobs/sha256/{hex_digest[:2]}/{hex_digest}")


def provenance_digest(candidate: Mapping[str, Any]) -> str:
    return admission_digest(candidate["provenance"])


def identity_projection(candidate: Mapping[str, Any], frozen: FrozenInput) -> dict[str, Any]:
    return {
        "admission_contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
        "namespace": candidate["placement"]["namespace"],
        "logical_source_id": candidate["logical_source_id"],
        "content_digest": frozen.digest,
        "content_length": frozen.length,
        "media_type": candidate["declared_media_type"],
        "original_filename": candidate["original_filename"],
        "provenance_digest": provenance_digest(candidate),
        "supersedes": candidate["supersedes"],
    }


def source_result_id(candidate: Mapping[str, Any], frozen: FrozenInput) -> str:
    return "source-result-" + admission_digest(identity_projection(candidate, frozen)).removeprefix("sha256:")


def descriptor_locator(candidate: Mapping[str, Any], result_id: str) -> str:
    namespace = candidate["placement"]["namespace"]
    logical_id = candidate["logical_source_id"]
    return safe_relative_locator(f"r/{namespace}/{logical_id}/{result_id}.json")


def descriptor_value(candidate: Mapping[str, Any], frozen: FrozenInput, *, run_id: str, observed_at: str) -> dict[str, Any]:
    result_id = source_result_id(candidate, frozen)
    blob_locator = content_locator(frozen.digest)
    desc_locator = descriptor_locator(candidate, result_id)
    return {
        "result_schema_version": "1.0",
        "source_result_id": result_id,
        "logical_source_id": candidate["logical_source_id"],
        "content_digest": frozen.digest,
        "content_length": frozen.length,
        "media_type": candidate["declared_media_type"],
        "blob_locator": blob_locator,
        "descriptor_locator": desc_locator,
        "original_filename": candidate["original_filename"],
        "provenance": candidate["provenance"],
        "provenance_digest": provenance_digest(candidate),
        "admission_contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
        "admission_run": {"run_id": run_id, "receipt_authority": "phase_evidence_by_run_id"},
        "observed_at": observed_at,
        "supersedes": candidate["supersedes"],
    }


def descriptor_bytes(candidate: Mapping[str, Any], frozen: FrozenInput, *, run_id: str, observed_at: str) -> bytes:
    return admission_canonical_bytes(descriptor_value(candidate, frozen, run_id=run_id, observed_at=observed_at))


def validate_candidate(value: Mapping[str, Any], schema: Mapping[str, Any], registry: RegistrySnapshot, frozen_inputs: Mapping[str, FrozenInput]) -> tuple[str, str, Any, Any, list[str]]:
    errors = sorted(
        Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        return "fail", "candidate.schema_invalid", "schema_valid", errors[0].message, ["candidate.schema_invalid"]
    if value["operation_id"] != value["idempotency_key"]:
        return "fail", "source.operation_key_mismatch", "operation_id_equals_idempotency_key", "mismatch", ["source.operation_key_mismatch"]
    frozen = frozen_inputs.get(ASSET_BINDING)
    if frozen is None:
        return "fail", "input.required_missing", ASSET_BINDING, None, ["input.required_missing"]
    try:
        revalidate_frozen(frozen)
    except PhaseError as exc:
        return "fail", exc.code, frozen.digest, "mismatch", [exc.code]
    expected_digest = value["asset_input"]["expected_digest"]
    expected_length = value["asset_input"]["expected_length"]
    if expected_digest is not None and expected_digest != frozen.digest:
        return "fail", "source.expected_digest_mismatch", expected_digest, frozen.digest, ["source.expected_digest_mismatch"]
    if expected_length is not None and expected_length != frozen.length:
        return "fail", "source.expected_length_mismatch", expected_length, frozen.length, ["source.expected_length_mismatch"]
    if not _LOGICAL_ID.fullmatch(value["logical_source_id"]):
        return "fail", "source.logical_id_invalid", "path_safe_lowercase", value["logical_source_id"], ["source.logical_id_invalid"]
    return "pass", "validation.pass", "source_candidate_valid", "source_candidate_valid", []


def validate_preconditions(value: Mapping[str, Any], frozen: FrozenInput, root: Path) -> tuple[str, str, Any, Any, list[str]]:
    result_id = source_result_id(value, frozen)
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
    logical_dir = root / "r" / value["placement"]["namespace"] / value["logical_source_id"]
    if logical_dir.is_dir():
        for existing in sorted(logical_dir.glob("*.json")):
            if existing.name == f"{result_id}.json":
                continue
            return "fail", "source.logical_identity_conflict", result_id, existing.name, ["source.logical_identity_conflict"]
    if descriptor_exists:
        data = read_target_bytes(root, desc_locator, maximum_bytes=_MAX_DESCRIPTOR_BYTES)
        if digest_bytes(data) != digest_bytes(descriptor_bytes(value, frozen, run_id=parse_json_bytes(data)["admission_run"]["run_id"], observed_at=parse_json_bytes(data)["observed_at"])):
            return "fail", "target.same_key_conflict", "expected_descriptor", desc_locator, ["target.same_key_conflict"]
        if not blob_ok:
            return "fail", "source.canonical_result_incomplete", "descriptor_and_blob", "descriptor_only", ["source.canonical_result_incomplete"]
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
            "target": {"root_binding": ROOT_BINDING, "relative_locator": descriptor_locator(value, source_result_id(value, frozen))},
            "input_binding": DESCRIPTOR_BINDING,
            "content_source": {"kind": "frozen_input", "binding_id": DESCRIPTOR_BINDING, "source_digest": desc_digest},
            "content_digest": desc_digest,
            "content_blob_digest": desc_digest,
            "content_length": len(desc_bytes),
            "content_bytes_b64": desc_b64,
            "preconditions": {"existence": "absent", "expected_digest": None, "expected_head": None, "concurrency_token": None},
            "lock_scope": "logical." + admission_digest({"namespace": value["placement"]["namespace"], "logical_id": value["logical_source_id"]}).removeprefix("sha256:"),
            "durability_policy_id": "file_data_synced",
            "on_failure": "stop_and_classify",
        },
    ]


def verify_result_reference(descriptor: Mapping[str, Any], descriptor_digest: str, root: Path, receipt_digest: str | None = None) -> None:
    schema_keys = {"source_result_id", "logical_source_id", "content_digest", "content_length", "blob_locator", "descriptor_locator"}
    if not schema_keys.issubset(descriptor):
        raise PhaseError("source.result_invalid")
    blob_observation = observe_target(root, str(descriptor["blob_locator"]))
    if (
        blob_observation["digest"] != descriptor["content_digest"]
        or blob_observation["length"] != descriptor["content_length"]
    ):
        raise PhaseError("source.blob_mismatch")
    if descriptor_digest != digest_bytes(admission_canonical_bytes(dict(descriptor))):
        raise PhaseError("source.descriptor_mismatch")


def derived_result_documents(descriptor: Mapping[str, Any], descriptor_digest: str, receipt_digest: str, registry: RegistrySnapshot) -> dict[str, Any]:
    run_id = descriptor["admission_run"]["run_id"]
    reference = {
        "reference_version": "1.0",
        "source_result_id": descriptor["source_result_id"],
        "logical_source_id": descriptor["logical_source_id"],
        "content_digest": descriptor["content_digest"],
        "blob_locator": descriptor["blob_locator"],
        "descriptor_digest": descriptor_digest,
        "descriptor_locator": descriptor["descriptor_locator"],
        "contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
        "phase_receipt": {"run_id": run_id, "receipt_digest": receipt_digest},
    }
    binding = {
        "binding_version": "1.0",
        "source_result_id": descriptor["source_result_id"],
        "logical_source_id": descriptor["logical_source_id"],
        "source_content_digest": descriptor["content_digest"],
        "source_blob_locator": descriptor["blob_locator"],
        "source_descriptor_digest": descriptor_digest,
        "source_descriptor_locator": descriptor["descriptor_locator"],
        "source_contract": {"id": CONTRACT_ID, "version": CONTRACT_VERSION},
        "source_phase_receipt": {"run_id": run_id, "receipt_digest": receipt_digest},
    }
    for schema_ref, value in (
        ("https://phase-tool.local/spec-candidates/admission-v1/schemas/source-result-reference.schema.json", reference),
        ("https://phase-tool.local/spec-candidates/admission-v1/schemas/source-result-binding.schema.json", binding),
    ):
        schema = registry.schema_document(schema_ref)
        Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).validate(value)
    return {"reference": reference, "binding": binding}


class SourceAdmissionHook:
    def idempotency_locator(self, value: Mapping[str, Any], frozen_inputs: Mapping[str, FrozenInput], *, default: Any) -> Any:
        frozen = frozen_inputs.get(ASSET_BINDING)
        if frozen is None:
            return default
        return descriptor_locator(value, source_result_id(value, frozen))

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
        if identifier == "source_admission.candidate_v1":
            schema = registry.schema_document(contract.document["candidate"]["schema_ref"], contract.document["candidate"]["schema_digest"])
            return validate_candidate(value, schema, registry, frozen_inputs)
        if identifier in {"source_admission.identity_v1", "source_admission.provenance_v1", "admission.canonical_json_v1"}:
            return "pass", "validation.pass", identifier, identifier, []
        if identifier == "source_admission.placement_v1":
            frozen = frozen_inputs.get(ASSET_BINDING)
            if frozen is None:
                return "fail", "input.required_missing", ASSET_BINDING, None, ["input.required_missing"]
            binding = contract.document["canonical_result"]["root_binding"]
            try:
                root = Path(root_bindings[binding])
            except KeyError as exc:
                raise PhaseError("plan.root_binding_missing", binding) from exc
            return validate_preconditions(value, frozen, root)
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
        if not isinstance(value, Mapping) or effect.get("kind") != "exclusive_create":
            return
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
        if identifier != "source_admission.result_v1":
            return None
        root_id = effect_plan["effects"][-1]["target"]["root_binding"]
        try:
            root = Path(root_bindings[root_id])
        except KeyError as exc:
            raise PhaseError("plan.root_binding_missing", root_id) from exc
        locator = effect_plan["effects"][-1]["target"]["relative_locator"]
        expected_digest = effect_plan["effects"][-1]["content_digest"]
        try:
            data = read_target_bytes(
                root,
                locator,
                maximum_bytes=int(effect_plan["effects"][-1]["content_length"]),
            )
            actual_digest = digest_bytes(data)
            descriptor = parse_json_bytes(data)
            verify_result_reference(descriptor, actual_digest, root)
            blockers = [] if actual_digest == expected_digest else ["verification.result_mismatch"]
        except (OSError, PhaseError):
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
        verify_result_reference(descriptor, descriptor_digest, root, receipt_digest)
        result_schema = registry.schema_document("https://phase-tool.local/spec-candidates/admission-v1/schemas/source-result.schema.json")
        Draft202012Validator(result_schema, registry=registry.schema_registry(), format_checker=FormatChecker()).validate(descriptor)
        if receipt_digest is None:
            raise PhaseError("source.receipt_digest_missing")
        return derived_result_documents(descriptor, descriptor_digest, receipt_digest, registry)


def create_contract_hook() -> SourceAdmissionHook:
    return SourceAdmissionHook()
