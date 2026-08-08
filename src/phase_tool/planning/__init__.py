from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..candidate import CapturedCandidate
from ..canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from ..errors import PhaseError
from ..freeze import FrozenInput, revalidate_frozen
from ..paths import safe_relative_locator
from ..registry import RegistrySnapshot, ResolvedContract
from ..contracts import append_locator, append_lock_scope, append_record_bytes, append_record_identity, expected_append_locator, load_contract_hook


def _exact(binding: Mapping[str, Any]) -> dict[str, str]:
    return {"id": str(binding["id"]), "version": str(binding["version"]), "package_digest": str(binding["package_digest"])}


def root_identity_records(contract: ResolvedContract, root_bindings: Mapping[str, Path]) -> list[dict[str, object]]:
    root_identities = []
    for declaration in sorted(contract.document["write_scope"]["roots"], key=lambda item: item["binding_id"]):
        binding_id = declaration["binding_id"]
        try:
            resolved = Path(root_bindings[binding_id]).resolve(strict=True)
        except KeyError as exc:
            raise PhaseError("plan.root_binding_missing", binding_id) from exc
        info = resolved.stat()
        root_identities.append({
            "binding_id": binding_id,
            "resolved_path": os.path.normcase(str(resolved)),
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
        })
    return root_identities


def root_identity_digest(contract: ResolvedContract, root_bindings: Mapping[str, Path]) -> str:
    return profile_digest("resolved-root-identity", root_identity_records(contract, root_bindings))


def build_idempotency_digests(
    contract: ResolvedContract,
    candidate: CapturedCandidate,
    frozen_inputs: Mapping[str, FrozenInput],
    root_bindings: Mapping[str, Path],
) -> tuple[str, str, str | None, str, list[dict[str, object]]]:
    value = parse_json_bytes(candidate.canonical_bytes)
    locator: Any = value.get("target_locator", sorted(value.get("destinations", [])))
    if contract.document["operation"]["intent"] == "append":
        locator = append_locator(contract.document, value)
    hook = load_contract_hook(contract)
    if hook is not None:
        locator = hook.idempotency_locator(value, frozen_inputs, default=locator)
    root_identities = root_identity_records(contract, root_bindings)
    root_identity = profile_digest("resolved-root-identity", root_identities)
    scope = {
        "contract": {
            "id": contract.document["identity"]["id"],
            "version": contract.document["identity"]["version"],
            "package_digest": contract.package_digest,
        },
        "result_locator": locator,
        "root_identity_digest": root_identity,
        "operation_intent": contract.document["operation"]["intent"],
    }
    scope_digest = profile_digest("idempotency-scope", scope)
    request_digest = profile_digest(
        "request",
        {
            "scope": scope,
            "candidate_digest": candidate.digest,
            "inputs": [item.intent_record() for _, item in sorted(frozen_inputs.items())],
        },
    )
    return scope_digest, request_digest, value.get("idempotency_key"), root_identity, root_identities


def _require_roots(contract: ResolvedContract, root_bindings: Mapping[str, Path]) -> None:
    required = {root["binding_id"] for root in contract.document["write_scope"]["roots"]}
    missing = required.difference(root_bindings)
    if missing:
        raise PhaseError("plan.root_binding_missing", sorted(missing)[0])
    forbidden = set(contract.document["write_scope"]["forbidden_root_bindings"])
    if forbidden.intersection(root_bindings):
        raise PhaseError("plan.forbidden_root_binding", sorted(forbidden.intersection(root_bindings))[0])
    resolved = [Path(root_bindings[item]).resolve(strict=True) for item in required]
    if len(resolved) != len(set(resolved)):
        raise PhaseError("plan.root_binding_collision")


def _ensure_validation_allows_plan(results: list[dict[str, Any]]) -> None:
    for result in results:
        if result["blocking"] and result["phase"] != "post_operation" and result["status"] != "pass":
            raise PhaseError("validation.blocked", result["code"])


def build_static_plan(
    contract: ResolvedContract,
    candidate: CapturedCandidate,
    frozen_inputs: Mapping[str, FrozenInput],
    validator_results: list[dict[str, Any]],
    *,
    root_bindings: Mapping[str, Path],
    run_id: str,
    generated_at: str,
    request_digest: str | None = None,
) -> dict[str, Any]:
    _require_roots(contract, root_bindings)
    _ensure_validation_allows_plan(validator_results)
    value = parse_json_bytes(candidate.canonical_bytes)
    operation = contract.document["operation"]
    common = {
        "effect_plan_version": "1.0",
        "plan_id": "plan." + canonical_digest({"run_id": run_id, "candidate": candidate.digest})[-16:],
        "run_id": run_id,
        "contract": {"id": contract.document["identity"]["id"], "version": contract.document["identity"]["version"], "package_digest": contract.package_digest},
        "operation_intent": operation["intent"],
        "mechanism": _exact(operation["mechanism"]),
        "write_scope_digest": canonical_digest(contract.document["write_scope"]),
        "generated_at": generated_at,
        "effect_order": "static_predeclared",
    }
    effects: list[dict[str, Any]] = []
    if operation["intent"] == "create":
        binding_id = value["input_binding"]
        frozen = frozen_inputs.get(binding_id)
        if frozen is None:
            raise PhaseError("input.required_missing", binding_id)
        revalidate_frozen(frozen)
        locator = safe_relative_locator(value["target_locator"])
        effects.append({
            "effect_id": "effect.create.001",
            "kind": "exclusive_create",
            "target": {"root_binding": contract.document["canonical_result"]["root_binding"], "relative_locator": locator},
            "input_binding": binding_id,
            "content_source": {"kind": "frozen_input", "binding_id": binding_id, "source_digest": frozen.digest},
            "content_digest": frozen.digest,
            "content_length": frozen.length,
            "preconditions": {"existence": "absent", "expected_digest": None, "expected_head": None, "concurrency_token": None},
            "lock_scope": None,
            "durability_policy_id": "file_data_synced",
            "on_failure": "stop_and_classify",
        })
    elif operation["intent"] == "append":
        locator = append_locator(contract.document, value)
        expected_locator = expected_append_locator(contract.document, value)
        if locator != expected_locator:
            raise PhaseError("plan.locator_template_mismatch", locator)
        expected_head = value["expected_head"]
        current_bytes = b""
        if expected_head is not None:
            root = Path(root_bindings[contract.document["canonical_result"]["root_binding"]])
            current_bytes = (root / locator).read_bytes()
        content = append_record_bytes(value, existing_bytes=current_bytes, expected_head=expected_head, request_digest=request_digest)
        operation_identity = value.get("operation_id", value.get("idempotency_key"))
        record_identity = str(value["record_id"]) if "record" in value else append_record_identity(content)
        content_digest = digest_bytes(content)
        effects.append({
            "effect_id": "effect.append.001",
            "kind": "append_record",
            "target": {"root_binding": contract.document["canonical_result"]["root_binding"], "relative_locator": locator},
            "operation_identity": operation_identity,
            "request_digest": request_digest,
            "record_identity": record_identity,
            "input_binding": None,
            "content_source": {"kind": "captured_candidate", "binding_id": None, "source_digest": candidate.digest},
            "content_digest": content_digest,
            "content_blob_digest": content_digest,
            "content_length": len(content),
            "content_bytes_b64": base64.b64encode(content).decode("ascii"),
            "preconditions": {
                "existence": "absent" if expected_head is None else "present",
                "expected_digest": None,
                "expected_head": expected_head,
                "concurrency_token": expected_head,
            },
            "lock_scope": append_lock_scope(value),
            "durability_policy_id": "file_data_synced",
            "on_failure": "stop_and_classify",
        })
    elif (hook := load_contract_hook(contract)) is not None:
        effects.extend(
            hook.build_effects(
                contract,
                value,
                frozen_inputs,
                run_id=run_id,
                generated_at=generated_at,
                root_bindings=root_bindings,
            )
        )
    elif operation["intent"] == "copy":
        frozen = frozen_inputs.get(value["input_binding"])
        if frozen is None:
            raise PhaseError("input.required_missing", value["input_binding"])
        revalidate_frozen(frozen)
        locator = safe_relative_locator("objects/" + frozen.digest.removeprefix("sha256:"))
        effects.append({
            "effect_id": "effect.copy.001",
            "kind": "copy_blob",
            "target": {"root_binding": contract.document["canonical_result"]["root_binding"], "relative_locator": locator},
            "input_binding": value["input_binding"],
            "content_source": {"kind": "frozen_input", "binding_id": value["input_binding"], "source_digest": frozen.digest},
            "content_digest": frozen.digest,
            "content_length": frozen.length,
            "preconditions": {"existence": "absent_or_same_digest", "expected_digest": frozen.digest, "expected_head": None, "concurrency_token": None},
            "lock_scope": None,
            "durability_policy_id": "file_data_synced",
            "on_failure": "stop_and_classify",
        })
    else:
        raise PhaseError("plan.operation_unsupported", operation["intent"])
    plan = common | {"effects": effects}
    validate_static_plan(plan, contract, root_bindings, None)
    return plan


def validate_plan_mechanism_authorization(
    plan: Mapping[str, Any],
    contract: ResolvedContract,
    registry: RegistrySnapshot | None,
) -> None:
    operation = contract.document["operation"]
    if plan.get("mechanism") != _exact(operation["mechanism"]):
        raise PhaseError("plan.mechanism_mismatch")
    allowed_mechanisms = {
        tuple(_exact(binding).items())
        for binding in [operation["mechanism"], *operation.get("effect_mechanisms", [])]
    }
    for effect in plan.get("effects", []):
        if "mechanism" not in effect:
            continue
        if tuple(_exact(effect["mechanism"]).items()) not in allowed_mechanisms:
            raise PhaseError("plan.effect_mechanism_not_allowed", str(effect["effect_id"]))
        if registry is not None:
            registry.resolve_mechanism(effect["mechanism"])


def validate_static_plan(
    plan: dict[str, Any],
    contract: ResolvedContract,
    root_bindings: Mapping[str, Path],
    registry: RegistrySnapshot | None,
) -> None:
    _require_roots(contract, root_bindings)
    if registry is not None:
        schema = registry.schema_document("https://phase-tool.local/schemas/effect-plan.schema.json")
        errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(plan), key=lambda error: list(error.path))
        if errors:
            raise PhaseError("plan.schema_invalid", errors[0].message)
    if plan.get("contract") != {"id": contract.document["identity"]["id"], "version": contract.document["identity"]["version"], "package_digest": contract.package_digest}:
        raise PhaseError("plan.contract_mismatch")
    validate_plan_mechanism_authorization(plan, contract, registry)
    effects = plan.get("effects", [])
    if len(effects) > contract.document["operation"]["maximum_effects"] or not effects:
        raise PhaseError("plan.incomplete")
    ids = [effect["effect_id"] for effect in effects]
    if len(ids) != len(set(ids)):
        raise PhaseError("plan.duplicate_effect_id")
    locators = [(effect["target"]["root_binding"], effect["target"]["relative_locator"]) for effect in effects]
    if len(locators) != len(set(locators)):
        raise PhaseError("plan.locator_collision")
    operation = contract.document["operation"]
    allowed = set(operation["allowed_effects"])
    required_roots = {item["binding_id"] for item in contract.document["write_scope"]["roots"]}
    for effect in effects:
        if effect["kind"] not in allowed:
            raise PhaseError("plan.effect_not_allowed", effect["kind"])
        if effect["target"]["root_binding"] not in required_roots:
            raise PhaseError("plan.root_binding_unknown", effect["target"]["root_binding"])
        safe_relative_locator(effect["target"]["relative_locator"])
        source = effect["content_source"]
        if source["kind"] == "captured_candidate" and source["binding_id"] is not None:
            raise PhaseError("plan.source_binding_mismatch")
        if source["kind"] == "frozen_input" and source["binding_id"] != effect["input_binding"]:
            raise PhaseError("plan.source_binding_mismatch")
        if effect["kind"] == "publish_new_version":
            archive_target = effect.get("archive_target")
            if not isinstance(archive_target, Mapping):
                raise PhaseError("plan.archive_target_missing", str(effect["effect_id"]))
            if archive_target["root_binding"] not in required_roots:
                raise PhaseError("plan.root_binding_unknown", archive_target["root_binding"])
            archive_locator = safe_relative_locator(str(archive_target["relative_locator"]))
            if effect.get("archive_digest") != effect["preconditions"]["expected_digest"]:
                raise PhaseError("plan.archive_binding_mismatch", str(effect["effect_id"]))
            if effect.get("archive_length") is None:
                raise PhaseError("plan.archive_binding_mismatch", str(effect["effect_id"]))
            archive_hex = str(effect["archive_digest"]).removeprefix("sha256:")
            mechanism_id = str(effect.get("mechanism", plan["mechanism"])["id"])
            if mechanism_id == "mechanism.object_store_publish_v2":
                expected_archive_locator = f"sha256/{archive_hex[:2]}/{archive_hex}"
                content_object_target = effect.get("content_object_target")
                if not isinstance(content_object_target, Mapping):
                    raise PhaseError("plan.content_object_target_missing", str(effect["effect_id"]))
                content_digest = effect.get("content_digest")
                content_blob_digest = effect.get("content_blob_digest")
                content_bytes_b64 = effect.get("content_bytes_b64")
                content_length = effect.get("content_length")
                content_source = effect.get("content_source")
                media_type = effect.get("media_type")
                if (
                    effect.get("input_binding") is not None
                    or not isinstance(content_source, Mapping)
                    or content_source.get("kind") != "captured_candidate"
                    or content_source.get("binding_id") is not None
                ):
                    raise PhaseError("plan.source_binding_mismatch")
                if (
                    not isinstance(content_digest, str)
                    or content_blob_digest != content_digest
                    or not isinstance(content_bytes_b64, str)
                    or not isinstance(content_length, int)
                    or isinstance(content_length, bool)
                    or content_length < 0
                ):
                    raise PhaseError("plan.content_binding_mismatch")
                if not isinstance(media_type, str) or not media_type:
                    raise PhaseError("plan.media_type_missing")
                try:
                    decoded_content = base64.b64decode(content_bytes_b64, validate=True)
                except (ValueError, base64.binascii.Error) as exc:
                    raise PhaseError("plan.content_encoding_invalid") from exc
                if digest_bytes(decoded_content) != content_digest or len(decoded_content) != content_length:
                    raise PhaseError("plan.content_binding_mismatch")
                if content_object_target["root_binding"] not in required_roots:
                    raise PhaseError("plan.root_binding_unknown", content_object_target["root_binding"])
                if content_object_target["root_binding"] != archive_target["root_binding"]:
                    raise PhaseError("publish.object_root_mismatch")
                content_hex = content_digest.removeprefix("sha256:")
                expected_content_locator = f"sha256/{content_hex[:2]}/{content_hex}"
                if safe_relative_locator(str(content_object_target["relative_locator"])) != expected_content_locator:
                    raise PhaseError("plan.content_object_binding_mismatch", str(effect["effect_id"]))
                if effect["target"]["root_binding"] == archive_target["root_binding"]:
                    raise PhaseError("publish.objects_root_not_separate")
            else:
                expected_archive_locator = f"archive/sha256/{archive_hex[:2]}/{archive_hex}"
            if archive_locator != expected_archive_locator:
                raise PhaseError("plan.archive_binding_mismatch", str(effect["effect_id"]))
            if archive_target == effect["target"]:
                raise PhaseError("publish.target_archive_collision")
