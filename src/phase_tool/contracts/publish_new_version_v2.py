from __future__ import annotations

import base64
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..canonical import digest_bytes, parse_json_bytes, profile_digest
from ..errors import PhaseError
from ..evidence import evidence_file_exists, read_evidence_bytes, validate_intent
from ..freeze import FrozenInput
from ..paths import inspect_target_path, safe_relative_locator
from ..registry import RegistrySnapshot, ResolvedContract
from .target_io import observe_target

CONTRACT_ID = "publish_new_version.v2"
CONTRACT_VERSION = "1.0.0"
CURRENT_ROOT_BINDING = "current_root"
OBJECTS_ROOT_BINDING = "objects_root"
_MAX_CONTENT_BYTES = 512 * 1024


def object_locator(content_digest: str) -> str:
    hexdigest = content_digest.removeprefix("sha256:")
    if len(hexdigest) != 64 or any(char not in "0123456789abcdef" for char in hexdigest):
        raise PhaseError("publish.current_digest_invalid", content_digest)
    return safe_relative_locator(f"sha256/{hexdigest[:2]}/{hexdigest}")


def inline_content(value: Mapping[str, Any]) -> bytes:
    content = value.get("content_utf8")
    if not isinstance(content, str):
        raise PhaseError("publish.content_utf8_required")
    try:
        data = content.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise PhaseError("publish.content_utf8_invalid") from exc
    if len(data) > _MAX_CONTENT_BYTES:
        raise PhaseError("publish.content_too_large")
    return data


def _state(root: Path, locator: str) -> dict[str, Any]:
    path, exists = inspect_target_path(root, locator)
    if not exists:
        return {"exists": False, "digest": None, "length": None}
    if not path.is_file():
        return {"exists": True, "digest": None, "length": None}
    observation = observe_target(root, locator)
    return {"exists": True, "digest": observation["digest"], "length": observation["length"]}


def _exact(state: Mapping[str, Any], digest: str, length: int) -> bool:
    return state == {"exists": True, "digest": digest, "length": length}


def _absent(state: Mapping[str, Any]) -> bool:
    return state == {"exists": False, "digest": None, "length": None}


def _classify(plan: Mapping[str, Any], root_bindings: Mapping[str, Path]) -> str:
    if plan.get("operation_intent") != "publish_new_version" or len(plan.get("effects", [])) != 1:
        return "blocked"
    effect = plan["effects"][0]
    try:
        current_root = Path(root_bindings[effect["target"]["root_binding"]])
        objects_root = Path(root_bindings[effect["archive_target"]["root_binding"]])
        current = _state(current_root, effect["target"]["relative_locator"])
        old_object = _state(objects_root, effect["archive_target"]["relative_locator"])
        new_object = _state(objects_root, effect["content_object_target"]["relative_locator"])
    except (KeyError, PhaseError):
        return "blocked"
    current_old = _exact(current, effect["archive_digest"], effect["archive_length"])
    current_new = _exact(current, effect["content_digest"], effect["content_length"])
    old_ok = _exact(old_object, effect["archive_digest"], effect["archive_length"])
    new_ok = _exact(new_object, effect["content_digest"], effect["content_length"])
    old_absent = _absent(old_object)
    new_absent = _absent(new_object)
    if current_old and old_absent and new_absent:
        return "no_effect_observed"
    if current_old and (old_ok or old_absent) and (new_ok or new_absent) and (old_ok or new_ok):
        return "archived_not_published"
    if current_new and old_ok and new_ok:
        return "published_not_finalized"
    return "blocked"


def validate_candidate(
    value: Mapping[str, Any], schema: Mapping[str, Any], registry: RegistrySnapshot, root_bindings: Mapping[str, Path]
) -> tuple[str, str, Any, Any, list[str]]:
    errors = sorted(
        Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        return "fail", "candidate.schema_invalid", "schema_valid", errors[0].message, ["candidate.schema_invalid"]
    try:
        safe_relative_locator(str(value["target_locator"]))
        object_locator(str(value["expected_current_digest"]))
        inline_content(value)
        current_root = Path(root_bindings[CURRENT_ROOT_BINDING]).resolve(strict=True)
        objects_root = Path(root_bindings[OBJECTS_ROOT_BINDING]).resolve(strict=True)
        if current_root == objects_root:
            raise PhaseError("publish.objects_root_not_separate")
        for child, parent in ((objects_root, current_root), (current_root, objects_root)):
            try:
                child.relative_to(parent)
            except ValueError:
                continue
            raise PhaseError("publish.objects_root_not_separate")
    except (KeyError, PhaseError) as exc:
        code = exc.code if isinstance(exc, PhaseError) else "plan.root_binding_missing"
        return "fail", code, "publish_v2_candidate_valid", "invalid", [code]
    return "pass", "validation.pass", "publish_v2_candidate_valid", "publish_v2_candidate_valid", []


def validate_preconditions(value: Mapping[str, Any], current_root: Path, objects_root: Path) -> tuple[str, str, Any, Any, list[str]]:
    content = inline_content(value)
    old_digest = str(value["expected_current_digest"])
    new_digest = digest_bytes(content)
    current = _state(current_root, safe_relative_locator(str(value["target_locator"])))
    old_object = _state(objects_root, object_locator(old_digest))
    new_object = _state(objects_root, object_locator(new_digest))
    current_old = current.get("digest") == old_digest
    if current_old and (not isinstance(current.get("length"), int) or current["length"] > _MAX_CONTENT_BYTES):
        return "fail", "publish.archive_too_large", _MAX_CONTENT_BYTES, current.get("length"), ["publish.archive_too_large"]
    old_allowed = _absent(old_object) or (old_object.get("digest") == old_digest and old_object.get("length") == current.get("length"))
    new_allowed = _absent(new_object) or _exact(new_object, new_digest, len(content))
    completed = _exact(current, new_digest, len(content)) and old_object.get("digest") == old_digest and new_allowed
    if (current_old and old_allowed and new_allowed) or completed:
        return "pass", "validation.pass", "current_and_objects_safe", {"current": current, "old_object": old_object, "new_object": new_object}, []
    code = "publish.object_conflict" if not old_allowed or not new_allowed else "publish.state_conflict"
    return "fail", code, "current_old_or_completed", {"current": current, "old_object": old_object, "new_object": new_object}, [code]


class PublishNewVersionV2Hook:
    def idempotency_locator(self, value: Mapping[str, Any], frozen_inputs: Mapping[str, FrozenInput], *, default: Any) -> Any:
        del frozen_inputs
        try:
            return safe_relative_locator(str(value["target_locator"]))
        except PhaseError:
            return default

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
        del frozen_inputs, run_id, generated_at
        roots = root_bindings or {}
        content = inline_content(value)
        old_digest = str(value["expected_current_digest"])
        new_digest = digest_bytes(content)
        locator = safe_relative_locator(str(value["target_locator"]))
        current = _state(Path(roots[CURRENT_ROOT_BINDING]), locator)
        old_length = current["length"] if current.get("digest") == old_digest else None
        if old_length is None:
            old_state = _state(Path(roots[OBJECTS_ROOT_BINDING]), object_locator(old_digest))
            old_length = old_state["length"] if old_state.get("digest") == old_digest else None
        if not isinstance(old_length, int) or old_length > _MAX_CONTENT_BYTES:
            raise PhaseError("publish.archive_too_large")
        return [{
            "ordinal": 0,
            "effect_id": "effect.publish.v2.001",
            "kind": "publish_new_version",
            "mechanism": {
                "id": contract.document["operation"]["mechanism"]["id"],
                "version": contract.document["operation"]["mechanism"]["version"],
                "package_digest": contract.document["operation"]["mechanism"]["package_digest"],
            },
            "target": {"root_binding": CURRENT_ROOT_BINDING, "relative_locator": locator},
            "archive_target": {"root_binding": OBJECTS_ROOT_BINDING, "relative_locator": object_locator(old_digest)},
            "content_object_target": {"root_binding": OBJECTS_ROOT_BINDING, "relative_locator": object_locator(new_digest)},
            "operation_identity": value["operation_id"],
            "request_digest": None,
            "input_binding": None,
            "content_source": {"kind": "captured_candidate", "binding_id": None, "source_digest": new_digest},
            "content_digest": new_digest,
            "content_blob_digest": new_digest,
            "content_length": len(content),
            "content_bytes_b64": base64.b64encode(content).decode("ascii"),
            "media_type": value["media_type"],
            "archive_digest": old_digest,
            "archive_length": old_length,
            "preconditions": {"existence": "present", "expected_digest": old_digest, "expected_head": None, "concurrency_token": old_digest},
            "lock_scope": "publish." + digest_bytes(locator.encode("utf-8")).removeprefix("sha256:"),
            "durability_policy_id": "file_and_directory_synced",
            "on_failure": "stop_and_classify",
        }]

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
        del frozen_inputs, evidence_root
        if identifier == "publish_new_version.candidate_v2":
            schema = registry.schema_document(contract.document["candidate"]["schema_ref"], contract.document["candidate"]["schema_digest"])
            return validate_candidate(value, schema, registry, root_bindings)
        if identifier == "publish_new_version.preconditions_v2":
            return validate_preconditions(value, Path(root_bindings[CURRENT_ROOT_BINDING]), Path(root_bindings[OBJECTS_ROOT_BINDING]))
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
        del contract, frozen_inputs, target_root, evidence_root
        if not isinstance(value, Mapping) or effect.get("kind") != "publish_new_version":
            return
        roots = root_bindings or {}
        status, code, *_ = validate_preconditions(value, Path(roots[CURRENT_ROOT_BINDING]), Path(roots[OBJECTS_ROOT_BINDING]))
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
        del contract, evidence_root
        if identifier != "publish_new_version.result_v2":
            return None
        effect = effect_plan["effects"][0]
        current = _state(Path(root_bindings[CURRENT_ROOT_BINDING]), effect["target"]["relative_locator"])
        objects = Path(root_bindings[OBJECTS_ROOT_BINDING])
        old_object = _state(objects, effect["archive_target"]["relative_locator"])
        new_object = _state(objects, effect["content_object_target"]["relative_locator"])
        expected = {
            "current": {"exists": True, "digest": effect["content_digest"], "length": effect["content_length"]},
            "old_object": {"exists": True, "digest": effect["archive_digest"], "length": effect["archive_length"]},
            "new_object": {"exists": True, "digest": effect["content_digest"], "length": effect["content_length"]},
        }
        actual = {"current": current, "old_object": old_object, "new_object": new_object}
        ok = actual == expected
        return "pass" if ok else "fail", "validation.pass" if ok else "verification.result_mismatch", expected, actual, [] if ok else ["verification.result_mismatch"]

    def inspect_result(self, data: bytes, current_digest: str, root: Path, receipt_digest: str | None, registry: RegistrySnapshot, evidence_root: Path | None = None) -> dict[str, Any]:
        del data, current_digest, root, receipt_digest, registry, evidence_root
        return {}

    def inspect_receipt_result(
        self,
        receipt: Mapping[str, Any],
        plan: Mapping[str, Any],
        root: Path,
        registry: RegistrySnapshot,
        evidence_root: Path,
        *,
        root_bindings: Mapping[str, Path] | None = None,
    ) -> dict[str, Any]:
        del root, registry, evidence_root
        effect = plan["effects"][0]
        receipts = receipt.get("effect_receipts", [])
        if len(receipts) != 1 or receipts[0].get("status") not in {"applied_verified", "applied_unverified"}:
            raise PhaseError("inspection.effect_receipts_mismatch")
        effect_receipt = receipts[0]
        roots = root_bindings or {}
        current = _state(Path(roots[CURRENT_ROOT_BINDING]), effect["target"]["relative_locator"])
        objects = Path(roots[OBJECTS_ROOT_BINDING])
        old_object = _state(objects, effect["archive_target"]["relative_locator"])
        new_object = _state(objects, effect["content_object_target"]["relative_locator"])
        if current != {"exists": True, "digest": effect["content_digest"], "length": effect["content_length"]}:
            raise PhaseError("inspection.target_mismatch", effect["target"]["relative_locator"])
        if old_object != {"exists": True, "digest": effect["archive_digest"], "length": effect["archive_length"]}:
            raise PhaseError("inspection.target_mismatch", effect["archive_target"]["relative_locator"])
        if new_object != {"exists": True, "digest": effect["content_digest"], "length": effect["content_length"]}:
            raise PhaseError("inspection.target_mismatch", effect["content_object_target"]["relative_locator"])
        if effect_receipt.get("archive_target") != effect["archive_target"] or effect_receipt.get("content_object_target") != effect["content_object_target"]:
            raise PhaseError("inspection.effect_receipts_mismatch")
        return {"current": current, "old_object": old_object, "new_object": new_object}

    def classify_prior_execution(self, evidence_root: Path, run_id: str, root_bindings: Mapping[str, Path], registry: RegistrySnapshot) -> str:
        run_root = evidence_root / ".phase" / "runs" / run_id
        intent_path = run_root / "intent.json"
        plan_path = run_root / "attachments" / "effect-plan.json"
        if not evidence_file_exists(intent_path) or not evidence_file_exists(plan_path):
            return "blocked"
        intent = parse_json_bytes(read_evidence_bytes(intent_path))
        validate_intent(intent, registry)
        plan = parse_json_bytes(read_evidence_bytes(plan_path))
        if intent.get("effect_plan_digest") != profile_digest("effect-plan", plan):
            return "blocked"
        return _classify(plan, root_bindings)

    def inspect_missing_receipt_result(self, plan: Mapping[str, Any], root_bindings: Mapping[str, Path], registry: RegistrySnapshot) -> str:
        del registry
        return _classify(plan, root_bindings)


def create_contract_hook() -> PublishNewVersionV2Hook:
    return PublishNewVersionV2Hook()
