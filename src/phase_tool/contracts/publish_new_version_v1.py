from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..canonical import digest_bytes, parse_json_bytes, profile_digest
from ..errors import PhaseError
from ..evidence import evidence_file_exists, read_evidence_bytes, validate_intent
from ..freeze import FrozenInput, revalidate_frozen
from ..paths import contained_read_path, inspect_target_path, safe_relative_locator
from ..registry import RegistrySnapshot, ResolvedContract
from .target_io import observe_target

CONTRACT_ID = "publish_new_version.v1"
CONTRACT_VERSION = "1.0.0"
ROOT_BINDING = "fixture_result_root"
PAYLOAD_BINDING = "payload"


def archive_locator(current_digest: str) -> str:
    hex_digest = current_digest.removeprefix("sha256:")
    if len(hex_digest) != 64 or any(char not in "0123456789abcdef" for char in hex_digest):
        raise PhaseError("publish.current_digest_invalid", current_digest)
    return safe_relative_locator(f"archive/sha256/{hex_digest[:2]}/{hex_digest}")


def _state(root: Path, locator: str) -> dict[str, Any]:
    path, exists = inspect_target_path(root, locator)
    if not exists:
        return {"exists": False, "digest": None, "length": None}
    if not path.is_file():
        return {"exists": True, "digest": None, "length": None}
    observation = observe_target(root, locator)
    return {"exists": True, "digest": observation["digest"], "length": observation["length"]}


def _classify_states(
    *,
    current: Mapping[str, Any],
    archive: Mapping[str, Any],
    before_digest: str,
    before_length: int,
    after_digest: str,
    after_length: int,
) -> str:
    current_before = current == {"exists": True, "digest": before_digest, "length": before_length}
    current_after = current == {"exists": True, "digest": after_digest, "length": after_length}
    archive_absent = archive == {"exists": False, "digest": None, "length": None}
    archive_exact = archive == {"exists": True, "digest": before_digest, "length": before_length}
    if current_before and archive_absent:
        return "no_effect_observed"
    if current_before and archive_exact:
        return "archived_not_published"
    if current_after and archive_exact:
        return "published_not_finalized"
    return "conflict_or_partial_or_indeterminate"


def _inspect_plan_state(plan: Mapping[str, Any], root_bindings: Mapping[str, Path]) -> str:
    if plan.get("operation_intent") != "publish_new_version" or len(plan.get("effects", [])) != 1:
        return "blocked"
    effect = plan["effects"][0]
    if effect.get("kind") != "publish_new_version":
        return "blocked"
    try:
        root = Path(root_bindings[effect["target"]["root_binding"]])
        current = _state(root, effect["target"]["relative_locator"])
        archive = _state(root, effect["archive_target"]["relative_locator"])
    except (KeyError, PhaseError):
        return "blocked"
    state = _classify_states(
        current=current,
        archive=archive,
        before_digest=effect["archive_digest"],
        before_length=effect["archive_length"],
        after_digest=effect["content_digest"],
        after_length=effect["content_length"],
    )
    return "blocked" if state == "conflict_or_partial_or_indeterminate" else state


def validate_candidate(
    value: Mapping[str, Any],
    schema: Mapping[str, Any],
    registry: RegistrySnapshot,
    frozen_inputs: Mapping[str, FrozenInput],
    root_bindings: Mapping[str, Path],
) -> tuple[str, str, Any, Any, list[str]]:
    errors = sorted(
        Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        return "fail", "candidate.schema_invalid", "schema_valid", errors[0].message, ["candidate.schema_invalid"]
    if value["input_binding"] != PAYLOAD_BINDING:
        return "fail", "publish.input_binding_unsupported", PAYLOAD_BINDING, value["input_binding"], ["publish.input_binding_unsupported"]
    if "current_state" in value:
        return "fail", "publish.current_state_public_binding_forbidden", None, "present", ["publish.current_state_public_binding_forbidden"]
    frozen = frozen_inputs.get(PAYLOAD_BINDING)
    if frozen is None:
        return "fail", "input.required_missing", PAYLOAD_BINDING, None, ["input.required_missing"]
    try:
        revalidate_frozen(frozen)
        target_locator = safe_relative_locator(str(value["target_locator"]))
        deterministic_archive = archive_locator(str(value["expected_current_digest"]))
        if target_locator == deterministic_archive:
            raise PhaseError("publish.target_archive_collision")
        Path(root_bindings[ROOT_BINDING])
    except (KeyError, PhaseError) as exc:
        code = exc.code if isinstance(exc, PhaseError) else "plan.root_binding_missing"
        return "fail", code, "publish_candidate_valid", "invalid", [code]
    return "pass", "validation.pass", "publish_candidate_valid", "publish_candidate_valid", []


def validate_preconditions(value: Mapping[str, Any], frozen: FrozenInput, root: Path) -> tuple[str, str, Any, Any, list[str]]:
    locator = safe_relative_locator(str(value["target_locator"]))
    expected = str(value["expected_current_digest"])
    archive = archive_locator(expected)
    try:
        current_state = _state(root, locator)
        archive_state = _state(root, archive)
    except PhaseError as exc:
        return "fail", exc.code, "safe_publish_paths", str(exc), [exc.code]
    before_length = -1
    if current_state["digest"] == expected:
        before_length = int(current_state["length"])
    elif archive_state["digest"] == expected:
        before_length = int(archive_state["length"])
    state = _classify_states(
        current=current_state,
        archive=archive_state,
        before_digest=expected,
        before_length=before_length,
        after_digest=frozen.digest,
        after_length=frozen.length,
    )
    if state == "no_effect_observed":
        return "pass", "validation.pass", "current_before_archive_absent", {"current": current_state, "archive": archive_state}, []
    if state == "archived_not_published":
        return "pass", "validation.pass", "current_before_archive_exact", {"current": current_state, "archive": archive_state}, []
    if state == "published_not_finalized":
        return "pass", "validation.pass", "current_after_archive_exact", {"current": current_state, "archive": archive_state}, []
    return "fail", "publish.state_conflict", "before_or_safe_continuation", {"current": current_state, "archive": archive_state}, ["publish.state_conflict"]


def build_effects(contract: ResolvedContract, value: Mapping[str, Any], frozen: FrozenInput) -> list[dict[str, Any]]:
    revalidate_frozen(frozen)
    locator = safe_relative_locator(str(value["target_locator"]))
    root_binding = contract.document["canonical_result"]["root_binding"]
    root = Path(getattr(contract, "_root_bindings", {}).get(root_binding, "."))  # unused compatibility guard
    del root
    expected_digest = str(value["expected_current_digest"])
    deterministic_archive = archive_locator(expected_digest)
    if locator == deterministic_archive:
        raise PhaseError("publish.target_archive_collision")
    return [
        {
            "ordinal": 0,
            "effect_id": "effect.publish.001",
            "kind": "publish_new_version",
            "target": {"root_binding": root_binding, "relative_locator": locator},
            "archive_target": {"root_binding": root_binding, "relative_locator": deterministic_archive},
            "operation_identity": value["operation_id"],
            "request_digest": None,
            "input_binding": PAYLOAD_BINDING,
            "content_source": {"kind": "frozen_input", "binding_id": PAYLOAD_BINDING, "source_digest": frozen.digest},
            "content_digest": frozen.digest,
            "content_length": frozen.length,
            "archive_digest": expected_digest,
            "archive_length": None,
            "preconditions": {
                "existence": "present",
                "expected_digest": expected_digest,
                "expected_head": None,
                "concurrency_token": expected_digest,
            },
            "lock_scope": "publish." + digest_bytes(locator.encode("utf-8")).removeprefix("sha256:"),
            "durability_policy_id": "file_data_synced",
            "on_failure": "stop_and_classify",
        }
    ]


class PublishNewVersionHook:
    def idempotency_locator(self, value: Mapping[str, Any], frozen_inputs: Mapping[str, FrozenInput], *, default: Any) -> Any:
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
        del run_id, generated_at
        frozen = frozen_inputs.get(PAYLOAD_BINDING)
        if frozen is None:
            raise PhaseError("input.required_missing", PAYLOAD_BINDING)
        effects = build_effects(contract, value, frozen)
        root = Path((root_bindings or {}).get(ROOT_BINDING, "."))
        if root.exists():
            current = _state(root, effects[0]["target"]["relative_locator"])
            archive = _state(root, effects[0]["archive_target"]["relative_locator"])
            if current["digest"] == value["expected_current_digest"]:
                effects[0]["archive_length"] = current["length"]
            elif archive["digest"] == value["expected_current_digest"]:
                effects[0]["archive_length"] = archive["length"]
        return effects

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
        del evidence_root
        if identifier == "publish_new_version.candidate_v1":
            schema = registry.schema_document(contract.document["candidate"]["schema_ref"], contract.document["candidate"]["schema_digest"])
            return validate_candidate(value, schema, registry, frozen_inputs, root_bindings)
        if identifier == "publish_new_version.preconditions_v1":
            frozen = frozen_inputs.get(PAYLOAD_BINDING)
            if frozen is None:
                return "fail", "input.required_missing", PAYLOAD_BINDING, None, ["input.required_missing"]
            return validate_preconditions(value, frozen, Path(root_bindings[ROOT_BINDING]))
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
        del contract, evidence_root, root_bindings
        if not isinstance(value, Mapping) or effect.get("kind") != "publish_new_version":
            return
        frozen = frozen_inputs.get(PAYLOAD_BINDING)
        if frozen is None:
            raise PhaseError("input.required_missing", PAYLOAD_BINDING)
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
        del contract, evidence_root
        if identifier != "publish_new_version.result_v1":
            return None
        effect = effect_plan["effects"][0]
        root = Path(root_bindings[effect["target"]["root_binding"]])
        current = _state(root, effect["target"]["relative_locator"])
        archive = _state(root, effect["archive_target"]["relative_locator"])
        ok = (
            current == {"exists": True, "digest": effect["content_digest"], "length": effect["content_length"]}
            and archive == {"exists": True, "digest": effect["archive_digest"], "length": effect["archive_length"]}
        )
        return (
            "pass" if ok else "fail",
            "validation.pass" if ok else "verification.result_mismatch",
            {
                "current": {"locator": effect["target"]["relative_locator"], "digest": effect["content_digest"], "length": effect["content_length"]},
                "archive": {"locator": effect["archive_target"]["relative_locator"], "digest": effect["archive_digest"], "length": effect["archive_length"]},
            },
            {"current": current, "archive": archive},
            [] if ok else ["verification.result_mismatch"],
        )

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
        del registry, evidence_root, root_bindings
        if not plan["effects"]:
            raise PhaseError("publish.plan_missing")
        effect = plan["effects"][0]
        receipt_effects = receipt.get("effect_receipts", [])
        if len(receipt_effects) != 1:
            raise PhaseError("publish.receipt_effect_missing")
        effect_receipt = receipt_effects[0]
        if effect_receipt.get("kind") != "publish_new_version":
            raise PhaseError("publish.receipt_effect_missing")
        if effect_receipt.get("status") != "applied_verified" or effect_receipt.get("attempted") is not True:
            raise PhaseError("inspection.effect_receipts_mismatch")
        current = _state(root, effect["target"]["relative_locator"])
        archive = _state(root, effect["archive_target"]["relative_locator"])
        if current != {"exists": True, "digest": effect["content_digest"], "length": effect["content_length"]}:
            raise PhaseError("inspection.target_mismatch", effect["target"]["relative_locator"])
        if archive != {"exists": True, "digest": effect["archive_digest"], "length": effect["archive_length"]}:
            raise PhaseError("inspection.target_mismatch", effect["archive_target"]["relative_locator"])
        if effect_receipt.get("archive_target") != effect["archive_target"] or effect_receipt.get("archive_after", {}).get("digest") != effect["archive_digest"]:
            raise PhaseError("inspection.effect_receipts_mismatch")
        expected_before = {"known": True, "exists": True, "digest": effect["archive_digest"], "length": effect["archive_length"], "head_token": None}
        expected_after = {"known": True, "exists": True, "digest": effect["content_digest"], "length": effect["content_length"], "head_token": None}
        expected_archive = {"known": True, "exists": True, "digest": effect["archive_digest"], "length": effect["archive_length"], "head_token": None}
        archive_before = effect_receipt.get("archive_before", {})
        if effect_receipt.get("before") != expected_before or effect_receipt.get("after") != expected_after:
            raise PhaseError("inspection.effect_receipts_mismatch")
        if archive_before.get("exists") is True and archive_before != expected_archive:
            raise PhaseError("inspection.effect_receipts_mismatch")
        if effect_receipt.get("archive_after") != expected_archive:
            raise PhaseError("inspection.effect_receipts_mismatch")
        return {"current": current, "archive": archive}

    def inspect_result(
        self,
        data: bytes,
        current_digest: str,
        root: Path,
        receipt_digest: str | None,
        registry: RegistrySnapshot,
        evidence_root: Path | None = None,
    ) -> dict[str, Any]:
        del data, current_digest, root, receipt_digest, registry, evidence_root
        return {}

    def classify_prior_execution(
        self,
        evidence_root: Path,
        run_id: str,
        root_bindings: Mapping[str, Path],
        registry: RegistrySnapshot,
    ) -> str:
        run_root = evidence_root / ".phase" / "runs" / run_id
        intent_path = run_root / "intent.json"
        plan_path = run_root / "attachments" / "effect-plan.json"
        if not evidence_file_exists(intent_path) or not evidence_file_exists(plan_path):
            return "blocked"
        intent = parse_json_bytes(read_evidence_bytes(intent_path))
        validate_intent(intent, registry)
        plan = parse_json_bytes(read_evidence_bytes(plan_path))
        if intent.get("effect_plan_digest") is None:
            return "blocked"
        if intent.get("effect_plan_digest") != profile_digest("effect-plan", plan):
            return "blocked"
        return _inspect_plan_state(plan, root_bindings)

    def inspect_missing_receipt_result(
        self,
        plan: Mapping[str, Any],
        root_bindings: Mapping[str, Path],
        registry: RegistrySnapshot,
    ) -> str:
        del registry
        return _inspect_plan_state(plan, root_bindings)


def create_contract_hook() -> PublishNewVersionHook:
    return PublishNewVersionHook()
