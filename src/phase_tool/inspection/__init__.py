from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ..errors import PhaseError
from ..evidence import evidence_file_exists, iter_run_artifacts, read_evidence_bytes, validate_intent, validate_receipt, validate_run_id
from ..paths import _platform_path
from ..planning import validate_plan_mechanism_authorization, validate_static_plan
from ..registry import BundledRegistry, RegistrySnapshot, ResolvedContract
from ..mutation.guarantees import GuaranteeProfileBinding, verify_guarantee_coverage
from ..mutation.implementation import mechanism_authority_usage, mechanism_supports_effect_kind
from ..mutation.platform import HostAuthorityProvider
from ..contracts import load_contract_hook

_MATERIALIZED_TARGET_LIMITS = {
    "content_addressed_copy": 16 * 1024 * 1024,
    "mechanism.archive_then_publish_v1": 16 * 1024 * 1024,
    "mechanism.exclusive_create_v1": 1_048_576,
    "mechanism.object_store_publish_v2": 512 * 1024,
}


def _read_canonical(path: Path) -> tuple[Any, str]:
    try:
        data = read_evidence_bytes(path)
    except OSError as exc:
        raise PhaseError("inspection.missing_artifact", str(path.name)) from exc
    try:
        value = parse_json_bytes(data)
    except PhaseError as exc:
        raise PhaseError("inspection.invalid_json", str(path.name)) from exc
    if canonical_bytes(value) != data:
        raise PhaseError("inspection.digest_mismatch", str(path.name))
    return value, digest_bytes(data)


def _validate_progress(progress: Mapping[str, Any], plan: Mapping[str, Any], effect_receipts: list[dict[str, Any]], registry: RegistrySnapshot) -> None:
    from ..mutation.broker import ordered_progress_document

    schema = registry.schema_document("https://phase-tool.local/schemas/ordered-effect-progress.schema.json")
    Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).validate(progress)
    if progress["plan_digest"] != profile_digest("effect-plan", plan):
        raise PhaseError("inspection.progress_plan_mismatch")
    planned_ids = [effect["effect_id"] for effect in plan["effects"]]
    receipt_ids = [receipt["effect_id"] for receipt in effect_receipts]
    if receipt_ids != planned_ids[: len(receipt_ids)]:
        raise PhaseError("inspection.progress_prefix_mismatch")
    if progress["completed_effect_ids"] != receipt_ids:
        raise PhaseError("inspection.progress_prefix_mismatch")
    if progress["not_started_effect_ids"] != planned_ids[len(receipt_ids):]:
        raise PhaseError("inspection.progress_prefix_mismatch")
    receipt_by_id = {receipt["effect_id"]: receipt for receipt in effect_receipts}
    for index, effect_progress in enumerate(progress["effects"]):
        if effect_progress["ordinal"] != index or effect_progress["effect_id"] != planned_ids[index]:
            raise PhaseError("inspection.progress_prefix_mismatch")
        receipt = receipt_by_id.get(effect_progress["effect_id"])
        if receipt is None:
            if effect_progress["state"] != "not_started" or effect_progress["receipt_digest"] is not None or effect_progress["observation_digest"] is not None:
                raise PhaseError("inspection.progress_prefix_mismatch")
            continue
        if effect_progress["receipt_digest"] != profile_digest("effect-receipt", receipt):
            raise PhaseError("inspection.progress_receipt_mismatch")
        observation_digest = profile_digest("effect-observation", {"effect_id": receipt["effect_id"], "after": receipt["after"], "status": receipt["status"]})
        if effect_progress["observation_digest"] != observation_digest:
            raise PhaseError("inspection.progress_observation_mismatch")
    if progress != ordered_progress_document(plan, effect_receipts):
        raise PhaseError("inspection.progress_semantic_mismatch")


def _verify_intent_blobs(run_root: Path, intent: Mapping[str, Any], plan: Mapping[str, Any] | None = None) -> None:
    for item in intent["inputs"]:
        digest = item["blob_digest"]
        if digest is None:
            continue
        blob = run_root / "blobs" / digest.split(":", 1)[1]
        from ..streaming import FILE_LIMIT, REQUEST_LIMIT, MECHANISM_ID, hash_file
        streamed = plan is not None and plan["mechanism"]["id"] in {MECHANISM_ID, "mechanism.bundle_create_v1"}
        maximum_bytes = REQUEST_LIMIT if plan is not None and plan["mechanism"]["id"] == "mechanism.bundle_create_v1" else FILE_LIMIT
        actual = hash_file(blob, maximum_bytes)[0] if streamed and evidence_file_exists(blob) else (digest_bytes(read_evidence_bytes(blob)) if evidence_file_exists(blob) else None)
        if actual != digest:
            raise PhaseError("inspection.digest_mismatch", blob.name)
    evidence = intent.get("evidence", {})
    for digest in evidence.get("content_blob_digests", []):
        blob = run_root / "blobs" / digest.split(":", 1)[1]
        from ..streaming import FILE_LIMIT, REQUEST_LIMIT, MECHANISM_ID, hash_file
        streamed = plan is not None and plan["mechanism"]["id"] in {MECHANISM_ID, "mechanism.bundle_create_v1"}
        maximum_bytes = REQUEST_LIMIT if plan is not None and plan["mechanism"]["id"] == "mechanism.bundle_create_v1" else FILE_LIMIT
        actual = hash_file(blob, maximum_bytes)[0] if streamed and evidence_file_exists(blob) else (digest_bytes(read_evidence_bytes(blob)) if evidence_file_exists(blob) else None)
        if actual != digest:
            raise PhaseError("inspection.digest_mismatch", blob.name)
    if plan is not None and plan["mechanism"]["id"] == "mechanism.bundle_create_v1":
        from ..bundle import parse_manifest, read_metadata, verify_frozen_members
        effect = plan["effects"][0]
        data = read_metadata(run_root / "blobs" / effect["content_digest"].removeprefix("sha256:"))
        if len(data) != effect["content_length"] or digest_bytes(data) != effect["content_digest"]:
            raise PhaseError("bundle.frozen_manifest_mismatch")
        verify_frozen_members(parse_manifest(data), run_root / "blobs")
    if plan is None or plan.get("operation_intent") != "publish_new_version":
        return
    inputs = {item["binding_id"]: item for item in intent["inputs"]}
    for effect in plan.get("effects", []):
        source = effect.get("content_source", {})
        if source.get("kind") != "frozen_input":
            continue
        binding_id = source.get("binding_id")
        item = inputs.get(binding_id)
        if item is None or item.get("blob_digest") is None:
            raise PhaseError("inspection.frozen_input_mismatch", str(binding_id))
        blob_digest = item["blob_digest"]
        blob = run_root / "blobs" / blob_digest.split(":", 1)[1]
        data = read_evidence_bytes(blob)
        if (
            item.get("digest") != blob_digest
            or source.get("source_digest") != blob_digest
            or effect.get("content_digest") != blob_digest
            or effect.get("content_length") != len(data)
        ):
            raise PhaseError("inspection.frozen_input_mismatch", str(binding_id))


def _validate_implementation_binding(
    binding: Mapping[str, Any],
    plan: Mapping[str, Any],
    contract: ResolvedContract,
    registry: RegistrySnapshot,
) -> None:
    mechanism = plan.get("mechanism")
    if binding.get("mechanism") != mechanism or binding.get("effect_plan_digest") != profile_digest("effect-plan", plan):
        raise PhaseError("inspection.implementation_binding_mismatch")
    if not isinstance(mechanism, Mapping):
        raise PhaseError("inspection.implementation_binding_mismatch")
    registry.resolve_mechanism(mechanism)
    authority = binding.get("authority")
    effects = plan.get("effects")
    if not isinstance(authority, Mapping) or not isinstance(effects, list):
        raise PhaseError("inspection.implementation_binding_mismatch")
    authority_usage = mechanism_authority_usage(mechanism)
    for effect in effects:
        if not isinstance(effect, Mapping):
            raise PhaseError("inspection.implementation_binding_mismatch")
        effect_mechanism = effect.get("mechanism", mechanism)
        if not isinstance(effect_mechanism, Mapping):
            raise PhaseError("inspection.implementation_binding_mismatch")
        registry.resolve_mechanism(effect_mechanism)
        if (
            mechanism_authority_usage(effect_mechanism) != authority_usage
            or not mechanism_supports_effect_kind(effect_mechanism, effect.get("kind"))
        ):
            raise PhaseError("inspection.implementation_binding_mismatch")
    if authority_usage == "mechanism_managed":
        if authority != {"usage": "mechanism_managed", "profile": None, "provider": None}:
            raise PhaseError("inspection.implementation_binding_mismatch")
        requirements = contract.document["operation"].get("required_guarantees")
        if requirements is not None:
            mechanisms = [contract.document["operation"]["mechanism"]]
            mechanisms.extend(contract.document["operation"].get("effect_mechanisms", []))
            verify_guarantee_coverage(requirements, mechanisms, None, registry)
        return
    profile = authority.get("profile")
    provider = authority.get("provider")
    if authority.get("usage") != "provider_backed" or not isinstance(profile, Mapping) or not isinstance(provider, Mapping):
        raise PhaseError("inspection.implementation_binding_mismatch")
    descriptor = registry.resolve_guarantee_profile(profile)
    implementation = descriptor["implementation"]
    expected_provider = {
        "id": implementation["id"],
        "version": implementation["version"],
        "artifact_digest": implementation["artifact_digest"],
    }
    if provider != expected_provider:
        raise PhaseError("inspection.implementation_binding_mismatch")
    requirements = contract.document["operation"].get("required_guarantees")
    if requirements is not None:
        mechanisms = [contract.document["operation"]["mechanism"]]
        mechanisms.extend(contract.document["operation"].get("effect_mechanisms", []))
        profile_binding = GuaranteeProfileBinding(
            id=profile["id"],
            version=profile["version"],
            descriptor_digest=profile["descriptor_digest"],
            implementation_id=implementation["id"],
            implementation_version=implementation["version"],
            implementation_artifact_digest=implementation["artifact_digest"],
        )
        verify_guarantee_coverage(requirements, mechanisms, profile_binding, registry)


def _implementation_binding_required(contract: ResolvedContract, registry: RegistrySnapshot) -> bool:
    evidence = contract.document.get("evidence")
    if not isinstance(evidence, Mapping):
        raise PhaseError("inspection.implementation_binding_classification_failed")
    schema_ref = evidence.get("receipt_schema_ref")
    schema_digest = evidence.get("receipt_schema_digest")
    if not isinstance(schema_ref, str) or not isinstance(schema_digest, str):
        raise PhaseError("inspection.implementation_binding_classification_failed")
    schema = registry.schema_document(schema_ref, schema_digest)
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        raise PhaseError("inspection.implementation_binding_classification_failed")
    return "implementation_binding" in properties


def _prior_receipt_run_id(runs_root: Path, current_run_id: str, prior_digest: str) -> str:
    for path in iter_run_artifacts(runs_root, "receipt.json"):
        if path.parent.name == current_run_id:
            continue
        try:
            candidate, _ = _read_canonical(path)
        except PhaseError:
            continue
        if profile_digest("receipt", candidate) == prior_digest:
            return path.parent.name
    raise PhaseError("inspection.prior_receipt_missing", prior_digest)


def _inspect_missing_receipt_state(
    hook: Any,
    plan: Mapping[str, Any],
    contract: ResolvedContract,
    root_bindings: Mapping[str, Path],
    registry: RegistrySnapshot,
) -> str | None:
    try:
        validate_static_plan(plan, contract, root_bindings, registry)
        return hook.inspect_missing_receipt_result(plan, root_bindings, registry)
    except PhaseError as exc:
        if exc.code != "plan.root_unavailable":
            raise
        raise PhaseError("inspection.target_unavailable") from exc
    except OSError as exc:
        raise PhaseError("inspection.target_unavailable") from exc


def _resolved_hook_roots(
    contract: ResolvedContract,
    root_bindings: Mapping[str, Path],
) -> dict[str, Path]:
    resolved = dict(root_bindings)
    for declaration in contract.document["write_scope"]["roots"]:
        binding_id = declaration["binding_id"]
        if binding_id not in root_bindings:
            continue
        try:
            resolved[binding_id] = Path(root_bindings[binding_id]).resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise PhaseError("inspection.target_unavailable") from exc
    return resolved


def inspect_run(
    evidence_root: Path,
    run_id: str,
    registry: RegistrySnapshot | None = None,
    *,
    root_bindings: Mapping[str, Path] | None = None,
    _visited_receipts: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Verify evidence and, for observed results, re-read installation-bound target bytes."""
    validate_run_id(run_id)
    registry = registry or BundledRegistry.load()
    try:
        root = Path(_platform_path(Path(evidence_root))).resolve(strict=True)
        run_root = (root / ".phase" / "runs" / run_id).resolve(strict=True)
        expected_parent = (root / ".phase" / "runs").resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise PhaseError("inspection.run_unavailable") from exc
    try:
        run_root.relative_to(expected_parent)
    except ValueError as exc:
        raise PhaseError("inspection.outside_evidence_root", run_id) from exc
    receipt_path = run_root / "receipt.json"
    if not evidence_file_exists(receipt_path):
        intent, _ = _read_canonical(run_root / "intent.json")
        intent_digest = profile_digest("intent", intent)
        validate_intent(intent, registry)
        plan, _ = _read_canonical(run_root / "attachments" / "effect-plan.json")
        plan_digest = profile_digest("effect-plan", plan)
        if plan_digest != intent["effect_plan_digest"]:
            raise PhaseError("inspection.digest_mismatch", "effect-plan.json")
        if plan.get("contract") != intent.get("contract"):
            raise PhaseError("inspection.contract_mismatch")
        if intent.get("evidence", {}).get("effect_plan_attachment_digest") != digest_bytes(canonical_bytes(plan)):
            raise PhaseError("inspection.digest_mismatch", "effect-plan.json")
        contract_binding = intent["contract"]
        contract = registry.resolve_contract(
            contract_binding["id"],
            contract_binding["version"],
            contract_binding["package_digest"],
            core_version=intent["core"]["version"],
        )
        validate_plan_mechanism_authorization(plan, contract, registry)
        implementation_binding = intent.get("implementation_binding")
        if implementation_binding is None and _implementation_binding_required(contract, registry):
            raise PhaseError("inspection.implementation_binding_missing")
        if implementation_binding is not None:
            if not isinstance(implementation_binding, Mapping):
                raise PhaseError("inspection.implementation_binding_mismatch")
            _validate_implementation_binding(implementation_binding, plan, contract, registry)
        _verify_intent_blobs(run_root, intent, plan)
        state_classification = None
        hook = load_contract_hook(contract)
        if hook is not None and hasattr(hook, "inspect_missing_receipt_result"):
            state_classification = _inspect_missing_receipt_state(
                hook,
                plan,
                contract,
                root_bindings or {},
                registry,
            )
        return {
            "run_id": run_id,
            "terminal_status": None,
            "execution_disposition": None,
            "mutation_attempted": None,
            "result_state": None,
            "intent_digest": intent_digest,
            "effect_plan_digest": plan_digest,
            "receipt_digest": None,
            "contract": intent["contract"],
            "canonical_profile": "phase-canonical-json-v1",
            "target_verified": None,
            "receipt_present": False,
            "intent_present": True,
            "inspection_required": True,
            "state_classification": state_classification,
            "implementation_binding": implementation_binding,
        }
    receipt, _ = _read_canonical(receipt_path)
    receipt_digest = profile_digest("receipt", receipt)
    if receipt_digest in _visited_receipts:
        raise PhaseError("inspection.prior_receipt_cycle", receipt_digest)
    validate_receipt(receipt, registry)
    intent = None
    intent_digest = None
    plan = None
    plan_digest = None
    target_verified: bool | None = None
    contract_result: Any | None = None
    state_classification: str | None = None
    if receipt["evidence"]["intent_digest"] is not None:
        intent, _ = _read_canonical(run_root / "intent.json")
        intent_digest = profile_digest("intent", intent)
        validate_intent(intent, registry)
        if intent_digest != receipt["evidence"]["intent_digest"]:
            raise PhaseError("inspection.digest_mismatch", "intent.json")
        plan, plan_attachment_digest = _read_canonical(run_root / "attachments" / "effect-plan.json")
        plan_digest = profile_digest("effect-plan", plan)
        if plan_digest != intent["effect_plan_digest"]:
            raise PhaseError("inspection.digest_mismatch", "effect-plan.json")
        if plan.get("contract") != intent.get("contract"):
            raise PhaseError("inspection.contract_mismatch")
        if receipt.get("contract") != intent.get("contract"):
            raise PhaseError("inspection.contract_mismatch")
        contract_for_plan = registry.resolve_contract(
            intent["contract"]["id"],
            intent["contract"]["version"],
            intent["contract"]["package_digest"],
            core_version=intent["core"]["version"],
        )
        validate_plan_mechanism_authorization(plan, contract_for_plan, registry)
        intent_binding = intent.get("implementation_binding")
        receipt_binding = receipt.get("implementation_binding")
        if intent_binding != receipt_binding:
            raise PhaseError("inspection.implementation_binding_mismatch")
        if intent_binding is None and _implementation_binding_required(contract_for_plan, registry):
            raise PhaseError("inspection.implementation_binding_missing")
        if intent_binding is not None:
            if not isinstance(intent_binding, Mapping):
                raise PhaseError("inspection.implementation_binding_mismatch")
            _validate_implementation_binding(intent_binding, plan, contract_for_plan, registry)
        validators, validators_digest = _read_canonical(run_root / "attachments" / "validator-results.json")
        if validators != receipt["validator_results"]:
            raise PhaseError("inspection.validator_results_mismatch")
        attachment_digests = {plan_attachment_digest, validators_digest}
        claimed = set(receipt["evidence"]["attachment_digests"])
        effect_receipts = receipt["effect_receipts"]
        if effect_receipts:
            pre_validators, pre_validators_digest = _read_canonical(run_root / "attachments" / "pre-validator-results.json")
            stored_effect_receipts, effect_receipts_digest = _read_canonical(run_root / "attachments" / "effect-receipts.json")
            if stored_effect_receipts != effect_receipts:
                raise PhaseError("inspection.effect_receipts_mismatch")
            planned_ids = [item["effect_id"] for item in plan["effects"]]
            receipt_ids = [item["effect_id"] for item in effect_receipts]
            if receipt_ids != planned_ids[: len(receipt_ids)]:
                raise PhaseError("inspection.effect_receipt_set_mismatch")
            if not isinstance(pre_validators, list):
                raise PhaseError("inspection.validator_results_mismatch")
            attachment_digests.update({pre_validators_digest, effect_receipts_digest})
        progress_path = run_root / "attachments" / "ordered-effect-progress.json"
        if evidence_file_exists(progress_path):
            progress, progress_digest = _read_canonical(progress_path)
            if progress_digest in claimed:
                _validate_progress(progress, plan, effect_receipts, registry)
                attachment_digests.add(progress_digest)
            elif receipt["evidence"]["finalization_status"] == "finalized":
                attachment_digests.add(progress_digest)
        if attachment_digests != claimed:
            raise PhaseError("inspection.attachment_set_mismatch")
        _verify_intent_blobs(run_root, intent, plan)
        hook_for_plan = load_contract_hook(contract_for_plan)
        needs_state_classification = (
            receipt["terminal_status"] not in {"succeeded_verified", "validated_planned"}
            or receipt["evidence"]["finalization_status"] != "finalized"
        )
        if needs_state_classification and hook_for_plan is not None and hasattr(hook_for_plan, "inspect_missing_receipt_result"):
            state_classification = _inspect_missing_receipt_state(
                hook_for_plan,
                plan,
                contract_for_plan,
                root_bindings or {},
                registry,
            )
    canonical_result = receipt["canonical_result"]
    if canonical_result is not None:
        if canonical_result.get("contract") != receipt.get("contract"):
            raise PhaseError("inspection.contract_mismatch")
        contract_binding = receipt["contract"]
        contract = registry.resolve_contract(
            contract_binding["id"],
            contract_binding["version"],
            contract_binding["package_digest"],
            core_version=receipt["core"]["version"],
        )
        roots = root_bindings or {}
        root_id = canonical_result["root_binding"]
        try:
            target_root = Path(roots[root_id])
        except KeyError as exc:
            raise PhaseError("inspection.target_root_missing", root_id) from exc
        try:
            resolved_target_root = target_root.resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise PhaseError("inspection.target_mismatch", canonical_result["locator"]) from exc
        state = canonical_result["state"]
        appended = canonical_result.get("appended_record")
        data: bytes | None = None
        streamed_state = None
        append_tail_bytes = 0
        if appended is not None:
            append_tail_bytes = appended.get("record_length")
            if (
                not isinstance(append_tail_bytes, int)
                or isinstance(append_tail_bytes, bool)
                or append_tail_bytes < 1
                or append_tail_bytes > 1024 * 1024
            ):
                raise PhaseError("inspection.target_mismatch", canonical_result["locator"])
        try:
            authority = HostAuthorityProvider().open_authority(
                resolved_target_root,
                canonical_result["locator"],
                create_parents=False,
            )
            try:
                if appended is not None:
                    stream_observation = authority.observe_record_stream(
                        prefix_length=appended["append_offset"] + append_tail_bytes,
                        segment_offset=appended["append_offset"],
                        segment_length=append_tail_bytes,
                    )
                elif contract.document["operation"]["mechanism"]["id"] == "mechanism.bundle_create_v1":
                    from ..bundle import verify_bundle
                    data, _manifest = verify_bundle(authority.target, state["digest"], run_id=run_id, plan_digest=plan_digest)
                    authority.assert_namespace_binding()
                elif contract.document["operation"]["mechanism"]["id"] == "mechanism.exclusive_create_v2":
                    from ..streaming import FILE_LIMIT, observe_target
                    streamed_state = observe_target(authority, FILE_LIMIT)
                else:
                    maximum_bytes = _MATERIALIZED_TARGET_LIMITS.get(
                        contract.document["operation"]["mechanism"]["id"]
                    )
                    if (
                        maximum_bytes is None
                        or not isinstance(state.get("length"), int)
                        or isinstance(state.get("length"), bool)
                        or state["length"] < 0
                        or state["length"] > maximum_bytes
                    ):
                        raise PhaseError("inspection.target_mismatch", canonical_result["locator"])
                    data = authority.read_bytes(maximum_bytes=maximum_bytes)
                    authority.assert_namespace_binding()
            finally:
                authority.close()
        except (OSError, PhaseError) as exc:
            raise PhaseError("inspection.target_mismatch", canonical_result["locator"]) from exc
        if appended is not None:
            if not receipt["effect_receipts"] or receipt["effect_receipts"][0].get("kind") != "append_record":
                raise PhaseError("inspection.append_evidence_missing")
            effect_receipt = receipt["effect_receipts"][0]
            for key in ("operation_identity", "request_digest", "record_identity", "append_offset", "record_digest", "record_length", "resulting_head"):
                if effect_receipt.get(key) != appended.get(key):
                    raise PhaseError("inspection.append_evidence_mismatch", key)
            offset = appended["append_offset"]
            length = append_tail_bytes
            end = offset + length
            if stream_observation.length < end or stream_observation.segment_digest != appended["record_digest"]:
                raise PhaseError("inspection.target_mismatch", canonical_result["locator"])
            if stream_observation.prefix_head_token != appended["resulting_head"]:
                raise PhaseError("inspection.target_mismatch", canonical_result["locator"])
        elif receipt["effect_receipts"] and receipt["effect_receipts"][0].get("kind") == "append_record":
            raise PhaseError("inspection.append_evidence_missing")
        elif streamed_state is not None:
            if any(streamed_state[key] != state[key] for key in ("exists", "digest", "length")):
                raise PhaseError("inspection.target_mismatch", canonical_result["locator"])
        elif data is None or state["exists"] is not True or digest_bytes(data) != state["digest"] or len(data) != state["length"]:
            raise PhaseError("inspection.target_mismatch", canonical_result["locator"])
        if receipt["execution_disposition"] == "reused_existing":
            prior_digest = receipt.get("prior_verified_receipt_digest")
            if not isinstance(prior_digest, str):
                raise PhaseError("inspection.prior_receipt_missing")
            prior_run_id = _prior_receipt_run_id(root / ".phase" / "runs", run_id, prior_digest)
            prior = inspect_run(
                root,
                prior_run_id,
                registry,
                root_bindings=root_bindings,
                _visited_receipts=_visited_receipts | {receipt_digest},
            )
            if prior.get("terminal_status") != "succeeded_verified" or prior.get("target_verified") is not True or prior.get("contract") != receipt["contract"]:
                raise PhaseError("inspection.prior_receipt_mismatch", prior_run_id)
            if prior.get("implementation_binding") != receipt.get("implementation_binding"):
                raise PhaseError("inspection.implementation_binding_mismatch")
            contract_result = prior.get("contract_result")
        else:
            hook = load_contract_hook(contract)
            if hook is not None:
                setattr(hook, "_registry", registry)
                hook_roots = _resolved_hook_roots(contract, root_bindings or {})
                try:
                    if data is None:
                        if not hasattr(hook, "inspect_stream_result"):
                            raise PhaseError("contract.hook_invalid")
                        contract_result = hook.inspect_stream_result(
                            stream_observation,
                            state["digest"],
                            target_root,
                            receipt_digest,
                            registry,
                            evidence_root=root,
                        )
                    else:
                        contract_result = hook.inspect_result(
                            data,
                            state["digest"],
                            target_root,
                            receipt_digest,
                            registry,
                            evidence_root=root,
                        )
                    if hasattr(hook, "inspect_receipt_result"):
                        receipt_result = hook.inspect_receipt_result(
                            receipt,
                            plan,
                            target_root,
                            registry,
                            root,
                            root_bindings=hook_roots,
                        )
                        if isinstance(contract_result, dict) and isinstance(receipt_result, dict):
                            contract_result = dict(contract_result) | receipt_result
                        else:
                            contract_result = receipt_result
                except OSError as exc:
                    raise PhaseError("inspection.target_unavailable") from exc
        target_verified = True
    result = {
        "run_id": run_id,
        "terminal_status": receipt["terminal_status"],
        "execution_disposition": receipt["execution_disposition"],
        "mutation_attempted": receipt["mutation_attempted"],
        "result_state": receipt["result_state"],
        "intent_digest": intent_digest,
        "effect_plan_digest": plan_digest,
        "receipt_digest": receipt_digest,
        "contract": receipt["contract"],
        "canonical_profile": "phase-canonical-json-v1",
        "target_verified": target_verified,
        "receipt_present": True,
        "intent_present": intent is not None,
        "inspection_required": False,
        "implementation_binding": receipt.get("implementation_binding"),
    }
    if state_classification is not None:
        result["state_classification"] = state_classification
    if contract_result is not None:
        result["contract_result"] = contract_result
    return result
