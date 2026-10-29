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
from ..preconditions import pre_validator_binding_required, verify_pre_validator_binding
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


def _verify_native_bundle_projection(contract,receipt,run_id,authority,observation,locator):
    """Bind a fresh bundle sample to its original owner and manifest lineage.

    Reuse already verifies its original receipt recursively. Its current run ID
    is not the directory owner's creation ID and must never replace that ID.
    """
    if receipt['execution_disposition']=='reused_existing':return
    from ..mutation.ntfs.bundle_execution import (
        _BUNDLE1_CONTRACT,_BUNDLE2_CONTRACT,validate_bundle_observation)
    exact={'id':contract.document['identity']['id'],'version':contract.document['identity']['version'],
        'package_digest':contract.package_digest}
    if exact not in (_BUNDLE1_CONTRACT,_BUNDLE2_CONTRACT):
        raise PhaseError('inspection.native_binding_mismatch')
    projection=authority.read_binding.read(run_id=run_id,intent_digest=receipt['evidence']['intent_digest'])
    validate_bundle_observation(observation,authority._manifest['root_grants'][0],locator,projection=projection)


def _verify_bound_pre_validators(run_root: Path, intent: Mapping[str, Any]) -> None:
    if not pre_validator_binding_required(intent):
        return
    # Planning saves the same pre-operation results at the final-results name;
    # execution saves them separately before handoff. Neither depends on the
    # presence or truth of a later receipt.
    name = "pre-validator-results.json" if intent["execution_requested"] else "validator-results.json"
    _validators, digest = _read_canonical(run_root / "attachments" / name)
    verify_pre_validator_binding(intent, digest)


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
        streamed = plan is not None and plan["mechanism"]["id"] in {MECHANISM_ID, "mechanism.bundle_create_v1", "mechanism.bundle_create_v2"}
        maximum_bytes = REQUEST_LIMIT if plan is not None and plan["mechanism"]["id"] in {"mechanism.bundle_create_v1", "mechanism.bundle_create_v2"} else FILE_LIMIT
        actual = hash_file(blob, maximum_bytes)[0] if streamed and evidence_file_exists(blob) else (digest_bytes(read_evidence_bytes(blob)) if evidence_file_exists(blob) else None)
        if actual != digest:
            raise PhaseError("inspection.digest_mismatch", blob.name)
    evidence = intent.get("evidence", {})
    for digest in evidence.get("content_blob_digests", []):
        blob = run_root / "blobs" / digest.split(":", 1)[1]
        from ..streaming import FILE_LIMIT, REQUEST_LIMIT, MECHANISM_ID, hash_file
        streamed = plan is not None and plan["mechanism"]["id"] in {MECHANISM_ID, "mechanism.bundle_create_v1", "mechanism.bundle_create_v2"}
        maximum_bytes = REQUEST_LIMIT if plan is not None and plan["mechanism"]["id"] in {"mechanism.bundle_create_v1", "mechanism.bundle_create_v2"} else FILE_LIMIT
        actual = hash_file(blob, maximum_bytes)[0] if streamed and evidence_file_exists(blob) else (digest_bytes(read_evidence_bytes(blob)) if evidence_file_exists(blob) else None)
        if actual != digest:
            raise PhaseError("inspection.digest_mismatch", blob.name)
    if plan is not None and plan["mechanism"]["id"] in {"mechanism.bundle_create_v1", "mechanism.bundle_create_v2"}:
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
    *, _native_authority=None,
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
        from ..mutation.ntfs.experimental_file1 import _experimental_admission
        admission = (None if _native_authority is None else
            _experimental_admission(_native_authority.read_binding))
        if admission is None:
            verify_guarantee_coverage(requirements, mechanisms, profile_binding, registry)
        else:
            admission.assess(_native_authority.read_binding, requirements, mechanisms)


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
    *, _native_authority: object | None = None,
) -> str | None:
    try:
        if _native_authority is None:
            validate_static_plan(plan, contract, root_bindings, registry)
        else:
            _native_authority.require_contract(contract)
            _native_authority.require_request_roots(root_bindings,
                Path(parse_json_bytes(_native_authority.read_binding.manifest_bytes)['evidence_root']))
            from ..planning import _validate_logical_plan
            _validate_logical_plan(plan,contract,registry)
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
    *, _native_authority: object | None = None,
) -> dict[str, Path]:
    if _native_authority is not None:
        _native_authority.require_contract(contract)
        _native_authority.require_request_roots(root_bindings,
            Path(parse_json_bytes(_native_authority.read_binding.manifest_bytes)['evidence_root']))
        return dict(root_bindings)  # Opaque lexical projections, never POSIX target roots.
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


def _check_native_intent_binding(intent, contract, authority):
    """Static exact-installation linkage before any contract hook/target path."""
    if authority is None:
        if intent.get('phase_intent_version') == '1.2':
            raise PhaseError('inspection.native_installation_required')
        return
    authority.require_contract(contract)
    if intent.get('phase_intent_version') != '1.2':
        raise PhaseError('ntfs.original_native_intent_required')
    expected = authority.read_binding._parser_bindings(intent)
    fields = {'installed_core_binding': intent['core'],
        'installed_native_binding': intent['native_binding'],
        'installed_root_grants': intent['idempotency']['root_identities'],
        'installed_implementation_binding': intent['implementation_binding']}
    if any(expected[key] != canonical_bytes(value) for key, value in fields.items()):
        raise PhaseError('ntfs.original_installation_binding_mismatch')


def _validate_capture_expectations(candidate_digest, frozen_input) -> None:
    """Private assertions contain immutable values, never paths or selectors."""
    import re

    def digest(value):
        return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None

    if candidate_digest is None:
        if frozen_input is not None:
            raise PhaseError("inspection.invalid_capture_expectation")
        return
    if not digest(candidate_digest):
        raise PhaseError("inspection.invalid_capture_expectation")
    if frozen_input is not None and not (
        type(frozen_input) is tuple and len(frozen_input) == 2
        and type(frozen_input[0]) is str and 0 < len(frozen_input[0]) <= 128
        and "\x00" not in frozen_input[0] and digest(frozen_input[1])
    ):
        raise PhaseError("inspection.invalid_capture_expectation")


def _verify_expected_capture(intent, candidate_digest, frozen_input) -> None:
    """Compare canonical captured VALUE, after ordinary leaf evidence checks.

    This supplies no contract grammar, code authentication or new evidence.
    Candidate formatting and its original source path are not asserted.
    """
    candidate = intent.get("candidate") if intent is not None else None
    storage = candidate.get("storage") if isinstance(candidate, Mapping) else None
    if (not isinstance(storage, Mapping) or set(storage) != {"mode", "value", "attachment_digest"}
        or candidate.get("input_mode") != "structured_json" or storage["mode"] != "inline"
        or storage["attachment_digest"] is not None):
        raise PhaseError("inspection.captured_request_unavailable")
    value = storage["value"]
    actual = profile_digest("candidate", value)
    if (candidate.get("digest") != actual or actual != candidate_digest
        or type(candidate.get("length")) is not int
        or candidate["length"] != len(canonical_bytes(value))):
        raise PhaseError("inspection.captured_candidate_mismatch")
    if frozen_input is not None:
        binding, expected = frozen_input
        matches = [item for item in intent["inputs"] if item["binding_id"] == binding]
        if (len(matches) != 1 or matches[0].get("digest") != expected
            or matches[0].get("blob_digest") != expected):
            raise PhaseError("inspection.captured_input_mismatch", binding)


def inspect_run(
    evidence_root: Path,
    run_id: str,
    registry: RegistrySnapshot | None = None,
    *,
    root_bindings: Mapping[str, Path] | None = None,
    _visited_receipts: frozenset[str] = frozenset(),
    _native_authority: object | None = None,
    _expected_candidate_digest: str | None = None,
    _expected_frozen_input: tuple[str, str] | None = None,
    _include_canonical_result: bool = False,
) -> dict[str, Any]:
    """Verify evidence and, for observed results, re-read installation-bound target bytes."""
    if type(_include_canonical_result) is not bool:
        raise PhaseError("inspection.invalid_result_projection")
    _validate_capture_expectations(_expected_candidate_digest, _expected_frozen_input)
    capture_expectations = ({} if _expected_candidate_digest is None else {
        "_expected_candidate_digest": _expected_candidate_digest,
        "_expected_frozen_input": _expected_frozen_input,
    })
    validate_run_id(run_id)
    registry = registry or BundledRegistry.load()
    if _native_authority is not None:
        from ..mutation.ntfs.experimental_file1 import _is_native_authority
        if not _is_native_authority(_native_authority) or _native_authority.registry is not registry:
            raise PhaseError("ntfs.closed_native_installation_required")
        _native_authority._usable()
        _native_authority.require_request_roots(root_bindings or {}, evidence_root)
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
    if (_native_authority is None and evidence_file_exists(
            run_root / 'attachments' / 'native-terminal-proof.json')):
        # A pre-intent rejection may have no profile/implementation binding.
        # Native provenance is still present; never accept it through Host I/O.
        raise PhaseError('inspection.native_installation_required')
    receipt_path = run_root / "receipt.json"
    if not evidence_file_exists(receipt_path):
        intent, _ = _read_canonical(run_root / "intent.json")
        intent_digest = profile_digest("intent", intent)
        validate_intent(intent, registry)
        if intent.get('phase_intent_version') == '1.2' and _native_authority is None:
            raise PhaseError('inspection.native_installation_required')
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
        _check_native_intent_binding(intent, contract, _native_authority)
        validate_plan_mechanism_authorization(plan, contract, registry)
        implementation_binding = intent.get("implementation_binding")
        if implementation_binding is None and _implementation_binding_required(contract, registry):
            raise PhaseError("inspection.implementation_binding_missing")
        if implementation_binding is not None:
            if not isinstance(implementation_binding, Mapping):
                raise PhaseError("inspection.implementation_binding_mismatch")
            _validate_implementation_binding(implementation_binding, plan, contract, registry, _native_authority=_native_authority)
        _verify_bound_pre_validators(run_root, intent)
        _verify_intent_blobs(run_root, intent, plan)
        state_classification = None
        hook = load_contract_hook(contract,**({} if _native_authority is None else {'_native_authority':_native_authority}))
        if hook is not None and hasattr(hook, "inspect_missing_receipt_result"):
            state_classification = _inspect_missing_receipt_state(
                hook,
                plan,
                contract,
                root_bindings or {},
                registry,
                **({} if _native_authority is None else {'_native_authority':_native_authority}),
            )
        from .recovered import inspect_missing_recovery
        recovery = ({'inspection_status': 'indeterminate',
            'inspection_error': 'inspection.original_receipt_unconfirmed',
            'inspection_required': True, 'recorded_recovery_mutation_attempted': None,
            'recovery_observations': []} if _native_authority is not None else
            inspect_missing_recovery(registry, root, run_root, intent, plan, root_bindings or {}))
        if _native_authority is not None:
            _native_authority._usable()  # Whole-read root/profile identity recheck.
        if capture_expectations:
            raise PhaseError("inspection.captured_request_unavailable")
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
            **recovery,
        }
    receipt, _ = _read_canonical(receipt_path)
    receipt_digest = profile_digest("receipt", receipt)
    if receipt_digest in _visited_receipts:
        raise PhaseError("inspection.prior_receipt_cycle", receipt_digest)
    validate_receipt(receipt, registry)
    native_proof = None
    if _native_authority is not None:
        from ..mutation.ntfs.proof import verify_native_terminal_proof
        # Read-only verification only. This never fsyncs, retries target effects
        # or discharges the original barrier; successor confirmation is separate.
        native_proof = verify_native_terminal_proof(_native_authority.read_binding, run_root, receipt)
    else:
        implementation = receipt.get('implementation_binding')
        authority_binding = implementation.get('authority') if isinstance(implementation, Mapping) else None
        profile = authority_binding.get('profile') if isinstance(authority_binding, Mapping) else None
        if isinstance(profile, Mapping) and profile.get('id') == 'phase.native.ntfs.authority.v1':
            raise PhaseError('inspection.native_installation_required')
    intent = None
    intent_digest = None
    plan = None
    plan_digest = None
    native_target_identity = None
    target_verified: bool | None = None
    contract_result: Any | None = None
    state_classification: str | None = None
    if receipt["evidence"]["intent_digest"] is not None:
        intent, _ = _read_canonical(run_root / "intent.json")
        intent_digest = profile_digest("intent", intent)
        validate_intent(intent, registry)
        if intent.get('phase_intent_version') == '1.2' and _native_authority is None:
            raise PhaseError('inspection.native_installation_required')
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
        _check_native_intent_binding(intent, contract_for_plan, _native_authority)
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
            _validate_implementation_binding(intent_binding, plan, contract_for_plan, registry, _native_authority=_native_authority)
        _verify_bound_pre_validators(run_root, intent)
        validators, validators_digest = _read_canonical(run_root / "attachments" / "validator-results.json")
        if validators != receipt["validator_results"]:
            raise PhaseError("inspection.validator_results_mismatch")
        attachment_digests = {plan_attachment_digest, validators_digest}
        claimed = set(receipt["evidence"]["attachment_digests"])
        if _native_authority is not None:
            from ..mutation.ntfs.experimental_file1 import _experimental_admission
            admission = _experimental_admission(_native_authority.read_binding)
            if admission is not None:
                admission.verify_attachment(_native_authority.read_binding, run_id, receipt)
                attachment_digests.add(admission.digest)
        effect_receipts = receipt["effect_receipts"]
        unknown_dispatch_without_receipts = (
            not effect_receipts
            and receipt["terminal_status"] == "indeterminate"
            and receipt["execution_disposition"] == "executed"
            and receipt["mutation_attempted"] is True
            and receipt["recovery_required"] is True
            and receipt["retry_disposition"] == "forbidden"
            and "broker.dispatch_outcome_unknown" in receipt["blockers"]
        )
        if effect_receipts or unknown_dispatch_without_receipts:
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
        if native_proof is not None:
            attachment_digests.add(native_proof["attachment_digest"])
        if attachment_digests != claimed:
            raise PhaseError("inspection.attachment_set_mismatch")
        _verify_intent_blobs(run_root, intent, plan)
        hook_for_plan = load_contract_hook(contract_for_plan,
            **({} if _native_authority is None else {'_native_authority':_native_authority}))
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
                **({} if _native_authority is None else {'_native_authority':_native_authority}),
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
        if _native_authority is not None:
            _native_authority.require_contract(contract)
            resolved_target_root = None  # No target-path resolution through Linux.
        else:
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
            if _native_authority is not None:
                if appended is not None or native_proof is None:
                    raise PhaseError('inspection.native_binding_mismatch')
                if contract.document['identity']['id'] in {'publish_new_version.v1','publish_new_version.v2'}:
                    version2=contract.document['identity']['id']=='publish_new_version.v2'
                    targets = native_proof['target_identity']
                    if receipt['execution_disposition'] != 'reused_existing' and (
                            type(targets) is not dict or set(targets) !=
                            ({'current','old_object','new_object'} if version2 else {'current','archive'})):
                        raise PhaseError('inspection.native_identity_mismatch')
                    observe=(_native_authority.observe_version2_advisory if version2 else _native_authority.observe_advisory)
                    observation = observe(root_binding=root_id,
                        locator=canonical_result['locator'],expected_identity=None if targets is None else targets['current'])
                else:
                    observation = _native_authority.observe(run_id=run_id, root_binding=root_id,
                        locator=canonical_result['locator'], expected_identity=native_proof['target_identity'])
                if contract.document['identity']['id'] in {'bundle_create.v1','bundle_create.v2'}:
                    _verify_native_bundle_projection(contract,receipt,run_id,_native_authority,
                        observation,canonical_result['locator'])
                streamed_state = observation['state']
                native_target_identity = observation['native']['native_identity']
            else:
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
                    elif contract.document["operation"]["mechanism"]["id"] in {"mechanism.bundle_create_v1", "mechanism.bundle_create_v2"}:
                        from ..bundle import verify_bundle
                        data, _manifest = verify_bundle(authority.target, state["digest"], run_id=run_id, plan_digest=plan_digest)
                        from ..prepared_binding import verify_bound_bundle_target
                        verify_bound_bundle_target(registry, contract, intent, plan, run_root, authority.target)
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
                **capture_expectations,
                **({} if _native_authority is None else {"_native_authority": _native_authority}),
            )
            if prior.get("terminal_status") != "succeeded_verified" or prior.get("target_verified") is not True or prior.get("contract") != receipt["contract"]:
                raise PhaseError("inspection.prior_receipt_mismatch", prior_run_id)
            if prior.get("implementation_binding") != receipt.get("implementation_binding"):
                raise PhaseError("inspection.implementation_binding_mismatch")
            if _native_authority is not None:
                if (prior.get('native_target_identity') is None
                    or native_target_identity != prior['native_target_identity']):
                    raise PhaseError('inspection.native_identity_mismatch')
            contract_result = prior.get("contract_result")
        else:
            native_context = {} if _native_authority is None else {'_native_authority':_native_authority}
            if (_native_authority is not None and contract.document['identity']['id'] in
                    {'publish_new_version.v1','publish_new_version.v2'}):
                if native_proof is None or native_proof['target_identity'] is None:
                    raise PhaseError('inspection.native_identity_mismatch')
                native_context['_native_expected_targets'] = canonical_bytes(native_proof['target_identity'])
            hook = load_contract_hook(contract,**native_context)
            if hook is not None:
                setattr(hook, "_registry", registry)
                hook_roots = _resolved_hook_roots(contract, root_bindings or {},
                    **({} if _native_authority is None else {'_native_authority':_native_authority}))
                try:
                    if _native_authority is not None:
                        if not hasattr(hook,'inspect_native_result'):
                            raise PhaseError('contract.hook_invalid')
                        contract_result = hook.inspect_native_result(receipt,plan,target_root,registry,root,
                            root_bindings=hook_roots)
                    else:
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
    if capture_expectations:
        if (target_verified is not True or receipt["terminal_status"] != "succeeded_verified"
            or receipt["evidence"]["finalization_status"] != "finalized"
            or receipt["execution_disposition"] not in {"executed", "reused_existing"}):
            raise PhaseError("inspection.captured_request_unavailable")
        if receipt["execution_disposition"] != "reused_existing":
            _verify_expected_capture(intent, _expected_candidate_digest, _expected_frozen_input)
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
    if _native_authority is not None:
        _native_authority._usable()
        result['native_target_identity'] = native_target_identity
    # Detached CURRENT receipt reference only. Its target digest/length were
    # checked above; owner/head/timestamp metadata keeps its historical meaning.
    # Do not pass this opt-in through recursion or replace CURRENT with prior.
    if (_include_canonical_result and canonical_result is not None
        and target_verified is True and receipt["terminal_status"] == "succeeded_verified"
        and receipt["evidence"]["finalization_status"] == "finalized"
        and receipt["execution_disposition"] in {"executed", "reused_existing"}):
        result["canonical_result"] = parse_json_bytes(canonical_bytes(canonical_result))
    return result
