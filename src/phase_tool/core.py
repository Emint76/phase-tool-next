from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from jsonschema.exceptions import ValidationError

from . import __version__
from .candidate import CapturedCandidate, capture_structured, normalize_captured_structured
from .canonical import digest_bytes, parse_json_bytes, profile_digest
from .contracts import load_contract_hook
from .errors import PhaseError
from .evidence import EvidenceStore, evidence_file_exists, iter_run_artifacts, operational_lock_path, read_evidence_bytes, validate_intent, validate_receipt
from .freeze import FrozenInput, freeze_declared_inputs
from .inspection import inspect_run
from .installation import Installation, host_installation
from .mutation import BrokerFaults, EffectBroker
from .mutation.broker import ordered_progress_document, validate_broker_faults
from .mutation.authority import GuaranteeProfileProvider
from .mutation.guarantees import verify_guarantee_coverage
from .mutation.implementation import mechanism_authority_usage
from .mutation.platform import HostAuthorityProvider
from .planning import build_idempotency_digests, build_static_plan, validate_static_plan
from .registry import BundledRegistry, RegistrySnapshot, ResolvedContract
from .validation import ValidatorRunner

CORE_BINDING = {
    "id": "phase.core",
    "version": __version__,
    "package_digest": profile_digest("core-package", {"id": "phase.core", "version": __version__, "capability": "effect_broker_v1"}),
}


class _OperationalFileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream = None

    def __enter__(self) -> "_OperationalFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("a+b")
        if os.name == "nt":
            import msvcrt

            self._stream.seek(0)
            msvcrt.locking(self._stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(self._stream.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *_exc: object) -> None:
        assert self._stream is not None
        if os.name == "nt":
            import msvcrt

            self._stream.seek(0)
            msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        self._stream.close()


@dataclass(frozen=True)
class PhaseRequest:
    contract_id: str
    contract_version: str
    contract_digest: str
    candidate_path: Path
    evidence_root: Path
    run_id: str
    input_paths: Mapping[str, Path]
    root_bindings: Mapping[str, Path]
    timestamp: str | None = None
    maximum_candidate_bytes: int = 1_048_576


@dataclass(frozen=True)
class CoreFaults:
    broker: BrokerFaults | None = None
    fail_receipt_write: bool = False


def _validated_core_faults(value: object) -> CoreFaults:
    if type(value) is not CoreFaults:
        raise PhaseError("broker.invalid_fault_configuration")
    if type(value.fail_receipt_write) is not bool:
        raise PhaseError("broker.invalid_fault_configuration")
    broker = None if value.broker is None else validate_broker_faults(value.broker)
    return CoreFaults(broker=broker, fail_receipt_write=value.fail_receipt_write)


@dataclass(frozen=True)
class PhaseOutcome:
    run_id: str
    exit_code: int
    receipt: dict[str, Any]
    intent: dict[str, Any] | None
    effect_plan: dict[str, Any] | None
    lifecycle: tuple[str, ...]
    receipt_digest: str | None
    effect_plan_digest: str | None


class PhaseCore:
    """One lifecycle coordinator; canonical target writes belong only to EffectBroker."""

    def __init__(
        self,
        registry: RegistrySnapshot | None = None,
        installation: Installation | None = None,
    ) -> None:
        self.registry = registry or BundledRegistry.load()
        self.installation = installation or host_installation()

    @staticmethod
    def _timestamp(request: PhaseRequest) -> str:
        return request.timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _check_root_separation(request: PhaseRequest) -> Path:
        evidence = Path(request.evidence_root).resolve(strict=False)
        for name, root_value in request.root_bindings.items():
            root = Path(root_value).resolve(strict=False)
            try:
                evidence.relative_to(root)
            except ValueError:
                pass
            else:
                raise PhaseError("evidence.overlaps_target_root", name)
            try:
                root.relative_to(evidence)
            except ValueError:
                pass
            else:
                raise PhaseError("evidence.overlaps_target_root", name)
        return evidence

    @staticmethod
    def _requested_binding(request: PhaseRequest) -> dict[str, str]:
        return {"id": request.contract_id, "version": request.contract_version, "package_digest": request.contract_digest}

    @staticmethod
    def _check_idempotency(
        store: EvidenceStore,
        contract: ResolvedContract,
        registry: RegistrySnapshot,
        key: str | None,
        scope_digest: str,
        request_digest: str,
        root_bindings: Mapping[str, Path],
        *,
        execute: bool,
    ) -> tuple[dict[str, Any], str] | None:
        if key is None:
            return None
        runs_root = store.evidence_root / ".phase" / "runs"
        for path in iter_run_artifacts(runs_root, "intent.json"):
            if path.parent == store.run_root:
                continue
            try:
                intent = parse_json_bytes(read_evidence_bytes(path))
                validate_intent(intent, registry)
            except (PhaseError, ValidationError, OSError) as exc:
                raise PhaseError("idempotency.prior_inspection_required", path.parent.name) from exc
            prior = intent.get("idempotency", {})
            if prior.get("key") == key and prior.get("scope_digest") == scope_digest and prior.get("request_digest") != request_digest:
                raise PhaseError("idempotency.same_key_conflict", key)
            if prior.get("key") == key and prior.get("scope_digest") == scope_digest and prior.get("request_digest") == request_digest:
                if not execute:
                    continue
                receipt_path = path.parent / "receipt.json"
                if not evidence_file_exists(receipt_path):
                    if intent.get("execution_requested") is False:
                        continue
                    try:
                        inspected = inspect_run(store.evidence_root, path.parent.name, registry, root_bindings=root_bindings)
                    except (PhaseError, ValidationError) as exc:
                        raise PhaseError("idempotency.prior_inspection_required", str(exc)) from exc
                    if inspected.get("state_classification") in {"no_effect_observed", "archived_not_published", "published_not_finalized"}:
                        continue
                    raise PhaseError("idempotency.prior_inspection_required", path.parent.name)
                receipt = parse_json_bytes(read_evidence_bytes(receipt_path))
                if receipt.get("terminal_status") == "validated_planned":
                    continue
                if receipt.get("terminal_status") != "succeeded_verified":
                    try:
                        inspected = inspect_run(store.evidence_root, path.parent.name, registry, root_bindings=root_bindings)
                    except (PhaseError, ValidationError) as exc:
                        raise PhaseError("idempotency.prior_inspection_required", str(exc)) from exc
                    if inspected.get("state_classification") in {"no_effect_observed", "archived_not_published", "published_not_finalized"}:
                        continue
                    raise PhaseError("idempotency.prior_inspection_required", path.parent.name)
                if receipt.get("evidence", {}).get("finalization_status") != "finalized":
                    raise PhaseError("idempotency.prior_inspection_required", path.parent.name)
                try:
                    inspected = inspect_run(store.evidence_root, path.parent.name, root_bindings=root_bindings)
                except (PhaseError, ValidationError) as exc:
                    raise PhaseError("idempotency.prior_result_changed", str(exc)) from exc
                if inspected.get("target_verified") is not True:
                    raise PhaseError("idempotency.prior_result_changed", path.parent.name)
                return receipt, profile_digest("receipt", receipt)
        return None

    def _intent(
        self,
        request: PhaseRequest,
        contract: ResolvedContract,
        candidate: CapturedCandidate,
        frozen: Mapping[str, FrozenInput],
        plan: dict[str, Any],
        timestamp: str,
        scope_digest: str,
        request_digest: str,
        key: str | None,
        root_identity_digest: str,
        root_identities: list[dict[str, object]],
        effect_plan_attachment_digest: str,
        content_blob_digests: list[str],
        execution_requested: bool,
    ) -> dict[str, Any]:
        implementation_binding = self._implementation_binding(plan)
        return {
            "phase_intent_version": "1.0",
            "run_id": request.run_id,
            "created_at": timestamp,
            "core": CORE_BINDING,
            "registry_snapshot_digest": contract.registry_snapshot_digest,
            "contract": self._requested_binding(request),
            "candidate": {
                "input_mode": candidate.input_mode,
                "digest": candidate.digest,
                "length": candidate.length,
                "storage": {"mode": "inline", "value": parse_json_bytes(candidate.canonical_bytes), "attachment_digest": None},
            },
            "inputs": [item.intent_record() for _, item in sorted(frozen.items())],
            "write_scope_digest": plan["write_scope_digest"],
            "operation": {"intent": contract.document["operation"]["intent"], "mechanism": plan["mechanism"]},
            "idempotency": {
                "key": key,
                "scope_digest": scope_digest,
                "request_digest": request_digest,
                "root_identity_digest": root_identity_digest,
                "root_identities": root_identities,
            },
            "effect_plan_digest": profile_digest("effect-plan", plan),
            "implementation_binding": implementation_binding,
            "execution_requested": execution_requested,
            "evidence": {
                "effect_plan_attachment_digest": effect_plan_attachment_digest,
                "content_blob_digests": sorted(content_blob_digests),
            },
            "status": "intent_recorded",
        }

    def _implementation_binding(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        mechanism = dict(plan["mechanism"])
        effect_plan_digest = profile_digest("effect-plan", plan)
        if mechanism_authority_usage(mechanism) == "mechanism_managed":
            authority = {"usage": "mechanism_managed", "profile": None, "provider": None}
        else:
            provider = self.installation.authority_provider
            if type(provider) is not HostAuthorityProvider or not isinstance(provider, GuaranteeProfileProvider):
                raise PhaseError("authority.guarantee_profile_unavailable")
            profile = self.installation.authority_profile_binding
            if profile is None:
                raise PhaseError("authority.guarantee_profile_unavailable")
            if provider.guarantee_profile_binding() != profile:
                raise PhaseError("guarantee.profile_provider_disagreement")
            authority = {
                "usage": "provider_backed",
                "profile": profile.as_dict(),
                "provider": {
                    "id": profile.implementation_id,
                    "version": profile.implementation_version,
                    "artifact_digest": profile.implementation_artifact_digest,
                },
            }
        return {
            "authority": authority,
            "mechanism": mechanism,
            "effect_plan_digest": effect_plan_digest,
        }

    def _verify_contract_guarantees(
        self,
        contract: ResolvedContract,
        root_bindings: Mapping[str, Path],
    ) -> dict[str, Any]:
        requirements = contract.document["operation"].get("required_guarantees")
        if not isinstance(requirements, Mapping):
            raise PhaseError("contract.guarantee_requirements_missing")
        mechanisms = [contract.document["operation"]["mechanism"]]
        mechanisms.extend(contract.document["operation"].get("effect_mechanisms", []))
        required_roots = {
            str(root["binding_id"])
            for root in contract.document["write_scope"]["roots"]
            if root["access"] == "write"
        }
        missing_roots = sorted(required_roots - set(root_bindings))
        if missing_roots:
            raise PhaseError(
                "guarantee.profile_scope_unsupported",
                details={"missing_root_bindings": missing_roots},
            )
        self.installation.qualify_authority_roots(
            {binding_id: root_bindings[binding_id] for binding_id in sorted(required_roots)}
        )
        if not any(mechanism_authority_usage(item) == "provider_backed" for item in mechanisms):
            return verify_guarantee_coverage(requirements, mechanisms, None, self.registry)
        provider = self.installation.authority_provider
        if type(provider) is not HostAuthorityProvider or not isinstance(provider, GuaranteeProfileProvider):
            raise PhaseError("authority.guarantee_profile_unavailable")
        selected_profile = self.installation.authority_profile_binding
        if selected_profile is None:
            raise PhaseError("authority.guarantee_profile_unavailable")
        if provider.guarantee_profile_binding() != selected_profile:
            raise PhaseError("guarantee.profile_provider_disagreement")
        return verify_guarantee_coverage(requirements, mechanisms, selected_profile, self.registry)

    def _verify_plan_guarantees(
        self,
        required_guarantees: Mapping[str, Any],
        plan: Mapping[str, Any],
    ) -> None:
        mechanisms_by_key: dict[tuple[str, str, str], Mapping[str, Any]] = {}
        plan_mechanism = plan["mechanism"]
        for mechanism in [plan_mechanism, *(effect.get("mechanism", plan_mechanism) for effect in plan["effects"])]:
            key = (mechanism["id"], mechanism["version"], mechanism["package_digest"])
            mechanisms_by_key[key] = mechanism
        selected_requirements = {
            "vocabulary": required_guarantees["vocabulary"],
            "mechanisms": [
                item
                for item in required_guarantees["mechanisms"]
                if (
                    item["mechanism"]["id"],
                    item["mechanism"]["version"],
                    item["mechanism"]["package_digest"],
                )
                in mechanisms_by_key
            ],
        }
        verify_guarantee_coverage(
            selected_requirements,
            list(mechanisms_by_key.values()),
            self.installation.authority_profile_binding,
            self.registry,
        )

    @staticmethod
    def _publish_append_blobs(store: EvidenceStore, plan: dict[str, Any]) -> list[str]:
        blob_digests: list[str] = []
        for effect in plan["effects"]:
            if effect.get("content_blob_digest") is None:
                continue
            encoded = effect.get("content_bytes_b64")
            if not isinstance(encoded, str):
                raise PhaseError("plan.content_inline_missing", str(effect["effect_id"]))
            try:
                content = base64.b64decode(encoded.encode("ascii"), validate=True)
            except ValueError as exc:
                raise PhaseError("plan.content_inline_invalid", str(effect["effect_id"])) from exc
            digest = digest_bytes(content)
            if digest != effect["content_digest"] or len(content) != effect["content_length"]:
                raise PhaseError("plan.content_binding_mismatch", str(effect["effect_id"]))
            if effect.get("content_blob_digest") != digest:
                raise PhaseError("plan.content_blob_digest_mismatch", str(effect["effect_id"]))
            store.write_blob_exact(digest, content)
            blob_digests.append(digest)
        return blob_digests

    @staticmethod
    def _ordered_progress(plan: Mapping[str, Any], effect_receipts: list[dict[str, Any]]) -> dict[str, Any]:
        return ordered_progress_document(plan, effect_receipts)

    def _base_receipt(
        self,
        request: PhaseRequest,
        validator_results: list[dict[str, Any]],
        timestamp: str,
    ) -> dict[str, Any]:
        return {
            "phase_receipt_version": "1.0",
            "run_id": request.run_id,
            "contract": self._requested_binding(request),
            "core": CORE_BINDING,
            "started_at": timestamp,
            "finished_at": timestamp,
            "validator_results": validator_results,
            "prior_verified_receipt_digest": None,
        }

    def _planned_receipt(
        self,
        request: PhaseRequest,
        validator_results: list[dict[str, Any]],
        timestamp: str,
        intent_digest: str,
        attachment_digests: list[str],
        implementation_binding: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self._base_receipt(request, validator_results, timestamp) | {
            "terminal_status": "validated_planned",
            "execution_disposition": "not_executed",
            "mutation_attempted": False,
            "result_state": "planned_no_effect",
            "canonical_result": None,
            "effect_receipts": [],
            "implementation_binding": dict(implementation_binding),
            "evidence": {
                "finalization_status": "finalized",
                "intent_digest": intent_digest,
                "receipt_digest_policy_id": "digest.phase_canonical_json_v1",
                "required_attachments_present": True,
                "attachment_digests": sorted(attachment_digests),
            },
            "retry_disposition": "safe_idempotent_retry",
            "recovery_required": False,
            "blockers": [],
            "exit_code": 0,
        }

    def _reused_receipt(
        self,
        request: PhaseRequest,
        validator_results: list[dict[str, Any]],
        timestamp: str,
        prior_receipt: Mapping[str, Any],
        prior_receipt_digest: str,
    ) -> dict[str, Any]:
        reused_validators = validator_results or [
            dict(item) | {"run_id": request.run_id, "started_at": timestamp, "finished_at": timestamp}
            for item in prior_receipt["validator_results"]
        ]
        return self._base_receipt(request, reused_validators, timestamp) | {
            "terminal_status": "succeeded_verified",
            "execution_disposition": "reused_existing",
            "mutation_attempted": False,
            "result_state": "verified_result",
            "canonical_result": prior_receipt["canonical_result"],
            "effect_receipts": [],
            "implementation_binding": prior_receipt.get("implementation_binding"),
            "evidence": {
                "finalization_status": "finalized",
                "intent_digest": None,
                "receipt_digest_policy_id": "digest.phase_canonical_json_v1",
                "required_attachments_present": True,
                "attachment_digests": [],
            },
            "retry_disposition": "noop_existing",
            "recovery_required": False,
            "blockers": [],
            "exit_code": 0,
            "prior_verified_receipt_digest": prior_receipt_digest,
        }

    def _rejection_receipt(
        self,
        request: PhaseRequest,
        validator_results: list[dict[str, Any]],
        timestamp: str,
        blocker: str,
        *,
        intent_digest: str | None = None,
        attachment_digests: list[str] | None = None,
        implementation_binding: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        blockers = sorted({item for result in validator_results for item in result.get("blockers", [])}) or [blocker]
        receipt = self._base_receipt(request, validator_results, timestamp) | {
            "terminal_status": "rejected",
            "execution_disposition": "not_executed",
            "mutation_attempted": False,
            "result_state": "none",
            "canonical_result": None,
            "effect_receipts": [],
            "evidence": {
                "finalization_status": "finalized",
                "intent_digest": intent_digest,
                "receipt_digest_policy_id": "digest.phase_canonical_json_v1",
                "required_attachments_present": bool(attachment_digests),
                "attachment_digests": sorted(attachment_digests or []),
            },
            "retry_disposition": "forbidden",
            "recovery_required": False,
            "blockers": blockers,
            "exit_code": 10,
        }
        if implementation_binding is not None:
            receipt["implementation_binding"] = dict(implementation_binding)
        return receipt

    @staticmethod
    def _canonical_result(contract: ResolvedContract, effect: Mapping[str, Any], observation: Mapping[str, Any], timestamp: str) -> dict[str, Any] | None:
        if observation.get("known") is not True or observation.get("exists") is not True:
            return None
        result = {
            "reference_version": "1.0",
            "owner_id": contract.document["canonical_result"]["owner_id"],
            "root_binding": effect["target"]["root_binding"],
            "locator": effect["target"]["relative_locator"],
            "contract": {
                "id": contract.document["identity"]["id"],
                "version": contract.document["identity"]["version"],
                "package_digest": contract.package_digest,
            },
            "authority_rule": contract.document["canonical_result"]["authority_rule"],
            "state": {
                "exists": True,
                "digest": observation.get("digest"),
                "length": observation.get("length"),
                "head_token": observation.get("head_token"),
            },
            "observed_at": timestamp,
        }
        appended = {
            "operation_identity": observation.get("operation_identity"),
            "request_digest": observation.get("request_digest"),
            "record_identity": observation.get("record_identity"),
            "append_offset": observation.get("append_offset"),
            "record_digest": observation.get("record_digest"),
            "record_length": observation.get("record_length"),
            "resulting_head": observation.get("resulting_head"),
        }
        if all(value is not None for value in appended.values()):
            result["appended_record"] = appended
        return result

    def _executed_receipt(
        self,
        request: PhaseRequest,
        contract: ResolvedContract,
        plan: Mapping[str, Any],
        validator_results: list[dict[str, Any]],
        effect_receipts: list[dict[str, Any]],
        timestamp: str,
        intent_digest: str,
        attachment_digests: list[str],
        implementation_binding: Mapping[str, Any],
        *,
        finalization_failed: bool,
        required_attachments_present: bool = True,
    ) -> dict[str, Any]:
        result_effect = plan["effects"][-1]
        failed_receipts = [receipt for receipt in effect_receipts if receipt["status"] != "applied_verified"]
        status = failed_receipts[0]["status"] if failed_receipts else ("applied_verified" if len(effect_receipts) == len(plan["effects"]) else "failed_no_effect")
        post_verified = all(
            result["status"] == "pass"
            for result in validator_results
            if result["phase"] == "post_operation" and result["blocking"]
        )
        mapping = {
            "failed_no_effect": ("failed_no_effect", "verified_no_effect", 20, False),
            "failed_partial": ("failed_partial", "known_partial", 30, True),
            "applied_unverified": ("committed_unverified", "committed_unverified", 40, True),
            "indeterminate": ("indeterminate", "indeterminate", 50, True),
        }
        all_effects_verified = status == "applied_verified" and len(effect_receipts) == len(plan["effects"])
        if all_effects_verified and post_verified and not finalization_failed:
            terminal, result_state, exit_code, recovery = "succeeded_verified", "verified_result", 0, False
        elif all_effects_verified:
            terminal, result_state, exit_code, recovery = "committed_unverified", "committed_unverified", 40, True
        else:
            if any(receipt["status"] == "failed_partial" for receipt in effect_receipts):
                terminal, result_state, exit_code, recovery = mapping["failed_partial"]
            elif failed_receipts:
                terminal, result_state, exit_code, recovery = mapping[status]
                if len(effect_receipts) > 1 and any(receipt["after"].get("exists") is True for receipt in effect_receipts[:-1]):
                    terminal, result_state, exit_code, recovery = "failed_partial", "known_partial", 30, True
            elif effect_receipts and any(receipt["status"] == "applied_verified" for receipt in effect_receipts):
                terminal, result_state, exit_code, recovery = "failed_partial", "known_partial", 30, True
            else:
                terminal, result_state, exit_code, recovery = "failed_no_effect", "verified_no_effect", 20, False
        error = failed_receipts[0].get("error") if failed_receipts else None
        blockers = [] if terminal == "succeeded_verified" else [
            "evidence.finalization_failed" if finalization_failed else (error["code"] if error else "verification.incomplete")
        ]
        return self._base_receipt(request, validator_results, timestamp) | {
            "terminal_status": terminal,
            "execution_disposition": "executed",
            "mutation_attempted": any(bool(receipt["attempted"]) for receipt in effect_receipts),
            "result_state": result_state,
            "canonical_result": (
                self._canonical_result(
                    contract,
                    result_effect,
                    dict(effect_receipts[-1]["after"]) | {
                        "operation_identity": effect_receipts[-1].get("operation_identity"),
                        "request_digest": effect_receipts[-1].get("request_digest"),
                        "record_identity": effect_receipts[-1].get("record_identity"),
                        "append_offset": effect_receipts[-1].get("append_offset"),
                        "record_digest": effect_receipts[-1].get("record_digest"),
                        "record_length": effect_receipts[-1].get("record_length"),
                        "resulting_head": effect_receipts[-1].get("resulting_head"),
                    },
                    timestamp,
                )
                if terminal in {"succeeded_verified", "committed_unverified"}
                else None
            ),
            "effect_receipts": effect_receipts,
            "implementation_binding": dict(implementation_binding),
            "evidence": {
                "finalization_status": "failed" if finalization_failed else "finalized",
                "intent_digest": intent_digest,
                "receipt_digest_policy_id": "digest.phase_canonical_json_v1",
                "required_attachments_present": required_attachments_present,
                "attachment_digests": sorted(attachment_digests),
            },
            "retry_disposition": "forbidden" if recovery else "safe_idempotent_retry",
            "recovery_required": recovery,
            "blockers": blockers,
            "exit_code": exit_code,
        }

    def run(self, request: PhaseRequest, *, execute: bool = False, faults: CoreFaults | None = None) -> PhaseOutcome:
        timestamp = self._timestamp(request)
        evidence_root = self._check_root_separation(request)
        store = EvidenceStore(evidence_root, request.run_id)
        evidence_root = store.evidence_root
        lifecycle: list[str] = []
        validator_results: list[dict[str, Any]] = []
        plan: dict[str, Any] | None = None
        intent: dict[str, Any] | None = None
        contract: ResolvedContract | None = None
        effect_receipts: list[dict[str, Any]] = []
        final_validators_published = False
        plan_digest: str | None = None
        attachment_digests: list[str] = []
        progress_digest: str | None = None
        active_faults = CoreFaults()
        try:
            active_faults = _validated_core_faults(CoreFaults() if faults is None else faults)
            lifecycle.append("resolve")
            contract = self.registry.resolve_contract(
                request.contract_id,
                request.contract_version,
                request.contract_digest,
                core_version=__version__,
            )
            exact_binding = f"{request.contract_id}@{request.contract_version}"
            if self.registry.contract_bindings().get(exact_binding) != self._requested_binding(request):
                raise PhaseError("registry.contract_generation_inactive", exact_binding)
            lifecycle.append("guarantees")
            required_guarantees = self._verify_contract_guarantees(contract, request.root_bindings)
            lifecycle.append("capture")
            candidate = capture_structured(Path(request.candidate_path), maximum_bytes=request.maximum_candidate_bytes)
            hook = load_contract_hook(contract)
            if hook is not None and hasattr(hook, "normalize_candidate"):
                normalized = hook.normalize_candidate(parse_json_bytes(candidate.canonical_bytes))
                candidate = normalize_captured_structured(candidate, normalized)
            lifecycle.append("freeze")
            frozen = freeze_declared_inputs(
                contract.document,
                parse_json_bytes(candidate.canonical_bytes),
                request.input_paths,
                request.root_bindings,
                store.blob_root,
                frozen_at=timestamp,
                maximum_structured_bytes=request.maximum_candidate_bytes,
            )
            scope_digest, request_digest, key, root_identity_digest, root_identities = build_idempotency_digests(
                contract,
                candidate,
                frozen,
                request.root_bindings,
            )
            idempotency_lock = None
            if key is not None:
                lock_digest = profile_digest("idempotency-lock", {"key": key, "scope_digest": scope_digest})
                idempotency_lock = _OperationalFileLock(operational_lock_path(store.operational_lock_root / "idempotency", lock_digest))
            if idempotency_lock is None:
                return self._run_after_idempotency_binding(
                    request,
                    store,
                    contract,
                    required_guarantees,
                    candidate,
                    frozen,
                    validator_results,
                    lifecycle,
                    timestamp,
                    scope_digest,
                    request_digest,
                    key,
                    root_identity_digest,
                    root_identities,
                    evidence_root,
                    execute,
                    active_faults,
                )
            with idempotency_lock:
                return self._run_after_idempotency_binding(
                    request,
                    store,
                    contract,
                    required_guarantees,
                    candidate,
                    frozen,
                    validator_results,
                    lifecycle,
                    timestamp,
                    scope_digest,
                    request_digest,
                    key,
                    root_identity_digest,
                    root_identities,
                    evidence_root,
                    execute,
                    active_faults,
                )
        except (PhaseError, OSError) as exc:
            intent_digest = profile_digest("intent", intent) if intent is not None else None
            if effect_receipts and intent_digest is not None and contract is not None and plan is not None:
                receipt = self._executed_receipt(
                    request,
                    contract,
                    plan,
                    validator_results,
                    effect_receipts,
                    timestamp,
                    intent_digest,
                    attachment_digests,
                    intent["implementation_binding"],
                    finalization_failed=True,
                    required_attachments_present=final_validators_published,
                )
                validate_receipt(receipt, self.registry)
                if not lifecycle or lifecycle[-1] != "receipt":
                    lifecycle.append("receipt")
                return PhaseOutcome(
                    request.run_id,
                    receipt["exit_code"],
                    receipt,
                    intent,
                    plan,
                    tuple(lifecycle),
                    None,
                    plan_digest,
                )
            if isinstance(exc, OSError):
                raise
            receipt = self._rejection_receipt(
                request,
                validator_results,
                timestamp,
                exc.code,
                intent_digest=intent_digest,
                attachment_digests=attachment_digests,
                implementation_binding=intent["implementation_binding"] if intent is not None else None,
            )
            validate_receipt(receipt, self.registry)
            store.write_canonical("receipt.json", receipt)
            receipt_digest = profile_digest("receipt", receipt)
            return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, intent, plan, tuple(lifecycle + ["receipt"]), receipt_digest, plan_digest)

    def _run_after_idempotency_binding(
        self,
        request: PhaseRequest,
        store: EvidenceStore,
        contract: ResolvedContract,
        required_guarantees: Mapping[str, Any],
        candidate: CapturedCandidate,
        frozen: Mapping[str, FrozenInput],
        validator_results: list[dict[str, Any]],
        lifecycle: list[str],
        timestamp: str,
        scope_digest: str,
        request_digest: str,
        key: str | None,
        root_identity_digest: str,
        root_identities: list[dict[str, object]],
        evidence_root: Path,
        execute: bool,
        active_faults: CoreFaults,
    ) -> PhaseOutcome:
        plan: dict[str, Any] | None = None
        intent: dict[str, Any] | None = None
        effect_receipts: list[dict[str, Any]] = []
        plan_digest: str | None = None
        attachment_digests: list[str] = []
        progress_digest: str | None = None
        latest_progress: dict[str, Any] | None = None
        runner = ValidatorRunner(self.registry)
        try:
            reused = self._check_idempotency(store, contract, self.registry, key, scope_digest, request_digest, request.root_bindings, execute=execute)
            if execute and reused is not None:
                receipt = self._reused_receipt(request, [], timestamp, reused[0], reused[1])
                validate_receipt(receipt, self.registry)
                lifecycle.append("receipt")
                store.write_canonical("receipt.json", receipt)
                return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, None, None, tuple(lifecycle), profile_digest("receipt", receipt), None)
            lifecycle.append("validate")
            validator_results = runner.run(
                contract,
                candidate,
                frozen,
                root_bindings=request.root_bindings,
                evidence_root=evidence_root,
                run_id=request.run_id,
                timestamp=timestamp,
            )
            blocking_valid = all(
                result["status"] == "pass"
                for result in validator_results
                if result["blocking"] and result["phase"] != "post_operation"
            )
            hook = load_contract_hook(contract)
            if execute and blocking_valid and hook is not None and hasattr(hook, "find_reusable_result"):
                prior = hook.find_reusable_result(
                    parse_json_bytes(candidate.canonical_bytes),
                    frozen,
                    request.root_bindings,
                    evidence_root,
                    self.registry,
                )
                if prior is not None:
                    receipt = self._reused_receipt(request, validator_results, timestamp, prior[0], prior[1])
                    validate_receipt(receipt, self.registry)
                    lifecycle.append("receipt")
                    store.write_canonical("receipt.json", receipt)
                    return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, None, None, tuple(lifecycle), profile_digest("receipt", receipt), None)
            lifecycle.append("plan")
            plan = build_static_plan(
                contract,
                candidate,
                frozen,
                validator_results,
                root_bindings=request.root_bindings,
                run_id=request.run_id,
                generated_at=timestamp,
                request_digest=request_digest,
            )
            validate_static_plan(plan, contract, request.root_bindings, self.registry)
            self._verify_plan_guarantees(required_guarantees, plan)
            content_blob_digests = self._publish_append_blobs(store, plan)
            _, plan_attachment_digest = store.write_canonical("attachments/effect-plan.json", plan)
            attachment_digests.append(plan_attachment_digest)
            plan_digest = profile_digest("effect-plan", plan)
            validator_name = "attachments/pre-validator-results.json" if execute else "attachments/validator-results.json"
            _, validators_digest = store.write_canonical(validator_name, validator_results)
            attachment_digests.append(validators_digest)
            intent = self._intent(
                request,
                contract,
                candidate,
                frozen,
                plan,
                timestamp,
                scope_digest,
                request_digest,
                key,
                root_identity_digest,
                root_identities,
                plan_attachment_digest,
                content_blob_digests,
                execute,
            )
            validate_intent(intent, self.registry)
            lifecycle.append("intent")
            intent_path, _ = store.write_canonical("intent.json", intent)
            intent_digest = profile_digest("intent", intent)
            if not execute:
                receipt = self._planned_receipt(
                    request,
                    validator_results,
                    timestamp,
                    intent_digest,
                    attachment_digests,
                    intent["implementation_binding"],
                )
            else:
                def record_progress(receipts: list[dict[str, object]]) -> None:
                    nonlocal progress_digest, latest_progress
                    if len(plan["effects"]) <= 1:
                        return
                    progress = self._ordered_progress(plan, receipts)  # type: ignore[arg-type]
                    _, digest = store.replace_attachment_canonical("ordered-effect-progress.json", progress)
                    progress_digest = digest
                    latest_progress = progress

                record_progress([])
                lifecycle.append("broker")
                broker_result = EffectBroker(
                    self.registry,
                    self.installation.authority_provider,
                    self.installation.authority_profile_binding,
                ).execute(
                    plan,
                    contract,
                    frozen,
                    request.root_bindings,
                    intent_path,
                    store.operational_lock_root,
                    evidence_root=evidence_root,
                    timestamp=timestamp,
                    faults=active_faults.broker,
                )
                effect_receipts = list(broker_result.effect_receipts)
                if broker_result.progress_digest is not None:
                    progress_digest = broker_result.progress_digest
                    latest_progress = self._ordered_progress(plan, effect_receipts)
                if broker_result.progress_error is not None:
                    raise PhaseError(broker_result.progress_error)
                lifecycle.append("effect")
                _, effects_digest = store.write_canonical("attachments/effect-receipts.json", effect_receipts)
                attachment_digests.append(effects_digest)
                if progress_digest is not None:
                    attachment_digests.append(progress_digest)
                lifecycle.append("verify")
                validator_results = runner.run_post_operation(
                    contract,
                    validator_results,
                    plan,
                    request.root_bindings,
                    evidence_root=evidence_root,
                    run_id=request.run_id,
                    timestamp=timestamp,
                    effect_receipts=effect_receipts,
                    ordered_progress=latest_progress,
                )
                _, final_validators_digest = store.write_canonical("attachments/validator-results.json", validator_results)
                attachment_digests.append(final_validators_digest)
                receipt = self._executed_receipt(
                    request,
                    contract,
                    plan,
                    validator_results,
                    effect_receipts,
                    timestamp,
                    intent_digest,
                    attachment_digests,
                    intent["implementation_binding"],
                    finalization_failed=active_faults.fail_receipt_write,
                )
            validate_receipt(receipt, self.registry)
            lifecycle.append("receipt")
            if not active_faults.fail_receipt_write:
                store.write_canonical("receipt.json", receipt)
            receipt_digest = None if active_faults.fail_receipt_write else profile_digest("receipt", receipt)
            return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, intent, plan, tuple(lifecycle), receipt_digest, plan_digest)
        except (PhaseError, OSError) as exc:
            intent_digest = profile_digest("intent", intent) if intent is not None else None
            if effect_receipts and intent_digest is not None and contract is not None and plan is not None:
                required_attachments_present = True
                try:
                    _, effects_digest = store.write_or_verify_canonical("attachments/effect-receipts.json", effect_receipts)
                    if effects_digest not in attachment_digests:
                        attachment_digests.append(effects_digest)
                except (PhaseError, OSError):
                    required_attachments_present = False
                if len(plan["effects"]) > 1:
                    latest_progress = self._ordered_progress(plan, effect_receipts)
                    try:
                        _, progress_digest = store.replace_attachment_canonical("ordered-effect-progress.json", latest_progress)
                        if progress_digest not in attachment_digests:
                            attachment_digests.append(progress_digest)
                    except (PhaseError, OSError):
                        required_attachments_present = False
                try:
                    _, validators_digest = store.write_or_verify_canonical("attachments/validator-results.json", validator_results)
                    if validators_digest not in attachment_digests:
                        attachment_digests.append(validators_digest)
                except (PhaseError, OSError):
                    required_attachments_present = False
                receipt = self._executed_receipt(
                    request,
                    contract,
                    plan,
                    validator_results,
                    effect_receipts,
                    timestamp,
                    intent_digest,
                    attachment_digests,
                    intent["implementation_binding"],
                    finalization_failed=True,
                    required_attachments_present=required_attachments_present,
                )
                validate_receipt(receipt, self.registry)
                if not lifecycle or lifecycle[-1] != "receipt":
                    lifecycle.append("receipt")
                receipt_digest = None
                try:
                    store.write_canonical("receipt.json", receipt)
                    receipt_digest = profile_digest("receipt", receipt)
                except (PhaseError, OSError):
                    pass
                return PhaseOutcome(
                    request.run_id,
                    receipt["exit_code"],
                    receipt,
                    intent,
                    plan,
                    tuple(lifecycle),
                    receipt_digest,
                    plan_digest,
                )
            if isinstance(exc, OSError):
                raise
            receipt = self._rejection_receipt(
                request,
                validator_results,
                timestamp,
                exc.code,
                intent_digest=intent_digest,
                attachment_digests=attachment_digests,
                implementation_binding=intent["implementation_binding"] if intent is not None else None,
            )
            validate_receipt(receipt, self.registry)
            store.write_canonical("receipt.json", receipt)
            receipt_digest = profile_digest("receipt", receipt)
            return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, intent, plan, tuple(lifecycle + ["receipt"]), receipt_digest, plan_digest)
