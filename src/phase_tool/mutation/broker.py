from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, fields
import base64
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from ..canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ..contracts import load_contract_hook
from ..errors import PhaseError
from ..evidence import replace_attachment_canonical

from ..freeze import FrozenInput
from ..planning import root_identity_digest, validate_static_plan
from ..paths import _platform_path
from ..registry import RegistrySnapshot, ResolvedContract
from .content_addressed_copy import ContentAddressedCopyFaults, execute_content_addressed_copy
from .exclusive_create import ExclusiveCreateFaults, execute_exclusive_create
from .expected_head_append import AppendRecordFaults, execute_append_record
from .archive_then_publish import ArchiveThenPublishFaults, execute_archive_then_publish
from .object_store_publish import ObjectStorePublishFaults, execute_object_store_publish
from .authority import AuthorityProvider, GuaranteeProfileProvider
from .guarantees import GuaranteeProfileBinding
from .implementation import mechanism_authority_usage, mechanism_supports_effect_kind
from .platform import HostAuthorityProvider


@dataclass(frozen=True)
class BrokerFaults:
    exclusive_create: ExclusiveCreateFaults | None = None
    append_record: AppendRecordFaults | None = None
    content_addressed_copy: ContentAddressedCopyFaults | None = None
    archive_then_publish: ArchiveThenPublishFaults | None = None
    object_store_publish: ObjectStorePublishFaults | None = None
    content_addressed_copy_fail_after_bytes: int | None = None
    mutate_plan_after_intent: bool = False
    before_mechanism: Callable[[Path], None] | None = None
    before_effect: Mapping[int, Callable[[Path], None]] | None = None
    before_effect_lock: Callable[[int, Path], None] | None = None


class BrokerExecutionResult(list[dict[str, Any]]):
    """List-compatible broker result with an internal progress-persistence status."""

    def __init__(
        self,
        effect_receipts: list[dict[str, Any]],
        progress_error: str | None = None,
        progress_digest: str | None = None,
    ) -> None:
        super().__init__(effect_receipts)
        self.progress_error = progress_error
        self.progress_digest = progress_digest

    @property
    def effect_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(self)


def ordered_progress_document(plan: Mapping[str, Any], effect_receipts: list[dict[str, Any]]) -> dict[str, Any]:
    receipt_by_id = {receipt["effect_id"]: receipt for receipt in effect_receipts}
    completed: list[str] = []
    verified: list[str] = []
    not_started: list[str] = []
    failed: str | None = None
    effects: list[dict[str, Any]] = []
    for index, effect in enumerate(plan["effects"]):
        effect_id = effect["effect_id"]
        receipt = receipt_by_id.get(effect_id)
        target = {
            "root_binding": effect["target"]["root_binding"],
            "relative_locator": effect["target"]["relative_locator"],
            "expected_digest": effect["content_digest"],
        }
        if receipt is None:
            not_started.append(effect_id)
            state = "not_started"
            observation_digest = None
            receipt_digest = None
        else:
            completed.append(effect_id)
            status = receipt["status"]
            observation_digest = profile_digest("effect-observation", {"effect_id": effect_id, "after": receipt["after"], "status": status})
            receipt_digest = profile_digest("effect-receipt", receipt)
            if status == "applied_verified":
                verified.append(effect_id)
                state = "verified_existing" if receipt.get("bytes_written") == 0 else "applied_new_verified"
            else:
                state = status
                failed = failed or effect_id
        effects.append({
            "ordinal": effect.get("ordinal", index),
            "effect_id": effect_id,
            "kind": effect["kind"],
            "mechanism": effect.get("mechanism", plan["mechanism"])["id"],
            "state": state,
            "target": target,
            "receipt_digest": receipt_digest,
            "observation_digest": observation_digest,
        })
    return {
        "progress_version": "1.0",
        "plan_digest": profile_digest("effect-plan", plan),
        "maximum_effects": len(plan["effects"]),
        "completed_effect_ids": completed,
        "verified_effect_ids": verified,
        "failed_effect_id": failed,
        "not_started_effect_ids": not_started,
        "effects": effects,
    }


_MECHANISM_FAULT_TYPES = {
    "exclusive_create": ExclusiveCreateFaults,
    "append_record": AppendRecordFaults,
    "content_addressed_copy": ContentAddressedCopyFaults,
    "archive_then_publish": ArchiveThenPublishFaults,
    "object_store_publish": ObjectStorePublishFaults,
}
_INTEGER_FAULT_FIELDS = {
    "maximum_write_size",
    "fail_after_bytes",
    "fail_after_archive_bytes",
    "fail_after_current_bytes",
    "fail_old_object_write_after_bytes",
    "fail_new_object_write_after_bytes",
    "fail_temporary_write_after_bytes",
}
_BYTES_FAULT_FIELDS = {"readback_override"}
_BOOLEAN_FAULT_FIELDS = {
    "readback_error",
    "lock_acquire_error",
    "fail_after_archive",
    "fail_after_publish_before_readback",
    "fail_after_objects",
    "fail_atomic_replace",
}


def _validated_mechanism_fault(value: object, expected_type: type[object]) -> object | None:
    if value is None:
        return None
    if type(value) is not expected_type:
        raise PhaseError("broker.invalid_fault_configuration")
    copied: dict[str, object] = {}
    for field in fields(value):
        item = getattr(value, field.name)
        if field.name in _INTEGER_FAULT_FIELDS:
            if item is not None and type(item) is not int:
                raise PhaseError("broker.invalid_fault_configuration")
        elif field.name in _BYTES_FAULT_FIELDS:
            if item is not None and type(item) is not bytes:
                raise PhaseError("broker.invalid_fault_configuration")
        elif field.name in _BOOLEAN_FAULT_FIELDS:
            if type(item) is not bool:
                raise PhaseError("broker.invalid_fault_configuration")
        elif item is not None:
            if callable(item):
                raise PhaseError("broker.unsafe_fault_callback")
            raise PhaseError("broker.invalid_fault_configuration")
        copied[field.name] = item
    return expected_type(**copied)


def validate_broker_faults(value: object) -> BrokerFaults:
    if type(value) is not BrokerFaults:
        raise PhaseError("broker.invalid_fault_configuration")
    if value.content_addressed_copy_fail_after_bytes is not None and type(value.content_addressed_copy_fail_after_bytes) is not int:
        raise PhaseError("broker.invalid_fault_configuration")
    if type(value.mutate_plan_after_intent) is not bool:
        raise PhaseError("broker.invalid_fault_configuration")
    for callback in (value.before_mechanism, value.before_effect, value.before_effect_lock):
        if callback is not None:
            if callable(callback) or isinstance(callback, Mapping):
                raise PhaseError("broker.unsafe_fault_callback")
            raise PhaseError("broker.invalid_fault_configuration")
    nested = {
        name: _validated_mechanism_fault(getattr(value, name), expected_type)
        for name, expected_type in _MECHANISM_FAULT_TYPES.items()
    }
    return BrokerFaults(
        **nested,  # type: ignore[arg-type]
        content_addressed_copy_fail_after_bytes=value.content_addressed_copy_fail_after_bytes,
        mutate_plan_after_intent=value.mutate_plan_after_intent,
    )


class _IntentBoundAuthorityProvider:
    def __init__(self, delegate: AuthorityProvider, root_identities: Mapping[str, tuple[int, int]]) -> None:
        self.delegate = delegate
        self.root_identities = root_identities

    def open_authority(
        self,
        root: Path,
        locator: str,
        reparse_detector: Callable[[Path], bool] | None = None,
        expected_root_identity: tuple[int, int] | None = None,
    ):
        key = os.path.normcase(str(Path(root).absolute()))
        expected = self.root_identities.get(key)
        if expected is None or (expected_root_identity is not None and expected_root_identity != expected):
            raise PhaseError("broker.root_identity_mismatch")
        return self.delegate.open_authority(
            root,
            locator,
            reparse_detector,
            expected_root_identity=expected,
        )

    def lock_target_root(self, root: Path, scope: str):
        return self.delegate.lock_target_root(root, scope)


class EffectBroker:
    """The only boundary allowed to invoke a target mutation mechanism."""

    def __init__(
        self,
        registry: RegistrySnapshot,
        authority_provider: AuthorityProvider,
        authority_profile_binding: GuaranteeProfileBinding | None = None,
    ) -> None:
        self.registry = registry
        self.authority_provider = authority_provider
        self.authority_profile_binding = authority_profile_binding
        schema = registry.schema_document("https://phase-tool.local/schemas/effect-receipt.schema.json")
        self._receipt_validator = Draft202012Validator(
            schema,
            registry=registry.schema_registry(),
            format_checker=FormatChecker(),
        )

    @staticmethod
    def _read_evidence_file(path: Path, missing_code: str, detail: str) -> bytes:
        platform_path = _platform_path(path)
        if not os.path.isfile(platform_path):
            raise PhaseError(missing_code, detail)
        with open(platform_path, "rb") as stream:
            return stream.read()

    def _locked_plan_from_evidence(
        self,
        plan: dict[str, object],
        contract: ResolvedContract,
        root_bindings: Mapping[str, Path],
        intent_path: Path,
    ) -> tuple[dict[str, object], dict[str, object]]:
        intent = parse_json_bytes(intent_path.read_bytes())
        run_root = intent_path.parent
        plan_path = run_root / "attachments" / "effect-plan.json"
        if not plan_path.is_file():
            raise PhaseError("broker.plan_attachment_missing")
        plan_bytes = plan_path.read_bytes()
        attached_plan = parse_json_bytes(plan_bytes)
        attachment_digest = digest_bytes(plan_bytes)
        evidence = intent.get("evidence", {})
        if evidence.get("effect_plan_attachment_digest") != attachment_digest:
            raise PhaseError("broker.plan_attachment_mismatch")
        if attached_plan != plan:
            raise PhaseError("broker.plan_attachment_mismatch")
        expected_contract = {"id": contract.document["identity"]["id"], "version": contract.document["identity"]["version"], "package_digest": contract.package_digest}
        if intent.get("contract") != expected_contract:
            raise PhaseError("broker.intent_contract_mismatch")
        operation = intent.get("operation")
        if not isinstance(operation, Mapping) or operation.get("mechanism") != attached_plan.get("mechanism"):
            raise PhaseError("broker.intent_mechanism_mismatch")
        if intent.get("effect_plan_digest") != profile_digest("effect-plan", attached_plan):
            raise PhaseError("broker.intent_plan_mismatch")
        self._validate_intent_implementation(intent, attached_plan)
        locked_plan = parse_json_bytes(canonical_bytes(attached_plan))
        validate_static_plan(locked_plan, contract, root_bindings, self.registry)
        return locked_plan, intent

    def _validate_intent_implementation(
        self,
        intent: Mapping[str, object],
        plan: Mapping[str, object],
    ) -> None:
        binding = intent.get("implementation_binding")
        if not isinstance(binding, Mapping):
            raise PhaseError("broker.intent_implementation_mismatch")
        mechanism = plan.get("mechanism")
        expected_plan_digest = profile_digest("effect-plan", plan)
        if binding.get("mechanism") != mechanism or binding.get("effect_plan_digest") != expected_plan_digest:
            raise PhaseError("broker.intent_implementation_mismatch")
        if not isinstance(mechanism, Mapping):
            raise PhaseError("broker.intent_implementation_mismatch")
        self.registry.resolve_mechanism(mechanism)
        authority_usage = mechanism_authority_usage(mechanism)
        effects = plan.get("effects")
        if not isinstance(effects, list):
            raise PhaseError("broker.intent_implementation_mismatch")
        for effect in effects:
            if not isinstance(effect, Mapping):
                raise PhaseError("broker.intent_implementation_mismatch")
            effect_mechanism = effect.get("mechanism", mechanism)
            if not isinstance(effect_mechanism, Mapping):
                raise PhaseError("broker.intent_implementation_mismatch")
            self.registry.resolve_mechanism(effect_mechanism)
            if (
                mechanism_authority_usage(effect_mechanism) != authority_usage
                or not mechanism_supports_effect_kind(effect_mechanism, effect.get("kind"))
            ):
                raise PhaseError("broker.intent_implementation_mismatch")

        authority = binding.get("authority")
        if authority_usage == "mechanism_managed":
            expected_authority = {"usage": "mechanism_managed", "profile": None, "provider": None}
        else:
            if type(self.authority_provider) is not HostAuthorityProvider or not isinstance(
                self.authority_provider, GuaranteeProfileProvider
            ):
                raise PhaseError("broker.intent_implementation_mismatch")
            profile = self.authority_profile_binding
            if profile is None or self.authority_provider.guarantee_profile_binding() != profile:
                raise PhaseError("broker.intent_implementation_mismatch")
            expected_authority = {
                "usage": "provider_backed",
                "profile": profile.as_dict(),
                "provider": {
                    "id": profile.implementation_id,
                    "version": profile.implementation_version,
                    "artifact_digest": profile.implementation_artifact_digest,
                },
            }
            self.registry.resolve_guarantee_profile(profile.as_dict())
        if authority != expected_authority:
            raise PhaseError("broker.intent_implementation_mismatch")

    @staticmethod
    def _validate_execution_roots(
        intent: Mapping[str, object],
        contract: ResolvedContract,
        root_bindings: Mapping[str, Path],
    ) -> dict[str, tuple[int, int]]:
        from ..installation import qualify_host_authority_roots

        expected_bindings = {item["binding_id"] for item in contract.document["write_scope"]["roots"]}
        qualify_host_authority_roots(
            {
                binding_id: root_bindings[binding_id]
                for binding_id in sorted(expected_bindings)
                if binding_id in root_bindings
            }
        )
        idempotency = intent.get("idempotency")
        expected = idempotency.get("root_identity_digest") if isinstance(idempotency, Mapping) else None
        records = idempotency.get("root_identities") if isinstance(idempotency, Mapping) else None
        if not isinstance(records, list) or expected != profile_digest("resolved-root-identity", records):
            raise PhaseError("broker.root_identity_mismatch")
        observed_bindings: set[str] = set()
        root_identities: dict[str, tuple[int, int]] = {}
        for record in records:
            if not isinstance(record, Mapping):
                raise PhaseError("broker.root_identity_mismatch")
            binding_id = record.get("binding_id")
            resolved_path = record.get("resolved_path")
            device = record.get("device")
            inode = record.get("inode")
            if (
                not isinstance(binding_id, str)
                or binding_id not in expected_bindings
                or binding_id in observed_bindings
                or not isinstance(resolved_path, str)
                or not isinstance(device, int)
                or isinstance(device, bool)
                or not isinstance(inode, int)
                or isinstance(inode, bool)
            ):
                raise PhaseError("broker.root_identity_mismatch")
            try:
                configured_path = os.path.normcase(str(Path(root_bindings[binding_id]).absolute()))
            except KeyError as exc:
                raise PhaseError("broker.root_identity_mismatch") from exc
            if configured_path != resolved_path:
                raise PhaseError("broker.root_identity_mismatch")
            observed_bindings.add(binding_id)
            root_identities[configured_path] = (device, inode)
        if observed_bindings != expected_bindings or expected != root_identity_digest(contract, root_bindings):
            raise PhaseError("broker.root_identity_mismatch")
        return root_identities

    @staticmethod
    def _attached_blob_content(effect: Mapping[str, object], intent_path: Path, intent: Mapping[str, object]) -> bytes:
        blob_digest = effect.get("content_blob_digest")
        if not isinstance(blob_digest, str):
            raise PhaseError("broker.content_blob_missing", str(effect.get("effect_id")))
        evidence = intent.get("evidence", {})
        bound_digests = evidence.get("content_blob_digests") if isinstance(evidence, Mapping) else None
        if not isinstance(bound_digests, list) or blob_digest not in bound_digests:
            raise PhaseError("broker.content_blob_unbound", str(effect.get("effect_id")))
        blob_path = intent_path.parent / "blobs" / blob_digest.split(":", 1)[1]
        content = EffectBroker._read_evidence_file(blob_path, "broker.content_blob_missing", blob_digest)
        if len(content) != effect["content_length"] or digest_bytes(content) != effect["content_digest"] or digest_bytes(content) != blob_digest:
            raise PhaseError("broker.content_blob_mismatch", blob_digest)
        encoded = effect.get("content_bytes_b64")
        if isinstance(encoded, str):
            inline = base64.b64decode(encoded.encode("ascii"), validate=True)
            if inline != content:
                raise PhaseError("broker.inline_blob_mismatch", str(effect.get("effect_id")))
        return content

    @staticmethod
    def _frozen_blob_content(effect: Mapping[str, object], intent_path: Path, intent: Mapping[str, object]) -> bytes:
        source = effect.get("content_source")
        if not isinstance(source, Mapping) or source.get("kind") != "frozen_input":
            raise PhaseError("broker.content_source_missing", str(effect.get("effect_id")))
        binding_id = source.get("binding_id")
        inputs = intent.get("inputs")
        if not isinstance(inputs, list):
            raise PhaseError("broker.content_source_missing", str(effect.get("effect_id")))
        matches = [item for item in inputs if isinstance(item, Mapping) and item.get("binding_id") == binding_id]
        if len(matches) != 1:
            raise PhaseError("broker.content_source_missing", str(binding_id))
        record = matches[0]
        blob_digest = record.get("blob_digest")
        if not isinstance(blob_digest, str):
            raise PhaseError("broker.content_source_not_frozen", str(binding_id))
        if blob_digest != effect.get("content_digest") or record.get("digest") != effect.get("content_digest"):
            raise PhaseError("broker.content_blob_mismatch", blob_digest)
        blob_path = intent_path.parent / "blobs" / blob_digest.split(":", 1)[1]
        content = EffectBroker._read_evidence_file(blob_path, "broker.content_blob_missing", blob_digest)
        if len(content) != effect["content_length"] or digest_bytes(content) != effect["content_digest"]:
            raise PhaseError("broker.content_blob_mismatch", blob_digest)
        return content

    def execute(
        self,
        plan: dict[str, object],
        contract: ResolvedContract,
        frozen_inputs: Mapping[str, FrozenInput],
        root_bindings: Mapping[str, Path],
        intent_path: Path,
        operational_lock_root: Path,
        *,
        evidence_root: Path | None = None,
        timestamp: str,
        faults: BrokerFaults | None = None,
    ) -> BrokerExecutionResult:
        active = validate_broker_faults(BrokerFaults() if faults is None else faults)
        if not intent_path.is_file():
            raise PhaseError("broker.intent_missing")
        locked_plan, intent = self._locked_plan_from_evidence(plan, contract, root_bindings, intent_path)
        if intent.get("execution_requested") is not True:
            raise PhaseError("broker.execution_not_requested")
        if active.mutate_plan_after_intent:
            plan["effects"].append(deepcopy(plan["effects"][0]))  # type: ignore[union-attr,index]
        if intent.get("effect_plan_digest") != profile_digest("effect-plan", plan):
            raise PhaseError("broker.plan_changed_after_intent")
        locked_plan, intent = self._locked_plan_from_evidence(plan, contract, root_bindings, intent_path)
        if intent.get("execution_requested") is not True:
            raise PhaseError("broker.execution_not_requested")
        effects = locked_plan["effects"]
        self._validate_execution_roots(intent, contract, root_bindings)
        if not effects or any(effect["kind"] not in {"exclusive_create", "append_record", "copy_blob", "publish_new_version"} for effect in effects):
            raise PhaseError("broker.plan_not_executable")
        receipts: list[dict[str, Any]] = []
        progress_digest: str | None = None
        hook = load_contract_hook(contract)
        if hook is not None:
            setattr(hook, "_registry", self.registry)
        candidate = intent.get("candidate", {}).get("storage", {}).get("value")
        for ordinal, effect in enumerate(effects):
            mechanism = effect.get("mechanism", locked_plan["mechanism"])
            entry = self.registry.resolve_mechanism(mechanism)
            descriptor = parse_json_bytes(self.registry.resource_bytes(str(entry["artifact"])))
            if descriptor.get("execution_allowed") is not True:
                raise PhaseError("broker.mechanism_execution_unavailable", str(mechanism["id"]))
            supported = {
                ("mechanism.exclusive_create_v1", "1.0.0"),
                ("mechanism.expected_head_append_v1", "1.0.0"),
                ("content_addressed_copy", "1.0.0"),
                ("mechanism.archive_then_publish_v1", "1.0.0"),
                ("mechanism.object_store_publish_v2", "1.0.0"),
            }
            if (mechanism["id"], mechanism["version"]) not in supported:
                raise PhaseError("broker.mechanism_execution_unavailable", str(mechanism["id"]))
            self._validate_execution_roots(intent, contract, root_bindings)
            root_id = effect["target"]["root_binding"]
            try:
                target_root = Path(root_bindings[root_id]).resolve(strict=True)
            except KeyError as exc:
                raise PhaseError("plan.root_binding_missing", str(root_id)) from exc
            lock_scope = effect.get("lock_scope")
            if isinstance(lock_scope, str) and mechanism_authority_usage(mechanism) == "provider_backed":
                context = self.authority_provider.lock_target_root(target_root, lock_scope)
            else:
                context = None
            if context is None:
                receipt = self._execute_one(
                    active, candidate, contract, effect, frozen_inputs, hook, intent, intent_path,
                    ordinal, target_root, root_bindings, evidence_root, timestamp
                )
            else:
                with context:
                    receipt = self._execute_one(
                        active, candidate, contract, effect, frozen_inputs, hook, intent, intent_path,
                        ordinal, target_root, root_bindings, evidence_root, timestamp
                    )
            self._receipt_validator.validate(receipt)
            receipts.append(receipt)
            if len(effects) > 1:
                try:
                    _, progress_digest = replace_attachment_canonical(
                        intent_path.parent / "attachments",
                        "ordered-effect-progress.json",
                        ordered_progress_document(locked_plan, receipts),
                    )
                except (OSError, PhaseError):
                    return BrokerExecutionResult(receipts, "evidence.finalization_failed", progress_digest)
            if receipt["status"] != "applied_verified":
                break
        return BrokerExecutionResult(receipts, progress_digest=progress_digest)

    def _execute_one(
        self,
        active: BrokerFaults,
        candidate: object,
        contract: ResolvedContract,
        effect: dict[str, object],
        frozen_inputs: Mapping[str, FrozenInput],
        hook: object | None,
        intent: Mapping[str, object],
        intent_path: Path,
        ordinal: int,
        target_root: Path,
        root_bindings: Mapping[str, Path],
        evidence_root: Path | None,
        timestamp: str,
    ) -> dict[str, object]:
        try:
            if hook is not None and hasattr(hook, "before_effect"):
                hook.before_effect(
                    candidate,
                    contract,
                    effect,
                    frozen_inputs,
                    target_root,
                    evidence_root=evidence_root,
                    root_bindings=root_bindings,
                )
            root_identities = self._validate_execution_roots(intent, contract, root_bindings)
            bound_authority_provider = _IntentBoundAuthorityProvider(self.authority_provider, root_identities)
            exclusive_faults = active.exclusive_create
            copy_faults = active.content_addressed_copy
            archive_faults = active.archive_then_publish
            object_store_faults = active.object_store_publish
            if effect.get("content_blob_digest") is not None:
                content = self._attached_blob_content(effect, intent_path, intent)
            elif effect["kind"] == "copy_blob":
                content = self._frozen_blob_content(effect, intent_path, intent)
            elif effect["content_source"]["kind"] == "frozen_input":
                content = self._frozen_blob_content(effect, intent_path, intent)
            else:
                encoded = effect.get("content_bytes_b64")
                if not isinstance(encoded, str):
                    raise PhaseError("broker.content_source_missing", "content_bytes_b64")
                content = base64.b64decode(encoded.encode("ascii"), validate=True)
        except PhaseError as exc:
            if ordinal == 0:
                raise
            unknown = {"known": False, "exists": None, "digest": None, "length": None, "head_token": None}
            return {
                "effect_receipt_version": "1.0",
                "run_id": str(intent.get("run_id")),
                "effect_id": effect["effect_id"],
                "kind": effect["kind"],
                "status": "failed_no_effect",
                "attempted": True,
                "before": unknown,
                "after": unknown,
                "bytes_written": 0,
                "verification_refs": ["broker.preinvocation"],
                "error": {"code": exc.code, "message": str(exc)},
                "started_at": timestamp,
                "finished_at": timestamp,
            }
        if effect["kind"] == "exclusive_create":
            return execute_exclusive_create(
                effect,
                target_root,
                content,
                run_id=str(contract.document.get("_run_id", intent.get("run_id"))),
                timestamp=timestamp,
                faults=exclusive_faults,
                authority_provider=bound_authority_provider,
            )
        if effect["kind"] == "append_record":
            return execute_append_record(
                effect,
                target_root,
                content,
                run_id=str(intent.get("run_id")),
                timestamp=timestamp,
                operational_lock_root=intent_path.parent.parent.parent / "locks",
                faults=active.append_record,
                expected_root_identity=root_identities[os.path.normcase(str(target_root.absolute()))],
            )
        if effect["kind"] == "publish_new_version":
            mechanism = effect.get("mechanism", contract.document["operation"]["mechanism"])
            if mechanism["id"] == "mechanism.object_store_publish_v2":
                objects_binding = effect["archive_target"]["root_binding"]
                try:
                    objects_root = Path(root_bindings[objects_binding]).resolve(strict=True)
                except KeyError as exc:
                    raise PhaseError("plan.root_binding_missing", str(objects_binding)) from exc
                return execute_object_store_publish(
                    effect,
                    target_root,
                    objects_root,
                    content,
                    run_id=str(intent.get("run_id")),
                    timestamp=timestamp,
                    faults=object_store_faults,
                    authority_provider=bound_authority_provider,
                )
            return execute_archive_then_publish(
                effect,
                target_root,
                content,
                run_id=str(intent.get("run_id")),
                timestamp=timestamp,
                faults=archive_faults,
                authority_provider=bound_authority_provider,
            )
        if active.content_addressed_copy_fail_after_bytes is not None:
            copy_faults = ContentAddressedCopyFaults(fail_after_bytes=active.content_addressed_copy_fail_after_bytes)
        return execute_content_addressed_copy(
            effect,
            target_root,
            content,
            run_id=str(intent.get("run_id")),
            timestamp=timestamp,
            faults=copy_faults,
            authority_provider=bound_authority_provider,
        )
