from __future__ import annotations

import base64
import errno
import os
import time
from contextlib import contextmanager
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
from .mutation.broker import BrokerExecutionInterrupted, ordered_progress_document, validate_broker_faults
from .mutation.authority import GuaranteeProfileProvider
from .mutation.guarantees import verify_guarantee_coverage
from .mutation.implementation import mechanism_authority_usage
from .mutation.platform import HostAuthorityProvider
from .planning import build_idempotency_digests, build_static_plan, validate_static_plan
from .registry import BundledRegistry, RegistrySnapshot, ResolvedContract
from .validation import ValidatorRunner

_OPERATIONAL_LOCK_TIMEOUT_SECONDS = 5.0
_OPERATIONAL_LOCK_RETRY_SECONDS = 0.05

CORE_BINDING = {
    "id": "phase.core",
    "version": __version__,
    "package_digest": profile_digest("core-package", {"id": "phase.core", "version": __version__, "capability": "effect_broker_v1"}),
}


class _OperationalFileLock:
    def __init__(self, path: Path, *, _checked_release: bool = False) -> None:
        if type(_checked_release) is not bool:
            raise PhaseError("lock.invalid_checked_mode")
        self.path = path
        self._stream = None
        self._checked_release = _checked_release
        self._checked_fd = None
        self._checked_identity = None
        self._checked_parent_identity = None
        self._checked_enter_attempted = False

    def fileno(self) -> int:
        if self._checked_release:
            if self._checked_fd is None:
                raise PhaseError("lock.descriptor_unavailable")
            return self._checked_fd
        assert self._stream is not None
        return self._stream.fileno()

    def _check_checked_namespace(self) -> None:
        import stat
        from .evidence import _reject_existing_links
        _reject_existing_links(self.path.parent)
        parent = self.path.parent.lstat()
        named = self.path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o022
            or (parent.st_dev, parent.st_ino) != self._checked_parent_identity
            or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
            or named.st_uid != os.geteuid() or named.st_mode & 0o022
            or (named.st_dev, named.st_ino) != self._checked_identity):
            raise PhaseError("lock.checked_namespace_identity_changed")

    @staticmethod
    def _checked_secondary(primary: BaseException | None, errors: list[BaseException]) -> None:
        if not errors:
            return
        if primary is not None:
            for error in errors:
                primary.add_note("Checked lock finalization: " + str(error))
            return
        raise PhaseError("lock.checked_finalization_unknown", details={
            'errors': [{'type': type(error).__name__, 'message': str(error),
                'code': getattr(error, 'code', None), 'errno': getattr(error, 'errno', None)}
                for error in errors]}) from errors[0]

    def _enter_checked(self) -> "_OperationalFileLock":
        import stat
        if self._checked_enter_attempted:
            raise PhaseError("lock.checked_acquisition_consumed")
        self._checked_enter_attempted = True
        if (os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW')
            or not hasattr(os, 'O_CLOEXEC') or not hasattr(os, 'O_DIRECTORY')
            or not self.path.is_absolute()):
            raise PhaseError("lock.checked_platform_unsupported")
        import fcntl
        from .evidence import _open_checked_operational_lock
        descriptor, parent_identity, identity = _open_checked_operational_lock(self.path)
        self._checked_fd = descriptor
        self._checked_parent_identity, self._checked_identity = parent_identity, identity
        descriptor = self._checked_fd
        try:
            deadline = time.monotonic() + _OPERATIONAL_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    if error.errno not in {errno.EINTR, errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise PhaseError("lock.acquire_timeout", str(self.path)) from error
                    if error.errno != errno.EINTR:
                        time.sleep(min(_OPERATIONAL_LOCK_RETRY_SECONDS, remaining))
                else:
                    self._check_checked_namespace()
                    return self
        except BaseException as primary:
            # May have acquired before a namespace-check failure. Finalize this
            # same descriptor once, preserving the original failure either way.
            self._exit_checked(primary)
            raise

    def _exit_checked(self, primary: BaseException | None) -> None:
        descriptor, self._checked_fd = self._checked_fd, None
        if descriptor is None:
            self._checked_secondary(primary, [PhaseError("lock.checked_finalization_consumed")])
            return
        import fcntl
        errors = []
        try: self._check_checked_namespace()
        except BaseException as error: errors.append(error)
        # A changed descriptor is no longer owned; never close a reused number.
        # The bootstrap must forbid transfer/fork/concurrent use; dev/ino alone
        # cannot authenticate an open-file-description after external FD reuse.
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != self._checked_identity:
                raise PhaseError("lock.checked_descriptor_identity_changed")
        except BaseException as error:
            errors.append(error)
        else:
            try: fcntl.flock(descriptor, fcntl.LOCK_UN)
            except BaseException as error: errors.append(error)
            try: os.close(descriptor)
            except BaseException as error: errors.append(error)
        self._checked_secondary(primary, errors)

    def __enter__(self) -> "_OperationalFileLock":
        if self._checked_release:
            return self._enter_checked()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("a+b")
        if os.name == "nt":
            import msvcrt

            self._stream.seek(0)
            msvcrt.locking(self._stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            deadline = time.monotonic() + _OPERATIONAL_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(self._stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        if deadline - time.monotonic() <= 0:
                            self._stream.close()
                            self._stream = None
                            raise PhaseError("lock.acquire_timeout", str(self.path)) from exc
                        continue
                    if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                        self._stream.close()
                        self._stream = None
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._stream.close()
                        self._stream = None
                        raise PhaseError("lock.acquire_timeout", str(self.path)) from exc
                    time.sleep(min(_OPERATIONAL_LOCK_RETRY_SECONDS, remaining))
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._checked_release:
            return self._exit_checked(_exc[1] if len(_exc) > 1 else None)
        assert self._stream is not None
        try:
            if os.name == "nt":
                import msvcrt

                self._stream.seek(0)
                msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            self._stream.close()
            self._stream = None


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
    expected_inputs: Mapping[str, tuple[str, int]] | None = None
    _expected_candidate_bytes: bytes | None = None


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


@dataclass
class _NativeRunContext:
    """Transient operation facts only; no installation authority or persistence.

    The future closed native wrapper must admit its actual installation and
    acquire the original-intent guard before entering the existing lifecycle.
    These facts neither qualify a root nor discharge an unresolved original.
    """

    started: bool = False
    inner_entered: bool = False
    intent_recording_started: bool = False
    broker_entered: bool = False
    preparation_attempted: bool = False
    publication_attempted: bool = False
    possible_dispatch: bool = False
    store: EvidenceStore | None = None
    prepared_bytes: bytes | None = None
    native_authority: object | None = None
    original_intent_digest: str | None = None
    idempotency_enter_started: bool = False
    idempotency_entered: bool = False
    idempotency_finalized: bool = False
    common_guard_finalized: bool = False
    proof_publication_attempted: bool = False
    native_failure_publication_attempted: bool = False
    native_failure_publication_confirmed: bool = False
    broker_interruption: BaseException | None = None

    def start(self) -> None:
        # Consume BEFORE EvidenceStore reservation, never after possible effects.
        if (self.started or self.inner_entered or self.intent_recording_started
            or self.broker_entered or self.preparation_attempted
            or self.publication_attempted or self.possible_dispatch
            or self.store is not None or self.prepared_bytes is not None or self.original_intent_digest is not None
            or self.idempotency_enter_started or self.idempotency_entered
            or self.idempotency_finalized or self.common_guard_finalized or self.proof_publication_attempted
            or self.native_failure_publication_attempted or self.native_failure_publication_confirmed
            or self.broker_interruption is not None):
            raise PhaseError("ntfs.terminal_context_consumed")
        self.started = True

    @property
    def prepared(self) -> PhaseOutcome | None:
        if self.prepared_bytes is None:
            return None
        value = parse_json_bytes(self.prepared_bytes)
        return PhaseOutcome(value['run_id'], value['exit_code'], value['receipt'],
            value['intent'], value['effect_plan'], tuple(value['lifecycle']),
            None, value['effect_plan_digest'])

    def prepare(self, store: EvidenceStore, outcome: PhaseOutcome) -> PhaseOutcome:
        if (not self.started or self.preparation_attempted or self.publication_attempted
            or self.store is not store):
            raise PhaseError("ntfs.terminal_preparation_consumed")
        self.preparation_attempted = True
        # Original/dispatch flags and the original store already exist before
        # this fallible serialization. A failed copy cannot authorize no-effect.
        from .canonical import canonical_bytes
        raw = canonical_bytes({'run_id': outcome.run_id, 'exit_code': outcome.exit_code,
            'receipt': outcome.receipt, 'intent': outcome.intent,
            'effect_plan': outcome.effect_plan, 'lifecycle': list(outcome.lifecycle),
            'effect_plan_digest': outcome.effect_plan_digest})
        self.prepared_bytes = raw
        # Each access decodes a fresh view; nested caller mutations cannot alter
        # the immutable pending bytes. No receipt digest acknowledges a commit.
        return self.prepared


def _prepare_native_terminal(context: _NativeRunContext, store: EvidenceStore,
    outcome: PhaseOutcome) -> PhaseOutcome:
    if type(context) is not _NativeRunContext or type(store) is not EvidenceStore:
        raise PhaseError("ntfs.terminal_context_required")
    return context.prepare(store, outcome)


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
        try:
            evidence = Path(request.evidence_root).resolve(strict=False)
        except (OSError, ValueError) as exc:
            raise PhaseError("evidence.root_separation_failed") from exc
        for name, root_value in request.root_bindings.items():
            try:
                root = Path(root_value).resolve(strict=False)
            except (OSError, ValueError) as exc:
                raise PhaseError("evidence.root_separation_failed") from exc
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
        _native_authority: object | None = None,
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
                        inspected = inspect_run(store.evidence_root, path.parent.name, registry, root_bindings=root_bindings, _native_authority=_native_authority)
                    except (PhaseError, ValidationError) as exc:
                        raise PhaseError("idempotency.prior_inspection_required", str(exc)) from exc
                    if inspected.get("state_classification") in {"no_effect_observed", "archived_not_published", "published_not_finalized"}:
                        continue
                    raise PhaseError("idempotency.prior_inspection_required", path.parent.name)
                receipt = parse_json_bytes(read_evidence_bytes(receipt_path))
                if receipt.get("terminal_status") == "validated_planned":
                    continue
                # A transient absent target cannot discharge an unresolved
                # dispatched worker. Only a future explicit verified resolution
                # path can do so; normal idempotency is not recovery authority.
                if "broker.dispatch_outcome_unknown" in receipt.get("blockers", []):
                    raise PhaseError("idempotency.prior_inspection_required", path.parent.name)
                if receipt.get("terminal_status") != "succeeded_verified":
                    try:
                        inspected = inspect_run(store.evidence_root, path.parent.name, registry, root_bindings=root_bindings, _native_authority=_native_authority)
                    except (PhaseError, ValidationError) as exc:
                        raise PhaseError("idempotency.prior_inspection_required", str(exc)) from exc
                    if inspected.get("state_classification") in {"no_effect_observed", "archived_not_published", "published_not_finalized"}:
                        continue
                    raise PhaseError("idempotency.prior_inspection_required", path.parent.name)
                if receipt.get("evidence", {}).get("finalization_status") != "finalized":
                    raise PhaseError("idempotency.prior_inspection_required", path.parent.name)
                try:
                    inspected = inspect_run(store.evidence_root, path.parent.name, registry, root_bindings=root_bindings, _native_authority=_native_authority)
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
        from .installation import _NativeFileCreateInstallation
        if type(self.installation) is _NativeFileCreateInstallation:
            return self.installation.authority.implementation_binding(plan)
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
        from .installation import _NativeFileCreateInstallation
        if type(self.installation) is _NativeFileCreateInstallation:
            self.installation.authority.require_request_roots(
                root_bindings, self.installation.read_binding.check_evidence_root())
            return self.installation.authority.require_contract(contract)
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
        from .mutation.ntfs.experimental_file1 import _experimental_admission
        binding = getattr(self.installation, 'read_binding', None)
        admission = None if binding is None else _experimental_admission(binding)
        if admission is None:
            verify_guarantee_coverage(
                selected_requirements,
                list(mechanisms_by_key.values()),
                self.installation.authority_profile_binding,
                self.registry,
            )
        else:
            admission.assess(binding, selected_requirements, list(mechanisms_by_key.values()))

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
        *, attachment_digests: list[str] | None = None,
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
                "attachment_digests": sorted(attachment_digests or []),
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
        interruption_code: str | None = None,
        possible_dispatch: bool = False,
    ) -> dict[str, Any]:
        terminal,result_state,exit_code,recovery,blockers = _classify_effect_outcome(
            plan,validator_results,effect_receipts,finalization_failed=finalization_failed,
            interruption_code=interruption_code,possible_dispatch=possible_dispatch)
        result_effect = plan['effects'][-1]
        return self._base_receipt(request, validator_results, timestamp) | {
            "terminal_status": terminal,
            "execution_disposition": "executed",
            "mutation_attempted": possible_dispatch or any(bool(receipt["attempted"]) for receipt in effect_receipts),
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
        from .installation import _NativeFileCreateInstallation
        if type(self.installation) is _NativeFileCreateInstallation:
            from .mutation.ntfs.lifecycle import _run_native_file_create
            return _run_native_file_create(self, request, execute=execute, faults=faults)
        return self._run_lifecycle(request, execute=execute, faults=faults)

    def _run_lifecycle(self, request: PhaseRequest, *, execute: bool = False,
        faults: CoreFaults | None = None, native_ctx: _NativeRunContext | None = None) -> PhaseOutcome:
        # Native startup/guard admission belongs to the future closed wrapper;
        # this private seam is not an entrypoint or a qualification exemption.
        if native_ctx is not None:
            if type(native_ctx) is not _NativeRunContext:
                raise PhaseError("ntfs.terminal_context_required")
            native_ctx.start()
        timestamp = self._timestamp(request)
        from .installation import _NativeFileCreateInstallation
        if type(self.installation) is _NativeFileCreateInstallation:
            if (type(native_ctx) is not _NativeRunContext
                or native_ctx.native_authority is not self.installation.authority):
                raise PhaseError("ntfs.closed_native_installation_required")
            evidence_root = self.installation.check_request(request)
        else:
            if native_ctx is not None and native_ctx.native_authority is not None:
                raise PhaseError("ntfs.closed_native_installation_required")
            evidence_root = self._check_root_separation(request)
        store = EvidenceStore(evidence_root, request.run_id)
        if native_ctx is not None:
            native_ctx.store = store
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
            from .mutation.ntfs.experimental_file1 import _experimental_admission
            binding = getattr(self.installation, 'read_binding', None)
            admission = None if binding is None else _experimental_admission(binding)
            if admission is not None:
                _, admission_digest = store.write_canonical('attachments/experimental-admission.json',
                    admission.document())
                attachment_digests.append(admission_digest)
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
            # Bind a literal caller value to the actual capture before any hook
            # or effect preparation. Path-only callers retain capture semantics.
            expected_candidate = request._expected_candidate_bytes
            if expected_candidate is not None:
                if type(expected_candidate) is not bytes or len(expected_candidate) > request.maximum_candidate_bytes:
                    raise PhaseError("candidate.invalid_expected_content")
                if candidate.canonical_bytes != expected_candidate:
                    raise PhaseError("candidate.expected_content_mismatch")
            hook = load_contract_hook(contract, **({} if native_ctx is None or native_ctx.native_authority is None else {"_native_authority":native_ctx.native_authority}))
            if hook is not None and hasattr(hook, "normalize_candidate"):
                normalized = hook.normalize_candidate(parse_json_bytes(candidate.canonical_bytes))
                candidate = normalize_captured_structured(candidate, normalized)
            schema_result = ValidatorRunner(self.registry).run_candidate_schema(
                contract,
                candidate,
                run_id=request.run_id,
                timestamp=timestamp,
            )
            if schema_result["status"] != "pass":
                validator_results = [schema_result]
                raise PhaseError(schema_result["code"])
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
            # Bind the caller's captured identity to Core's actual frozen input,
            # not to the mutable pathname handed across the application seam.
            for binding_id, expected in (request.expected_inputs or {}).items():
                item = frozen.get(binding_id)
                if item is None or (item.digest, item.length) != expected:
                    raise PhaseError("freeze.expected_content_mismatch", binding_id)
            if native_ctx is not None and native_ctx.native_authority is not None:
                identity_result = native_ctx.native_authority.idempotency(
                    contract, candidate, frozen, request.root_bindings)
            else:
                identity_result = build_idempotency_digests(contract, candidate, frozen, request.root_bindings)
            scope_digest, request_digest, key, root_identity_digest, root_identities = identity_result
            idempotency_lock = None
            if key is not None:
                lock_digest = profile_digest("idempotency-lock", {"key": key, "scope_digest": scope_digest})
                idempotency_path = operational_lock_path(store.operational_lock_root / "idempotency", lock_digest)
                idempotency_lock = _OperationalFileLock(idempotency_path, _checked_release=native_ctx is not None)
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
                    native_ctx,
                )
            if native_ctx is not None:
                native_ctx.idempotency_enter_started = True
            with idempotency_lock:
                if native_ctx is not None:
                    native_ctx.idempotency_entered = True
                locked_outcome = self._run_after_idempotency_binding(
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
                    native_ctx,
                )
            if native_ctx is not None:
                native_ctx.idempotency_finalized = True
            return locked_outcome
        except (PhaseError, OSError) as exc:
            if native_ctx is not None and (native_ctx.inner_entered or native_ctx.preparation_attempted):
                # Inner operation facts may exist even if draft serialization
                # failed. Never replace them using this outer scope's None locals.
                raise
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
                outcome = PhaseOutcome(
                    request.run_id, receipt["exit_code"], receipt, intent, plan,
                    tuple(lifecycle), None, plan_digest)
                if native_ctx is not None:
                    return _prepare_native_terminal(native_ctx, store, outcome)
                return outcome
            if isinstance(exc, OSError):
                try:
                    store.release_unpublished_run()
                except OSError:
                    pass
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
            if native_ctx is not None:
                return _prepare_native_terminal(native_ctx, store, PhaseOutcome(
                    request.run_id, receipt["exit_code"], receipt, intent, plan,
                    tuple(lifecycle + ["receipt"]), None, plan_digest))
            try:
                store.write_canonical("receipt.json", receipt)
            except OSError:
                try:
                    store.release_unpublished_run()
                except OSError:
                    pass
                raise
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
        native_ctx: _NativeRunContext | None = None,
    ) -> PhaseOutcome:
        plan: dict[str, Any] | None = None
        intent: dict[str, Any] | None = None
        effect_receipts: list[dict[str, Any]] = []
        plan_digest: str | None = None
        from .mutation.ntfs.experimental_file1 import _experimental_admission
        binding = getattr(self.installation, 'read_binding', None)
        admission = None if binding is None else _experimental_admission(binding)
        if admission is not None:
            admission.verify_attachment(binding, request.run_id)
        attachment_digests: list[str] = [] if admission is None else [admission.digest]
        progress_digest: str | None = None
        latest_progress: dict[str, Any] | None = None
        interruption_code: str | None = None
        possible_dispatch = False
        native_authority = None if native_ctx is None else native_ctx.native_authority
        runner = (ValidatorRunner(self.registry) if native_authority is None else
            ValidatorRunner(self.registry, _native_authority=native_authority))
        if native_ctx is not None:
            native_ctx.inner_entered = True
        try:
            reused = self._check_idempotency(store, contract, self.registry, key, scope_digest, request_digest, request.root_bindings, execute=execute, _native_authority=native_authority)
            if execute and reused is not None:
                receipt = self._reused_receipt(request, [], timestamp, reused[0], reused[1], attachment_digests=attachment_digests)
                validate_receipt(receipt, self.registry)
                lifecycle.append("receipt")
                if native_ctx is not None:
                    return _prepare_native_terminal(native_ctx, store, PhaseOutcome(
                        request.run_id, receipt["exit_code"], receipt, None, None,
                        tuple(lifecycle), None, None))
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
            hook = load_contract_hook(contract, **({} if native_authority is None else {"_native_authority":native_authority}))
            if execute and blocking_valid and hook is not None and hasattr(hook, "find_reusable_result"):
                try:
                    prior = hook.find_reusable_result(
                        parse_json_bytes(candidate.canonical_bytes),
                        frozen,
                        request.root_bindings,
                        evidence_root,
                        self.registry,
                    )
                except OSError as exc:
                    raise PhaseError("idempotency.observation_unavailable") from exc
                if prior is not None:
                    receipt = self._reused_receipt(request, validator_results, timestamp, prior[0], prior[1], attachment_digests=attachment_digests)
                    validate_receipt(receipt, self.registry)
                    lifecycle.append("receipt")
                    if native_ctx is not None:
                        return _prepare_native_terminal(native_ctx, store, PhaseOutcome(
                            request.run_id, receipt["exit_code"], receipt, None, None,
                            tuple(lifecycle), None, None))
                    store.write_canonical("receipt.json", receipt)
                    return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, None, None, tuple(lifecycle), profile_digest("receipt", receipt), None)
            lifecycle.append("plan")
            if native_authority is not None:
                plan = native_authority.plan(contract, candidate, frozen, validator_results,
                    roots=request.root_bindings, run_id=request.run_id, timestamp=timestamp,
                    request_digest=request_digest)
            else:
                plan = build_static_plan(contract, candidate, frozen, validator_results,
                    root_bindings=request.root_bindings, run_id=request.run_id, generated_at=timestamp,
                    request_digest=request_digest)
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
            if native_authority is not None:
                intent["phase_intent_version"] = "1.2"
                intent["native_binding"] = native_authority.native_binding()
                intent["evidence"]["pre_validator_results_digest"] = validators_digest
            elif contract.document["identity"]["id"] == "bundle_create.v2":
                intent["phase_intent_version"] = "1.1"
                intent["evidence"]["pre_validator_results_digest"] = validators_digest
            validate_intent(intent, self.registry)
            lifecycle.append("intent")
            if native_ctx is not None:
                native_ctx.original_intent_digest = profile_digest('intent', intent)
                native_ctx.intent_recording_started = True
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
                if native_ctx is not None:
                    native_ctx.broker_entered = True
                try:
                    broker_result = EffectBroker(
                        self.registry,
                        self.installation.authority_provider if native_authority is None else None,
                        self.installation.authority_profile_binding,
                        **({} if native_authority is None else {"_native_authority": native_authority}),
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
                        **({} if native_authority is None else {"_native_intent_digest": intent_digest}),
                    )
                except BrokerExecutionInterrupted as interrupted:
                    effect_receipts = list(interrupted.effect_receipts)
                    possible_dispatch = interrupted.possible_dispatch
                    if native_ctx is not None:
                        native_ctx.possible_dispatch |= possible_dispatch
                        native_ctx.broker_interruption=interrupted.cause
                    if interrupted.progress_digest is not None:
                        progress_digest = interrupted.progress_digest
                        latest_progress = self._ordered_progress(plan, effect_receipts)
                    if isinstance(interrupted.cause, PhaseError):
                        interruption_code = interrupted.cause.code
                    raise interrupted.cause from interrupted
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
            if native_ctx is not None:
                return _prepare_native_terminal(native_ctx, store, PhaseOutcome(
                    request.run_id, receipt["exit_code"], receipt, intent, plan,
                    tuple(lifecycle), None, plan_digest))
            if not active_faults.fail_receipt_write:
                store.write_canonical("receipt.json", receipt)
            receipt_digest = None if active_faults.fail_receipt_write else profile_digest("receipt", receipt)
            return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, intent, plan, tuple(lifecycle), receipt_digest, plan_digest)
        except (PhaseError, OSError) as exc:
            if native_ctx is not None and native_ctx.preparation_attempted:
                raise
            if (native_ctx is not None and native_ctx.broker_interruption is not None
                and native_authority is not None and native_authority._failure_bytes is not None):
                try:
                    from .evidence import _write_native_parent_failure
                    if native_ctx.native_failure_publication_attempted:
                        raise PhaseError('ntfs.native_failure_publication_consumed')
                    native_ctx.native_failure_publication_attempted=True
                    failure=parse_json_bytes(native_authority._failure_bytes,maximum_bytes=2*1024**2)
                    _,failure_digest=_write_native_parent_failure(store,
                        self.installation.read_binding,failure)
                    native_ctx.native_failure_publication_confirmed=True
                    attachment_digests.append(failure_digest)
                except BaseException as secondary:
                    try:exc.add_note('Native parent diagnostic publication: '+type(secondary).__name__)
                    except BaseException:pass
            intent_digest = profile_digest("intent", intent) if intent is not None else None
            if (effect_receipts or possible_dispatch) and intent_digest is not None and contract is not None and plan is not None:
                required_attachments_present = not (native_ctx is not None
                    and native_ctx.native_failure_publication_attempted
                    and not native_ctx.native_failure_publication_confirmed)
                try:
                    _, effects_digest = store.write_or_verify_canonical("attachments/effect-receipts.json", effect_receipts)
                    if effects_digest not in attachment_digests:
                        attachment_digests.append(effects_digest)
                except (PhaseError, OSError):
                    required_attachments_present = False
                if possible_dispatch and len(plan["effects"]) > 1:
                    # Progress1.0 calls every unreceipted effect not_started.
                    # Do not produce that false claim for a lost dispatch. The
                    # first native adapter must admit single-effect plans only;
                    # a future versioned progress format is needed for more.
                    required_attachments_present = False
                elif len(plan["effects"]) > 1:
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
                    finalization_failed=interruption_code is None or not required_attachments_present,
                    required_attachments_present=required_attachments_present,
                    interruption_code=interruption_code,
                    possible_dispatch=possible_dispatch,
                )
                validate_receipt(receipt, self.registry)
                if not lifecycle or lifecycle[-1] != "receipt":
                    lifecycle.append("receipt")
                receipt_digest = None
                if native_ctx is not None:
                    return _prepare_native_terminal(native_ctx, store, PhaseOutcome(
                        request.run_id, receipt["exit_code"], receipt, intent, plan,
                        tuple(lifecycle), None, plan_digest))
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
            if native_ctx is not None:
                return _prepare_native_terminal(native_ctx, store, PhaseOutcome(
                    request.run_id, receipt["exit_code"], receipt, intent, plan,
                    tuple(lifecycle + ["receipt"]), None, plan_digest))
            try:
                store.write_canonical("receipt.json", receipt)
            except OSError:
                try:
                    store.release_unpublished_run()
                except OSError:
                    pass
                raise
            receipt_digest = profile_digest("receipt", receipt)
            return PhaseOutcome(request.run_id, receipt["exit_code"], receipt, intent, plan, tuple(lifecycle + ["receipt"]), receipt_digest, plan_digest)


@contextmanager
def _guard_native_original_intents(read_binding, *, history_bindings=None):
    """Unselected refusal barrier over existing Core evidence, not authority.

    A future trusted native entrypoint must acquire this BEFORE EvidenceStore
    reservation and hold it through dispatch, retained-worker quiescence and
    final evidence. Every overlapping root must share this physical evidence
    root and lock. Normal Core.run/Host routes do not select this helper.
    Executed originals require the exact native terminal attachment and full
    current immutable dependency durability confirmation under this SAME lock.
    Legacy executed originals without that proof remain blocking.
    """
    import re
    import stat
    import sys
    from .canonical import canonical_bytes
    from .evidence import validate_run_id
    from .installation import (_NativeFileCreateReadBinding,
        _resolve_native_file_create_read_binding, _validate_native_history_bindings, _linux_filesystem_type,
        qualify_host_authority_roots)
    from .mutation.ntfs.native import _require
    from .streaming import read_bounded_file

    _require(type(read_binding) is _NativeFileCreateReadBinding,
        'ntfs.original_read_binding_required')
    # Recheck immutable configuration/current registry before any lock write.
    _resolve_native_file_create_read_binding(manifest_bytes=read_binding.manifest_bytes,
        expected_manifest_digest=read_binding.manifest_digest, registry=read_binding.registry)
    manifest=parse_json_bytes(read_binding.manifest_bytes, maximum_bytes=2*1024**2)
    root=Path(manifest['evidence_root']);registry=read_binding.registry
    _require(manifest['native_read_installation_version']!='1.4' or history_bindings is not None,
        'ntfs.original_history_binding_mismatch')
    bindings=((read_binding,) if history_bindings is None else
        _validate_native_history_bindings(read_binding,history_bindings))
    static=tuple((row,parse_json_bytes(row.manifest_bytes,maximum_bytes=2*1024**2)) for row in bindings)

    def historical_binding(contract,core,installation=None):
        # Select ONLY from accepted static data, never from original claims.
        # Contract-only selection is used solely for strict pre-intent rejects.
        matches=[row for row,leaf in static if contract==leaf['contract'] and core==leaf['core']
            and (installation is None or installation=={
                'id':leaf['installation_id'],'descriptor_digest':row.manifest_digest})]
        _require(len(matches)==1,'ntfs.original_history_binding_mismatch')
        return matches[0]
    _require(sys.platform.startswith('linux'), 'ntfs.original_linux_reader_required')
    qualify_host_authority_roots({'phase_evidence_root':root})
    _require(_linux_filesystem_type(root)=='ext4', 'ntfs.original_ext4_evidence_required')
    phase=root/'.phase';runs=phase/'runs'

    def safe_info(path, *, directory):
        try:info=path.lstat()
        except OSError as exc:
            raise PhaseError('ntfs.original_evidence_unavailable') from exc
        _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid==os.geteuid() and not info.st_mode & 0o022,
            'ntfs.original_evidence_object_unsafe')
        if not directory:
            _require(info.st_nlink==1, 'ntfs.original_evidence_object_unsafe')
        return info.st_dev,info.st_ino

    # Existing history is required; never mkdir a missing runs root as empty.
    identity=manifest['evidence_identity']
    _require(safe_info(root,directory=True)==(identity['device'],identity['inode']),
        'ntfs.original_evidence_identity_mismatch')
    anchors={path:safe_info(path,directory=True) for path in (root,phase,runs)}

    def check_anchors():
        for path,expected in anchors.items():
            _require(safe_info(path,directory=True)==expected,
                'ntfs.original_evidence_identity_mismatch')

    def control(path):
        raw=read_bounded_file(path,2*1024**2)
        value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
        _require(canonical_bytes(value)==raw, 'ntfs.original_evidence_not_canonical')
        return value,raw

    def inventory(run):
        # Flat Core-owned blobs/attachments only; do not follow any link or skip
        # a non-directory run. This is not a cached index or a history count cap.
        names=set();attachments={}
        with os.scandir(run) as entries:
            for entry in entries:
                path=run/entry.name;names.add(entry.name)
                if entry.name in {'blobs','attachments'}:
                    safe_info(path,directory=True)
                    with os.scandir(path) as children:
                        for child in children:
                            item=path/child.name;safe_info(item,directory=False)
                            if entry.name=='blobs':
                                _require(re.fullmatch(r'[0-9a-f]{64}',child.name) is not None,
                                    'ntfs.original_evidence_name_unsafe')
                            else:attachments[child.name]=item
                else:
                    safe_info(path,directory=False)
                    _require(entry.name in {'intent.json','receipt.json'},
                        'ntfs.original_evidence_name_unsafe')
        return names,attachments

    def no_effect_receipt(receipt,run_id,attachments,*,planned,selected):
        # Resolve the exact known package before validate_receipt's legacy
        # unknown-package structural fallback can be reached.
        _require(type(receipt) is dict, 'ntfs.original_receipt_binding_mismatch')
        leaf=parse_json_bytes(selected.manifest_bytes,maximum_bytes=2*1024**2)
        _require(receipt.get('contract')==leaf['contract'] and receipt.get('core')==leaf['core']
            and receipt.get('run_id')==run_id, 'ntfs.original_receipt_binding_mismatch')
        binding=receipt['contract']
        registry.resolve_contract(binding['id'],binding['version'],binding['package_digest'],
            core_version=receipt['core']['version'])
        validate_receipt(receipt,registry)
        _require(receipt['terminal_status']==('validated_planned' if planned else 'rejected')
            and receipt['execution_disposition']=='not_executed'
            and receipt['mutation_attempted'] is False
            and receipt['result_state']==('planned_no_effect' if planned else 'none')
            and receipt['canonical_result'] is None and receipt['effect_receipts']==[]
            and receipt['prior_verified_receipt_digest'] is None
            and receipt['recovery_required'] is False
            and receipt['evidence']['finalization_status']=='finalized'
            and 'broker.dispatch_outcome_unknown' not in receipt['blockers'],
            'ntfs.original_history_unresolved')
        if not planned:
            _require(receipt['evidence']['intent_digest'] is None
                and receipt.get('implementation_binding') is None
                and receipt['retry_disposition']=='forbidden' and receipt['exit_code']==10
                and bool(receipt['blockers']), 'ntfs.original_history_unresolved')
        allowed={'effect-plan.json','pre-validator-results.json','validator-results.json'}
        from .mutation.ntfs.experimental_file1 import _experimental_admission
        admission = _experimental_admission(selected)
        if admission is not None:
            admission.verify_attachment(selected, run_id, receipt)
            allowed.add('experimental-admission.json')
        _require(set(attachments)<=allowed, 'ntfs.original_history_unresolved')
        actual={digest_bytes(control(path)[1]) for path in attachments.values()}
        _require(actual==set(receipt['evidence']['attachment_digests'])
            and receipt['evidence']['required_attachments_present']==bool(actual),
            'ntfs.original_attachment_mismatch')

    def native_closure(run, receipt, visited=frozenset()):
        from .mutation.ntfs.proof import verify_native_terminal_proof
        from .evidence import _confirm_native_immutable_files_durable
        _require(type(receipt) is dict and receipt.get('run_id') == run.name,
            'ntfs.original_receipt_binding_mismatch')
        digest = profile_digest('receipt',receipt)
        _require(digest not in visited, 'inspection.prior_receipt_cycle')
        proof,_=control(run/'attachments'/'native-terminal-proof.json')
        _require(type(proof) is dict and type(proof.get('installation')) is dict
            and set(proof['installation'])=={'id','descriptor_digest'},
            'ntfs.original_history_binding_mismatch')
        selected=historical_binding(receipt.get('contract'),receipt.get('core'),proof['installation'])
        checked = verify_native_terminal_proof(selected,run,receipt)
        _require(receipt['evidence']['finalization_status'] == 'finalized'
            and receipt['recovery_required'] is False
            and 'broker.dispatch_outcome_unknown' not in receipt['blockers'],
            'ntfs.original_history_unresolved')
        physical = checked['proof']['physical']
        status,disposition = receipt['terminal_status'],receipt['execution_disposition']
        if status == 'succeeded_verified':
            _require(receipt['evidence']['required_attachments_present'] is True
                and receipt['canonical_result'] is not None and receipt['exit_code'] == 0
                and receipt['blockers'] == [], 'ntfs.original_history_unresolved')
            if disposition == 'reused_existing':
                _require(physical['no_dispatch_safety_established'] is True,
                    'ntfs.original_history_unresolved')
                from .inspection import _prior_receipt_run_id
                prior = _prior_receipt_run_id(runs,run.name,receipt['prior_verified_receipt_digest'])
                prior_receipt,_ = control(runs/prior/'receipt.json')
                _require(prior_receipt['terminal_status'] == 'succeeded_verified'
                    and prior_receipt['contract'] == receipt['contract']
                    and canonical_bytes(prior_receipt['canonical_result']) == canonical_bytes(receipt['canonical_result'])
                    and prior_receipt.get('implementation_binding') == receipt.get('implementation_binding'),
                    'inspection.prior_receipt_mismatch')
                native_closure(runs/prior,prior_receipt,visited|{digest})
            else:
                _require(disposition == 'executed' and physical['parent_safety_established'] is True,
                    'ntfs.original_history_unresolved')
        elif status == 'failed_no_effect':
            _require(disposition == 'executed' and physical['parent_safety_established'] is True
                and receipt['evidence']['required_attachments_present'] is True
                and receipt['canonical_result'] is None,
                'ntfs.original_history_unresolved')
        elif status == 'validated_planned':
            original,_ = control(run/'intent.json')
            _require(original['execution_requested'] is False and disposition == 'not_executed'
                and physical['no_dispatch_safety_established'] is True
                and receipt['evidence']['required_attachments_present'] is True,
                'ntfs.original_history_unresolved')
        else:
            # Preserve the old pre-intent rejection scope. Never use a degraded
            # or unknown-quiescence receipt to discharge an execution original.
            _require(status == 'rejected' and disposition == 'not_executed'
                and physical['no_dispatch_safety_established'] is True
                and receipt['evidence']['intent_digest'] is None
                and 'intent.json' not in {entry.name for entry in run.iterdir()}
                and receipt['canonical_result'] is None and receipt['effect_receipts'] == []
                and receipt['prior_verified_receipt_digest'] is None
                and receipt['retry_disposition'] == 'forbidden' and receipt['exit_code'] == 10
                and bool(receipt['blockers']), 'ntfs.original_history_unresolved')
        # Not an observation-only shortcut: sync all exact immutable bytes and
        # directories, check namespace and consume each close once. No new marker
        # is written and no native target operation/retry is authorized here.
        check_anchors()
        _confirm_native_immutable_files_durable(root,(identity['device'],identity['inode']),
            run.name,checked['immutable_files'])
        check_anchors()

    def check_history():
        with os.scandir(runs) as entries:
            for entry in entries:
                run=runs/entry.name;safe_info(run,directory=True)
                names,attachments=inventory(run)
                abandoned=re.fullmatch(r'\.abandoned-(.+)-([0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15})',entry.name)
                if abandoned:
                    validate_run_id(abandoned.group(1))
                    _require('intent.json' not in names and 'receipt.json' not in names,
                        'ntfs.original_history_unresolved')
                    continue
                validate_run_id(entry.name)
                _require('intent.json' in names or 'receipt.json' in names,
                    'ntfs.original_history_unresolved')
                if 'native-terminal-proof.json' in attachments:
                    _require('receipt.json' in names, 'ntfs.original_history_unresolved')
                    terminal,_ = control(run/'receipt.json')
                    native_closure(run,terminal)
                    continue
                if 'intent.json' not in names:
                    receipt,_=control(run/'receipt.json')
                    _require(type(receipt) is dict,'ntfs.original_receipt_binding_mismatch')
                    selected=historical_binding(receipt.get('contract'),receipt.get('core'))
                    no_effect_receipt(receipt,entry.name,attachments,planned=False,selected=selected)
                    continue
                intent,_=control(run/'intent.json')
                _require(type(intent) is dict and intent.get('phase_intent_version')=='1.2',
                    'ntfs.original_native_intent_required')
                validate_intent(intent,registry)
                _require(intent['run_id']==entry.name and intent['registry_snapshot_digest']==registry.digest,
                    'ntfs.original_intent_mismatch')
                selected=historical_binding(intent['contract'],intent['core'],intent['native_binding']['installation'])
                expected=selected._parser_bindings(intent)
                for key,value in [('installed_core_binding',intent['core']),
                    ('installed_native_binding',intent['native_binding']),
                    ('installed_root_grants',intent['idempotency']['root_identities']),
                    ('installed_implementation_binding',intent['implementation_binding'])]:
                    _require(expected[key]==canonical_bytes(value),
                        'ntfs.original_installation_binding_mismatch')
                # No POSIX observer for an executed native target. Terminal-looking
                # receipts/EOF/no-effect/exit status cannot close a retained worker.
                _require(intent['execution_requested'] is False, 'ntfs.original_history_unresolved')
                _require('receipt.json' in names, 'ntfs.original_history_unresolved')
                receipt,_=control(run/'receipt.json')
                no_effect_receipt(receipt,entry.name,attachments,planned=True,selected=selected)
                for path in attachments.values():
                    control(path)
                blobs=run/'blobs'
                selected_manifest=parse_json_bytes(selected.manifest_bytes,maximum_bytes=2*1024**2)
                if selected_manifest['native_read_installation_version']=='1.4':
                    # Add full fixed-role verification, never replace native
                    # profile/proof policy with successful content validation.
                    digest=profile_digest('intent',intent)
                    _require(receipt['evidence']['intent_digest']==digest
                        and receipt.get('implementation_binding')==intent['implementation_binding']
                        and set(attachments)=={'effect-plan.json','validator-results.json'},
                        'ntfs.original_history_unresolved')
                    validators,_=control(attachments['validator-results.json'])
                    _require(validators==receipt['validator_results'],'ntfs.original_attachment_mismatch')
                    expected_blobs={row['blob_digest'].removeprefix('sha256:') for row in intent['inputs']
                        if row['blob_digest'] is not None}
                    def check_planned_blobs():
                        safe_info(blobs,directory=True)
                        with os.scandir(blobs) as frozen:
                            actual=set()
                            for item in frozen:
                                safe_info(blobs/item.name,directory=False)
                                actual.add(item.name)
                        _require(actual==expected_blobs,'ntfs.original_frozen_input_required')
                    check_planned_blobs()
                    selected.validate_planned(run_id=entry.name,intent_digest=digest)
                    check_planned_blobs();check_anchors()
                elif blobs.exists():
                    # Historical proofless fallback bound remains unchanged.
                    with os.scandir(blobs) as frozen:
                        for item in frozen:
                            _require(item.stat(follow_symlinks=False).st_size<=1024**2,
                                'ntfs.original_frozen_input_required')
                # KEEP the native-installation refusal. Full content alone
                # never closes a proofless native original or grants authority.
                inspect_run(root,entry.name,registry)

    yielded=False;primary_error=None
    try:
        # Purpose is fixed in code, never a request key/nonce/run/installation ID.
        lock_path=operational_lock_path(phase/'locks',digest_bytes(b'phase.native-original-intents.v1'))
        anchors[lock_path.parent]=safe_info(lock_path.parent,directory=True)
        with _OperationalFileLock(lock_path, _checked_release=True) as lock:
            try:
                opened=os.fstat(lock.fileno())
                lock_identity=(opened.st_dev,opened.st_ino)
                def check_lock():
                    check_anchors()
                    _require(safe_info(lock_path,directory=False)==lock_identity,
                        'ntfs.original_evidence_identity_mismatch')
                check_lock()
                check_history();check_lock()
                try:
                    yielded=True
                    yield None
                except BaseException as primary:
                    try:check_lock()
                    except (OSError,PhaseError) as secondary:
                        primary.add_note('Native original guard secondary identity failure: '+str(secondary))
                    raise
                else:check_lock()
            except BaseException as error:
                primary_error=error
                raise
    except BaseException as error:
        if primary_error is not None and error is not primary_error:
            primary_error.add_note('Native original guard secondary lock-finalization failure: '+str(error))
            raise primary_error from error
        if isinstance(error,OSError) and not yielded:
            raise PhaseError('ntfs.original_evidence_unavailable') from error
        raise


def _classify_effect_outcome(plan, validator_results, effect_receipts, *,
    finalization_failed, interruption_code=None, possible_dispatch=False):
    """Existing pure Core classifier, reused by native historical verification.

    No capture, lifecycle, provider, target observation, write or retry permission.
    """
    if type(possible_dispatch) is not bool:
        raise PhaseError("broker.invalid_dispatch_disposition")
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
    if possible_dispatch:
        terminal, result_state, exit_code, recovery = "indeterminate", "indeterminate", 50, True
    elif all_effects_verified and post_verified and not finalization_failed:
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
        interruption_code
        or ("evidence.finalization_failed" if finalization_failed else (error["code"] if error else "verification.incomplete"))
    ]
    if possible_dispatch:
        blockers = sorted(set(blockers + ["broker.dispatch_outcome_unknown"]))
    return terminal,result_state,exit_code,recovery,blockers
