"""Bounded ready-file publication; all target effects remain in Phase Core."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from .candidate import encode_structured_input
from .canonical import parse_json_bytes, profile_digest
from .errors import PhaseError
from .evidence import _reject_existing_links, read_evidence_bytes, validate_run_id
from .freeze import copy_and_hash, revalidate_frozen
from .inspection import _MATERIALIZED_TARGET_LIMITS
from .mutation.exclusive_create import _MAX_CONTENT_BYTES
from .paths import contained_read_path, contained_target_path, safe_relative_locator

if TYPE_CHECKING:
    from .application import ApplicationResponse, PhaseApplication

CONTRACT_BINDING = "file_create.v1@1.0.0"
TARGET_ROOT_BINDING = "phase_result_root"
# The create writer and independent inspector are tighter than copy_and_hash.
MAX_BYTES = min(_MAX_CONTENT_BYTES, _MATERIALIZED_TARGET_LIMITS["mechanism.exclusive_create_v1"])


class PublishFileResult(BaseModel):
    """New closed result schema; historical command/receipt schemas are unchanged."""

    model_config = ConfigDict(extra="forbid", strict=True)
    publish_file_result_version: Literal["1.0"] = "1.0"
    success: bool = False
    status: Literal["verified", "rejected_before_write", "committed_unverified", "indeterminate"]
    request_id: str
    run_id: str
    evidence_root: str
    target_locator: str
    contract_binding: str = CONTRACT_BINDING
    contract_digest: str | None = None
    content_digest: str | None = None
    content_length: int | None = None
    receipt_digest: str | None = None
    intent_digest: str | None = None
    effect_plan_digest: str | None = None
    execution_disposition: str | None = None
    mutation_attempted: bool | None = False
    target_verified: bool = False
    inspection_required: bool = False
    error: str | None = None
    exit_code: int = 10


def _root(path: Path, *, existing: bool) -> Path:
    path = Path(path).absolute()
    _reject_existing_links(path)
    resolved = path.resolve(strict=existing)
    if (existing or resolved.exists()) and not resolved.is_dir():
        raise PhaseError("publish_file.invalid_root")
    return resolved


def publish_file(
    application: PhaseApplication,
    *,
    source_root: Path,
    source_locator: str,
    target_root: Path,
    target_locator: str,
    preparation_root: Path,
    evidence_root: Path,
    request_id: str,
    run_id: str,
    expected_digest: str | None = None,
    publication_version: str = "1.0",
) -> ApplicationResponse:
    from .application import ApplicationResponse

    result = PublishFileResult(
        status="rejected_before_write", request_id=request_id, run_id=run_id,
        evidence_root=str(evidence_root), target_locator=target_locator,
    )
    handed_off = False
    publication_lock = None
    try:
        if publication_version not in {"1.0", "2.0"}:
            raise PhaseError("publish_file.unsupported_version")
        from .streaming import CONTRACT_BINDING as STREAM_BINDING, FILE_LIMIT, REQUEST_LIMIT, copy_and_hash_stream
        if publication_version == "2.0":
            request_bytes = encode_structured_input({
                "source_root": str(source_root), "source_locator": source_locator,
                "target_root": str(target_root), "target_locator": target_locator,
                "preparation_root": str(preparation_root), "evidence_root": str(evidence_root),
                "request_id": request_id, "run_id": run_id,
                "expected_digest": expected_digest, "publication_version": publication_version,
            })
            if len(request_bytes) > REQUEST_LIMIT:
                raise PhaseError("publish_file.request_too_large")
        contract_binding = STREAM_BINDING if publication_version == "2.0" else CONTRACT_BINDING
        capture = copy_and_hash_stream if publication_version == "2.0" else copy_and_hash
        maximum_bytes = FILE_LIMIT if publication_version == "2.0" else MAX_BYTES
        result.contract_binding = contract_binding
        validate_run_id(run_id)
        if not re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*", request_id) or len(request_id) > 128:
            raise PhaseError("publish_file.invalid_request_id")
        if expected_digest is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
            raise PhaseError("publish_file.invalid_expected_digest")
        source_root = _root(source_root, existing=True)
        target_root = _root(target_root, existing=True)
        preparation_root = _root(preparation_root, existing=True)
        evidence_root = _root(evidence_root, existing=False)
        roots = (source_root, target_root, preparation_root, evidence_root)
        for index, left in enumerate(roots):
            for right in roots[index + 1:]:
                if left.is_relative_to(right) or right.is_relative_to(left):
                    raise PhaseError("publish_file.overlapping_roots")
        result.evidence_root = str(evidence_root)
        if publication_version == "2.0":
            from .installation import qualify_host_authority_roots
            qualify_host_authority_roots({TARGET_ROOT_BINDING: target_root})
            from .mutation.posix.authority import PosixTargetRootLock
            publication_lock = PosixTargetRootLock(target_root, "publish-file-v2", timeout_seconds=0)
            publication_lock.__enter__()
        source_locator = safe_relative_locator(source_locator)
        target_locator = safe_relative_locator(target_locator)
        contained_read_path(source_root, source_locator)
        destination = contained_target_path(target_root, target_locator)
        if (evidence_root / ".phase" / "runs" / run_id).exists():
            result.status = "indeterminate"
            result.mutation_attempted = None
            result.exit_code = 40
            raise PhaseError("evidence.run_exists")
        if destination.exists():
            result.inspection_required = True
            raise PhaseError("publish_file.target_exists_inspection_required")
        binding = application._binding(contract_binding)
        result.contract_digest = binding["package_digest"]
        candidate = {
            "operation_id": request_id, "idempotency_key": request_id,
            "input_binding": "payload", "target_locator": target_locator,
        }
        candidate_bytes = encode_structured_input(candidate)
        if len(candidate_bytes) > 1_048_576:
            raise PhaseError("candidate.too_large")
        # Explicit isolated scratch: callers supply roots, never candidates/blobs.
        with TemporaryDirectory(prefix="phase-publish-", dir=preparation_root) as scratch:
            frozen = capture(
                "payload", source_root, source_locator, Path(scratch),
                frozen_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                maximum_bytes=maximum_bytes,
            )
            result.content_digest = frozen.digest
            result.content_length = frozen.length
            if expected_digest is not None and frozen.digest != expected_digest:
                raise PhaseError("publish_file.source_digest_mismatch")
            revalidate_frozen(frozen)
            assert frozen.blob_path is not None
            with NamedTemporaryFile(mode="wb", suffix=".json", dir=scratch, delete=False) as temporary:
                temporary.write(candidate_bytes)
                candidate_path = Path(temporary.name)
            handed_off = True
            executed = application.run(
                "execute", contract_binding=contract_binding,
                contract_digest=binding["package_digest"], candidate_path=candidate_path,
                evidence_root=evidence_root, run_id=run_id,
                input_paths={"payload": frozen.blob_path},
                expected_inputs={"payload": (frozen.digest, frozen.length)},
                root_bindings={TARGET_ROOT_BINDING: target_root},
            )
            # Preserve the returned execution evidence before fallible cleanup.
            payload = executed.payload
            for field in ("receipt_digest", "intent_digest", "effect_plan_digest", "execution_disposition", "mutation_attempted"):
                setattr(result, field, payload[field])
            if payload["run_id"] != run_id:
                result.status = "indeterminate"
                result.mutation_attempted = None
                result.execution_disposition = None
                result.exit_code = 40
            elif payload["success"]:
                result.status = "committed_unverified"
                result.exit_code = 30
            elif payload["mutation_attempted"]:
                result.status = "indeterminate"
                result.exit_code = 40
        if payload["run_id"] != run_id:
            result.status = "indeterminate"
            result.mutation_attempted = None
            result.exit_code = 40
            raise PhaseError(payload["error"] or "publish_file.execution_unknown")
        if not payload["success"]:
            result.status = "indeterminate" if payload["mutation_attempted"] else "rejected_before_write"
            result.exit_code = 40 if payload["mutation_attempted"] else 10
            raise PhaseError(payload["error"] or "publish_file.execution_failed")
        result.status = "committed_unverified"
        result.exit_code = 30
        inspected = application.inspect(
            evidence_root=evidence_root, run_id=run_id,
            root_bindings={TARGET_ROOT_BINDING: target_root},
        ).payload
        if not inspected["success"]:
            raise PhaseError(inspected["error"] or "publish_file.inspection_failed")
        compared = ("run_id", "terminal_status", "execution_disposition", "mutation_attempted", "receipt_digest", "intent_digest", "effect_plan_digest")
        if any(payload[key] != inspected[key] for key in compared):
            raise PhaseError("publish_file.evidence_mismatch")
        if inspected["target_verified"] is not True or not result.receipt_digest or payload["terminal_status"] != "succeeded_verified":
            raise PhaseError("publish_file.not_verified")
        run_root = evidence_root / ".phase" / "runs" / run_id
        intent = parse_json_bytes(read_evidence_bytes(run_root / "intent.json"))
        plan = parse_json_bytes(read_evidence_bytes(run_root / "attachments" / "effect-plan.json"))
        if (
            profile_digest("intent", intent) != result.intent_digest
            or profile_digest("effect-plan", plan) != result.effect_plan_digest
            or intent["candidate"]["storage"]["value"] != candidate
            or intent["contract"] != binding
            or intent["idempotency"]["key"] != request_id
            or len(plan["effects"]) != 1
        ):
            raise PhaseError("publish_file.evidence_mismatch")
        effect = plan["effects"][0]
        if (
            effect["target"] != {"root_binding": TARGET_ROOT_BINDING, "relative_locator": target_locator}
            or effect["content_digest"] != result.content_digest
            or effect["content_length"] != result.content_length
            or effect["kind"] != "exclusive_create"
        ):
            raise PhaseError("publish_file.evidence_mismatch")
        result.success = True
        result.status = "verified"
        result.target_verified = True
        result.exit_code = 0
    except (PhaseError, OSError, ValueError) as exc:
        result.error = exc.code if isinstance(exc, PhaseError) else "publish_file.failure"
        if handed_off and result.execution_disposition is None and result.status != "indeterminate":
            result.status = "indeterminate"
            result.mutation_attempted = None
            result.exit_code = 40
        if result.status in {"committed_unverified", "indeterminate"} or result.error.startswith("idempotency."):
            result.inspection_required = True
    finally:
        if publication_lock is not None:
            try:
                publication_lock.__exit__(None, None, None)
            except OSError:
                result.success = False
                result.status = "indeterminate"
                result.inspection_required = True
                result.error = "publish_file.lock_finalization_failed"
                result.exit_code = 40
    return ApplicationResponse(result.model_dump(), result.exit_code)
