"""One explicit bundle request over the existing Phase Core lifecycle."""
from __future__ import annotations
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict
from .bundle import CONTRACT_BINDING, parse_manifest, read_metadata, validate_members
from .candidate import encode_structured_input
from .canonical import parse_json_bytes, profile_digest
from .errors import PhaseError
from .evidence import read_evidence_bytes, validate_run_id
from .installation import qualify_host_authority_roots
from .paths import contained_target_path, safe_relative_locator
from .publish_file import _root
from .streaming import REQUEST_LIMIT


class PublishBundleResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    publish_bundle_result_version: Literal["1.0"] = "1.0"
    status: Literal["verified", "rejected_before_write", "committed_unverified", "indeterminate"] = "rejected_before_write"
    success: bool = False
    request_id: str
    run_id: str
    evidence_root: str
    target_locator: str
    contract_binding: str = CONTRACT_BINDING
    contract_digest: str | None = None
    bundle_digest: str | None = None
    member_count: int | None = None
    total_length: int | None = None
    receipt_digest: str | None = None
    intent_digest: str | None = None
    effect_plan_digest: str | None = None
    mutation_attempted: bool | None = False
    target_verified: bool = False
    inspection_required: bool = False
    error: str | None = None
    exit_code: int = 10


def publish_bundle(application, *, source_root: Path, members: list[str], target_root: Path,
                   target_locator: str, preparation_root: Path, evidence_root: Path,
                   request_id: str, run_id: str):
    from .application import ApplicationResponse

    result = PublishBundleResult(request_id=request_id, run_id=run_id,
        evidence_root=str(evidence_root), target_locator=target_locator)
    handed_off = False
    lock = None
    try:
        validate_run_id(run_id)
        if not re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*", request_id) or len(request_id) > 128:
            raise PhaseError("bundle.invalid_request_id")
        members = validate_members(members)
        request = {"source_root":str(source_root),"target_root":str(target_root),
            "preparation_root":str(preparation_root),"evidence_root":str(evidence_root),
            "target_locator":target_locator,"members":members,"request_id":request_id,"run_id":run_id}
        if len(encode_structured_input(request)) > REQUEST_LIMIT:
            raise PhaseError("bundle.request_too_large")
        source_root = _root(source_root, existing=True)
        target_root = _root(target_root, existing=True)
        preparation_root = _root(preparation_root, existing=True)
        evidence_root = _root(evidence_root, existing=False)
        roots = [source_root,target_root,preparation_root,evidence_root]
        for index, left in enumerate(roots):
            for right in roots[index+1:]:
                if left.is_relative_to(right) or right.is_relative_to(left):
                    raise PhaseError("bundle.overlapping_roots")
        target_locator = safe_relative_locator(target_locator)
        destination = contained_target_path(target_root,target_locator)
        qualify_host_authority_roots({"phase_result_root":target_root})
        from .mutation.posix.authority import PosixTargetRootLock
        lock = PosixTargetRootLock(target_root,"publish-bundle",timeout_seconds=0)
        lock.__enter__()
        if (evidence_root/".phase/runs"/run_id).exists():
            result.status, result.mutation_attempted, result.exit_code = "indeterminate", None, 40
            raise PhaseError("evidence.run_exists")
        if destination.exists():
            raise PhaseError("bundle.target_exists_inspection_required")
        binding = application._binding(CONTRACT_BINDING)
        result.contract_digest = binding["package_digest"]
        candidate = {"operation_id":request_id,"idempotency_key":request_id,
                     "input_binding":"payload","target_locator":target_locator,"members":members}
        # Candidate only; Core fixes all input bytes and creates the bound manifest.
        with TemporaryDirectory(prefix="phase-bundle-",dir=preparation_root) as temporary:
            from tempfile import NamedTemporaryFile
            with NamedTemporaryFile(mode="wb",suffix=".json",dir=temporary,delete=False) as output:
                output.write(encode_structured_input(candidate))
                candidate_path = Path(output.name)
            handed_off = True
            executed = application.run("execute",contract_binding=CONTRACT_BINDING,
                contract_digest=binding["package_digest"],candidate_path=candidate_path,
                evidence_root=evidence_root,run_id=run_id,input_paths={"payload":source_root},
                root_bindings={"phase_result_root":target_root}).payload
            if executed["run_id"] != run_id:
                result.status, result.mutation_attempted, result.exit_code = "indeterminate", None, 40
                raise PhaseError(executed["error"] or "bundle.execution_unknown")
            for field in ("receipt_digest","intent_digest","effect_plan_digest","mutation_attempted"):
                setattr(result,field,executed[field])
            if executed["success"]:
                result.status,result.exit_code = "committed_unverified",30
            elif executed["mutation_attempted"]:
                result.status,result.exit_code = "indeterminate",40
            if not executed["success"]:
                raise PhaseError(executed["error"] or "bundle.execution_failed")
        inspected = application.inspect(evidence_root=evidence_root,run_id=run_id,
            root_bindings={"phase_result_root":target_root}).payload
        keys = ("run_id","terminal_status","execution_disposition","mutation_attempted",
                "receipt_digest","intent_digest","effect_plan_digest")
        if not inspected["success"] or not inspected["target_verified"] or any(executed[k] != inspected[k] for k in keys):
            raise PhaseError("bundle.inspection_mismatch")
        run = evidence_root/".phase/runs"/run_id
        intent = parse_json_bytes(read_evidence_bytes(run/"intent.json"))
        plan = parse_json_bytes(read_evidence_bytes(run/"attachments/effect-plan.json"))
        if (profile_digest("intent",intent) != result.intent_digest
            or profile_digest("effect-plan",plan) != result.effect_plan_digest
            or intent["candidate"]["storage"]["value"] != candidate
            or intent["contract"] != binding or len(plan["effects"]) != 1):
            raise PhaseError("bundle.evidence_mismatch")
        effect = plan["effects"][0]
        if effect["target"] != {"root_binding":"phase_result_root","relative_locator":target_locator}:
            raise PhaseError("bundle.evidence_mismatch")
        manifest = parse_manifest(read_metadata(run/"blobs"/effect["content_digest"].removeprefix("sha256:")))
        if [item["path"] for item in manifest["members"]] != members:
            raise PhaseError("bundle.evidence_mismatch")
        result.bundle_digest = effect["content_digest"]
        result.member_count = len(members)
        result.total_length = manifest["total_length"]
        result.status,result.success,result.target_verified,result.exit_code = "verified",True,True,0
    except (PhaseError,OSError,ValueError,KeyError,TypeError) as exc:
        result.error = exc.code if isinstance(exc,PhaseError) else "bundle.failure"
        if handed_off and result.receipt_digest is None:
            result.status,result.mutation_attempted,result.exit_code = "indeterminate",None,40
        result.inspection_required = result.status in {"indeterminate","committed_unverified"} or result.error == "bundle.target_exists_inspection_required"
    finally:
        if lock is not None:
            try:
                lock.__exit__(None,None,None)
            except OSError:
                result.status,result.success,result.exit_code = "indeterminate",False,40
                result.error,result.inspection_required = "bundle.lock_finalization_failed",True
    return ApplicationResponse(result.model_dump(),result.exit_code)
