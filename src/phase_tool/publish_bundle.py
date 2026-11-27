"""One explicit bundle request over the existing Phase Core lifecycle."""
from __future__ import annotations
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_serializer, model_validator
from .bundle import CONTRACT_BINDING, _BundleLimitExceeded, parse_manifest, read_metadata, validate_members
from .candidate import encode_structured_input
from .canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from .errors import PhaseError
from .evidence import read_evidence_bytes, validate_run_id
from .installation import qualify_host_authority_roots
from .paths import contained_target_path, safe_relative_locator
from .publish_file import _root, _semantic_replay_enabled
from .streaming import REQUEST_LIMIT


class PublishBundleResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    publish_bundle_result_version: Literal["1.0", "1.1"] = "1.0"
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
    execution_disposition: Literal["not_executed", "executed", "reused_existing"] | None = None
    mutation_attempted: bool | None = False
    target_verified: bool = False
    inspection_required: bool = False
    error: str | None = None
    exit_code: int = 10


    @model_validator(mode="after")
    def _legacy_disposition_unavailable(self):
        if self.publish_bundle_result_version == "1.0" and self.execution_disposition is not None:
            raise ValueError("Legacy bundle result has no execution disposition field")
        return self

    @model_serializer(mode="wrap")
    def _serialize_versioned_result(self, handler):
        value = handler(self)
        if self.publish_bundle_result_version == "1.0":
            value.pop("execution_disposition", None)
        return value


def _require_bundle_projection(reference, projection, *, binding, target_locator, members):
    """Literal correlation of already verified facts; no target or history I/O."""
    if (type(reference) is not dict or reference.get("contract") != binding
        or reference.get("root_binding") != "phase_result_root"
        or reference.get("locator") != target_locator or type(projection) is not dict
        or set(projection) != {"manifest", "manifest_digest", "member_count", "total_length"}):
        raise PhaseError("bundle.evidence_mismatch")
    raw = canonical_bytes(projection["manifest"])
    manifest = parse_manifest(raw)
    digest = digest_bytes(raw)
    if (reference.get("state") != {"exists": True, "digest": digest, "length": len(raw), "head_token": None}
        or projection["manifest_digest"] != digest or type(projection["member_count"]) is not int
        or projection["member_count"] != len(manifest["members"])
        or type(projection["total_length"]) is not int or projection["total_length"] != manifest["total_length"]
        or [item["path"] for item in manifest["members"]] != members):
        raise PhaseError("bundle.evidence_mismatch")
    return manifest, digest


def _bundle_publication_candidate(request_id, target_locator, members):
    """One pure Host/native candidate formula, never an authority selector."""
    if (type(request_id) is not str or len(request_id)>128
        or re.fullmatch(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*",request_id) is None):
        raise PhaseError('bundle.invalid_request_id')
    members=validate_members(members)
    target_locator=safe_relative_locator(target_locator)
    candidate={'operation_id':request_id,'idempotency_key':request_id,'input_binding':'payload',
        'target_locator':target_locator,'members':members}
    raw=encode_structured_input(candidate)
    if len(raw)>REQUEST_LIMIT:
        raise _BundleLimitExceeded('bundle.request_too_large','candidate_bytes',len(raw),REQUEST_LIMIT)
    return candidate,raw


def publish_bundle(application, *, source_root: Path, members: list[str], target_root: Path,
                   target_locator: str, preparation_root: Path, evidence_root: Path,
                   request_id: str, run_id: str, publication_version: str = '1.0'):
    from .application import ApplicationResponse

    result = PublishBundleResult(request_id=request_id, run_id=run_id,
        evidence_root=str(evidence_root), target_locator=target_locator)
    handed_off = False
    semantic_replay = False
    lock = None
    try:
        if publication_version not in {'1.0','2.0'}:
            raise PhaseError('bundle.unsupported_version')
        selected_binding = 'bundle_create.v2@1.1.0' if publication_version == '2.0' else CONTRACT_BINDING
        result.contract_binding = selected_binding
        # Host adapters resolve/lock POSIX targets and own scratch cleanup.
        # Native publication needs prepared Core input and a fresh read-only inspector.
        from .installation import _NativeFileCreateInstallation
        if type(getattr(application, 'installation', None)) is _NativeFileCreateInstallation:
            raise PhaseError('ntfs.high_level_publication_unavailable')
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
        binding = application._binding(selected_binding)
        semantic_replay = _semantic_replay_enabled(application, binding)
        if destination.exists() and not semantic_replay:
            raise PhaseError("bundle.target_exists_inspection_required")
        if semantic_replay:
            result.publish_bundle_result_version = "1.1"
            result.execution_disposition = "not_executed"
        result.contract_digest = binding["package_digest"]
        candidate,candidate_bytes = _bundle_publication_candidate(request_id,target_locator,members)
        # Candidate only; Core fixes all input bytes and creates the bound manifest.
        with TemporaryDirectory(prefix="phase-bundle-",dir=preparation_root) as temporary:
            from tempfile import NamedTemporaryFile
            with NamedTemporaryFile(mode="wb",suffix=".json",dir=temporary,delete=False) as output:
                output.write(candidate_bytes)
                candidate_path = Path(output.name)
            handed_off = True
            executed = application.run("execute",contract_binding=selected_binding,
                contract_digest=binding["package_digest"],candidate_path=candidate_path,
                evidence_root=evidence_root,run_id=run_id,input_paths={"payload":source_root},
                root_bindings={"phase_result_root":target_root},
                _expected_candidate_bytes=candidate_bytes).payload
            if executed["run_id"] != run_id:
                result.status, result.mutation_attempted, result.exit_code = "indeterminate", None, 40
                raise PhaseError(executed["error"] or "bundle.execution_unknown")
            for field in ("receipt_digest","intent_digest","effect_plan_digest","mutation_attempted"):
                setattr(result,field,executed[field])
            if semantic_replay:
                result.execution_disposition = executed["execution_disposition"]
            if executed["success"]:
                result.status,result.exit_code = "committed_unverified",30
            elif executed["mutation_attempted"]:
                result.status,result.exit_code = "indeterminate",40
            if not executed["success"]:
                raise PhaseError(executed["error"] or "bundle.execution_failed")
        reused = executed["execution_disposition"] == "reused_existing"
        reference = projection = None
        if reused and (not semantic_replay or executed["mutation_attempted"] is not False
            or executed["intent_digest"] is not None or executed["effect_plan_digest"] is not None):
            raise PhaseError("bundle.evidence_mismatch")
        if semantic_replay:
            # Core alone compared every projected captured-input field/scope.
            # The same inspector now verifies its original owner and projects
            # the observed manifest; the facade never walks original evidence.
            response, reference, projection = application._inspect_bundle_with_result(
                evidence_root=evidence_root,run_id=run_id,
                root_bindings={"phase_result_root":target_root},
                _expected_candidate_digest=profile_digest("candidate", candidate))
            inspected = response.payload
        else:
            inspected = application.inspect(evidence_root=evidence_root,run_id=run_id,
                root_bindings={"phase_result_root":target_root}).payload
        keys = ("run_id","terminal_status","execution_disposition","mutation_attempted",
                "receipt_digest","intent_digest","effect_plan_digest")
        if not inspected["success"] or not inspected["target_verified"] or any(executed[k] != inspected[k] for k in keys):
            raise PhaseError("bundle.inspection_mismatch")
        if reused:
            manifest, bundle_digest = _require_bundle_projection(reference, projection,
                binding=binding,target_locator=target_locator,members=members)
            result.bundle_digest = bundle_digest
        else:
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

            if semantic_replay:
                observed_manifest, observed_digest = _require_bundle_projection(reference, projection,
                    binding=binding,target_locator=target_locator,members=members)
                if observed_manifest != manifest or observed_digest != result.bundle_digest:
                    raise PhaseError("bundle.evidence_mismatch")
        result.member_count = len(members)
        result.total_length = manifest["total_length"]
        result.status,result.success,result.target_verified,result.exit_code = "verified",True,True,0
    except (PhaseError,OSError,ValueError,KeyError,TypeError) as exc:
        result.error = exc.code if isinstance(exc,PhaseError) else "bundle.failure"
        if handed_off and result.receipt_digest is None:
            result.status,result.mutation_attempted,result.exit_code = "indeterminate",None,40
            if semantic_replay:
                result.execution_disposition = None
        result.inspection_required = result.status in {"indeterminate","committed_unverified"} or result.error == "bundle.target_exists_inspection_required"
    finally:
        if lock is not None:
            try:
                lock.__exit__(None,None,None)
            except OSError:
                result.status,result.success,result.exit_code = "indeterminate",False,40
                result.error,result.inspection_required = "bundle.lock_finalization_failed",True
    return ApplicationResponse(result.model_dump(),result.exit_code)


def _native_bundle_publication_ack(result,ack):
    """Project one validated actual ACK; no evidence, provider or target I/O."""
    for field in ('receipt_digest','intent_digest','effect_plan_digest','execution_disposition','mutation_attempted'):
        result[field]=ack[field]
    if (ack.get('stage3_command_result_version')=='1.2' or ack.get('inspection_required')is True
        or ack['exit_code']==40 or ack['mutation_attempted']is None):
        result.update(status='indeterminate',exit_code=40,inspection_required=True,
            error=ack['error']or'bundle.execution_unknown');return False
    if ack['success']is not True:
        uncertain=ack['mutation_attempted']is not False
        result.update(status='indeterminate'if uncertain else'rejected_before_write',
            exit_code=40 if uncertain else 10,inspection_required=uncertain or (ack['error']or'').startswith('idempotency.'),
            error=ack['error']or'bundle.execution_failed');return False
    result.update(status='committed_unverified',exit_code=30,inspection_required=True)
    if not(ack['command']=='execute'and ack['run_id']==result['run_id']and ack['exit_code']==0
        and ack['error']is None and ack['blockers']==[] and ack['terminal_status']=='succeeded_verified'
        and ack['receipt_digest']and ack['execution_disposition']in{'executed','reused_existing'}):
        raise PhaseError('bundle.evidence_mismatch')
    return True


def _native_bundle_publication_inspected(result,ack,inspected,reference,projection,*,binding,members):
    """Same inspector projection/receipt correlation as Host, no original traversal."""
    fields=('run_id','terminal_status','execution_disposition','mutation_attempted',
        'receipt_digest','intent_digest','effect_plan_digest')
    if (inspected['success']is not True or inspected['target_verified']is not True
        or inspected['exit_code']!=0 or inspected['error']is not None or inspected['blockers']!=[]
        or inspected['terminal_status']!='succeeded_verified'
        or any(ack[field]!=inspected[field]for field in fields)):
        raise PhaseError(inspected['error']or'bundle.inspection_mismatch')
    manifest,digest=_require_bundle_projection(reference,projection,binding=binding,
        target_locator=result['target_locator'],members=members)
    result.update(bundle_digest=digest,member_count=len(manifest['members']),total_length=manifest['total_length'])
