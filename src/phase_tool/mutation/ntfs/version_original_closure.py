"""Closed read-only Version Original verification for explicit continuation.

No target read/write, registry/provider selection, receipt publication or retry
permission. Existing Original parser, terminal proof and Evidence owner remain
authoritative. A missing original receipt stays missing. Namespace/runtime trust
and genuine witnessed process facts remain external deployment prerequisites.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os,threading

from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from ...errors import PhaseError
from .native import _require

ROLES=('Version1','Version2')


def version_original_role(binding):
    from ...installation import _NativeFileCreateReadBinding
    from .owner_directory_fixture import _kinds
    from .owner_semantic_contracts import semantic_owner_contract
    _require(type(binding)is _NativeFileCreateReadBinding,'recovery.closed_native_version_required')
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    matches=[role for role in ROLES if manifest.get('native_read_installation_version')==_kinds()[role]._manifest_version
        and manifest.get('contract')in(_kinds()[role]._contract,semantic_owner_contract(role))]
    _require(len(matches)==1,'recovery.closed_native_version_required')
    role=matches[0]
    context=getattr(binding,'_owner_directory_context',None)
    if context is not None:
        # Closed ordinary4 context remains its own trusted installation owner.
        # No profile/catalog data is accepted from a saved intent or request.
        from .owner_directory import require_owner_directory_binding
        require_owner_directory_binding(binding,role)
    else:
        admission=binding.experimental_admission
        _require(type(admission)is _kinds()[role],'recovery.closed_native_version_required')
        admission.check_binding(binding);admission.profile(binding)
    return role,manifest


def _canonical(path):
    from ...evidence import _reject_existing_links
    from ...streaming import read_bounded_file
    _reject_existing_links(path)
    raw=read_bounded_file(path,2*1024**2)
    value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
    _require(canonical_bytes(value)==raw,'recovery.original_not_canonical')
    return value,raw



def _version_attachment_shape(admission_present,names):
    experimental={'experimental-admission.json','experimental-attempt.json'}
    _require(type(admission_present)is bool and type(names)is set,'recovery.version_attachment_binding')
    _require(not(names&experimental)if not admission_present else 'experimental-admission.json'in names,'recovery.version_attachment_binding')


def _verify_version_admission_attachments(binding,role,run_id,files):
    from .experimental_file1 import _experimental_admission
    admission=_experimental_admission(binding)
    names={name.split('/')[1]for name in files if name.startswith('attachments/')}
    _version_attachment_shape(admission is not None,names)
    if admission is None:
        from .owner_directory import require_owner_directory_binding
        require_owner_directory_binding(binding,role)
    else:admission.verify_attachment(binding,run_id)

def _receipt_from_saved_commitment(binding,run,intent,plan,proof,files):
    """Reconstruct only the normal fully prepared Core value, READ ONLY.

    This recovers bytes committed by native-terminal-proof's existing prepared
    digest. It neither inserts receipt.json nor calls that absent object final.
    A partial/foreign/missing record or nonmatching digest is an error; there is
    no status guessing, flag search, target observation or semantic downgrade.
    """
    from ...core import PhaseCore,PhaseRequest,CORE_BINDING
    _require(intent['core']==CORE_BINDING,'recovery.pending_core_generation_unsupported')
    validators,_=_canonical(run/'attachments/validator-results.json')
    effects,_=_canonical(run/'attachments/effect-receipts.json')
    _require(type(validators)is list and type(effects)is list and len(effects)==1,
        'recovery.original_terminal_records_required')
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    request=PhaseRequest(intent['contract']['id'],intent['contract']['version'],intent['contract']['package_digest'],
        run/'intent.json',Path(manifest['evidence_root']),intent['run_id'],{},
        {key:Path(value)for key,value in manifest['root_projections'].items()})
    # Same Core's pure deterministic builder only, no new lifecycle/coordinator.
    core=object.__new__(PhaseCore);core.registry=binding.registry
    attachments=[value[0]for name,value in files.items()
                 if name.startswith('attachments/')and name!='attachments/native-terminal-proof.json']
    # The Core flag describes unresolved dispatch, not a known worker having
    # run. Passing True forces an indeterminate receipt and cannot reconstruct
    # a successful terminal commitment. The digest comparison below and the
    # caller's full terminal proof verification still establish the closure.
    prepared=core._executed_receipt(request,
        binding.registry.resolve_contract(intent['contract']['id'],intent['contract']['version'],intent['contract']['package_digest'],
            core_version=intent['core']['version']),
        plan,validators,effects,intent['created_at'],profile_digest('intent',intent),attachments,
        intent['implementation_binding'],finalization_failed=False,required_attachments_present=True,
        interruption_code=None,possible_dispatch=False)
    _require(profile_digest('receipt',prepared)==proof['prepared_receipt_digest'],
        'recovery.original_pending_receipt_unconfirmed')
    receipt=parse_json_bytes(canonical_bytes(prepared))
    proof_digest=files['attachments/native-terminal-proof.json'][0]
    receipt['evidence']['attachment_digests']=sorted(set(attachments+[proof_digest]))
    return receipt


def verify_closed_version_original(binding,run_id,request_id,expected_intent_digest):
    """Exact immutable Original + affirmative worker/IO/owner closure only.

    The result is not current-target verification or permission to mutate. A
    separate fresh native contract classification under the common guard is
    mandatory immediately before any explicit same-operation continuation.
    """
    from ...evidence import validate_run_id,validate_receipt
    from .bundle_recovery_original import native_inventory,verify_quiescence
    from .proof import verify_native_terminal_proof
    role,manifest=version_original_role(binding)
    validate_run_id(run_id)
    root=binding.check_evidence_root();run=root/'.phase'/'runs'/run_id
    intent,_=_canonical(run/'intent.json');plan,_=_canonical(run/'attachments/effect-plan.json')
    _require(intent['run_id']==run_id and intent['execution_requested']is True
        and intent['contract']==manifest['contract']and intent['core']==manifest['core']
        and intent['idempotency']['key']==request_id
        and profile_digest('intent',intent)==expected_intent_digest
        and intent['effect_plan_digest']==profile_digest('effect-plan',plan),
        'recovery.request_conflict')
    # Real existing full semantic parser, including all frozen bytes/admission.
    projection=binding.read(run_id=run_id,intent_digest=expected_intent_digest)
    before=native_inventory(binding,run)
    _verify_version_admission_attachments(binding,role,run_id,before)
    from .version_lineage import verify_version_lineage
    verify_version_lineage(binding,run,intent)
    if 'attachments/native-terminal-proof.json'not in before:
        _require('receipt.json'not in before and 'attachments/native-parent-failure.json'in before,
            'recovery.original_closed_completion_required')
        from .version_failure_completion import verify_version_failure_completion
        failure,_raw=_canonical(run/'attachments/native-parent-failure.json')
        closed=verify_version_failure_completion(binding,projection,intent,plan,failure)
        allowed={'effect-plan.json','pre-validator-results.json','validator-results.json','effect-receipts.json',
            'experimental-admission.json','experimental-attempt.json','native-parent-failure.json','native-version-lineage.json'}
        names={name.split('/')[1]for name in before if name.startswith('attachments/')}
        _require(names<=allowed and {'effect-plan.json','pre-validator-results.json','native-parent-failure.json'}<=names,
            'recovery.original_dependency_set_mismatch')
        from .experimental_file1 import _experimental_admission
        admission=_experimental_admission(binding)
        if admission is not None:admission.verify_attachment(binding,run_id)
        if 'effect-receipts.json'in names:
            effects,_raw=_canonical(run/'attachments/effect-receipts.json')
            _require(effects in([],[closed['parent']['completion']['effect_receipt']]),
                'recovery.original_terminal_records_required')
        after=native_inventory(binding,run)
        _require(before==after,'recovery.original_changed')
        binding.check_evidence_root()
        return {'role':role,'run':run,'intent':intent,'plan':plan,'projection':projection,
            'closure_kind':'validated_parent_failure_completion','receipt_present':False,
            'verification_receipt':None,'original_receipt_digest':None,'original_terminal_status':None,
            'proof':None,'proof_digest':before['attachments/native-parent-failure.json'][0],
            'target_identities':closed['target_identities'],'files':before,
            'original_files':{name:row for name,row in before.items()if not name.startswith('recovery/')},
            'failure_completion':closed,
            'scope':'VALIDATED_PARENT_FAILURE_CLOSURE_NOT_TERMINAL_PROOF_OR_CURRENT_TARGET_SUCCESS'}
    proof,_=_canonical(run/'attachments/native-terminal-proof.json')
    receipt_present='receipt.json'in before
    if receipt_present:
        receipt,_=_canonical(run/'receipt.json')
    else:
        receipt=_receipt_from_saved_commitment(binding,run,intent,plan,proof,before)
    validate_receipt(receipt,binding.registry)
    _require(receipt['run_id']==run_id and receipt['evidence']['intent_digest']==expected_intent_digest
        and receipt['execution_disposition']=='executed'and receipt['mutation_attempted']is True,
        'recovery.original_receipt_mismatch')
    checked=verify_native_terminal_proof(binding,run,receipt)
    physical=checked['proof']['physical']
    _require(physical['parent_safety_established']is True
        and physical['possible_dispatch']is True and physical['no_dispatch_safety_established']is False
        and physical['local_channel_sealed']is True and physical['server_ingress_sealed']is True
        and checked['proof']['common_guard_finalized']is True,
        'recovery.original_worker_not_quiescent')
    parent=physical['parent_response']
    # Strong existing source-bound creation-HANDLE event sequence, not PID/EOF.
    verify_quiescence(parent,parent['completion'])
    original_files=dict(checked['immutable_files'])
    if not receipt_present:
        # The proof verifier accepts its logical prepared value; do NOT invent
        # a physical receipt file or durability-confirm an absent object.
        original_files.pop('receipt.json')
    actual_original={name:value for name,value in before.items()if not name.startswith('recovery/')}
    _require(original_files==actual_original,'recovery.original_dependency_set_mismatch')
    after=native_inventory(binding,run)
    _require(before==after,'recovery.original_changed')
    binding.check_evidence_root()
    return {'role':role,'run':run,'intent':intent,'plan':plan,'projection':projection,
        'closure_kind':'native_terminal_proof','receipt_present':receipt_present,'verification_receipt':receipt,
        'original_receipt_digest':profile_digest('receipt',receipt)if receipt_present else None,
        'original_terminal_status':receipt['terminal_status']if receipt_present else None,
        'proof':checked['proof'],'proof_digest':checked['attachment_digest'],
        'target_identities':checked['target_identity'],'files':before,'original_files':original_files,
        'scope':'VERIFIED_ORIGINAL_CLOSURE_NOT_CURRENT_TARGET_OR_CONTINUATION_AUTHORITY'}


@dataclass(frozen=True)
class _NativeVersionOriginalClosure:
    binding:object
    run_id:str
    request_id:str
    intent_digest:str
    files:tuple
    owner:tuple

    def check(self,run):
        _require(type(self)is _NativeVersionOriginalClosure
            and self.owner==(os.getpid(),threading.get_ident())
            and run.name==self.run_id
            and run==Path(parse_json_bytes(self.binding.manifest_bytes)['evidence_root'])/'.phase'/'runs'/self.run_id,
            'recovery.selected_original_mismatch')
        checked=verify_closed_version_original(self.binding,self.run_id,self.request_id,self.intent_digest)
        _require(tuple(sorted(checked['files'].items()))==self.files,'recovery.original_changed')
        return checked


@dataclass(frozen=True)
class _NativeVersionContinuationSelection:
    closure:_NativeVersionOriginalClosure
    new_run_id:str

    @property
    def binding(self):return self.closure.binding
    @property
    def run_id(self):return self.closure.run_id
    @property
    def original_run_id(self):return self.closure.run_id
    @property
    def request_id(self):return self.closure.request_id
    @property
    def intent_digest(self):return self.closure.intent_digest

    def check(self,run):
        _require(type(self)is _NativeVersionContinuationSelection
            and type(self.closure)is _NativeVersionOriginalClosure,'recovery.selected_original_mismatch')
        return self.closure.check(run)


def closed_version_original_selection(binding,run_id,request_id,intent_digest):
    """Closure-only durability token. No fabricated new attempt identity."""
    value=verify_closed_version_original(binding,run_id,request_id,intent_digest)
    return _NativeVersionOriginalClosure(binding,run_id,request_id,intent_digest,
        tuple(sorted(value['files'].items())),(os.getpid(),threading.get_ident()))


def select_closed_version_original(binding,*,original_run_id,new_run_id,request_id,intent_digest):
    from ...evidence import validate_run_id
    validate_run_id(original_run_id);validate_run_id(new_run_id)
    _require(original_run_id!=new_run_id,'recovery.new_attempt_required')
    closure=closed_version_original_selection(binding,original_run_id,request_id,intent_digest)
    return _NativeVersionContinuationSelection(closure,new_run_id)
