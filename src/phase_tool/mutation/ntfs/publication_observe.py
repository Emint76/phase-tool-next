"""Observe existing File1/File2/Bundle1 through SAME Native inspection owner.

SOURCE candidate. No worker, GO, effect, receipt repair, recovery commit, new
journal or permission to retry. A known worker closure is a prerequisite, not
something inferred from a fresh hash or from this detached observation.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os
import re
import threading

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from .native import _require

_ROLES={'file_create.v1':'File1','file_create.v2':'File2','bundle_create.v1':'Bundle1'}
_OBSERVATION_KEYS = {
    'native_publication_observation_version', 'run_id', 'request_id', 'intent_digest',
    'effect_plan_digest', 'installation_digest', 'registry_snapshot_digest',
    'original_files', 'observation', 'recovery_mutation_attempted',
}


def publication_observe_role(binding):
    from ...installation import _NativeFileCreateReadBinding
    from .owner_directory_fixture import _kinds
    from .owner_semantic_contracts import semantic_owner_contract
    _require(type(binding)is _NativeFileCreateReadBinding,'recovery.closed_publication_observer_required')
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    role=_ROLES.get(manifest.get('contract',{}).get('id'))
    _require(role is not None and manifest['native_read_installation_version']==_kinds()[role]._manifest_version
        and manifest['contract']in(_kinds()[role]._contract,semantic_owner_contract(role)),
        'recovery.closed_publication_observer_required')
    if getattr(binding,'_owner_directory_context',None)is not None:
        from .owner_directory import require_owner_directory_binding
        require_owner_directory_binding(binding,role)
    else:
        from .experimental_file1 import _experimental_admission
        admission=_experimental_admission(binding)
        if admission is not None:admission.check_binding(binding);admission.profile(binding)
        else:
            # Same qualified-profile guard; no fixture/evidence predicate grants
            # a profile. Current unqualified ordinary route stays closed.
            from ...installation import _native_qualified_profile
            _native_qualified_profile(binding.registry,manifest['authority']['profile'],**({'_file2':True}if role=='File2'else{}))
    return role,manifest


def verify_closed_publication_original(binding,run_id,request_id,intent_digest):
    from ...evidence import validate_run_id,validate_receipt
    from .version_original_closure import _canonical,_receipt_from_saved_commitment
    from .bundle_recovery_original import native_inventory,verify_quiescence
    from .proof import verify_native_terminal_proof
    role,manifest=publication_observe_role(binding);validate_run_id(run_id)
    run=binding.check_evidence_root()/'.phase/runs'/run_id
    intent,_=_canonical(run/'intent.json');plan,_=_canonical(run/'attachments/effect-plan.json')
    _require(intent['run_id']==run_id and intent['execution_requested']is True
        and intent['contract']==manifest['contract']and intent['core']==manifest['core']
        and intent['registry_snapshot_digest']==binding.registry.digest
        and intent['idempotency']['key']==request_id and profile_digest('intent',intent)==intent_digest
        and intent['effect_plan_digest']==profile_digest('effect-plan',plan)
        and len(plan['effects'])==1,'recovery.request_conflict')
    projection=binding.read(run_id=run_id,intent_digest=intent_digest)
    before=native_inventory(binding,run)
    # This subset requires affirmative terminal closure. Proofless, live and
    # unknown workers stay blocked; no failure evidence is silently promoted.
    _require('attachments/native-terminal-proof.json'in before,'recovery.original_closed_completion_required')
    proof,_=_canonical(run/'attachments/native-terminal-proof.json')
    present='receipt.json'in before
    receipt=(_canonical(run/'receipt.json')[0]if present else
        _receipt_from_saved_commitment(binding,run,intent,plan,proof,before))
    validate_receipt(receipt,binding.registry)
    _require(receipt['run_id']==run_id and receipt['evidence']['intent_digest']==intent_digest
        and receipt['execution_disposition']=='executed'and receipt['mutation_attempted']is True,
        'recovery.original_receipt_mismatch')
    checked=verify_native_terminal_proof(binding,run,receipt);physical=checked['proof']['physical']
    _require(physical['parent_safety_established']is True and physical['possible_dispatch']is True
        and physical['no_dispatch_safety_established']is False and physical['local_channel_sealed']is True
        and physical['server_ingress_sealed']is True and checked['proof']['common_guard_finalized']is True,
        'recovery.original_worker_not_quiescent')
    verify_quiescence(physical['parent_response'],physical['parent_response']['completion'])
    files=dict(checked['immutable_files'])
    if not present:files.pop('receipt.json')
    _require(files=={n:v for n,v in before.items()if not n.startswith('recovery/')}
        and before==native_inventory(binding,run),'recovery.original_changed')
    binding.check_evidence_root()
    return {'role':role,'manifest':manifest,'run':run,'intent':intent,'plan':plan,'projection':projection,
        'closure_kind':'native_terminal_proof','receipt_present':present,
        'original_receipt_digest':profile_digest('receipt',receipt)if present else None,
        'original_terminal_status':receipt['terminal_status']if present else None,
        'target_identity':checked['target_identity'],'files':before}


@dataclass(frozen=True)
class _NativePublicationObserveSelection:
    binding:object
    run_id:str
    request_id:str
    intent_digest:str
    files:tuple
    owner:tuple

    def check(self,run):
        _require(type(self)is _NativePublicationObserveSelection and self.owner==(os.getpid(),threading.get_ident())
            and run==Path(parse_json_bytes(self.binding.manifest_bytes)['evidence_root'])/'.phase/runs'/self.run_id,
            'recovery.selected_original_mismatch')
        value=verify_closed_publication_original(self.binding,self.run_id,self.request_id,self.intent_digest)
        _require(tuple(sorted(value['files'].items()))==self.files,'recovery.original_changed')
        return value


def select_closed_publication_observation(binding,run_id,request_id,intent_digest):
    value=verify_closed_publication_original(binding,run_id,request_id,intent_digest)
    return publication_observation_selection(binding, value)


def publication_observation_selection(binding, value):
    intent = value['intent']
    return _NativePublicationObserveSelection(binding, intent['run_id'],
        intent['idempotency']['key'], profile_digest('intent', intent),
        tuple(sorted(value['files'].items())),(os.getpid(),threading.get_ident()))


def classify_publication_observation(original,observation):
    """Existing validators own Native shape/Bundle owner+manifest correlation."""
    effect=original['plan']['effects'][0];role=original['role']
    grant=original['manifest']['root_grants'][0];locator=effect['target']['relative_locator']
    if role=='Bundle1':
        from .bundle_execution import validate_bundle_observation,bundle_postcondition
        checked=validate_bundle_observation(observation,grant,locator,projection=original['projection'])
        status,*_=bundle_postcondition(checked,grant_data=grant,effect=effect,projection=original['projection'])
        content_ok=status=='pass'
    elif role=='File2':
        from .file2_execution import validate_file2_observation
        checked=validate_file2_observation(observation,grant,locator)
        content_ok=checked['state']['digest']==effect['content_digest']and checked['state']['length']==effect['content_length']
    else:
        _require(role=='File1','recovery.closed_publication_observer_required')
        from .parent_result import _observation
        checked=_observation(observation,grant,locator)
        content_ok=checked['state']['digest']==effect['content_digest']and checked['state']['length']==effect['content_length']
    return (content_ok and checked['state']['exists']is True and original['target_identity']is not None
        and checked['native']['native_identity']==original['target_identity'])


def validate_publication_observation_shape(value, intent):
    _require(type(value) is dict and set(value) == _OBSERVATION_KEYS
        and value['native_publication_observation_version'] == '1.0'
        and intent['contract']['id'] in _ROLES
        and value['run_id'] == intent['run_id']
        and value['request_id'] == intent['idempotency']['key']
        and value['intent_digest'] == profile_digest('intent', intent)
        and value['effect_plan_digest'] == intent['effect_plan_digest']
        and value['registry_snapshot_digest'] == intent['registry_snapshot_digest']
        and type(value['installation_digest']) is str
        and re.fullmatch(r'sha256:[0-9a-f]{64}', value['installation_digest'])
        and type(value['original_files']) is dict
        and type(value['observation']) is dict
        and value['recovery_mutation_attempted'] is False,
        'recovery.publication_observation_mismatch')


def _publication_observation_value(binding, original, observation):
    intent = original['intent']
    return {
        'native_publication_observation_version': '1.0',
        'run_id': intent['run_id'],
        'request_id': intent['idempotency']['key'],
        'intent_digest': profile_digest('intent', intent),
        'effect_plan_digest': intent['effect_plan_digest'],
        'installation_digest': binding.manifest_digest,
        'registry_snapshot_digest': binding.registry.digest,
        'original_files': {name: list(row) for name, row in original['files'].items()
            if not name.startswith('recovery/')},
        'observation': observation,
        'recovery_mutation_attempted': False,
    }


def verify_saved_publication_observations(binding, original):
    """Verify historical observation bytes after independent Original closure."""
    from .bundle_recovery_original import native_inventory
    from .version_original_closure import _canonical

    observations = []
    for name, (digest, size) in sorted(original['files'].items()):
        if not name.startswith('recovery/'):
            continue
        _require(name == 'recovery/' + digest[7:] + '.json',
            'recovery.publication_observation_mismatch')
        value, raw = _canonical(original['run'] / name)
        validate_publication_observation_shape(value, original['intent'])
        expected = _publication_observation_value(binding, original, value['observation'])
        _require(digest_bytes(raw) == digest and len(raw) == size and canonical_bytes(expected) == raw
            and classify_publication_observation(original, value['observation']),
            'recovery.publication_observation_mismatch')
        observations.append({'digest': digest, 'observation': value})
    _require(bool(observations), 'recovery.publication_observation_required')
    _require(original['files'] == native_inventory(binding, original['run']), 'recovery.original_changed')
    return tuple(observations)


def _persist_publication_observation(selection, original, observed):
    """Call only after sealing the inspection channel inside the common guard."""
    from ...evidence import _open_native_recovery_store, _write_native_recovery_canonical, _close_native_recovery_store
    from .bundle_recovery_original import native_inventory

    binding = selection.binding
    value = _publication_observation_value(binding, original, observed)
    validate_publication_observation_shape(value, original['intent'])
    raw = canonical_bytes(value)
    digest = digest_bytes(raw)
    leaf = digest[7:] + '.json'
    store = _open_native_recovery_store(binding, selection.run_id, _publication_selection=selection)
    primary = None
    try:
        path, recorded_digest = _write_native_recovery_canonical(store, leaf, value)
        _require(path == original['run'] / 'recovery' / leaf and recorded_digest == digest,
            'recovery.publication_observation_mismatch')
        expected = original['files'] | {'recovery/' + leaf: (digest, len(raw))}
        _require(native_inventory(binding, original['run']) == expected, 'recovery.original_changed')
        return path, digest
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            _close_native_recovery_store(store)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note('Publication observation Evidence finalization: ' + str(error))


def recover_native_publication_observe(application,*,evidence_root,run_id,target_root,request_id,expected_intent_digest,mode='observe'):
    """Observe the target read-only and append a guarded Evidence observation.

    The saved record binds past observations only. A later common guard
    revalidates the closed Original and confirms the exact files' durability.
    A missing Original receipt stays missing.
    """
    from ...application import ApplicationResponse
    from ...recovery import NativeRecoveryResult
    from ...continuation_progress import LockFinalization
    from ...installation import _NativeFileCreateInstallation
    from ...core import _guard_native_original_intents
    from .uncertainty import _diagnostic
    result=NativeRecoveryResult(run_id=run_id,request_id=request_id,recovery_mutation_attempted=False)
    # Unsupported commit is rejected before selecting/reading Original or IO.
    if mode!='observe':
        result.status='rejected';result.error='recovery.unsupported_mode';result.exit_code=10
        return ApplicationResponse(result.model_dump(),result.exit_code)
    authority=None
    try:
        installed=application.installation
        _require(type(installed)is _NativeFileCreateInstallation,'recovery.closed_publication_observer_required')
        authority=installed.authority;binding=installed.read_binding
        role,manifest=publication_observe_role(binding)
        contract=binding.registry.resolve_contract(manifest['contract']['id'],manifest['contract']['version'],
            manifest['contract']['package_digest'],core_version=manifest['core']['version'])
        authority.require_contract(contract)
        _require(authority.read_binding is binding and authority._inspection_only is True
            and Path(evidence_root)==Path(manifest['evidence_root'])
            and str(target_root)==manifest['root_projections'][contract.document['canonical_result']['root_binding']],
            'recovery.closed_publication_observer_required')
        selection=select_closed_publication_observation(binding,run_id,request_id,expected_intent_digest)
        with _guard_native_original_intents(binding,history_bindings=installed.history_bindings,_recovery_selection=selection):
            operation_primary=None
            try:
                original=selection.check(Path(evidence_root)/'.phase/runs'/run_id)
                if any(name.startswith('recovery/') for name in original['files']):
                    verify_saved_publication_observations(binding, original)
                effect=original['plan']['effects'][0]
                result.intent_digest=expected_intent_digest;result.effect_plan_digest=original['intent']['effect_plan_digest']
                result.original_receipt_digest=original['original_receipt_digest']
                result.original_terminal_status=original['original_terminal_status']
                # Advisory read avoids poisoning transport on historical ID
                # difference; mandatory local full identity comparison follows.
                observed=authority.observe(run_id=run_id,root_binding=effect['target']['root_binding'],
                    locator=effect['target']['relative_locator'],expected_identity=None)
                _require(classify_publication_observation(original,observed),'recovery.target_not_verified')
                result.target_verified=True;result.recovery_effect_state='committed'
                _require(original['files']==selection.check(original['run'])['files'],'recovery.original_changed')
            except BaseException as error:
                operation_primary=error
                raise
            finally:
                try:authority.seal(intent_digest=None)  # Actual inspection-only closure.
                except BaseException as error:
                    if operation_primary is None:raise
                    try:operation_primary.add_note('Publication observe secondary seal: '+type(error).__name__)
                    except BaseException:pass
                    raise operation_primary from error
            observation_path, observation_digest = _persist_publication_observation(selection, original, observed)
        result.lock_finalization=LockFinalization(unlock='succeeded',close='succeeded')
        result.observation_path = observation_path.as_posix()
        result.observation_digest = observation_digest
        result.status='verified_existing';result.success=True;result.inspection_required=False;result.exit_code=0
    except BaseException as error:
        # Do not turn abrupt interruption/SystemExit into an ordinary negative.
        if not isinstance(error,(Exception,)):raise
        result.success=False;result.status='indeterminate';result.exit_code=40;result.inspection_required=True
        result.error=getattr(error,'code',None)or'recovery.native_unknown';result.native_error_details=[_diagnostic(error)]
    finally:
        # An error before entering the guard must still close a selected fresh
        # inspection-only channel. No second seal after any attempted seal.
        if authority is not None and getattr(authority,'_inspection_only',False)is True and not authority._seal_attempted:
            try:authority.seal(intent_digest=None)
            except BaseException as error:
                result.success=False;result.status='indeterminate';result.exit_code=40;result.inspection_required=True
                result.error=result.error or'recovery.channel_finalization_unknown';result.native_error_details.append(_diagnostic(error))
    return ApplicationResponse(result.model_dump(),result.exit_code)
