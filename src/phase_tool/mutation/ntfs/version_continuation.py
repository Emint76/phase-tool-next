"""Explicit same-operation continuation through the existing Core only.

Candidate SOURCE. No alternate effects, receipts, lock, journal, version store
or admission. Unknown dispatch / absent proof / live workers remain refused.
Exact versioned parent-failure closure is additional to terminal-proof closure.
"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import os,re,threading

from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from ...errors import PhaseError
from .native import _require
from .version_original_closure import (version_original_role,verify_closed_version_original,
    select_closed_version_original,_NativeVersionContinuationSelection)

_ACTIVE=ContextVar('phase_explicit_native_version_continuation',default=None)
_CLASSES=frozenset({'no_effect_observed','archived_not_published','published_not_finalized'})
_KEYS=frozenset({'native_version_resolution_version','run_id','request_id','intent_digest',
    'effect_plan_digest','contract','installation_digest','registry_snapshot_digest',
    'original_files','closure_proof_digest','physical_receipt_present','classification',
    'observation','common_guard_finalized'})
_LINK_KEYS={'continued_run_id','continued_intent_digest','lineage_digest'}
_PENDING_KEYS = (_KEYS - {'common_guard_finalized'}) | {
    'closure_kind', 'continued_run_id', 'continued_intent_digest',
}


def validate_version_resolution_shape(value,original):
    """Strict new Core recovery observation; never a version publication receipt."""
    _require(type(value)is dict and (
        (value.get('native_version_resolution_version')=='1.0'and set(value)==_KEYS)or
        (value.get('native_version_resolution_version')=='1.1'and set(value)==_KEYS|{'closure_kind'}
            and value.get('closure_kind')in{'native_terminal_proof','validated_parent_failure_completion'})or
        (value.get('native_version_resolution_version')=='1.2'and set(value)==_KEYS|{'closure_kind'}|_LINK_KEYS
            and value.get('closure_kind')in{'native_terminal_proof','validated_parent_failure_completion'})or
        (value.get('native_version_resolution_version') == '1.3' and set(value) == _PENDING_KEYS
            and value.get('closure_kind') in {'native_terminal_proof', 'validated_parent_failure_completion'}))
        and value['run_id']==original['run_id'] and value['request_id']==original['idempotency']['key']
        and value['intent_digest']==profile_digest('intent',original)
        and value['effect_plan_digest']==original['effect_plan_digest']
        and value['contract']==original['contract']
        and value['contract']['id']in{'publish_new_version.v1','publish_new_version.v2'}
        and type(value['physical_receipt_present'])is bool
        and (value['native_version_resolution_version'] == '1.3' or value['common_guard_finalized'] is True)
        and value['classification']in _CLASSES and type(value['observation'])is dict
        and type(value['original_files'])is dict and bool(value['original_files']),
        'recovery.version_resolution_mismatch')
    for key in('installation_digest','registry_snapshot_digest','closure_proof_digest'):
        _require(type(value[key])is str and re.fullmatch(r'sha256:[0-9a-f]{64}',value[key])is not None,
            'recovery.version_resolution_mismatch')
    for name,row in value['original_files'].items():
        _require(type(name)is str and name in{'intent.json','receipt.json'}or
            type(name)is str and name.startswith(('attachments/','blobs/')),
            'recovery.version_resolution_mismatch')
        _require('..'not in name.split('/')and type(row)is list and len(row)==2
            and type(row[0])is str and re.fullmatch(r'sha256:[0-9a-f]{64}',row[0])is not None
            and type(row[1])is int and row[1]>=0,'recovery.version_resolution_mismatch')
    if value['native_version_resolution_version'] in {'1.2', '1.3'}:
        from ...evidence import validate_run_id
        validate_run_id(value['continued_run_id'])
        _require(value['continued_run_id']!=original['run_id'],'recovery.version_lineage_conflict')
        if value['native_version_resolution_version'] == '1.3':
            digest = value['continued_intent_digest']
            _require(type(digest) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', digest) is not None,
                'recovery.version_lineage_conflict')
        else:
            for key in ('continued_intent_digest', 'lineage_digest'):
                _require(value[key] is None or type(value[key]) is str
                    and re.fullmatch(r'sha256:[0-9a-f]{64}', value[key]) is not None,
                    'recovery.version_lineage_conflict')
            _require((value['continued_intent_digest'] is None) == (value['lineage_digest'] is None),
                'recovery.version_lineage_conflict')
    return value


def classify_observation(original,observation):
    """Fresh authenticated channel sample + exact Original physical correlation.

    This predicate itself authenticates no sample. Both live and retained paths
    first require the Original's existing proof and exact trusted installation.
    Missing or equal-byte substituted known objects never count as exact IDs.
    """
    manifest=parse_json_bytes(original['binding'].manifest_bytes)
    effect=original['plan']['effects'][0];role=original['role']
    _require(role in('Version1','Version2'),'recovery.closed_native_version_required')
    if role=='Version1':
        from .version1_observation import validate_version1_observation
        from ...contracts.publish_new_version_v1 import _classify_states
        _require(type(observation)is dict and set(observation)=={'current','archive'},'recovery.version_observation_mismatch')
        grant=manifest['root_grants'][0]
        rows={name:validate_version1_observation(observation[name],grant,effect[key]['relative_locator'])
            for name,key in(('current','target'),('archive','archive_target'))}
        states={name:{k:row['state'][k]for k in('exists','digest','length')}for name,row in rows.items()}
        classification=_classify_states(current=states['current'],archive=states['archive'],
            before_digest=effect['archive_digest'],before_length=effect['archive_length'],
            after_digest=effect['content_digest'],after_length=effect['content_length'])
        current,archive=(rows[name]['native']['native_identity']for name in('current','archive'))
        _require(current is None or archive is None or current!=archive,'ntfs.version1_current_archive_alias')
    else:
        from .version2_observation import validate_version2_triple
        from ...contracts.publish_new_version_v2 import _classify
        rows=validate_version2_triple(observation,manifest['root_grants'],effect)
        states={name:{k:row['state'][k]for k in('exists','digest','length')}for name,row in rows.items()}
        # Exact existing semantic classifier, no target projection filesystem IO.
        classification=_classify(original['plan'],{},_observe_effect=lambda _effect,_roots:states)
    _require(set(rows)==set(original['target_identities']),'recovery.version_observation_mismatch')
    for name,expected in original['target_identities'].items():
        _require(expected is None or rows[name]['native']['native_identity']==expected,
            'recovery.version_original_identity_changed')
    _require(classification in _CLASSES,'recovery.version_ambiguous_state')
    return classification


def verify_saved_version_resolution(binding,original):
    """Discharge an Original only through a separately finalized continuation."""
    from ...evidence import validate_receipt
    from .version_original_closure import _canonical
    from .proof import verify_native_terminal_proof
    original=dict(original,binding=binding)
    directory=original['run']/'recovery';accepted=[]
    for path in sorted(directory.iterdir()):
        value,raw=_canonical(path)
        record_digest = digest_bytes(raw)
        _require(re.fullmatch(r'[0-9a-f]{64}\.json',path.name)is not None
            and path.name == record_digest[7:] + '.json', 'recovery.version_resolution_mismatch')
        validate_version_resolution_shape(value,original['intent'])
        # Earlier draft formats are readable for preservation. They do not
        # establish a publication performed while the common guard was held.
        _require(value['native_version_resolution_version'] == '1.3',
            'recovery.version_guarded_resolution_required')
        _require(value.get('closure_kind','native_terminal_proof')==original['closure_kind']
            and value['installation_digest']==binding.manifest_digest
            and value['registry_snapshot_digest']==binding.registry.digest
            and value['original_files']=={name:list(row)for name,row in original['original_files'].items()}
            and value['closure_proof_digest']==original['proof_digest']
            and value['physical_receipt_present']==original['receipt_present']
            and value['classification']==classify_observation(original,value['observation']),
            'recovery.version_resolution_mismatch')
        continued = original['run'].parent / value['continued_run_id']
        terminal, _ = _canonical(continued / 'receipt.json')
        validate_receipt(terminal, binding.registry)
        _require(terminal['run_id'] == continued.name
            and terminal['terminal_status'] == 'succeeded_verified'
            and terminal['execution_disposition'] == 'executed'
            and terminal['evidence']['intent_digest'] == value['continued_intent_digest'],
            'recovery.version_continuation_unfinalized')
        lineage_path = 'attachments/native-version-lineage.json'
        lineage, lineage_raw = _canonical(continued / lineage_path)
        _require(lineage.get('native_version_lineage_version') == '1.1'
            and lineage.get('original_run_id') == original['intent']['run_id']
            and lineage.get('resolution_digest') == record_digest,
            'recovery.version_lineage_conflict')
        checked = verify_native_terminal_proof(binding, continued, terminal)
        _require(checked['immutable_files'].get(lineage_path) == (digest_bytes(lineage_raw), len(lineage_raw))
            and checked['proof']['physical']['parent_response']['completion']['physical_evidence'].get(
                'native_version_durability_version') == '1.1',
            'recovery.version_lineage_conflict')
        accepted.append(value)
    _require(bool(accepted),'recovery.version_resolution_required')
    return tuple(accepted)


class _Lease:
    __slots__=('selection','owner','active','taken','request_checked','observation','failed','lineage','lineage_attempted','resolution')
    def __init__(self,selection):
        self.selection=selection;self.owner=(os.getpid(),threading.get_ident())
        self.active=True;self.taken=False;self.request_checked=False;self.observation=None;self.failed=False;self.lineage=None;self.lineage_attempted=False
        self.resolution = None
    def check(self):
        _require(type(self)is _Lease and self.active and not self.failed
            and self.owner==(os.getpid(),threading.get_ident()),'recovery.version_scope_required')


def _take_version_continuation(binding,new_run_id):
    lease=_ACTIVE.get()
    if lease is None:return None
    lease.check()
    _require(not lease.taken and lease.selection.binding is binding and lease.selection.new_run_id==new_run_id,
        'recovery.version_scope_consumed')
    lease.taken=True
    return lease.selection


def _check_version_continuation_request(store,contract,key,scope_digest,request_digest,authority):
    lease=_ACTIVE.get()
    if lease is None:return
    lease.check();selection=lease.selection
    _require(lease.taken and not lease.request_checked and lease.observation is not None and authority is not None
        and authority.read_binding is selection.binding and store.run_root.name==selection.new_run_id,
        'recovery.version_scope_required')
    original=selection.check(store.runs_root/selection.original_run_id);intent=original['intent']
    exact={'id':contract.document['identity']['id'],'version':contract.document['identity']['version'],'package_digest':contract.package_digest}
    _require(exact==intent['contract'] and key==selection.request_id
        and scope_digest==intent['idempotency']['scope_digest']
        and request_digest==intent['idempotency']['request_digest'],
        'idempotency.same_key_conflict')
    # Natural fresh capture reaches here. Do not reset timestamp or reinterpret
    # old request policies to force a digest match. Legacy v1 mismatch refuses.
    lease.request_checked=True
    return selection.original_run_id


def observe_version_continuation(selection,authority):
    lease=_ACTIVE.get();_require(lease is not None,'recovery.version_scope_required');lease.check()
    _require(lease.selection is selection and lease.taken and lease.observation is None
        and authority.read_binding is selection.binding,'recovery.version_scope_required')
    original=selection.check(Path(parse_json_bytes(selection.binding.manifest_bytes)['evidence_root'])/'.phase/runs'/selection.original_run_id)
    original=dict(original,binding=selection.binding)
    _require(not os.path.lexists(original['run'] / 'recovery')
        and original['original_terminal_status'] != 'succeeded_verified',
        'recovery.version_already_resolved_or_pending')
    effect=original['plan']['effects'][0]
    if original['role']=='Version1':
        observation={name:authority.observe_advisory(root_binding=effect[key]['root_binding'],
            locator=effect[key]['relative_locator'],expected_identity=None)
            for name,key in(('current','target'),('archive','archive_target'))}
    else:observation=authority.observe_version2_triple(effect=effect,expected_targets=None)
    classification=classify_observation(original,observation)
    # No GO, receipt, target write or successful-target claim is created here.
    lease.observation={'closure_kind':original['closure_kind'],
        'run_id':selection.original_run_id,
        'request_id':selection.request_id,'intent_digest':selection.intent_digest,
        'effect_plan_digest':original['intent']['effect_plan_digest'],'contract':original['intent']['contract'],
        'installation_digest':selection.binding.manifest_digest,'registry_snapshot_digest':selection.binding.registry.digest,
        'original_files':{name:list(row)for name,row in original['original_files'].items()},
        'closure_proof_digest':original['proof_digest'],'physical_receipt_present':original['receipt_present'],
        'classification':classification,'observation':observation}


def stage_version_resolution(selection, *, new_intent_digest):
    """Persist the prebound record inside the held native common guard.

    The record makes no guard-finalization claim. History requires the new
    run's verified terminal proof and physical receipt before using it.
    """
    lease = _ACTIVE.get()
    _require(lease is not None, 'recovery.version_scope_required')
    lease.check()
    _require(lease.selection is selection and lease.request_checked and lease.lineage is not None
        and lease.resolution is not None, 'recovery.version_scope_required')
    from ...evidence import _open_native_recovery_store,_close_native_recovery_store,_write_native_recovery_canonical
    record = lease.resolution
    resolution_digest = digest_bytes(canonical_bytes(record))
    _require(record['continued_intent_digest'] == new_intent_digest
        and resolution_digest == lease.lineage['value']['resolution_digest'], 'recovery.version_lineage_conflict')
    original = selection.check(selection.binding.check_evidence_root() / '.phase' / 'runs' / selection.original_run_id)
    validate_version_resolution_shape(record, original['intent'])
    _require(not os.path.lexists(original['run'] / 'recovery'), 'recovery.version_already_resolved_or_pending')
    leaf = resolution_digest[7:] + '.json'
    store = _open_native_recovery_store(selection.binding, selection.original_run_id)
    primary = None
    try:
        path, actual_digest = _write_native_recovery_canonical(store, leaf, record)
        _require(path == original['run'] / 'recovery' / leaf and actual_digest == resolution_digest,
            'recovery.version_lineage_conflict')
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            _close_native_recovery_store(store)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note('Version resolution Evidence finalization: ' + str(error))


def _require_version_continuation_kernels():
    # Source-composition prerequisite only, NOT admission or qualification.
    # Fresh hash equality cannot replace missing prior data/namespace flushes.
    from . import version1_effect,version2_effect
    _require(getattr(version1_effect,'VERSION_CONTINUATION_DURABILITY_CAPABILITY',None)=='1.1'
        and getattr(version2_effect,'VERSION_CONTINUATION_DURABILITY_CAPABILITY',None)=='1.1',
        'recovery.version_durability_component_required')


def continue_version(core,request,*,original_run_id,request_id,expected_intent_digest):
    """Internal SOURCE API; ordinary public frontdoors require separate review.

    A real freshly admitted Core request supplies no authority, policy, root or
    candidate override beyond the existing PhaseRequest. Its natural request
    identity must match the selected exact Original after fresh capture.
    """
    from ...core import PhaseCore,PhaseRequest
    from ...installation import _NativeFileCreateInstallation
    _require(type(core)is PhaseCore and type(request)is PhaseRequest
        and type(core.installation)is _NativeFileCreateInstallation and _ACTIVE.get()is None,
        'recovery.version_scope_required')
    _require_version_continuation_kernels()
    binding=core.installation.read_binding
    version_original_role(binding)
    selection=select_closed_version_original(binding,original_run_id=original_run_id,new_run_id=request.run_id,
        request_id=request_id,intent_digest=expected_intent_digest)
    lease=_Lease(selection);token=_ACTIVE.set(lease)
    try:return core.run(request,execute=True)
    except BaseException:lease.failed=True;raise
    finally:
        lease.active=False;_ACTIVE.reset(token)
