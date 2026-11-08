"""Bounded trusted owner3 history configuration over existing reader owners.

This is immutable installation configuration, never a journal/index or Original
store. Every retained run remains subject to the existing complete Core scan.
Families select only literal existing kinds/factories; no registry resource,
provider, policy or callable is taken from evidence or operation JSON.
"""
import base64
from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes
from .owner_directory_fixture import _need,_digest,_kinds,_ROLES,fixture_document,check_manifest
from .owner_semantic_contracts import semantic_owner_contract

_MAX_PREDECESSORS=32


def _kind(family,role):
    _need(role in _ROLES,'ntfs.semantic_history_family_mismatch')
    if family in {'per-run','owner2','owner3'}:
        return _kinds()[role]
    if family=='legacy-shared':
        from .experimental_history import _ExperimentalHistoryFile1Admission,_ExperimentalHistoryVersion1Admission
        rows={'File1':_ExperimentalHistoryFile1Admission,'Version1':_ExperimentalHistoryVersion1Admission}
        _need(role in rows,'ntfs.semantic_history_family_mismatch')
        return rows[role]
    if family=='legacy-bundle2-v1':
        from .experimental_bundle2 import _ExperimentalBundle2Admission
        _need(role=='Bundle2','ntfs.semantic_history_family_mismatch')
        return _ExperimentalBundle2Admission
    if family=='legacy-bundle2-v2':
        from .experimental_bundle2_v2 import _ExperimentalBundle2AdmissionV2
        _need(role=='Bundle2','ntfs.semantic_history_family_mismatch')
        return _ExperimentalBundle2AdmissionV2
    _need(False,'ntfs.semantic_history_family_mismatch')


def _decode(encoded,digest,limit):
    _digest(digest);_need(type(encoded)is str,'ntfs.accepted_history_shape')
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,UnicodeError)as error:
        from ...errors import PhaseError
        raise PhaseError('ntfs.accepted_history_shape')from error
    _need(0<len(raw)<=limit and base64.b64encode(raw).decode('ascii')==encoded and digest_bytes(raw)==digest,
        'ntfs.accepted_history_binding_mismatch')
    value=parse_json_bytes(raw,maximum_bytes=limit)
    _need(type(value)is dict and canonical_bytes(value)==raw,'ntfs.accepted_history_shape')
    return raw,value


def _physical(grant):
    _need(type(grant)is dict and 'root_binding'in grant,'ntfs.original_history_domain_mismatch')
    return canonical_bytes({key:value for key,value in grant.items()if key!='root_binding'})


def _domain(manifest,fixture):
    for key in('evidence_root','evidence_identity','preparation_root','preparation_identity'):
        _need(manifest.get(key)==fixture[key],'ntfs.original_history_domain_mismatch')
    # Core is a logical binding, not a wheel digest. Each complete reader below
    # resolves its own trusted Core/registry/profile/composition independently.
    allowed={_physical(row)for row in fixture['root_grants']}
    grants=manifest.get('root_grants')
    _need(type(grants)is list and len(grants)in{1,2}
        and len({_physical(row)for row in grants})==len(grants)
        and all(_physical(row)in allowed for row in grants),'ntfs.original_history_domain_mismatch')
    projections=manifest.get('root_projections')
    _need(type(projections)is dict and set(projections)=={row['root_binding']for row in grants},
        'ntfs.original_history_domain_mismatch')
    current=_physical(fixture['root_grants'][0])
    for row in grants:
        expected='/ntfs-result'if _physical(row)==current else'/ntfs-objects'
        _need(projections[row['root_binding']]==expected,'ntfs.original_history_domain_mismatch')


def owner3_history_buffers(raw,expected_digest,*,active_bytes,active_digest):
    _need(type(raw)is bytes and len(raw)<=2*1024**2 and digest_bytes(raw)==expected_digest,
        'ntfs.accepted_history_binding_mismatch')
    value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
    _need(type(value)is dict and canonical_bytes(value)==raw and set(value)=={
        'history_manifest_set_version','fixture_base64','fixture_digest','manifests','predecessors'}
        and value['history_manifest_set_version']=='3.0','ntfs.accepted_history_shape')
    fixture_raw,fixture=_decode(value['fixture_base64'],value['fixture_digest'],32768)
    _need(fixture_document(fixture_raw)==fixture and fixture['experimental_admission_version']=='3.0',
        'ntfs.semantic_history_family_mismatch')
    rows=value['manifests'];past=value['predecessors']
    _need(type(rows)is list and len(rows)==6 and type(past)is list and len(past)<=_MAX_PREDECESSORS,
        'ntfs.accepted_history_shape')
    buffers=[];tuples=set()
    for role,row in zip(_ROLES,rows,strict=True):
        _need(type(row)is dict and set(row)=={'role','manifest_base64','manifest_digest'}and row['role']==role,
            'ntfs.accepted_history_shape')
        body,manifest=_decode(row['manifest_base64'],row['manifest_digest'],2*1024**2)
        check_manifest(_kinds()[role],fixture_raw,manifest,row['manifest_digest'])
        _need(manifest['contract']==semantic_owner_contract(role),'ntfs.semantic_owner_contract_mismatch')
        _domain(manifest,fixture)
        buffers.append((body,row['manifest_digest'],fixture_raw,_kinds()[role]))
    for row in past:
        _need(type(row)is dict and set(row)=={'family','role','manifest_base64','manifest_digest',
            'admission_base64','admission_digest'},'ntfs.accepted_history_shape')
        kind=_kind(row['family'],row['role'])
        body,manifest=_decode(row['manifest_base64'],row['manifest_digest'],2*1024**2)
        admission_raw,document=_decode(row['admission_base64'],row['admission_digest'],32768)
        admission=kind(admission_raw);_need(admission.document()==document,'ntfs.semantic_history_family_mismatch')
        version=document['experimental_admission_version']
        if row['family']=='owner3':
            _need(version=='3.0','ntfs.semantic_history_family_mismatch')
            check_manifest(kind,admission_raw,manifest,row['manifest_digest'])
        elif row['family']=='owner2':
            _need(version=='2.0','ntfs.semantic_history_family_mismatch')
            check_manifest(kind,admission_raw,manifest,row['manifest_digest'])
        else:
            _need(version in {'1.0','1.1'} and manifest['contract']==kind._contract
                and manifest['native_read_installation_version']==kind._manifest_version,
                'ntfs.semantic_history_family_mismatch')
        _domain(manifest,fixture)
        buffers.append((body,row['manifest_digest'],admission_raw,kind))
    for body,digest,cap,kind in buffers:
        manifest=parse_json_bytes(body,maximum_bytes=2*1024**2)
        key=canonical_bytes({'contract':manifest['contract'],'core':manifest['core'],
            'installation':{'id':manifest['installation_id'],'descriptor_digest':digest},
            'registry_snapshot_digest':manifest['registry_snapshot_digest']})
        _need(key not in tuples,'ntfs.original_history_binding_mismatch');tuples.add(key)
    _need(type(active_bytes)is bytes and digest_bytes(active_bytes)==active_digest
        and sum(body==active_bytes and digest==active_digest for body,digest,cap,kind in buffers[:6])==1,
        'ntfs.accepted_history_binding_mismatch')
    return tuple(buffers)


def validate_owner3_history_bindings(active,bindings):
    from ...installation import _NativeFileCreateReadBinding,_native_experimental_read_binding
    _need(type(active)is _NativeFileCreateReadBinding and type(bindings)is tuple
        and 6<=len(bindings)<=6+_MAX_PREDECESSORS,'ntfs.original_history_binding_mismatch')
    active_raw=active.experimental_admission.raw;fixture=fixture_document(active_raw)
    _need(fixture['experimental_admission_version']=='3.0','ntfs.semantic_history_family_mismatch')
    tuples=set()
    for index,row in enumerate(bindings):
        _need(type(row)is _NativeFileCreateReadBinding and row._qualification_context is None,
            'ntfs.original_history_binding_mismatch')
        checked=_native_experimental_read_binding(manifest_bytes=row.manifest_bytes,
            expected_manifest_digest=row.manifest_digest,admission=row.experimental_admission)
        _need(type(row.registry)is type(checked.registry)and row.registry.digest==checked.registry.digest
            and canonical_bytes(row.registry.to_document())==canonical_bytes(checked.registry.to_document()),
            'ntfs.original_history_binding_mismatch')
        row.experimental_admission.profile(row)
        manifest=parse_json_bytes(row.manifest_bytes,maximum_bytes=2*1024**2);_domain(manifest,fixture)
        if index<6:
            _need(type(row.experimental_admission)is _kinds()[_ROLES[index]]
                and row.experimental_admission.raw==active_raw
                and manifest['contract']==semantic_owner_contract(_ROLES[index]),
                'ntfs.original_history_binding_mismatch')
        key=canonical_bytes({'contract':manifest['contract'],'core':manifest['core'],
            'installation':{'id':manifest['installation_id'],'descriptor_digest':row.manifest_digest},
            'registry_snapshot_digest':manifest['registry_snapshot_digest']})
        _need(key not in tuples,'ntfs.original_history_binding_mismatch');tuples.add(key)
    _need(sum(row.manifest_bytes==active.manifest_bytes and row.manifest_digest==active.manifest_digest
        and row.experimental_admission.raw==active_raw for row in bindings[:6])==1,
        'ntfs.original_history_binding_mismatch')
    return bindings


def owner3_binding_for_original(bindings,*,run_id,contract,core,installation,registry_snapshot_digest,
        pre_intent_rejection=False):
    from ...installation import _NativeFileCreateReadBinding
    _need(type(bindings)is tuple and 6<=len(bindings)<=6+_MAX_PREDECESSORS,
        'ntfs.original_history_binding_mismatch')
    # Existing Core re-resolves the complete set before entering its history
    # scan. Recheck every immutable reader projection here, like owner2's exact
    # tuple selector; rebuilding all registries for EVERY retained Original
    # would multiply full-scan work by the manifest count. No cache is added.
    _need(all(type(row)is _NativeFileCreateReadBinding and row._qualification_context is None for row in bindings),
        'ntfs.original_history_binding_mismatch')
    fixture=fixture_document(bindings[0].experimental_admission.raw)
    _need(fixture['experimental_admission_version']=='3.0','ntfs.semantic_history_family_mismatch')
    seen=set()
    for index,row in enumerate(bindings):
        _need(digest_bytes(row.manifest_bytes)==row.manifest_digest,'ntfs.original_history_binding_mismatch')
        manifest=parse_json_bytes(row.manifest_bytes,maximum_bytes=2*1024**2)
        _need(canonical_bytes(manifest)==row.manifest_bytes and manifest['registry_snapshot_digest']==row.registry.digest,
            'ntfs.original_history_binding_mismatch')
        row.experimental_admission.check_binding(row);_domain(manifest,fixture)
        if index<6:
            _need(type(row.experimental_admission)is _kinds()[_ROLES[index]]
                and row.experimental_admission.raw==bindings[0].experimental_admission.raw
                and manifest['contract']==semantic_owner_contract(_ROLES[index]),
                'ntfs.original_history_binding_mismatch')
        identity=canonical_bytes({'contract':manifest['contract'],'core':manifest['core'],
            'installation':{'id':manifest['installation_id'],'descriptor_digest':row.manifest_digest},
            'registry_snapshot_digest':manifest['registry_snapshot_digest']})
        _need(identity not in seen,'ntfs.original_history_binding_mismatch');seen.add(identity)
    candidates=[];per_run=[]
    for row in bindings:
        manifest=parse_json_bytes(row.manifest_bytes,maximum_bytes=2*1024**2)
        if manifest['contract']!=contract or manifest['core']!=core:continue
        if not pre_intent_rejection:
            if (installation=={'id':manifest['installation_id'],'descriptor_digest':row.manifest_digest}
                    and registry_snapshot_digest==manifest['registry_snapshot_digest']):candidates.append(row)
        else:
            _need(installation is None and registry_snapshot_digest is None,'ntfs.original_history_binding_mismatch')
            document=row.experimental_admission.document()
            if document['experimental_admission_version']in{'1.0','1.1'}:
                if document['run_id']==run_id:per_run.append(row)
            else:candidates.append(row)
    # Exact fixed legacy per-run identity is narrower than an installation-free
    # stable receipt; subsequent existing no-effect/admission byte checks still
    # must succeed. Ambiguous stable readers never guess from attachments.
    if pre_intent_rejection and per_run:candidates=per_run
    _need(len(candidates)==1,'ntfs.original_history_binding_mismatch')
    return candidates[0]
