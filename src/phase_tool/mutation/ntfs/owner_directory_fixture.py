"""SOURCE-ONLY closed synthetic directory fixture; not ordinary admission.

This draft is not installed/activated. It extends data correlation for the exact
six existing experimental admission classes, never the authority/provider graph.
Actual Core, original parsers, EvidenceStore, root lock and worker stay owners.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import PurePosixPath, PureWindowsPath
import re
import threading

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ...errors import PhaseError
from ...paths import safe_relative_locator

_VERSION = '2.0'
_AUTHORIZATION = 'sha256:6d3646ce58d6045fae41d1b22791c4f05d6cb177c343883fad86cd6ae0b0a40b'
_ATTEMPT_NAME = 'experimental-attempt.json'
_ROLES = ('File1','File2','Version1','Version2','Bundle1','Bundle2')
_DIGEST = re.compile('sha256:[0-9a-f]{64}')
_UUID = re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
_CAPTURE_CONSUMED = object()
_REMAINING_CORE_CONTROL_BYTES = 32*1024**2
_MAXIMUM_CENSUS_ENTRIES = 2_500_000


def _need(value, code='ntfs.owner_fixture_mismatch'):
    if not value:
        raise PhaseError(code)


def _kinds():
    from .experimental_file1 import _ExperimentalFile1Admission
    from .experimental_file2 import _ExperimentalFile2Admission
    from .experimental_version1 import _ExperimentalVersion1Admission
    from .experimental_version2 import _ExperimentalVersion2Admission
    from .experimental_bundle1 import _ExperimentalBundle1Admission
    from .experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
    return dict(zip(_ROLES, (_ExperimentalFile1Admission,_ExperimentalFile2Admission,
        _ExperimentalVersion1Admission,_ExperimentalVersion2Admission,
        _ExperimentalBundle1Admission,_ExperimentalBundle2AdmissionV3), strict=True))


def _digest(value):
    _need(type(value) is str and _DIGEST.fullmatch(value) is not None)


def _identity(value):
    _need(type(value) is dict and set(value)=={'stable_id','device','inode'}
        and type(value['stable_id']) is str and re.fullmatch('[a-z][a-z0-9._-]{0,127}',value['stable_id']) is not None
        and type(value['device']) is int and value['device']>=0
        and type(value['inode']) is int and value['inode']>0)


def _posix(value):
    _need(type(value) is str and PurePosixPath(value).is_absolute()
        and str(PurePosixPath(value))==value and value!='/' and '..' not in PurePosixPath(value).parts)
    return PurePosixPath(value)


def fixture_document(raw):
    """Pure closed parser. A fixture cannot choose a class/factory/policy."""
    _need(type(raw) is bytes and 0<len(raw)<=32768,'ntfs.owner_fixture_shape')
    doc=parse_json_bytes(raw,maximum_bytes=32768)
    if type(doc)is dict and doc.get('experimental_admission_version')=='3.0':
        from .owner_semantic_fixture import semantic_fixture_document
        return semantic_fixture_document(raw)
    _need(type(doc) is dict and canonical_bytes(doc)==raw and set(doc)=={
        'experimental_admission_version','authorization_digest','fixture_uuid','owner_scope_id',
        'wheel_digest','core','windows_roots','root_grants','root_projections',
        'evidence_root','evidence_identity','preparation_root','preparation_identity',
        'roles','request_limits','qualification','release_eligible'},'ntfs.owner_fixture_shape')
    _need(doc['experimental_admission_version']==_VERSION and doc['authorization_digest']==_AUTHORIZATION
        and doc['release_eligible'] is False and doc['qualification']=={'A05':'NOT_VERIFIED','G01':'NOT_VERIFIED'},
        'ntfs.owner_fixture_scope')
    _need(type(doc['fixture_uuid']) is str and _UUID.fullmatch(doc['fixture_uuid']) is not None
        and doc['owner_scope_id']=='phase.qualification.owner.'+doc['fixture_uuid'])
    _digest(doc['wheel_digest'])
    _need(type(doc['core']) is dict and set(doc['core'])=={'id','version','package_digest'}
        and doc['core']['id']=='phase.core' and type(doc['core']['version']) is str)
    _digest(doc['core']['package_digest'])
    roots=doc['windows_roots']
    _need(type(roots) is dict and set(roots)=={'current_root','objects_root'})
    parent=PureWindowsPath('S:/Phase-NTFS-Qualification')/doc['fixture_uuid']
    for binding,leaf in (('current_root','results'),('objects_root','objects')):
        _need(type(roots[binding]) is str and roots[binding]==str(parent/leaf))
    from .version2_observation import _version2_grants
    grants=_version2_grants(doc['root_grants'])
    _need(all(grants[key].components==PureWindowsPath(roots[key]).parts[1:] for key in roots))
    projections=doc['root_projections']
    _need(type(projections) is dict and set(projections)==set(roots)
        and projections=={'current_root':'/ntfs-result','objects_root':'/ntfs-objects'})
    evidence,preparation=(_posix(doc[key]) for key in ('evidence_root','preparation_root'))
    _need(not evidence.is_relative_to(preparation) and not preparation.is_relative_to(evidence))
    for key in ('evidence_identity','preparation_identity'):_identity(doc[key])
    _need(doc['evidence_identity']!=doc['preparation_identity'])
    for projection in projections.values():
        value=_posix(projection)
        _need(all(not value.is_relative_to(root) and not root.is_relative_to(value) for root in (evidence,preparation)))
    limits=doc['request_limits']
    _need(type(limits) is dict and set(limits)=={'run_prefix','maximum_attempts','maximum_retained_bytes'}
        and limits['run_prefix']=='od2-'+doc['fixture_uuid']+'-'
        and type(limits['maximum_attempts']) is int and 1<=limits['maximum_attempts']<=65536
        and type(limits['maximum_retained_bytes']) is int and 1<=limits['maximum_retained_bytes']<=32*1024**3)
    rows=doc['roles'];kinds=_kinds()
    _need(type(rows) is list and len(rows)==6 and all(type(row) is dict for row in rows)
        and [row.get('role') for row in rows]==list(_ROLES))
    for row in rows:
        kind=kinds[row['role']]
        _need(set(row)=={'role','contract','native_read_installation_version','registry_snapshot_digest','authority','root_binding'}
            and row['contract']==kind._contract and row['native_read_installation_version']==kind._manifest_version)
        _digest(row['registry_snapshot_digest'])
        authority=row['authority'];profile=authority.get('profile') if type(authority) is dict else None
        _need(type(authority) is dict and set(authority)=={'usage','profile','provider'} and authority['usage']=='provider_backed'
            and type(profile) is dict and set(profile)=={'id','version','descriptor_digest'}
            and type(profile['id']) is str and type(profile['version']) is str
            and profile['id']+'@'+profile['version']==kind._profile)
        _digest(profile['descriptor_digest'])
        provider=authority['provider']
        _need(type(provider) is dict and set(provider)=={'id','version','artifact_digest'}
            and type(provider['id']) is str and type(provider['version']) is str)
        _digest(provider['artifact_digest'])
        _need(type(row['root_binding']) is str and re.fullmatch('[a-z][a-z0-9_]{0,63}',row['root_binding']) is not None
            and (row['role']!='Version2' or row['root_binding']=='current_root'))
    return doc


def is_fixture(raw):
    """An unknown/malformed new version never falls through as a legacy form."""
    _need(type(raw) is bytes and len(raw)<=32768,'ntfs.owner_fixture_shape')
    value=parse_json_bytes(raw,maximum_bytes=32768)
    return type(value) is dict and value.get('experimental_admission_version')in {_VERSION,'3.0'}


def fixture_role(kind,raw):
    kinds=_kinds();matches=[name for name,expected in kinds.items() if kind is expected]
    _need(len(matches)==1,'ntfs.experimental_admission_required')
    doc=fixture_document(raw)
    return doc,next(row for row in doc['roles'] if row['role']==matches[0])


def installation_id(kind,raw):
    doc,role=fixture_role(kind,raw)
    identity=digest_bytes(canonical_bytes({'fixture_digest':digest_bytes(raw),'role':role['role']}))
    return kind._installation_prefix+('owner3.'if doc['experimental_admission_version']=='3.0'else'owner2.')+identity[7:]


def role_projection(kind,raw):
    """Fixed data view for the unchanged exact experimental authorities."""
    doc,role=fixture_role(kind,raw)
    grants=parse_json_bytes(canonical_bytes(doc['root_grants']))
    current=grants[0];current['root_binding']=role['root_binding']
    shared={key:doc[key] for key in ('authorization_digest','wheel_digest','evidence_identity','preparation_identity','qualification','release_eligible')}
    shared.update(experimental_admission_version=doc['experimental_admission_version'],contract=role['contract'],owner_scope_id=doc['owner_scope_id'],fixture_digest=digest_bytes(raw))
    if role['role']=='Version2':
        shared.update(root_grants=grants,windows_roots=doc['windows_roots'])
    else:
        shared.update(root_grant=current,windows_root=doc['windows_roots']['current_root'])
    return shared


def check_manifest(kind,raw,manifest,manifest_digest):
    doc,role=fixture_role(kind,raw);_digest(manifest_digest)
    _need(type(manifest) is dict and manifest['installation_id']==installation_id(kind,raw)
        and manifest['native_read_installation_version']==role['native_read_installation_version']
        and all(manifest[key]==role[key] for key in ('contract','registry_snapshot_digest','authority'))
        and manifest['core']==doc['core']
        and all(manifest[key]==doc[key] for key in ('evidence_root','evidence_identity','preparation_root','preparation_identity')),
        'ntfs.owner_fixture_binding_mismatch')
    view=role_projection(kind,raw)
    grants=view.get('root_grants',[view.get('root_grant')])
    projections=({'current_root':'/ntfs-result','objects_root':'/ntfs-objects'} if role['role']=='Version2'
        else {role['root_binding']:'/ntfs-result'})
    _need(manifest['root_grants']==grants and manifest['root_projections']==projections,'ntfs.owner_fixture_binding_mismatch')
    # Fixed launch verifies actual manifest/config/runtime-graph digests. They
    # cannot be put in this fixture: graph->fixture would introduce a hash cycle.
    return view


def _run(doc,run_id):
    from ...evidence import validate_run_id
    validate_run_id(run_id)
    prefix=doc['request_limits']['run_prefix']
    _need(run_id.startswith(prefix) and len(run_id)>len(prefix),'ntfs.owner_fixture_run_mismatch')


def _captured_value(kind,raw,run_id,candidate_bytes,input_records,payload_length):
    doc,role=fixture_role(kind,raw);_run(doc,run_id)
    _need(type(candidate_bytes) is bytes and len(candidate_bytes)<=2*1024**2)
    value=parse_json_bytes(candidate_bytes,maximum_bytes=2*1024**2)
    _need(type(value) is dict and canonical_bytes(value)==candidate_bytes
        and type(value.get('idempotency_key')) is str and len(value['idempotency_key'])<=128
        and re.fullmatch('[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*',value['idempotency_key']) is not None)
    target=value.get('target_locator')
    _need(type(target) is str and safe_relative_locator(target)==target)
    result={'run_id':run_id,'request_id':value['idempotency_key'],'target_locator':target,
        'candidate_digest':digest_bytes(candidate_bytes),'captured_inputs':input_records}
    if role['role']=='Version2':
        from ...contracts.publish_new_version_v2 import inline_content
        _need(input_records==[] and payload_length is None)
        content=inline_content(value)
        result.update(content_digest=digest_bytes(content),content_length=len(content))
    else:
        _need(type(input_records) is list and len(input_records)==1 and type(input_records[0]) is dict)
        frozen=input_records[0];_need(frozen['binding_id']==value.get('input_binding')=='payload'
            and frozen['freeze_strategy']==('manifest_and_hash' if role['role'] in {'Bundle1','Bundle2'} else 'copy_and_hash')
            and frozen['digest']==frozen['blob_digest'])
        _digest(frozen['digest'])
        maximum={'File1':1024**2,'File2':2*1024**3,'Version1':16*1024**2,'Bundle1':4*1024**3,'Bundle2':4*1024**3}[role['role']]
        _need(type(payload_length) is int and 0<=payload_length<=maximum)
        result.update(payload_digest=frozen['digest'],payload_length=payload_length)
    return result


@dataclass(frozen=True)
class _CapturedOwnerAttempt:
    """One actual Core capture correlation; no dispatch/retry authority."""
    owner: tuple[int,int]
    role: str
    fixture_digest: str
    capture_bytes: bytes

    def document(self):
        _need(self.owner==(os.getpid(),threading.get_ident()),'ntfs.owner_fixture_context_owner')
        return parse_json_bytes(self.capture_bytes,maximum_bytes=2*1024**2)


def captured_attempt(kind,raw,run_id,candidate_bytes,input_records,payload_length):
    """Called ONLY by the exact-type Core seam on real captured/frozen facts.

    The integration must consume the attempt slot once before invoking this,
    including a failed call. No operation JSON can supply this context object.
    """
    doc,role=fixture_role(kind,raw)
    capture=_captured_value(kind,raw,run_id,candidate_bytes,input_records,payload_length)
    return _CapturedOwnerAttempt((os.getpid(),threading.get_ident()),role['role'],digest_bytes(raw),canonical_bytes(capture))


def attempt_record(kind,raw,manifest_digest,captured,intent,plan):
    """Derived from actual validated intent/plan before existing Core dispatch."""
    doc,role=fixture_role(kind,raw)
    _need(type(captured) is _CapturedOwnerAttempt and captured.role==role['role']
        and captured.fixture_digest==digest_bytes(raw),'ntfs.owner_fixture_capture_required')
    capture=captured.document()
    _need(intent['run_id']==plan['run_id']==capture['run_id']
        and intent['contract']==plan['contract']==role['contract']
        and intent['core']==doc['core'] and intent['registry_snapshot_digest']==role['registry_snapshot_digest']
        and intent['native_binding']['installation']=={'id':installation_id(kind,raw),'descriptor_digest':manifest_digest}
        and intent['inputs']==capture['captured_inputs']
        and digest_bytes(canonical_bytes(intent['candidate']['storage']['value']))==capture['candidate_digest'],
        'ntfs.owner_fixture_original_mismatch')
    _need(plan['effects'] and len(plan['effects'])==1
        and plan['effects'][0]['target']=={'root_binding':role['root_binding'],'relative_locator':capture['target_locator']})
    return {'experimental_attempt_version':doc['experimental_admission_version'],'fixture_digest':digest_bytes(raw),
        'owner_scope_id':doc['owner_scope_id'],'role':role['role'],'capture':capture,
        'installation':{'id':installation_id(kind,raw),'descriptor_digest':manifest_digest},
        'intent_digest':profile_digest('intent',intent),'effect_plan_digest':profile_digest('effect-plan',plan)}


def _binding_context(binding):
    from ...installation import _NativeFileCreateReadBinding
    _need(type(binding) is _NativeFileCreateReadBinding,'ntfs.original_read_binding_required')
    admission=binding.experimental_admission
    if admission is None:
        return None
    if not is_fixture(admission.raw):
        from .experimental_file1 import _experimental_admission
        _experimental_admission(binding)
        return None
    _need(type(admission) in tuple(_kinds().values()),'ntfs.experimental_admission_required')
    fixture_role(type(admission),admission.raw)
    return admission


def bind_captured_owner_attempt(binding,*,run_id,candidate,frozen):
    """ROOT-OWNED CORE SEAM 1, after actual capture/freeze, before idempotency.

    Legacy returns unchanged. The actual context's single capture slot is spent
    before validation, so a failed/ambiguous bind never authorizes another try.
    An uninitialized or foreign-process/thread admission is refused. Only the
    real CapturedCandidate/FrozenInput objects produced by Core are accepted.
    """
    admission=_binding_context(binding)
    if admission is None:
        return
    _need(getattr(admission,'_owner_fixture_owner',None)==(os.getpid(),threading.get_ident()),
        'ntfs.owner_fixture_context_owner')
    _need(getattr(admission,'_owner_fixture_capture',None) is None,'ntfs.owner_fixture_capture_consumed')
    object.__setattr__(admission,'_owner_fixture_capture',_CAPTURE_CONSUMED)
    enforce_owner_evidence_budget(binding,run_id=run_id)
    from ...candidate import CapturedCandidate
    from ...freeze import FrozenInput
    _need(type(candidate) is CapturedCandidate and type(frozen) is dict
        and all(type(item) is FrozenInput for item in frozen.values()),'ntfs.owner_fixture_capture_required')
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    check_manifest(type(admission),admission.raw,manifest,binding.manifest_digest)
    records=[item.intent_record() for _,item in sorted(frozen.items())]
    payload=frozen.get('payload')
    state=captured_attempt(type(admission),admission.raw,run_id,candidate.canonical_bytes,records,
        None if payload is None else payload.length)
    object.__setattr__(admission,'_owner_fixture_capture',state)


class _EvidenceBudgetIO:
    """POSIX ext4 metadata only; actual root admission belongs to binding."""
    def __init__(self):
        import sys
        _need(sys.platform.startswith('linux') and hasattr(os,'geteuid'),'ntfs.owner_fixture_budget_linux_required')
        self.uid=os.geteuid()
    def lstat(self,path):return path.lstat()
    def names(self,path):
        with os.scandir(path) as entries:return tuple(row.name for row in entries)


def enforce_owner_evidence_budget(binding,*,run_id,_io=None):
    """Fresh complete metadata census under the SAME outer Core history lock.

    No new journal/counter/index is authoritative. Count ALL current runs and
    retained files, including negative/foreign/unknown originals. The separate
    existing history guard still validates their full semantics and closure.
    This component cap concerns logical bytes in Core evidence plus a bounded
    future-control reserve. It does NOT replace the campaign's physical-volume,
    NTFS, preparation, aggregate32GiB, memory or filesystem-reserve preflight.
    _io is a private in-memory test fixture, never request/config selectable.
    """
    import stat
    admission=_binding_context(binding)
    if admission is None:return None
    doc=fixture_document(admission.raw);_run(doc,run_id)
    check_manifest(type(admission),admission.raw,
        parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2),binding.manifest_digest)
    io=_EvidenceBudgetIO() if _io is None else _io
    _need(type(io.uid) is int and io.uid>=0)
    root=binding.check_evidence_root();runs=root/'.phase'/'runs'
    directories={};files={};members={};total=0;entries=0;pending=[root]
    def state(info,directory):
        _need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400
            and info.st_uid==io.uid and not info.st_mode&0o022
            and (directory or info.st_nlink==1),'ntfs.owner_fixture_budget_unsafe')
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    root_info=io.lstat(root);directories[root]=state(root_info,True)
    while pending:
        directory=pending.pop();names=io.names(directory)
        _need(type(names) is tuple and len(names)==len(set(names))
            and all(type(name) is str and name not in {'','.','..'} and '/' not in name and '\\' not in name for name in names),
            'ntfs.owner_fixture_budget_unsafe')
        members[directory]=frozenset(names)
        for name in names:
            entries+=1;_need(entries<=_MAXIMUM_CENSUS_ENTRIES,'ntfs.owner_fixture_budget_exceeded')
            path=directory/name;info=io.lstat(path)
            if stat.S_ISDIR(info.st_mode):
                directories[path]=state(info,True);pending.append(path)
            else:
                files[path]=state(info,False);_need(type(info.st_size) is int and info.st_size>=0)
                total+=info.st_size
                _need(total+_REMAINING_CORE_CONTROL_BYTES<=doc['request_limits']['maximum_retained_bytes'],
                    'ntfs.owner_fixture_budget_exceeded')
    _need(runs in directories and run_id in members[runs]
        and all(runs/name in directories for name in members[runs]),'ntfs.owner_fixture_budget_unsafe')
    _need(len(members[runs])<=doc['request_limits']['maximum_attempts'],'ntfs.owner_fixture_budget_exceeded')
    for path,before in directories.items():
        _need(state(io.lstat(path),True)==before,'ntfs.owner_fixture_budget_drift')
        names=io.names(path)
        _need(type(names) is tuple and len(names)==len(set(names)) and frozenset(names)==members[path],
            'ntfs.owner_fixture_budget_drift')
    for path,before in files.items():_need(state(io.lstat(path),False)==before,'ntfs.owner_fixture_budget_drift')
    _need(total+_REMAINING_CORE_CONTROL_BYTES<=doc['request_limits']['maximum_retained_bytes'],
        'ntfs.owner_fixture_budget_exceeded')
    return {'scope':'CURRENT_CORE_EVIDENCE_RESOURCE_CENSUS_ONLY_NOT_PROOF','run_count':len(members[runs]),
        'file_count':len(files),'directory_count':len(directories),'logical_bytes':total,
        'remaining_control_reserve_bytes':_REMAINING_CORE_CONTROL_BYTES,'authoritative_counter_created':False,
        'foreign_or_negative_runs_filtered':False,'cross_run_cache':False}


def captured_binding_view(admission,base_view):
    """Use only immutable actual captured facts in the unchanged authority API."""
    _need(type(admission) in tuple(_kinds().values()),'ntfs.experimental_admission_required')
    state=getattr(admission,'_owner_fixture_capture',None)
    if state is None:
        return dict(base_view)
    _need(type(state) is _CapturedOwnerAttempt and state.fixture_digest==digest_bytes(admission.raw),
        'ntfs.owner_fixture_capture_required')
    return dict(base_view,**state.document())


def owner_attempt_document(binding,*,intent,plan):
    """ROOT-OWNED CORE SEAM 2, after validate_intent, before intent/dispatch.

    Core writes this returned DATA through its existing owned EvidenceStore to
    attachments/experimental-attempt.json and includes the actual digest in the
    existing attachment list. This function neither writes nor dispatches.
    """
    admission=_binding_context(binding)
    if admission is None:
        return None
    state=getattr(admission,'_owner_fixture_capture',None)
    return attempt_record(type(admission),admission.raw,binding.manifest_digest,state,intent,plan)


def original_attempt_document(kind,raw,manifest_digest,*,intent,plan):
    """Expected attachment from actual original buffers; no saved proof cache.

    The existing complete original parser remains mandatory. This only derives
    the exact additional scope/capture/intent/plan correlation for its attachment.
    All ordinary input records, including natural frozen_at, are retained.
    """
    _need(type(intent) is dict and type(plan) is dict and type(plan.get('effects')) is list
        and len(plan['effects'])==1,'ntfs.owner_fixture_original_mismatch')
    _,role=fixture_role(kind,raw)
    state=captured_attempt(kind,raw,intent['run_id'],canonical_bytes(intent['candidate']['storage']['value']),
        intent['inputs'],None if role['role']=='Version2' else plan['effects'][0]['content_length'])
    return attempt_record(kind,raw,manifest_digest,state,intent,plan)


def verify_attempt_record(kind,raw,manifest_digest,*,attempt_bytes,intent,plan):
    _need(type(attempt_bytes) is bytes and 0<len(attempt_bytes)<=2*1024**2,'ntfs.owner_fixture_attempt_required')
    expected=original_attempt_document(kind,raw,manifest_digest,intent=intent,plan=plan)
    _need(attempt_bytes==canonical_bytes(expected),'ntfs.owner_fixture_original_mismatch')
    return expected


def original_binding_view(admission,intent,plan):
    """Additional literal view AFTER the existing complete Original parser."""
    _need(type(admission) in tuple(_kinds().values()),'ntfs.experimental_admission_required')
    _,role=fixture_role(type(admission),admission.raw)
    capture=_captured_value(type(admission),admission.raw,intent['run_id'],
        canonical_bytes(intent['candidate']['storage']['value']),intent['inputs'],
        None if role['role']=='Version2' else plan['effects'][0]['content_length'])
    return dict(role_projection(type(admission),admission.raw),**capture)


def check_admission_run(admission,run_id):
    """Launch-only scope check, before any actual attempt capture is possible."""
    if is_fixture(admission.raw):
        _need(type(admission) in tuple(_kinds().values()),'ntfs.experimental_admission_required')
        _run(fixture_document(admission.raw),run_id)
    else:
        _need(admission.document()['run_id']==run_id,'ntfs.experimental_run_mismatch')


def verify_fixture_attachments(admission,binding,run_id,receipt=None,*,_io=None):
    """Fresh ext4 Original attachment checks; no authority or outcome cache.

    The existing Original parser still verifies actual blobs, schemas, plans,
    preconditions and terminal proof. No attachment selects a registry/provider.
    A saved attempt without an Original is unresolved, never an empty history.
    """
    import stat
    from ...streaming import read_bounded_file
    check_admission_run(admission,run_id)
    _need(_binding_context(binding) is admission,'ntfs.owner_fixture_binding_mismatch')
    root=binding.check_evidence_root();run=root/'.phase'/'runs'/run_id
    uid=os.geteuid() if _io is None else _io.uid
    info_at=(lambda path:path.lstat()) if _io is None else _io.lstat
    read=read_bounded_file if _io is None else _io.read_bounded
    def state(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    def control(path,cap):
        info=info_at(path)
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==uid
            and not info.st_mode&0o022,'ntfs.owner_fixture_evidence_mismatch')
        raw=read(path,cap)
        _need(state(info_at(path))==state(info),'ntfs.owner_fixture_evidence_drift')
        return raw
    static=control(run/'attachments'/'experimental-admission.json',32768)
    _need(static==admission.raw,'ntfs.owner_fixture_evidence_mismatch')
    if receipt is not None:
        _need(digest_bytes(static) in receipt['evidence']['attachment_digests'],'ntfs.owner_fixture_evidence_mismatch')
    try:info=info_at(run/'intent.json')
    except FileNotFoundError:
        try:info_at(run/'attachments'/_ATTEMPT_NAME)
        except FileNotFoundError:return frozenset({digest_bytes(static)})
        raise PhaseError('ntfs.owner_fixture_orphan_attempt_unresolved')
    original=control(run/'intent.json',2*1024**2)
    plan_bytes=control(run/'attachments'/'effect-plan.json',2*1024**2)
    intent=parse_json_bytes(original,maximum_bytes=2*1024**2)
    plan=parse_json_bytes(plan_bytes,maximum_bytes=2*1024**2)
    _need(canonical_bytes(intent)==original and canonical_bytes(plan)==plan_bytes,'ntfs.owner_fixture_evidence_mismatch')
    attempt_bytes=control(run/'attachments'/_ATTEMPT_NAME,2*1024**2)
    verify_attempt_record(type(admission),admission.raw,binding.manifest_digest,
        attempt_bytes=attempt_bytes,intent=intent,plan=plan)
    if receipt is not None:
        _need(digest_bytes(attempt_bytes) in receipt['evidence']['attachment_digests'],'ntfs.owner_fixture_evidence_mismatch')
    return frozenset({digest_bytes(static),digest_bytes(attempt_bytes)})


def select_original_tuple(bindings,*,contract,core,installation,registry_snapshot_digest):
    """Read selector over six trusted manifests, before attachment data is read.

    Binding reconstruction/profile validation remains the installation owner's
    responsibility; this helper grants no authority and performs no I/O.
    """
    from ...installation import _NativeFileCreateReadBinding
    _need(type(bindings) is tuple and len(bindings)==6,'ntfs.original_history_binding_mismatch')
    roles=[];rows=[];fixture_digests=set()
    for binding in bindings:
        _need(type(binding) is _NativeFileCreateReadBinding,'ntfs.original_history_binding_mismatch')
        admission=binding.experimental_admission
        doc,role=fixture_role(type(admission),admission.raw);roles.append(role['role'])
        fixture_digests.add(digest_bytes(admission.raw))
        manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
        check_manifest(type(admission),admission.raw,manifest,binding.manifest_digest)
        _need(binding.registry.digest==manifest['registry_snapshot_digest'],'ntfs.original_history_binding_mismatch')
        if (contract==manifest['contract'] and core==manifest['core']
                and installation=={'id':manifest['installation_id'],'descriptor_digest':binding.manifest_digest}
                and registry_snapshot_digest==manifest['registry_snapshot_digest']):rows.append(binding)
    _need(sorted(roles)==sorted(_ROLES) and len(set(roles))==6 and len(fixture_digests)==1
        and len(rows)==1,'ntfs.original_history_binding_mismatch')
    return rows[0]


def select_pre_intent_rejected_role(bindings,*,contract,core):
    """ONLY caller's existing strict no-intent/no-effect rejection branch.

    A malformed/missing native installation on an intent must NEVER call this.
    This selector grants no resolution of an execution Original or unknown.
    """
    _need(type(bindings) is tuple and len(bindings)==6,'ntfs.original_history_binding_mismatch')
    rows=[]
    for row in bindings:
        manifest=parse_json_bytes(row.manifest_bytes,maximum_bytes=2*1024**2)
        # Validate the complete six-role domain, even though this receipt has
        # no installation identity. No target/key/run filter is permitted.
        select_original_tuple(bindings,contract=manifest['contract'],core=manifest['core'],
            installation={'id':manifest['installation_id'],'descriptor_digest':row.manifest_digest},
            registry_snapshot_digest=manifest['registry_snapshot_digest'])
        if contract==manifest['contract'] and core==manifest['core']:rows.append(row)
    _need(len(rows)==1,'ntfs.original_history_binding_mismatch')
    return rows[0]


def owner_history_buffers(raw,expected_digest,*,active_bytes,active_digest):
    """One shared fixed fixture, six stable role manifests; no per-run rows."""
    import base64
    _need(type(raw) is bytes and len(raw)<=2*1024**2 and digest_bytes(raw)==expected_digest,
        'ntfs.accepted_history_binding_mismatch')
    value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
    if type(value)is dict and value.get('history_manifest_set_version')=='3.0':
        from .owner_semantic_history import owner3_history_buffers
        return owner3_history_buffers(raw,expected_digest,active_bytes=active_bytes,active_digest=active_digest)
    _need(type(value) is dict and canonical_bytes(value)==raw and set(value)=={
        'history_manifest_set_version','fixture_base64','fixture_digest','manifests'}
        and value['history_manifest_set_version']=='2.0','ntfs.accepted_history_shape')
    def decode(encoded,digest,limit):
        _digest(digest);_need(type(encoded) is str,'ntfs.accepted_history_shape')
        try:body=base64.b64decode(encoded,validate=True)
        except (ValueError,UnicodeError) as error:raise PhaseError('ntfs.accepted_history_shape') from error
        _need(len(body)<=limit and base64.b64encode(body).decode('ascii')==encoded and digest_bytes(body)==digest,
            'ntfs.accepted_history_binding_mismatch')
        return body
    fixture=decode(value['fixture_base64'],value['fixture_digest'],32768);fixture_document(fixture)
    rows=value['manifests'];_need(type(rows) is list and len(rows)==6,'ntfs.accepted_history_shape')
    buffers=[];kinds=_kinds()
    for role,row in zip(_ROLES,rows,strict=True):
        _need(type(row) is dict and set(row)=={'role','manifest_base64','manifest_digest'}
            and row['role']==role,'ntfs.accepted_history_shape')
        body=decode(row['manifest_base64'],row['manifest_digest'],2*1024**2)
        manifest=parse_json_bytes(body,maximum_bytes=2*1024**2)
        _need(canonical_bytes(manifest)==body,'ntfs.accepted_history_shape')
        check_manifest(kinds[role],fixture,manifest,row['manifest_digest'])
        buffers.append((body,row['manifest_digest'],fixture,kinds[role]))
    _need(type(active_bytes) is bytes and digest_bytes(active_bytes)==active_digest
        and sum(body==active_bytes and digest==active_digest for body,digest,_,_ in buffers)==1,
        'ntfs.accepted_history_binding_mismatch')
    return tuple(buffers)


def validate_owner_history_bindings(active,bindings):
    """Fresh exact registry/implementation checks on all six installed readers."""
    from ...installation import _NativeFileCreateReadBinding,_native_experimental_read_binding
    _need(type(active) is _NativeFileCreateReadBinding and type(bindings) is tuple,
        'ntfs.original_history_binding_mismatch')
    _need(type(active.experimental_admission) in tuple(_kinds().values()),'ntfs.experimental_admission_required')
    active_raw=active.experimental_admission.raw;active_doc=fixture_document(active_raw)
    if active_doc['experimental_admission_version']=='3.0':
        from .owner_semantic_history import validate_owner3_history_bindings
        return validate_owner3_history_bindings(active,bindings)
    _need(len(bindings)==6,'ntfs.original_history_binding_mismatch')
    manifests=[]
    for role,row in zip(_ROLES,bindings,strict=True):
        _need(type(row) is _NativeFileCreateReadBinding and type(row.experimental_admission) is _kinds()[role]
            and row.experimental_admission.raw==active_raw and row._qualification_context is None,
            'ntfs.original_history_binding_mismatch')
        checked=_native_experimental_read_binding(manifest_bytes=row.manifest_bytes,
            expected_manifest_digest=row.manifest_digest,admission=row.experimental_admission)
        _need(type(row.registry) is type(checked.registry) and row.registry.digest==checked.registry.digest
            and canonical_bytes(row.registry.to_document())==canonical_bytes(checked.registry.to_document()),
            'ntfs.original_history_binding_mismatch')
        row.experimental_admission.profile(row)
        manifests.append(parse_json_bytes(row.manifest_bytes,maximum_bytes=2*1024**2))
    common=('core','composition','evidence_root','evidence_identity','preparation_root','preparation_identity')
    _need(all(all(other[key]==manifests[0][key] for key in common) for other in manifests[1:])
        and sum(row.manifest_bytes==active.manifest_bytes and row.manifest_digest==active.manifest_digest
            and row.experimental_admission.raw==active_raw for row in bindings)==1,
        'ntfs.original_history_domain_mismatch')
    return bindings
