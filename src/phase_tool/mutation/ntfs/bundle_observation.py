"""Closed native phase_bundle_v1 verification for the pending Core bundle slice.

The representation/owner are unchanged. All reads are relative to real pinned
handles; owner device/inode comes from an actual same-HANDLE fstat bridge. This
module does not grant execution, mutate storage or replace Core evidence.
"""
import hashlib
import re

from ...bundle import MANIFEST_NAME, OWNER_NAME, MAX_MEMBERS, parse_manifest
from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...evidence import validate_run_id
from ...errors import PhaseError
from ...paths import safe_relative_locator
from ...streaming import REQUEST_LIMIT
from .native import NativeIO, NativeHandle, NativeIdentity, _leaf, _require
from .scoped import NativeRootGrant, NativeScopedTarget

_DIGEST = re.compile('sha256:[0-9a-f]{64}')



class _BundleHandlePins:
    """Transient native handle scope; essential closes precede all diagnostics.

    This preserves body and multiple close failures instead of relying on an
    exception context that the existing bounded serializer does not traverse.
    It never retries an unknown close and creates no persistent operation state.
    """
    def __init__(self):self._handles=[];self._state='open'
    def hold(self,handle):
        _require(self._state=='open' and type(handle) is NativeHandle
            and handle.finalization_state=='open','ntfs.bundle_pins_closed')
        self._handles.append(handle)
        return handle
    def __enter__(self):
        _require(self._state=='open','ntfs.bundle_pins_closed')
        return self
    def __exit__(self,kind,value,tb):
        _require(self._state=='open','ntfs.bundle_pins_closed')
        self._state='closing';errors=[]
        for handle in reversed(self._handles):
            try:handle.close()
            except BaseException as error:errors.append(error)
        self._state='unknown' if errors else 'closed'
        if errors:
            from .uncertainty import _diagnostic
            error=PhaseError('ntfs.bundle_handles_finalization_failed',details={
                'primary_error':None if value is None else _diagnostic(value),
                'close_errors':[_diagnostic(e)for e in errors],'finalization':'unknown'})
            error.primary_error=value;error.close_errors=tuple(errors)
            raise error from (value if value is not None else errors[0])
        self._handles.clear()


def _read_metadata(io, handle, name, maximum):
    with io.child(handle,name,directory=False) as source:
        identity=io.identity(source)
        before=io.assert_object(source,directory=False,expected=identity)
        _require(before['links']==1 and before['length']<=maximum,'ntfs.bundle_metadata_bound')
        data=b''.join(io.read_chunks(source,maximum))
        after=io.assert_object(source,directory=False,expected=identity)
        _require(len(data)==before['length']==after['length'] and after['links']==1,
            'ntfs.bundle_metadata_changed')
    return data


def verify_bundle_handle(io, handle, *, expected_identity, expected_manifest=None,
                         run_id=None, plan_digest=None):
    """Sample one pinned directory tree; no path reopen or consumer commit.

    Every child stays pinned until the second membership/identity check. Files
    deny DELETE while read. This is byte verification under the existing Phase
    root coordination, not global protection against unrelated content writes.
    """
    _require(type(expected_identity) is NativeIdentity,'ntfs.invalid_identity')
    _require((run_id is None)==(plan_digest is None),'ntfs.bundle_owner_binding_required')
    io.assert_object(handle,directory=True,expected=expected_identity)
    pair=io.directory_stat_identity(handle,expected_identity)
    manifest_raw=_read_metadata(io,handle,MANIFEST_NAME,REQUEST_LIMIT)
    manifest=parse_manifest(manifest_raw)
    _require(expected_manifest is None or manifest_raw==expected_manifest,'bundle.manifest_mismatch')
    owner_raw=_read_metadata(io,handle,OWNER_NAME,32768)
    owner=parse_json_bytes(owner_raw,maximum_bytes=32768)
    _require(type(owner) is dict and canonical_bytes(owner)==owner_raw
        and set(owner)=={'owner_version','run_id','plan_digest','device','inode'}
        and owner['owner_version']=='1.0' and type(owner['run_id']) is str
        and type(owner['plan_digest']) is str and _DIGEST.fullmatch(owner['plan_digest']) is not None
        and type(owner['device']) is int and type(owner['inode']) is int
        and {'device':owner['device'],'inode':owner['inode']}==pair,'bundle.owner_mismatch')
    validate_run_id(owner['run_id'])
    _require(run_id is None or (owner['run_id']==run_id and owner['plan_digest']==plan_digest),
        'bundle.owner_mismatch')
    members={item['path']:item for item in manifest['members']}
    expected_files=set(members)|{MANIFEST_NAME,OWNER_NAME}
    expected_dirs=set()
    children={}
    for path in expected_files:
        parts=path.split('/')
        for part in parts:_leaf(part)
        for index,part in enumerate(parts):
            parent='/'.join(parts[:index]);name='/'.join(parts[:index+1])
            directory=index<len(parts)-1
            old=children.setdefault(parent,{})
            _require(part not in old or old[part] is directory,'bundle.path_prefix_conflict')
            old[part]=directory
            if directory:expected_dirs.add(name)
    observed={};directories=[];seen_files=set();seen_dirs=set()
    with _BundleHandlePins() as pins:
        pending=[('',handle)]
        while pending:
            relative,directory=pending.pop()
            identity=io.identity(directory)
            entries=io.entries(directory,MAX_MEMBERS+2)
            wanted=children.get(relative,{})
            _require(set(entries)==set(wanted)
                and all(entries[name]['directory'] is is_directory for name,is_directory in wanted.items()),
                'bundle.membership_mismatch')
            directories.append((directory,identity,entries))
            for name in sorted(entries):
                row=entries[name];path=relative+'/'+name if relative else name
                child=pins.hold(io.child(directory,name,directory=row['directory']))
                child_id=io.identity(child)
                _require(child_id.volume_serial==expected_identity.volume_serial
                    and child_id.file_id==row['file_id'],'ntfs.bundle_member_identity_mismatch')
                facts=io.assert_object(child,directory=row['directory'],expected=child_id)
                if row['directory']:
                    seen_dirs.add(path);pending.append((path,child));continue
                seen_files.add(path)
                _require(facts['links']==1,'ntfs.bundle_member_link_forbidden')
                if path in members:
                    item=members[path];actual=io.hash_file(child,item['length'])
                    _require(actual==(item['digest'],item['length']),'bundle.member_mismatch')
                    _require(io.info(child)['links']==1,'ntfs.bundle_member_link_forbidden')
                    observed[path]={'path':path,'native_identity':child_id.as_dict(),
                        'digest':actual[0],'length':actual[1]}
                else:
                    expected=manifest_raw if path==MANIFEST_NAME else owner_raw
                    _require(b''.join(io.read_chunks(child,len(expected)))==expected,'ntfs.bundle_metadata_changed')
                io.assert_object(child,directory=False,expected=child_id)
        _require(seen_files==expected_files and seen_dirs==expected_dirs,'bundle.membership_mismatch')
        for directory,identity,entries in reversed(directories):
            io.assert_object(directory,directory=True,expected=identity)
            _require(io.entries(directory,MAX_MEMBERS+2)==entries,'ntfs.bundle_membership_changed')
        io.assert_object(handle,directory=True,expected=expected_identity)
        _require(io.directory_stat_identity(handle,expected_identity)==pair,'ntfs.bundle_stat_identity_mismatch')
    # Compact canonical byte/identity closure, bounded by the existing manifest.
    # It is not an extra journal; fresh inspect physically repeats this verifier.
    digest=hashlib.sha256(b'Phase.NTFS.BundleMembers.v1\0')
    for item in manifest['members']:digest.update(canonical_bytes(observed[item['path']])+b'\n')
    return {'exists':True,'native_identity':expected_identity.as_dict(),
        'manifest_digest':digest_bytes(manifest_raw),'manifest_length':len(manifest_raw),
        'owner':owner,'stat_identity':pair,'member_count':len(members),
        'total_length':manifest['total_length'],'member_observations_digest':'sha256:'+digest.hexdigest()}


def observe_bundle(grant, locator, *, expected_identity=None):
    _require(type(grant) is NativeRootGrant,'ntfs.invalid_root_grant')
    locator=safe_relative_locator(locator);io=NativeIO()
    with NativeScopedTarget(io,grant,locator) as scope:
        scope.assert_bound()
        try:
            handle=io.child(scope.parent,scope.name,directory=True)
        except PhaseError as error:
            if error.code!='ntfs.open_failed' or error.details!={'ntstatus':'0xc0000034'}:raise
            state={'known':True,'exists':False,'digest':None,'length':None,'head_token':None}
            native={'exists':False,'native_identity':None}
        else:
            with handle:
                identity=io.identity(handle)
                _require(expected_identity is None or identity==NativeIdentity.parse(expected_identity),
                    'ntfs.observer_identity_mismatch')
                native=verify_bundle_handle(io,handle,expected_identity=identity)
                scope.assert_directory_name(handle,identity)
                state={'known':True,'exists':True,'digest':native['manifest_digest'],
                    'length':native['manifest_length'],'head_token':None}
        _require(expected_identity is None or (native['exists'] is True
            and native['native_identity']==expected_identity),'ntfs.observer_identity_mismatch')
        scope.assert_bound()
    _require(not io._handles and not getattr(io,'_bundle_stat_ownership_unknown',False),'ntfs.observer_handle_finalization_unknown')
    return {'bundle_observation_version':'1.0','state':state,'native':native,
        'grant':grant.as_dict(),'locator':locator,'handles_finalized':True}
