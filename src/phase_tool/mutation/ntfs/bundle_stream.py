"""UNSELECTED bundle data prerequisite; no authority, target or lifecycle.

Wrap the existing file2 data roles for exact ordered member occurrences.
One future fixed parent must still authenticate the complete original, retain
its existing gate/process/deadline and own the sole GO. Bytes/tokens establish
no Windows installation, namespace exclusion, receipt or terminal outcome.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import os
from pathlib import Path

from ...bundle import MAX_MEMBERS, MAX_TOTAL_BYTES, parse_manifest
from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...streaming import FILE_LIMIT
from .file2_stream import (
    _CHUNK, _File2SnapshotSource, _File2TwoPassReceiver, _failure,
    _file2_verified_source, _header, _token,
)
from .native import _require

_PROTOCOL = 'phase.native.bundle.bytes'
_VERSION = '1.0'
_HEADER_LIMIT = 2*1024**2


def _bundle_header(*, context_bytes, channel_id, manifest_bytes):
    _require(type(manifest_bytes) is bytes, 'ntfs.bundle_manifest_required')
    manifest = parse_manifest(manifest_bytes)
    # Reuse exact context/channel validation; this is data correlation only.
    checked = parse_json_bytes(_header(context_bytes=context_bytes,
        channel_id=channel_id, content_digest=digest_bytes(manifest_bytes),
        content_length=len(manifest_bytes)))
    raw = canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'header',
        'context':checked['context'],'channel_id':channel_id,
        'manifest_digest':digest_bytes(manifest_bytes),
        'manifest_base64':base64.b64encode(manifest_bytes).decode('ascii')})
    _require(0<len(raw)<=_HEADER_LIMIT, 'ntfs.bundle_header_bound')
    return manifest, raw


def _member_headers(header, manifest):
    value = parse_json_bytes(header, maximum_bytes=_HEADER_LIMIT)
    context = canonical_bytes(value['context'])
    hd = digest_bytes(header)
    result = []
    channels = set()
    for ordinal, item in enumerate(manifest['members']):
        channel = digest_bytes(canonical_bytes({
            'domain':'phase.native.bundle.member.v1','outer_header_digest':hd,
            'ordinal':ordinal,'path':item['path']})).removeprefix('sha256:')[:32]
        _require(channel not in channels, 'ntfs.bundle_member_channel_collision')
        channels.add(channel)
        result.append(_header(context_bytes=context,channel_id=channel,
            content_digest=item['digest'],content_length=item['length']))
    return tuple(result)


def _bundle_token(header, kind):
    return canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':kind,
        'header_digest':digest_bytes(header)})


def _bundle_end(header, manifest, phase):
    return canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'end',
        'header_digest':digest_bytes(header),'pass':phase,
        'manifest_digest':parse_json_bytes(header,maximum_bytes=_HEADER_LIMIT)['manifest_digest'],
        'member_count':len(manifest['members']),'total_length':manifest['total_length']})


def _bundle_source_bounds(manifest_bytes):
    """Logical payload/FD bounds, not disk-block reservation or RSS proof.

    Existing snapshot acquisition accepts up to FILE_LIMIT before comparing
    the expected length. An invalid last blob may coexist with all preceding
    valid snapshots: reserve declared total + FILE_LIMIT, up to 6GiB, plus
    filesystem overhead/headroom and the separately retained original blobs.
    """
    manifest = parse_manifest(manifest_bytes)
    chunks = sum((m['length']+_CHUNK-1)//_CHUNK for m in manifest['members'])
    _require(chunks<=MAX_TOTAL_BYTES//_CHUNK+MAX_MEMBERS,
        'ntfs.bundle_vector_bound')
    return {'snapshot_payload_peak':manifest['total_length']+FILE_LIMIT,
        'snapshot_fds':len(manifest['members']),'acquisition_fd_overhead':2,
        'chunk_hashes':chunks,'header_bytes_limit':_HEADER_LIMIT}


class _BundleTwoPassReceiver:
    """Bounded data checker only; no worker, pipe, sink or GO ownership."""

    def __init__(self, *, context_bytes, channel_id, manifest_bytes):
        self._manifest,self._header_raw = _bundle_header(context_bytes=context_bytes,
            channel_id=channel_id,manifest_bytes=manifest_bytes)
        self._headers = _member_headers(self._header_raw,self._manifest)
        self._ends = {phase:_bundle_end(self._header_raw,self._manifest,phase) for phase in (1,2)}
        self._manifest_digest = digest_bytes(manifest_bytes)
        self._children = tuple(_File2TwoPassReceiver(
            context_bytes=context_bytes,
            channel_id=parse_json_bytes(h)['channel_id'],
            content_digest=m['digest'],content_length=m['length'])
            for h,m in zip(self._headers,self._manifest['members']))
        self._state='header'
        self._index=self._in_member=self._released=self._offset=0

    def feed(self, raw):
        try:
            _require(self._state in ('header','first','replay'),
                'ntfs.bundle_sequence_unavailable')
            _require(type(raw) is bytes and 0<len(raw)<=_HEADER_LIMIT,
                'ntfs.bundle_frame_bound')
            if self._state=='header':
                _require(raw==self._header_raw, 'ntfs.bundle_header_mismatch')
                self._state='first'
                return None
            phase=1 if self._state=='first' else 2
            if raw==self._ends[phase]:
                _require(self._index==len(self._children) and self._in_member==0,
                    'ntfs.bundle_members_incomplete')
                self._state='ready' if phase==1 else 'complete'
                return None
            _require(self._index<len(self._children), 'ntfs.bundle_extra_frame')
            item=self._manifest['members'][self._index]
            child=self._children[self._index]
            chunk=child.feed(raw)
            self._in_member+=1
            count=(item['length']+_CHUNK-1)//_CHUNK+(2 if phase==1 else 1)
            _require(self._in_member<=count, 'ntfs.bundle_member_frame_count')
            result=None
            if phase==1:
                _require(chunk is None, 'ntfs.bundle_first_pass_release')
            elif chunk is not None:
                result=(item['path'],self._offset,chunk)
                self._offset+=len(chunk)
                self._released+=len(chunk)
            if self._in_member==count:
                _require(chunk is None, 'ntfs.bundle_member_end_required')
                if phase==1:
                    _require(child.ready_frame()==_token(digest_bytes(self._headers[self._index]),'ready'),
                        'ntfs.bundle_child_ready_mismatch')
                else:
                    child.finish()
                    _require(self._offset==item['length'], 'ntfs.bundle_member_incomplete')
                self._index+=1
                self._in_member=self._offset=0
            return result
        except BaseException:
            self._state='failed'
            raise

    def ready_frame(self):
        try:
            _require(self._state=='ready', 'ntfs.bundle_first_pass_incomplete')
            self._state='rewound'
            return _bundle_token(self._header_raw,'ready')
        except BaseException:
            self._state='failed'
            raise

    def accept_rewound(self, raw):
        try:
            _require(self._state=='rewound' and type(raw) is bytes
                and raw==_bundle_token(self._header_raw,'rewound'),
                'ntfs.bundle_rewind_token_mismatch')
            for child,header in zip(self._children,self._headers):
                child.accept_rewound(_token(digest_bytes(header),'rewound'))
            self._state='go'
        except BaseException:
            self._state='failed'
            raise

    def accept_go(self, raw):
        try:
            _require(self._state=='go' and type(raw) is bytes
                and raw==_bundle_token(self._header_raw,'go'),
                'ntfs.bundle_go_token_mismatch')
            for child,header in zip(self._children,self._headers):
                child.accept_go(_token(digest_bytes(header),'go'))
            self._state='replay'
            self._index=self._in_member=self._offset=0
        except BaseException:
            self._state='failed'
            raise

    def finish(self):
        try:
            _require(self._state=='complete'
                and self._released==self._manifest['total_length'],
                'ntfs.bundle_replay_incomplete')
            self._state='consumed'
            return {'accepted_manifest_digest':self._manifest_digest,
                'accepted_members':len(self._children),
                'accepted_payload_length':self._released}
        except BaseException:
            self._state='failed'
            raise


class _BundleSnapshotSource:
    """Same-process borrowed snapshot contexts; never a native GO capability."""

    def __init__(self, sources, *, context_bytes, channel_id, manifest_bytes):
        self._manifest,self._header_raw = _bundle_header(context_bytes=context_bytes,
            channel_id=channel_id,manifest_bytes=manifest_bytes)
        headers=_member_headers(self._header_raw,self._manifest)
        _require(type(sources) is tuple and len(sources)==len(headers),
            'ntfs.bundle_snapshot_binding')
        for source,header in zip(sources,headers):
            _require(type(source) is _File2SnapshotSource and source._header_raw==header,
                'ntfs.bundle_snapshot_binding')
            source._check('first-unused')
        self._sources,self._headers=sources,headers
        self._state='first-unused'

    def _check(self, state):
        _require(self._state==state and self._sources is not None,
            'ntfs.bundle_source_unavailable')

    def _frames(self, phase):
        state='first-active' if phase==1 else 'replay-active'
        completed=False
        try:
            self._check(state)
            if phase==1:
                yield self._header_raw
                self._check(state)
            for source in self._sources:
                self._check(state)
                frames=source.first_frames() if phase==1 else source.replay_frames()
                try:
                    for raw in frames:
                        self._check(state)
                        yield raw
                        self._check(state)
                finally:
                    frames.close()
                self._check(state)
                source._check('first-done' if phase==1 else 'emitted')
            yield _bundle_end(self._header_raw,self._manifest,phase)
            self._check(state)
            completed=True
        finally:
            if self._state==state:
                self._state=('first-done' if phase==1 else 'emitted') if completed else 'failed'
            elif self._state not in ('failed','retired'):
                self._state='failed'

    def first_frames(self):
        try:
            self._check('first-unused')
            self._state='first-active'
            return self._frames(1)
        except BaseException:
            self._state='failed'
            raise

    def rewind_after_ready(self, raw):
        try:
            self._check('first-done')
            self._state='rewinding'
            _require(type(raw) is bytes and raw==_bundle_token(self._header_raw,'ready'),
                'ntfs.bundle_ready_mismatch')
            for source,header in zip(self._sources,self._headers):
                got=source.rewind_after_ready(_token(digest_bytes(header),'ready'))
                _require(got==_token(digest_bytes(header),'rewound'),
                    'ntfs.bundle_child_rewind_mismatch')
                self._check('rewinding')
            self._state='rewound'
            return _bundle_token(self._header_raw,'rewound')
        except BaseException:
            self._state='failed'
            raise

    def replay_frames(self):
        try:
            self._check('rewound')
            self._state='replay-active'
            return self._frames(2)
        except BaseException:
            self._state='failed'
            raise

    def _retire(self):
        self._state='retired'
        self._sources=None



def _bundle_failure(error):
    """Retain cause/context/group edges, including acquisition cleanup errors.

    Existing snapshot contexts may raise before __enter__ returns. They own
    that failed acquisition's cleanup; never call __exit__ again. Record its
    exception graph and attempt every previously entered context once.
    """
    pending=[error];positions={id(error):0};records=[]
    for value in pending:
        record=_failure(value)
        record['context_suppressed']=bool(value.__suppress_context__)
        record['details']=value.details if isinstance(value,PhaseError) else None
        for name,linked in (('cause',value.__cause__),('context',value.__context__)):
            if linked is not None:
                if id(linked) not in positions:
                    positions[id(linked)]=len(pending);pending.append(linked)
                record[name]=positions[id(linked)]
            else:
                record[name]=None
        groups=value.exceptions if isinstance(value,BaseExceptionGroup) else ()
        children=[]
        for linked in groups:
            if id(linked) not in positions:
                positions[id(linked)]=len(pending);pending.append(linked)
            children.append(positions[id(linked)])
        record['group']=children
        records.append(record)
    return {'root':0,'exceptions':records}


def _bundle_fd_preflight(member_count):
    """Read-only capacity observation, never a reservation or policy change."""
    import resource
    soft,_=resource.getrlimit(resource.RLIMIT_NOFILE)
    observed=len(os.listdir('/proc/self/fd'))
    _require(soft==resource.RLIM_INFINITY or soft>=observed+member_count+2,
        'ntfs.bundle_snapshot_fd_capacity')


def _bundle_diagnostic(error, failures):
    """Best effort AFTER all essential closes; raw exceptions remain retained."""
    try:
        return _bundle_failure(error)
    except BaseException as diagnostic:
        failures.append(diagnostic)
        return {'diagnostic_unavailable':True,'type':type(error).__name__,
            'code':error.code if isinstance(error,PhaseError) else None,
            'formatter_error_type':type(diagnostic).__name__}


@contextmanager
def _bundle_verified_source(blob_root: Path, *, context_bytes, channel_id, manifest_bytes):
    """Acquire all existing file2 snapshots; close ALL contexts on any failure.

    The caller owns verified root/original identity, resource admission and
    deadlines. This unselected factory has no authority, target path or spool.
    Up to6GiB malformed capture payload plus overhead/headroom must be budgeted.
    """
    _require(os.name=='posix' and os.uname().sysname=='Linux',
        'ntfs.bundle_linux_source_required')
    manifest,header=_bundle_header(context_bytes=context_bytes,
        channel_id=channel_id,manifest_bytes=manifest_bytes)
    bounds=_bundle_source_bounds(manifest_bytes)
    _bundle_fd_preflight(bounds['snapshot_fds'])
    managers=[];sources=[];source=None;primary=None;errors=[]
    acquisition=None;retirement=None
    try:
        for item,member_header in zip(manifest['members'],_member_headers(header,manifest)):
            child=parse_json_bytes(member_header)
            manager=_file2_verified_source(Path(blob_root)/item['digest'].removeprefix('sha256:'),
                context_bytes=context_bytes,channel_id=child['channel_id'],
                content_digest=item['digest'],content_length=item['length'])
            try:
                borrowed=manager.__enter__()
            except BaseException as error:
                acquisition=error
                raise
            managers.append(manager)
            sources.append(borrowed)
        source=_BundleSnapshotSource(tuple(sources),context_bytes=context_bytes,
            channel_id=channel_id,manifest_bytes=manifest_bytes)
        yield source
    except BaseException as error:
        primary=error
        raise
    finally:
        if source is not None:
            source._state='retiring'  # Block paused generators BEFORE any fallible cleanup.
            try:
                source._retire()
            except BaseException as error:
                retirement=error
        # Essential unwind first. Diagnostic formatting must never skip a close.
        for ordinal,manager in reversed(tuple(enumerate(managers))):
            try:
                manager.__exit__(None,None,None)
            except BaseException as error:
                errors.append((ordinal,error))
        if errors or retirement is not None or acquisition is not None:
            failures=[]
            primary_info=None if primary is None else _bundle_diagnostic(primary,failures)
            acquisition_info=(primary_info if acquisition is primary else
                None if acquisition is None else _bundle_diagnostic(acquisition,failures))
            details={'primary':primary_info,'acquisition':acquisition_info,
                'retirement':None if retirement is None else _bundle_diagnostic(retirement,failures),
                'finalization':[{'member_ordinal':ordinal,'error':_bundle_diagnostic(error,failures)}
                    for ordinal,error in errors]}
            details['diagnostic_complete']=not failures
            details['diagnostic_error_types']=[type(e).__name__ for e in failures]
            outcome=PhaseError('ntfs.bundle_source_finalization_unavailable'
                if errors or retirement is not None else 'ntfs.bundle_snapshot_acquisition_unavailable',
                details=details)
            # In-process originals survive even if rendering their diagnostics fails.
            # They are not serialized as successful evidence or remotely dispatched.
            outcome.original_primary=primary
            outcome.finalization_errors=tuple(errors)
            outcome.retirement_error=retirement
            outcome.diagnostic_errors=tuple(failures)
            raise outcome from primary
