"""Unselected file2 byte-protocol prerequisite, never native admission.

The future fixed caller must authenticate the FULL original/installation before
constructing these data roles. Matching frames/tokens authenticate no process,
grant, actual rewind in another process, GO, target, EOF or worker exit.
No NativeIO, Core selector, receipt, journal, queue or durable state is created.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import sys

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...evidence import validate_run_id
from ...streaming import FILE_LIMIT, _verified_blob_snapshot, fingerprint
from .native import _require


_PROTOCOL = 'phase.native.file2.bytes'
_VERSION = '1.0'
_CHUNK = 256*1024
_MAX_CHUNKS = FILE_LIMIT//_CHUNK
_MAX_FRAME = 2*_CHUNK
_CONTEXT = {'run_id','intent_digest','installation_digest','operation_nonce'}
_COMMON = {'protocol','version','kind','header_digest','pass'}
_DIGEST = re.compile('sha256:[0-9a-f]{64}')


def _header(*, context_bytes: bytes, channel_id: str,
            content_digest: str, content_length: int) -> bytes:
    _require(type(context_bytes) is bytes and len(context_bytes)<=4096,
        'ntfs.file2_context_required')
    context=parse_json_bytes(context_bytes,maximum_bytes=4096)
    _require(type(context) is dict and set(context)==_CONTEXT
        and canonical_bytes(context)==context_bytes
        and type(context['run_id']) is str
        and type(context['operation_nonce']) is str
        and re.fullmatch('[0-9a-f]{32}',context['operation_nonce']) is not None,
        'ntfs.file2_context_required')
    validate_run_id(context['run_id'])
    _require(all(type(context[k]) is str and _DIGEST.fullmatch(context[k]) is not None
        for k in ('intent_digest','installation_digest')),'ntfs.file2_context_required')
    _require(type(channel_id) is str and re.fullmatch('[0-9a-f]{32}',channel_id) is not None,
        'ntfs.file2_channel_required')
    _require(type(content_digest) is str and _DIGEST.fullmatch(content_digest) is not None
        and type(content_length) is int and 0<=content_length<=FILE_LIMIT,
        'ntfs.file2_content_bound')
    return canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'header',
        'channel_id':channel_id,'context':context,'content_digest':content_digest,
        'content_length':content_length,'chunk_bytes':_CHUNK,
        'chunk_count':(content_length+_CHUNK-1)//_CHUNK})


def _token(header_digest: str, kind: str) -> bytes:
    return canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,
        'kind':kind,'header_digest':header_digest})


def _frame(raw: bytes) -> dict:
    _require(type(raw) is bytes and 0<len(raw)<=_MAX_FRAME,'ntfs.file2_frame_bound')
    value=parse_json_bytes(raw,maximum_bytes=_MAX_FRAME)
    _require(type(value) is dict and canonical_bytes(value)==raw
        and value.get('protocol')==_PROTOCOL and value.get('version')==_VERSION,
        'ntfs.file2_frame_shape')
    return value


class _File2TwoPassReceiver:
    """One-shot bounded data checker; byte release is not physical execution.

    First-pass payload is discarded after its digest is recorded. Only replay
    bytes checked against the ACTUAL first-pass vector can be returned by feed.
    The caller must retain its existing gate, actual GO owner, framing/EOF and
    process witnesses. finish reports no receipt, target fact or quiescence.
    """
    def __init__(self, *, context_bytes: bytes, channel_id: str,
                 content_digest: str, content_length: int):
        self._header_raw=_header(context_bytes=context_bytes,channel_id=channel_id,
            content_digest=content_digest,content_length=content_length)
        self._header_digest=digest_bytes(self._header_raw)
        self._digest,self._length=content_digest,content_length
        self._chunks=(content_length+_CHUNK-1)//_CHUNK
        self._state='header'
        self._hashes: list[bytes]=[]
        self._hash=hashlib.sha256()
        self._offset=self._index=0

    def feed(self, raw: bytes) -> bytes | None:
        try:
            _require(self._state in ('header','first','replay'),'ntfs.file2_sequence_unavailable')
            frame=_frame(raw)
            if self._state=='header':
                _require(raw==self._header_raw,'ntfs.file2_header_mismatch')
                self._state='first'
                return None
            phase=1 if self._state=='first' else 2
            _require(frame.get('header_digest')==self._header_digest
                and type(frame.get('pass')) is int and frame['pass']==phase,
                'ntfs.file2_pass_mismatch')
            if frame.get('kind')=='end':
                _require(set(frame)==_COMMON|{'content_digest','content_length','chunk_count'}
                    and type(frame['content_length']) is int and type(frame['chunk_count']) is int
                    and frame['content_length']==self._offset==self._length
                    and frame['chunk_count']==self._index==self._chunks==len(self._hashes)
                    and frame['content_digest']==self._digest=='sha256:'+self._hash.hexdigest(),
                    'ntfs.file2_end_mismatch')
                self._state='ready' if phase==1 else 'complete'
                return None
            _require(frame.get('kind')=='chunk'
                and set(frame)==_COMMON|{'index','offset','content_base64'}
                and type(frame['index']) is int and frame['index']==self._index<self._chunks
                and type(frame['offset']) is int and frame['offset']==self._offset,
                'ntfs.file2_chunk_order')
            wanted=min(_CHUNK,self._length-self._offset)
            text=frame['content_base64']
            _require(wanted>0 and type(text) is str and len(text)==(wanted+2)//3*4,
                'ntfs.file2_chunk_bound')
            chunk=base64.b64decode(text,validate=True)
            _require(len(chunk)==wanted and base64.b64encode(chunk).decode('ascii')==text,
                'ntfs.file2_chunk_encoding')
            actual=hashlib.sha256(chunk).digest()
            if phase==1:
                _require(len(self._hashes)==self._index<_MAX_CHUNKS,'ntfs.file2_vector_bound')
                self._hashes.append(actual)
            else:
                # Before hash/offset update and BEFORE this chunk can reach a sink.
                _require(actual==self._hashes[self._index],'ntfs.file2_replay_mismatch')
            self._hash.update(chunk)
            self._offset+=len(chunk);self._index+=1
            return None if phase==1 else chunk
        except BaseException:
            self._state='failed'
            raise

    def ready_frame(self) -> bytes:
        try:
            _require(self._state=='ready','ntfs.file2_first_pass_incomplete')
            self._state='rewound'
            return _token(self._header_digest,'ready')
        except BaseException:
            self._state='failed'
            raise

    def accept_rewound(self, raw: bytes) -> None:
        try:
            _require(self._state=='rewound' and type(raw) is bytes
                and raw==_token(self._header_digest,'rewound'),'ntfs.file2_rewind_token_mismatch')
            self._state='go'
        except BaseException:
            self._state='failed'
            raise

    def accept_go(self, raw: bytes) -> None:
        try:
            _require(self._state=='go' and type(raw) is bytes
                and raw==_token(self._header_digest,'go'),'ntfs.file2_go_token_mismatch')
            self._state='replay'
            self._hash=hashlib.sha256()
            self._offset=self._index=0
        except BaseException:
            self._state='failed'
            raise

    def finish(self) -> dict:
        try:
            _require(self._state=='complete','ntfs.file2_replay_incomplete')
            self._state='consumed'
            return {'accepted_content_digest':self._digest,
                'accepted_content_length':self._length,'accepted_chunks':self._chunks}
        except BaseException:
            self._state='failed'
            raise


class _File2SnapshotSource:
    """Private same-process FD borrower; only _file2_verified_source constructs it."""
    def __init__(self, fd: int, header: bytes):
        self._fd=fd
        self._header_raw=header;self._header_digest=digest_bytes(header)
        metadata=parse_json_bytes(header,maximum_bytes=4096)
        self._length,self._digest=metadata['content_length'],metadata['content_digest']
        self._fingerprint=fingerprint(os.fstat(fd))
        _require(self._fingerprint[2]==self._length
            and os.lseek(fd,0,os.SEEK_CUR)==0,'ntfs.file2_snapshot_binding')
        self._state='first-unused'

    def _check(self, state: str) -> None:
        _require(self._state==state and self._fd is not None,'ntfs.file2_source_unavailable')
        _require(fingerprint(os.fstat(self._fd))==self._fingerprint,'ntfs.file2_snapshot_changed')

    def _read_chunk(self, wanted: int, state: str) -> bytes:
        data=bytearray()
        while len(data)<wanted:
            self._check(state)
            part=os.read(self._fd,wanted-len(data))
            _require(0<len(part)<=wanted-len(data),'ntfs.file2_snapshot_truncated')
            data.extend(part)
        return bytes(data)

    def _frames(self, phase: int):
        state='first-active' if phase==1 else 'replay-active'
        completed=False
        try:
            self._check(state)
            if phase==1:yield self._header_raw
            offset=index=0;hasher=hashlib.sha256()
            while offset<self._length:
                chunk=self._read_chunk(min(_CHUNK,self._length-offset),state)
                hasher.update(chunk)
                yield canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'chunk',
                    'header_digest':self._header_digest,'pass':phase,'index':index,
                    'offset':offset,'content_base64':base64.b64encode(chunk).decode('ascii')})
                offset+=len(chunk);index+=1
            self._check(state)
            _require(os.read(self._fd,1)==b'','ntfs.file2_snapshot_extra_bytes')
            self._check(state)
            _require('sha256:'+hasher.hexdigest()==self._digest,'ntfs.file2_snapshot_digest_mismatch')
            yield canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'end',
                'header_digest':self._header_digest,'pass':phase,'content_digest':self._digest,
                'content_length':offset,'chunk_count':index})
            # END was a suspension point. An intervening rejected call must
            # remain terminal; draining the old generator cannot revive it.
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
            self._state='first-active'  # Consume synchronously, before returning a generator.
            return self._frames(1)
        except BaseException:
            self._state='failed'
            raise

    def rewind_after_ready(self, raw: bytes) -> bytes:
        try:
            self._check('first-done')
            self._state='rewinding'  # No retry even if parsing or lseek fails.
            _require(type(raw) is bytes and raw==_token(self._header_digest,'ready'),
                'ntfs.file2_ready_mismatch')
            _require(os.lseek(self._fd,0,os.SEEK_SET)==0,'ntfs.file2_snapshot_rewind_failed')
            self._check('rewinding')
            self._state='rewound'
            return _token(self._header_digest,'rewound')
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

    def _retire(self) -> None:
        # The EXISTING snapshot context owns the sole close; never close/retry here.
        self._state='retired';self._fd=None


def _failure(error: BaseException) -> dict:
    return {'type':type(error).__name__,'code':error.code if isinstance(error,PhaseError) else None}


@contextmanager
def _file2_verified_source(blob: Path, *, context_bytes: bytes, channel_id: str,
                           content_digest: str, content_length: int):
    """Borrow the existing verified anonymous Linux snapshot through one exchange.

    Full source/installation/root authority remains the future trusted caller's
    responsibility. This factory accepts no caller FD/iterator/size policy.
    Closing its FD proves nothing about a remote worker or operation outcome.
    """
    _require(sys.platform.startswith('linux'),'ntfs.file2_linux_source_required')
    header=_header(context_bytes=context_bytes,channel_id=channel_id,
        content_digest=content_digest,content_length=content_length)
    manager=_verified_blob_snapshot(blob,(content_digest,content_length))
    entered=False;source=None;primary=None
    try:
        fd=manager.__enter__();entered=True
        source=_File2SnapshotSource(fd,header)
        yield source
    except BaseException as error:
        primary=error
        raise
    finally:
        if source is not None:source._retire()
        if entered:
            try:
                manager.__exit__(None,None,None)
            except BaseException as close_error:
                if primary is None:raise
                # Preserve BOTH errors and the original cause, never a success.
                raise PhaseError('ntfs.file2_source_finalization_unavailable',details={
                    'primary':_failure(primary),'finalization':_failure(close_error)}) from primary
