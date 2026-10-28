"""Finite version1 messages over the SAME existing owned process/pipe.

No transport service, queue, spool, evidence owner, process, I/O or deadline
reset. Callers use one local deadline for the entire sequence. Reader callers
must separately establish EOF/actual owner exit; a worker end leaves its pipe
open for READY/GO. Data correlation never authenticates the installed producer.
"""
from __future__ import annotations

import base64
import hashlib
import re

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...evidence import validate_run_id
from ...paths import safe_relative_locator
from .handoff import ParsedNativeVersion1, ParsedNativeVersion2
from .native import _require
from .worker import _grant, _version1_context, _version2_context


_CHUNK = 256*1024
_LIMIT = 16*1024**2
_COMMON = {'native_original_transfer_version','kind','header_digest'}
_EXPECTED_CONTEXT = {'run_id','intent_digest','installation_digest','operation_nonce'}


def _metadata(parsed: ParsedNativeVersion1) -> dict:
    _require(type(parsed) is ParsedNativeVersion1,'ntfs.original_version1_tuple_required')
    context = _version1_context(parse_json_bytes(parsed.context_bytes))
    grant = _grant(parse_json_bytes(parsed.grant_bytes))
    effect = parse_json_bytes(parsed.effect_bytes)
    _require(type(effect) is dict and effect.get('kind') == 'publish_new_version'
        and type(effect.get('target')) is dict and set(effect['target']) == {'root_binding','relative_locator'}
        and effect['target']['root_binding'] == grant.binding
        and type(effect.get('archive_target')) is dict
        and set(effect['archive_target']) == {'root_binding','relative_locator'}
        and effect['archive_target']['root_binding'] == grant.binding,'ntfs.original_transfer_effect_binding')
    current = safe_relative_locator(effect['target']['relative_locator'])
    archive = safe_relative_locator(effect['archive_target']['relative_locator'])
    _require(current != archive and type(parsed.content_bytes) is bytes
        and len(parsed.content_bytes) <= _LIMIT and type(effect.get('content_length')) is int
        and effect['content_length'] == len(parsed.content_bytes)
        and effect.get('content_digest') == digest_bytes(parsed.content_bytes)
        and type(parsed.timestamp) is str and 0 < len(parsed.timestamp) <= 128,
        'ntfs.original_transfer_content_binding')
    validate_run_id(context['run_id'])
    # Reject noncanonical metadata before sending; don't silently normalize the
    # tuple handed off by the original parser.
    _require(canonical_bytes(context) == parsed.context_bytes
        and canonical_bytes(grant.as_dict()) == parsed.grant_bytes
        and canonical_bytes(effect) == parsed.effect_bytes,'ntfs.original_transfer_metadata_binding')
    return {'context':context,'grant':grant.as_dict(),'effect':effect,'timestamp':parsed.timestamp}


def _metadata_version2(parsed):
    from .version2_effect import _effect_binding
    _require(type(parsed) is ParsedNativeVersion2,'ntfs.original_version2_tuple_required')
    context=_version2_context(parse_json_bytes(parsed.context_bytes))
    grants=parse_json_bytes(parsed.grant_bytes)
    effect=parse_json_bytes(parsed.effect_bytes)
    _effect_binding(grants,effect,parsed.content_bytes)
    _require(type(parsed.timestamp) is str and 0<len(parsed.timestamp)<=128
        and canonical_bytes(context)==parsed.context_bytes
        and canonical_bytes(grants)==parsed.grant_bytes
        and canonical_bytes(effect)==parsed.effect_bytes,'ntfs.original_transfer_metadata_binding')
    return {'context':context,'grants':grants,'effect':effect,'timestamp':parsed.timestamp}


def _header(parsed, *, channel_id: str, leg: str,
            query_digest: str | None, _version2: bool = False) -> dict:
    _require(type(_version2) is bool,'ntfs.original_closed_role_required')
    _require(type(channel_id) is str and re.fullmatch('[0-9a-f]{32}',channel_id) is not None
        and leg in ('reader','worker'),'ntfs.original_transfer_context')
    _require((leg == 'worker' and query_digest is None) or (leg == 'reader'
        and type(query_digest) is str and re.fullmatch('sha256:[0-9a-f]{64}',query_digest) is not None),
        'ntfs.original_transfer_query_binding')
    metadata = _metadata_version2(parsed) if _version2 else _metadata(parsed)
    length = len(parsed.content_bytes)
    return {'native_original_transfer_version':'1.2' if _version2 else '1.1','kind':'header','leg':leg,
        'channel_id':channel_id,'query_digest':query_digest,'metadata':metadata,
        'content_digest':metadata['effect']['content_digest'],'content_length':length,
        'chunk_count':(length+_CHUNK-1)//_CHUNK}


def original_version1_frames(parsed: ParsedNativeVersion1, *, channel_id: str,
                              leg: str, query_digest: str | None):
    yield from _original_frames(parsed,channel_id=channel_id,leg=leg,query_digest=query_digest,_version2=False)


def original_version2_frames(parsed: ParsedNativeVersion2, *, channel_id: str,
                              leg: str, query_digest: str | None):
    yield from _original_frames(parsed,channel_id=channel_id,leg=leg,query_digest=query_digest,_version2=True)


def _original_frames(parsed, *, channel_id, leg, query_digest, _version2):
    """Stream bounded canonical frames; never accumulate an outgoing queue."""
    header = _header(parsed,channel_id=channel_id,leg=leg,query_digest=query_digest,_version2=_version2)
    raw = canonical_bytes(header)
    _require(0 < len(raw) <= 2*1024**2,'ntfs.original_transfer_frame_limit')
    digest = digest_bytes(raw)
    yield raw
    for index,offset in enumerate(range(0,len(parsed.content_bytes),_CHUNK)):
        yield canonical_bytes({'native_original_transfer_version':header['native_original_transfer_version'],'kind':'chunk',
            'header_digest':digest,'index':index,'offset':offset,
            'content_base64':base64.b64encode(parsed.content_bytes[offset:offset+_CHUNK]).decode('ascii')})
    yield canonical_bytes({'native_original_transfer_version':header['native_original_transfer_version'],'kind':'end',
        'header_digest':digest,'content_digest':header['content_digest'],
        'content_length':header['content_length'],'chunk_count':header['chunk_count']})


class _Version1OriginalDecoder:
    """Single finite in-memory message decoder, not another lifecycle owner.

    Every malformed/truncated/mixed sequence is terminal for this instance.
    It does not receive, retry, dispatch, read files or manufacture a receipt.
    Its consumer owns process/pipe provenance, one local deadline and exit.
    """
    _TRANSFER_VERSION = '1.1'
    _CONTENT_LIMIT = _LIMIT
    _GRANT_KEY = 'grant'

    @staticmethod
    def _checked_context(value):
        return _version1_context(value)

    @staticmethod
    def _checked_grant_bytes(value):
        return canonical_bytes(_grant(value).as_dict())

    @staticmethod
    def _tuple(metadata, content):
        return ParsedNativeVersion1(canonical_bytes(metadata['context']),canonical_bytes(metadata['grant']),
            canonical_bytes(metadata['effect']),content,metadata['timestamp'])

    @staticmethod
    def _check_tuple(parsed):
        return _metadata(parsed)

    def __init__(self, *, channel_id: str, leg: str, query_digest: str | None,
                 expected_context: dict, expected_grant: bytes):
        expected_keys = (_EXPECTED_CONTEXT if leg == 'reader' else _EXPECTED_CONTEXT-{'intent_digest'})
        _require(type(expected_context) is dict and set(expected_context) == expected_keys,
            'ntfs.original_transfer_expected_context')
        self._expected_context = canonical_bytes(expected_context)
        validate_run_id(expected_context['run_id'])
        _require(type(expected_context['operation_nonce']) is str and re.fullmatch(
            '[0-9a-f]{32}',expected_context['operation_nonce']) is not None,
            'ntfs.original_transfer_expected_context')
        for name in sorted(expected_keys-{'run_id','operation_nonce'}):
            _require(type(expected_context[name]) is str and re.fullmatch(
                'sha256:[0-9a-f]{64}',expected_context[name]) is not None,
                'ntfs.original_transfer_expected_context')
        _require(type(channel_id) is str and re.fullmatch('[0-9a-f]{32}',channel_id) is not None
            and leg in ('reader','worker'),'ntfs.original_transfer_context')
        _require((leg == 'reader' and type(query_digest) is str
            and re.fullmatch('sha256:[0-9a-f]{64}',query_digest) is not None)
            or (leg == 'worker' and query_digest is None),'ntfs.original_transfer_expected_role')
        _require(type(expected_grant) is bytes,'ntfs.original_transfer_expected_grant')
        _require(self._checked_grant_bytes(parse_json_bytes(expected_grant)) == expected_grant,
            'ntfs.original_transfer_expected_grant')
        self._grant_bytes = expected_grant
        self._channel_id,self._leg,self._query_digest = channel_id,leg,query_digest
        # The worker has not read the Linux original and cannot pretend to know
        # its full tuple in advance. Its fixed installation pins run/nonce/root/
        # installation/channel. It echoes the complete received context/effect/
        # bytes at READY; ONLY the parent that read the original may compare that
        # echo and grant GO. A completed transfer alone never grants execution.
        self._state,self._header,self._header_digest = 'header',None,None
        self._data,self._hash,self._index = bytearray(),hashlib.sha256(),0

    def feed(self, raw: bytes) -> None:
        try:
            _require(self._state in ('header','content'),'ntfs.original_transfer_consumed')
            _require(type(raw) is bytes and 0 < len(raw) <= 2*1024**2,
                'ntfs.original_transfer_frame_limit')
            frame = parse_json_bytes(raw,maximum_bytes=2*1024**2)
            _require(type(frame) is dict and canonical_bytes(frame) == raw
                and frame.get('native_original_transfer_version') == self._TRANSFER_VERSION,
                'ntfs.original_transfer_frame_shape')
            if self._state == 'header':
                self._start(frame,raw)
            elif frame.get('kind') == 'chunk':
                self._chunk(frame)
            else:
                self._end(frame)
        except BaseException:
            self._state = 'failed'
            raise

    def _start(self, frame: dict, raw: bytes) -> None:
        _require(set(frame) == {'native_original_transfer_version','kind','leg','channel_id',
            'query_digest','metadata','content_digest','content_length','chunk_count'}
            and frame['kind'] == 'header' and frame['leg'] == self._leg
            and frame['channel_id'] == self._channel_id and frame['query_digest'] == self._query_digest,
            'ntfs.original_transfer_header_binding')
        _require(type(frame['content_length']) is int and 0 <= frame['content_length'] <= self._CONTENT_LIMIT
            and type(frame['chunk_count']) is int
            and frame['chunk_count'] == (frame['content_length']+_CHUNK-1)//_CHUNK
            and type(frame['content_digest']) is str
            and re.fullmatch('sha256:[0-9a-f]{64}',frame['content_digest']) is not None,
            'ntfs.original_transfer_header_bound')
        metadata = frame['metadata']
        _require(type(metadata) is dict and set(metadata) == {'context',self._GRANT_KEY,'effect','timestamp'},
            'ntfs.original_transfer_metadata_binding')
        context = self._checked_context(metadata['context'])
        _require(self._checked_grant_bytes(metadata[self._GRANT_KEY]) == self._grant_bytes,
            'ntfs.original_transfer_expected_grant')
        expected = parse_json_bytes(self._expected_context)
        _require(all(context[key] == value for key,value in expected.items())
            and type(metadata['effect']) is dict
            and type(metadata['effect'].get('content_length')) is int
            and metadata['effect']['content_length'] == frame['content_length']
            and metadata['effect'].get('content_digest') == frame['content_digest'],
            'ntfs.original_transfer_metadata_binding')
        self._header,self._header_digest,self._state = frame,digest_bytes(raw),'content'

    def _chunk(self, frame: dict) -> None:
        header = self._header
        _require(set(frame) == _COMMON|{'index','offset','content_base64'}
            and frame['header_digest'] == self._header_digest
            and type(frame['index']) is int and frame['index'] == self._index < header['chunk_count']
            and type(frame['offset']) is int and frame['offset'] == len(self._data),
            'ntfs.original_transfer_chunk_order')
        wanted = min(_CHUNK,header['content_length']-len(self._data))
        encoded = frame['content_base64']
        _require(wanted > 0 and type(encoded) is str and len(encoded) == (wanted+2)//3*4,
            'ntfs.original_transfer_chunk_bound')
        chunk = base64.b64decode(encoded,validate=True)
        _require(len(chunk) == wanted and base64.b64encode(chunk).decode('ascii') == encoded,
            'ntfs.original_transfer_chunk_encoding')
        self._data.extend(chunk)
        self._hash.update(chunk)
        self._index += 1

    def _end(self, frame: dict) -> None:
        header = self._header
        _require(set(frame) == _COMMON|{'content_digest','content_length','chunk_count'}
            and frame['kind'] == 'end' and frame['header_digest'] == self._header_digest
            and type(frame['content_length']) is int and type(frame['chunk_count']) is int
            and frame['content_length'] == len(self._data) == header['content_length']
            and frame['chunk_count'] == self._index == header['chunk_count']
            and frame['content_digest'] == header['content_digest'] == 'sha256:'+self._hash.hexdigest(),
            'ntfs.original_transfer_end_binding')
        metadata = header['metadata']
        parsed = self._tuple(metadata,bytes(self._data))
        self._check_tuple(parsed)  # Complete shape/content before returning a tuple or any READY/GO.
        self._state = 'ended'

    @property
    def ended(self) -> bool:
        return self._state == 'ended'

    def finish(self) -> ParsedNativeVersion1 | ParsedNativeVersion2:
        try:
            _require(self._state == 'ended','ntfs.original_transfer_incomplete')
            self._state = 'consumed'
            metadata = self._header['metadata']
            return self._tuple(metadata,bytes(self._data))
        except BaseException:
            self._state = 'failed'
            raise


class _Version2OriginalDecoder(_Version1OriginalDecoder):
    """Same finite state machine; literal Version2 data roles and bounds only."""
    _TRANSFER_VERSION = '1.2'
    _CONTENT_LIMIT = 512*1024
    _GRANT_KEY = 'grants'

    @staticmethod
    def _checked_context(value):
        return _version2_context(value)

    @staticmethod
    def _checked_grant_bytes(value):
        from .version2_observation import _version2_grants
        _version2_grants(value)
        return canonical_bytes(value)

    @staticmethod
    def _tuple(metadata, content):
        return ParsedNativeVersion2(canonical_bytes(metadata['context']),canonical_bytes(metadata['grants']),
            canonical_bytes(metadata['effect']),content,metadata['timestamp'])

    @staticmethod
    def _check_tuple(parsed):
        return _metadata_version2(parsed)

    def __init__(self, *, channel_id, leg, query_digest, expected_context, expected_grants):
        super().__init__(channel_id=channel_id,leg=leg,query_digest=query_digest,
            expected_context=expected_context,expected_grant=expected_grants)
