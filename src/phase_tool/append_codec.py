from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from .canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from .errors import PhaseError

CANONICAL_JSONL_CODEC_ID = "canonical-jsonl"
CANONICAL_JSONL_CODEC_VERSION = "1"
_STREAM_CHUNK_BYTES = 1024 * 1024
_MAX_RECORD_BYTES = 1024 * 1024


@dataclass(frozen=True)
class StreamObservation:
    digest: str
    length: int
    record_count: int
    head_token: str
    tail: bytes
    prefix_head_token: str | None = None
    segment_digest: str | None = None
    segment: bytes | None = None


def iter_bounded_lines(path: Path) -> Iterator[bytes]:
    with path.open("rb") as stream:
        while True:
            line = stream.readline(_MAX_RECORD_BYTES + 1)
            if not line:
                return
            if len(line) > _MAX_RECORD_BYTES or not line.endswith(b"\n"):
                raise PhaseError("input.invalid_tail")
            yield line


def absent_head_token() -> str:
    return profile_digest(
        "append-head",
        {
            "codec_id": CANONICAL_JSONL_CODEC_ID,
            "codec_version": CANONICAL_JSONL_CODEC_VERSION,
            "state": "absent",
            "byte_length": None,
            "record_count": None,
            "stream_digest": None,
        },
    )


def append_head_token(previous_head: str | None, record: bytes, previous_length: int, codec_id: str = CANONICAL_JSONL_CODEC_ID) -> str:
    validate_record_bytes(record)
    return profile_digest(
        "append-head",
        {
            "codec_id": codec_id,
            "codec_version": CANONICAL_JSONL_CODEC_VERSION,
            "previous_head": previous_head,
            "previous_length": previous_length,
            "record_digest": digest_bytes(record),
            "record_length": len(record),
        },
    )


def validate_record_bytes(record: bytes) -> dict[str, object]:
    if not record.endswith(b"\n"):
        raise PhaseError("codec.record_lf_missing")
    if record.endswith(b"\r\n"):
        raise PhaseError("codec.record_crlf_forbidden")
    if record.count(b"\n") != 1:
        raise PhaseError("codec.record_multiple_lines")
    body = record[:-1]
    if not body:
        raise PhaseError("codec.blank_record")
    value = parse_json_bytes(body)
    if not isinstance(value, dict):
        raise PhaseError("codec.record_not_object")
    if canonical_bytes(value) != body:
        raise PhaseError("codec.record_noncanonical")
    return value


def validate_stream_bytes(data: bytes) -> int:
    if data == b"":
        return 0
    if data.endswith(b"\r\n") or b"\r\n" in data:
        raise PhaseError("codec.crlf_forbidden")
    if not data.endswith(b"\n"):
        raise PhaseError("input.invalid_tail")
    count = 0
    for line in data.splitlines(keepends=True):
        validate_record_bytes(line)
        count += 1
    return count


def observe_stream(
    stream: BinaryIO,
    *,
    tail_bytes: int = 0,
    prefix_length: int | None = None,
    segment_offset: int | None = None,
    segment_length: int | None = None,
) -> StreamObservation:
    digest = hashlib.sha256()
    length = 0
    record_count = 0
    pending = bytearray()
    tail = bytearray()
    prefix_head_token = absent_head_token() if prefix_length == 0 else None
    segment_digest: str | None = None
    segment: bytes | None = None
    while True:
        chunk = stream.read(_STREAM_CHUNK_BYTES)
        if not chunk:
            break
        if tail_bytes > 0:
            tail.extend(chunk)
            if len(tail) > tail_bytes:
                del tail[:-tail_bytes]
        pending.extend(chunk)
        while True:
            newline = pending.find(b"\n")
            if newline < 0:
                break
            line = bytes(pending[: newline + 1])
            del pending[: newline + 1]
            if len(line) > _MAX_RECORD_BYTES:
                raise PhaseError("input.invalid_tail")
            validate_record_bytes(line)
            record_start = length
            digest.update(line)
            length += len(line)
            record_count += 1
            if prefix_length == length:
                prefix_head_token = stream_head_token_from_summary(
                    "sha256:" + digest.hexdigest(),
                    length,
                    record_count,
                )
            if segment_offset == record_start and segment_length == len(line):
                segment_digest = digest_bytes(line)
                segment = line
        if len(pending) > _MAX_RECORD_BYTES:
            raise PhaseError("input.invalid_tail")
    if pending:
        raise PhaseError("input.invalid_tail")
    stream_digest = "sha256:" + digest.hexdigest()
    return StreamObservation(
        digest=stream_digest,
        length=length,
        record_count=record_count,
        head_token=stream_head_token_from_summary(stream_digest, length, record_count),
        tail=bytes(tail),
        prefix_head_token=prefix_head_token,
        segment_digest=segment_digest,
        segment=segment,
    )


def stream_head_token_from_summary(
    stream_digest: str,
    byte_length: int,
    record_count: int,
    codec_id: str = CANONICAL_JSONL_CODEC_ID,
) -> str:
    return profile_digest(
        "append-head",
        {
            "codec_id": codec_id,
            "codec_version": CANONICAL_JSONL_CODEC_VERSION,
            "state": "present",
            "byte_length": byte_length,
            "record_count": record_count,
            "stream_digest": stream_digest,
        },
    )


def stream_head_token(data: bytes, codec_id: str = CANONICAL_JSONL_CODEC_ID) -> str:
    record_count = validate_stream_bytes(data)
    return stream_head_token_from_summary(
        digest_bytes(data),
        len(data),
        record_count,
        codec_id,
    )
