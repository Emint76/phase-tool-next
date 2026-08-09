from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..canonical import canonical_bytes, immutable_value, parse_json_bytes, profile_digest_bytes
from ..errors import PhaseError


@dataclass(frozen=True)
class CapturedCandidate:
    input_mode: str
    captured_bytes: bytes
    canonical_bytes: bytes
    digest: str
    length: int
    value: Any


def _read_once(path: Path, maximum_bytes: int) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise PhaseError("candidate.input_unavailable") from exc
    if len(data) > maximum_bytes:
        raise PhaseError("candidate.too_large", f"candidate exceeds {maximum_bytes} bytes")
    return data


def capture_structured(path: Path, *, maximum_bytes: int = 1_048_576) -> CapturedCandidate:
    raw = _read_once(path, maximum_bytes)
    parsed = parse_json_bytes(raw, maximum_bytes=maximum_bytes)
    encoded = canonical_bytes(parsed)
    return CapturedCandidate(
        input_mode="structured_json",
        captured_bytes=raw,
        canonical_bytes=encoded,
        digest=profile_digest_bytes("candidate", encoded),
        length=len(encoded),
        value=immutable_value(parsed),
    )


def normalize_captured_structured(candidate: CapturedCandidate, value: Any) -> CapturedCandidate:
    """Replace only the contract-canonical value while preserving exact captured bytes."""
    encoded = canonical_bytes(value)
    return CapturedCandidate(
        input_mode=candidate.input_mode,
        captured_bytes=candidate.captured_bytes,
        canonical_bytes=encoded,
        digest=profile_digest_bytes("candidate", encoded),
        length=len(encoded),
        value=immutable_value(value),
    )


def capture_raw(path: Path, *, maximum_bytes: int = 1_048_576) -> CapturedCandidate:
    raw = _read_once(path, maximum_bytes)
    return CapturedCandidate(
        input_mode="binary_bundle",
        captured_bytes=raw,
        canonical_bytes=raw,
        digest=profile_digest_bytes("candidate", raw),
        length=len(raw),
        value=None,
    )
