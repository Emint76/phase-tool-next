from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from .errors import PhaseError

PROFILE_ID = "phase_canonical_json_v1"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PhaseError("candidate.duplicate_key", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _check_shape(value: Any, maximum_depth: int, maximum_nodes: int) -> None:
    count = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > maximum_nodes:
            raise PhaseError("candidate.maximum_nodes_exceeded", str(maximum_nodes))
        if depth > maximum_depth:
            raise PhaseError("candidate.maximum_depth_exceeded", str(maximum_depth))
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def parse_json_bytes(
    data: bytes,
    *,
    maximum_bytes: int | None = None,
    maximum_depth: int = 64,
    maximum_nodes: int = 100_000,
) -> Any:
    if maximum_bytes is not None and len(data) > maximum_bytes:
        raise PhaseError("candidate.too_large", f"candidate exceeds {maximum_bytes} bytes")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PhaseError("candidate.invalid_utf8", str(exc)) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=lambda value: (_ for _ in ()).throw(PhaseError("canonical.float_forbidden", value)),
            parse_constant=lambda value: (_ for _ in ()).throw(PhaseError("canonical.nonfinite_forbidden", value)),
        )
    except PhaseError:
        raise
    except RecursionError as exc:
        raise PhaseError("candidate.maximum_depth_exceeded", str(maximum_depth)) from exc
    except json.JSONDecodeError as exc:
        raise PhaseError("candidate.invalid_json", str(exc)) from exc
    except ValueError as exc:
        raise PhaseError("candidate.invalid_json") from exc
    _check_shape(value, maximum_depth, maximum_nodes)
    return value


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PhaseError("canonical.nonfinite_forbidden")
        raise PhaseError("canonical.float_forbidden")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PhaseError("canonical.non_string_key")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise PhaseError("canonical.normalized_key_collision", normalized_key)
            normalized[normalized_key] = _normalize(item)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, memoryview, str)):
        return [_normalize(item) for item in value]
    raise PhaseError("canonical.unsupported_type", type(value).__name__)


def _encode_normalized(normalized: Any) -> bytes:
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_bytes(value: Any) -> bytes:
    return _encode_normalized(_normalize(value))


def canonical_candidate_bytes(value: Any) -> bytes:
    normalized = _normalize(value)
    try:
        return _encode_normalized(normalized)
    except ValueError as exc:
        raise PhaseError("candidate.invalid_json") from exc


def canonical_digest(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


_DOMAIN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_PROFILE_PREFIX = b"phase-canonical-json-v1\x00"


def profile_digest_bytes(domain: str, canonical_or_raw_bytes: bytes) -> str:
    if not _DOMAIN.fullmatch(domain):
        raise ValueError(f"invalid canonical digest domain: {domain!r}")
    return digest_bytes(_PROFILE_PREFIX + domain.encode("ascii") + b"\x00" + canonical_or_raw_bytes)


def profile_digest(domain: str, value: Any) -> str:
    return profile_digest_bytes(domain, canonical_bytes(value))


def immutable_value(value: Any) -> Any:
    normalized = _normalize(value)
    if isinstance(normalized, dict):
        return MappingProxyType({key: immutable_value(item) for key, item in normalized.items()})
    if isinstance(normalized, list):
        return tuple(immutable_value(item) for item in normalized)
    return normalized
