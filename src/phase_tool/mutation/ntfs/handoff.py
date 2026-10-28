"""The one immutable original tuple, shared by parser and fixed physical role.
Structural data only: no authority, filesystem access or GO permission.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedNativeFileCreate:
    context_bytes: bytes
    grant_bytes: bytes
    effect_bytes: bytes
    content_bytes: bytes
    timestamp: str


@dataclass(frozen=True)
class ParsedNativeVersion1(ParsedNativeFileCreate):
    """Same immutable tuple shape, distinct exact semantic type; no GO authority."""


@dataclass(frozen=True)
class ParsedNativeVersion2(ParsedNativeFileCreate):
    """Captured-candidate bytes and two ordered grants; never a frozen input.

    grant_bytes is the canonical current_root/objects_root list. The original
    parser and fixed Version2 worker must check this distinct exact type.
    """


@dataclass(frozen=True)
class _OriginalControlProjection:
    """Declared lineage only: no actual payload, FD, filesystem or GO authority."""
    context_bytes: bytes
    grant_bytes: bytes
    effect_bytes: bytes
    timestamp: str
    input_binding: str | None
    content_digest: str
    content_length: int
