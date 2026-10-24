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
