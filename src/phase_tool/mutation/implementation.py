from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from ..errors import PhaseError

AuthorityUsage = Literal["provider_backed", "mechanism_managed"]

_MECHANISM_AUTHORITY_USAGE: dict[tuple[str, str, str], AuthorityUsage] = {
    (
        "content_addressed_copy",
        "1.0.0",
        "sha256:ea3dd62ad45312315c30da15a8aa53566e554d4e7733ee5f41c67d1c4cf37fa2",
    ): "provider_backed",
    (
        "mechanism.archive_then_publish_v1",
        "1.0.0",
        "sha256:7b7e5ab183e6ef08e86b9fd0a408def310f325a4eca73dbcddfb18627fdb6cd6",
    ): "provider_backed",
    (
        "mechanism.exclusive_create_v1",
        "1.0.0",
        "sha256:79564033bced595dda6c50b139c85d350c2eabbfbe586a17cfcbe5037884411b",
    ): "provider_backed",
    (
        "mechanism.expected_head_append_v1",
        "1.0.0",
        "sha256:ee49db0f5f2f67c7ec8d5b252a2ebab6384c3032364e449dc4df588ab8880d4a",
    ): "mechanism_managed",
    (
        "mechanism.object_store_publish_v2",
        "1.0.0",
        "sha256:da9b36ae4cbe25b9b17f0d107ff8263db6b95e2407010481a1ccc8e5a5d06fd0",
    ): "provider_backed",
}

_MECHANISM_EFFECT_KINDS: dict[tuple[str, str, str], frozenset[str]] = {
    ("content_addressed_copy", "1.0.0", "sha256:ea3dd62ad45312315c30da15a8aa53566e554d4e7733ee5f41c67d1c4cf37fa2"): frozenset({"copy_blob"}),
    ("mechanism.archive_then_publish_v1", "1.0.0", "sha256:7b7e5ab183e6ef08e86b9fd0a408def310f325a4eca73dbcddfb18627fdb6cd6"): frozenset({"publish_new_version"}),
    ("mechanism.exclusive_create_v1", "1.0.0", "sha256:79564033bced595dda6c50b139c85d350c2eabbfbe586a17cfcbe5037884411b"): frozenset({"exclusive_create"}),
    ("mechanism.expected_head_append_v1", "1.0.0", "sha256:ee49db0f5f2f67c7ec8d5b252a2ebab6384c3032364e449dc4df588ab8880d4a"): frozenset({"append_record"}),
    ("mechanism.object_store_publish_v2", "1.0.0", "sha256:da9b36ae4cbe25b9b17f0d107ff8263db6b95e2407010481a1ccc8e5a5d06fd0"): frozenset({"publish_new_version"}),
}


def _mechanism_key(binding: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(binding.get("id")),
        str(binding.get("version")),
        str(binding.get("package_digest")),
    )


def mechanism_authority_usage(binding: Mapping[str, Any]) -> AuthorityUsage:
    key = _mechanism_key(binding)
    try:
        return _MECHANISM_AUTHORITY_USAGE[key]
    except KeyError as exc:
        raise PhaseError("authority.mechanism_binding_unknown", str(binding.get("id", "unknown"))) from exc


def mechanism_supports_effect_kind(binding: Mapping[str, Any], effect_kind: object) -> bool:
    try:
        return str(effect_kind) in _MECHANISM_EFFECT_KINDS[_mechanism_key(binding)]
    except KeyError as exc:
        raise PhaseError("authority.mechanism_binding_unknown", str(binding.get("id", "unknown"))) from exc
