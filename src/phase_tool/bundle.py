"""Exact phase_bundle_v1 representation and recursive byte verification."""
from __future__ import annotations

import os
from pathlib import Path
import re

from .canonical import canonical_bytes, digest_bytes, parse_json_bytes
from .errors import PhaseError
from .evidence import _reject_existing_links, _write_bytes_exclusive_atomic
from .paths import safe_relative_locator
from .streaming import FILE_LIMIT, REQUEST_LIMIT, copy_and_hash_stream, hash_file

MECHANISM_ID = "mechanism.bundle_create_v1"
CONTRACT_BINDING = "bundle_create.v1@1.0.0"
MAX_MEMBERS = 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_DEPTH = 32
MANIFEST_NAME = "phase-bundle.json"
OWNER_NAME = "phase-owner.json"


def validate_members(members: object) -> list[str]:
    if type(members) is not list or not 1 <= len(members) <= MAX_MEMBERS:
        raise PhaseError("bundle.member_count_limit")
    paths: list[str] = []
    aliases: set[str] = set()
    for value in members:
        if type(value) is not str or len(value) > 1024:
            raise PhaseError("bundle.invalid_member_path")
        path = safe_relative_locator(value)
        parts = path.split("/")
        if len(parts) > MAX_DEPTH or parts[0].casefold() in {MANIFEST_NAME, OWNER_NAME}:
            raise PhaseError("bundle.reserved_or_deep_path")
        folded = path.casefold()
        if folded in aliases:
            raise PhaseError("bundle.duplicate_path")
        aliases.add(folded)
        paths.append(path)
    for path in aliases:
        parts = path.split("/")
        if any("/".join(parts[:index]) in aliases for index in range(1, len(parts))):
            raise PhaseError("bundle.path_prefix_conflict")
    return sorted(paths, key=lambda item: item.encode("utf-8"))


def read_metadata(path: Path) -> bytes:
    from .streaming import read_bounded_file
    return read_bounded_file(path, REQUEST_LIMIT)


def parse_manifest(data: bytes) -> dict:
    if len(data) > REQUEST_LIMIT:
        raise PhaseError("bundle.metadata_limit")
    manifest = parse_json_bytes(data)
    if type(manifest) is not dict or set(manifest) != {"bundle_version", "members", "total_length"} or manifest["bundle_version"] != "1.0":
        raise PhaseError("bundle.invalid_manifest")
    members = manifest["members"]
    if type(members) is not list or any(type(item) is not dict or set(item) != {"path", "length", "digest"} for item in members):
        raise PhaseError("bundle.invalid_manifest")
    paths = validate_members([item["path"] for item in members])
    if paths != [item["path"] for item in members]:
        raise PhaseError("bundle.noncanonical_membership")
    total = 0
    for item in members:
        if type(item["length"]) is not int or not 0 <= item["length"] <= FILE_LIMIT:
            raise PhaseError("bundle.member_size_limit")
        if type(item["digest"]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]):
            raise PhaseError("bundle.invalid_digest")
        total += item["length"]
        if total > MAX_TOTAL_BYTES:
            raise PhaseError("bundle.total_size_limit")
    if type(manifest["total_length"]) is not int or manifest["total_length"] != total or canonical_bytes(manifest) != data:
        raise PhaseError("bundle.invalid_manifest")
    return manifest


def freeze_bundle(binding_id: str, source: Path, members: list[str], blob_root: Path, *, frozen_at: str):
    from .freeze import FrozenInput
    records = []
    total = 0
    for path in validate_members(members):
        frozen = copy_and_hash_stream(binding_id, source, path, blob_root,
            frozen_at=frozen_at, maximum_bytes=min(FILE_LIMIT, MAX_TOTAL_BYTES-total))
        total += frozen.length
        records.append({"path": path, "length": frozen.length, "digest": frozen.digest})
    data = canonical_bytes({"bundle_version": "1.0", "members": records, "total_length": total})
    parse_manifest(data)
    digest = digest_bytes(data)
    blob = blob_root / digest.removeprefix("sha256:")
    try:
        _write_bytes_exclusive_atomic(blob, data, digest)
    except FileExistsError:
        if read_metadata(blob) != data:
            raise PhaseError("freeze.blob_collision")
    return FrozenInput(binding_id, "manifest_and_hash", digest, len(data), frozen_at,
        blob_digest=digest, blob_path=blob, manifest_digest=digest,
        manifest=tuple(records), streamed=True)


def verify_frozen_members(manifest: dict, blob_root: Path) -> None:
    for item in manifest["members"]:
        path = blob_root / item["digest"].removeprefix("sha256:")
        if hash_file(path, item["length"]) != (item["digest"], item["length"]):
            raise PhaseError("bundle.frozen_member_mismatch", item["path"])


def verify_bundle(target: Path, expected_digest: str, *, run_id: str, plan_digest: str) -> tuple[bytes, dict]:
    _reject_existing_links(target)
    before = target.stat()
    if not target.is_dir():
        raise PhaseError("bundle.target_not_directory")
    data = read_metadata(target / MANIFEST_NAME)
    if digest_bytes(data) != expected_digest:
        raise PhaseError("bundle.manifest_mismatch")
    manifest = parse_manifest(data)
    owner_data = read_metadata(target / OWNER_NAME)
    owner = parse_json_bytes(owner_data)
    if owner != {"owner_version": "1.0", "run_id": run_id, "plan_digest": plan_digest,
                 "device": before.st_dev, "inode": before.st_ino}:
        raise PhaseError("bundle.owner_mismatch")
    expected_files = {item["path"] for item in manifest["members"]} | {MANIFEST_NAME, OWNER_NAME}
    expected_dirs: set[str] = set()
    for name in expected_files:
        parts = name.split("/")
        expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    seen_files: set[str] = set()
    seen_dirs: set[str] = set()
    pending = [""]
    while pending:
        relative = pending.pop()
        with os.scandir(target / relative) as entries:
            for entry in entries:
                name = f"{relative}/{entry.name}" if relative else entry.name
                if entry.is_symlink():
                    raise PhaseError("path.link_forbidden", name)
                if entry.is_dir(follow_symlinks=False):
                    if name not in expected_dirs:
                        raise PhaseError("bundle.unexpected_directory", name)
                    seen_dirs.add(name)
                    pending.append(name)
                elif entry.is_file(follow_symlinks=False) and name in expected_files:
                    seen_files.add(name)
                else:
                    raise PhaseError("bundle.unexpected_member", name)
    if seen_files != expected_files or seen_dirs != expected_dirs:
        raise PhaseError("bundle.missing_member")
    for item in manifest["members"]:
        if hash_file(target / item["path"], item["length"]) != (item["digest"], item["length"]):
            raise PhaseError("bundle.member_mismatch", item["path"])
    after = target.stat()
    _reject_existing_links(target)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise PhaseError("bundle.target_identity_changed")
    return data, manifest
