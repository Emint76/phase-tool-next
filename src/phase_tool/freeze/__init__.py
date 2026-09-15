from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..candidate import capture_structured
from ..canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from ..contracts import append_locator
from ..errors import PhaseError
from ..evidence import _ensure_directory_durable, _write_bytes_exclusive_atomic
from ..paths import _platform_path, contained_read_path, safe_relative_locator


@dataclass(frozen=True)
class FrozenInput:
    binding_id: str
    strategy: str
    digest: str
    length: int
    frozen_at: str
    blob_digest: str | None = None
    blob_path: Path | None = None
    manifest_digest: str | None = None
    manifest: tuple[dict[str, Any], ...] = ()
    revalidation_token: str | None = None
    relative_locator: str | None = None
    # Internal implementation choice, not a new historical intent field.
    streamed: bool = False

    def intent_record(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "freeze_strategy": self.strategy,
            "digest": self.digest,
            "manifest_digest": self.manifest_digest,
            "blob_digest": self.blob_digest,
            "provenance_ref": None,
            "frozen_at": self.frozen_at,
            "revalidation_token": self.revalidation_token,
        }


def value_snapshot(binding_id: str, value: Any, *, frozen_at: str) -> FrozenInput:
    data = canonical_bytes(value)
    return FrozenInput(binding_id, "value_snapshot", digest_bytes(data), len(data), frozen_at)


def freeze_declared_inputs(
    contract_document: Mapping[str, Any],
    candidate_value: Mapping[str, Any],
    supplied_paths: Mapping[str, Path],
    root_bindings: Mapping[str, Path],
    blob_root: Path,
    *,
    frozen_at: str,
    maximum_structured_bytes: int,
) -> dict[str, FrozenInput]:
    frozen: dict[str, FrozenInput] = {}
    for declaration in contract_document["input_bindings"]:
        binding_id = declaration["id"]
        strategy = declaration["freeze_strategy"]
        supplied = supplied_paths.get(binding_id)
        if strategy == "lock_snapshot_revalidate" and supplied is None and candidate_value.get("expected_head") is not None:
            root_id = contract_document["canonical_result"]["root_binding"]
            try:
                root = Path(root_bindings[root_id])
            except KeyError as exc:
                raise PhaseError("plan.root_binding_missing", root_id) from exc
            frozen[binding_id] = lock_snapshot_revalidate(
                binding_id, root, append_locator(dict(contract_document), dict(candidate_value)), frozen_at=frozen_at
            )
            continue
        if supplied is None:
            if declaration["required"]:
                raise PhaseError("input.required_missing", binding_id)
            continue
        path = Path(supplied)
        if contract_document["operation"]["mechanism"]["id"] in {"mechanism.bundle_create_v1", "mechanism.bundle_create_v2"}:
            from ..bundle import freeze_bundle
            from ..installation import qualify_host_authority_roots
            qualify_host_authority_roots(root_bindings)
            frozen[binding_id] = freeze_bundle(binding_id, path, candidate_value["members"], blob_root, frozen_at=frozen_at)
            continue
        if strategy == "copy_and_hash":
            from ..streaming import MECHANISM_ID, copy_and_hash_stream
            capture = copy_and_hash_stream if contract_document["operation"]["mechanism"]["id"] == MECHANISM_ID else copy_and_hash
            frozen[binding_id] = capture(binding_id, path.parent, path.name, blob_root, frozen_at=frozen_at)
        elif strategy == "manifest_and_hash":
            frozen[binding_id] = manifest_and_hash(binding_id, path, frozen_at=frozen_at)
        elif strategy == "lock_snapshot_revalidate":
            frozen[binding_id] = lock_snapshot_revalidate(binding_id, path.parent, path.name, frozen_at=frozen_at)
        elif strategy == "value_snapshot":
            captured = capture_structured(path, maximum_bytes=maximum_structured_bytes)
            frozen[binding_id] = value_snapshot(binding_id, parse_json_bytes(captured.canonical_bytes), frozen_at=frozen_at)
        else:
            raise PhaseError("freeze.strategy_unsupported", strategy)
    return frozen


def _stat_fingerprint(stat: os.stat_result) -> tuple[int, int, int, int]:
    return int(stat.st_dev), int(stat.st_ino), int(stat.st_size), int(stat.st_mtime_ns)


def _io_path(path: Path) -> Path:
    if os.name == "nt" and len(str(path.resolve(strict=False))) >= 260:
        return Path(_platform_path(path))
    return path


def _read_file_stable(path: Path, maximum_bytes: int) -> bytes:
    io_path = _io_path(path)
    before = io_path.stat()
    with io_path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(maximum_bytes + 1)
    after = io_path.stat()
    if _stat_fingerprint(before) != _stat_fingerprint(opened) or _stat_fingerprint(opened) != _stat_fingerprint(after):
        raise PhaseError("freeze.source_changed_during_capture", path.name)
    return data


def copy_and_hash(
    binding_id: str,
    input_root: Path,
    relative_locator: str,
    blob_root: Path,
    *,
    frozen_at: str,
    maximum_bytes: int = 16 * 1024 * 1024,
) -> FrozenInput:
    try:
        source = contained_read_path(input_root, relative_locator)
        if not os.path.isfile(_platform_path(source)):
            raise PhaseError("freeze.not_regular_file", relative_locator)
        data = _read_file_stable(source, maximum_bytes)
    except PhaseError:
        raise
    except OSError as exc:
        raise PhaseError("freeze.input_unavailable") from exc
    if len(data) > maximum_bytes:
        raise PhaseError("freeze.input_too_large", relative_locator)
    digest = digest_bytes(data)
    _ensure_directory_durable(blob_root, parents=True)
    if blob_root.is_symlink():
        raise PhaseError("path.link_forbidden", str(blob_root))
    destination = blob_root / digest.removeprefix("sha256:")
    platform_destination = _platform_path(destination)
    if os.path.exists(platform_destination):
        if os.path.islink(platform_destination) or _read_file_stable(destination, maximum_bytes) != data:
            raise PhaseError("freeze.blob_collision", digest)
    else:
        try:
            _write_bytes_exclusive_atomic(destination, data, digest)
        except FileExistsError:
            if os.path.islink(platform_destination) or _read_file_stable(destination, maximum_bytes) != data:
                raise PhaseError("freeze.blob_collision", digest)
    if _read_file_stable(destination, maximum_bytes) != data:
        raise PhaseError("freeze.blob_readback_mismatch", digest)
    return FrozenInput(
        binding_id,
        "copy_and_hash",
        digest,
        len(data),
        frozen_at,
        blob_digest=digest,
        blob_path=destination,
        relative_locator=safe_relative_locator(relative_locator),
    )


def revalidate_frozen(frozen: FrozenInput) -> None:
    if frozen.blob_path is None:
        raise PhaseError("freeze.blob_missing", frozen.binding_id)
    try:
        info = os.stat(_platform_path(frozen.blob_path))
    except FileNotFoundError as exc:
        raise PhaseError("freeze.blob_missing", frozen.binding_id) from exc
    except OSError as exc:
        raise PhaseError("freeze.blob_unavailable", frozen.binding_id) from exc
    if not stat.S_ISREG(info.st_mode):
        raise PhaseError("freeze.blob_missing", frozen.binding_id)
    try:
        if frozen.streamed:
            from ..streaming import hash_file
            digest, length = hash_file(frozen.blob_path, frozen.length)
        else:
            data = _read_file_stable(frozen.blob_path, frozen.length)
            digest, length = digest_bytes(data), len(data)
    except OSError as exc:
        raise PhaseError("freeze.blob_unavailable", frozen.binding_id) from exc
    except PhaseError as exc:
        raise PhaseError("freeze.blob_tampered", frozen.binding_id) from exc
    if digest != frozen.blob_digest or length != frozen.length:
        raise PhaseError("freeze.blob_tampered", frozen.binding_id)


def _scan_manifest(root: Path, maximum_files: int, maximum_total_bytes: int) -> tuple[list[dict[str, Any]], int]:
    root = root.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        safe_relative_locator(relative)
        if path.is_symlink():
            raise PhaseError("path.link_forbidden", relative)
        from ..paths import _is_reparse_point
        if _is_reparse_point(path):
            raise PhaseError("path.reparse_forbidden", relative)
        if path.is_dir():
            continue
        if not path.is_file():
            raise PhaseError("freeze.unsupported_entry", relative)
        remaining = maximum_total_bytes - total
        data = _read_file_stable(path, max(remaining, 0))
        total += len(data)
        entries.append({"locator": relative, "length": len(data), "digest": digest_bytes(data), "type": "file"})
        if len(entries) > maximum_files or total > maximum_total_bytes:
            raise PhaseError("freeze.manifest_limit")
    return entries, total


def manifest_and_hash(
    binding_id: str,
    root: Path,
    *,
    frozen_at: str,
    maximum_files: int = 1024,
    maximum_total_bytes: int = 16 * 1024 * 1024,
) -> FrozenInput:
    entries, total = _scan_manifest(root, maximum_files, maximum_total_bytes)
    manifest = {"profile": "phase_manifest_v1", "entries": entries}
    manifest_digest = canonical_digest(manifest)
    return FrozenInput(
        binding_id,
        "manifest_and_hash",
        manifest_digest,
        total,
        frozen_at,
        manifest_digest=manifest_digest,
        manifest=tuple(entries),
    )


def revalidate_manifest(
    frozen: FrozenInput,
    root: Path,
    *,
    maximum_files: int = 1024,
    maximum_total_bytes: int = 16 * 1024 * 1024,
) -> None:
    if frozen.strategy != "manifest_and_hash":
        raise PhaseError("freeze.strategy_mismatch", frozen.binding_id)
    entries, total = _scan_manifest(root, maximum_files, maximum_total_bytes)
    digest = canonical_digest({"profile": "phase_manifest_v1", "entries": entries})
    if digest != frozen.manifest_digest or tuple(entries) != frozen.manifest or total != frozen.length:
        raise PhaseError("freeze.manifest_drift", frozen.binding_id)


def _stream_digest_length(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                return "sha256:" + digest.hexdigest(), length
            digest.update(chunk)
            length += len(chunk)


def _snapshot_token(path: Path, content_digest: str, length: int) -> str:
    stat = path.stat()
    return canonical_digest({
        "content_digest": content_digest,
        "length": length,
        "device": int(stat.st_dev),
        "inode": int(stat.st_ino),
        "modified_ns": int(stat.st_mtime_ns),
    })


def lock_snapshot_revalidate(binding_id: str, root: Path, relative_locator: str, *, frozen_at: str) -> FrozenInput:
    try:
        path = contained_read_path(root, relative_locator)
        if not path.is_file():
            raise PhaseError("freeze.not_regular_file", relative_locator)
        digest, length = _stream_digest_length(path)
        token = _snapshot_token(path, digest, length)
    except PhaseError:
        raise
    except OSError as exc:
        raise PhaseError("freeze.input_unavailable") from exc
    return FrozenInput(
        binding_id,
        "lock_snapshot_revalidate",
        digest,
        length,
        frozen_at,
        revalidation_token=token,
        relative_locator=safe_relative_locator(relative_locator),
    )


def revalidate_snapshot(frozen: FrozenInput, root: Path) -> None:
    if frozen.strategy != "lock_snapshot_revalidate" or frozen.relative_locator is None:
        raise PhaseError("freeze.strategy_mismatch", frozen.binding_id)
    path = contained_read_path(root, frozen.relative_locator)
    digest, length = _stream_digest_length(path)
    if _snapshot_token(path, digest, length) != frozen.revalidation_token:
        raise PhaseError("freeze.stale_snapshot", frozen.binding_id)
