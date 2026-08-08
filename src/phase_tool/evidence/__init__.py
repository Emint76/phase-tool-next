from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..canonical import canonical_bytes, digest_bytes
from ..errors import PhaseError
from ..paths import _is_reparse_point, _platform_path
from ..registry import RegistrySnapshot

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_run_id(run_id: str) -> str:
    if not _RUN_ID.fullmatch(run_id) or run_id in {".", ".."}:
        raise PhaseError("evidence.invalid_run_id", run_id)
    return run_id


def _reject_existing_links(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts[1:] if path.is_absolute() else path.parts:
        current = current / part
        platform_current = Path(_platform_path(current))
        if os.path.exists(platform_current) and (platform_current.is_symlink() or _is_reparse_point(platform_current)):
            code = "path.link_forbidden" if platform_current.is_symlink() else "path.reparse_forbidden"
            raise PhaseError(code, str(current))


def read_evidence_bytes(path: Path) -> bytes:
    with open(_platform_path(path), "rb") as stream:
        return stream.read()


def evidence_file_exists(path: Path) -> bool:
    return os.path.isfile(_platform_path(path))


def iter_run_artifacts(runs_root: Path, file_name: str) -> list[Path]:
    artifacts: list[Path] = []
    try:
        with os.scandir(_platform_path(runs_root)) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                artifact = runs_root / entry.name / file_name
                if evidence_file_exists(artifact):
                    artifacts.append(artifact)
    except OSError as exc:
        raise PhaseError("evidence.enumeration_failed", file_name) from exc
    return sorted(artifacts, key=lambda path: path.parent.name)


def replace_attachment_canonical(attachment_root: Path, file_name: str, value: Any) -> tuple[Path, str]:
    if "/" in file_name or not file_name.endswith(".json"):
        raise PhaseError("evidence.invalid_path", file_name)
    attachment_root.mkdir(parents=False, exist_ok=True)
    path = attachment_root / file_name
    data = canonical_bytes(value)
    tmp = attachment_root / (file_name + ".tmp")
    try:
        os.unlink(_platform_path(tmp))
    except FileNotFoundError:
        pass
    with open(_platform_path(tmp), "xb", buffering=0) as stream:
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = stream.write(view[written:])
            if count is None or count <= 0:
                raise PhaseError("evidence.short_write", file_name)
            written += count
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(_platform_path(tmp), _platform_path(path))
    if os.name != "nt":
        descriptor = os.open(attachment_root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return path, digest_bytes(data)


class EvidenceStore:
    def __init__(self, evidence_root: Path, run_id: str) -> None:
        validate_run_id(run_id)
        absolute = evidence_root.absolute()
        _reject_existing_links(absolute)
        os.makedirs(_platform_path(absolute), exist_ok=True)
        _reject_existing_links(absolute)
        self.evidence_root = Path(_platform_path(absolute)).resolve(strict=True)
        phase_root = self.evidence_root / ".phase"
        runs_root = phase_root / "runs"
        os.makedirs(_platform_path(runs_root), exist_ok=True)
        self.run_root = runs_root / run_id
        try:
            os.mkdir(_platform_path(self.run_root))
        except FileExistsError as exc:
            raise PhaseError("evidence.run_exists", run_id) from exc
        self.blob_root = self.run_root / "blobs"
        self.attachment_root = self.run_root / "attachments"
        self.operational_lock_root = phase_root / "locks"
        os.makedirs(_platform_path(self.operational_lock_root), exist_ok=True)

    def write_canonical(self, relative: str, value: Any) -> tuple[Path, str]:
        if "/" in relative:
            parent_name, file_name = relative.split("/", 1)
            if parent_name != "attachments" or "/" in file_name:
                raise PhaseError("evidence.invalid_path", relative)
            self.attachment_root.mkdir(parents=False, exist_ok=True)
            path = self.attachment_root / file_name
        else:
            path = self.run_root / relative
        data = canonical_bytes(value)
        with open(_platform_path(path), "xb", buffering=0) as stream:
            view = memoryview(data)
            written = 0
            while written < len(view):
                count = stream.write(view[written:])
                if count is None or count <= 0:
                    raise PhaseError("evidence.short_write", relative)
                written += count
            stream.flush()
            os.fsync(stream.fileno())
        return path, digest_bytes(data)

    def write_or_verify_canonical(self, relative: str, value: Any) -> tuple[Path, str]:
        data = canonical_bytes(value)
        try:
            return self.write_canonical(relative, value)
        except FileExistsError:
            if "/" in relative:
                parent_name, file_name = relative.split("/", 1)
                if parent_name != "attachments" or "/" in file_name:
                    raise PhaseError("evidence.invalid_path", relative)
                path = self.attachment_root / file_name
            else:
                path = self.run_root / relative
            if read_evidence_bytes(path) != data:
                raise PhaseError("evidence.artifact_conflict", relative)
            return path, digest_bytes(data)

    def replace_attachment_canonical(self, file_name: str, value: Any) -> tuple[Path, str]:
        return replace_attachment_canonical(self.attachment_root, file_name, value)

    def write_blob_exact(self, digest: str, data: bytes) -> Path:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise PhaseError("evidence.invalid_blob_digest", digest)
        actual = digest_bytes(data)
        if actual != digest:
            raise PhaseError("evidence.blob_digest_mismatch", digest)
        path = self.blob_root / digest.split(":", 1)[1]
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(_platform_path(path), "xb", buffering=0) as stream:
            view = memoryview(data)
            written = 0
            while written < len(view):
                count = stream.write(view[written:])
                if count is None or count <= 0:
                    raise PhaseError("evidence.short_write", path.name)
                written += count
            stream.flush()
            os.fsync(stream.fileno())
        return path


def operational_lock_path(lock_root: Path, key_digest: str) -> Path:
    if not key_digest.startswith("sha256:") or len(key_digest) != 71:
        raise PhaseError("lock.invalid_digest", key_digest)
    root = Path(lock_root).absolute()
    _reject_existing_links(root)
    root.mkdir(parents=True, exist_ok=True)
    _reject_existing_links(root)
    root = root.resolve(strict=True)
    if root.is_symlink() or _is_reparse_point(root):
        raise PhaseError("path.link_forbidden" if root.is_symlink() else "path.reparse_forbidden", str(root))
    path = root / (key_digest.removeprefix("sha256:") + ".lock")
    if os.path.lexists(path):
        info = path.lstat()
        if path.is_symlink():
            raise PhaseError("path.link_forbidden", str(path))
        if _is_reparse_point(path):
            raise PhaseError("path.reparse_forbidden", str(path))
        if not stat.S_ISREG(info.st_mode):
            raise PhaseError("path.special_forbidden", str(path))
    return path


def validate_intent(intent: dict[str, Any], registry: RegistrySnapshot) -> None:
    schema = registry.schema_document("https://phase-tool.local/schemas/phase-intent.schema.json")
    Draft202012Validator(schema, registry=registry.schema_registry(), format_checker=FormatChecker()).validate(intent)


def validate_receipt(receipt: dict[str, Any], registry: RegistrySnapshot) -> None:
    schema = registry.schema_document("https://phase-tool.local/schemas/phase-receipt.schema.json")
    validator_registry = registry.schema_registry()
    Draft202012Validator(schema, registry=validator_registry, format_checker=FormatChecker()).validate(receipt)
    contract_binding = receipt["contract"]
    try:
        contract = registry.resolve_contract(
            contract_binding["id"],
            contract_binding["version"],
            contract_binding["package_digest"],
            core_version=receipt["core"]["version"],
        )
    except PhaseError as exc:
        if exc.code == "registry.entry_not_found":
            return
        raise
    evidence = contract.document["evidence"]
    exact_schema = registry.schema_document(
        evidence["receipt_schema_ref"],
        evidence["receipt_schema_digest"],
    )
    Draft202012Validator(exact_schema, registry=validator_registry, format_checker=FormatChecker()).validate(receipt)
