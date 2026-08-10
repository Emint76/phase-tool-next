from __future__ import annotations

import ctypes
import errno
import os
import re
import stat
import sysconfig
import uuid
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


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(_platform_path(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_directory_durable(path: Path, *, parents: bool) -> None:
    path.mkdir(parents=parents, exist_ok=True)
    _fsync_directory(path.parent)


def _temporary_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")


def _write_descriptor(descriptor: int, data: bytes, label: str) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise PhaseError("evidence.short_write", label)
        written += count
    os.fsync(descriptor)


def _open_pinned_directory(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(_platform_path(path), flags)


def _open_temporary(parent_descriptor: int, file_name: str) -> int:
    """Open an owned named stage relative to a pinned parent directory."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    return os.open(file_name, flags, 0o600, dir_fd=parent_descriptor)


def _write_temporary(path: Path, data: bytes, label: str) -> None:
    """Portable non-production fallback used where directory fds are unavailable."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(_platform_path(path), flags, 0o600)
    try:
        _write_descriptor(descriptor, data, label)
    finally:
        os.close(descriptor)


def _rename_noreplace(parent_descriptor: int, source_name: str, destination_name: str) -> None:
    """Atomically consume a named stage only when the canonical name is absent."""
    library = ctypes.CDLL(None, use_errno=True)
    source = ctypes.c_char_p(os.fsencode(source_name))
    destination = ctypes.c_char_p(os.fsencode(destination_name))
    try:
        renameat2 = library.renameat2
    except AttributeError:
        machine = os.uname().machine.lower()
        generic_machines = {
            "aarch64",
            "arc",
            "arceb",
            "arm64",
            "csky",
            "hexagon",
            "loongarch64",
            "nios2",
            "openrisc",
            "or1k",
            "riscv32",
            "riscv64",
        }
        syscall_numbers = {
            "alpha": 510,
            "m68k": 351,
            "microblaze": 383,
            "parisc": 337,
            "parisc64": 337,
            "ppc": 357,
            "ppc64": 357,
            "ppc64le": 357,
            "s390": 347,
            "s390x": 347,
            "sh4": 371,
            "sh4eb": 371,
            "sparc": 345,
            "sparc64": 345,
            "xtensa": 336,
        }
        if machine in generic_machines:
            syscall_number = 276
        elif machine.startswith("arm"):
            syscall_number = 382
        elif machine == "x86_64":
            syscall_number = 316 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x4000013C
        elif re.fullmatch(r"i[3-6]86", machine):
            syscall_number = 353
        elif machine.startswith("mips"):
            multiarch = str(sysconfig.get_config_var("MULTIARCH") or "")
            if "abin32" in multiarch:
                syscall_number = 6315
            elif "abi64" in multiarch or (not multiarch and ctypes.sizeof(ctypes.c_void_p) == 8):
                syscall_number = 5311
            else:
                syscall_number = 4351
        else:
            syscall_number = syscall_numbers.get(machine)
        if syscall_number is None:
            raise OSError(errno.ENOSYS, "renameat2 is unavailable")
        syscall = library.syscall
        syscall.restype = ctypes.c_long
        result = syscall(
            ctypes.c_long(syscall_number),
            ctypes.c_int(parent_descriptor),
            source,
            ctypes.c_int(parent_descriptor),
            destination,
            ctypes.c_uint(1),
        )
    else:
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        result = renameat2(parent_descriptor, source, parent_descriptor, destination, 1)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def _open_anonymous_staging(parent: Path) -> tuple[int, int] | None:
    if os.name != "posix" or not hasattr(os, "O_TMPFILE"):
        return None
    parent_descriptor = _open_pinned_directory(parent)
    try:
        descriptor = os.open(".", os.O_WRONLY | os.O_TMPFILE, 0o600, dir_fd=parent_descriptor)
    except OSError as exc:
        os.close(parent_descriptor)
        unsupported = {errno.EINVAL, errno.EISDIR, errno.ENOSYS, errno.EOPNOTSUPP}
        if hasattr(errno, "ENOTSUP"):
            unsupported.add(errno.ENOTSUP)
        if exc.errno in unsupported:
            return None
        raise
    return parent_descriptor, descriptor


def _link_anonymous(descriptor: int, parent_descriptor: int, file_name: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    linkat = library.linkat
    linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    linkat.restype = ctypes.c_int
    if linkat(descriptor, ctypes.c_char_p(b""), parent_descriptor, ctypes.c_char_p(os.fsencode(file_name)), 0x1000) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), file_name)


def _fsync_pinned_directory(parent_descriptor: int, parent: Path) -> None:
    os.fsync(parent_descriptor)
    pinned = os.fstat(parent_descriptor)
    current = os.stat(_platform_path(parent), follow_symlinks=False)
    if (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino):
        raise OSError(errno.ESTALE, "evidence parent directory identity changed", str(parent))


def _write_bytes_exclusive_atomic(path: Path, data: bytes, label: str) -> None:
    """Fsync staged bytes, then atomically link an absent canonical name.

    Linux uses an anonymous inode, so partial bytes never have a directory
    name. The named fallback atomically renames a complete stage into the
    canonical name, consuming the owned staging entry without any unlink.
    Failed or contended attempts retain their stage fail-closed because POSIX
    has no inode-conditional unlink primitive.
    """
    anonymous = _open_anonymous_staging(path.parent)
    if anonymous is not None:
        parent_descriptor, descriptor = anonymous
        try:
            _write_descriptor(descriptor, data, label)
            _link_anonymous(descriptor, parent_descriptor, path.name)
            _fsync_pinned_directory(parent_descriptor, path.parent)
        finally:
            try:
                os.close(descriptor)
            finally:
                os.close(parent_descriptor)
        return
    if os.name != "posix":
        temporary = _temporary_path(path)
        _write_temporary(temporary, data, label)
        os.link(_platform_path(temporary), _platform_path(path), follow_symlinks=False)
        _fsync_directory(path.parent)
        return
    parent_descriptor = _open_pinned_directory(path.parent)
    descriptor: int | None = None
    temporary_name = _temporary_path(path).name
    try:
        descriptor = _open_temporary(parent_descriptor, temporary_name)
        _write_descriptor(descriptor, data, label)
        _rename_noreplace(parent_descriptor, temporary_name, path.name)
        _fsync_pinned_directory(parent_descriptor, path.parent)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            os.close(parent_descriptor)


def _replace_bytes_atomic(path: Path, data: bytes, label: str) -> None:
    """Replace a mutable projection only after its complete staged bytes are synced."""
    anonymous = _open_anonymous_staging(path.parent)
    if anonymous is not None:
        parent_descriptor, descriptor = anonymous
        temporary_name = _temporary_path(path).name
        try:
            _write_descriptor(descriptor, data, label)
            _link_anonymous(descriptor, parent_descriptor, temporary_name)
            os.replace(temporary_name, path.name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            _fsync_pinned_directory(parent_descriptor, path.parent)
        finally:
            try:
                os.close(descriptor)
            finally:
                os.close(parent_descriptor)
        return
    temporary = _temporary_path(path)
    _write_temporary(temporary, data, label)
    os.replace(_platform_path(temporary), _platform_path(path))
    _fsync_directory(path.parent)


def replace_attachment_canonical(attachment_root: Path, file_name: str, value: Any) -> tuple[Path, str]:
    if "/" in file_name or not file_name.endswith(".json"):
        raise PhaseError("evidence.invalid_path", file_name)
    _ensure_directory_durable(attachment_root, parents=False)
    path = attachment_root / file_name
    data = canonical_bytes(value)
    _replace_bytes_atomic(path, data, file_name)
    return path, digest_bytes(data)


class EvidenceStore:
    def __init__(self, evidence_root: Path, run_id: str) -> None:
        try:
            validate_run_id(run_id)
            absolute = evidence_root.absolute()
            _reject_existing_links(absolute)
            os.makedirs(_platform_path(absolute), exist_ok=True)
            _fsync_directory(absolute.parent)
            _reject_existing_links(absolute)
            self.evidence_root = Path(_platform_path(absolute)).resolve(strict=True)
            phase_root = self.evidence_root / ".phase"
            self.runs_root = phase_root / "runs"
            os.makedirs(_platform_path(self.runs_root), exist_ok=True)
            _fsync_directory(phase_root)
            _fsync_directory(self.evidence_root)
            self.run_root = self.runs_root / run_id
            self.blob_root = self.run_root / "blobs"
            self.attachment_root = self.run_root / "attachments"
            self.operational_lock_root = phase_root / "locks"
            # Shared roots are prepared before the exclusive run-id reservation.
            os.makedirs(_platform_path(self.operational_lock_root), exist_ok=True)
            _fsync_directory(phase_root)
            try:
                os.mkdir(_platform_path(self.run_root), 0o700)
            except FileExistsError as exc:
                raise PhaseError("evidence.run_exists", run_id) from exc
            try:
                run_info = os.stat(_platform_path(self.run_root), follow_symlinks=False)
                _fsync_directory(self.runs_root)
            except OSError:
                # Ownership could not be proven after reservation. Keep the
                # canonical run id blocked rather than deleting by path.
                raise
            self._owned_run_identity = (run_info.st_dev, run_info.st_ino)
            self._authoritative_evidence_published = False
        except PhaseError:
            raise
        except OSError as exc:
            raise PhaseError("evidence.initialization_failed") from exc

    def write_canonical(self, relative: str, value: Any) -> tuple[Path, str]:
        if "/" in relative:
            parent_name, file_name = relative.split("/", 1)
            if parent_name != "attachments" or "/" in file_name:
                raise PhaseError("evidence.invalid_path", relative)
            _ensure_directory_durable(self.attachment_root, parents=False)
            path = self.attachment_root / file_name
        else:
            path = self.run_root / relative
        data = canonical_bytes(value)
        _write_bytes_exclusive_atomic(path, data, relative)
        if relative in {"intent.json", "receipt.json"}:
            self._authoritative_evidence_published = True
        return path, digest_bytes(data)

    def release_unpublished_run(self) -> bool:
        """Quarantine an owned pre-intent reservation without deleting its bytes."""
        if self._owned_run_identity is None or self._authoritative_evidence_published:
            return False
        if evidence_file_exists(self.run_root / "intent.json") or evidence_file_exists(self.run_root / "receipt.json"):
            return False
        try:
            run_info = os.stat(_platform_path(self.run_root), follow_symlinks=False)
        except FileNotFoundError:
            self._owned_run_identity = None
            return True
        if not stat.S_ISDIR(run_info.st_mode) or (run_info.st_dev, run_info.st_ino) != self._owned_run_identity:
            return False
        abandoned = self.runs_root / f".abandoned-{self.run_root.name}-{uuid.uuid4().hex}"
        os.rename(_platform_path(self.run_root), _platform_path(abandoned))
        abandoned_info = os.stat(_platform_path(abandoned), follow_symlinks=False)
        if (abandoned_info.st_dev, abandoned_info.st_ino) != self._owned_run_identity:
            # Namespace identity became uncertain. Preserve every byte and
            # leave the canonical run id blocked rather than guessing.
            try:
                os.mkdir(_platform_path(self.run_root), 0o000)
            except FileExistsError:
                pass
            try:
                _fsync_directory(self.runs_root)
            except OSError:
                pass
            return False
        self._owned_run_identity = None
        _fsync_directory(self.runs_root)
        return True

    def write_or_verify_canonical(self, relative: str, value: Any) -> tuple[Path, str]:
        data = canonical_bytes(value)
        if "/" in relative:
            parent_name, file_name = relative.split("/", 1)
            if parent_name != "attachments" or "/" in file_name:
                raise PhaseError("evidence.invalid_path", relative)
            path = self.attachment_root / file_name
        else:
            path = self.run_root / relative
        if evidence_file_exists(path):
            if read_evidence_bytes(path) != data:
                raise PhaseError("evidence.artifact_conflict", relative)
            if relative in {"intent.json", "receipt.json"}:
                self._authoritative_evidence_published = True
            return path, digest_bytes(data)
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
            if relative in {"intent.json", "receipt.json"}:
                self._authoritative_evidence_published = True
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
        _ensure_directory_durable(path.parent, parents=True)
        _write_bytes_exclusive_atomic(path, data, path.name)
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
