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


def _write_bytes_exclusive_atomic(path: Path, data: bytes, label: str, *,
    _parent_descriptor: int | None = None) -> None:
    """Fsync staged bytes, then atomically link an absent canonical name.

    Linux uses an anonymous inode, so partial bytes never have a directory
    name. The named fallback atomically renames a complete stage into the
    canonical name, consuming the owned staging entry without any unlink.
    Failed or contended attempts retain their stage fail-closed because POSIX
    has no inode-conditional unlink primitive.
    """
    if _parent_descriptor is not None:
        if os.name != 'posix':raise PhaseError('platform.mutation_unsupported')
        _write_bytes_exclusive_at(_parent_descriptor,path,data,label)
        return
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


def _open_checked_operational_lock(path: Path) -> tuple[int, tuple[int, int], tuple[int, int]]:
    """Open one owned control-lock leaf under its pinned existing parent.

    This is the existing evidence IO boundary, not a target mutation API or
    native admission. The caller owns the returned FD, takes the original flock
    and checks namespace identity throughout that lifetime. No mkdir, overwrite,
    truncation, retry, descriptor transfer or persistent lock index is provided.
    """
    if (os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW')
        or not hasattr(os, 'O_CLOEXEC') or not hasattr(os, 'O_DIRECTORY')
        or not path.is_absolute()):
        raise PhaseError("lock.checked_platform_unsupported")
    _reject_existing_links(path.parent)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o022):
        raise PhaseError("lock.checked_parent_unsafe")
    parent_identity = parent.st_dev, parent.st_ino
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        pinned = os.fstat(parent_fd)
        if (pinned.st_dev, pinned.st_ino) != parent_identity:
            raise PhaseError("lock.checked_namespace_identity_changed")
        descriptor = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o022):
            raise PhaseError("lock.checked_object_unsafe")
        identity = info.st_dev, info.st_ino
        _reject_existing_links(path.parent)
        current_parent, named = path.parent.lstat(), path.lstat()
        if ((current_parent.st_dev, current_parent.st_ino) != parent_identity
            or current_parent.st_uid != os.geteuid() or current_parent.st_mode & 0o022
            or not stat.S_ISDIR(current_parent.st_mode) or not stat.S_ISREG(named.st_mode)
            or (named.st_dev, named.st_ino) != identity):
            raise PhaseError("lock.checked_namespace_identity_changed")
    except BaseException as primary:
        if descriptor is not None:
            try: os.close(descriptor)
            except BaseException as error: primary.add_note("Checked lock open cleanup: " + str(error))
        try: os.close(parent_fd)
        except BaseException as error: primary.add_note("Checked lock parent cleanup: " + str(error))
        raise
    # Parent FD close is consumed once; on failure never return the lock FD.
    try:
        os.close(parent_fd)
    except BaseException as primary:
        try: os.close(descriptor)
        except BaseException as error: primary.add_note("Checked lock open cleanup: " + str(error))
        raise
    return descriptor, parent_identity, identity


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
    version = intent.get("phase_intent_version")
    if version in ("1.1", "1.2"):
        binding = intent["contract"]
        contract = registry.resolve_contract(binding["id"], binding["version"], binding["package_digest"], core_version=intent["core"]["version"])
        resource = {"1.1": "schemas/phase-intent-1.1.schema.json",
                    "1.2": "schemas/phase-intent-1.2.schema.json"}[version]
        matches = [a["digest"] for a in contract.entry["package_artifacts"] if a["resource"] == resource]
        if len(matches) != 1:
            raise PhaseError("intent.schema_unbound")
        schema = registry.schema_document("https://phase-tool.local/" + resource, matches[0])
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


# DRAFT function intended for existing phase_tool/evidence/__init__.py.
# No candidate import/test/execution. This extends the existing evidence IO
# boundary; it is not another store, marker, journal or recovery authority.

def _confirm_native_immutable_files_durable(root, expected_root_identity, run_id, expected_files):
    """Confirm current durability ONLY inside the existing native common lock.

    The caller first verifies a permitted positive terminal proof and projects
    every immutable dependency from the original receipt/intent. Never call
    from readonly inspect. No mkdir, replacement, deletion, target I/O or retry.
    Accepted fixed mount contour has NO descendant mounts below this evidence
    root (including same-device binds); bootstrap must verify this before use.
    Trusted owner is single-threaded/non-reentrant, with no fork/FD transfer or
    unrelated close/reuse; inode equality is not open-file-description identity.
    """
    import hashlib
    import threading
    from ..installation import (qualify_host_authority_roots, _linux_filesystem_type,
        _require_native_no_descendant_mounts)
    from ..canonical import digest_bytes
    from ..mutation.ntfs.native import _require

    _require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_CLOEXEC')
        and hasattr(os, 'O_DIRECTORY') and root.is_absolute(), 'ntfs.native_durability_platform_required')
    validate_run_id(run_id)
    qualify_host_authority_roots({'phase_evidence_root':root})
    _require(_linux_filesystem_type(root) == 'ext4', 'ntfs.original_ext4_evidence_required')
    _require_native_no_descendant_mounts(root)
    _require(type(expected_files) is dict and 'receipt.json' in expected_files
        and 'attachments/native-terminal-proof.json' in expected_files,
        'ntfs.native_durability_dependency_mismatch')
    for name, binding in expected_files.items():
        parts = name.split('/')
        _require((parts in (['receipt.json'], ['intent.json'], ['preparation-binding.json'])
                or (len(parts) == 2 and parts[0] == 'attachments'
                    and re.fullmatch(r'[a-z][a-z0-9.-]*\.json',parts[1]) is not None)
                or (len(parts) == 2 and parts[0] == 'blobs'
                    and re.fullmatch('[0-9a-f]{64}',parts[1]) is not None))
            and type(binding) is tuple and len(binding) == 2
            and type(binding[0]) is str and re.fullmatch('sha256:[0-9a-f]{64}',binding[0]) is not None
            and type(binding[1]) is int and 0 <= binding[1] <= (2*1024**3 if parts[0]=='blobs' else 2*1024**2),
            'ntfs.native_durability_dependency_mismatch')

    owner = os.getpid(),threading.get_ident()
    opened = []
    directories = {}
    files = {}
    primary = None
    secondary = []

    def owned():
        _require(owner == (os.getpid(),threading.get_ident()), 'ntfs.native_durability_owner_changed')

    def fingerprint(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    def safe(info, directory):
        _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.geteuid() and not info.st_mode & 0o022
            and info.st_dev == expected_root_identity[0]
            and (directory or info.st_nlink == 1), 'ntfs.original_evidence_object_unsafe')

    def pin(parent, name, *, directory):
        owned()
        flags = os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
        if directory:flags |= os.O_DIRECTORY
        descriptor = os.open(name,flags,dir_fd=parent) if parent is not None else os.open(name,flags)
        # Register ownership BEFORE any subsequent failing stat/identity check.
        record = {'fd':descriptor,'parent':parent,'name':name,'directory':directory,'identity':None}
        opened.append(record)
        info = os.fstat(descriptor)
        safe(info,directory)
        record['identity'] = info.st_dev,info.st_ino
        named = os.stat(name,dir_fd=parent,follow_symlinks=False) if parent is not None else root.lstat()
        safe(named,directory)
        _require(fingerprint(info) == fingerprint(named), 'ntfs.original_evidence_identity_mismatch')
        return record

    def check(record):
        owned()
        info = os.fstat(record['fd']);safe(info,record['directory'])
        _require(record['identity'] == (info.st_dev,info.st_ino), 'ntfs.original_evidence_identity_mismatch')
        named = (os.stat(record['name'],dir_fd=record['parent'],follow_symlinks=False)
            if record['parent'] is not None else root.lstat())
        safe(named,record['directory'])
        _require(fingerprint(info) == fingerprint(named), 'ntfs.original_evidence_identity_mismatch')
        return info

    def inventory():
        run = directories['run']['fd']
        names = set(os.listdir(run))
        allowed={'intent.json','receipt.json','attachments','blobs'}
        if 'preparation-binding.json' in expected_files:allowed.add('preparation-binding.json')
        _require(names <= allowed,
            'ntfs.native_durability_dependency_mismatch')
        actual = names - {'attachments','blobs'}
        for child in ('attachments','blobs'):
            if child in names:
                _require(child in directories, 'ntfs.native_durability_dependency_mismatch')
                actual.update(child+'/'+name for name in os.listdir(directories[child]['fd']))
        _require(actual == set(expected_files), 'ntfs.native_durability_dependency_mismatch')

    try:
        _reject_existing_links(root)
        directories['root'] = pin(None,root,directory=True)
        _require(directories['root']['identity'] == expected_root_identity,
            'ntfs.original_evidence_identity_mismatch')
        for key,parent,name in [('phase','root','.phase'),('runs','phase','runs'),('run','runs',run_id)]:
            directories[key] = pin(directories[parent]['fd'],name,directory=True)
        present = set(os.listdir(directories['run']['fd']))
        for child in ('attachments','blobs'):
            if child in present:
                directories[child] = pin(directories['run']['fd'],child,directory=True)
        inventory()
        for name,(expected_digest,expected_length) in sorted(expected_files.items()):
            parts = name.split('/')
            parent = directories['run'] if len(parts) == 1 else directories[parts[0]]
            record = pin(parent['fd'],parts[-1],directory=False)
            before = check(record)
            _require(before.st_size == expected_length, 'ntfs.native_durability_bytes_mismatch')
            digest = hashlib.sha256();length = 0
            while True:
                owned()
                chunk = os.read(record['fd'], min(65536,expected_length-length+1))
                if not chunk:break
                length += len(chunk)
                _require(length <= expected_length, 'ntfs.native_durability_bytes_mismatch')
                digest.update(chunk)
            _require(length == expected_length and 'sha256:'+digest.hexdigest() == expected_digest
                and fingerprint(before) == fingerprint(check(record)),
                'ntfs.native_durability_bytes_mismatch')
            files[name] = record,before
        inventory()
        # Include receipt/proof, every attachment and every frozen blob. A
        # visible immutable link is not a successful durability acknowledgement.
        for record,before in files.values():
            _require(fingerprint(check(record)) == fingerprint(before),
                'ntfs.native_durability_bytes_mismatch')
            os.fsync(record['fd'])
            _require(fingerprint(check(record)) == fingerprint(before),
                'ntfs.native_durability_bytes_mismatch')
        for key in reversed(tuple(directories)):
            record = directories[key];check(record);os.fsync(record['fd']);check(record)
        inventory();_reject_existing_links(root);_require_native_no_descendant_mounts(root)
        for record,before in files.values():
            _require(fingerprint(check(record)) == fingerprint(before),
                'ntfs.native_durability_bytes_mismatch')
    except BaseException as error:
        primary = error
    finally:
        # Each owned FD has ONE close attempt; continue independent cleanup,
        # preserve primary, never close a descriptor whose identity changed.
        for record in reversed(opened):
            try:
                owned()
                current = os.fstat(record['fd'])
                if record['identity'] is not None:
                    _require(record['identity'] == (current.st_dev,current.st_ino),
                        'ntfs.original_evidence_identity_mismatch')
                os.close(record['fd'])
            except BaseException as error:
                if primary is None:primary = error
                else:secondary.append(error)
    if primary is not None:
        for error in secondary:
            try:
                primary.add_note('Native durability secondary close failure: '+type(error).__name__)
            except BaseException:
                pass
        raise primary


def _write_native_parent_failure(store,binding,value):
    """ONE negative-only write inside Core's EXISTING native common guard.

    Caller consumes its attempt BEFORE this function. Current namespace must be
    positively known; no fallback, overwrite or retry after any uncertain write.
    A failure attachment never supplies closure/quiescence or repairs completeness.
    """
    from ..installation import _NativeFileCreateReadBinding
    from ..mutation.ntfs.failure import validate_native_parent_failure
    from ..mutation.ntfs.native import _require
    _require(type(store) is EvidenceStore and type(binding) is _NativeFileCreateReadBinding,
        'ntfs.native_failure_store_required')
    validate_native_parent_failure(binding,value)
    root=binding.check_evidence_root()
    _require(root==store.evidence_root and store.run_root==root/'.phase'/'runs'/value['run_id'],
        'ntfs.native_failure_binding_mismatch')
    _reject_existing_links(store.run_root)
    for path in (root,root/'.phase',store.runs_root,store.run_root,store.attachment_root):
        info=path.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid()
            and not info.st_mode&0o022,'ntfs.original_evidence_object_unsafe')
    info=store.run_root.lstat()
    _require((info.st_dev,info.st_ino)==store._owned_run_identity,
        'ntfs.original_evidence_identity_mismatch')
    from ..streaming import read_bounded_file
    from ..canonical import parse_json_bytes,profile_digest
    original=parse_json_bytes(read_bounded_file(store.run_root/'intent.json',2*1024**2),
        maximum_bytes=2*1024**2)
    _require(profile_digest('intent',original)==value['intent_digest']
        and original['effect_plan_digest']==value['effect_plan_digest']
        and original['native_binding']['operation_nonce']==value['operation_nonce'],
        'ntfs.native_failure_binding_mismatch')
    binding.check_evidence_root()
    return _write_native_canonical(store,binding,'attachments/native-parent-failure.json',value)


def _confirm_native_original_absent(binding,run_id):
    """Positive no-follow absence under current qualified ext4 identity.

    Single accepted owner/no fork/FD replacement/mount changes. This is not a
    history reset, empty-history inference, dispatch permission or durability
    acknowledgement. Every descriptor closes before absence is returned.
    """
    from ..installation import _NativeFileCreateReadBinding
    from ..mutation.ntfs.native import _require
    from ..canonical import parse_json_bytes
    _require(type(binding) is _NativeFileCreateReadBinding,'ntfs.original_read_binding_required')
    root=binding.check_evidence_root()
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    identity=manifest['evidence_identity']
    opened=[]
    primary=None
    absent=False
    try:
        def pin(name,parent=None):
            descriptor=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                dir_fd=parent)
            record=[descriptor,None,parent,name]
            opened.append(record)
            info=os.fstat(descriptor)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid()
                and not info.st_mode&0o022 and info.st_dev==identity['device'],
                'ntfs.original_evidence_object_unsafe')
            record[1]=(info.st_dev,info.st_ino)
            try:named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError as error:
                # Successful open followed by a missing namespace edge is NOT
                # evidence of absence, even if a later rename restores it.
                raise PhaseError('ntfs.original_evidence_identity_mismatch') from error
            _require(stat.S_ISDIR(named.st_mode) and (named.st_dev,named.st_ino)==record[1],
                'ntfs.original_evidence_identity_mismatch')
            return descriptor
        current=pin(root)
        _require(opened[0][1]==(identity['device'],identity['inode']),
            'ntfs.original_evidence_identity_mismatch')
        for component in ('.phase','runs',run_id):
            try:current=pin(component,current)
            except FileNotFoundError:
                absent=True
                break
        else:
            try:os.stat('intent.json',dir_fd=current,follow_symlinks=False)
            except FileNotFoundError:absent=True
        _require(absent,'ntfs.original_unexpected_intent')
        for descriptor,expected,parent,name in opened:
            current_info=os.fstat(descriptor)
            named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            _require(expected==(current_info.st_dev,current_info.st_ino)==(named.st_dev,named.st_ino)
                and stat.S_ISDIR(named.st_mode),'ntfs.original_evidence_identity_mismatch')
        binding.check_evidence_root()
    except BaseException as error:
        primary=error
    finally:
        for descriptor,expected,_parent,_name in reversed(opened):
            try:
                if expected is not None:
                    info=os.fstat(descriptor)
                    _require(expected==(info.st_dev,info.st_ino),'ntfs.original_evidence_identity_mismatch')
                os.close(descriptor)  # Exactly one attempt, no close/reuse recovery.
            except BaseException as error:
                if primary is None:primary=error
                else:
                    try:primary.add_note('Original absence secondary close: '+type(error).__name__)
                    except BaseException:pass
    if primary is not None:raise primary



# Source fragment for the existing EvidenceIO module, not another store.

def _write_bytes_exclusive_at(parent_descriptor, path, data, label):
    """Existing exclusive primitives with an already verified borrowed parent.

    The caller owns the parent FD and namespace checks. This function owns only
    its single staging FD; it never reopens a pathname, retries a publication,
    replaces an object, removes a stage or closes the borrowed descriptor.
    """
    descriptor=None
    primary=None
    try:
        try:
            descriptor=os.open('.',os.O_WRONLY|os.O_TMPFILE|os.O_CLOEXEC,
                0o600,dir_fd=parent_descriptor)
        except OSError as error:
            unsupported={errno.EINVAL,errno.EISDIR,errno.ENOSYS,errno.EOPNOTSUPP}
            if hasattr(errno,'ENOTSUP'):unsupported.add(errno.ENOTSUP)
            if error.errno not in unsupported:raise
        if descriptor is not None:
            _write_descriptor(descriptor,data,label)
            _link_anonymous(descriptor,parent_descriptor,path.name)
        else:
            temporary_name=_temporary_path(path).name
            descriptor=_open_temporary(parent_descriptor,temporary_name)
            _write_descriptor(descriptor,data,label)
            _rename_noreplace(parent_descriptor,temporary_name,path.name)
        _fsync_pinned_directory(parent_descriptor,path.parent)
    except BaseException as error:
        primary=error
    finally:
        if descriptor is not None:
            try:os.close(descriptor)
            except BaseException as error:
                if primary is None:primary=error
                else:
                    try:primary.add_note('Native publication secondary stage close: '+type(error).__name__)
                    except BaseException:pass
    if primary is not None:raise primary


def _write_native_canonical(store,binding,relative,value):
    """Anchor native terminal/negative writes in the ONE existing EvidenceStore.

    A caller consumes each attempt first. Pin and check the current qualified
    root, run and attachment parent BEFORE staging; retain those exact FDs for
    exclusive publication. A rename after pin cannot redirect bytes into a
    replacement directory. A changed namespace or failed ack is unresolved,
    never permission to repeat, overwrite, downgrade or publish elsewhere.
    """
    import threading
    from ..canonical import parse_json_bytes
    from ..installation import _NativeFileCreateReadBinding
    from ..mutation.ntfs.native import _require
    _require(type(store) is EvidenceStore and type(binding) is _NativeFileCreateReadBinding,
        'ntfs.native_failure_store_required')
    _require(relative in {'receipt.json','attachments/native-terminal-proof.json',
        'attachments/native-parent-failure.json','prepared-stage-checkpoint'},'evidence.invalid_path')
    root=binding.check_evidence_root()
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    expected_root=manifest['evidence_identity']
    run_id=validate_run_id(store.run_root.name)
    checkpoint=relative=='prepared-stage-checkpoint'
    if checkpoint:
        from ..prepared_binding import NATIVE_BOUND_CONTRACT, PreparationBinding
        from ..continuation import PreparedStage
        exact=dict(zip(('id','version','package_digest'),NATIVE_BOUND_CONTRACT))
        _require(manifest['native_read_installation_version']=='1.7'
            and manifest['contract']==exact and type(value) is dict
            and set(value)=={'prepared','binding'},'ntfs.original_closed_checkpoint_required')
        PreparedStage.model_validate(value['prepared'])
        PreparationBinding.model_validate(value['binding'])
        _require(value['prepared']['run_id']==value['binding']['run_id']==run_id
            and value['prepared']['contract']==value['binding']['contract']==exact
            and value['binding']['preparation_digest']==digest_bytes(canonical_bytes(value['prepared'])),
            'recovery.preparation_binding_mismatch')
    _require(root==store.evidence_root and store.run_root==root/'.phase'/'runs'/run_id,
        'ntfs.native_failure_binding_mismatch')
    owner=os.getpid(),threading.get_ident()
    opened=[]
    primary=None
    result=None

    def check(record):
        _require(owner==(os.getpid(),threading.get_ident()),'ntfs.native_durability_owner_changed')
        fd,identity,parent,name=record
        current=os.fstat(fd)
        named=os.stat(name,dir_fd=parent,follow_symlinks=False)
        _require(stat.S_ISDIR(current.st_mode) and stat.S_ISDIR(named.st_mode)
            and identity==(current.st_dev,current.st_ino)==(named.st_dev,named.st_ino)
            and current.st_uid==os.geteuid() and not current.st_mode&0o022,
            'ntfs.original_evidence_identity_mismatch')

    def pin(name,parent=None):
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        record=[fd,None,parent,name]
        opened.append(record)
        info=os.fstat(fd)
        record[1]=info.st_dev,info.st_ino
        _require(info.st_dev==expected_root['device'],'ntfs.original_evidence_identity_mismatch')
        check(record)
        return fd

    try:
        current=pin(root)
        _require(opened[0][1]==(expected_root['device'],expected_root['inode']),
            'ntfs.original_evidence_identity_mismatch')
        for component in ('.phase','runs',run_id):current=pin(component,current)
        _require(opened[-1][1]==store._owned_run_identity,'ntfs.original_evidence_identity_mismatch')
        run_descriptor=current
        expected_attachment=getattr(store,'_native_owned_attachment_identity',None)
        _require(relative!='receipt.json' or expected_attachment is not None,
            'ntfs.native_terminal_attachment_unowned')
        if checkpoint or relative.startswith('attachments/') or expected_attachment is not None:
            before_pin=len(opened)
            try:attachment=pin('attachments',run_descriptor)
            except FileNotFoundError:
                # Open may prove absence only before it acquired a descriptor.
                # An already owned parent may never be silently recreated.
                if len(opened)!=before_pin or expected_attachment is not None:raise
                os.mkdir('attachments',0o700,dir_fd=run_descriptor)
                os.fsync(run_descriptor)
                attachment=pin('attachments',run_descriptor)
            observed_attachment=opened[-1][1]
            if expected_attachment is None:
                store._native_owned_attachment_identity=observed_attachment
            else:
                _require(observed_attachment==expected_attachment,
                    'ntfs.original_evidence_identity_mismatch')
            current=attachment if relative.startswith('attachments/') else run_descriptor
        for record in opened:check(record)
        binding.check_evidence_root()
        if checkpoint:
            from ..recovery import read_record
            writes=(('attachments/prepared-stage.json',value['prepared'],attachment),
                    ('preparation-binding.json',value['binding'],run_descriptor))
            for leaf,record_value,parent_fd in writes:
                for record in opened:check(record)
                _write_bytes_exclusive_atomic(store.run_root/leaf,canonical_bytes(record_value),leaf,
                    _parent_descriptor=parent_fd)
                for record in opened:check(record)
            for leaf,record_value,_parent_fd in writes:
                _require(read_record(store.run_root/leaf)==record_value,'recovery.preparation_binding_mismatch')
                for record in opened:check(record)
            path=store.run_root/'attachments/prepared-stage.json'
            data=canonical_bytes(value['prepared'])
        else:
            path=store.run_root/relative
            data=canonical_bytes(value)
            _write_bytes_exclusive_atomic(path,data,relative,_parent_descriptor=current)
        for record in opened:check(record)
        binding.check_evidence_root()
        if relative=='receipt.json':store._authoritative_evidence_published=True
        result=path,digest_bytes(data)
    except BaseException as error:
        primary=error
    finally:
        for fd,identity,_parent,_name in reversed(opened):
            try:
                _require(owner==(os.getpid(),threading.get_ident()),'ntfs.native_durability_owner_changed')
                if identity is not None:
                    info=os.fstat(fd)
                    _require(identity==(info.st_dev,info.st_ino),'ntfs.original_evidence_identity_mismatch')
                os.close(fd)
            except BaseException as error:
                if primary is None:primary=error
                else:
                    try:primary.add_note('Native publication secondary directory close: '+type(error).__name__)
                    except BaseException:pass
    if primary is not None:raise primary
    return result
