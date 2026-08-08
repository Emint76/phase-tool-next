from __future__ import annotations

import fcntl
import os
import stat
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Callable

from ...canonical import digest_bytes
from ...errors import PhaseError
from ...paths import _is_reparse_point, safe_relative_locator
from ..authority import TargetAuthority
from ..guarantees import GuaranteeProfileBinding, registered_profile_binding


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


class PosixTargetRootLock:
    def __init__(self, root: Path, scope: str) -> None:
        self.root = Path(root)
        self.scope = scope
        self._descriptor: int | None = None

    def __enter__(self) -> "PosixTargetRootLock":
        if self.root.is_symlink() or _is_reparse_point(self.root):
            raise PhaseError("path.reparse_forbidden", str(self.root))
        root = self.root.resolve(strict=True)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        self._descriptor = os.open(root, flags)
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_EX)
        except Exception:
            os.close(self._descriptor)
            self._descriptor = None
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._descriptor is not None:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            os.close(self._descriptor)
            self._descriptor = None


class PosixTargetAuthority:
    def __init__(
        self,
        root: Path,
        locator: str,
        reparse_detector: Callable[[Path], bool] | None = None,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        self.locator = safe_relative_locator(locator)
        self.reparse_detector = reparse_detector or _is_reparse_point
        self.root = root.resolve(strict=True)
        self.target = self.root.joinpath(*self.locator.split("/"))
        self.parent_path = self.target.parent
        self.name = self.target.name
        self._handles: list[int] = []
        self.parent_fd: int | None = None
        self._namespace_bindings: list[tuple[Path, tuple[int, int]]] = []
        try:
            self._prepare_and_pin_parent(expected_root_identity)
        except Exception:
            self.close()
            raise

    @staticmethod
    def _directory_flags() -> int:
        return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)

    def _prepare_and_pin_parent(self, expected_root_identity: tuple[int, int] | None) -> None:
        root_fd = os.open(self.root, self._directory_flags())
        self._handles.append(root_fd)
        root_info = os.fstat(root_fd)
        root_identity = (int(root_info.st_dev), int(root_info.st_ino))
        if expected_root_identity is not None and root_identity != expected_root_identity:
            raise PhaseError("broker.root_identity_mismatch")
        self._namespace_bindings.append((self.root, root_identity))
        if self.reparse_detector(self.root):
            raise PhaseError("path.reparse_forbidden", self.locator)
        parent_fd = root_fd
        current = self.root
        for part in self.locator.split("/")[:-1]:
            current = current / part
            if self.reparse_detector(current):
                raise PhaseError("path.reparse_forbidden", self.locator)
            try:
                child_fd = os.open(part, self._directory_flags(), dir_fd=parent_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                if self.reparse_detector(current):
                    raise PhaseError("path.reparse_forbidden", self.locator)
                child_fd = os.open(part, self._directory_flags(), dir_fd=parent_fd)
            self._handles.append(child_fd)
            child_info = os.fstat(child_fd)
            self._namespace_bindings.append((current, (int(child_info.st_dev), int(child_info.st_ino))))
            parent_fd = child_fd
        self.parent_fd = parent_fd
        if self.target.is_symlink():
            raise PhaseError("path.link_forbidden", self.locator)
        if self.reparse_detector(self.target):
            raise PhaseError("path.reparse_forbidden", self.locator)

    def close(self) -> None:
        for handle in reversed(self._handles):
            os.close(handle)
        self._handles = []
        self.parent_fd = None
        self._namespace_bindings = []

    def assert_namespace_binding(self) -> None:
        for path, expected_identity in self._namespace_bindings:
            try:
                current = os.lstat(path)
            except FileNotFoundError as exc:
                raise PhaseError("path.parent_identity_changed", self.locator) from exc
            if not stat.S_ISDIR(current.st_mode):
                raise PhaseError("path.parent_identity_changed", self.locator)
            current_identity = (int(current.st_dev), int(current.st_ino))
            if current_identity != expected_identity:
                raise PhaseError("path.parent_identity_changed", self.locator)

    def observe(self) -> dict[str, object]:
        assert self.parent_fd is not None
        try:
            info = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return {"known": True, "exists": False, "digest": None, "length": None, "head_token": None}
        if stat.S_ISLNK(info.st_mode):
            raise PhaseError("path.link_forbidden", self.locator)
        if not stat.S_ISREG(info.st_mode):
            return {"known": True, "exists": True, "digest": None, "length": None, "head_token": None}
        descriptor = os.open(self.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=self.parent_fd)
        try:
            data = _read_descriptor(descriptor)
        finally:
            os.close(descriptor)
        return {"known": True, "exists": True, "digest": digest_bytes(data), "length": len(data), "head_token": None}

    def open_exclusive(self) -> int:
        assert self.parent_fd is not None
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(self.name, flags, 0o600, dir_fd=self.parent_fd)

    def open_existing(self, *, writable: bool = False, deny_write_sharing: bool = False) -> int:
        del deny_write_sharing
        assert self.parent_fd is not None
        flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(self.name, flags, dir_fd=self.parent_fd)

    def read_bytes(self, descriptor: int | None = None) -> bytes:
        opened = descriptor if descriptor is not None else self.open_existing()
        try:
            return _read_descriptor(opened)
        finally:
            if descriptor is None:
                os.close(opened)

    def readback(self, override: bytes | None, descriptor: int | None = None) -> dict[str, object]:
        observed_bytes = override if override is not None else self.read_bytes(descriptor)
        return {"known": True, "exists": True, "digest": digest_bytes(observed_bytes), "length": len(observed_bytes), "head_token": None}

    def replace_from(self, source: TargetAuthority) -> None:
        assert source.parent_fd is not None
        assert self.parent_fd is not None
        os.replace(source.name, self.name, src_dir_fd=source.parent_fd, dst_dir_fd=self.parent_fd)

    def link_from(self, source: TargetAuthority) -> None:
        assert source.parent_fd is not None
        assert self.parent_fd is not None
        os.link(
            source.name,
            self.name,
            src_dir_fd=source.parent_fd,
            dst_dir_fd=self.parent_fd,
            follow_symlinks=False,
        )

    def unlink(self, *, missing_ok: bool = False) -> None:
        assert self.parent_fd is not None
        try:
            os.unlink(self.name, dir_fd=self.parent_fd)
        except FileNotFoundError:
            if not missing_ok:
                raise

    def fsync_parent(self) -> None:
        if self.parent_fd is not None:
            os.fsync(self.parent_fd)


class PosixAuthorityProvider:
    def guarantee_profile_binding(self) -> GuaranteeProfileBinding:
        return registered_profile_binding("phase.posix.authority.v1@1.0.0")

    def open_authority(
        self,
        root: Path,
        locator: str,
        reparse_detector: Callable[[Path], bool] | None = None,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> PosixTargetAuthority:
        return PosixTargetAuthority(root, locator, reparse_detector, expected_root_identity)

    def lock_target_root(self, root: Path, scope: str) -> AbstractContextManager[object]:
        return PosixTargetRootLock(root, scope)
