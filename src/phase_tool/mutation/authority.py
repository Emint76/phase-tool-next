from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from .guarantees import GuaranteeProfileBinding


class TargetAuthority(Protocol):
    root: Path
    locator: str
    target: Path
    name: str
    parent_fd: int | None
    reparse_detector: Callable[[Path], bool]

    def observe(self) -> dict[str, object]: ...

    def open_exclusive(self) -> int: ...

    def open_existing(self, *, writable: bool = False, deny_write_sharing: bool = False) -> int: ...

    def read_bytes(self, descriptor: int | None = None) -> bytes: ...

    def readback(self, override: bytes | None, descriptor: int | None = None) -> dict[str, object]: ...

    def replace_from(self, source: "TargetAuthority") -> None: ...

    def link_from(self, source: "TargetAuthority") -> None: ...

    def unlink(self, *, missing_ok: bool = False) -> None: ...

    def assert_namespace_binding(self) -> None: ...

    def fsync_parent(self) -> None: ...

    def close(self) -> None: ...


@runtime_checkable
class GuaranteeProfileProvider(Protocol):
    def guarantee_profile_binding(self) -> GuaranteeProfileBinding: ...


@runtime_checkable
class AuthorityProvider(Protocol):
    def open_authority(
        self,
        root: Path,
        locator: str,
        reparse_detector: Callable[[Path], bool] | None = None,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> TargetAuthority: ...

    def lock_target_root(self, root: Path, scope: str) -> AbstractContextManager[object]: ...
