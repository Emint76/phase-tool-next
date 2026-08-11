from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from .guarantees import GuaranteeProfileBinding


@dataclass(frozen=True)
class RecordStreamObservation:
    digest: str
    length: int
    record_count: int
    head_token: str
    tail: bytes
    prefix_head_token: str | None = None
    segment_digest: str | None = None
    segment: bytes | None = None


class TargetAuthority(Protocol):
    root: Path
    locator: str
    target: Path
    name: str
    parent_fd: int | None
    reparse_detector: Callable[[Path], bool]

    def observe(self) -> dict[str, object]: ...

    def observe_record_stream(
        self,
        descriptor: int | None = None,
        *,
        tail_bytes: int = 0,
        prefix_length: int | None = None,
        segment_offset: int | None = None,
        segment_length: int | None = None,
    ) -> RecordStreamObservation: ...

    def open_exclusive(self) -> int: ...

    def open_existing(self, *, writable: bool = False, deny_write_sharing: bool = False) -> int: ...

    def read_bytes(
        self,
        descriptor: int | None = None,
        *,
        maximum_bytes: int | None = None,
    ) -> bytes: ...

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
        *,
        create_parents: bool = True,
    ) -> TargetAuthority: ...

    def lock_target_root(self, root: Path, scope: str) -> AbstractContextManager[object]: ...
