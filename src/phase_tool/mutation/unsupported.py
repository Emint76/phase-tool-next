from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Callable, NoReturn

from ..errors import PhaseError


def _unsupported() -> NoReturn:
    raise PhaseError("platform.mutation_unsupported")


class UnsupportedTargetAuthority:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _unsupported()


class UnsupportedTargetRootLock:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        _unsupported()


class UnsupportedAuthorityProvider:
    def open_authority(
        self,
        root: Path,
        locator: str,
        reparse_detector: Callable[[Path], bool] | None = None,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> UnsupportedTargetAuthority:
        del root, locator, reparse_detector, expected_root_identity
        _unsupported()

    def lock_target_root(self, root: Path, scope: str) -> AbstractContextManager[object]:
        del root, scope
        _unsupported()
