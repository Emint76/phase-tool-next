from __future__ import annotations

import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Callable

from .errors import PhaseError

_COMPONENT = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$")
_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE)


def safe_relative_locator(locator: str) -> str:
    if not isinstance(locator, str) or not locator or len(locator) > 1024:
        raise PhaseError("path.invalid_locator")
    if "\\" in locator or ":" in locator or locator.startswith("/"):
        raise PhaseError("path.absolute_or_platform_qualified", locator)
    parts = locator.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PhaseError("path.traversal", locator)
    for part in parts:
        if not _COMPONENT.fullmatch(part) or part.endswith((".", " ")):
            raise PhaseError("path.invalid_component", part)
        if _RESERVED.fullmatch(part):
            raise PhaseError("path.windows_reserved", part)
    return str(PurePosixPath(*parts))


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.lstat().st_file_attributes  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False
    return bool(attributes & 0x400)


def _platform_path(path: Path) -> str:
    text = str(path)
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    return "\\\\?\\" + os.path.abspath(text)


def contained_read_path(root: Path, locator: str) -> Path:
    normalized = safe_relative_locator(locator)
    root = root.resolve(strict=True)
    current = root
    for part in normalized.split("/"):
        current = current / part
        platform_current = Path(_platform_path(current))
        if platform_current.is_symlink():
            raise PhaseError("path.link_forbidden", normalized)
        if os.path.exists(platform_current) and _is_reparse_point(platform_current):
            raise PhaseError("path.reparse_forbidden", normalized)
    if os.name == "nt":
        if not os.path.exists(_platform_path(current)):
            raise PhaseError("path.not_found", normalized)
        return current
    try:
        resolved = current.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PhaseError("path.not_found", normalized) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PhaseError("path.outside_root", normalized) from exc
    return resolved


def inspect_target_path(root: Path, locator: str) -> tuple[Path, bool]:
    """Resolve existing components without creating missing target parents."""
    normalized = safe_relative_locator(locator)
    root = root.resolve(strict=True)
    current = root
    missing = False
    for part in normalized.split("/"):
        current = current / part
        if missing:
            continue
        platform_current = Path(_platform_path(current))
        try:
            info = os.lstat(platform_current)
        except (FileNotFoundError, NotADirectoryError):
            missing = True
            continue
        if stat.S_ISLNK(info.st_mode):
            raise PhaseError("path.link_forbidden", normalized)
        if bool(getattr(info, "st_file_attributes", 0) & 0x400):
            raise PhaseError("path.reparse_forbidden", normalized)
    if not missing:
        if os.name == "nt":
            return current, True
        resolved = current.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise PhaseError("path.outside_root", normalized) from exc
        return resolved, True
    return current, False


def contained_target_path(
    root: Path,
    locator: str,
    *,
    reparse_detector: Callable[[Path], bool] | None = None,
) -> Path:
    normalized = safe_relative_locator(locator)
    root = root.resolve(strict=True)
    detector = reparse_detector or _is_reparse_point
    current = root
    parts = normalized.split("/")
    for index, part in enumerate(parts):
        current = current / part
        if current.is_symlink():
            raise PhaseError("path.link_forbidden", normalized)
        if current.exists() and detector(current):
            raise PhaseError("path.reparse_forbidden", normalized)
        if index < len(parts) - 1 and not current.is_dir():
            raise PhaseError("path.parent_missing", normalized)
    parent = current.parent.resolve(strict=True)
    try:
        parent.relative_to(root)
    except ValueError as exc:
        raise PhaseError("path.outside_root", normalized) from exc
    return current


def ensure_target_parent(root: Path, locator: str, *, reparse_detector: Callable[[Path], bool] | None = None) -> None:
    normalized = safe_relative_locator(locator)
    root = root.resolve(strict=True)
    detector = reparse_detector or _is_reparse_point
    current = root
    for part in normalized.split("/")[:-1]:
        current = current / part
        if current.exists():
            if current.is_symlink():
                raise PhaseError("path.link_forbidden", normalized)
            if detector(current):
                raise PhaseError("path.reparse_forbidden", normalized)
            if not current.is_dir():
                raise PhaseError("path.parent_missing", normalized)
            continue
        current.mkdir()
        if current.is_symlink():
            raise PhaseError("path.link_forbidden", normalized)
        if detector(current):
            raise PhaseError("path.reparse_forbidden", normalized)
