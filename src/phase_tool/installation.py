from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .errors import PhaseError
from .mutation.authority import AuthorityProvider
from .mutation.guarantees import GuaranteeProfileBinding, registered_profile_binding
from .mutation.platform import HostAuthorityProvider


@dataclass(frozen=True)
class Installation:
    authority_provider: AuthorityProvider
    authority_profile_binding: GuaranteeProfileBinding | None = None

    def qualify_authority_roots(self, root_bindings: Mapping[str, Path]) -> None:
        qualify_host_authority_roots(root_bindings)


def _resolved_existing_root(path: Path) -> Path:
    lexical = Path(os.path.abspath(path))
    resolved = Path(path).resolve(strict=True)
    if os.path.normcase(str(lexical)) != os.path.normcase(str(resolved)):
        raise PhaseError("guarantee.profile_scope_unsupported", str(path))
    return resolved


def _linux_filesystem_type(path: Path) -> str:
    resolved = str(_resolved_existing_root(path))
    selected: tuple[int, str] | None = None
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        if not separator or len(fields) < 5:
            continue
        mount = re.sub(r"\\([0-7]{3})", lambda item: chr(int(item.group(1), 8)), fields[4])
        if resolved == mount or resolved.startswith(mount.rstrip("/") + "/"):
            candidate = (len(mount), right.split()[0])
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    if selected is None:
        raise PhaseError("guarantee.profile_scope_unsupported", resolved)
    return selected[1]


def _linux_kernel_release() -> str:
    return Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8")


def _is_containerized_linux() -> bool:
    try:
        return _linux_filesystem_type(Path("/")) == "overlay"
    except (PhaseError, OSError):
        return False


def _is_wsl() -> bool:
    try:
        release = _linux_kernel_release().strip()
        if re.fullmatch(r"[0-9]+\.[0-9]+[A-Za-z0-9._+-]*", release) is None:
            return True
        return "microsoft" in release.lower() and not _is_containerized_linux()
    except OSError:
        return True


def qualify_host_authority_roots(root_bindings: Mapping[str, Path]) -> None:
    if not sys.platform.startswith("linux"):
        raise PhaseError(
            "platform.mutation_unsupported",
            details={"platform": sys.platform},
        )
    for binding_id, root in sorted(root_bindings.items()):
        try:
            filesystem = _linux_filesystem_type(Path(root))
            is_wsl = _is_wsl()
            qualified = not is_wsl and filesystem in {"ext4", "overlay"}
            if is_wsl:
                filesystem = f"wsl:{filesystem}"
        except (FileNotFoundError, OSError) as exc:
            raise PhaseError("guarantee.profile_scope_unsupported", binding_id) from exc
        if not qualified:
            raise PhaseError(
                "guarantee.profile_scope_unsupported",
                binding_id,
                details={"binding_id": binding_id, "filesystem": filesystem},
            )


def host_installation() -> Installation:
    """Build the explicit host installation configuration at one composition boundary."""

    provider = HostAuthorityProvider()
    profile = registered_profile_binding("phase.posix.authority.v1@1.0.0") if sys.platform.startswith("linux") else None
    return Installation(
        authority_provider=provider,
        authority_profile_binding=profile,
    )
