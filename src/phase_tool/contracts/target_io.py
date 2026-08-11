from __future__ import annotations

from pathlib import Path

from ..mutation.platform import HostAuthorityProvider


def observe_target(root: Path, locator: str) -> dict[str, object]:
    authority = HostAuthorityProvider().open_authority(root, locator, create_parents=False)
    try:
        observation = authority.observe()
        authority.assert_namespace_binding()
        return observation
    finally:
        authority.close()


def read_target_bytes(root: Path, locator: str, *, maximum_bytes: int) -> bytes:
    authority = HostAuthorityProvider().open_authority(root, locator, create_parents=False)
    try:
        data = authority.read_bytes(maximum_bytes=maximum_bytes)
        authority.assert_namespace_binding()
        return data
    finally:
        authority.close()
