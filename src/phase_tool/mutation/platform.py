from __future__ import annotations

import sys

if sys.platform.startswith("linux"):
    from .posix.authority import PosixAuthorityProvider as HostAuthorityProvider
    from .posix.authority import PosixTargetAuthority as HostTargetAuthority
    from .posix.authority import PosixTargetRootLock as HostTargetRootLock
else:
    from .unsupported import UnsupportedAuthorityProvider as HostAuthorityProvider
    from .unsupported import UnsupportedTargetAuthority as HostTargetAuthority
    from .unsupported import UnsupportedTargetRootLock as HostTargetRootLock

__all__ = ["HostAuthorityProvider", "HostTargetAuthority", "HostTargetRootLock"]
