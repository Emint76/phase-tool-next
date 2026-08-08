"""Backward-compatible names for the installation-selected authority classes."""

from .platform import HostTargetAuthority as TargetAuthority
from .platform import HostTargetRootLock as TargetRootLock

__all__ = ["TargetAuthority", "TargetRootLock"]