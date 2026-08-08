from __future__ import annotations

import os
from pathlib import Path

import pytest

if os.name == "nt":
    pytest.skip("POSIX authority conformance requires POSIX", allow_module_level=True)

from phase_tool.mutation.posix import PosixAuthorityProvider
from phase_tool.mutation.posix.authority import PosixTargetRootLock
from tests.mutation.common.conformance import assert_basic_authority_conformance
from tests.mutation.common.guarantee_conformance import assert_common_guarantees


def test_posix_authority_common_conformance(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    assert_basic_authority_conformance(PosixAuthorityProvider(), root)


def test_posix_root_lock_closes_descriptor_when_flock_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import phase_tool.mutation.posix.authority as authority_module

    root = tmp_path / "root"
    root.mkdir()
    closed: list[int] = []
    original_close = authority_module.os.close

    def fail_flock(_descriptor: int, _operation: int) -> None:
        raise OSError("injected flock failure")

    def record_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(authority_module.fcntl, "flock", fail_flock)
    monkeypatch.setattr(authority_module.os, "close", record_close)
    lock = PosixTargetRootLock(root, "scope")

    with pytest.raises(OSError, match="injected flock failure"):
        lock.__enter__()

    assert len(closed) == 1
    assert lock._descriptor is None


def test_posix_production_profile_common_guarantees(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    provider = PosixAuthorityProvider()
    binding = provider.guarantee_profile_binding()
    assert binding.id == "phase.posix.authority.v1"
    assert_common_guarantees(provider, root)


def test_posix_production_profile_claims_only_executable_conformance_guarantees() -> None:
    from phase_tool.registry import BundledRegistry

    provider = PosixAuthorityProvider()
    profile = BundledRegistry.load().resolve_guarantee_profile(provider.guarantee_profile_binding().as_dict())

    assert profile["classification"] == "production"
    assert set(profile["provided_guarantees"]) == {
        "exclusive_create",
        "readback_verification",
        "cross_process_serialization",
        "namespace_bound_mutation",
        "atomic_replace",
        "namespace_metadata_flush_attempted",
    }
    assert {item["guarantee"] for item in profile["conformance"]} == set(profile["provided_guarantees"])
    assert "process_crash_recovery" not in profile["provided_guarantees"]
