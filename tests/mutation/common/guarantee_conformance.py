from __future__ import annotations

import hashlib
import multiprocessing
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from phase_tool.installation import host_installation
from phase_tool.mutation.authority import AuthorityProvider


def _attempt_host_lock(root: str, scope: str, attempting: object, acquired: object) -> None:
    provider = host_installation().authority_provider
    attempting.set()  # type: ignore[attr-defined]
    with provider.lock_target_root(Path(root), scope):
        acquired.set()  # type: ignore[attr-defined]


def assert_exclusive_create_guarantee(provider: AuthorityProvider, root: Path) -> None:
    (root / "exclusive").mkdir()
    barrier = threading.Barrier(8)

    def contender(index: int) -> bool:
        authority = provider.open_authority(root, "exclusive/item.bin")
        try:
            barrier.wait()
            try:
                descriptor = authority.open_exclusive()
            except FileExistsError:
                return False
            try:
                os.write(descriptor, f"winner-{index}".encode("ascii"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return True
        finally:
            authority.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        winners = list(executor.map(contender, range(8)))

    assert winners.count(True) == 1
    assert (root / "exclusive" / "item.bin").read_bytes().startswith(b"winner-")


def assert_readback_verification_guarantee(provider: AuthorityProvider, root: Path) -> None:
    authority = provider.open_authority(root, "readback/item.bin")
    content = b"guarantee-readback"
    try:
        descriptor = authority.open_exclusive()
        try:
            os.write(descriptor, content)
            observed = authority.readback(None, descriptor)
        finally:
            os.close(descriptor)
        assert observed["known"] is True
        assert observed["exists"] is True
        assert observed["length"] == len(content)
        assert observed["digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    finally:
        authority.close()


def assert_cross_process_serialization_guarantee(provider: AuthorityProvider, root: Path) -> None:
    context = multiprocessing.get_context("spawn")
    attempting = context.Event()
    acquired = context.Event()
    scope = "guarantee-conformance"
    with provider.lock_target_root(root, scope):
        worker = context.Process(target=_attempt_host_lock, args=(str(root), scope, attempting, acquired))
        worker.start()
        assert attempting.wait(10)
        time.sleep(0.2)
        assert not acquired.is_set()
    assert acquired.wait(10)
    worker.join(10)
    assert worker.exitcode == 0


def assert_common_guarantees(provider: AuthorityProvider, root: Path) -> None:
    assert_exclusive_create_guarantee(provider, root)
    assert_readback_verification_guarantee(provider, root)
    assert_cross_process_serialization_guarantee(provider, root)
