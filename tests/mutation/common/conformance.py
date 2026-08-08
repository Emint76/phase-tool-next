from __future__ import annotations

import os
from pathlib import Path

from phase_tool.mutation.authority import AuthorityProvider


def assert_basic_authority_conformance(provider: AuthorityProvider, root: Path) -> None:
    authority = provider.open_authority(root, "nested/item.bin")
    try:
        before = authority.observe()
        assert before == {
            "known": True,
            "exists": False,
            "digest": None,
            "length": None,
            "head_token": None,
        }
        descriptor = authority.open_exclusive()
        try:
            os.write(descriptor, b"authority-conformance")
            os.fsync(descriptor)
            readback = authority.readback(None, descriptor)
        finally:
            os.close(descriptor)
        assert readback["exists"] is True
        assert readback["length"] == len(b"authority-conformance")
        authority.assert_namespace_binding()
        authority.fsync_parent()
        assert authority.read_bytes() == b"authority-conformance"
        observed = authority.observe()
        assert observed["digest"] == readback["digest"]
        assert observed["length"] == readback["length"]
    finally:
        authority.close()

    existing = provider.open_authority(root, "nested/item.bin")
    try:
        try:
            existing.open_exclusive()
        except FileExistsError:
            pass
        else:
            raise AssertionError("open_exclusive accepted an existing target")
    finally:
        existing.close()

    replacement = provider.open_authority(root, "nested/replacement.bin")
    destination = provider.open_authority(root, "nested/item.bin")
    try:
        descriptor = replacement.open_exclusive()
        try:
            os.write(descriptor, b"replacement")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        destination.replace_from(replacement)
        assert destination.read_bytes() == b"replacement"
    finally:
        replacement.close()
        destination.close()

    link_source = provider.open_authority(root, "nested/link-source.bin")
    link_target = provider.open_authority(root, "nested/link-target.bin")
    try:
        descriptor = link_source.open_exclusive()
        try:
            os.write(descriptor, b"linked")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        link_target.link_from(link_source)
        link_source.unlink()
        assert link_target.read_bytes() == b"linked"
        link_target.unlink()
        assert link_target.observe()["exists"] is False
    finally:
        link_source.close()
        link_target.close()

    with provider.lock_target_root(root, "authority-conformance"):
        pass
