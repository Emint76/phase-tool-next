"""Bounded binary I/O for the explicitly versioned streaming file route.

The digest identifies the bytes actually consumed. Matching descriptor/path stat
fingerprints detect ordinary drift, not an atomic snapshot of a hostile writer.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from tempfile import NamedTemporaryFile

from .errors import PhaseError
from .evidence import _ensure_directory_durable, _reject_existing_links
from .paths import contained_read_path

CHUNK_BYTES = 1024 * 1024
FILE_LIMIT = 2 * 1024 * 1024 * 1024
REQUEST_LIMIT = 1024 * 1024
MECHANISM_ID = "mechanism.exclusive_create_v2"
CONTRACT_BINDING = "file_create.v2@1.0.0"


def limits() -> dict[str, int]:
    return {"request_bytes": REQUEST_LIMIT, "file_bytes": FILE_LIMIT,
            "total_bytes": FILE_LIMIT, "objects": 1, "workers_per_operation": 1,
            "concurrent_operations_per_target_root": 1,
            "chunk_bytes": CHUNK_BYTES}


def fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def transfer(source: int, maximum_bytes: int, destination: int | None = None,
             *, write_counter: list[int] | None = None) -> tuple[str, int]:
    """Hash all consumed bytes, optionally copy them; never write beyond the cap."""
    if type(maximum_bytes) is not int or maximum_bytes < 0:
        raise PhaseError("stream.invalid_limit")
    if write_counter is not None and (type(write_counter) is not list or len(write_counter) != 1 or type(write_counter[0]) is not int or write_counter[0] < 0):
        raise PhaseError("stream.invalid_counter")
    before = os.fstat(source)
    if not stat.S_ISREG(before.st_mode):
        raise PhaseError("stream.not_regular_file")
    if before.st_size > maximum_bytes:
        raise PhaseError("stream.limit_exceeded")
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(source, min(CHUNK_BYTES, maximum_bytes-total+1))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise PhaseError("stream.limit_exceeded")
        digest.update(chunk)
        if destination is not None:
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                if written <= 0 or written > len(view):
                    raise OSError("stream write made invalid progress")
                if write_counter is not None:
                    write_counter[0] += written
                view = view[written:]
    if fingerprint(before) != fingerprint(os.fstat(source)) or total != before.st_size:
        raise PhaseError("freeze.source_changed_during_capture")
    return "sha256:" + digest.hexdigest(), total


def read_bounded_file(path: Path, maximum_bytes: int) -> bytes:
    if type(maximum_bytes) is not int or maximum_bytes < 0:
        raise PhaseError("stream.invalid_limit")
    _reject_existing_links(path)
    before = path.stat()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise PhaseError("stream.not_regular_file")
        if fingerprint(before) != fingerprint(opened):
            raise PhaseError("freeze.source_changed_during_capture")
        if opened.st_size > maximum_bytes:
            raise PhaseError("stream.limit_exceeded")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum_bytes + 1)
        if len(data) > maximum_bytes:
            raise PhaseError("stream.limit_exceeded")
        if fingerprint(opened) != fingerprint(os.fstat(fd)) or fingerprint(opened) != fingerprint(path.stat()):
            raise PhaseError("freeze.source_changed_during_capture")
        _reject_existing_links(path)
        return data
    finally:
        os.close(fd)


def hash_file(path: Path, maximum_bytes: int) -> tuple[str, int]:
    _reject_existing_links(path)
    before = path.stat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        if fingerprint(before) != fingerprint(os.fstat(descriptor)):
            raise PhaseError("freeze.source_changed_during_capture")
        result = transfer(descriptor, maximum_bytes)
        if fingerprint(os.fstat(descriptor)) != fingerprint(path.stat()):
            raise PhaseError("freeze.source_changed_during_capture")
        return result
    finally:
        os.close(descriptor)


def copy_and_hash_stream(binding_id: str, input_root: Path, relative_locator: str,
                         blob_root: Path, *, frozen_at: str,
                         maximum_bytes: int = FILE_LIMIT):
    from .freeze import FrozenInput

    source = contained_read_path(input_root, relative_locator)
    _reject_existing_links(blob_root)
    _ensure_directory_durable(blob_root, parents=True)
    temporary: Path | None = None
    try:
        before = source.stat()
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        try:
            if fingerprint(before) != fingerprint(os.fstat(descriptor)):
                raise PhaseError("freeze.source_changed_during_capture")
            with NamedTemporaryFile(prefix="stream-", dir=blob_root, delete=False) as output:
                temporary = Path(output.name)
                digest, length = transfer(descriptor, maximum_bytes, output.fileno())
                os.fsync(output.fileno())
            if fingerprint(os.fstat(descriptor)) != fingerprint(source.stat()):
                raise PhaseError("freeze.source_changed_during_capture")
        finally:
            os.close(descriptor)
        destination = blob_root / digest.removeprefix("sha256:")
        try:
            os.link(temporary, destination)
        except FileExistsError:
            pass
        if hash_file(destination, maximum_bytes) != (digest, length):
            raise PhaseError("freeze.blob_collision")
        # The link and the data both survive successful finalization on POSIX.
        directory = os.open(blob_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return FrozenInput(binding_id, "copy_and_hash", digest, length, frozen_at,
                           blob_digest=digest, blob_path=destination,
                           relative_locator=relative_locator, streamed=True)
    finally:
        # Only this invocation's private temporary link; never the retained blob.
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def observe_target(authority, maximum_bytes: int) -> dict[str, object]:
    try:
        descriptor = authority.open_existing()
    except FileNotFoundError:
        return {"known": True, "exists": False, "digest": None, "length": None, "head_token": None}
    try:
        digest, length = transfer(descriptor, maximum_bytes)
        current = authority.open_existing()
        try:
            if fingerprint(os.fstat(descriptor)) != fingerprint(os.fstat(current)):
                raise PhaseError("path.target_identity_changed")
        finally:
            os.close(current)
        authority.assert_namespace_binding()
        return {"known": True, "exists": True, "digest": digest, "length": length, "head_token": None}
    finally:
        os.close(descriptor)
