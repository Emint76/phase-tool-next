"""RC01 streaming route: retain the explicitly versioned F01 surface."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from phase_tool.application import PhaseApplication

pytestmark = pytest.mark.skipif(os.name != "posix", reason="qualified Linux mutation required")


def test_v2_publishes_above_legacy_limit_and_cross_inspects(tmp_path: Path) -> None:
    roots = {name: tmp_path / name for name in ("source", "target", "prep", "evidence")}
    for root in roots.values():
        root.mkdir()
    data = bytes(range(256)) * 8193
    (roots["source"] / "input.bin").write_bytes(data)
    app = PhaseApplication()
    result = app.publish_file(
        source_root=roots["source"], source_locator="input.bin",
        target_root=roots["target"], target_locator="output.bin",
        preparation_root=roots["prep"], evidence_root=roots["evidence"],
        request_id="rc01-stream", run_id="rc01-stream",
        publication_version="2.0",
    ).payload
    assert result["status"] == "verified", result
    assert result["contract_binding"] == "file_create.v2@1.0.0"
    assert result["content_digest"] == "sha256:" + hashlib.sha256(data).hexdigest()
    assert (roots["target"] / "output.bin").read_bytes() == data
    inspected = app.inspect(
        evidence_root=roots["evidence"], run_id="rc01-stream",
        root_bindings={"phase_result_root": roots["target"]},
    ).payload
    assert inspected["success"] and inspected["target_verified"], inspected
    assert inspected["receipt_digest"] == result["receipt_digest"]


def test_v2_cli_and_real_mcp_share_versioned_route(tmp_path: Path) -> None:
    import asyncio
    from .test_publish_file import roots, arguments, cli
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"stream" * 200000)
    args = arguments(paths, run_id="v2-cli") | {"publication_version": "2.0"}
    code, result = cli("publish-file", args)
    assert code == 0, result

    async def exchange():
        import sys
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "phase_tool", "mcp", "serve", "--stdio"])
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                args.update(run_id="v2-mcp", request_id="v2-mcp", target_locator="from-mcp.bin")
                published = await session.call_tool("phase_publish_file", {k:str(v) for k,v in args.items()})
                assert not published.isError, published
                return published.structuredContent
    mcp = asyncio.run(exchange())
    assert mcp["status"] == "verified", mcp
    assert mcp["contract_digest"] == result["contract_digest"]
    assert mcp["content_digest"] == result["content_digest"]


def test_v2_rejects_nonregular_source_without_blocking(tmp_path: Path) -> None:
    import subprocess
    import sys
    from .test_publish_file import roots, arguments
    paths = roots(tmp_path)
    os.mkfifo(paths["source"] / "ready.zip")
    args = arguments(paths) | {"publication_version": "2.0"}
    argv = [sys.executable, "-m", "phase_tool", "publish-file"]
    for key, value in args.items():
        argv.extend(["--" + key.replace("_", "-"), str(value)])
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=5)
    assert completed.returncode == 10, completed.stdout
    assert not (paths["target"] / "result.bin").exists()


def test_v2_bounds_parallel_publications_before_capture(tmp_path: Path) -> None:
    from .test_publish_file import roots, arguments
    from phase_tool.mutation.posix.authority import PosixTargetRootLock
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"bounded")
    with PosixTargetRootLock(paths["target"], "other-worker"):
        result = PhaseApplication().publish_file(**arguments(paths), publication_version="2.0").payload
    assert result["status"] == "rejected_before_write", result
    assert result["error"] == "lock.acquire_timeout"
    assert list(paths["preparation"].iterdir()) == []
    assert list(paths["evidence"].iterdir()) == []
    assert not (paths["target"] / "result.bin").exists()


def test_v2_caps_whole_request_before_root_or_input_io(tmp_path: Path) -> None:
    from .test_publish_file import roots, arguments
    paths = roots(tmp_path)
    args = arguments(paths) | {"request_id": "a" * (1024*1024)}
    result = PhaseApplication().publish_file(**args, publication_version="2.0").payload
    assert result["error"] == "publish_file.request_too_large"
    assert result["mutation_attempted"] is False
    assert list(paths["evidence"].iterdir()) == []


@pytest.mark.parametrize("size", [0, 1048575, 1048576, 1048577, 16777217])
def test_v2_legacy_freeze_and_writer_boundaries(tmp_path: Path, size: int) -> None:
    from .test_publish_file import roots, arguments
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"x" * size)
    result = PhaseApplication().publish_file(**arguments(paths), publication_version="2.0").payload
    assert result["success"] is True, result
    assert result["content_length"] == size


def test_v2_rejects_above_new_file_limit_before_target_write(tmp_path: Path) -> None:
    from .test_publish_file import roots, arguments
    from phase_tool.streaming import FILE_LIMIT
    paths = roots(tmp_path)
    # Sparse only for the over-limit admission case, never the 1 GiB I/O gate.
    with (paths["source"] / "ready.zip").open("wb") as output:
        output.truncate(FILE_LIMIT + 1)
    result = PhaseApplication().publish_file(**arguments(paths), publication_version="2.0").payload
    assert result["error"] == "stream.limit_exceeded", result
    assert result["mutation_attempted"] is False
    assert not (paths["target"] / "result.bin").exists()


@pytest.mark.parametrize("case", ["grow", "change", "write_error", "short_write"])
def test_stream_consumption_is_bounded_and_detects_drift(tmp_path: Path, monkeypatch, case: str) -> None:
    from phase_tool import streaming
    from phase_tool.errors import PhaseError
    source = tmp_path / "input"
    source.write_bytes(b"a" * (streaming.CHUNK_BYTES + 1))
    dest = tmp_path / "output"
    read, write = os.read, os.write
    counts = []
    changed = False
    def observed_read(fd, count):
        nonlocal changed
        counts.append(count)
        block = read(fd, count)
        if not changed and case in {"grow", "change"}:
            changed = True
            with source.open("ab" if case == "grow" else "r+b") as out:
                out.write(b"b")
        return block
    def observed_write(fd, data):
        if case == "write_error":
            raise OSError(28, "injected no space")
        return write(fd, data[:7] if case == "short_write" else data)
    monkeypatch.setattr(streaming.os, "read", observed_read)
    monkeypatch.setattr(streaming.os, "write", observed_write)
    with source.open("rb") as incoming, dest.open("wb") as outgoing:
        if case == "short_write":
            digest, length = streaming.transfer(incoming.fileno(), streaming.CHUNK_BYTES+1, outgoing.fileno())
            assert length == streaming.CHUNK_BYTES+1
        else:
            with pytest.raises((PhaseError, OSError)):
                streaming.transfer(incoming.fileno(), streaming.CHUNK_BYTES+1, outgoing.fileno())
    assert max(counts) <= streaming.CHUNK_BYTES
    assert dest.stat().st_size <= streaming.CHUNK_BYTES+1


@pytest.mark.parametrize("which", ["target", "frozen_blob"])
def test_v2_inspect_detects_corruption(tmp_path: Path, which: str) -> None:
    from .test_publish_file import roots, arguments
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"b" * 1048577)
    app = PhaseApplication()
    result = app.publish_file(**arguments(paths), publication_version="2.0").payload
    assert result["success"], result
    path = paths["target"] / "result.bin" if which == "target" else paths["evidence"] / ".phase/runs/f01-cli/blobs" / result["content_digest"].split(":")[1]
    with path.open("r+b") as output:
        output.write(b"c")
    inspected = app.inspect(evidence_root=paths["evidence"], run_id="f01-cli", root_bindings={"phase_result_root":paths["target"]}).payload
    assert inspected["success"] is False, inspected


def test_v2_close_failure_after_effect_never_reports_no_mutation(tmp_path: Path, monkeypatch) -> None:
    from .test_publish_file import roots, arguments
    from phase_tool.mutation.posix.authority import PosixTargetAuthority
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"written")
    original = PosixTargetAuthority.close
    fired = False
    def fail_close(authority):
        nonlocal fired
        written = authority.target == paths["target"] / "result.bin" and authority.target.exists()
        original(authority)
        if written and not fired:
            fired = True
            raise OSError("injected post-effect close failure")
    monkeypatch.setattr(PosixTargetAuthority, "close", fail_close)
    result = PhaseApplication().publish_file(**arguments(paths), publication_version="2.0").payload
    assert fired
    assert (paths["target"] / "result.bin").read_bytes() == b"written"
    assert result["success"] is False, result
    assert result["mutation_attempted"] is not False, result
    assert result["status"] in {"indeterminate", "committed_unverified"}, result


def test_v2_enospc_after_target_creation_retains_honest_partial_state(tmp_path: Path, monkeypatch) -> None:
    from .test_publish_file import roots, arguments
    from phase_tool import streaming
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready payload")
    destination = paths["target"] / "result.bin"
    write = os.write
    attempted = False
    def limited_write(fd, data):
        nonlocal attempted
        if destination.exists():
            opened, target = os.fstat(fd), destination.stat()
            if (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino):
                if attempted:
                    raise OSError(28, "injected no space")
                attempted = True
                return write(fd, data[:1])
        return write(fd, data)
    monkeypatch.setattr(streaming.os, "write", limited_write)
    result = PhaseApplication().publish_file(**arguments(paths), publication_version="2.0").payload
    assert attempted and destination.read_bytes() == b"r"
    assert result["status"] == "indeterminate", result
    assert result["mutation_attempted"] is True
    assert result["inspection_required"] is True
    assert not result["success"] and not result["target_verified"]


def test_v2_precreate_observation_error_returns_valid_honest_result(tmp_path: Path, monkeypatch) -> None:
    from .test_publish_file import roots, arguments
    from phase_tool.mutation import stream_create
    from phase_tool.errors import PhaseError
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    def unavailable(*args, **kwargs):
        raise PhaseError("stream.limit_exceeded")
    monkeypatch.setattr(stream_create, "observe_target", unavailable)
    result = PhaseApplication().publish_file(**arguments(paths), publication_version="2.0").payload
    assert not result["success"]
    assert result["inspection_required"]
    assert result["status"] == "indeterminate", result
    assert not (paths["target"] / "result.bin").exists()
