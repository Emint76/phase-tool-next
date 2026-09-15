from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from phase_tool.application import PhaseApplication
from phase_tool.errors import PhaseError
from phase_tool.publish_file import MAX_BYTES, PublishFileResult

pytestmark = pytest.mark.skipif(os.name != "posix", reason="F01 mutation evidence requires POSIX")


def roots(tmp_path: Path) -> dict[str, Path]:
    result = {name: tmp_path / name for name in ("source", "target", "preparation", "evidence")}
    for path in result.values():
        path.mkdir()
    (result["target"] / "canary").write_bytes(b"preserve me")
    return result


def arguments(paths: dict[str, Path], *, run_id: str = "f01-cli") -> dict[str, object]:
    return {
        "source_root": paths["source"], "source_locator": "ready.zip",
        "target_root": paths["target"], "target_locator": "result.bin",
        "preparation_root": paths["preparation"], "evidence_root": paths["evidence"],
        "request_id": "f01-request", "run_id": run_id,
    }


def cli(command: str, args: dict[str, object]) -> tuple[int, dict[str, object]]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    argv = [sys.executable, "-m", "phase_tool", command]
    for name, value in args.items():
        argv.extend(["--" + name.replace("_", "-"), str(value)])
    completed = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def test_cli_publishes_binary_with_receipt_and_independent_verification(tmp_path: Path) -> None:
    paths = roots(tmp_path)
    content = bytes(range(256)) + b"\x00\xff\r\nnot a zip"
    (paths["source"] / "ready.zip").write_bytes(content)
    code, result = cli("publish-file", arguments(paths))
    assert code == 0, result
    assert result["publish_file_result_version"] == "1.0"
    assert result["contract_binding"] == "file_create.v1@1.0.0"
    assert result["contract_digest"] == "sha256:e3231b5f97bb49c499a82fd1d003ddde081c9cbe31b7b10b87435526c1e15870"
    assert result["status"] == "verified"
    assert result["target_verified"] is True
    assert result["receipt_digest"].startswith("sha256:")
    assert result["content_digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    assert result["content_length"] == len(content)
    assert (paths["target"] / "result.bin").read_bytes() == content
    assert (paths["target"] / "canary").read_bytes() == b"preserve me"
    run = paths["evidence"] / ".phase" / "runs" / "f01-cli"
    assert (run / "receipt.json").is_file()
    assert (run / "intent.json").is_file()
    assert list((run / "blobs").iterdir())
    assert list(paths["preparation"].iterdir()) == []
    assert "content" not in result


def test_real_mcp_publication_and_cross_transport_inspect(tmp_path: Path) -> None:
    paths = roots(tmp_path)
    content = b"\x00\xffMCP\r\n" + bytes(range(256))
    (paths["source"] / "ready.zip").write_bytes(content)
    cli_code, cli_result = cli("publish-file", arguments(paths))
    assert cli_code == 0, cli_result

    async def exchange() -> tuple[dict, dict]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        params = StdioServerParameters(command=sys.executable, args=["-m", "phase_tool", "mcp", "serve", "--stdio"], env=env)
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert "phase_publish_file" in {tool.name for tool in tools.tools}
                cross = await session.call_tool("phase_inspect", {
                    "evidence_root": str(paths["evidence"]), "run_id": "f01-cli",
                    "root_bindings": {"phase_result_root": str(paths["target"])},
                })
                args = arguments(paths, run_id="f01-mcp") | {"target_locator": "from-mcp.bin", "request_id": "mcp-request"}
                published = await session.call_tool("phase_publish_file", {key: str(value) for key, value in args.items()})
                assert not published.isError, published
                return cross.structuredContent, published.structuredContent

    cross, published = asyncio.run(asyncio.wait_for(exchange(), timeout=60))
    assert cross["target_verified"] is True
    assert cross["receipt_digest"] == cli_result["receipt_digest"]
    assert published["status"] == "verified", published
    assert published["content_digest"] == cli_result["content_digest"]
    code, inspected = cli("inspect", {
        "evidence_root": paths["evidence"], "run_id": "f01-mcp",
        "root": f"phase_result_root={paths['target']}",
    })
    assert code == 0, inspected
    assert inspected["target_verified"] is True
    assert inspected["receipt_digest"] == published["receipt_digest"]
    assert (paths["target"] / "from-mcp.bin").read_bytes() == content


def tree(path: Path) -> dict[str, bytes]:
    return {item.relative_to(path).as_posix(): item.read_bytes() for item in path.rglob("*") if item.is_file()}


@pytest.mark.parametrize("case", ["missing_source", "existing_target", "locator", "source_locator", "missing_root", "evidence_file", "evidence_overlap", "preparation_overlap", "source_overlap", "root_link", "source_link", "target_link", "invalid_digest", "wrong_digest", "request_id", "run_id"])
def test_refusals_preserve_target_canary_and_never_verify(tmp_path: Path, case: str) -> None:
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    args = arguments(paths)
    if case == "missing_source":
        args["source_locator"] = "missing.bin"
    elif case == "existing_target":
        (paths["target"] / "result.bin").write_bytes(b"existing")
    elif case == "locator":
        args["target_locator"] = "../outside.bin"
    elif case == "source_locator":
        args["source_locator"] = ".secret"
    elif case == "missing_root":
        args["target_root"] = tmp_path / "missing"
    elif case == "evidence_file":
        invalid = tmp_path / "evidence-file"
        invalid.write_bytes(b"not a directory")
        args["evidence_root"] = invalid
    elif case == "evidence_overlap":
        args["evidence_root"] = paths["source"] / ".." / "target" / "evidence"
    elif case == "preparation_overlap":
        args["preparation_root"] = paths["target"]
    elif case == "source_overlap":
        args["source_root"] = tmp_path
    elif case == "root_link":
        (tmp_path / "alias").symlink_to(paths["target"], target_is_directory=True)
        args["target_root"] = tmp_path / "alias"
    elif case == "source_link":
        (paths["source"] / "alias.bin").symlink_to(paths["source"] / "ready.zip")
        args["source_locator"] = "alias.bin"
    elif case == "target_link":
        (paths["target"] / "result.bin").symlink_to(paths["target"] / "canary")
    elif case == "invalid_digest":
        args["expected_digest"] = "not-a-digest"
    elif case == "wrong_digest":
        args["expected_digest"] = "sha256:" + "0" * 64
    elif case == "request_id":
        args["request_id"] = "invalid id"
    elif case == "run_id":
        args["run_id"] = "../run"
    before = tree(paths["target"])
    code, result = cli("publish-file", args)
    assert code != 0, result
    PublishFileResult.model_validate(result)
    assert result["status"] == "rejected_before_write", result
    assert result["mutation_attempted"] is False
    assert result["target_verified"] is False
    assert result["error"]
    assert tree(paths["target"]) == before
    assert not (tmp_path / "outside.bin").exists()
    assert not (paths["target"] / "evidence").exists()


@pytest.mark.parametrize("size", [0, MAX_BYTES - 1, MAX_BYTES, MAX_BYTES + 1])
def test_real_byte_boundaries(tmp_path: Path, size: int) -> None:
    paths = roots(tmp_path)
    data = b"\xff" * size
    (paths["source"] / "ready.zip").write_bytes(data)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    PublishFileResult.model_validate(result)
    if size <= MAX_BYTES:
        assert result["status"] == "verified", result
        assert (paths["target"] / "result.bin").read_bytes() == data
    else:
        assert result["status"] == "rejected_before_write", result
        assert result["error"] == "freeze.input_too_large"
        assert tree(paths["target"]) == {"canary": b"preserve me"}


def test_source_growth_at_capture_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.freeze as freeze

    paths = roots(tmp_path)
    source = paths["source"] / "ready.zip"
    source.write_bytes(b"short")
    original = freeze._read_file_stable
    def grow(path: Path, maximum_bytes: int) -> bytes:
        if path == source:
            source.write_bytes(b"a" * (MAX_BYTES + 1))
        return original(path, maximum_bytes)
    monkeypatch.setattr(freeze, "_read_file_stable", grow)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["error"] == "freeze.input_too_large", result
    assert tree(paths["target"]) == {"canary": b"preserve me"}


def test_changed_original_after_capture_is_not_consumed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.publish_file as publication

    paths = roots(tmp_path)
    source = paths["source"] / "ready.zip"
    source.write_bytes(b"captured\x00\xff")
    original = publication.copy_and_hash
    def capture(*args, **kwargs):
        frozen = original(*args, **kwargs)
        source.write_bytes(b"later bytes are not input")
        return frozen
    monkeypatch.setattr(publication, "copy_and_hash", capture)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["status"] == "verified", result
    assert (paths["target"] / "result.bin").read_bytes() == b"captured\x00\xff"


def test_corrupt_prepared_capture_rejected_before_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.publish_file as publication

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    original = publication.copy_and_hash
    def corrupt(*args, **kwargs):
        frozen = original(*args, **kwargs)
        frozen.blob_path.write_bytes(b"corrupt")
        return frozen
    monkeypatch.setattr(publication, "copy_and_hash", corrupt)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["error"] == "freeze.blob_tampered", result
    assert result["mutation_attempted"] is False
    assert tree(paths["target"]) == {"canary": b"preserve me"}


def test_repeat_request_refuses_with_inspection_without_second_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.mutation.broker as broker

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    original = broker.execute_exclusive_create
    calls = []
    def counted(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(broker, "execute_exclusive_create", counted)
    app = PhaseApplication()
    first = app.publish_file(**arguments(paths)).payload
    assert first["status"] == "verified", first
    prior_stat = (paths["target"] / "result.bin").stat()
    second = app.publish_file(**arguments(paths, run_id="repeat")).payload
    assert second["status"] == "rejected_before_write", second
    assert second["error"] == "publish_file.target_exists_inspection_required", second
    assert second["inspection_required"] is True
    assert second["mutation_attempted"] is False
    assert len(calls) == 1
    assert (paths["target"] / "result.bin").stat().st_ino == prior_stat.st_ino
    intent = json.loads((paths["evidence"] / ".phase/runs/f01-cli/intent.json").read_bytes())
    assert intent["idempotency"]["key"] == "f01-request"
    assert not (paths["evidence"] / ".phase/runs/repeat").exists()
    assert app.inspect(evidence_root=paths["evidence"], run_id="f01-cli", root_bindings={"phase_result_root": paths["target"]}).payload["target_verified"] is True
    occupied = app.publish_file(**arguments(paths)).payload
    assert occupied["status"] == "indeterminate", occupied
    assert occupied["error"] == "evidence.run_exists"
    assert occupied["run_id"] == "f01-cli"
    assert len(calls) == 1


def test_inspect_failure_after_write_preserves_execution_and_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.application as application

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    def fail(*args, **kwargs):
        raise PhaseError("inspection.injected_failure")
    monkeypatch.setattr(application, "inspect_run", fail)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["status"] == "committed_unverified", result
    assert result["success"] is False
    assert result["target_verified"] is False
    assert result["execution_disposition"] == "executed"
    assert result["mutation_attempted"] is True
    assert result["receipt_digest"] and result["intent_digest"]
    assert result["run_id"] == "f01-cli"
    assert (paths["target"] / "result.bin").read_bytes() == b"ready"


def test_compact_result_model_is_closed_and_versioned() -> None:
    from jsonschema import Draft202012Validator

    schema = PublishFileResult.model_json_schema()
    Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["publish_file_result_version"]["const"] == "1.0"


def test_preparation_cleanup_failure_preserves_already_returned_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.publish_file as publication

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    original = publication.TemporaryDirectory
    class CleanupFailure(original):
        def __exit__(self, *args):
            super().__exit__(*args)
            raise OSError("injected cleanup failure")
    monkeypatch.setattr(publication, "TemporaryDirectory", CleanupFailure)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["status"] == "committed_unverified", result
    assert result["execution_disposition"] == "executed"
    assert result["receipt_digest"] and result["intent_digest"]
    assert result["mutation_attempted"] is True
    assert result["target_verified"] is False
    assert (paths["target"] / "result.bin").read_bytes() == b"ready"
