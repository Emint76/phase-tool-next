"""Installed-wheel F01 acceptance. Run outside the checkout with its venv Python."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    import phase_tool
    from phase_tool.publish_file import PublishFileResult

    installed = Path(phase_tool.__file__).resolve()
    assert installed.is_relative_to(Path(sys.prefix).resolve()), installed
    distribution = metadata.distribution("phase-tool")
    direct_url = json.loads(distribution.read_text("direct_url.json") or "{}")
    assert not direct_url.get("dir_info", {}).get("editable", False), direct_url
    phase = Path(sys.executable).parent / "phase"
    phase_mcp = Path(sys.executable).parent / "phase-mcp"
    assert phase.is_file() and phase_mcp.is_file()
    paths = {name: root / name for name in ("source", "target", "preparation", "evidence")}
    for path in paths.values():
        path.mkdir()
    content = bytes(range(256)) + b"\x00\xff\r\nnot-an-archive"
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    (paths["source"] / "ready.zip").write_bytes(content)
    (paths["target"] / "canary").write_bytes(b"preserved")
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    records: dict[str, object] = {}

    def invoke(name: str, command: str, parameters: dict[str, object], expected_code: int = 0) -> dict:
        argv = [str(phase), command]
        for key, value in parameters.items():
            argv.extend(["--" + key.replace("_", "-"), str(value)])
        completed = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True, timeout=60)
        records[name] = {"argv": argv, "exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
        assert completed.returncode == expected_code, records[name]
        result = json.loads(completed.stdout)
        if command == "publish-file":
            PublishFileResult.model_validate(result)
        return result

    publication = {
        "source_root": paths["source"], "source_locator": "ready.zip",
        "target_root": paths["target"], "target_locator": "from-cli.bin",
        "preparation_root": paths["preparation"], "evidence_root": paths["evidence"],
        "request_id": "installed-cli", "run_id": "installed-cli",
        "expected_digest": digest,
    }
    cli = invoke("cli_publish", "publish-file", publication)
    assert cli["status"] == "verified" and cli["target_verified"] is True
    assert cli["content_digest"] == digest and cli["content_length"] == len(content)
    assert (paths["target"] / "from-cli.bin").read_bytes() == content

    async def exchange() -> dict:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        parameters = StdioServerParameters(command=str(phase_mcp), cwd=str(root), env=env)
        with (root / "mcp-stderr.log").open("w", encoding="utf-8") as stderr:
            async with stdio_client(parameters, errlog=stderr) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    tool = next(item for item in tools.tools if item.name == "phase_publish_file")
                    assert tool.inputSchema["additionalProperties"] is False
                    assert tool.outputSchema["additionalProperties"] is False
                    records["mcp_publish_schema"] = tool.model_dump(mode="json")
                    inspected = await session.call_tool("phase_inspect", {
                        "evidence_root": str(paths["evidence"]), "run_id": "installed-cli",
                        "root_bindings": {"phase_result_root": str(paths["target"])},
                    })
                    assert not inspected.isError, inspected
                    inspection = inspected.structuredContent
                    records["mcp_inspect_cli"] = inspection
                    assert inspection["target_verified"] is True
                    assert inspection["receipt_digest"] == cli["receipt_digest"]
                    mcp_args = {key: str(value) for key, value in publication.items()}
                    mcp_args.update(target_locator="from-mcp.bin", request_id="installed-mcp", run_id="installed-mcp")
                    response = await session.call_tool("phase_publish_file", mcp_args)
                    assert not response.isError, response
                    result = response.structuredContent
                    PublishFileResult.model_validate(result)
                    records["mcp_publish"] = result
                    assert result["status"] == "verified" and result["target_verified"] is True
                    assert result["content_digest"] == digest
                    return result

    mcp = asyncio.run(asyncio.wait_for(exchange(), timeout=90))
    assert (paths["target"] / "from-mcp.bin").read_bytes() == content
    inspected = invoke("cli_inspect_mcp", "inspect", {
        "evidence_root": paths["evidence"], "run_id": "installed-mcp",
        "root": f"phase_result_root={paths['target']}",
    })
    assert inspected["target_verified"] is True and inspected["receipt_digest"] == mcp["receipt_digest"]
    repeat = invoke("repeat_refusal", "publish-file", publication | {"run_id": "repeat"}, expected_code=10)
    assert repeat["error"] == "publish_file.target_exists_inspection_required"
    assert repeat["inspection_required"] is True and repeat["mutation_attempted"] is False
    missing = invoke("missing_refusal", "publish-file", publication | {"source_locator": "missing.bin", "run_id": "missing"}, expected_code=10)
    assert missing["status"] == "rejected_before_write" and missing["target_verified"] is False
    assert (paths["target"] / "canary").read_bytes() == b"preserved"
    assert sorted(item.name for item in paths["target"].iterdir()) == ["canary", "from-cli.bin", "from-mcp.bin"]
    assert list(paths["preparation"].iterdir()) == []
    summary = {
        "success": True, "installed_module": str(installed), "python": sys.executable,
        "cli_entrypoint": str(phase), "mcp_entrypoint": str(phase_mcp),
        "content_digest": digest, "content_length": len(content),
        "cli_receipt": cli["receipt_digest"], "mcp_receipt": mcp["receipt_digest"],
        "cross_inspect": True, "repeat_refusal": True, "records": records,
    }
    with (root / "summary.json").open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
    print(json.dumps({key: value for key, value in summary.items() if key != "records"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
