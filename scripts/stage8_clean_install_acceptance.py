from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv as venv_module
import zipfile
from pathlib import Path
from typing import Any

NOW = "2026-07-30T12:00:00Z"


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], *, cwd: Path, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(command, cwd=cwd, env=environment, input=input_text, capture_output=True, text=True, check=False, timeout=300)
    if check and completed.returncode != 0:
        raise AssertionError(f"command failed: {command!r} rc={completed.returncode} stdout={completed.stdout!r} stderr={completed.stderr!r}")
    return completed


def tool_payload(result: object) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    return json.loads(getattr(result, "content")[0].text)


async def mcp_installed_acceptance(
    server: Path,
    *,
    cwd: Path,
    candidate: dict[str, Any],
    payload: Path,
    target: Path,
    evidence: Path,
) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    parameters = StdioServerParameters(command=str(server), args=[], cwd=str(cwd), env=environment)
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = sorted(tool.name for tool in tools.tools)
            schemas_strict = all(tool.inputSchema.get("additionalProperties") is False for tool in tools.tools)
            extra = await session.call_tool("phase_execute", {
                "contract_binding": "fixture_create.v1@1.0.0", "candidate": candidate,
                "evidence_root": str(evidence), "run_id": "clean-wheel-extra", "unknown": True,
            })
            boolean_integer = await session.call_tool("phase_execute", {
                "contract_binding": "fixture_create.v1@1.0.0", "candidate": candidate,
                "evidence_root": str(evidence), "run_id": "clean-wheel-bool",
                "maximum_candidate_bytes": True,
            })
            application_rejection = tool_payload(await session.call_tool("phase_execute", {
                "contract_binding": "missing.v1@1.0.0", "candidate": candidate,
                "evidence_root": str(evidence), "run_id": "clean-wheel-missing-contract",
            }))
            listed_after_rejections = tool_payload(await session.call_tool("phase_contracts_list", {}))
            executed = tool_payload(await session.call_tool("phase_execute", {
                "contract_binding": "fixture_create.v1@1.0.0", "candidate": candidate,
                "evidence_root": str(evidence), "run_id": "clean-wheel-mcp",
                "input_paths": {"payload": str(payload)},
                "root_bindings": {"fixture_result_root": str(target)}, "timestamp": NOW,
            }))
            inspected = tool_payload(await session.call_tool("phase_inspect", {
                "evidence_root": str(evidence), "run_id": "clean-wheel-mcp",
                "root_bindings": {"fixture_result_root": str(target)},
            }))
            return {
                "tool_names": names,
                "tool_inventory": names == [
                    "phase_contract_describe", "phase_contracts_list", "phase_execute",
                    "phase_inspect", "phase_plan", "phase_publish_file", "phase_validate",
                ],
                "schemas_strict": schemas_strict,
                "protocol_rejections": extra.isError is True and boolean_integer.isError is True,
                "application_rejection": application_rejection.get("error") == "application.contract_binding_not_found",
                "survived_rejections": bool(listed_after_rejections.get("contracts")),
                "execute_inspect": executed.get("terminal_status") == "succeeded_verified" and inspected.get("target_verified") is True,
            }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    allowed = (repository / ".stage8-tmp").resolve()
    output = args.output_root.resolve()
    if output == allowed or allowed not in output.parents:
        raise AssertionError("--output-root must be a child of repository .stage8-tmp")
    if output.exists():
        shutil.rmtree(output)
    dist = output / "dist"
    dist.mkdir(parents=True)
    external = Path(tempfile.mkdtemp(prefix="phase-stage8-clean-"))
    summary: dict[str, Any] = {}
    try:
        source = external / "source"
        (source / "src").mkdir(parents=True)
        for filename in ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in"):
            shutil.copy2(repository / filename, source / filename)
        shutil.copytree(repository / "docs", source / "docs")
        shutil.copytree(repository / "src" / "phase_tool", source / "src" / "phase_tool")
        build = run([sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(dist)], cwd=source)
        wheels = list(dist.glob("*.whl"))
        sdists = list(dist.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise AssertionError(f"unexpected distributions: {wheels!r} {sdists!r}")
        wheel, sdist = wheels[0], sdists[0]
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            required_suffixes = {
                "phase_tool/application.py",
                "phase_tool/mcp_server.py",
                "phase_tool/data/registry.json",
            }
            for suffix in required_suffixes:
                if not any(name.endswith(suffix) for name in names):
                    raise AssertionError(f"wheel missing {suffix}")
            entrypoint_name = next(name for name in names if name.endswith(".dist-info/entry_points.txt"))
            entrypoints = archive.read(entrypoint_name).decode("utf-8")
            if "phase = phase_tool.cli.main:main" not in entrypoints or "phase-mcp = phase_tool.mcp_server:main" not in entrypoints:
                raise AssertionError(entrypoints)

        venv = external / "venv"
        venv_module.EnvBuilder(with_pip=True).create(venv)
        python = venv / "Scripts" / "python.exe" if os.name == "nt" else venv / "bin" / "python"
        scripts = python.parent
        phase = scripts / ("phase.exe" if os.name == "nt" else "phase")
        phase_mcp = scripts / ("phase-mcp.exe" if os.name == "nt" else "phase-mcp")
        run([str(python), "-m", "pip", "install", str(wheel)], cwd=external)

        metadata = json.loads(run([str(python), "-c", "import importlib.metadata as m,json; d=m.distribution('phase-tool'); f=next((f for f in (d.files or []) if str(f).endswith('direct_url.json')),None); u=json.loads(d.locate_file(f).read_text()) if f else {}; print(json.dumps({'root':str(d.locate_file('')),'editable':bool(u.get('dir_info',{}).get('editable',False))}))"], cwd=external).stdout)
        imported = run([str(python), "-c", "import phase_tool; print(phase_tool.__version__)"], cwd=external).stdout.strip()
        help_result = run([str(phase), "--help"], cwd=external)
        version = run([str(phase), "--version"], cwd=external).stdout.strip()
        doctor = json.loads(run([str(phase), "doctor"], cwd=external).stdout)
        contracts = json.loads(run([str(phase), "contracts", "list"], cwd=external).stdout)
        unknown_option = run([str(phase), "doctor", "--unknown"], cwd=external, check=False)
        missing_arguments = run([str(phase), "execute"], cwd=external, check=False)
        unknown_contract = run([
            str(phase), "execute", "--contract", "missing.v1@1.0.0", "--candidate", str(external / "missing.json"),
            "--evidence-root", str(external / "rejected-evidence"), "--run-id", "clean-wheel-rejected",
        ], cwd=external, check=False)
        unknown_contract_payload = json.loads(unknown_contract.stdout)

        payload = external / "fixture.bin"
        payload.write_bytes(b"clean wheel fixture payload")
        candidate = external / "candidate.json"
        candidate_value = {
            "idempotency_key": "clean-wheel-cli-key",
            "input_binding": "payload",
            "operation_id": "clean-wheel-cli-operation",
            "target_locator": "objects/clean-wheel-cli.bin",
        }
        candidate.write_text(json.dumps(candidate_value), encoding="utf-8")
        target = external / "target"
        target.mkdir()
        evidence = external / "evidence"
        validate = json.loads(run([
            str(phase), "validate", "--contract", "fixture_create.v1@1.0.0", "--candidate", str(candidate),
            "--evidence-root", str(evidence), "--run-id", "clean-wheel-validate", "--input", f"payload={payload}",
            "--root", f"fixture_result_root={target}", "--timestamp", NOW,
        ], cwd=external).stdout)
        plan = json.loads(run([
            str(phase), "plan", "--contract", "fixture_create.v1@1.0.0", "--candidate", str(candidate),
            "--evidence-root", str(evidence), "--run-id", "clean-wheel-plan", "--input", f"payload={payload}",
            "--root", f"fixture_result_root={target}", "--timestamp", NOW,
        ], cwd=external).stdout)
        execute = json.loads(run([
            str(phase), "execute", "--contract", "fixture_create.v1@1.0.0", "--candidate", str(candidate),
            "--evidence-root", str(evidence), "--run-id", "clean-wheel-cli", "--input", f"payload={payload}",
            "--root", f"fixture_result_root={target}", "--timestamp", NOW,
        ], cwd=external).stdout)
        inspect = json.loads(run([
            str(phase), "inspect", "--evidence-root", str(evidence), "--run-id", "clean-wheel-cli",
            "--root", f"fixture_result_root={target}",
        ], cwd=external).stdout)

        mcp_candidate = {
            "idempotency_key": "clean-wheel-mcp-key",
            "input_binding": "payload",
            "operation_id": "clean-wheel-mcp-operation",
            "target_locator": "objects/clean-wheel-mcp.bin",
        }
        mcp_acceptance = asyncio.run(mcp_installed_acceptance(
            phase_mcp, cwd=external, candidate=mcp_candidate, payload=payload,
            target=target, evidence=evidence,
        ))

        run([str(python), "-m", "pip", "uninstall", "--yes", "phase-tool"], cwd=external)
        absent = run([str(python), "-c", "import phase_tool"], cwd=external, check=False)
        uninstall_verified = absent.returncode != 0
        run([str(python), "-m", "pip", "install", str(wheel)], cwd=external)
        reinstall_verified = run([str(phase), "--version"], cwd=external).stdout.strip() == "phase 1.0.0"

        summary = {
            "success": True,
            "wheel": {"name": wheel.name, "sha256": sha256(wheel), "entries": len(names)},
            "sdist": {"name": sdist.name, "sha256": sha256(sdist)},
            "build_stdout_lines": len(build.stdout.splitlines()),
            "installed_outside_checkout": repository.resolve() not in Path(metadata["root"]).resolve().parents,
            "editable_install": metadata["editable"],
            "pythonpath_present": "PYTHONPATH" in os.environ and bool(os.environ.get("PYTHONPATH")),
            "import_version": imported,
            "help_discovery": help_result.returncode == 0 and "contracts" in help_result.stdout and "execute" in help_result.stdout,
            "version": version,
            "doctor": doctor,
            "contracts": {"count": len(contracts["contracts"])},
            "cli_parse_rejections": unknown_option.returncode == 2 and missing_arguments.returncode == 2 and not unknown_option.stdout and not missing_arguments.stdout,
            "cli_application_rejection": unknown_contract.returncode == 10 and unknown_contract_payload.get("error") == "application.contract_binding_not_found",
            "cli_validate_plan_execute_inspect": validate["terminal_status"] == "validated_planned" and plan["terminal_status"] == "validated_planned" and execute["terminal_status"] == "succeeded_verified" and inspect["target_verified"] is True,
            "mcp": mcp_acceptance,
            "uninstall_verified": uninstall_verified,
            "reinstall_verified": reinstall_verified,
        }
        summary["success"] = all([
            summary["installed_outside_checkout"], not summary["editable_install"], not summary["pythonpath_present"],
            imported == "1.0.0", summary["help_discovery"], doctor["success"], summary["cli_parse_rejections"],
            summary["cli_application_rejection"], summary["cli_validate_plan_execute_inspect"], all(mcp_acceptance.values()),
            uninstall_verified, reinstall_verified,
        ])
    finally:
        shutil.rmtree(external, ignore_errors=True)

    (output / "clean-install-summary.json").write_text(json.dumps(summary, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if summary.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
