from __future__ import annotations

import ast
import asyncio
import json
import os
import subprocess
import sys
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from phase_tool.application import PhaseApplication
from scripts.stage8_integrity_audit import generation_errors

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-07-30T12:00:00Z"


def test_application_discovers_and_describes_exact_contracts_from_registry() -> None:
    application = PhaseApplication()

    listed = application.contracts_list()
    bindings = [item["contract_binding"] for item in listed.payload["contracts"]]

    assert listed.exit_code == 0
    assert bindings == sorted(bindings)
    assert "fixture_create.v1@1.0.0" in bindings
    assert "source_admission.v1@1.0.0" in bindings
    assert "knowledge_admission.v1@1.0.0" in bindings

    described = application.contract_describe("fixture_create.v1@1.0.0")
    assert described.exit_code == 0
    assert described.payload["contract_binding"] == "fixture_create.v1@1.0.0"
    assert described.payload["contract"]["identity"] == {"id": "fixture_create.v1", "version": "1.0.0", "core_compatibility": {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"}}
    assert described.payload["package_digest"].startswith("sha256:")
    assert described.payload["package_artifacts"]


def _phase(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-m", "phase_tool", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )


def test_product_cli_reports_version_health_and_registry_contracts() -> None:
    version = _phase("--version")
    assert version.returncode == 0
    assert version.stdout.strip() == "phase 1.0.0"
    assert version.stderr == ""

    doctor = _phase("doctor")
    assert doctor.returncode == 0, doctor.stderr
    health = json.loads(doctor.stdout)
    assert health["success"] is True
    assert health["version"] == "1.0.0"
    assert health["registry"]["contract_count"] >= 6
    assert health["mcp_sdk"]["compatible"] is True

    listed = _phase("contracts", "list")
    assert listed.returncode == 0, listed.stderr
    contracts = json.loads(listed.stdout)
    assert any(item["contract_binding"] == "fixture_create.v1@1.0.0" for item in contracts["contracts"])

    described = _phase("contracts", "describe", "--contract", "fixture_create.v1@1.0.0")
    assert described.returncode == 0, described.stderr
    description = json.loads(described.stdout)
    assert description["contract"]["identity"]["id"] == "fixture_create.v1"


def test_fixture_contract_executes_through_universal_cli_exact_registry_binding(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps({
        "idempotency_key": "stage8-fixture-key",
        "input_binding": "payload",
        "operation_id": "stage8-fixture-operation",
        "target_locator": "objects/stage8.bin",
    }), encoding="utf-8")
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"stage8 fixture payload")
    target = tmp_path / "target"
    (target / "objects").mkdir(parents=True)
    evidence = tmp_path / "evidence"

    executed = _phase(
        "execute",
        "--contract", "fixture_create.v1@1.0.0",
        "--candidate", str(candidate),
        "--evidence-root", str(evidence),
        "--run-id", "stage8-fixture-cli",
        "--input", f"payload={payload}",
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    )

    assert executed.returncode == 0, executed.stderr
    result = json.loads(executed.stdout)
    assert result["terminal_status"] == "succeeded_verified"
    assert result["mutation_attempted"] is True
    assert (target / "objects" / "stage8.bin").read_bytes() == b"stage8 fixture payload"

    inspected = _phase(
        "inspect",
        "--evidence-root", str(evidence),
        "--run-id", "stage8-fixture-cli",
        "--root", f"fixture_result_root={target}",
    )
    assert inspected.returncode == 0, inspected.stderr
    assert json.loads(inspected.stdout)["target_verified"] is True


def _tool_payload(result: object) -> dict[str, object]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content")
    return json.loads(content[0].text)


def test_real_mcp_stdio_discovers_and_executes_fixture_through_universal_tool(tmp_path: Path) -> None:
    candidate = {
        "idempotency_key": "stage8-mcp-fixture-key",
        "input_binding": "payload",
        "operation_id": "stage8-mcp-fixture-operation",
        "target_locator": "objects/stage8-mcp.bin",
    }
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"stage8 mcp fixture payload")
    target = tmp_path / "target"
    (target / "objects").mkdir(parents=True)
    evidence = tmp_path / "evidence"

    async def exchange() -> tuple[list[str], dict[str, object], dict[str, object]]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "phase_tool.mcp_server"],
            cwd=str(ROOT),
            env=environment,
        )
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = sorted(tool.name for tool in tools.tools)
                executed = await session.call_tool("phase_execute", {
                    "contract_binding": "fixture_create.v1@1.0.0",
                    "candidate": candidate,
                    "evidence_root": str(evidence),
                    "run_id": "stage8-fixture-mcp",
                    "input_paths": {"payload": str(payload)},
                    "root_bindings": {"fixture_result_root": str(target)},
                    "timestamp": NOW,
                })
                inspected = await session.call_tool("phase_inspect", {
                    "evidence_root": str(evidence),
                    "run_id": "stage8-fixture-mcp",
                    "root_bindings": {"fixture_result_root": str(target)},
                })
                return names, _tool_payload(executed), _tool_payload(inspected)

    names, executed, inspected = asyncio.run(exchange())

    assert names == [
        "phase_contract_describe",
        "phase_contracts_list",
        "phase_execute",
        "phase_inspect",
        "phase_plan",
        "phase_validate",
    ]
    assert "phase_source_admit" not in names
    assert "phase_knowledge_admit" not in names
    assert executed["terminal_status"] == "succeeded_verified"
    assert executed["mutation_attempted"] is True
    assert inspected["target_verified"] is True
    assert (target / "objects" / "stage8-mcp.bin").read_bytes() == b"stage8 mcp fixture payload"


def test_phase_mcp_cli_surface_is_thin_stdio_equivalent() -> None:
    async def exchange() -> list[str]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "phase_tool", "mcp", "serve", "--stdio"],
            cwd=str(ROOT),
            env=environment,
        )
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = await session.list_tools()
                return sorted(tool.name for tool in tools.tools)

    assert asyncio.run(exchange()) == [
        "phase_contract_describe",
        "phase_contracts_list",
        "phase_execute",
        "phase_inspect",
        "phase_plan",
        "phase_validate",
    ]


def test_cli_mcp_and_application_are_contract_agnostic_thin_adapters() -> None:
    cli_source = (ROOT / "src" / "phase_tool" / "cli" / "main.py").read_text(encoding="utf-8")
    mcp_source = (ROOT / "src" / "phase_tool" / "mcp_server.py").read_text(encoding="utf-8")
    application_source = (ROOT / "src" / "phase_tool" / "application.py").read_text(encoding="utf-8")

    for source in (cli_source, mcp_source, application_source):
        assert "source_admission" not in source
        assert "knowledge_admission" not in source
    assert "PhaseCore" not in cli_source
    assert "PhaseCore" not in mcp_source
    assert "PhaseCore(self.registry, self.installation).run(" in application_source
    assert application_source.count("PhaseCore(") == 1

    mcp_tree = ast.parse(mcp_source)
    tool_names = {
        decorator.keywords[0].value.value
        for node in ast.walk(mcp_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "tool"
        and decorator.keywords
        and isinstance(decorator.keywords[0].value, ast.Constant)
    }
    assert tool_names == {
        "phase_contracts_list",
        "phase_contract_describe",
        "phase_validate",
        "phase_plan",
        "phase_execute",
        "phase_inspect",
    }


def test_stage8_real_cli_mcp_source_knowledge_equivalence_acceptance() -> None:
    root = ROOT / ".stage8-tmp" / "product-acceptance-test"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "stage8_product_acceptance.py"),
            "--tmp-root", str(root),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads((root / "stage8-product-acceptance-summary.json").read_text(encoding="utf-8"))
    assert summary["success"] is True
    assert summary["scenario_count"] == 8
    assert summary["cli"]["source"]["terminal_status"] == "succeeded_verified"
    assert summary["cli"]["knowledge"]["terminal_status"] == "succeeded_verified"
    assert summary["mcp"]["source"]["terminal_status"] == "succeeded_verified"
    assert summary["mcp"]["knowledge"]["terminal_status"] == "succeeded_verified"
    assert summary["equivalence"]["source_result_id"] is True
    assert summary["equivalence"]["knowledge_result_id"] is True
    assert summary["equivalence"]["canonical_artifact_digest"] is True
    assert summary["equivalence"]["inspection_semantics"] is True


def test_cli_and_mcp_share_transport_independent_error_model(tmp_path: Path) -> None:
    candidate_value = {
        "idempotency_key": "stage8-error-key",
        "input_binding": "payload",
        "operation_id": "stage8-error-operation",
        "target_locator": "objects/error.bin",
    }
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps(candidate_value), encoding="utf-8")
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"error model payload")
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"

    cli_result = _phase(
        "execute", "--contract", "missing.v1@1.0.0",
        "--candidate", str(candidate), "--evidence-root", str(evidence),
        "--run-id", "error-cli", "--input", f"payload={payload}",
        "--root", f"fixture_result_root={target}", "--timestamp", NOW,
    )
    cli_payload = json.loads(cli_result.stdout)

    async def exchange() -> dict[str, object]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "phase_tool.mcp_server"], cwd=str(ROOT), env=environment)
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                result = await session.call_tool("phase_execute", {
                    "contract_binding": "missing.v1@1.0.0",
                    "candidate": candidate_value,
                    "evidence_root": str(evidence),
                    "run_id": "error-mcp",
                    "input_paths": {"payload": str(payload)},
                    "root_bindings": {"fixture_result_root": str(target)},
                    "timestamp": NOW,
                })
                return _tool_payload(result)

    mcp_payload = asyncio.run(exchange())
    assert cli_result.returncode == 10
    for key in ("success", "error", "blockers", "exit_code", "mutation_attempted", "terminal_status", "execution_disposition"):
        assert cli_payload[key] == mcp_payload[key]
    assert cli_payload["error"] == "application.contract_binding_not_found"


def test_mcp_stdio_stdout_contains_protocol_json_only_and_diagnostics_use_stderr() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "stage8-purity", "version": "1.0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]

    async def exchange() -> tuple[int, str, str]:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "phase_tool.mcp_server",
            cwd=ROOT,
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        responses: list[bytes] = []
        for message in messages:
            process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
            await process.stdin.drain()
            if "id" in message:
                responses.append(await asyncio.wait_for(process.stdout.readline(), timeout=60))
        process.stdin.close()
        await process.stdin.wait_closed()
        remaining_stdout, stderr = await asyncio.wait_for(
            asyncio.gather(process.stdout.read(), process.stderr.read()),
            timeout=60,
        )
        returncode = await asyncio.wait_for(process.wait(), timeout=60)
        return returncode, b"".join(responses + [remaining_stdout]).decode("utf-8"), stderr.decode("utf-8")

    returncode, stdout, stderr = asyncio.run(exchange())
    assert returncode == 0, stderr
    protocol = [json.loads(line) for line in stdout.splitlines() if line]
    assert [message["id"] for message in protocol] == [1, 2]
    assert all(message["jsonrpc"] == "2.0" for message in protocol)
    assert "Processing request" not in stdout
    assert "Processing request" in stderr


def test_publication_metadata_documentation_and_linux_ci_are_complete() -> None:
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "1.0.0"
    assert project["readme"] == "README.md"
    assert project["license"]["file"] == "LICENSE"
    assert project["scripts"] == {
        "phase": "phase_tool.cli.main:main",
        "phase-mcp": "phase_tool.mcp_server:main",
    }
    assert "mcp>=1.26,<2" in project["dependencies"]
    assert all("<" in dependency for dependency in project["dependencies"])

    required = [
        ROOT / "README.md",
        ROOT / "LICENSE",
        ROOT / "docs" / "CLI-REFERENCE.md",
        ROOT / "docs" / "MCP-SETUP.md",
        ROOT / "docs" / "STAGE-8-EXAMPLES.md",
        ROOT / "docs" / "TROUBLESHOOTING.md",
        ROOT / ".github" / "workflows" / "ci.yml",
    ]
    for path in required:
        assert path.is_file(), path
    combined = "\n".join(path.read_text(encoding="utf-8") for path in required if path.suffix == ".md")
    for command in ("phase --version", "phase doctor", "phase contracts list", "phase mcp serve --stdio", "phase-mcp"):
        assert command in combined
    assert "source_admission.v1@1.0.0" in combined
    assert "knowledge_admission.v1@1.0.0" in combined
    workflow = required[-1].read_text(encoding="utf-8")
    assert "windows-latest" not in workflow
    assert "ubuntu-latest" in workflow


def test_wheel_sdist_clean_install_uninstall_reinstall_acceptance() -> None:
    root = ROOT / ".stage8-tmp" / "clean-install-acceptance"
    build_root = ROOT / "build"
    build_before = (
        build_root.exists(),
        {
            path.relative_to(build_root).as_posix(): path.read_bytes()
            for path in build_root.rglob("*") if path.is_file()
        },
    )
    egg_info = ROOT / "src" / "phase_tool.egg-info"
    protected_before = {
        path.relative_to(egg_info).as_posix(): path.read_bytes()
        for path in egg_info.rglob("*") if path.is_file()
    }
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage8_clean_install_acceptance.py"), "--output-root", str(root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
        timeout=600,
    )

    assert completed.returncode == 0, completed.stderr
    protected_after = {
        path.relative_to(egg_info).as_posix(): path.read_bytes()
        for path in egg_info.rglob("*") if path.is_file()
    }
    assert protected_after == protected_before
    build_after = (
        build_root.exists(),
        {
            path.relative_to(build_root).as_posix(): path.read_bytes()
            for path in build_root.rglob("*") if path.is_file()
        },
    )
    assert build_after == build_before
    summary = json.loads((root / "clean-install-summary.json").read_text(encoding="utf-8"))
    assert summary["success"] is True
    assert summary["wheel"]["sha256"].startswith("sha256:")
    assert summary["sdist"]["sha256"].startswith("sha256:")
    assert summary["installed_outside_checkout"] is True
    assert summary["editable_install"] is False
    assert summary["pythonpath_present"] is False
    assert summary["version"] == "phase 1.0.0"
    assert summary["doctor"]["success"] is True
    assert summary["contracts"]["count"] >= 6
    assert summary["cli_execute_inspect"] is True
    assert summary["phase_mcp_execute_inspect"] is True
    assert summary["uninstall_verified"] is True
    assert summary["reinstall_verified"] is True


def test_documented_commands_and_links_smoke() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage8_docs_smoke.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["success"] is True
    assert summary["commands"] == 9
    assert summary["links_checked"] >= 5


def test_integrity_audit_rejects_zero_and_multiple_current_generations() -> None:
    entries = json.loads((ROOT / "src" / "phase_tool" / "data" / "registry.json").read_text(encoding="utf-8"))["entries"]
    assert generation_errors(entries) == []

    zero_current = deepcopy(entries)
    for entry in zero_current:
        if entry.get("kind") == "contract" and entry.get("id") == "fixture_copy.v1":
            entry["current"] = False
    assert generation_errors(zero_current)

    multiple_current = deepcopy(entries)
    for entry in multiple_current:
        if entry.get("kind") == "schema" and entry.get("schema_ref") == "https://phase-tool.local/schemas/phase-receipt.schema.json":
            entry["current"] = True
    assert generation_errors(multiple_current)


def test_package_schema_registry_manifest_and_wheel_integrity_audit() -> None:
    wheel = next((ROOT / ".stage8-tmp" / "clean-install-acceptance" / "dist").glob("*.whl"))
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage8_integrity_audit.py"), "--wheel", str(wheel)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["success"] is True
    assert summary["registry_entries"] >= 64
    assert summary["contract_bindings"] >= 6
    assert summary["package_artifacts"] >= 27
    assert summary["schemas_checked"] >= 19
    assert summary["manifest_entries"] >= 60
    assert summary["wheel_entries"] >= summary["package_artifacts"]
    assert summary["errors"] == []
    with zipfile.ZipFile(wheel) as archive:
        wheel_entries = set(archive.namelist())
    assert "phase_tool/mutation/unsupported.py" in wheel_entries
    assert not any(name.startswith("phase_tool/mutation/windows/") for name in wheel_entries)
    assert "phase_tool/data/descriptors/guarantee/phase.windows.authority.v1.json" not in wheel_entries


def test_contract_describe_unknown_binding_has_same_cli_mcp_error_envelope() -> None:
    cli = _phase("contracts", "describe", "--contract", "missing.v1@1.0.0")

    async def exchange() -> dict[str, object]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "phase_tool.mcp_server"], cwd=str(ROOT), env=environment)
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                return _tool_payload(await session.call_tool("phase_contract_describe", {"contract_binding": "missing.v1@1.0.0"}))

    mcp_payload = asyncio.run(exchange())
    assert cli.returncode == 10
    cli_payload = json.loads(cli.stdout)
    assert cli.stderr == ""
    assert cli_payload == mcp_payload
    assert cli_payload == {
        "success": False,
        "error": "application.contract_binding_not_found",
        "blockers": ["application.contract_binding_not_found"],
        "exit_code": 10,
    }


def test_structured_candidate_size_limit_is_checked_before_temp_materialization(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import phase_tool.application as application_module

    called = False

    def forbidden_materialization(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("oversized candidate reached temporary materialization")

    monkeypatch.setattr(application_module, "NamedTemporaryFile", forbidden_materialization)
    response = PhaseApplication().run(
        "execute",
        contract_binding="fixture_create.v1@1.0.0",
        candidate={"payload": "x" * 128},
        evidence_root=tmp_path / "evidence",
        run_id="oversized-mcp-candidate",
        input_paths={},
        root_bindings={},
        maximum_candidate_bytes=32,
    )

    assert called is False
    assert response.exit_code == 10
    assert response.payload["error"] == "candidate.too_large"


def test_doctor_enforces_full_declared_mcp_version_range(monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.application as application_module

    application = PhaseApplication()
    for sdk_version, expected in (("1.25.9", False), ("1.26.0rc1", False), ("1.26.0", True), ("1.29.0", True), ("2.0.0", False)):
        monkeypatch.setattr(application_module, "distribution_version", lambda name, value=sdk_version: value)
        response = application.doctor()
        assert response.payload["mcp_sdk"]["version"] == sdk_version
        assert response.payload["mcp_sdk"]["compatible"] is expected
        assert response.payload["success"] is expected
        assert response.exit_code == (0 if expected else 10)


def test_execute_without_required_arguments_uses_current_universal_cli_validation() -> None:
    result = _phase("execute")
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "mutation_execution_unavailable_in_stage_2" not in combined
    assert "--candidate" in result.stderr
    assert "--evidence-root" in result.stderr
    assert "--run-id" in result.stderr
