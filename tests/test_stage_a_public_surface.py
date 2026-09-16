from __future__ import annotations

import asyncio
import importlib
import json
import os
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from phase_tool.registry import BundledRegistry

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-08-11T12:00:00Z"
COMMAND_SCHEMA_REF = "https://phase-tool.local/schemas/stage3-command-result.schema.json"


def _entrypoint(name: str) -> str:
    executable = shutil.which(name)
    assert executable is not None, f"installed entrypoint unavailable: {name}"
    return executable


def _run_phase(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [_entrypoint("phase"), *arguments],
        cwd=cwd or ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _assert_no_internal_leakage(completed: subprocess.CompletedProcess[str]) -> None:
    combined = completed.stdout + completed.stderr
    assert "Traceback (most recent call last)" not in combined
    assert "FileNotFoundError" not in combined
    assert "ValueError:" not in combined
    assert "KeyError:" not in combined
    assert "No such file or directory" not in combined


def _command_payload(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    payload = json.loads(completed.stdout)
    schema = BundledRegistry.load().schema_document(COMMAND_SCHEMA_REF)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    assert payload["exit_code"] == completed.returncode
    return payload


def _tool_payload(result: object) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content")
    return json.loads(content[0].text)


def _fixture(tmp_path: Path, stem: str) -> tuple[Path, Path, Path, Path, dict[str, Any]]:
    candidate_value = {
        "idempotency_key": f"{stem}-key",
        "input_binding": "payload",
        "operation_id": f"{stem}-operation",
        "target_locator": f"objects/{stem}.bin",
    }
    candidate = tmp_path / f"{stem}.json"
    candidate.write_text(json.dumps(candidate_value), encoding="utf-8")
    payload = tmp_path / f"{stem}.bin"
    payload.write_bytes(f"{stem} payload".encode())
    target = tmp_path / f"{stem}-target"
    target.mkdir()
    evidence = tmp_path / f"{stem}-evidence"
    return candidate, payload, target, evidence, candidate_value


def test_public_surface_snapshot_is_concise_and_complete() -> None:
    document = (ROOT / "docs" / "PUBLIC-SURFACE-V1.md").read_text(encoding="utf-8")

    for required in (
        "Linux/POSIX",
        "phase-mcp",
        "phase_contracts_list",
        "phase_contract_describe",
        "phase_validate",
        "phase_plan",
        "phase_execute",
        "phase_inspect",
        "stage3-command-result.schema.json",
        "stage3_command_result_version",
        "phase-intent.schema.json",
        "phase-receipt.schema.json",
        "field-extensible discovery payloads",
        "string `status`",
        "string `snapshot_digest`",
        "string `distribution`",
        "string `required_range`",
        "exit 2",
        "exit 10",
        "deprecat",
        "human-readable",
        "internal Python",
    ):
        assert required.lower() in document.lower()
    assert len(document.splitlines()) <= 180


def test_installed_cli_discovery_and_argparse_failures_are_deterministic() -> None:
    cases = [
        ((), 2, "usage:"),
        (("--help",), 0, "{doctor,contracts,mcp,validate,plan,execute,inspect,publish-file,publish-bundle,publication-limits,publication-status,recover-publication}"),
        (("--version",), 0, "phase 1.1.0"),
        (("unknown-command",), 2, "invalid choice"),
        (("doctor", "--unknown"), 2, "unrecognized arguments"),
        (("contracts",), 2, "required"),
        (("contracts", "describe"), 2, "--contract"),
        (("execute",), 2, "--candidate"),
        (("execute", "--maximum-candidate-bytes", "not-an-integer"), 2, "invalid int value"),
        (("inspect", "--evidence-root", "evidence", "--run-id", "run", "--root", "malformed"), 2, "NAME=PATH"),
    ]

    for arguments, returncode, marker in cases:
        completed = _run_phase(*arguments)
        assert completed.returncode == returncode, (arguments, completed.stdout, completed.stderr)
        _assert_no_internal_leakage(completed)
        stream = completed.stdout if returncode == 0 else completed.stderr
        assert marker in stream
        if returncode == 2:
            assert completed.stdout == ""


def test_installed_cli_public_operations_and_json_rejections(tmp_path: Path) -> None:
    if not os.sys.platform.startswith("linux"):
        pytest.skip("release acceptance is Linux/POSIX-only")
    candidate, payload, target, evidence, _ = _fixture(tmp_path, "stage-a-cli")
    common = (
        "--contract", "fixture_create.v1@1.0.0",
        "--candidate", str(candidate),
        "--evidence-root", str(evidence),
        "--input", f"payload={payload}",
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    )

    doctor = _run_phase("doctor")
    assert doctor.returncode == 0
    doctor_payload = json.loads(doctor.stdout)
    assert doctor_payload["success"] is True
    assert {"success", "version", "registry", "mcp_sdk"} <= doctor_payload.keys()
    assert {"status", "snapshot_digest", "contract_count"} <= doctor_payload["registry"].keys()
    assert {"distribution", "version", "required_range", "compatible"} <= doctor_payload["mcp_sdk"].keys()
    assert isinstance(doctor_payload["version"], str)
    assert isinstance(doctor_payload["registry"]["status"], str)
    assert isinstance(doctor_payload["registry"]["snapshot_digest"], str)
    assert type(doctor_payload["registry"]["contract_count"]) is int
    assert isinstance(doctor_payload["mcp_sdk"]["distribution"], str)
    assert doctor_payload["mcp_sdk"]["version"] is None or isinstance(doctor_payload["mcp_sdk"]["version"], str)
    assert isinstance(doctor_payload["mcp_sdk"]["required_range"], str)
    assert type(doctor_payload["mcp_sdk"]["compatible"]) is bool
    listed = _run_phase("contracts", "list")
    contracts = json.loads(listed.stdout)
    assert listed.returncode == 0
    assert contracts["contracts"]
    assert {"contracts", "registry_snapshot_digest"} <= contracts.keys()
    assert isinstance(contracts["registry_snapshot_digest"], str)
    assert {
        "contract_binding", "id", "version", "package_digest", "operation_intent",
    } <= contracts["contracts"][0].keys()
    assert all(isinstance(contracts["contracts"][0][field], str) for field in (
        "contract_binding", "id", "version", "package_digest", "operation_intent",
    ))
    described = _run_phase("contracts", "describe", "--contract", "fixture_create.v1@1.0.0")
    assert described.returncode == 0
    described_payload = json.loads(described.stdout)
    assert described_payload["contract_binding"] == "fixture_create.v1@1.0.0"
    assert {
        "contract_binding", "package_digest", "registry_snapshot_digest", "contract", "package_artifacts",
    } <= described_payload.keys()
    assert all(isinstance(described_payload[field], str) for field in (
        "contract_binding", "package_digest", "registry_snapshot_digest",
    ))
    assert isinstance(described_payload["contract"], dict)
    assert isinstance(described_payload["package_artifacts"], list)

    validate = _run_phase("validate", *common, "--run-id", "stage-a-cli-validate")
    plan = _run_phase("plan", *common, "--run-id", "stage-a-cli-plan")
    execute = _run_phase("execute", *common, "--run-id", "stage-a-cli-execute")
    assert _command_payload(validate)["terminal_status"] == "validated_planned"
    assert _command_payload(plan)["terminal_status"] == "validated_planned"
    execute_payload = _command_payload(execute)
    assert execute_payload["terminal_status"] == "succeeded_verified"
    assert execute_payload["mutation_attempted"] is True
    inspect = _run_phase(
        "inspect", "--evidence-root", str(evidence), "--run-id", "stage-a-cli-execute",
        "--root", f"fixture_result_root={target}",
    )
    inspect_payload = _command_payload(inspect)
    assert inspect_payload["target_verified"] is True

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    missing = tmp_path / "missing.json"
    before = sorted(path.relative_to(target).as_posix() for path in target.rglob("*"))
    json_failures = [
        (
            ("execute", "--contract", "missing.v1@1.0.0", "--candidate", str(candidate),
             "--evidence-root", str(tmp_path / "reject-evidence-1"), "--run-id", "unknown-contract"),
            "application.contract_binding_not_found",
        ),
        (
            ("execute", "--contract", "fixture_create.v1@1.0.0", "--contract-id", "fixture_create.v1",
             "--candidate", str(candidate), "--evidence-root", str(tmp_path / "reject-evidence-2"),
             "--run-id", "conflicting-binding"),
            "cli.conflicting_contract_binding",
        ),
        (
            ("execute", "--contract-id", "fixture_create.v1", "--contract-version", "1.0.0",
             "--candidate", str(candidate), "--evidence-root", str(tmp_path / "reject-evidence-3"),
             "--run-id", "incomplete-binding"),
            "cli.contract_binding_required",
        ),
        (
            ("execute", "--contract", "fixture_create.v1@1.0.0", "--candidate", str(missing),
             "--evidence-root", str(tmp_path / "reject-evidence-4"), "--run-id", "missing-candidate",
             "--root", f"fixture_result_root={target}"),
            "candidate.input_unavailable",
        ),
        (
            ("execute", "--contract", "fixture_create.v1@1.0.0", "--candidate", str(malformed),
             "--evidence-root", str(tmp_path / "reject-evidence-5"), "--run-id", "malformed-candidate",
             "--root", f"fixture_result_root={target}"),
            "candidate.invalid_json",
        ),
        (
            ("execute", "--contract", "fixture_create.v1@1.0.0", "--candidate", str(candidate),
             "--evidence-root", str(tmp_path / "reject-evidence-6"), "--run-id", "duplicate-input",
             "--input", f"payload={payload}", "--input", f"payload={payload}"),
            "cli.duplicate_binding",
        ),
        (
            ("execute", "--contract", "fixture_create.v1@1.0.0", "--candidate", str(candidate),
             "--evidence-root", str(tmp_path / "reject-evidence-7"), "--run-id", "../invalid"),
            "evidence.invalid_run_id",
        ),
        (
            ("inspect", "--evidence-root", str(tmp_path / "unavailable-evidence"), "--run-id", "missing-run"),
            "inspection.run_unavailable",
        ),
    ]
    for arguments, code in json_failures:
        completed = _run_phase(*arguments)
        assert completed.returncode == 10, (arguments, completed.stdout, completed.stderr)
        assert completed.stderr == ""
        _assert_no_internal_leakage(completed)
        rejected = _command_payload(completed)
        assert rejected["success"] is False
        assert rejected["error"] == code
        assert rejected["blockers"] == [code]
        assert rejected["mutation_attempted"] is False
    after = sorted(path.relative_to(target).as_posix() for path in target.rglob("*"))
    assert after == before


def test_command_result_schema_acceptance_and_rejection_boundaries() -> None:
    schema = BundledRegistry.load().schema_document(COMMAND_SCHEMA_REF)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    valid = {
        "stage3_command_result_version": "1.0",
        "command": "execute",
        "success": False,
        "run_id": None,
        "terminal_status": "rejected",
        "execution_disposition": "not_executed",
        "mutation_attempted": False,
        "effect_plan_digest": None,
        "intent_digest": None,
        "receipt_digest": None,
        "target_verified": None,
        "blockers": ["candidate.invalid_json"],
        "error": "candidate.invalid_json",
        "exit_code": 10,
    }
    validator.validate(valid)
    full = deepcopy(valid)
    full.update({
        "success": True,
        "run_id": "run-1",
        "terminal_status": "succeeded_verified",
        "execution_disposition": "executed",
        "mutation_attempted": True,
        "effect_plan_digest": "sha256:" + "1" * 64,
        "intent_digest": "sha256:" + "2" * 64,
        "receipt_digest": "sha256:" + "3" * 64,
        "target_verified": True,
        "blockers": [],
        "error": None,
        "exit_code": 0,
    })
    validator.validate(full)

    invalid_values: list[dict[str, Any]] = []
    missing = deepcopy(valid)
    missing.pop("success")
    invalid_values.append(missing)
    extra = deepcopy(valid)
    extra["private"] = True
    invalid_values.append(extra)
    for key, value in (
        ("command", "remove"),
        ("success", 1),
        ("exit_code", True),
        ("exit_code", "10"),
        ("terminal_status", "successful"),
        ("execution_disposition", "maybe"),
        ("mutation_attempted", None),
        ("blockers", None),
        ("run_id", 1),
    ):
        malformed = deepcopy(valid)
        malformed[key] = value
        invalid_values.append(malformed)
    nested = deepcopy(valid)
    nested["blockers"] = [{"code": "candidate.invalid_json"}]
    invalid_values.append(nested)

    for malformed in invalid_values:
        with pytest.raises(ValidationError):
            validator.validate(malformed)


def test_public_evidence_schemas_reject_structural_boundary_violations() -> None:
    registry = BundledRegistry.load()
    for reference in (
        "https://phase-tool.local/schemas/phase-intent.schema.json",
        "https://phase-tool.local/schemas/phase-receipt.schema.json",
    ):
        schema = registry.schema_document(reference)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for malformed in (None, [], {}, {"unexpected": True}):
            with pytest.raises(ValidationError):
                validator.validate(malformed)


@pytest.mark.skipif(not os.sys.platform.startswith("linux"), reason="release acceptance is Linux/POSIX-only")
def test_actual_mcp_entrypoint_adversarial_long_lived_session(tmp_path: Path) -> None:
    candidate, payload, target, evidence, candidate_value = _fixture(tmp_path, "stage-a-mcp")
    del candidate

    async def exchange() -> tuple[list[str], list[dict[str, Any]], list[object], dict[str, Any]]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        parameters = StdioServerParameters(
            command=_entrypoint("phase-mcp"),
            args=[],
            cwd=str(tmp_path),
            env=environment,
        )
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = sorted(tool.name for tool in tools.tools)
                schemas = {tool.name: tool.inputSchema for tool in tools.tools}
                application_rejections = []
                application_rejections.append(_tool_payload(await session.call_tool("phase_execute", {
                    "contract_binding": "missing.v1@1.0.0",
                    "candidate": candidate_value,
                    "evidence_root": str(evidence),
                    "run_id": "mcp-bad-binding",
                })))
                application_rejections.append(_tool_payload(await session.call_tool("phase_execute", {
                    "contract_binding": "fixture_create.v1@1.0.0",
                    "candidate": {},
                    "evidence_root": str(evidence),
                    "run_id": "mcp-malformed-candidate",
                    "input_paths": {"payload": str(payload)},
                    "root_bindings": {"fixture_result_root": str(target)},
                })))
                application_rejections.append(_tool_payload(await session.call_tool("phase_inspect", {
                    "evidence_root": str(tmp_path / "missing-evidence"),
                    "run_id": "missing-run",
                })))
                protocol_rejections = []
                for arguments in (
                    {},
                    {"contract_binding": "fixture_create.v1@1.0.0", "candidate": candidate_value,
                     "evidence_root": str(evidence), "run_id": "extra", "unknown": True},
                    {"contract_binding": 7, "candidate": candidate_value,
                     "evidence_root": str(evidence), "run_id": "wrong-scalar"},
                    {"contract_binding": "fixture_create.v1@1.0.0", "candidate": [],
                     "evidence_root": str(evidence), "run_id": "wrong-container"},
                    {"contract_binding": "fixture_create.v1@1.0.0", "candidate": candidate_value,
                     "evidence_root": str(evidence), "run_id": "bool-int", "maximum_candidate_bytes": True},
                ):
                    protocol_rejections.append(await session.call_tool("phase_execute", arguments))
                described_after_rejections = _tool_payload(await session.call_tool(
                    "phase_contract_describe", {"contract_binding": "fixture_create.v1@1.0.0"}
                ))
                listed_after_rejections = _tool_payload(await session.call_tool("phase_contracts_list", {}))
                validated = _tool_payload(await session.call_tool("phase_validate", {
                    "contract_binding": "fixture_create.v1@1.0.0",
                    "candidate": candidate_value,
                    "evidence_root": str(evidence),
                    "run_id": "stage-a-mcp-validate",
                    "input_paths": {"payload": str(payload)},
                    "root_bindings": {"fixture_result_root": str(target)},
                    "timestamp": NOW,
                }))
                planned = _tool_payload(await session.call_tool("phase_plan", {
                    "contract_binding": "fixture_create.v1@1.0.0",
                    "candidate": candidate_value,
                    "evidence_root": str(evidence),
                    "run_id": "stage-a-mcp-plan",
                    "input_paths": {"payload": str(payload)},
                    "root_bindings": {"fixture_result_root": str(target)},
                    "timestamp": NOW,
                }))
                nullable = _tool_payload(await session.call_tool("phase_validate", {
                    "contract_binding": "fixture_create.v1@1.0.0",
                    "candidate": candidate_value,
                    "evidence_root": str(evidence),
                    "run_id": "stage-a-mcp-nullable",
                    "input_paths": None,
                    "root_bindings": None,
                    "timestamp": None,
                }))
                executed = _tool_payload(await session.call_tool("phase_execute", {
                    "contract_binding": "fixture_create.v1@1.0.0",
                    "candidate": candidate_value,
                    "evidence_root": str(evidence),
                    "run_id": "stage-a-mcp-execute",
                    "input_paths": {"payload": str(payload)},
                    "root_bindings": {"fixture_result_root": str(target)},
                    "timestamp": NOW,
                }))
                inspected = _tool_payload(await session.call_tool("phase_inspect", {
                    "evidence_root": str(evidence),
                    "run_id": "stage-a-mcp-execute",
                    "root_bindings": {"fixture_result_root": str(target)},
                }))
                return names, application_rejections, protocol_rejections, {
                    "schemas": schemas,
                    "described": described_after_rejections,
                    "listed": listed_after_rejections,
                    "validated": validated,
                    "planned": planned,
                    "nullable": nullable,
                    "executed": executed,
                    "inspected": inspected,
                }

    names, application_rejections, protocol_rejections, valid = asyncio.run(exchange())
    assert names == [
        "phase_contract_describe",
        "phase_contracts_list",
        "phase_execute",
        "phase_inspect",
        "phase_plan",
        "phase_publication_limits",
        "phase_publication_status",
        "phase_publish_bundle",
        "phase_publish_file",
        "phase_recover_publication",
        "phase_validate",
    ]
    for schema in valid["schemas"].values():
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
    pipeline_required = {"contract_binding", "candidate", "evidence_root", "run_id"}
    for tool_name in ("phase_validate", "phase_plan", "phase_execute"):
        assert set(valid["schemas"][tool_name]["required"]) == pipeline_required
    assert [item["error"] for item in application_rejections] == [
        "application.contract_binding_not_found",
        "candidate.schema_invalid",
        "inspection.run_unavailable",
    ]
    assert all(item["success"] is False and item["mutation_attempted"] is False for item in application_rejections)
    for result in protocol_rejections:
        assert result.isError is True
        serialized = str(result)
        assert "Traceback (most recent call last)" not in serialized
        assert str(ROOT) not in serialized
        assert str(tmp_path) not in serialized
    assert valid["described"]["contract_binding"] == "fixture_create.v1@1.0.0"
    assert valid["listed"]["contracts"]
    assert valid["validated"]["terminal_status"] == "validated_planned"
    assert valid["planned"]["terminal_status"] == "validated_planned"
    assert valid["nullable"]["success"] is False
    assert isinstance(valid["nullable"]["error"], str)
    assert valid["nullable"]["mutation_attempted"] is False
    assert valid["executed"]["terminal_status"] == "succeeded_verified"
    assert valid["inspected"]["target_verified"] is True


@pytest.mark.skipif(not os.sys.platform.startswith("linux"), reason="release acceptance is Linux/POSIX-only")
def test_cli_and_mcp_share_semantics_for_equivalent_rejection(tmp_path: Path) -> None:
    candidate, payload, target, evidence, candidate_value = _fixture(tmp_path, "stage-a-consistency")
    cli = _run_phase(
        "execute", "--contract", "missing.v1@1.0.0", "--candidate", str(candidate),
        "--evidence-root", str(evidence), "--run-id", "consistency-cli",
        "--input", f"payload={payload}", "--root", f"fixture_result_root={target}",
    )
    cli_payload = _command_payload(cli)

    async def exchange() -> dict[str, Any]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        parameters = StdioServerParameters(command=_entrypoint("phase-mcp"), args=[], cwd=str(tmp_path), env=environment)
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                return _tool_payload(await session.call_tool("phase_execute", {
                    "contract_binding": "missing.v1@1.0.0",
                    "candidate": candidate_value,
                    "evidence_root": str(evidence),
                    "run_id": "consistency-mcp",
                    "input_paths": {"payload": str(payload)},
                    "root_bindings": {"fixture_result_root": str(target)},
                }))

    mcp_payload = asyncio.run(exchange())
    for key in (
        "success", "terminal_status", "execution_disposition", "mutation_attempted",
        "effect_plan_digest", "intent_digest", "receipt_digest", "target_verified",
        "blockers", "error", "exit_code",
    ):
        assert cli_payload[key] == mcp_payload[key]


@pytest.mark.parametrize(
    ("terminal_status", "execution_disposition", "mutation_attempted", "exit_code"),
    [
        ("succeeded_verified", "executed", True, 0),
        ("rejected", "not_executed", False, 10),
        ("failed_no_effect", "executed", True, 20),
        ("failed_partial", "executed", True, 30),
        ("committed_unverified", "executed", True, 40),
        ("indeterminate", "executed", True, 50),
    ],
)
def test_cli_propagates_public_lifecycle_exit_classes(
    monkeypatch: pytest.MonkeyPatch,
    terminal_status: str,
    execution_disposition: str,
    mutation_attempted: bool,
    exit_code: int,
) -> None:
    from phase_tool.application import ApplicationResponse

    cli = importlib.import_module("phase_tool.cli.main")
    payload = {
        "stage3_command_result_version": "1.0",
        "command": "execute",
        "success": exit_code == 0,
        "run_id": "exit-class",
        "terminal_status": terminal_status,
        "execution_disposition": execution_disposition,
        "mutation_attempted": mutation_attempted,
        "effect_plan_digest": None,
        "intent_digest": None,
        "receipt_digest": None,
        "target_verified": None,
        "blockers": [] if exit_code == 0 else ["test.public_exit_class"],
        "error": None if exit_code == 0 else "test.public_exit_class",
        "exit_code": exit_code,
    }

    class StubApplication:
        def run(self, *_args: Any, **_kwargs: Any) -> ApplicationResponse:
            return ApplicationResponse(payload, exit_code)

    emitted: list[object] = []
    monkeypatch.setattr(cli, "PhaseApplication", StubApplication)
    monkeypatch.setattr(cli, "_write", emitted.append)

    actual = cli.main([
        "execute", "--contract", "fixture_create.v1@1.0.0", "--candidate", "candidate.json",
        "--evidence-root", "evidence", "--run-id", "exit-class",
    ])

    assert actual == exit_code
    assert emitted == [payload]
