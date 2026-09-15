from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import StrictInt

from .application import PhaseApplication
from .publish_file import PublishFileResult

_SERVER = FastMCP(
    "Phase Tool",
    instructions="Universal registry-bound Phase Tool operations.",
    json_response=True,
)


def _application() -> PhaseApplication:
    return PhaseApplication()


def _run(
    operation: str,
    *,
    contract_binding: str,
    candidate: dict[str, Any],
    evidence_root: str,
    run_id: str,
    input_paths: dict[str, str] | None,
    root_bindings: dict[str, str] | None,
    timestamp: str | None,
    maximum_candidate_bytes: int,
) -> dict[str, Any]:
    return _application().run(
        operation,
        contract_binding=contract_binding,
        candidate=candidate,
        evidence_root=Path(evidence_root),
        run_id=run_id,
        input_paths={name: Path(value) for name, value in (input_paths or {}).items()},
        root_bindings={name: Path(value) for name, value in (root_bindings or {}).items()},
        timestamp=timestamp,
        maximum_candidate_bytes=maximum_candidate_bytes,
    ).payload


@_SERVER.tool(name="phase_contracts_list")
def phase_contracts_list() -> dict[str, Any]:
    """List exact contract bindings from the bundled registry."""
    return _application().contracts_list().payload


@_SERVER.tool(name="phase_contract_describe")
def phase_contract_describe(contract_binding: str) -> dict[str, Any]:
    """Describe an exact registry-bound contract and its package metadata."""
    return _application().contract_describe(contract_binding).payload


@_SERVER.tool(name="phase_validate")
def phase_validate(
    contract_binding: str,
    candidate: dict[str, Any],
    evidence_root: str,
    run_id: str,
    input_paths: dict[str, str] | None = None,
    root_bindings: dict[str, str] | None = None,
    timestamp: str | None = None,
    maximum_candidate_bytes: StrictInt = 1_048_576,
) -> dict[str, Any]:
    """Validate a candidate through the universal Phase lifecycle."""
    return _run("validate", **locals())


@_SERVER.tool(name="phase_plan")
def phase_plan(
    contract_binding: str,
    candidate: dict[str, Any],
    evidence_root: str,
    run_id: str,
    input_paths: dict[str, str] | None = None,
    root_bindings: dict[str, str] | None = None,
    timestamp: str | None = None,
    maximum_candidate_bytes: StrictInt = 1_048_576,
) -> dict[str, Any]:
    """Plan a candidate through the universal Phase lifecycle."""
    return _run("plan", **locals())


@_SERVER.tool(name="phase_execute")
def phase_execute(
    contract_binding: str,
    candidate: dict[str, Any],
    evidence_root: str,
    run_id: str,
    input_paths: dict[str, str] | None = None,
    root_bindings: dict[str, str] | None = None,
    timestamp: str | None = None,
    maximum_candidate_bytes: StrictInt = 1_048_576,
) -> dict[str, Any]:
    """Execute a registry-bound contract through the application service."""
    return _run("execute", **locals())


@_SERVER.tool(name="phase_inspect")
def phase_inspect(
    evidence_root: str,
    run_id: str,
    root_bindings: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect and reverify a Phase run."""
    return _application().inspect(
        evidence_root=Path(evidence_root),
        run_id=run_id,
        root_bindings={name: Path(value) for name, value in (root_bindings or {}).items()},
    ).payload


@_SERVER.tool(name="phase_publish_file")
def phase_publish_file(
    source_root: str,
    source_locator: str,
    target_root: str,
    target_locator: str,
    preparation_root: str,
    evidence_root: str,
    request_id: str,
    run_id: str,
    expected_digest: str | None = None,
) -> PublishFileResult:
    """Publish one small ready file create-only, then independently inspect it."""
    response = _application().publish_file(
        source_root=Path(source_root), source_locator=source_locator,
        target_root=Path(target_root), target_locator=target_locator,
        preparation_root=Path(preparation_root), evidence_root=Path(evidence_root),
        request_id=request_id, run_id=run_id, expected_digest=expected_digest,
    )
    return PublishFileResult.model_validate(response.payload)


def _seal_tool_argument_models() -> None:
    """Keep advertised MCP schemas and runtime validation equally strict."""
    for tool in _SERVER._tool_manager.list_tools():  # type: ignore[attr-defined]
        argument_model = tool.fn_metadata.arg_model
        argument_model.model_config["extra"] = "forbid"
        argument_model.model_rebuild(force=True)
        tool.parameters = argument_model.model_json_schema(by_alias=True)


_seal_tool_argument_models()


def main() -> int:
    """Run the isolated MCP 1.x stdio adapter."""
    _SERVER.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
