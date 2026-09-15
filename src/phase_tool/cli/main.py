from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from jsonschema import Draft202012Validator, FormatChecker

from .. import __version__
from ..application import PhaseApplication
from ..canonical import canonical_bytes
from ..errors import PhaseError
from ..registry import BundledRegistry


def _binding(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("binding must be NAME=PATH")
    name, raw_path = value.split("=", 1)
    if not name or not raw_path:
        raise argparse.ArgumentTypeError("binding must be NAME=PATH")
    return name, Path(raw_path)


def _write_json(value: object) -> None:
    sys.stdout.buffer.write(canonical_bytes(value) + b"\n")


def _write(value: object) -> None:
    registry = BundledRegistry.load()
    schema = registry.schema_document("https://phase-tool.local/schemas/stage3-command-result.schema.json")
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    _write_json(value)


def _add_pipeline_arguments(parser: argparse.ArgumentParser, *, required: bool = True) -> None:
    parser.add_argument("--contract")
    parser.add_argument("--contract-id")
    parser.add_argument("--contract-version")
    parser.add_argument("--contract-digest")
    parser.add_argument("--candidate", type=Path, required=required)
    parser.add_argument("--evidence-root", type=Path, required=required)
    parser.add_argument("--run-id", required=required)
    parser.add_argument("--input", action="append", default=[], type=_binding)
    parser.add_argument("--root", action="append", default=[], type=_binding)
    parser.add_argument("--timestamp")
    parser.add_argument("--maximum-candidate-bytes", type=int, default=1_048_576)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phase", description="Universal local Phase Tool")
    parser.add_argument("--version", action="version", version=f"phase {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor")
    contracts = subparsers.add_parser("contracts")
    contracts_commands = contracts.add_subparsers(dest="contracts_command", required=True)
    contracts_commands.add_parser("list")
    describe = contracts_commands.add_parser("describe")
    describe.add_argument("--contract", required=True)
    mcp = subparsers.add_parser("mcp")
    mcp_commands = mcp.add_subparsers(dest="mcp_command", required=True)
    serve = mcp_commands.add_parser("serve")
    serve.add_argument("--stdio", action="store_true", required=True)
    for name in ("validate", "plan"):
        command = subparsers.add_parser(name)
        _add_pipeline_arguments(command)
    execute = subparsers.add_parser("execute")
    _add_pipeline_arguments(execute)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--evidence-root", type=Path, required=True)
    inspect.add_argument("--run-id", required=True)
    inspect.add_argument("--root", action="append", default=[], type=_binding)
    publish = subparsers.add_parser("publish-file", allow_abbrev=False)
    for name in ("source-root", "target-root", "preparation-root", "evidence-root"):
        publish.add_argument("--" + name, type=Path, required=True)
    for name in ("source-locator", "target-locator", "request-id", "run-id"):
        publish.add_argument("--" + name, required=True)
    publish.add_argument("--expected-digest")
    publish.add_argument("--publication-version", choices=("1.0", "2.0"), default="1.0")
    bundle = subparsers.add_parser("publish-bundle", allow_abbrev=False)
    for name in ("source-root", "target-root", "preparation-root", "evidence-root"):
        bundle.add_argument("--" + name, type=Path, required=True)
    for name in ("target-locator", "request-id", "run-id"):
        bundle.add_argument("--" + name, required=True)
    bundle.add_argument("--member", dest="members", action="append", required=True)
    bundle.add_argument("--publication-version", choices=("1.0", "2.0"), default="1.0")
    subparsers.add_parser("publication-limits")
    for name in ("publication-status", "recover-publication"):
        query = subparsers.add_parser(name, allow_abbrev=False)
        query.add_argument("--evidence-root", type=Path, required=True)
        query.add_argument("--run-id", required=True)
        if name == "publication-status":
            query.add_argument("--wait-seconds", type=int, default=0)
        else:
            query.add_argument("--target-root", type=Path, required=True)
            query.add_argument("--request-id", required=True)
            query.add_argument("--expected-intent-digest", required=True)
            query.add_argument("--mode", choices=("observe", "commit_prepared"), default="observe")
    return parser


def _envelope(
    command: str,
    *,
    success: bool,
    run_id: str | None,
    terminal_status: str | None,
    execution_disposition: str | None,
    mutation_attempted: bool,
    effect_plan_digest: str | None,
    intent_digest: str | None,
    receipt_digest: str | None,
    blockers: list[str],
    error: str | None,
    exit_code: int,
    target_verified: bool | None = None,
) -> dict[str, object]:
    return {
        "stage3_command_result_version": "1.0",
        "command": command,
        "success": success,
        "run_id": run_id,
        "terminal_status": terminal_status,
        "execution_disposition": execution_disposition,
        "mutation_attempted": mutation_attempted,
        "effect_plan_digest": effect_plan_digest,
        "intent_digest": intent_digest,
        "receipt_digest": receipt_digest,
        "target_verified": target_verified,
        "blockers": blockers,
        "error": error,
        "exit_code": exit_code,
    }


def _pipeline(args: argparse.Namespace, *, execute: bool) -> int:
    roots = dict(args.root)
    inputs = dict(args.input)
    if len(roots) != len(args.root) or len(inputs) != len(args.input):
        raise PhaseError("cli.duplicate_binding")
    if args.contract is not None:
        if any(value is not None for value in (args.contract_id, args.contract_version, args.contract_digest)):
            raise PhaseError("cli.conflicting_contract_binding")
        exact_binding = args.contract
        digest = None
    else:
        if not all((args.contract_id, args.contract_version, args.contract_digest)):
            raise PhaseError("cli.contract_binding_required")
        exact_binding = f"{args.contract_id}@{args.contract_version}"
        digest = args.contract_digest
    response = PhaseApplication().run(
        args.command,
        contract_binding=exact_binding,
        contract_digest=digest,
        candidate_path=args.candidate,
        evidence_root=args.evidence_root,
        run_id=args.run_id,
        input_paths=inputs,
        root_bindings=roots,
        timestamp=args.timestamp,
        maximum_candidate_bytes=args.maximum_candidate_bytes,
    )
    _write(response.payload)
    return response.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    application = PhaseApplication()
    if args.command == "doctor":
        response = application.doctor()
        _write_json(response.payload)
        return response.exit_code
    if args.command == "contracts":
        response = (
            application.contracts_list()
            if args.contracts_command == "list"
            else application.contract_describe(args.contract)
        )
        _write_json(response.payload)
        return response.exit_code
    if args.command in {"publication-limits", "publication-status", "recover-publication"}:
        method = {"publication-limits": application.publication_limits,
                  "publication-status": application.publication_status,
                  "recover-publication": application.recover_publication}[args.command]
        response = method(**{key: value for key, value in vars(args).items() if key != "command"})
        _write_json(response.payload)
        return response.exit_code
    if args.command == "publish-bundle":
        response = application.publish_bundle(**{
            key: value for key, value in vars(args).items() if key != "command"
        })
        _write_json(response.payload)
        return response.exit_code
    if args.command == "publish-file":
        response = application.publish_file(**{
            key: value for key, value in vars(args).items() if key != "command"
        })
        _write_json(response.payload)
        return response.exit_code
    if args.command == "mcp":
        from ..mcp_server import main as mcp_main

        return mcp_main()
    try:
        if args.command in {"validate", "plan", "execute"}:
            return _pipeline(args, execute=args.command == "execute")
        if args.command == "inspect":
            roots = dict(args.root)
            if len(roots) != len(args.root):
                raise PhaseError("cli.duplicate_binding")
            response = application.inspect(
                evidence_root=args.evidence_root,
                run_id=args.run_id,
                root_bindings=roots,
            )
            _write(response.payload)
            return response.exit_code
    except (PhaseError, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, PhaseError) else "cli.failure"
        _write(_envelope(
            args.command,
            success=False,
            run_id=None,
            terminal_status=None,
            execution_disposition=None,
            mutation_attempted=False,
            effect_plan_digest=None,
            intent_digest=None,
            receipt_digest=None,
            blockers=[code],
            target_verified=None,
            error=code,
            exit_code=10,
        ))
        return 10
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
