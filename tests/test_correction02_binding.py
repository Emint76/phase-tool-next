"""C1 intent-bound preconditions and truthful publication capabilities."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes
from phase_tool.evidence import validate_receipt
from .test_publish_bundle import bundle_arguments


LINUX = pytest.mark.skipif(os.name != "posix", reason="qualified Linux publication required")


def _raw_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _target_snapshot(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        result[path.relative_to(root).as_posix()] = (
            info.st_mode, info.st_dev, info.st_ino,
            _raw_digest(path.read_bytes()) if path.is_file() else None,
        )
    return result


def _query(args: dict, intent_digest: str) -> dict:
    return {key: args[key] for key in ("evidence_root", "run_id", "target_root", "request_id")} | {
        "expected_intent_digest": intent_digest,
    }


def _inspect(app: PhaseApplication, args: dict) -> dict:
    return app.inspect(
        evidence_root=args["evidence_root"], run_id=args["run_id"],
        root_bindings={"phase_result_root": args["target_root"]},
    ).payload


def _tamper_preconditions(run: Path, *, coherent_receipt: bool) -> None:
    path = run / "attachments/pre-validator-results.json"
    previous = _raw_digest(path.read_bytes())
    pre = json.loads(path.read_bytes())
    pre[0]["actual"] = "coherently replaced pre-validator claim"
    path.write_bytes(canonical_bytes(pre))
    if coherent_receipt:
        receipt_path = run / "receipt.json"
        receipt = json.loads(receipt_path.read_bytes())
        hashes = receipt["evidence"]["attachment_digests"]
        assert hashes.count(previous) == 1
        hashes[hashes.index(previous)] = _raw_digest(path.read_bytes())
        receipt_path.write_bytes(canonical_bytes(receipt))


@LINUX
@pytest.mark.parametrize("operation", ["inspect", "observe"])
def test_successful_bundle_rejects_coherent_precondition_receipt_tamper(tmp_path, operation):
    args = bundle_arguments(tmp_path) | {"publication_version": "2.0"}
    app = PhaseApplication()
    first = app.publish_bundle(**args).payload
    assert first["success"] and first["target_verified"], first
    assert _inspect(app, args)["target_verified"] is True
    query = _query(args, first["intent_digest"])
    assert app.recover_publication(**query).payload["success"] is True
    run = args["evidence_root"] / ".phase/runs" / args["run_id"]
    original_intent = (run / "intent.json").read_bytes()
    intent = json.loads(original_intent)
    assert intent["phase_intent_version"] == "1.1"
    pre_path = run / "attachments/pre-validator-results.json"
    assert intent["evidence"]["pre_validator_results_digest"] == _raw_digest(pre_path.read_bytes())
    before = _target_snapshot(args["target_root"])

    _tamper_preconditions(run, coherent_receipt=True)
    validate_receipt(json.loads((run / "receipt.json").read_bytes()), app.registry)
    assert intent["evidence"]["pre_validator_results_digest"] != _raw_digest(pre_path.read_bytes())
    assert (run / "intent.json").read_bytes() == original_intent
    result = _inspect(app, args) if operation == "inspect" else app.recover_publication(**query).payload

    assert result["success"] is False, result
    assert result.get("target_verified") is not True, result
    assert result["error"] == (
        "preconditions.digest_mismatch" if operation == "inspect"
        else "recovery.original_verification_incomplete"
    ), result
    assert _target_snapshot(args["target_root"]) == before
    assert (run / "intent.json").read_bytes() == original_intent


@LINUX
@pytest.mark.parametrize("damage", ["changed", "missing"])
@pytest.mark.parametrize("operation", ["missing_receipt", "commit_prepared"])
def test_untrusted_preconditions_never_authorize_recovery_effect(tmp_path, monkeypatch, damage, operation):
    from phase_tool.evidence import EvidenceStore
    from phase_tool.mutation import bundle_create
    from .test_rc01_correction import crash_prepared_bundle

    app = PhaseApplication()
    if operation == "commit_prepared":
        args, run, query = crash_prepared_bundle(tmp_path, version="2.0")
        assert list(args["target_root"].glob("phase-stage-*"))
        assert not (args["target_root"] / args["target_locator"]).exists()
    else:
        args = bundle_arguments(tmp_path) | {"publication_version": "2.0"}
        write = EvidenceStore.write_canonical

        def lose_receipt(self, relative, value):
            if relative == "receipt.json":
                raise OSError("injected receipt loss after actual bundle commit")
            return write(self, relative, value)

        with monkeypatch.context() as patch:
            patch.setattr(EvidenceStore, "write_canonical", lose_receipt)
            first = app.publish_bundle(**args).payload
        assert not first["success"] and first["intent_digest"], first
        assert (args["target_root"] / args["target_locator"] / "a.bin").read_bytes() == b"a"
        run = args["evidence_root"] / ".phase/runs" / args["run_id"]
        query = _query(args, first["intent_digest"])
        assert app.recover_publication(**query).payload["success"] is True
    assert not (run / "receipt.json").exists()
    original_intent = (run / "intent.json").read_bytes()
    proof = (run / "attachments/prepared-stage.json").read_bytes()
    before = _target_snapshot(args["target_root"])
    if damage == "missing":
        (run / "attachments/pre-validator-results.json").unlink()
    else:
        _tamper_preconditions(run, coherent_receipt=False)

    def forbidden_commit(*args, **kwargs):
        pytest.fail("untrusted preconditions must be refused before a target effect")

    monkeypatch.setattr(bundle_create, "_rename_noreplace", forbidden_commit)
    result = app.recover_publication(
        **query, mode="commit_prepared" if operation == "commit_prepared" else "observe",
    ).payload
    assert not result["success"] and not result["target_verified"], result
    assert result["recovery_mutation_attempted"] is False, result
    assert result["error"] == "recovery.preconditions_not_proven", result
    assert _target_snapshot(args["target_root"]) == before
    assert (run / "intent.json").read_bytes() == original_intent
    assert (run / "attachments/prepared-stage.json").read_bytes() == proof
    assert not (run / "recovery/commit-intent.json").exists()


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_binding_helper_has_explicit_historical_guarantees(version):
    from phase_tool.errors import PhaseError
    from phase_tool.preconditions import verify_pre_validator_binding

    original = _raw_digest(b"original")
    changed = _raw_digest(b"changed")
    intent = {"phase_intent_version": version, "evidence": {}}
    if version == "1.0":
        assert verify_pre_validator_binding(intent, changed) is False
        assert "pre_validator_results_digest" not in intent["evidence"]
    else:
        intent["evidence"]["pre_validator_results_digest"] = original
        assert verify_pre_validator_binding(intent, original) is True
        with pytest.raises(PhaseError, match="preconditions.digest_mismatch"):
            verify_pre_validator_binding(intent, changed)
        intent["evidence"].clear()
        with pytest.raises(PhaseError, match="preconditions.digest_mismatch"):
            verify_pre_validator_binding(intent, original)


@pytest.mark.parametrize("version", [None, "", "1.2", "2.0"])
def test_binding_helper_does_not_exempt_unknown_formats(version):
    from phase_tool.errors import PhaseError
    from phase_tool.preconditions import verify_pre_validator_binding

    with pytest.raises(PhaseError, match="preconditions.unsupported_intent_version"):
        verify_pre_validator_binding({"phase_intent_version": version}, _raw_digest(b"anything"))


@LINUX
@pytest.mark.parametrize("version", ["1.0", "2.0"])
def test_genuine_historical_and_current_bundles_inspect_and_observe(tmp_path, version):
    args = bundle_arguments(tmp_path) | {"publication_version": version}
    app = PhaseApplication()
    first = app.publish_bundle(**args).payload
    assert first["success"] and _inspect(app, args)["target_verified"], first
    run = args["evidence_root"] / ".phase/runs" / args["run_id"]
    original = (run / "intent.json").read_bytes()
    intent = json.loads(original)
    assert ("pre_validator_results_digest" in intent["evidence"]) is (version == "2.0")
    before = _target_snapshot(args["target_root"])
    result = app.recover_publication(**_query(args, first["intent_digest"])).payload
    assert result["success"] and result["target_verified"], result
    assert result["recovery_mutation_attempted"] is False
    assert _target_snapshot(args["target_root"]) == before
    assert (run / "intent.json").read_bytes() == original


@LINUX
def test_fast_status_reports_saved_claim_not_fresh_verification(tmp_path, monkeypatch):
    from phase_tool import bundle, streaming
    from phase_tool.mutation import EffectBroker

    args = bundle_arguments(tmp_path) | {"publication_version": "2.0"}
    app = PhaseApplication()
    first = app.publish_bundle(**args).payload
    assert first["success"], first
    run = args["evidence_root"] / ".phase/runs" / args["run_id"]
    _tamper_preconditions(run, coherent_receipt=True)
    before = _target_snapshot(args["target_root"])

    def forbidden(*args, **kwargs):
        pytest.fail("metadata status must neither inspect bytes nor authorize continuation")

    monkeypatch.setattr(bundle, "verify_bundle", forbidden)
    monkeypatch.setattr(streaming, "hash_file", forbidden)
    monkeypatch.setattr(PhaseApplication, "inspect", forbidden)
    monkeypatch.setattr(EffectBroker, "resume_prepared_bundle", forbidden)
    result = app.publication_status(evidence_root=args["evidence_root"], run_id=args["run_id"]).payload
    assert result["query_succeeded"] and result["stage"] == "receipt_recorded", result
    assert result["recorded_terminal_status"] == "succeeded_verified"
    assert result["verification_performed"] is False and result["target_verified"] is False
    assert result["process_liveness"] == "not_checked"
    assert _target_snapshot(args["target_root"]) == before


def test_capabilities_match_cli_and_mcp_interfaces(tmp_path):
    import asyncio
    import inspect
    import subprocess
    import sys
    from phase_tool.cli.main import build_parser
    from phase_tool.recovery import recover_publication

    app = PhaseApplication()
    caps = app.publication_limits().payload
    assert caps["bundle_v2"] == caps["bundle_v1"]
    assert caps["publication_versions"] == {"file": ["1.0", "2.0"], "bundle": ["1.0", "2.0"]}
    modes = caps["recovery_modes"]
    assert list(modes) == ["observe", "commit_prepared"]
    assert caps["recovery_default_mode"] == inspect.signature(recover_publication).parameters["mode"].default == "observe"
    assert modes["observe"]["target_mutation"] is False
    assert modes["commit_prepared"]["target_mutation"] is True
    assert modes["commit_prepared"]["target_effect"] == "remaining_directory_commit_only"
    assert caps["status"] == {
        "semantics": "historical_metadata_only", "verification_performed": False,
        "target_verified": False, "target_mutation": False, "process_liveness": "not_checked",
    }
    parser = build_parser()
    commands = next(action.choices for action in parser._actions if action.dest == "command")
    for kind in ("file", "bundle"):
        option = next(action for action in commands[f"publish-{kind}"]._actions if action.dest == "publication_version")
        assert list(option.choices) == caps["publication_versions"][kind]
    recovery_mode = next(action for action in commands["recover-publication"]._actions if action.dest == "mode")
    assert list(recovery_mode.choices) == list(modes)
    assert recovery_mode.default == caps["recovery_default_mode"]
    status_arguments = {action.dest for action in commands["publication-status"]._actions}
    assert "mode" not in status_arguments and "target_root" not in status_arguments
    child = subprocess.run([sys.executable, "-m", "phase_tool", "publication-limits"],
                           capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, child.stdout + child.stderr
    assert json.loads(child.stdout) == caps

    async def exchange():
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async with stdio_client(StdioServerParameters(
            command=sys.executable, args=["-m", "phase_tool", "mcp", "serve", "--stdio"],
        )) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = {tool.name: tool.inputSchema for tool in (await session.list_tools()).tools}
                result = await session.call_tool("phase_publication_limits", {})
                assert not result.isError, result
                assert result.structuredContent == caps
                assert tools["phase_publish_bundle"]["properties"]["publication_version"]["enum"] == caps["publication_versions"]["bundle"]
                # The older file adapter admits a string and validates the
                # supported vocabulary at runtime, rather than via an enum.
                assert tools["phase_publish_file"]["properties"]["publication_version"]["type"] == "string"
                args = bundle_arguments(tmp_path)
                for version in caps["publication_versions"]["file"]:
                    request = {key: str(value) for key, value in args.items() if key != "members"}
                    request.update(source_locator="a.bin", publication_version=version,
                                   target_locator=f"file-{version}", run_id=f"file-{version}", request_id=f"file-{version}")
                    published = await session.call_tool("phase_publish_file", request)
                    assert not published.isError and published.structuredContent["success"], published
                mode = tools["phase_recover_publication"]["properties"]["mode"]
                assert mode["enum"] == list(modes) and mode["default"] == caps["recovery_default_mode"]
                assert "mode" not in tools["phase_publication_status"]["properties"]

    asyncio.run(exchange())


@LINUX
def test_capabilities_bind_continuation_to_actual_publication_contract(tmp_path):
    from .test_rc01_correction import crash_prepared_bundle

    app = PhaseApplication()
    caps = app.publication_limits().payload
    args, run, query = crash_prepared_bundle(tmp_path, version="2.0")
    intent = json.loads((run / "intent.json").read_bytes())
    binding = intent["contract"]
    assert caps["recovery_modes"]["commit_prepared"]["contract_bindings"] == [f"{binding['id']}@{binding['version']}"]
    stage = next(args["target_root"].glob("phase-stage-*"))
    identity = stage.stat().st_ino
    observed = app.recover_publication(**query).payload
    assert not observed["success"] and observed["recovery_mutation_attempted"] is False
    assert stage.exists() and not (args["target_root"] / args["target_locator"]).exists()
    continued = app.recover_publication(**query, mode="commit_prepared").payload
    assert continued["success"] and continued["recovery_mutation_attempted"], continued
    assert not stage.exists() and (args["target_root"] / args["target_locator"]).stat().st_ino == identity


@LINUX
@pytest.mark.parametrize("case", ["missing_receipt", "planned", "receipt_without_effects"])
def test_inspection_binding_does_not_depend_on_effect_receipt_presence(tmp_path, case):
    from .test_rc01_correction import crash_prepared_bundle

    app = PhaseApplication()
    if case == "missing_receipt":
        args, run, _query_args = crash_prepared_bundle(tmp_path, version="2.0")
        original_inspection = _inspect(app, args)
        assert original_inspection["success"] and original_inspection["receipt_digest"] is None, original_inspection
    else:
        args = bundle_arguments(tmp_path) | {"publication_version": "2.0"}
        if case == "planned":
            contract = app.publication_limits().payload["recovery_modes"]["commit_prepared"]["contract_bindings"][0]
            first = app.run("plan", contract_binding=contract,
                candidate={"operation_id":args["request_id"], "idempotency_key":args["request_id"],
                           "input_binding":"payload", "target_locator":args["target_locator"], "members":args["members"]},
                evidence_root=args["evidence_root"], run_id=args["run_id"],
                input_paths={"payload":args["source_root"]}, root_bindings={"phase_result_root":args["target_root"]}).payload
        else:
            first = app.publish_bundle(**args).payload
        assert first["success"], first
        assert _inspect(app, args)["success"] is True
        run = args["evidence_root"] / ".phase/runs" / args["run_id"]
    original = (run / "intent.json").read_bytes()
    before = _target_snapshot(args["target_root"])
    if case == "planned":
        path = run / "attachments/validator-results.json"
        previous = _raw_digest(path.read_bytes())
        value = json.loads(path.read_bytes())
        value[0]["actual"] = "coherently replaced pre-validator claim"
        path.write_bytes(canonical_bytes(value))
        receipt_path = run / "receipt.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["validator_results"] = value
        hashes = receipt["evidence"]["attachment_digests"]
        hashes[hashes.index(previous)] = _raw_digest(path.read_bytes())
        receipt_path.write_bytes(canonical_bytes(receipt))
    else:
        _tamper_preconditions(run, coherent_receipt=case == "receipt_without_effects")
        if case == "receipt_without_effects":
            receipt_path = run / "receipt.json"
            receipt = json.loads(receipt_path.read_bytes())
            receipt["effect_receipts"] = []
            receipt["evidence"]["attachment_digests"] = [
                _raw_digest((run / "attachments" / name).read_bytes())
                for name in ("effect-plan.json", "validator-results.json")
            ]
            receipt_path.write_bytes(canonical_bytes(receipt))
    if case == "receipt_without_effects":
        # Existing receipt schema already forbids claiming executed success
        # with no effect receipts; this is not an additional C1 defect.
        from jsonschema.exceptions import ValidationError
        with pytest.raises(ValidationError):
            validate_receipt(json.loads((run / "receipt.json").read_bytes()), app.registry)
        assert _target_snapshot(args["target_root"]) == before
        assert (run / "intent.json").read_bytes() == original
        return
    if (run / "receipt.json").exists():
        validate_receipt(json.loads((run / "receipt.json").read_bytes()), app.registry)
    result = _inspect(app, args)
    assert result["success"] is False, result
    assert result["error"] == "preconditions.digest_mismatch", result
    assert _target_snapshot(args["target_root"]) == before
    assert (run / "intent.json").read_bytes() == original
