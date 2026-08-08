from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from phase_tool.paths import _platform_path

NOW = "2026-07-29T12:00:00Z"
SOURCE_CONTRACT = "source_admission.v1"
KNOWLEDGE_CONTRACT = "knowledge_admission.v1"
FIXED_MTIME_NS = 1_800_000_000_000_000_000


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.utime(path, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS))


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    os.utime(path, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS))


def sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def read_target_bytes(path: Path) -> bytes:
    with open(_platform_path(path), "rb") as stream:
        return stream.read()


def registry_binding(repo: Path, contract_id: str) -> str:
    registry = json.loads((repo / "src" / "phase_tool" / "data" / "registry.json").read_text(encoding="utf-8"))
    matches = [
        entry
        for entry in registry["entries"]
        if (
            entry.get("kind") == "contract"
            and entry.get("id") == contract_id
            and entry.get("version") == "1.0.0"
            and entry.get("current", True) is True
        )
    ]
    if len(matches) != 1:
        raise AssertionError(f"ambiguous contract binding: {contract_id}: {len(matches)} current entries")
    return str(matches[0]["package_digest"])


def source_candidate(payload: bytes) -> dict[str, object]:
    return {
        "candidate_version": "1.0",
        "contract": {"id": SOURCE_CONTRACT, "version": "1.0.0"},
        "operation_id": "stage7-source-operation",
        "idempotency_key": "stage7-source-operation",
        "logical_source_id": "stage7-source",
        "asset_input": {"binding_id": "asset", "expected_digest": sha(payload), "expected_length": len(payload)},
        "declared_media_type": "text/plain",
        "original_filename": "stage7-source.txt",
        "provenance": {
            "provenance_version": "1.0",
            "origin": {"kind": "external_uri", "locator": "https://example.invalid/stage7-source", "label": "Stage 7 acceptance source"},
            "supplied_by": {"kind": "adapter", "identifier": "adapter.stage7.acceptance"},
        },
        "placement": {"target_root_binding": "admission_result_root", "namespace": "acceptance"},
        "supersedes": None,
        "request_metadata": {"submitted_by": "adapter.stage7.acceptance", "correlation_id": "stage7-source-operation"},
    }


def knowledge_candidate(artifact: bytes, source_binding: dict[str, object], *, operation_id: str, logical_id: str = "stage7-knowledge", producer: str = "producer.stage7.acceptance") -> dict[str, object]:
    return {
        "candidate_version": "1.0",
        "contract": {"id": KNOWLEDGE_CONTRACT, "version": "1.0.0"},
        "operation_id": operation_id,
        "idempotency_key": operation_id,
        "logical_knowledge_id": logical_id,
        "artifact_input": {"binding_id": "asset", "expected_digest": sha(artifact), "expected_length": len(artifact)},
        "artifact_kind": "document",
        "artifact_format": "application/json",
        "provenance": {
            "provenance_version": "1.0",
            "source_bindings": [source_binding],
            "producer": {"kind": "tool", "identifier": producer, "version": "1.0.0"},
            "transformation": {"identifier": "transform.stage7.acceptance", "version": "1.0.0", "parameters_digest": sha(b"stage7-parameters")},
        },
        "placement": {"target_root_binding": "admission_result_root", "namespace": "acceptance"},
        "supersedes": None,
        "request_metadata": {"submitted_by": "adapter.stage7.acceptance", "correlation_id": operation_id},
    }


def run_json(argv: list[str], env: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"non-JSON CLI output: rc={completed.returncode} argv={argv!r} stdout={completed.stdout!r} stderr={completed.stderr!r}") from exc
    result["_returncode"] = completed.returncode
    result["_stderr"] = completed.stderr
    result["_argv"] = argv
    return result


def target_tree(root: Path) -> list[dict[str, object]]:
    if not root.exists():
        return []
    result = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        data = read_target_bytes(path)
        result.append({"path": path.relative_to(root).as_posix(), "length": len(data), "digest": sha(data)})
    return result


def helper_text() -> str:
    return r'''from __future__ import annotations
import argparse, json
from pathlib import Path
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.mutation import BrokerFaults
from phase_tool.paths import _platform_path

NOW = "2026-07-29T12:00:00Z"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["descriptor_conflict", "effect0_failure"])
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--contract-digest", required=True)

    args = parser.parse_args()
    request = PhaseRequest(contract_id="knowledge_admission.v1", contract_version="1.0.0", contract_digest=args.contract_digest,
        candidate_path=args.candidate, evidence_root=args.evidence, run_id=args.run_id,
        input_paths={"asset": args.artifact}, root_bindings={"admission_result_root": args.target}, timestamp=NOW)
    if args.scenario == "effect0_failure":
        faults = CoreFaults(broker=BrokerFaults(content_addressed_copy_fail_after_bytes=2))
    elif args.scenario == "descriptor_conflict":
        def conflict(intent_path):
            plan = json.loads((intent_path.parent / "attachments" / "effect-plan.json").read_text(encoding="utf-8"))
            destination = args.target.joinpath(*plan["effects"][1]["target"]["relative_locator"].split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            with open(_platform_path(destination), "wb") as stream:
                stream.write(b"stage7 conflicting descriptor")
        faults = CoreFaults(broker=BrokerFaults(before_effect={1: conflict}))

    outcome = PhaseCore().run(request, execute=True, faults=faults)
    receipt = outcome.receipt
    print(json.dumps({"command": "helper." + args.scenario, "success": outcome.exit_code == 0,
        "run_id": outcome.run_id, "terminal_status": receipt["terminal_status"],
        "execution_disposition": receipt["execution_disposition"], "mutation_attempted": receipt["mutation_attempted"],
        "blockers": receipt["blockers"], "exit_code": outcome.exit_code,
        "receipt_digest": outcome.receipt_digest}, sort_keys=True, separators=(",", ":")))
    raise SystemExit(outcome.exit_code)

if __name__ == "__main__": main()
'''


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage 7 real CLI acceptance harness")
    parser.add_argument("--tmp-root", type=Path, default=Path(".stage7-tmp") / "final-cli")
    parser.add_argument("--phase", type=Path)
    parser.add_argument("--python", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    root = args.tmp_root.resolve()
    allowed = (repo / ".stage7-tmp").resolve()
    try:
        root.relative_to(allowed)
    except ValueError as exc:
        raise AssertionError("--tmp-root must be inside repository .stage7-tmp") from exc
    if root == allowed:
        raise AssertionError("use a child of .stage7-tmp")
    if root.exists() or os.path.lexists(_platform_path(root)):
        shutil.rmtree(_platform_path(root))
    root.mkdir(parents=True)
    target, evidence = root / "target", root / "evidence"
    candidates, payloads = root / "candidates", root / "payloads"
    for path in (target, evidence, candidates, payloads):
        path.mkdir()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    phase = [str(args.phase.resolve())] if args.phase is not None else [sys.executable, "-m", "phase_tool"]
    python = str(args.python.resolve()) if args.python is not None else sys.executable
    source_digest = registry_binding(repo, SOURCE_CONTRACT)
    knowledge_digest = registry_binding(repo, KNOWLEDGE_CONTRACT)
    matrix: dict[str, dict[str, Any]] = {}
    failures: dict[str, list[object]] = {}

    def common(contract_id: str, digest: str, candidate: Path, asset: Path, run_id: str) -> list[str]:
        return ["--contract-id", contract_id, "--contract-version", "1.0.0", "--contract-digest", digest,
            "--candidate", str(candidate), "--evidence-root", str(evidence), "--run-id", run_id,
            "--input", f"asset={asset}", "--root", f"admission_result_root={target}", "--timestamp", NOW]

    def record(name: str, result: dict[str, Any], before: list[dict[str, object]], expect: dict[str, Any]) -> None:
        scenario = {"command": result.get("command"), "argv": result["_argv"], "exit": result["_returncode"],
            "terminal_status": result.get("terminal_status"), "disposition": result.get("execution_disposition"),
            "mutation_attempted": result.get("mutation_attempted"), "blockers": result.get("blockers", []),
            "target_before": before, "target_after": target_tree(target), "envelope": result, "expect": expect}
        matrix[name] = scenario
        for field in ("exit", "terminal_status", "disposition", "mutation_attempted"):
            if field in expect and scenario[field] != expect[field]:
                failures.setdefault(name, []).append({"field": field, "expected": expect[field], "actual": scenario[field]})
        if "blocker" in expect and expect["blocker"] not in scenario["blockers"]:
            failures.setdefault(name, []).append({"field": "blockers", "expected": expect["blocker"], "actual": scenario["blockers"]})
        if expect.get("unchanged") and scenario["target_before"] != scenario["target_after"]:
            failures.setdefault(name, []).append({"field": "target", "expected": "unchanged"})
        if "target_verified" in expect and result.get("target_verified") != expect["target_verified"]:
            failures.setdefault(name, []).append({"field": "target_verified", "expected": expect["target_verified"], "actual": result.get("target_verified")})

    def cli(name: str, command: str, argv: list[str], expect: dict[str, Any]) -> dict[str, Any]:
        before = target_tree(target)
        result = run_json([*phase, command, *argv], env)
        record(name, result, before, expect)
        return result

    source_bytes = b"Stage 7 exact source bytes\n"
    source_path, source_candidate_path = payloads / "source.txt", candidates / "source.json"
    write_bytes(source_path, source_bytes)
    write_json(source_candidate_path, source_candidate(source_bytes))
    source_execution = cli("01_source_bootstrap", "execute", common(SOURCE_CONTRACT, source_digest, source_candidate_path, source_path, "stage7-source"),
        {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})
    source_inspection = cli("02_source_inspect", "inspect", ["--evidence-root", str(evidence), "--run-id", "stage7-source", "--root", f"admission_result_root={target}"],
        {"exit": 0, "terminal_status": "succeeded_verified", "target_verified": True})
    source_receipt = json.loads((evidence / ".phase" / "runs" / "stage7-source" / "receipt.json").read_text(encoding="utf-8"))
    source_reference = source_receipt["canonical_result"]
    source_descriptor_path = target.joinpath(*source_reference["locator"].split("/"))
    source_descriptor_bytes = read_target_bytes(source_descriptor_path)
    source_descriptor = json.loads(source_descriptor_bytes)
    source_binding = {
        "binding_version": "1.0",
        "source_result_id": source_descriptor["source_result_id"],
        "logical_source_id": source_descriptor["logical_source_id"],
        "source_content_digest": source_descriptor["content_digest"],
        "source_blob_locator": source_descriptor["blob_locator"],
        "source_descriptor_digest": sha(source_descriptor_bytes),
        "source_descriptor_locator": source_descriptor["descriptor_locator"],
        "source_contract": {"id": SOURCE_CONTRACT, "version": "1.0.0"},
        "source_phase_receipt": {"run_id": "stage7-source", "receipt_digest": source_execution["receipt_digest"]},
    }

    artifact = b'{"stage":7,"status":"accepted"}\n'
    artifact_path, candidate_path = payloads / "knowledge.json", candidates / "knowledge.json"
    write_bytes(artifact_path, artifact)
    write_json(candidate_path, knowledge_candidate(artifact, source_binding, operation_id="stage7-knowledge-operation"))
    cli("03_validate_knowledge", "validate", common(KNOWLEDGE_CONTRACT, knowledge_digest, candidate_path, artifact_path, "knowledge-validate"),
        {"exit": 0, "terminal_status": "validated_planned", "disposition": "not_executed", "mutation_attempted": False, "unchanged": True})
    cli("04_plan_knowledge", "plan", common(KNOWLEDGE_CONTRACT, knowledge_digest, candidate_path, artifact_path, "knowledge-plan"),
        {"exit": 0, "terminal_status": "validated_planned", "disposition": "not_executed", "mutation_attempted": False, "unchanged": True})
    execution = cli("05_execute_knowledge", "execute", common(KNOWLEDGE_CONTRACT, knowledge_digest, candidate_path, artifact_path, "knowledge-execute"),
        {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})
    inspection = cli("06_inspect_knowledge", "inspect", ["--evidence-root", str(evidence), "--run-id", "knowledge-execute", "--root", f"admission_result_root={target}"],
        {"exit": 0, "terminal_status": "succeeded_verified", "target_verified": True})
    cli("07_exact_reuse", "execute", common(KNOWLEDGE_CONTRACT, knowledge_digest, candidate_path, artifact_path, "knowledge-reuse"),
        {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "reused_existing", "mutation_attempted": False, "unchanged": True})

    changed = knowledge_candidate(b"changed", source_binding, operation_id="stage7-knowledge-operation")
    changed_path, changed_asset = candidates / "same-op-changed.json", payloads / "same-op-changed.bin"
    write_json(changed_path, changed); write_bytes(changed_asset, b"changed")
    cli("08_same_operation_different_request", "execute", common(KNOWLEDGE_CONTRACT, knowledge_digest, changed_path, changed_asset, "same-op-changed"),
        {"exit": 10, "terminal_status": "rejected", "mutation_attempted": False, "blocker": "idempotency.same_key_conflict", "unchanged": True})

    for name, value, blocker in (
        ("09_no_source_binding", knowledge_candidate(b"none", source_binding, operation_id="no-source", logical_id="no-source"), "candidate.schema_invalid"),
        ("10_untrusted_source_id_only", knowledge_candidate(b"id-only", source_binding, operation_id="id-only", logical_id="id-only"), "candidate.schema_invalid"),
    ):
        if name.startswith("09"):
            value["provenance"]["source_bindings"] = []
            payload = b"none"
        else:
            value["provenance"]["source_bindings"] = [{"source_result_id": source_binding["source_result_id"]}]
            payload = b"id-only"
        cp, ap = candidates / f"{name}.json", payloads / f"{name}.bin"
        write_json(cp, value); write_bytes(ap, payload)
        cli(name, "execute", common(KNOWLEDGE_CONTRACT, knowledge_digest, cp, ap, name),
            {"exit": 10, "terminal_status": "rejected", "mutation_attempted": False, "blocker": blocker, "unchanged": True})

    provenance_changed = knowledge_candidate(artifact, source_binding, operation_id="changed-provenance", producer="producer.changed")
    cp = candidates / "changed-provenance.json"; write_json(cp, provenance_changed)
    cli("11_same_logical_changed_provenance", "execute", common(KNOWLEDGE_CONTRACT, knowledge_digest, cp, artifact_path, "changed-provenance"),
        {"exit": 10, "terminal_status": "rejected", "mutation_attempted": False, "blocker": "knowledge.logical_identity_conflict", "unchanged": True})

    helper = root / "stage7_helper.py"; helper.write_text(helper_text(), encoding="utf-8")
    def helper_run(name: str, scenario: str, candidate_value: dict[str, object], payload: bytes, logical: str, expect: dict[str, Any]) -> None:
        cp, ap = candidates / f"{name}.json", payloads / f"{name}.bin"
        candidate_value["logical_knowledge_id"] = logical
        write_json(cp, candidate_value); write_bytes(ap, payload)
        argv = [python, str(helper), scenario, "--candidate", str(cp), "--artifact", str(ap), "--evidence", str(evidence),
            "--target", str(target), "--run-id", name, "--contract-digest", knowledge_digest]
        before = target_tree(target); result = run_json(argv, env); record(name, result, before, expect)

    helper_run("12_effect0_failure", "effect0_failure", knowledge_candidate(b"effect0", source_binding, operation_id="effect0", logical_id="effect0"), b"effect0", "effect0",
        {"exit": 30, "terminal_status": "failed_partial", "mutation_attempted": True, "blocker": "mechanism.write_failed"})
    helper_run("13_unsafe_descriptor_callback_rejected", "descriptor_conflict", knowledge_candidate(b"effect1", source_binding, operation_id="effect1", logical_id="effect1"), b"effect1", "effect1",
        {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "broker.unsafe_fault_callback", "unchanged": True})

    knowledge_receipt = json.loads((evidence / ".phase" / "runs" / "knowledge-execute" / "receipt.json").read_text(encoding="utf-8"))
    canonical = knowledge_receipt["canonical_result"]
    descriptor_path = target.joinpath(*canonical["locator"].split("/"))
    descriptor_bytes = read_target_bytes(descriptor_path); descriptor = json.loads(descriptor_bytes)
    blob_path = target.joinpath(*descriptor["blob_locator"].split("/")); blob_bytes = read_target_bytes(blob_path)
    checks = {
        "pythonpath_removed": "PYTHONPATH" not in env,
        "exact_binding": knowledge_digest.startswith("sha256:") and len(knowledge_digest) == 71,
        "target_verified": inspection["target_verified"] is True,
        "platform_safe_descriptor_read": descriptor["descriptor_locator"] == canonical["locator"],
        "ordered_effects": [item["effect_id"] for item in json.loads((evidence / ".phase" / "runs" / "knowledge-execute" / "attachments" / "effect-plan.json").read_text())["effects"]] == ["effect.0.blob", "effect.1.descriptor"],
        "descriptor_binds_blob": descriptor["artifact_digest"] == sha(blob_bytes) and descriptor["artifact_length"] == len(blob_bytes),
        "source_binding_preserved": descriptor["provenance"]["source_bindings"] == [source_binding],
        "reference_receipt_link": descriptor["admission_run"]["run_id"] == "knowledge-execute" and inspection["receipt_digest"] == execution["receipt_digest"],
        "partial_effect0_truthful": matrix["12_effect0_failure"]["terminal_status"] == "failed_partial",
        "unsafe_descriptor_callback_rejected": matrix["13_unsafe_descriptor_callback_rejected"]["terminal_status"] == "rejected",
    }
    for name, value in checks.items():
        if not value:
            failures.setdefault("checks", []).append(name)
    summary = {
        "stage": 7,
        "contract": {"id": KNOWLEDGE_CONTRACT, "version": "1.0.0", "package_digest": knowledge_digest},
        "success": not failures,
        "scenario_count": len(matrix),
        "command_order": list(matrix),
        "command_matrix": matrix,
        "checks": checks,
        "failures": failures,
        "knowledge_result": {
            "knowledge_result_id": descriptor["knowledge_result_id"],
            "artifact_digest": descriptor["artifact_digest"],
            "blob_locator": descriptor["blob_locator"],
            "descriptor_locator": descriptor["descriptor_locator"],
            "descriptor_digest": sha(descriptor_bytes),
            "receipt_digest": inspection["receipt_digest"],
            "descriptor_path_length": len(str(descriptor_path)),
        },
        "inspection": inspection,
        "target_tree": target_tree(target),
        "helper_note": "Fault-only helpers invoke the same PhaseCore, EvidenceStore and EffectBroker; callable faults verify fail-before-callback rejection without injecting production mutations.",
    }
    summary_path = root / "stage7-cli-acceptance-summary.json"
    write_json(summary_path, summary)
    print(json.dumps({"success": not failures, "scenario_count": len(matrix), "summary": str(summary_path)}, sort_keys=True, separators=(",", ":")))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
