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

NOW = "2026-07-29T12:00:00Z"
CONTRACT = "source_admission.v1"
FIXED_MTIME_NS = 1_800_000_000_000_000_000


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.utime(path, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS))


def write_input(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    os.utime(path, ns=(FIXED_MTIME_NS, FIXED_MTIME_NS))


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def blob_locator(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    return f"blobs/sha256/{digest[:2]}/{digest}"


def tree(root: Path) -> list[dict[str, object]]:
    if not root.exists():
        return []
    answer = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        data = path.read_bytes()
        answer.append({"path": path.relative_to(root).as_posix(), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return answer


def file_snapshot(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    if not path.is_file():
        return {"path": str(path), "exists": False, "length": None, "digest": None}
    data = path.read_bytes()
    return {"path": str(path), "exists": True, "length": len(data), "digest": sha(data)}


def read_json(path: Path) -> object | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def clear_directory_contents(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def binding(repo: Path, contract_id: str) -> str:
    registry = json.loads((repo / "src" / "phase_tool" / "data" / "registry.json").read_text(encoding="utf-8"))
    matches = [
        item
        for item in registry["entries"]
        if (
            item.get("kind") == "contract"
            and item.get("id") == contract_id
            and item.get("version") == "1.0.0"
            and item.get("current", True) is True
        )
    ]
    if len(matches) != 1:
        raise AssertionError(f"ambiguous contract binding: {contract_id}: {len(matches)} current entries")
    return str(matches[0]["package_digest"])


def source_candidate(
    *, payload: bytes, logical_id: str, operation_id: str, filename: str | None = "manual.txt",
    expected_digest: str | None | object = ..., expected_length: int | None | object = ...,
) -> dict[str, object]:
    digest = sha(payload) if expected_digest is ... else expected_digest
    length = len(payload) if expected_length is ... else expected_length
    return {
        "candidate_version": "1.0",
        "contract": {"id": CONTRACT, "version": "1.0.0"},
        "operation_id": operation_id,
        "idempotency_key": operation_id,
        "logical_source_id": logical_id,
        "asset_input": {"binding_id": "asset", "expected_digest": digest, "expected_length": length},
        "declared_media_type": "text/plain",
        "original_filename": filename,
        "provenance": {
            "provenance_version": "1.0",
            "origin": {"kind": "external_uri", "locator": "https://example.invalid/source", "label": "acceptance fixture"},
            "supplied_by": {"kind": "adapter", "identifier": "adapter.acceptance"},
        },
        "placement": {"target_root_binding": "admission_result_root", "namespace": "acceptance"},
        "supersedes": None,
        "request_metadata": {"submitted_by": "adapter.acceptance", "correlation_id": operation_id},
    }


def run_process(argv: list[str], env: dict[str, str]) -> dict[str, Any]:
    process = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"non-JSON command output: rc={process.returncode} argv={argv!r} stdout={process.stdout!r} stderr={process.stderr!r}") from exc
    value["_returncode"] = process.returncode
    value["_stderr"] = process.stderr
    value["_argv"] = argv
    return value


def artifacts(evidence: Path, run_id: str | None) -> dict[str, object] | None:
    if run_id is None:
        return None
    root = evidence / ".phase" / "runs" / run_id
    if not root.exists():
        return None
    receipt = read_json(root / "receipt.json")
    plan = read_json(root / "attachments" / "effect-plan.json")
    progress = read_json(root / "attachments" / "ordered-effect-progress.json")
    effects = read_json(root / "attachments" / "effect-receipts.json")
    intent = read_json(root / "intent.json")
    canonical = receipt.get("canonical_result") if isinstance(receipt, dict) else None
    return {
        "intent": intent,
        "effect_plan": plan,
        "ordered_effect_progress": progress,
        "effect_receipts": effects,
        "receipt": receipt,
        "canonical_result": canonical,
        "files": tree(root),
    }


def helper_text() -> str:
    return r'''from __future__ import annotations
import argparse, json
from pathlib import Path
from phase_tool.canonical import profile_digest
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.inspection import inspect_run
from phase_tool.mutation import BrokerFaults

NOW = "2026-07-29T12:00:00Z"

def emit(command, outcome):
    receipt = outcome.receipt
    value = {
        "stage3_command_result_version": "1.0", "command": command,
        "success": outcome.exit_code == 0, "run_id": outcome.run_id,
        "terminal_status": receipt["terminal_status"],
        "execution_disposition": receipt["execution_disposition"],
        "mutation_attempted": receipt["mutation_attempted"],
        "effect_plan_digest": outcome.effect_plan_digest,
        "intent_digest": profile_digest("intent", outcome.intent) if outcome.intent else None,
        "receipt_digest": outcome.receipt_digest, "target_verified": None,
        "blockers": receipt["blockers"], "error": None if outcome.exit_code == 0 else receipt["blockers"][0],
        "exit_code": outcome.exit_code,
    }
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    raise SystemExit(outcome.exit_code)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("scenario", choices=["inspect_result", "tamper_plan", "effect0_failure", "effect1_failure", "descriptor_conflict"])
    p.add_argument("--candidate", type=Path, required=True); p.add_argument("--payload", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True); p.add_argument("--target", type=Path, required=True)
    p.add_argument("--run-id", required=True); p.add_argument("--contract-digest", required=True)
    a = p.parse_args()
    if a.scenario == "inspect_result":
        result = inspect_run(a.evidence, a.run_id, root_bindings={"admission_result_root": a.target})
        print(json.dumps({"command": "helper.inspect_result", **result}, sort_keys=True, separators=(",", ":")))
        raise SystemExit(0)
    request = PhaseRequest(contract_id="source_admission.v1", contract_version="1.0.0", contract_digest=a.contract_digest,
        candidate_path=a.candidate, evidence_root=a.evidence, run_id=a.run_id, input_paths={"asset": a.payload},
        root_bindings={"admission_result_root": a.target}, timestamp=NOW)
    faults = None
    if a.scenario == "tamper_plan":
        faults = CoreFaults(broker=BrokerFaults(mutate_plan_after_intent=True))
    elif a.scenario == "effect0_failure":
        faults = CoreFaults(broker=BrokerFaults(content_addressed_copy_fail_after_bytes=2))
    elif a.scenario == "effect1_failure":
        def corrupt(intent_path):
            plan = json.loads((intent_path.parent / "attachments" / "effect-plan.json").read_text(encoding="utf-8"))
            digest = plan["effects"][1]["content_blob_digest"]
            (intent_path.parent / "blobs" / digest.split(":", 1)[1]).write_bytes(b"corrupt descriptor blob")
        faults = CoreFaults(broker=BrokerFaults(before_effect={1: corrupt}))
    else:
        def conflict(intent_path):
            plan = json.loads((intent_path.parent / "attachments" / "effect-plan.json").read_text(encoding="utf-8"))
            path = a.target.joinpath(*plan["effects"][1]["target"]["relative_locator"].split("/"))
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"conflicting descriptor")
        faults = CoreFaults(broker=BrokerFaults(before_effect={1: conflict}))
    emit("helper." + a.scenario, PhaseCore().run(request, execute=True, faults=faults))

if __name__ == "__main__": main()
'''


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage 6 real CLI acceptance harness")
    parser.add_argument("--tmp-root", type=Path, default=Path(".stage6-tmp") / "final-cli")
    parser.add_argument("--phase", type=Path)
    parser.add_argument("--python", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    root = args.tmp_root.resolve()
    allowed = (repo / ".stage6-tmp").resolve()
    try:
        root.relative_to(allowed)
    except ValueError as exc:
        raise AssertionError("--tmp-root must be inside repository .stage6-tmp") from exc
    if root == allowed:
        raise AssertionError("refusing to recreate .stage6-tmp itself; use a child such as final-cli")
    root.mkdir(parents=True, exist_ok=True)
    target, evidence = root / "target", root / "evidence"
    payloads, candidates = root / "payloads", root / "candidates"
    preserved = {target, evidence, payloads, candidates}
    for child in root.iterdir():
        if child in preserved:
            clear_directory_contents(child)
        elif child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for child in preserved:
        child.mkdir(exist_ok=True)
    # Legacy append mechanisms require their bounded parent to pre-exist.
    for child in ("objects", "streams", "tasks"):
        (target / child).mkdir()
    env = os.environ.copy(); env.pop("PYTHONPATH", None)
    phase = [str(args.phase.resolve())] if args.phase is not None else [sys.executable, "-m", "phase_tool"]
    python = str(args.python.resolve()) if args.python is not None else sys.executable
    helper = root / "helpers" / "stage6_helper.py"
    helper.parent.mkdir(); helper.write_text(helper_text(), encoding="utf-8")
    source_binding = binding(repo, CONTRACT)
    matrix: dict[str, dict[str, Any]] = {}
    failures: dict[str, list[object]] = {}

    def common(contract_id: str, candidate: Path, run_id: str, payload: Path | None = None) -> list[str]:
        root_name = "admission_result_root" if contract_id == CONTRACT else ("task_journal_root" if contract_id == "task_journal.v1" else "fixture_result_root")
        result = ["--contract-id", contract_id, "--contract-version", "1.0.0", "--contract-digest", binding(repo, contract_id),
                  "--candidate", str(candidate), "--evidence-root", str(evidence), "--run-id", run_id,
                  "--root", f"{root_name}={target}", "--timestamp", NOW]
        if payload is not None: result += ["--input", f"asset={payload}" if contract_id == CONTRACT else f"payload={payload}"]
        return result

    def record(name: str, result: dict[str, Any], run_id: str | None, before: list[dict[str, object]], after: list[dict[str, object]],
               expect: dict[str, Any], source_before: object = None, source_after: object = None) -> None:
        art = artifacts(evidence, run_id)
        scenario = {
            "command": result.get("command"), "argv": result["_argv"], "exit": result["_returncode"],
            "terminal_status": result.get("terminal_status"), "disposition": result.get("execution_disposition"),
            "mutation_attempted": result.get("mutation_attempted"), "blockers": result.get("blockers", []),
            "plan": art.get("effect_plan") if art else None, "progress": art.get("ordered_effect_progress") if art else None,
            "effect_receipts": art.get("effect_receipts") if art else None, "receipt": art.get("receipt") if art else None,
            "artifacts": art, "target_tree_before": before, "target_tree_after": after,
            "source_before": source_before, "source_after": source_after, "envelope": result, "expect": expect,
        }
        matrix[name] = scenario
        for field in ("exit", "terminal_status", "disposition", "mutation_attempted"):
            if field in expect and scenario.get(field) != expect[field]:
                failures.setdefault(name, []).append({"field": field, "expected": expect[field], "actual": scenario.get(field)})
        if "blocker" in expect and expect["blocker"] not in scenario["blockers"]:
            failures.setdefault(name, []).append({"field": "blockers", "expected": expect["blocker"], "actual": scenario["blockers"]})
        if expect.get("unchanged") and before != after:
            failures.setdefault(name, []).append({"field": "target_tree", "expected": "unchanged"})
        if expect.get("source_unchanged") and source_before != source_after:
            failures.setdefault(name, []).append({"field": "source", "expected": "unchanged"})
        if "target_verified" in expect and result.get("target_verified") != expect["target_verified"]:
            failures.setdefault(name, []).append({"field": "target_verified", "expected": expect["target_verified"], "actual": result.get("target_verified")})

    def cli(name: str, command: str, argv: list[str], run_id: str | None, expect: dict[str, Any], payload: Path | None = None) -> dict[str, Any]:
        before = tree(target); sb = file_snapshot(payload)
        result = run_process([*phase, command, *argv], env)
        record(name, result, run_id, before, tree(target), expect, sb, file_snapshot(payload))
        return result

    def helper_run(name: str, scenario: str, candidate: Path, payload: Path, run_id: str, expect: dict[str, Any]) -> dict[str, Any]:
        before = tree(target); sb = file_snapshot(payload)
        result = run_process([python, str(helper), scenario, "--candidate", str(candidate), "--payload", str(payload),
                              "--evidence", str(evidence), "--target", str(target), "--run-id", run_id,
                              "--contract-digest", source_binding], env)
        record(name, result, run_id, before, tree(target), expect, sb, file_snapshot(payload))
        return result

    def source_files(stem: str, payload: bytes, logical: str, op: str, **changes: object) -> tuple[Path, Path]:
        payload_path = payloads / f"{stem}.bin"; write_input(payload_path, payload)
        value = source_candidate(payload=payload, logical_id=logical, operation_id=op, filename=changes.pop("filename", "manual.txt"))
        value.update(changes)
        candidate_path = candidates / f"{stem}.json"; write_json(candidate_path, value)
        return candidate_path, payload_path

    text = b"stage6 source text\n"
    c_text, p_text = source_files("text", text, "source-text", "op-text")
    cli("01_validate_source", "validate", common(CONTRACT, c_text, "source-validate", p_text), "source-validate", {"exit": 0, "terminal_status": "validated_planned", "disposition": "not_executed", "mutation_attempted": False, "unchanged": True, "source_unchanged": True}, p_text)
    cli("02_plan_source", "plan", common(CONTRACT, c_text, "source-plan", p_text), "source-plan", {"exit": 0, "terminal_status": "validated_planned", "disposition": "not_executed", "mutation_attempted": False, "unchanged": True, "source_unchanged": True}, p_text)
    cli("03_unchanged_target_validate", "validate", common(CONTRACT, c_text, "source-validate-unchanged", p_text), "source-validate-unchanged", {"exit": 0, "unchanged": True}, p_text)
    cli("04_unchanged_target_plan", "plan", common(CONTRACT, c_text, "source-plan-unchanged", p_text), "source-plan-unchanged", {"exit": 0, "unchanged": True}, p_text)
    cli("05_execute_text", "execute", common(CONTRACT, c_text, "source-execute", p_text), "source-execute", {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True, "source_unchanged": True}, p_text)
    cli("06_inspect_run_descriptor_blob", "inspect", ["--evidence-root", str(evidence), "--run-id", "source-execute", "--root", f"admission_result_root={target}"], "source-execute", {"exit": 0, "target_verified": True})
    helper_run("06b_inspect_contract_result", "inspect_result", c_text, p_text, "source-execute", {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True, "target_verified": True})
    cli("07_same_operation_same_request_reuse", "execute", common(CONTRACT, c_text, "source-reuse", p_text), "source-reuse", {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "reused_existing", "mutation_attempted": False, "unchanged": True}, p_text)

    c, p = source_files("same-op-conflict", text, "source-text", "op-text")
    changed_request = json.loads(c.read_text(encoding="utf-8"))
    changed_request["request_metadata"]["submitted_by"] = "adapter.other"
    write_json(c, changed_request)
    cli("08_same_operation_different_request_conflict", "execute", common(CONTRACT, c, "same-op-conflict", p), "same-op-conflict", {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "idempotency.same_key_conflict", "unchanged": True}, p)
    c, p = source_files("logical-conflict", b"different logical content", "source-text", "op-logical-conflict")
    cli("09_same_logical_different_content_conflict", "execute", common(CONTRACT, c, "logical-conflict", p), "logical-conflict", {"exit": 10, "terminal_status": "rejected", "mutation_attempted": False, "blocker": "source.logical_identity_conflict", "unchanged": True}, p)
    c, p = source_files("filename-a", b"same filename bytes", "source-filename-a", "op-filename-a", filename="a.txt")
    cli("10_same_bytes_filename_baseline", "execute", common(CONTRACT, c, "filename-a", p), "filename-a", {"exit": 0, "terminal_status": "succeeded_verified"}, p)
    c, p = source_files("filename-b", b"same filename bytes", "source-filename-b", "op-filename-b", filename="b.txt")
    cli("11_same_bytes_different_filename", "execute", common(CONTRACT, c, "filename-b", p), "filename-b", {"exit": 0, "terminal_status": "succeeded_verified"}, p)
    c, p = source_files("logical-a", b"same logical bytes", "source-logical-a", "op-logical-a")
    cli("12_same_bytes_logical_baseline", "execute", common(CONTRACT, c, "logical-a", p), "logical-a", {"exit": 0}, p)
    c, p = source_files("logical-b", b"same logical bytes", "source-logical-b", "op-logical-b")
    cli("13_same_bytes_different_logical_id", "execute", common(CONTRACT, c, "logical-b", p), "logical-b", {"exit": 0}, p)

    recovery = b"existing blob missing descriptor"
    (target / blob_locator(recovery)).parent.mkdir(parents=True, exist_ok=True); (target / blob_locator(recovery)).write_bytes(recovery)
    c, p = source_files("recovery", recovery, "source-recovery", "op-recovery")
    cli("14_existing_blob_missing_descriptor_recovery", "execute", common(CONTRACT, c, "recovery", p), "recovery", {"exit": 0, "terminal_status": "succeeded_verified"}, p)
    c, p = source_files("descriptor-conflict", b"descriptor conflict payload", "source-partial", "op-partial")
    helper_run("15_unsafe_descriptor_callback_rejected", "descriptor_conflict", c, p, "descriptor-conflict", {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "broker.unsafe_fault_callback", "unchanged": True})
    c, p = source_files("binary", bytes([0, 1, 2, 253, 254, 255]), "source-binary", "op-binary")
    cli("16_binary", "execute", common(CONTRACT, c, "binary", p), "binary", {"exit": 0}, p)
    c, p = source_files("empty", b"", "source-empty", "op-empty")
    cli("17_empty", "execute", common(CONTRACT, c, "empty", p), "empty", {"exit": 0}, p)
    c, p = source_files("unsafe", b"unsafe", "../unsafe", "op-unsafe")
    cli("18_unsafe_logical_id", "execute", common(CONTRACT, c, "unsafe", p), "unsafe", {"exit": 10, "terminal_status": "rejected", "mutation_attempted": False, "blocker": "path.traversal", "unchanged": True}, p)
    c, p = source_files("digest-mismatch", b"digest mismatch", "source-digest-mismatch", "op-digest-mismatch")
    value = json.loads(c.read_text(encoding="utf-8")); value["asset_input"]["expected_digest"] = sha(b"not the payload"); write_json(c, value)
    cli("19_digest_mismatch", "execute", common(CONTRACT, c, "digest-mismatch", p), "digest-mismatch", {"exit": 10, "terminal_status": "rejected", "blocker": "source.expected_digest_mismatch", "unchanged": True}, p)
    c, p = source_files("bad-provenance", b"bad provenance", "source-bad-provenance", "op-bad-provenance")
    value = json.loads(c.read_text(encoding="utf-8")); value["provenance"] = {"provenance_version": "1.0", "origin": "malformed"}; write_json(c, value)
    cli("20_malformed_provenance", "execute", common(CONTRACT, c, "bad-provenance", p), "bad-provenance", {"exit": 10, "terminal_status": "rejected", "blocker": "candidate.schema_invalid", "unchanged": True}, p)
    c, p = source_files("tamper", b"ordered plan tamper", "source-tamper", "op-tamper")
    helper_run("21_ordered_plan_tampering", "tamper_plan", c, p, "tamper", {"exit": 10, "terminal_status": "rejected", "mutation_attempted": False, "blocker": "broker.plan_changed_after_intent", "unchanged": True})
    c, p = source_files("effect0", b"effect zero failure", "source-effect0", "op-effect0")
    helper_run("22_effect0_failure_effect1_not_started", "effect0_failure", c, p, "effect0", {"exit": 30, "terminal_status": "failed_partial", "mutation_attempted": True, "blocker": "mechanism.write_failed"})
    c, p = source_files("effect1", b"effect one failure", "source-effect1", "op-effect1")
    helper_run("23_unsafe_effect_callback_rejected", "effect1_failure", c, p, "effect1", {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "broker.unsafe_fault_callback", "unchanged": True})

    create_payload = payloads / "create.bin"; write_input(create_payload, b"create")
    create = candidates / "create.json"; write_json(create, {"operation_id": "create-6", "target_locator": "objects/create-6.bin", "input_binding": "payload", "idempotency_key": "create-6"})
    cli("24_fixture_create_regression", "execute", common("fixture_create.v1", create, "fixture-create", create_payload), "fixture-create", {"exit": 0}, create_payload)
    append = candidates / "append.json"; write_json(append, {"stream_id": "stage6", "target_locator": "streams/stage6.jsonl", "record_id": "r6", "expected_head": None, "record": {"stage": 6}, "idempotency_key": "append-6"})
    cli("25_fixture_append_regression", "execute", common("fixture_append.v1", append, "fixture-append"), "fixture-append", {"exit": 0})
    copy_payload = payloads / "copy.bin"; write_input(copy_payload, b"copy regression")
    copy = candidates / "copy.json"; write_json(copy, {"transfer_id": "copy-6", "object_id": "copy-6", "input_binding": "payload", "destinations": ["objects/copy-6.bin"], "idempotency_key": "copy-6"})
    cli("26_fixture_copy_regression", "execute", common("fixture_copy.v1", copy, "fixture-copy", copy_payload), "fixture-copy", {"exit": 0}, copy_payload)
    task = candidates / "task.json"; write_json(task, {"task_id": "task-6", "action": "open", "expected_head": None, "idempotency_key": "task-6", "operation_id": "task-6", "original_instruction": "Stage 6 acceptance"})
    cli("27_task_journal_regression", "execute", common("task_journal.v1", task, "task-journal"), "task-journal", {"exit": 0})
    knowledge_args = [
        "--contract-id", "knowledge_admission.v1", "--contract-version", "1.0.0",
        "--contract-digest", "sha256:" + "0" * 64, "--candidate", str(c_text),
        "--evidence-root", str(evidence), "--run-id", "knowledge-unavailable",
        "--root", f"admission_result_root={target}", "--timestamp", NOW,
    ]
    cli("28_knowledge_execute_unavailable", "execute", knowledge_args, "knowledge-unavailable", {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "registry.entry_not_found", "unchanged": True})

    # Cross-scenario semantic assertions and structured inspection.
    execution = matrix["05_execute_text"]["artifacts"]
    assert isinstance(execution, dict)
    receipt = execution["receipt"]; plan = execution["effect_plan"]; progress = execution["ordered_effect_progress"]
    canonical = receipt["canonical_result"]
    descriptor_path = target.joinpath(*canonical["locator"].split("/"))
    descriptor_bytes = descriptor_path.read_bytes(); descriptor = json.loads(descriptor_bytes)
    blob_path = target.joinpath(*descriptor["blob_locator"].split("/")); blob_bytes = blob_path.read_bytes()
    contract_inspection = matrix["06b_inspect_contract_result"]["envelope"]["contract_result"]
    inspection = {
        "run_id": "source-execute", "descriptor": descriptor,
        "descriptor_path": str(descriptor_path), "descriptor_digest": sha(descriptor_bytes), "descriptor_length": len(descriptor_bytes),
        "blob_path": str(blob_path), "blob_digest": sha(blob_bytes), "blob_length": len(blob_bytes),
        "source_result_id": descriptor["source_result_id"],
        "source_result": descriptor,
        "source_result_reference": contract_inspection["reference"],
        "source_result_binding": contract_inspection["binding"],
    }
    checks = {
        "py_subprocess_path_absent": "PYTHONPATH" not in env,
        "text_plan_ordered": [e["effect_id"] for e in plan["effects"]] == ["effect.0.blob", "effect.1.descriptor"],
        "text_progress_complete": progress["completed_effect_ids"] == ["effect.0.blob", "effect.1.descriptor"] and progress["not_started_effect_ids"] == [],
        "intent_before_effect": execution["intent"] is not None and execution["effect_receipts"] is not None,
        "text_source_unchanged": matrix["05_execute_text"]["source_before"] == matrix["05_execute_text"]["source_after"],
        "reuse_no_overwrite": matrix["07_same_operation_same_request_reuse"]["target_tree_before"] == matrix["07_same_operation_same_request_reuse"]["target_tree_after"],
        "recovery_blob_reused": matrix["14_existing_blob_missing_descriptor_recovery"]["effect_receipts"][0]["bytes_written"] == 0,
        "recovery_descriptor_created": matrix["14_existing_blob_missing_descriptor_recovery"]["effect_receipts"][1]["bytes_written"] > 0,
        "descriptor_callback_rejected_before_effect": matrix["15_unsafe_descriptor_callback_rejected"]["progress"] is None,
        "effect0_blocks_effect1": matrix["22_effect0_failure_effect1_not_started"]["progress"]["not_started_effect_ids"] == ["effect.1.descriptor"],
        "effect_callback_rejected_before_effect": matrix["23_unsafe_effect_callback_rejected"]["progress"] is None,
        "descriptor_binds_blob": descriptor["content_digest"] == sha(blob_bytes) and descriptor["content_length"] == len(blob_bytes),
        "same_bytes_blob_reuse": matrix["11_same_bytes_different_filename"]["effect_receipts"][0]["bytes_written"] == 0,
        "different_filename_result_id": matrix["10_same_bytes_filename_baseline"]["receipt"]["canonical_result"]["locator"] != matrix["11_same_bytes_different_filename"]["receipt"]["canonical_result"]["locator"],
        "different_logical_result_id": matrix["12_same_bytes_logical_baseline"]["receipt"]["canonical_result"]["locator"] != matrix["13_same_bytes_different_logical_id"]["receipt"]["canonical_result"]["locator"],
        "inspection_result_reference_binding": set(contract_inspection) == {"reference", "binding"}
        and contract_inspection["reference"]["descriptor_digest"] == sha(descriptor_bytes)
        and contract_inspection["binding"]["source_descriptor_digest"] == sha(descriptor_bytes),
        "knowledge_not_registered": "registry.entry_not_found" in matrix["28_knowledge_execute_unavailable"]["blockers"],
    }
    for name, ok in checks.items():
        if not ok: failures.setdefault("summary_checks", []).append(name)
    if len(matrix) < 27: failures.setdefault("scenario_count", []).append(len(matrix))
    summary = {
        "success": not failures, "scenario_count": len(matrix), "command_order": list(matrix), "command_exit_matrix": {k: {"command": v["command"], "exit": v["exit"]} for k, v in matrix.items()},
        "statuses_dispositions": {k: {"status": v["terminal_status"], "disposition": v["disposition"], "mutation_attempted": v["mutation_attempted"]} for k, v in matrix.items()},
        "command_matrix": matrix, "checks": checks, "inspection": inspection,
        "text_result": {"content_digest": descriptor["content_digest"], "content_length": descriptor["content_length"], "blob_locator": descriptor["blob_locator"], "descriptor_locator": descriptor["descriptor_locator"], "source_result_id": descriptor["source_result_id"]},
        "target_tree": tree(target), "evidence_tree": tree(evidence), "failures": failures,
        "helper_note": "Controlled helpers invoke real PhaseCore/EvidenceStore/EffectBroker; callable fault scenarios verify fail-before-callback rejection and never inject production mutations.",
    }
    summary_path = root / "stage6-cli-acceptance-summary.json"
    write_json(summary_path, summary)
    print(json.dumps({"success": not failures, "scenario_count": len(matrix), "summary": str(summary_path)}, sort_keys=True, separators=(",", ":")))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
