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

NOW = "2026-07-27T06:00:00Z"
REQUIRED_SCENARIO_FIELDS = {
    "exit",
    "terminal_status",
    "disposition",
    "mutation_attempted",
    "blockers",
    "artifacts",
    "target_tree_before",
    "target_tree_after",
}


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _locator(data: bytes) -> str:
    return "objects/" + hashlib.sha256(data).hexdigest()


def _binding(contract_id: str) -> str:
    registry = json.loads((Path(__file__).resolve().parents[1] / "src" / "phase_tool" / "data" / "registry.json").read_text(encoding="utf-8"))
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


def _run_process(command: list[str], env: dict[str, str]) -> dict[str, Any]:
    process = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON: rc={process.returncode} stdout={process.stdout!r} stderr={process.stderr!r}") from exc
    payload["_returncode"] = process.returncode
    payload["_stderr"] = process.stderr
    payload["_argv"] = command
    return payload


def _tree(root: Path) -> list[dict[str, object]]:
    if not root.exists():
        return []
    items = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        data = path.read_bytes()
        items.append({"path": path.relative_to(root).as_posix(), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return items


def _file_snapshot(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    if not path.exists():
        return {"path": str(path), "exists": False, "length": None, "sha256": None}
    data = path.read_bytes()
    return {"path": str(path), "exists": True, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _clear_directory_contents(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _artifact(path: Path) -> object | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _run_artifacts(evidence: Path, run_id: str | None) -> dict[str, object] | None:
    if run_id is None:
        return None
    run = evidence / ".phase" / "runs" / run_id
    if not run.exists():
        return None
    receipt = _artifact(run / "receipt.json")
    plan = _artifact(run / "attachments" / "effect-plan.json")
    effects = _artifact(run / "attachments" / "effect-receipts.json")
    intent = _artifact(run / "intent.json")
    return {
        "intent": intent,
        "effect_plan": plan,
        "effect_receipts": effects,
        "receipt": receipt,
        "canonical_result": receipt.get("canonical_result") if isinstance(receipt, dict) else None,
        "evidence_files": _tree(run),
    }


def _copy_candidate(path: Path, key: str, destination: str = "objects/user-name.bin") -> None:
    _write_json(
        path,
        {
            "transfer_id": key,
            "object_id": "user-name",
            "input_binding": "payload",
            "destinations": [destination],
            "idempotency_key": key,
        },
    )


def _create_candidate(path: Path) -> None:
    _write_json(path, {"operation_id": "create-1", "target_locator": "objects/create.bin", "input_binding": "payload", "idempotency_key": "create-key"})


def _append_candidate(path: Path) -> None:
    _write_json(path, {"stream_id": "alpha", "target_locator": "streams/alpha.jsonl", "record_id": "r1", "expected_head": None, "record": {"stage": 5}, "idempotency_key": "append-key"})


def _task_candidate(path: Path) -> None:
    _write_json(path, {"task_id": "task-1", "action": "open", "expected_head": None, "idempotency_key": "task-key", "operation_id": "task-key", "original_instruction": "Stage 5 CLI acceptance"})


def _common(contract_id: str, candidate: Path, evidence: Path, target: Path, run_id: str, payload: Path | None = None) -> list[str]:
    root_name = "task_journal_root" if contract_id == "task_journal.v1" else "fixture_result_root"
    args = [
        "--contract-id",
        contract_id,
        "--contract-version",
        "1.0.0",
        "--contract-digest",
        _binding(contract_id),
        "--candidate",
        str(candidate),
        "--evidence-root",
        str(evidence),
        "--run-id",
        run_id,
        "--root",
        f"{root_name}={target}",
        "--timestamp",
        NOW,
    ]
    if payload is not None:
        args.extend(["--input", f"payload={payload}"])
    return args


def _helper_script(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        r'''
from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.mutation import BrokerFaults
from phase_tool.planning import validate_static_plan

NOW = "2026-07-27T06:00:00Z"


def emit(value: object, code: int) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    raise SystemExit(code)


def binding(contract_id: str) -> str:
    registry = json.loads((Path(__file__).resolve().parents[3] / "src" / "phase_tool" / "data" / "registry.json").read_text(encoding="utf-8"))
    for entry in registry["entries"]:
        if (
            entry.get("kind") == "contract"
            and entry.get("id") == contract_id
            and entry.get("version") == "1.0.0"
            and entry.get("current", True) is True
        ):
            return str(entry["package_digest"])
    raise AssertionError(contract_id)


def envelope(command: str, outcome) -> dict[str, object]:
    return {
        "stage3_command_result_version": "1.0",
        "command": command,
        "success": outcome.exit_code == 0,
        "run_id": outcome.run_id,
        "terminal_status": outcome.receipt["terminal_status"],
        "execution_disposition": outcome.receipt["execution_disposition"],
        "mutation_attempted": outcome.receipt["mutation_attempted"],
        "effect_plan_digest": outcome.effect_plan_digest,
        "intent_digest": profile_digest("intent", outcome.intent) if outcome.intent is not None else None,
        "receipt_digest": outcome.receipt_digest,
        "target_verified": None,
        "blockers": outcome.receipt["blockers"],
        "error": None if outcome.exit_code == 0 else outcome.receipt["blockers"][0],
        "exit_code": outcome.exit_code,
    }


def request(args: argparse.Namespace) -> PhaseRequest:
    root_name = "task_journal_root" if args.contract_id == "task_journal.v1" else "fixture_result_root"
    inputs = {"payload": args.payload} if args.payload else {}
    return PhaseRequest(
        contract_id=args.contract_id,
        contract_version="1.0.0",
        contract_digest=binding(args.contract_id),
        candidate_path=args.candidate,
        evidence_root=args.evidence,
        run_id=args.run_id,
        input_paths=inputs,
        root_bindings={root_name: args.target},
        timestamp=NOW,
    )


def corrupt_blob(intent_path: Path) -> None:
    run = intent_path.parent
    intent = parse_json_bytes(intent_path.read_bytes())
    blob_digest = intent["inputs"][0]["blob_digest"]
    (run / "blobs" / blob_digest.split(":", 1)[1]).write_bytes(b"corrupted frozen blob")


def add_multi_effect(intent_path: Path) -> None:
    run = intent_path.parent
    plan_path = run / "attachments" / "effect-plan.json"
    plan = parse_json_bytes(plan_path.read_bytes())
    plan["effects"].append(deepcopy(plan["effects"][0]))
    plan["effects"][1]["effect_id"] = "effect.copy.002"
    plan_path.write_bytes(canonical_bytes(plan))
    intent = parse_json_bytes(intent_path.read_bytes())
    intent["evidence"]["effect_plan_attachment_digest"] = "sha256:" + hashlib.sha256(plan_path.read_bytes()).hexdigest()
    intent["effect_plan_digest"] = profile_digest("effect-plan", plan)
    intent_path.write_bytes(canonical_bytes(intent))


def static_multi_effect_gate(args: argparse.Namespace) -> None:
    core = PhaseCore()
    planned = core.run(request(args))
    assert planned.effect_plan is not None
    assert planned.intent is not None
    plan = deepcopy(planned.effect_plan)
    plan["effects"].append(deepcopy(plan["effects"][0]))
    plan["effects"][1]["effect_id"] = "effect.copy.002"
    plan_bytes = canonical_bytes(plan)
    run = args.evidence / ".phase" / "runs" / args.run_id
    plan_path = run / "attachments" / "effect-plan.json"
    plan_path.write_bytes(plan_bytes)
    intent = deepcopy(planned.intent)
    intent["execution_requested"] = True
    intent["effect_plan_digest"] = profile_digest("effect-plan", plan)
    intent["evidence"]["effect_plan_attachment_digest"] = digest_bytes(plan_bytes)
    (run / "intent.json").write_bytes(canonical_bytes(intent))
    contract = core.registry.resolve_contract("fixture_copy.v1", "1.0.0", binding("fixture_copy.v1"), core_version="1.0.0")
    validate_static_plan(plan, contract, {"fixture_result_root": args.target}, core.registry)


ARG_TARGET = None


def destination_appears(intent_path: Path) -> None:
    intent_path.parent.mkdir(parents=True, exist_ok=True)
    plan = parse_json_bytes((intent_path.parent / "attachments" / "effect-plan.json").read_bytes())
    effect = plan["effects"][0]
    target = Path(ARG_TARGET) / effect["target"]["relative_locator"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"late conflicting bytes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["corrupt_blob", "multi_effect", "destination_appears"])
    parser.add_argument("--contract-id", default="fixture_copy.v1")
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    global ARG_TARGET
    ARG_TARGET = args.target
    if args.scenario == "multi_effect":
        try:
            static_multi_effect_gate(args)
        except PhaseError as exc:
            emit({"command": "helper.multi_effect", "terminal_status": "rejected", "execution_disposition": "not_executed", "mutation_attempted": False, "blockers": [exc.code], "exit_code": 10}, 10)
        emit({"command": "helper.multi_effect", "terminal_status": "unexpected", "execution_disposition": "not_executed", "mutation_attempted": False, "blockers": [], "exit_code": 1}, 1)
    hook = {"corrupt_blob": corrupt_blob, "multi_effect": add_multi_effect, "destination_appears": destination_appears}[args.scenario]
    faults = CoreFaults(broker=BrokerFaults(before_mechanism=hook))
    try:
        outcome = PhaseCore().run(request(args), execute=True, faults=faults)
    except PhaseError as exc:
        emit({"command": "helper." + args.scenario, "terminal_status": "rejected", "execution_disposition": "not_executed", "mutation_attempted": False, "blockers": [exc.code], "exit_code": 10}, 10)
    result = envelope("helper." + args.scenario, outcome)
    emit(result, int(result["exit_code"]))


if __name__ == "__main__":
    main()
'''.lstrip(),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tmp-root", type=Path, default=Path(".stage5-tmp") / "final-cli")
    parser.add_argument("--phase", type=Path)
    parser.add_argument("--python", type=Path)
    args = parser.parse_args()
    root = args.tmp_root.resolve()
    if ".stage5-tmp" not in root.parts:
        raise AssertionError("--tmp-root must be inside .stage5-tmp")
    target = root / "target"
    evidence = root / "evidence"
    root.mkdir(parents=True, exist_ok=True)
    for child in root.iterdir():
        if child == target:
            _clear_directory_contents(child)
        elif child == evidence:
            _clear_directory_contents(child)
        elif child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for child in ("objects", "streams", "tasks"):
        (target / child).mkdir(parents=True)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    phase = [str(args.phase.resolve())] if args.phase is not None else [sys.executable, "-m", "phase_tool"]
    python = str(args.python.resolve()) if args.python is not None else sys.executable

    helper = root / "helpers" / "stage5_helper.py"
    _helper_script(helper)
    payload_dir = root / "payloads"
    candidate_dir = root / "candidates"
    payload_dir.mkdir()
    candidate_dir.mkdir()
    matrix: dict[str, dict[str, Any]] = {}

    def record_cli(name: str, command: str, common: list[str], expect: dict[str, Any]) -> None:
        payload_path = None
        if "--input" in common:
            raw_input = str(common[common.index("--input") + 1])
            if raw_input.startswith("payload="):
                payload_path = Path(raw_input.split("=", 1)[1])
        before = _tree(target)
        source_before = _file_snapshot(payload_path)
        result = _run_process([*phase, command, *common], env)
        source_after = _file_snapshot(payload_path)
        after = _tree(target)
        run_id = str(common[common.index("--run-id") + 1])
        record(name, result, run_id, before, after, expect, command, "phase-cli", source_before, source_after)

    def record_helper(name: str, scenario: str, candidate: Path, run_id: str, payload: Path, expect: dict[str, Any]) -> None:
        before = _tree(target)
        source_before = _file_snapshot(payload)
        result = _run_process(
            [
                python,
                str(helper),
                scenario,
                "--candidate",
                str(candidate),
                "--evidence",
                str(evidence),
                "--target",
                str(target),
                "--payload",
                str(payload),
                "--run-id",
                run_id,
            ],
            env,
        )
        source_after = _file_snapshot(payload)
        after = _tree(target)
        record(name, result, run_id, before, after, expect, "helper." + scenario, "core-helper", source_before, source_after)

    def record(
        name: str,
        result: dict[str, Any],
        run_id: str | None,
        before: list[dict[str, object]],
        after: list[dict[str, object]],
        expect: dict[str, Any],
        command: str,
        runner: str,
        source_before: dict[str, object] | None,
        source_after: dict[str, object] | None,
    ) -> None:
        scenario = {
            "command": command,
            "runner": runner,
            "exit": result["_returncode"],
            "terminal_status": result.get("terminal_status"),
            "disposition": result.get("execution_disposition"),
            "mutation_attempted": result.get("mutation_attempted"),
            "blockers": result.get("blockers"),
            "artifacts": _run_artifacts(evidence, run_id),
            "target_tree_before": before,
            "target_tree_after": after,
            "source_before": source_before,
            "source_after": source_after,
            "envelope": result,
            "expect": expect,
        }
        missing = sorted(field for field in REQUIRED_SCENARIO_FIELDS if field not in scenario)
        if missing:
            scenario["classification_failure"] = f"missing fields: {missing}"
        if scenario["terminal_status"] is None:
            scenario["classification_failure"] = "terminal_status must not be None"
        matrix[name] = scenario

    copy = candidate_dir / "copy.json"
    payload = payload_dir / "copy.txt"
    payload.write_bytes(b"stage5 cli copy\n")
    _copy_candidate(copy, "copy-key")
    copy_digest = _sha(payload.read_bytes())
    copy_locator = _locator(payload.read_bytes())

    record_cli("01_validate_copy", "validate", _common("fixture_copy.v1", copy, evidence, target, "copy-validate", payload), {"exit": 0, "terminal_status": "validated_planned", "disposition": "not_executed", "mutation_attempted": False, "target_unchanged": True})
    record_cli("02_plan_copy", "plan", _common("fixture_copy.v1", copy, evidence, target, "copy-plan", payload), {"exit": 0, "terminal_status": "validated_planned", "disposition": "not_executed", "mutation_attempted": False, "target_unchanged": True})
    record_cli("03_execute_new_text", "execute", _common("fixture_copy.v1", copy, evidence, target, "copy-execute", payload), {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})
    record_cli("04_inspect_run_and_target", "inspect", ["--evidence-root", str(evidence), "--run-id", "copy-execute", "--root", f"fixture_result_root={target}"], {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True, "target_verified": True})
    record_cli("05_prior_exact_reuse", "execute", _common("fixture_copy.v1", copy, evidence, target, "copy-reuse", payload), {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "reused_existing", "mutation_attempted": False})

    different_same_key_payload = payload_dir / "same-key-different.txt"
    different_same_key_payload.write_bytes(b"same key different request\n")
    same_key = candidate_dir / "same-key-conflict.json"
    _copy_candidate(same_key, "copy-key")
    record_cli("06_same_operation_key_different_request_digest_conflict", "execute", _common("fixture_copy.v1", same_key, evidence, target, "same-key-conflict", different_same_key_payload), {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "idempotency.same_key_conflict"})

    identical = candidate_dir / "identical.json"
    identical_payload = payload_dir / "identical.bin"
    identical_payload.write_bytes(b"preexisting identical")
    _copy_candidate(identical, "identical-key")
    (target / _locator(identical_payload.read_bytes())).write_bytes(identical_payload.read_bytes())
    record_cli("07_existing_identical_no_prior", "execute", _common("fixture_copy.v1", identical, evidence, target, "existing-identical", identical_payload), {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})

    conflict = candidate_dir / "conflict.json"
    conflict_payload = payload_dir / "conflict.bin"
    conflict_payload.write_bytes(b"conflict payload")
    _copy_candidate(conflict, "conflict-key")
    (target / _locator(conflict_payload.read_bytes())).write_bytes(b"different")
    record_cli("08_existing_different", "execute", _common("fixture_copy.v1", conflict, evidence, target, "existing-different", conflict_payload), {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "target.same_key_conflict"})

    binary = candidate_dir / "binary.json"
    binary_payload = payload_dir / "binary.bin"
    binary_payload.write_bytes(bytes([0, 1, 2, 253, 254, 255]))
    _copy_candidate(binary, "binary-key")
    record_cli("09_binary_copy", "execute", _common("fixture_copy.v1", binary, evidence, target, "binary", binary_payload), {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})

    reserved = candidate_dir / "reserved.json"
    _copy_candidate(reserved, "reserved-key", destination="objects/CON.txt")
    record_cli("10_unsafe_locator_rejection", "execute", _common("fixture_copy.v1", reserved, evidence, target, "reserved", payload), {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False})

    corrupted = candidate_dir / "corrupted.json"
    corrupted_payload = payload_dir / "corrupted.bin"
    corrupted_payload.write_bytes(b"corrupt me")
    _copy_candidate(corrupted, "corrupted-key")
    record_helper("11_corrupted_frozen_blob_rejection", "corrupt_blob", corrupted, "corrupted-blob", corrupted_payload, {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "broker.unsafe_fault_callback"})

    create = candidate_dir / "create.json"
    create_payload = payload_dir / "create.bin"
    create_payload.write_bytes(b"create")
    _create_candidate(create)
    record_cli("12_fixture_create", "execute", _common("fixture_create.v1", create, evidence, target, "create", create_payload), {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})

    append = candidate_dir / "append.json"
    _append_candidate(append)
    record_cli("13_fixture_append", "execute", _common("fixture_append.v1", append, evidence, target, "append"), {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})

    task = candidate_dir / "task.json"
    _task_candidate(task)
    record_cli("14_task_journal", "execute", _common("task_journal.v1", task, evidence, target, "task"), {"exit": 0, "terminal_status": "succeeded_verified", "disposition": "executed", "mutation_attempted": True})

    multi = candidate_dir / "multi.json"
    multi_payload = payload_dir / "multi.bin"
    multi_payload.write_bytes(b"multi")
    _copy_candidate(multi, "multi-key")
    record_helper("15_multi_effect_execution_rejection", "multi_effect", multi, "multi-effect", multi_payload, {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "plan.incomplete"})

    appears = candidate_dir / "appears.json"
    appears_payload = payload_dir / "appears.bin"
    appears_payload.write_bytes(b"appears")
    _copy_candidate(appears, "appears-key")
    record_cli("16_plan_before_destination_appears", "plan", _common("fixture_copy.v1", appears, evidence, target, "appears-plan", appears_payload), {"exit": 0, "terminal_status": "validated_planned", "disposition": "not_executed", "mutation_attempted": False, "target_unchanged": True})
    late = candidate_dir / "late-conflict.json"
    late_payload = payload_dir / "late-conflict.bin"
    late_payload.write_bytes(b"late conflict")
    _copy_candidate(late, "late-conflict-key")
    record_helper("17_destination_appears_conflict", "destination_appears", late, "destination-appears", late_payload, {"exit": 10, "terminal_status": "rejected", "disposition": "not_executed", "mutation_attempted": False, "blocker": "broker.unsafe_fault_callback"})

    failures: dict[str, Any] = {}
    for name, scenario in matrix.items():
        expect = scenario["expect"]
        for field in ("exit", "terminal_status", "disposition", "mutation_attempted"):
            if scenario.get(field) != expect.get(field):
                failures.setdefault(name, []).append({"field": field, "expected": expect.get(field), "observed": scenario.get(field)})
        if "blocker" in expect:
            blockers = scenario.get("blockers") or []
            allowed = str(expect["blocker"]).split("|")
            if not any(blocker in blockers for blocker in allowed):
                failures.setdefault(name, []).append({"field": "blockers", "expected_one_of": allowed, "observed": blockers})
        if expect.get("target_unchanged") is True and scenario["target_tree_before"] != scenario["target_tree_after"]:
            failures.setdefault(name, []).append({"field": "target_tree", "expected": "unchanged", "observed": "changed"})
        if expect.get("target_verified") is True and scenario["envelope"].get("target_verified") is not True:
            failures.setdefault(name, []).append({"field": "target_verified", "expected": True, "observed": scenario["envelope"].get("target_verified")})
        if scenario.get("classification_failure"):
            failures.setdefault(name, []).append({"field": "classification", "observed": scenario["classification_failure"]})
        if REQUIRED_SCENARIO_FIELDS.difference(scenario):
            failures.setdefault(name, []).append({"field": "required_fields", "missing": sorted(REQUIRED_SCENARIO_FIELDS.difference(scenario))})

    summary = {
        "success": not failures,
        "scenario_count": len(matrix),
        "required_cli_scenarios": sorted(matrix),
        "command_order": list(matrix),
        "command_matrix": matrix,
        "copy": {"digest": copy_digest, "length": payload.stat().st_size, "locator": copy_locator},
        "target_tree": _tree(target),
        "evidence_tree": _tree(evidence),
        "py_subprocess_path_absent": "PYTHONPATH" not in env,
        "helper_note": "core-helper scenarios invoke real PhaseCore, EvidenceStore, EffectBroker, and mechanisms with controlled faults because public phase CLI cannot pause after intent.",
        "failures": failures,
    }
    summary_path = root / "stage5-cli-acceptance-summary.json"
    _write_json(summary_path, summary)
    print(json.dumps({"success": not failures, "scenario_count": len(matrix), "summary": str(summary_path)}, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
