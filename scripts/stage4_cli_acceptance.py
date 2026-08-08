from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

NOW = "2026-07-27T04:00:00Z"


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def _run(phase: Path | None, args: list[str], *, env: dict[str, str]) -> dict[str, object]:
    command = [str(phase.resolve())] if phase is not None else [sys.executable, "-m", "phase_tool"]
    process = subprocess.run([*command, *args], capture_output=True, text=True, env=env, check=False)
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid CLI JSON for {args}: rc={process.returncode} stdout={process.stdout!r} stderr={process.stderr!r}") from exc
    payload["_returncode"] = process.returncode
    return payload


def _with_candidate(common: list[str], candidate: Path) -> list[str]:
    updated = list(common)
    updated[updated.index("--candidate") + 1] = str(candidate)
    return updated


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
    return matches[0]["package_digest"]


def _head(data: bytes) -> str:
    from phase_tool.append_codec import stream_head_token

    return stream_head_token(data)


def _receipt(evidence: Path, run_id: str) -> object:
    return json.loads((evidence / ".phase" / "runs" / run_id / "receipt.json").read_text(encoding="utf-8"))


def _artifact(evidence: Path, run_id: str, relative: str) -> object:
    path = evidence / ".phase" / "runs" / run_id / relative
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _task_snapshot(evidence: Path, target: Path, run_id: str, stream: Path, before: bytes, after: bytes) -> dict[str, object]:
    receipt = _receipt(evidence, run_id)
    effects = receipt.get("effect_receipts", []) if isinstance(receipt, dict) else []
    first_effect = effects[0] if effects else {}
    return {
        "before_hex": before.hex(),
        "after_hex": after.hex(),
        "head": _head(after),
        "append_offset": first_effect.get("append_offset"),
        "intent": _artifact(evidence, run_id, "intent.json"),
        "effect_plan": _artifact(evidence, run_id, "attachments/effect-plan.json"),
        "effect_receipts": _artifact(evidence, run_id, "attachments/effect-receipts.json"),
        "final_receipt": receipt,
        "stream_sha256": hashlib.sha256(after).hexdigest(),
        "stream_path": stream.relative_to(target).as_posix(),
    }


def _tree_snapshot(root: Path) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        data = path.read_bytes()
        items.append({"path": path.relative_to(root).as_posix(), "length": len(data), "sha256": __import__("hashlib").sha256(data).hexdigest()})
    return items


def _require_verified_inspect(results: dict[str, object], name: str, failures: dict[str, object]) -> None:
    result = results[name]  # type: ignore[index]
    if result.get("target_verified") is not True:
        failures[f"{name}_target_verified"] = result


def _require_append_delta(snapshot: dict[str, object], failures: dict[str, object], name: str) -> None:
    before = bytes.fromhex(str(snapshot["before_hex"]))
    after = bytes.fromhex(str(snapshot["after_hex"]))
    receipt = snapshot["final_receipt"] if "final_receipt" in snapshot else snapshot["receipt"]
    effect_receipts = receipt.get("effect_receipts", []) if isinstance(receipt, dict) else []
    effect = effect_receipts[0] if effect_receipts else {}
    plan = snapshot.get("effect_plan")
    planned_effect = plan["effects"][0] if isinstance(plan, dict) else None
    offset = effect.get("append_offset")
    length = effect.get("record_length")
    digest = effect.get("record_digest")
    if offset != len(before) or not isinstance(length, int) or after[: len(before)] != before:
        failures[f"{name}_prefix_offset"] = snapshot
        return
    appended = after[len(before):]
    if len(appended) != length or "sha256:" + hashlib.sha256(appended).hexdigest() != digest:
        failures[f"{name}_append_digest"] = snapshot
    if planned_effect is not None and planned_effect.get("content_digest") != digest:
        failures[f"{name}_plan_digest"] = snapshot


def _require_exact_target_tree(target: Path, failures: dict[str, object]) -> None:
    allowed = {
        "objects/create.bin",
        "streams/alpha.jsonl",
        "tasks/task-1.jsonl",
    }
    observed = {item["path"] for item in _tree_snapshot(target)}
    if observed != allowed:
        failures["target_tree"] = {"expected": sorted(allowed), "observed": sorted(observed)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tmp-root", type=Path, required=True)
    parser.add_argument("--phase", type=Path)
    args = parser.parse_args()
    root = args.tmp_root.resolve()
    if ".stage4-tmp" not in root.parts:
        raise AssertionError("--tmp-root must be inside .stage4-tmp")
    if root.exists() and any(root.iterdir()):
        raise AssertionError("--tmp-root must be fresh or empty")
    root.mkdir(parents=True, exist_ok=True)
    target = root / "target"
    evidence = root / "evidence"
    for child in ("streams", "tasks", "objects"):
        (target / child).mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    snapshots: dict[str, object] = {"canary_before": _tree_snapshot(root)}

    append_candidate = root / "candidates" / "append.json"
    _write_json(append_candidate, {
        "stream_id": "alpha",
        "target_locator": "streams/alpha.jsonl",
        "record_id": "record-1",
        "expected_head": None,
        "record": {"value": 1},
        "idempotency_key": "append-key",
    })
    append_common = [
        "--contract-id", "fixture_append.v1",
        "--contract-version", "1.0.0",
        "--contract-digest", _binding("fixture_append.v1"),
        "--candidate", str(append_candidate),
        "--evidence-root", str(evidence),
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    ]
    results: dict[str, object] = {}
    for command in ("validate", "plan"):
        dry_candidate = root / "candidates" / f"append-{command}.json"
        _write_json(dry_candidate, json.loads(append_candidate.read_text(encoding="utf-8")) | {"idempotency_key": f"append-{command}-key"})
        results[f"append_{command}"] = _run(args.phase, [command, *_with_candidate(append_common, dry_candidate), "--run-id", f"append-{command}"], env=env)
    before_initial = (target / "streams" / "alpha.jsonl").read_bytes() if (target / "streams" / "alpha.jsonl").exists() else b""
    results["append_execute"] = _run(args.phase, ["execute", *append_common, "--run-id", "append-execute"], env=env)
    after_initial = (target / "streams" / "alpha.jsonl").read_bytes()
    results["append_inspect"] = _run(args.phase, ["inspect", "--evidence-root", str(evidence), "--run-id", "append-execute", "--root", f"fixture_result_root={target}"], env=env)

    conflict_candidate = root / "candidates" / "append-conflict.json"
    _write_json(conflict_candidate, json.loads(append_candidate.read_text(encoding="utf-8")) | {"record": {"value": 2}})
    results["append_conflict"] = _run(args.phase, ["execute", *_with_candidate(append_common, conflict_candidate), "--run-id", "append-conflict"], env=env)

    current = (target / "streams" / "alpha.jsonl").read_bytes()
    second_candidate = root / "candidates" / "append-second.json"
    _write_json(second_candidate, {
        "stream_id": "alpha",
        "target_locator": "streams/alpha.jsonl",
        "record_id": "record-2",
        "expected_head": _head(current),
        "record": {"value": 2},
        "idempotency_key": "append-key-2",
    })
    second_common = _with_candidate(append_common, second_candidate)
    before_second = current
    results["append_second"] = _run(args.phase, ["execute", *second_common, "--run-id", "append-second"], env=env)
    after_second = (target / "streams" / "alpha.jsonl").read_bytes()
    results["append_reuse_after_later"] = _run(args.phase, ["execute", *append_common, "--run-id", "append-reuse-after-later"], env=env)

    stale_candidate = root / "candidates" / "append-stale.json"
    _write_json(stale_candidate, json.loads(second_candidate.read_text(encoding="utf-8")) | {"record_id": "record-3", "record": {"value": 3}, "idempotency_key": "append-stale"})
    stale_common = _with_candidate(append_common, stale_candidate)
    results["append_stale"] = _run(args.phase, ["execute", *stale_common, "--run-id", "append-stale"], env=env)

    task_candidate = root / "candidates" / "task-open.json"
    _write_json(task_candidate, {"task_id": "task-1", "action": "open", "expected_head": None, "idempotency_key": "task-open", "operation_id": "task-open", "original_instruction": "Do work"})
    task_common = [
        "--contract-id", "task_journal.v1",
        "--contract-version", "1.0.0",
        "--contract-digest", _binding("task_journal.v1"),
        "--candidate", str(task_candidate),
        "--evidence-root", str(evidence),
        "--root", f"task_journal_root={target}",
        "--timestamp", NOW,
    ]
    for command in ("validate", "plan"):
        dry_candidate = root / "candidates" / f"task-open-{command}.json"
        _write_json(dry_candidate, json.loads(task_candidate.read_text(encoding="utf-8")) | {"idempotency_key": f"task-open-{command}", "operation_id": f"task-open-{command}"})
        results[f"task_open_{command}"] = _run(args.phase, [command, *_with_candidate(task_common, dry_candidate), "--run-id", f"task-open-{command}"], env=env)
    task_stream = target / "tasks" / "task-1.jsonl"
    before_task_open = task_stream.read_bytes() if task_stream.exists() else b""
    results["task_open"] = _run(args.phase, ["execute", *task_common, "--run-id", "task-open"], env=env)
    after_task_open = task_stream.read_bytes()
    snapshots["task_open"] = _task_snapshot(evidence, target, "task-open", task_stream, before_task_open, after_task_open)
    results["task_open_inspect"] = _run(args.phase, ["inspect", "--evidence-root", str(evidence), "--run-id", "task-open", "--root", f"task_journal_root={target}"], env=env)
    task_head = _head(task_stream.read_bytes())
    event_candidate = root / "candidates" / "task-event.json"
    _write_json(event_candidate, {"task_id": "task-1", "action": "event", "expected_head": task_head, "idempotency_key": "task-event", "operation_id": "task-event", "event_kind": "progress", "event_payload": {"text": "started"}})
    before_task_event = task_stream.read_bytes()
    results["task_event"] = _run(args.phase, ["execute", *_with_candidate(task_common, event_candidate), "--run-id", "task-event"], env=env)
    after_task_event = task_stream.read_bytes()
    snapshots["task_event"] = _task_snapshot(evidence, target, "task-event", task_stream, before_task_event, after_task_event)
    event_record = json.loads(task_stream.read_text(encoding="utf-8").splitlines()[1])
    task_head = _head(task_stream.read_bytes())
    close_candidate = root / "candidates" / "task-close.json"
    _write_json(close_candidate, {"task_id": "task-1", "action": "close", "expected_head": task_head, "idempotency_key": "task-close", "operation_id": "task-close", "outcome": "completed"})
    before_task_close = task_stream.read_bytes()
    results["task_close"] = _run(args.phase, ["execute", *_with_candidate(task_common, close_candidate), "--run-id", "task-close"], env=env)
    after_task_close = task_stream.read_bytes()
    snapshots["task_close"] = _task_snapshot(evidence, target, "task-close", task_stream, before_task_close, after_task_close)
    task_head = _head(task_stream.read_bytes())
    correction_candidate = root / "candidates" / "task-correction.json"
    _write_json(correction_candidate, {"task_id": "task-1", "action": "correction", "expected_head": task_head, "idempotency_key": "task-correction", "operation_id": "task-correction", "target_sequence": 2, "target_event_hash": event_record["event_hash"], "reason": "correct progress", "replacement": {"event_payload": {"text": "started promptly"}}})
    before_task_correction = task_stream.read_bytes()
    results["task_correction"] = _run(args.phase, ["execute", *_with_candidate(task_common, correction_candidate), "--run-id", "task-correction"], env=env)
    after_task_correction = task_stream.read_bytes()
    snapshots["task_correction"] = _task_snapshot(evidence, target, "task-correction", task_stream, before_task_correction, after_task_correction)
    results["task_inspect"] = _run(args.phase, ["inspect", "--evidence-root", str(evidence), "--run-id", "task-correction", "--root", f"task_journal_root={target}"], env=env)
    before_task_reuse = task_stream.read_bytes()
    results["task_open_reuse_after_later"] = _run(args.phase, ["execute", *task_common, "--run-id", "task-open-reuse-after-later"], env=env)
    after_task_reuse = task_stream.read_bytes()
    snapshots["task_open_reuse_after_later"] = _task_snapshot(evidence, target, "task-open-reuse-after-later", task_stream, before_task_reuse, after_task_reuse)
    task_conflict_candidate = root / "candidates" / "task-open-conflict.json"
    _write_json(task_conflict_candidate, {"task_id": "task-1", "action": "open", "expected_head": None, "idempotency_key": "task-open", "operation_id": "task-open", "original_instruction": "Different work"})
    before_task_conflict = task_stream.read_bytes()
    results["task_open_conflict"] = _run(args.phase, ["execute", *_with_candidate(task_common, task_conflict_candidate), "--run-id", "task-open-conflict"], env=env)
    after_task_conflict = task_stream.read_bytes()
    snapshots["task_open_conflict"] = {"before_hex": before_task_conflict.hex(), "after_hex": after_task_conflict.hex(), "head": _head(after_task_conflict)}
    stale_event_candidate = root / "candidates" / "task-stale-event.json"
    _write_json(stale_event_candidate, {"task_id": "task-1", "action": "event", "expected_head": _head(after_task_open), "idempotency_key": "task-stale-event", "operation_id": "task-stale-event", "event_kind": "progress", "event_payload": {"text": "stale"}})
    before_task_stale = task_stream.read_bytes()
    results["task_stale_event"] = _run(args.phase, ["execute", *_with_candidate(task_common, stale_event_candidate), "--run-id", "task-stale-event"], env=env)
    after_task_stale = task_stream.read_bytes()
    snapshots["task_stale_event"] = {"before_hex": before_task_stale.hex(), "after_hex": after_task_stale.hex(), "head": _head(after_task_stale), "receipt": _receipt(evidence, "task-stale-event")}

    payload = root / "payload.bin"
    payload.write_bytes(b"create")
    create_candidate = root / "candidates" / "create.json"
    _write_json(create_candidate, {"operation_id": "create-1", "target_locator": "objects/create.bin", "input_binding": "payload", "idempotency_key": "create-key"})
    create_common = [
        "--contract-id", "fixture_create.v1",
        "--contract-version", "1.0.0",
        "--contract-digest", _binding("fixture_create.v1"),
        "--candidate", str(create_candidate),
        "--evidence-root", str(evidence),
        "--input", f"payload={payload}",
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    ]
    results["create_execute"] = _run(args.phase, ["execute", *create_common, "--run-id", "create-execute"], env=env)

    copy_candidate = root / "candidates" / "copy.json"
    _write_json(copy_candidate, {"transfer_id": "transfer-1", "object_id": "object-1", "input_binding": "payload", "destinations": ["objects/copy.bin"], "idempotency_key": "copy-key"})
    copy_common = [
        "--contract-id", "fixture_copy.v1",
        "--contract-version", "1.0.0",
        "--contract-digest", _binding("fixture_copy.v1"),
        "--candidate", str(copy_candidate),
        "--evidence-root", str(evidence),
        "--input", f"payload={payload}",
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    ]
    results["copy_fail_closed"] = _run(args.phase, ["execute", *copy_common, "--run-id", "copy-execute"], env=env)

    from phase_tool.contracts.task_journal_v1 import project_task

    snapshots |= {
        "py_subprocess_path_absent": "PYTHONPATH" not in env,
        "append_initial": {"before_hex": before_initial.hex(), "after_hex": after_initial.hex(), "head": _head(after_initial), "receipt": _receipt(evidence, "append-execute")},
        "append_second": {"before_hex": before_second.hex(), "after_hex": after_second.hex(), "head": _head(after_second), "receipt": _receipt(evidence, "append-second")},
        "task_projection": project_task(task_stream),
        "task_final_receipt": _receipt(evidence, "task-correction"),
        "canary_after": _tree_snapshot(root),
    }
    summary = root / "stage4-cli-acceptance-result.json"
    _write_json(summary, {"results": results, "snapshots": snapshots})
    expected = {
        "append_validate": 0,
        "append_plan": 0,
        "append_execute": 0,
        "append_inspect": 0,
        "append_reuse_after_later": 0,
        "append_conflict": 10,
        "append_second": 0,
        "append_stale": 10,
        "task_open": 0,
        "task_open_validate": 0,
        "task_open_plan": 0,
        "task_open_inspect": 0,
        "task_event": 0,
        "task_close": 0,
        "task_correction": 0,
        "task_inspect": 0,
        "task_open_reuse_after_later": 0,
        "task_open_conflict": 10,
        "task_stale_event": 10,
        "create_execute": 0,
        "copy_fail_closed": 10,
    }
    failures = {name: results[name] for name, code in expected.items() if results[name]["_returncode"] != code}  # type: ignore[index]
    expected_status = {
        "append_validate": ("validated_planned", "not_executed", False),
        "append_plan": ("validated_planned", "not_executed", False),
        "append_execute": ("succeeded_verified", "executed", True),
        "append_reuse_after_later": ("succeeded_verified", "reused_existing", False),
        "append_conflict": ("rejected", "not_executed", False),
        "append_second": ("succeeded_verified", "executed", True),
        "append_stale": ("rejected", "not_executed", False),
        "task_open_validate": ("validated_planned", "not_executed", False),
        "task_open_plan": ("validated_planned", "not_executed", False),
        "task_open": ("succeeded_verified", "executed", True),
        "task_event": ("succeeded_verified", "executed", True),
        "task_close": ("succeeded_verified", "executed", True),
        "task_correction": ("succeeded_verified", "executed", True),
        "task_open_reuse_after_later": ("succeeded_verified", "reused_existing", False),
        "task_open_conflict": ("rejected", "not_executed", False),
        "task_stale_event": ("rejected", "not_executed", False),
        "create_execute": ("succeeded_verified", "executed", True),
    }
    for name, (terminal, disposition, attempted) in expected_status.items():
        result = results[name]  # type: ignore[index]
        if (result["terminal_status"], result["execution_disposition"], result["mutation_attempted"]) != (terminal, disposition, attempted):
            failures[name] = result
    if snapshots["task_open_reuse_after_later"]["before_hex"] != snapshots["task_open_reuse_after_later"]["after_hex"]:  # type: ignore[index]
        failures["task_open_reuse_after_later_bytes"] = snapshots["task_open_reuse_after_later"]  # type: ignore[assignment]
    if snapshots["task_open_conflict"]["before_hex"] != snapshots["task_open_conflict"]["after_hex"]:  # type: ignore[index]
        failures["task_open_conflict_bytes"] = snapshots["task_open_conflict"]  # type: ignore[assignment]
    if snapshots["task_stale_event"]["before_hex"] != snapshots["task_stale_event"]["after_hex"]:  # type: ignore[index]
        failures["task_stale_event_bytes"] = snapshots["task_stale_event"]  # type: ignore[assignment]
    if failures:
        print(json.dumps({"success": False, "summary": str(summary), "failures": failures}, sort_keys=True), file=sys.stderr)
        return 1
    for inspect_name in ("append_inspect", "task_open_inspect", "task_inspect"):
        _require_verified_inspect(results, inspect_name, failures)
    for snapshot_name in ("task_open", "task_event", "task_close", "task_correction"):
        _require_append_delta(snapshots[snapshot_name], failures, snapshot_name)  # type: ignore[index]
    _require_exact_target_tree(target, failures)
    if failures:
        print(json.dumps({"success": False, "summary": str(summary), "failures": failures}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"success": True, "summary": str(summary)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
