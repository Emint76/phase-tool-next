from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run
from phase_tool.registry import BundledRegistry

NOW = "2026-07-27T00:00:00Z"
ROOT = Path(__file__).resolve().parents[1]


def exact(contract_id: str) -> dict[str, str]:
    return BundledRegistry.load().contract_bindings()[f"{contract_id}@1.0.0"]


def tree_digest(root: Path) -> str:
    entries: list[dict[str, str | int]] = []
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(root).as_posix()):
        data = path.read_bytes()
        entries.append({"path": path.relative_to(root).as_posix(), "length": len(data), "digest": digest_bytes(data)})
    return digest_bytes(canonical_bytes(entries))


def write_append(path: Path, *, key: str = "key-1", value: int = 1) -> None:
    path.write_text(json.dumps({
        "stream_id": "alpha",
        "target_locator": "streams/alpha.jsonl",
        "record_id": "record-1",
        "expected_head": None,
        "record": {"value": value},
        "idempotency_key": key,
    }), encoding="utf-8")


def write_copy(path: Path, *, key: str = "copy-key-1") -> None:
    path.write_text(json.dumps({
        "transfer_id": "transfer-1",
        "object_id": "object-1",
        "input_binding": "payload",
        "destinations": ["objects/b", "objects/a"],
        "idempotency_key": key,
    }), encoding="utf-8")


def request(
    contract_id: str,
    candidate: Path,
    evidence: Path,
    target: Path,
    run_id: str,
    *,
    inputs: dict[str, Path] | None = None,
) -> PhaseRequest:
    binding = exact(contract_id)
    return PhaseRequest(
        contract_id=contract_id,
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence,
        run_id=run_id,
        input_paths=inputs or {},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )


def test_append_and_copy_share_one_core_lifecycle_and_do_not_mutate_targets(tmp_path: Path) -> None:
    core = PhaseCore()

    append_target = tmp_path / "append-target"
    append_target.mkdir()
    (append_target / "sentinel").write_bytes(b"unchanged")
    append_candidate = tmp_path / "append.json"
    write_append(append_candidate)
    append_before = tree_digest(append_target)
    append_outcome = core.run(request("fixture_append.v1", append_candidate, tmp_path / "append-evidence", append_target, "append-run"))
    assert append_outcome.exit_code == 0
    assert tree_digest(append_target) == append_before

    copy_target = tmp_path / "copy-target"
    copy_target.mkdir()
    (copy_target / "objects").mkdir()
    (copy_target / "sentinel").write_bytes(b"unchanged")
    copy_candidate = tmp_path / "copy.json"
    write_copy(copy_candidate)
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    payload = input_root / "payload.bin"
    payload.write_bytes(b"payload")
    copy_before = tree_digest(copy_target)
    copy_outcome = core.run(request("fixture_copy.v1", copy_candidate, tmp_path / "copy-evidence", copy_target, "copy-run", inputs={"payload": payload}))
    assert copy_outcome.exit_code == 0
    assert tree_digest(copy_target) == copy_before

    assert append_outcome.lifecycle == copy_outcome.lifecycle == (
        "resolve",
        "guarantees",
        "capture",
        "freeze",
        "validate",
        "plan",
        "intent",
        "receipt",
    )
    assert append_outcome.receipt["terminal_status"] == copy_outcome.receipt["terminal_status"] == "validated_planned"
    assert append_outcome.receipt["mutation_attempted"] is copy_outcome.receipt["mutation_attempted"] is False
    assert append_outcome.receipt["canonical_result"] is copy_outcome.receipt["canonical_result"] is None
    copy_inspection = inspect_run(tmp_path / "copy-evidence", "copy-run")
    assert copy_inspection["effect_plan_digest"] == copy_outcome.effect_plan_digest


def test_evidence_is_schema_valid_deterministic_and_has_no_domain_result(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    first = PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence-a", target, "same-run"))
    second = PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence-b", target, "same-run"))
    assert first.exit_code == second.exit_code == 0
    first_run = tmp_path / "evidence-a" / ".phase" / "runs" / "same-run"
    second_run = tmp_path / "evidence-b" / ".phase" / "runs" / "same-run"
    for relative in ("intent.json", "receipt.json", "attachments/effect-plan.json", "attachments/validator-results.json"):
        assert (first_run / relative).read_bytes() == (second_run / relative).read_bytes()
    assert not list(first_run.glob("*result*"))
    assert set(item.name for item in first_run.iterdir()) == {"intent.json", "receipt.json", "blobs", "attachments"}


def test_early_invalid_candidate_writes_truthful_rejection_receipt(tmp_path: Path) -> None:
    candidate = tmp_path / "invalid.json"
    candidate.write_text('{"stream_id":"alpha"}', encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    outcome = PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence", target, "rejected-run"))
    run_root = tmp_path / "evidence" / ".phase" / "runs" / "rejected-run"
    assert outcome.exit_code != 0
    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["evidence"]["intent_digest"] is None
    assert not (run_root / "intent.json").exists()
    assert (run_root / "receipt.json").is_file()


def test_inspect_is_read_only_and_detects_tampering(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"
    outcome = PhaseCore().run(request("fixture_append.v1", candidate, evidence, target, "inspect-run"))
    assert outcome.exit_code == 0
    before = tree_digest(evidence)
    summary = inspect_run(evidence, "inspect-run")
    assert summary["terminal_status"] == "validated_planned"
    assert summary["mutation_attempted"] is False
    assert tree_digest(evidence) == before
    plan_path = evidence / ".phase" / "runs" / "inspect-run" / "attachments" / "effect-plan.json"
    plan_path.write_bytes(plan_path.read_bytes() + b" ")
    with pytest.raises(PhaseError, match="inspection.digest_mismatch"):
        inspect_run(evidence, "inspect-run")


def test_same_key_different_request_is_rejected_without_target_mutation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    target = tmp_path / "target"
    target.mkdir()
    candidate = tmp_path / "candidate.json"
    write_append(candidate, value=1)
    first = PhaseCore().run(request("fixture_append.v1", candidate, evidence, target, "run-one"))
    assert first.exit_code == 0
    write_append(candidate, value=2)
    before = tree_digest(target)
    second = PhaseCore().run(request("fixture_append.v1", candidate, evidence, target, "run-two"))
    assert second.exit_code != 0
    assert second.receipt["blockers"] == ["idempotency.same_key_conflict"]
    assert tree_digest(target) == before


def test_invalid_run_id_and_evidence_target_overlap_are_rejected_before_write(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "canary").write_bytes(b"unchanged")
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    before = tree_digest(target)
    with pytest.raises(PhaseError, match="evidence.invalid_run_id"):
        PhaseCore().run(request("fixture_append.v1", candidate, tmp_path / "evidence", target, "../escape"))
    with pytest.raises(PhaseError, match="evidence.overlaps_target_root"):
        PhaseCore().run(request("fixture_append.v1", candidate, target / "evidence", target, "safe-run"))
    alias = target.parent / "sibling" / ".." / target.name / "evidence-alias"
    with pytest.raises(PhaseError, match="evidence.overlaps_target_root"):
        PhaseCore().run(request("fixture_append.v1", candidate, alias, target, "alias-run"))
    assert tree_digest(target) == before
    assert not (target / "evidence").exists()
    assert not (target / "evidence-alias").exists()


def test_standalone_cli_validate_plan_inspect_and_execute_refusal(tmp_path: Path) -> None:
    phase = [sys.executable, "-m", "phase_tool"]
    candidate = tmp_path / "candidate.json"
    write_append(candidate)
    target = tmp_path / "target"
    target.mkdir()
    evidence = tmp_path / "evidence"
    contract = exact("fixture_append.v1")
    base = [
        *phase,
        "--contract-id", "fixture_append.v1",
        "--contract-version", "1.0.0",
        "--contract-digest", contract["package_digest"],
        "--candidate", str(candidate),
        "--evidence-root", str(evidence),
        "--root", f"fixture_result_root={target}",
        "--timestamp", NOW,
    ]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    validate = subprocess.run([*phase, "validate", *base[len(phase):], "--run-id", "cli-validate"], capture_output=True, text=True, env=env, check=False)
    assert validate.returncode == 0, validate.stderr
    assert json.loads(validate.stdout)["terminal_status"] == "validated_planned"
    plan = subprocess.run([*phase, "plan", *base[len(phase):], "--run-id", "cli-plan"], capture_output=True, text=True, env=env, check=False)
    assert plan.returncode == 0, plan.stderr
    assert json.loads(plan.stdout)["effect_plan_digest"].startswith("sha256:")
    inspect = subprocess.run([*phase, "inspect", "--evidence-root", str(evidence), "--run-id", "cli-plan"], capture_output=True, text=True, env=env, check=False)
    assert inspect.returncode == 0, inspect.stderr
    assert json.loads(inspect.stdout)["mutation_attempted"] is False
    execute = subprocess.run([*phase, "execute"], capture_output=True, text=True, env=env, check=False)
    assert execute.returncode == 2
    assert execute.stdout == ""
    assert "mutation_execution_unavailable_in_stage_2" not in execute.stderr
    assert "--candidate" in execute.stderr
    assert "--evidence-root" in execute.stderr
    assert "--run-id" in execute.stderr
    failure = subprocess.run(
        [*phase, "inspect", "--evidence-root", str(tmp_path / "missing"), "--run-id", "missing-run"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert failure.returncode == 10, failure.stderr
    failure_output = json.loads(failure.stdout)
    assert failure_output["success"] is False
    assert failure_output["mutation_attempted"] is False
    assert failure_output["error"] == "cli.failure"
