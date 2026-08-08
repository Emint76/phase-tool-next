from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from phase_tool.candidate import capture_structured
from phase_tool.errors import PhaseError
from phase_tool.freeze import copy_and_hash
from phase_tool.planning import build_static_plan, validate_static_plan
from phase_tool.registry import BundledRegistry
from phase_tool.validation import ValidatorRunner

NOW = "2026-07-27T00:00:00Z"


def binding(registry: BundledRegistry, contract_id: str) -> dict[str, str]:
    return registry.load().contract_bindings()[f"{contract_id}@1.0.0"]


def resolved(contract_id: str):
    registry = BundledRegistry.load()
    exact = registry.contract_bindings()[f"{contract_id}@1.0.0"]
    return registry, registry.resolve_contract(contract_id, "1.0.0", exact["package_digest"], core_version="1.0.0")


def append_candidate(tmp_path: Path, *, valid: bool = True):
    value = {
        "stream_id": "alpha",
        "target_locator": "streams/alpha.jsonl",
        "record_id": "record-1",
        "expected_head": None,
        "record": {"value": 1},
        "idempotency_key": "append-key-1",
    }
    if not valid:
        value.pop("record_id")
    path = tmp_path / "append.json"
    import json
    path.write_text(json.dumps(value), encoding="utf-8")
    return capture_structured(path)


def copy_candidate(tmp_path: Path):
    value = {
        "transfer_id": "transfer-1",
        "object_id": "object-1",
        "input_binding": "payload",
        "destinations": ["objects/b", "objects/a"],
        "idempotency_key": "copy-key-1",
    }
    path = tmp_path / "copy.json"
    import json
    path.write_text(json.dumps(value), encoding="utf-8")
    return capture_structured(path)


def test_ordered_validator_runner_passes_and_marks_post_operation_not_reached(tmp_path: Path) -> None:
    registry, contract = resolved("fixture_append.v1")
    target_root = tmp_path / "target"
    target_root.mkdir()
    results = ValidatorRunner(registry).run(contract, append_candidate(tmp_path), {}, root_bindings={"fixture_result_root": target_root}, run_id="run-1", timestamp=NOW)
    assert [item["validator"]["id"] for item in results] == [item["binding"]["id"] for item in contract.document["validators"]]
    assert [item["status"] for item in results] == ["pass", "pass", "pass", "pass", "not_reached"]
    schema = registry.schema_document("https://phase-tool.local/schemas/validator-result.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for result in results:
        validator.validate(result)


def test_blocking_candidate_failure_prevents_later_validators(tmp_path: Path) -> None:
    registry, contract = resolved("fixture_append.v1")
    results = ValidatorRunner(registry).run(contract, append_candidate(tmp_path, valid=False), {}, run_id="run-2", timestamp=NOW)
    statuses = [item["status"] for item in results]
    assert statuses[:2] == ["pass", "fail"]
    assert statuses[2:] == ["not_reached", "not_reached", "not_reached"]
    assert results[1]["blockers"] == ["candidate.schema_invalid"]


def test_blocking_validator_unknown_prevents_planning(tmp_path: Path) -> None:
    registry, contract = resolved("fixture_copy.v1")
    captured = copy_candidate(tmp_path)
    results = ValidatorRunner(registry).run(
        contract,
        captured,
        {},
        run_id="run-3",
        timestamp=NOW,
        forced_unknown={"fixture.copy.candidate_v1"},
    )
    assert [item["status"] for item in results][:2] == ["pass", "unknown"]
    assert all(item["status"] == "not_reached" for item in results[2:])


def test_append_and_copy_use_same_static_plan_api(tmp_path: Path) -> None:
    append_registry, append_contract = resolved("fixture_append.v1")
    append = append_candidate(tmp_path)
    target_root = tmp_path / "append-target"
    target_root.mkdir()
    append_results = ValidatorRunner(append_registry).run(append_contract, append, {}, root_bindings={"fixture_result_root": target_root}, run_id="run-append", timestamp=NOW)
    append_plan = build_static_plan(
        append_contract,
        append,
        {},
        append_results,
        root_bindings={"fixture_result_root": target_root},
        run_id="run-append",
        generated_at=NOW,
    )

    copy_registry, copy_contract = resolved("fixture_copy.v1")
    copy = copy_candidate(tmp_path)
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "payload.bin").write_bytes(b"payload")
    frozen = copy_and_hash("payload", input_root, "payload.bin", tmp_path / "evidence" / "blobs", frozen_at=NOW)
    (input_root / "payload.bin").unlink()
    target_root = tmp_path / "copy-target"
    target_root.mkdir()
    (target_root / "objects").mkdir()
    copy_results = ValidatorRunner(copy_registry).run(copy_contract, copy, {"payload": frozen}, root_bindings={"fixture_result_root": target_root}, run_id="run-copy", timestamp=NOW)
    copy_plan = build_static_plan(
        copy_contract,
        copy,
        {"payload": frozen},
        copy_results,
        root_bindings={"fixture_result_root": target_root},
        run_id="run-copy",
        generated_at=NOW,
    )

    assert append_plan["effects"][0]["content_source"] == {
        "kind": "captured_candidate",
        "binding_id": None,
        "source_digest": append.digest,
    }
    assert {item["content_source"]["source_digest"] for item in copy_plan["effects"]} == {frozen.digest}
    assert [item["target"]["relative_locator"] for item in copy_plan["effects"]] == [
        "objects/" + hashlib.sha256(b"payload").hexdigest()
    ]
    validate_static_plan(append_plan, append_contract, {"fixture_result_root": target_root.parent / "append-target"}, append_registry)
    validate_static_plan(copy_plan, copy_contract, {"fixture_result_root": target_root}, copy_registry)


def test_plan_rejects_duplicate_ids_locator_collisions_and_wrong_mechanism(tmp_path: Path) -> None:
    registry, contract = resolved("fixture_copy.v1")
    candidate = copy_candidate(tmp_path)
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "payload").write_bytes(b"payload")
    frozen = copy_and_hash("payload", input_root, "payload", tmp_path / "blobs", frozen_at=NOW)
    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "objects").mkdir()
    results = ValidatorRunner(registry).run(contract, candidate, {"payload": frozen}, root_bindings={"fixture_result_root": target_root}, run_id="run-copy", timestamp=NOW)
    plan = build_static_plan(contract, candidate, {"payload": frozen}, results, root_bindings={"fixture_result_root": target_root}, run_id="run-copy", generated_at=NOW)
    multi_effect_contract = replace(contract, document=deepcopy(contract.document))
    multi_effect_contract.document["operation"]["maximum_effects"] = 2

    duplicate = deepcopy(plan)
    duplicate["effects"].append(deepcopy(duplicate["effects"][0]))
    with pytest.raises(PhaseError, match="plan.duplicate_effect_id"):
        validate_static_plan(duplicate, multi_effect_contract, {"fixture_result_root": target_root}, registry)

    collision = deepcopy(plan)
    collision["effects"].append(deepcopy(collision["effects"][0]))
    collision["effects"][1]["effect_id"] = "effect.copy.002"
    collision["effects"][1]["target"] = deepcopy(collision["effects"][0]["target"])
    with pytest.raises(PhaseError, match="plan.locator_collision"):
        validate_static_plan(collision, multi_effect_contract, {"fixture_result_root": target_root}, registry)

    wrong_mechanism = deepcopy(plan)
    wrong_mechanism["mechanism"]["id"] = "mechanism.other_v1"
    with pytest.raises(PhaseError, match="plan.mechanism_mismatch"):
        validate_static_plan(wrong_mechanism, contract, {"fixture_result_root": target_root}, registry)

    unauthorized_effect_mechanism = deepcopy(plan)
    entry = next(
        item
        for item in registry.to_document()["entries"]
        if item.get("kind") == "mechanism" and item.get("id") == "mechanism.exclusive_create_v1"
    )
    unauthorized_effect_mechanism["effects"][0]["mechanism"] = {
        "id": entry["id"],
        "version": entry["version"],
        "package_digest": entry["package_digest"],
    }
    with pytest.raises(PhaseError, match="plan.effect_mechanism_not_allowed"):
        validate_static_plan(unauthorized_effect_mechanism, contract, {"fixture_result_root": target_root}, registry)


def test_plan_requires_complete_root_bindings(tmp_path: Path) -> None:
    registry, contract = resolved("fixture_append.v1")
    captured = append_candidate(tmp_path)
    target_root = tmp_path / "target"
    target_root.mkdir()
    results = ValidatorRunner(registry).run(contract, captured, {}, root_bindings={"fixture_result_root": target_root}, run_id="run", timestamp=NOW)
    with pytest.raises(PhaseError, match="plan.root_binding_missing"):
        build_static_plan(contract, captured, {}, results, root_bindings={}, run_id="run", generated_at=NOW)
