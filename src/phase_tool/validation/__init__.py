from __future__ import annotations

import base64
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from ..candidate import CapturedCandidate
from ..canonical import digest_bytes, parse_json_bytes, profile_digest
from ..errors import PhaseError
from ..freeze import FrozenInput, revalidate_frozen, revalidate_snapshot
from ..paths import contained_read_path, inspect_target_path, safe_relative_locator
from ..registry import RegistrySnapshot, ResolvedContract
from ..contracts import append_locator, load_contract_hook
from ..contracts import task_journal_v1
from ..append_codec import stream_head_token, validate_stream_bytes


class ValidatorRunner:
    """Runs only the fixed validator declarations already admitted by the registry."""

    def __init__(self, registry: RegistrySnapshot) -> None:
        self.registry = registry
        self._result_schema = registry.schema_document("https://phase-tool.local/schemas/validator-result.schema.json")
        self._result_validator = Draft202012Validator(self._result_schema, format_checker=FormatChecker())

    def _result(
        self,
        declaration: Mapping[str, Any],
        *,
        run_id: str,
        timestamp: str,
        status: str,
        code: str,
        expected: Any,
        actual: Any,
        blockers: list[str],
    ) -> dict[str, Any]:
        binding = declaration["binding"]
        result = {
            "validator_result_version": "1.0",
            "run_id": run_id,
            "phase": declaration["phase"],
            "validator": {"id": binding["id"], "version": binding["version"], "package_digest": binding["package_digest"]},
            "status": status,
            "code": code,
            "blocking": declaration["blocking"],
            "expected": expected,
            "actual": actual,
            "observation_refs": [],
            "blockers": blockers,
            "started_at": timestamp,
            "finished_at": timestamp,
        }
        self._result_validator.validate(result)
        return result

    def _candidate_validation(self, contract: ResolvedContract, candidate: CapturedCandidate) -> tuple[str, str, Any, Any, list[str]]:
        schema = self.registry.schema_document(contract.document["candidate"]["schema_ref"], contract.document["candidate"]["schema_digest"])
        value = parse_json_bytes(candidate.canonical_bytes)
        errors = sorted(
            Draft202012Validator(
                schema,
                registry=self.registry.schema_registry(),
                format_checker=FormatChecker(),
            ).iter_errors(value),
            key=lambda error: list(error.path),
        )
        if errors:
            return "fail", "candidate.schema_invalid", "schema_valid", errors[0].message, ["candidate.schema_invalid"]
        return "pass", "validation.pass", "schema_valid", "schema_valid", []

    def run_candidate_schema(
        self,
        contract: ResolvedContract,
        candidate: CapturedCandidate,
        *,
        run_id: str,
        timestamp: str,
    ) -> dict[str, Any]:
        declaration = next(item for item in contract.document["validators"] if item["phase"] == "candidate")
        outcome = self._candidate_validation(contract, candidate)
        return self._result(
            declaration,
            run_id=run_id,
            timestamp=timestamp,
            status=outcome[0],
            code=outcome[1],
            expected=outcome[2],
            actual=outcome[3],
            blockers=outcome[4],
        )

    def _target_root(self, contract: ResolvedContract, root_bindings: Mapping[str, Path]) -> Path:
        binding = contract.document["canonical_result"]["root_binding"]
        try:
            return Path(root_bindings[binding])
        except KeyError as exc:
            raise PhaseError("plan.root_binding_missing", binding) from exc

    def _run_builtin(
        self,
        identifier: str,
        contract: ResolvedContract,
        candidate: CapturedCandidate,
        frozen_inputs: Mapping[str, FrozenInput],
        root_bindings: Mapping[str, Path],
        evidence_root: Path | None,
    ) -> tuple[str, str, Any, Any, list[str]]:
        value = parse_json_bytes(candidate.canonical_bytes)
        if identifier == "validator.exact_binding_v1":
            return "pass", "validation.pass", "exact_registry_binding", "exact_registry_binding", []
        hook = load_contract_hook(contract)
        if hook is not None:
            setattr(hook, "_registry", self.registry)
            handled = hook.run_validator(identifier, contract, value, frozen_inputs, root_bindings, self.registry, evidence_root=evidence_root)
            if handled is not None:
                return handled
        if identifier == "phase.ordered_effect_plan_progress_v1":
            return "not_reached", "validation.not_reached", "post_operation", None, []
        if identifier in {"fixture.append.candidate_v1", "fixture.copy.candidate_v1", "fixture.create.candidate_v1"}:
            outcome = self._candidate_validation(contract, candidate)
            if outcome[0] != "pass" or identifier != "fixture.copy.candidate_v1":
                return outcome
            try:
                for locator in value["destinations"]:
                    safe_relative_locator(locator)
            except PhaseError as exc:
                return "fail", exc.code, "safe_relative_locator", str(locator), [exc.code]
            return outcome
        if identifier == "task_journal.candidate_v1":
            schema = self.registry.schema_document(contract.document["candidate"]["schema_ref"], contract.document["candidate"]["schema_digest"])
            return task_journal_v1.validate_candidate(value, schema)
        if identifier == "task_journal.state_v1":
            root = self._target_root(contract, root_bindings)
            locator = append_locator(contract.document, value)
            path, _exists = inspect_target_path(root, locator)
            return task_journal_v1.validate_state(value, path)
        if identifier == "validator.frozen_blob_v1":
            frozen = frozen_inputs.get("payload")
            if frozen is None:
                return "fail", "input.required_missing", "payload", None, ["input.required_missing"]
            try:
                revalidate_frozen(frozen)
            except PhaseError as exc:
                return "fail", exc.code, frozen.digest, "mismatch", [exc.code]
            return "pass", "validation.pass", frozen.digest, frozen.digest, []
        if identifier == "validator.destination_absent_v1":
            root = self._target_root(contract, root_bindings)
            target, exists = inspect_target_path(root, value["target_locator"])
            if exists:
                return "fail", "target.destination_exists", "absent", "present", ["target.destination_exists"]
            return "pass", "validation.pass", "absent", "absent", []
        if identifier == "validator.expected_head_v1":
            root = self._target_root(contract, root_bindings)
            locator = append_locator(contract.document, value) if contract.document["operation"]["intent"] == "append" else value["target_locator"]
            target, exists = inspect_target_path(root, locator)
            expected = value["expected_head"]
            if expected is None:
                if exists:
                    return "fail", "target.same_key_conflict", "absent", "present", ["target.same_key_conflict"]
                return "pass", "validation.pass", "absent", "absent", []
            frozen = frozen_inputs.get("current_state")
            if not exists or frozen is None:
                return "fail", "freeze.stale_snapshot", expected, None, ["freeze.stale_snapshot"]
            if contract.document["operation"]["intent"] == "append":
                try:
                    current_head = stream_head_token(target.read_bytes())
                except PhaseError as exc:
                    return "fail", exc.code, expected, "invalid_stream", [exc.code]
                if expected != current_head:
                    return "fail", "freeze.stale_snapshot", expected, current_head, ["freeze.stale_snapshot"]
            else:
                try:
                    revalidate_snapshot(frozen, root)
                except PhaseError as exc:
                    return "fail", exc.code, expected, "stale", [exc.code]
                if expected not in {frozen.digest, frozen.revalidation_token}:
                    return "fail", "freeze.stale_snapshot", expected, frozen.revalidation_token, ["freeze.stale_snapshot"]
            return "pass", "validation.pass", expected, expected, []
        if identifier == "validator.valid_tail_v1":
            if value["expected_head"] is None:
                return "pass", "validation.pass", "not_applicable", "not_applicable", []
            root = self._target_root(contract, root_bindings)
            locator = append_locator(contract.document, value)
            target, exists = inspect_target_path(root, locator)
            if not exists or not target.is_file():
                return "fail", "input.invalid_tail", True, False, ["input.invalid_tail"]
            try:
                validate_stream_bytes(target.read_bytes())
            except PhaseError as exc:
                return "fail", exc.code, True, False, [exc.code]
            return "pass", "validation.pass", True, True, []
        if identifier == "validator.destination_preconditions_v1":
            frozen = frozen_inputs.get("payload")
            if frozen is None:
                return "fail", "input.required_missing", "payload", None, ["input.required_missing"]
            root = self._target_root(contract, root_bindings)
            if contract.document["operation"]["intent"] == "copy":
                locators = ["objects/" + frozen.digest.removeprefix("sha256:")]
            else:
                locators = value["destinations"]
            observed: list[str] = []
            for locator in locators:
                target, exists = inspect_target_path(root, locator)
                if exists:
                    if not target.is_file() or digest_bytes(target.read_bytes()) != frozen.digest:
                        return "fail", "target.same_key_conflict", frozen.digest, locator, ["target.same_key_conflict"]
                    observed.append("same_digest")
                else:
                    observed.append("absent")
            return "pass", "validation.pass", "absent_or_same_digest", observed, []
        if identifier == "validator.result_digest_v1":
            return "not_reached", "validation.not_reached", "post_operation", None, []
        raise PhaseError("validator.unavailable", identifier)

    def run(
        self,
        contract: ResolvedContract,
        candidate: CapturedCandidate,
        frozen_inputs: Mapping[str, FrozenInput],
        *,
        root_bindings: Mapping[str, Path] | None = None,
        evidence_root: Path | None = None,
        run_id: str,
        timestamp: str,
        forced_unknown: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        roots = root_bindings or {}
        unknown = forced_unknown or set()
        blocked = False
        results: list[dict[str, Any]] = []
        for declaration in contract.document["validators"]:
            identifier = declaration["binding"]["id"]
            if blocked or declaration["phase"] == "post_operation":
                outcome = ("not_reached", "validation.not_reached", "prior_phases_pass", None, [])
            elif identifier in unknown:
                blockers = ["validator.unknown"] if declaration["blocking"] else []
                outcome = ("unknown", "validator.unknown", "known_result", None, blockers)
            else:
                outcome = self._run_builtin(identifier, contract, candidate, frozen_inputs, roots, evidence_root)
            result = self._result(
                declaration,
                run_id=run_id,
                timestamp=timestamp,
                status=outcome[0],
                code=outcome[1],
                expected=outcome[2],
                actual=outcome[3],
                blockers=outcome[4],
            )
            results.append(result)
            if declaration["blocking"] and result["status"] in {"fail", "unknown"}:
                blocked = True
        return results

    def run_post_operation(
        self,
        contract: ResolvedContract,
        prior_results: list[dict[str, Any]],
        effect_plan: Mapping[str, Any],
        root_bindings: Mapping[str, Path],
        *,
        evidence_root: Path | None = None,
        run_id: str,
        timestamp: str,
        effect_receipts: list[dict[str, Any]] | None = None,
        ordered_progress: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Re-run declared post validators against actual target bytes."""
        completed = list(prior_results)
        declarations = list(contract.document["validators"])
        for index, declaration in enumerate(declarations):
            if declaration["phase"] != "post_operation":
                continue
            identifier = declaration["binding"]["id"]
            if identifier == "phase.ordered_effect_plan_progress_v1":
                receipts = effect_receipts or []
                receipt_by_id = {receipt["effect_id"]: receipt for receipt in receipts}
                completed_ids: list[str] = []
                verified_ids: list[str] = []
                not_started_ids: list[str] = []
                failed_id: str | None = None
                expected_effects: list[dict[str, Any]] = []
                for ordinal, effect in enumerate(effect_plan["effects"]):
                    effect_id = effect["effect_id"]
                    receipt = receipt_by_id.get(effect_id)
                    if receipt is None:
                        not_started_ids.append(effect_id)
                        state = "not_started"
                        receipt_digest = None
                        observation_digest = None
                    else:
                        completed_ids.append(effect_id)
                        status = receipt["status"]
                        receipt_digest = profile_digest("effect-receipt", receipt)
                        observation_digest = profile_digest(
                            "effect-observation",
                            {"effect_id": effect_id, "after": receipt["after"], "status": status},
                        )
                        if status == "applied_verified":
                            verified_ids.append(effect_id)
                            state = "verified_existing" if receipt.get("bytes_written") == 0 else "applied_new_verified"
                        else:
                            state = status
                            failed_id = failed_id or effect_id
                    expected_effects.append(
                        {
                            "ordinal": effect.get("ordinal", ordinal),
                            "effect_id": effect_id,
                            "kind": effect["kind"],
                            "mechanism": effect.get("mechanism", effect_plan["mechanism"])["id"],
                            "state": state,
                            "target": {
                                "root_binding": effect["target"]["root_binding"],
                                "relative_locator": effect["target"]["relative_locator"],
                                "expected_digest": effect["content_digest"],
                            },
                            "receipt_digest": receipt_digest,
                            "observation_digest": observation_digest,
                        }
                    )
                expected_progress = {
                    "progress_version": "1.0",
                    "plan_digest": profile_digest("effect-plan", effect_plan),
                    "maximum_effects": len(effect_plan["effects"]),
                    "completed_effect_ids": completed_ids,
                    "verified_effect_ids": verified_ids,
                    "failed_effect_id": failed_id,
                    "not_started_effect_ids": not_started_ids,
                    "effects": expected_effects,
                }
                schema = self.registry.schema_document("https://phase-tool.local/schemas/ordered-effect-progress.schema.json")
                schema_errors = [] if ordered_progress is None else list(
                    Draft202012Validator(
                        schema,
                        registry=self.registry.schema_registry(),
                        format_checker=FormatChecker(),
                    ).iter_errors(ordered_progress)
                )
                matches = ordered_progress is not None and not schema_errors and dict(ordered_progress) == expected_progress
                completed[index] = self._result(
                    declaration,
                    run_id=run_id,
                    timestamp=timestamp,
                    status="pass" if matches else "fail",
                    code="validation.pass" if matches else "validation.ordered_progress_mismatch",
                    expected=expected_progress,
                    actual=ordered_progress,
                    blockers=[] if matches else ["validation.ordered_progress_mismatch"],
                )
                continue
            hook = load_contract_hook(contract)
            if hook is not None:
                setattr(hook, "_registry", self.registry)
                handled = hook.run_post_validator(identifier, contract, effect_plan, root_bindings, evidence_root=evidence_root)
                if handled is None:
                    pass
                else:
                    status, code, expected, actual, blockers = handled
                    completed[index] = self._result(
                        declaration,
                        run_id=run_id,
                        timestamp=timestamp,
                        status=status,
                        code=code,
                        expected=expected,
                        actual=actual,
                        blockers=blockers,
                    )
                    continue
            if identifier != "validator.result_digest_v1":
                raise PhaseError("validator.unavailable", identifier)
            expected: list[dict[str, Any]] = []
            actual: list[dict[str, Any]] = []
            blockers: list[str] = []
            for effect in effect_plan["effects"]:
                root_id = effect["target"]["root_binding"]
                try:
                    root = Path(root_bindings[root_id])
                except KeyError as exc:
                    raise PhaseError("plan.root_binding_missing", root_id) from exc
                locator = effect["target"]["relative_locator"]
                expected.append({"locator": locator, "digest": effect["content_digest"], "length": effect["content_length"]})
                try:
                    path = contained_read_path(root, locator)
                    data = path.read_bytes()
                    observation = {"locator": locator, "digest": digest_bytes(data), "length": len(data)}
                    actual.append(observation)
                    if effect["kind"] == "append_record":
                        encoded = effect.get("content_bytes_b64")
                        record = base64.b64decode(encoded.encode("ascii"), validate=True) if isinstance(encoded, str) else b""
                        if not record or not data.endswith(record):
                            blockers.append("verification.result_mismatch")
                    elif observation["digest"] != effect["content_digest"] or observation["length"] != effect["content_length"]:
                        blockers.append("verification.result_mismatch")
                except (OSError, PhaseError):
                    actual.append({"locator": locator, "digest": None, "length": None})
                    blockers.append("verification.target_unavailable")
            status = "pass" if not blockers else "fail"
            completed[index] = self._result(
                declaration,
                run_id=run_id,
                timestamp=timestamp,
                status=status,
                code="validation.pass" if not blockers else blockers[0],
                expected=expected,
                actual=actual,
                blockers=sorted(set(blockers)),
            )
        return completed
