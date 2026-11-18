"""Contract observation-routing regressions, not native qualification.

Synthetic pairs exercise the contract hook directly. They are not native
observations or an admitted authority; no Core/provider/qualification guard is
patched. Real Host Core/frozen/evidence fixtures remain in disposable roots.
"""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.contracts import load_contract_hook
from phase_tool.contracts import publish_new_version_v1 as publish
from phase_tool.core import PhaseCore
from phase_tool.errors import PhaseError
from phase_tool.freeze import copy_and_hash
from phase_tool.registry import BundledRegistry
from . import test_publish_new_version as legacy


class SyntheticPairHook(publish.PublishNewVersionHook):
    """Test-only facts: never returned by the unchanged product factory."""
    def __init__(self, pair=None, error=None):
        self.pair, self.error, self.calls = pair, error, []

    def _observe_pair(self, root, current_locator, archive_target_locator,
                      *, allow_missing_root=False):
        self.calls.append((root, current_locator, archive_target_locator, allow_missing_root))
        if self.error is not None:
            raise self.error
        return deepcopy(self.pair)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux Host/contract component scope")
class Version1ObservationSeamTests(unittest.TestCase):
    @contextmanager
    def fixture(self, *, execute=False):
        with TemporaryDirectory(prefix="phase-version1-pair-") as name:
            base = Path(name)
            request, target, evidence, current, before, after = legacy._request(
                base, run_id="version1-pair-fixture", key="version1-pair-fixture")
            registry = BundledRegistry.load()
            contract = registry.resolve_contract(
                request.contract_id, request.contract_version, request.contract_digest,
                core_version="1.0.0")
            payload = request.input_paths["payload"]
            frozen = copy_and_hash("payload", payload.parent, payload.name,
                base / "independent-frozen", frozen_at=legacy.NOW)
            # This is the genuine ordinary Host installation, never a native
            # role constructed with an admission check patched out.
            outcome = PhaseCore().run(request, execute=execute)
            self.assertEqual(outcome.exit_code, 0)
            self.assertEqual(outcome.receipt["terminal_status"],
                "succeeded_verified" if execute else "validated_planned")
            self.assertIs(type(load_contract_hook(contract)), publish.PublishNewVersionHook)
            self.assertEqual(contract.document["operation"]["atomicity_claim"], "none")
            value = json.loads(request.candidate_path.read_bytes())
            old = {"exists": True, "digest": digest_bytes(before), "length": len(before)}
            new = {"exists": True, "digest": digest_bytes(after), "length": len(after)}
            absent = {"exists": False, "digest": None, "length": None}
            yield SimpleNamespace(base=base, request=request, target=target, evidence=evidence,
                current=current, before=before, after=after, registry=registry, contract=contract,
                frozen=frozen, inputs={"payload": frozen}, outcome=outcome, value=value,
                old=old, new=new, absent=absent, plan=outcome.effect_plan,
                archive=publish.archive_locator(value["expected_current_digest"]),
                opaque=base / "opaque-target-projection-never-created")

    @contextmanager
    def forbid_target_io(self, opaque):
        def reject(*args, **kwargs):
            raise AssertionError("contract component used POSIX target I/O")
        def guarded(original):
            def check(path, *args, **kwargs):
                if path == opaque or path.is_relative_to(opaque):
                    return reject()
                return original(path, *args, **kwargs)
            return check
        with ExitStack() as stack:
            for name in ("_state", "inspect_target_path", "observe_target"):
                stack.enter_context(patch.object(publish, name, side_effect=reject))
            # Frozen-input and evidence paths stay real. Opaque target
            # projections alone must never reach these filesystem methods.
            for name in ("exists", "stat", "lstat", "open", "resolve"):
                stack.enter_context(patch.object(Path, name, guarded(getattr(Path, name))))
            yield

    def assert_pair_call(self, hook, fixture, *, allow_missing_root=False):
        self.assertEqual(hook.calls, [(fixture.opaque, fixture.value["target_locator"],
            fixture.archive, allow_missing_root)])

    def test_precondition_golden_states_and_legacy_wrapper(self):
        # Explicit contract outcomes, including exact permitted continuation
        # states. Physical fixtures also exercise the unchanged legacy API.
        variants = (
            ("before", "absent", "pass", "validation.pass", "current_before_archive_absent"),
            ("before", "before", "pass", "validation.pass", "current_before_archive_exact"),
            ("after", "before", "pass", "validation.pass", "current_after_archive_exact"),
            ("after", "absent", "fail", "publish.state_conflict", "before_or_safe_continuation"),
            ("before", "wrong", "fail", "publish.state_conflict", "before_or_safe_continuation"),
        )
        for current_kind, archive_kind, status, code, expected in variants:
            with self.subTest(current=current_kind, archive=archive_kind), self.fixture() as f:
                current = f.old if current_kind == "before" else f.new
                archive = (f.absent if archive_kind == "absent" else f.old
                    if archive_kind == "before" else
                    {"exists": True, "digest": digest_bytes(b"wrong"), "length": 5})
                f.current.write_bytes(f.before if current_kind == "before" else f.after)
                if archive_kind != "absent":
                    archive_path = f.target / f.archive
                    archive_path.parent.mkdir(parents=True)
                    archive_path.write_bytes(f.before if archive_kind == "before" else b"wrong")
                legacy_result = publish.validate_preconditions(f.value, f.frozen, f.target)
                hook = SyntheticPairHook((current, archive))
                with self.forbid_target_io(f.opaque):
                    actual = hook._validate_preconditions(f.value, f.frozen, f.opaque)
                self.assertEqual(actual, legacy_result)
                self.assertEqual(actual[:3], (status, code, expected))
                self.assertEqual(actual[3], {"current": current, "archive": archive})
                self.assertEqual(actual[4], [] if status == "pass" else ["publish.state_conflict"])
                self.assert_pair_call(hook, f)

    def test_build_routes_pair_and_preserves_only_planning_missing_root_skip(self):
        with self.fixture() as f:
            for pair, expected_length in (
                    ((f.old, f.absent), len(f.before)),
                    ((f.new, f.old), len(f.before)),
                    ((f.new, f.absent), None), (None, None)):
                with self.subTest(pair=pair):
                    hook = SyntheticPairHook(pair)
                    with self.forbid_target_io(f.opaque):
                        effects = hook.build_effects(f.contract, f.value, f.inputs,
                            run_id=f.request.run_id, generated_at=legacy.NOW,
                            root_bindings={"fixture_result_root": f.opaque})
                    self.assertEqual(len(effects), 1)
                    self.assertEqual(effects[0]["archive_length"], expected_length)
                    expected = deepcopy(f.plan["effects"][0])
                    # Compare all contract-owned effect fields with the actual
                    # Host plan; ordinal0 and request_digestNone stay unchanged.
                    expected["archive_length"] = expected_length
                    self.assertEqual(effects[0], expected)
                    self.assert_pair_call(hook, f, allow_missing_root=True)
            missing = f.base / "ordinary-missing-target-root"
            with patch.object(publish, "_state", side_effect=AssertionError(
                    "missing build root must skip state reads")) as state:
                effects = publish.PublishNewVersionHook().build_effects(
                    f.contract, f.value, f.inputs, run_id=f.request.run_id,
                    generated_at=legacy.NOW, root_bindings={"fixture_result_root": missing})
            state.assert_not_called()
            self.assertIsNone(effects[0]["archive_length"])
            hook = SyntheticPairHook(error=PhaseError("synthetic.pair.unavailable"))
            with self.forbid_target_io(f.opaque), self.assertRaisesRegex(
                    PhaseError, "synthetic.pair.unavailable"):
                hook.build_effects(f.contract, f.value, f.inputs, run_id=f.request.run_id,
                    generated_at=legacy.NOW, root_bindings={"fixture_result_root": f.opaque})
            self.assert_pair_call(hook, f, allow_missing_root=True)

    def test_validator_uses_pair_only_when_preconditions_need_target_facts(self):
        with self.fixture() as f:
            roots = {"fixture_result_root": f.opaque}
            hook = SyntheticPairHook((f.old, f.absent))
            with self.forbid_target_io(f.opaque):
                candidate = hook.run_validator("publish_new_version.candidate_v1", f.contract,
                    f.value, f.inputs, roots, f.registry, evidence_root=f.evidence)
                self.assertEqual(candidate[:2], ("pass", "validation.pass"))
                self.assertEqual(hook.calls, [])
                self.assertIsNone(hook.run_validator("unknown.validator", f.contract,
                    f.value, f.inputs, roots, f.registry))
                missing = hook.run_validator("publish_new_version.preconditions_v1", f.contract,
                    f.value, {}, roots, f.registry)
                self.assertEqual(missing[:2], ("fail", "input.required_missing"))
                self.assertEqual(hook.calls, [])
                actual = hook.run_validator("publish_new_version.preconditions_v1", f.contract,
                    f.value, f.inputs, roots, f.registry)
            self.assertEqual(actual[:3], ("pass", "validation.pass", "current_before_archive_absent"))
            self.assert_pair_call(hook, f)
            broken = SyntheticPairHook(error=PhaseError("synthetic.pair.unavailable"))
            with self.forbid_target_io(f.opaque):
                rejected = broken.run_validator("publish_new_version.preconditions_v1", f.contract,
                    f.value, f.inputs, roots, f.registry)
            self.assertEqual(rejected[:2], ("fail", "synthetic.pair.unavailable"))
            self.assertEqual(rejected[4], ["synthetic.pair.unavailable"])
            self.assert_pair_call(broken, f)

    def test_before_effect_uses_instance_pair_and_preserves_refusal(self):
        with self.fixture() as f:
            effect = f.plan["effects"][0]
            hook = SyntheticPairHook((f.old, f.absent))
            with self.forbid_target_io(f.opaque):
                self.assertIsNone(hook.before_effect([], f.contract, effect, f.inputs, f.opaque))
                self.assertIsNone(hook.before_effect(f.value, f.contract,
                    effect | {"kind": "exclusive_create"}, f.inputs, f.opaque))
                self.assertEqual(hook.calls, [])
                hook.before_effect(f.value, f.contract, effect, f.inputs, f.opaque)
            self.assert_pair_call(hook, f)
            for pair, error in (((f.new, f.absent), None),
                    (None, PhaseError("synthetic.pair.unavailable"))):
                broken = SyntheticPairHook(pair, error)
                expected = "publish.state_conflict" if error is None else "synthetic.pair.unavailable"
                with self.forbid_target_io(f.opaque), self.assertRaisesRegex(PhaseError, expected):
                    broken.before_effect(f.value, f.contract, effect, f.inputs, f.opaque)
                self.assert_pair_call(broken, f)

    def test_post_validator_checks_both_pair_states_and_propagates_unknown(self):
        with self.fixture(execute=True) as f:
            for pair, expected in (((f.new, f.old), "pass"),
                    ((f.old, f.old), "fail"), ((f.new, f.absent), "fail")):
                hook = SyntheticPairHook(pair)
                with self.forbid_target_io(f.opaque):
                    self.assertIsNone(hook.run_post_validator("unknown.validator",
                        f.contract, {}, {"fixture_result_root": f.opaque}))
                    self.assertEqual(hook.calls, [])
                    actual = hook.run_post_validator("publish_new_version.result_v1",
                        f.contract, f.plan, {"fixture_result_root": f.opaque})
                self.assertEqual(actual[0], expected)
                self.assertEqual(actual[1], "validation.pass" if expected == "pass"
                    else "verification.result_mismatch")
                self.assertEqual(actual[3], {"current": pair[0], "archive": pair[1]})
                self.assert_pair_call(hook, f)
            broken = SyntheticPairHook(error=PhaseError("synthetic.pair.unavailable"))
            with self.forbid_target_io(f.opaque), self.assertRaisesRegex(
                    PhaseError, "synthetic.pair.unavailable"):
                broken.run_post_validator("publish_new_version.result_v1", f.contract,
                    f.plan, {"fixture_result_root": f.opaque})
            self.assert_pair_call(broken, f)

    def test_receipt_inspection_routes_pair_and_preserves_binding_checks(self):
        with self.fixture(execute=True) as f:
            # A genuine ordinary Host receipt is the golden input, not a fake
            # successful native receipt. The synthetic pair is component data.
            receipt = f.outcome.receipt
            golden = publish.PublishNewVersionHook().inspect_receipt_result(
                receipt, f.plan, f.target, f.registry, f.evidence)
            hook = SyntheticPairHook((f.new, f.old))
            with self.forbid_target_io(f.opaque):
                actual = hook.inspect_receipt_result(receipt, f.plan, f.opaque,
                    f.registry, f.evidence)
            self.assertEqual(actual, golden)
            self.assertEqual(actual, {"current": f.new, "archive": f.old})
            self.assert_pair_call(hook, f)
            for pair in ((f.old, f.old), (f.new, f.absent)):
                broken = SyntheticPairHook(pair)
                with self.forbid_target_io(f.opaque), self.assertRaisesRegex(
                        PhaseError, "inspection.target_mismatch"):
                    broken.inspect_receipt_result(receipt, f.plan, f.opaque,
                        f.registry, f.evidence)
                self.assert_pair_call(broken, f)
            for field, value, before_pair in (
                    ("attempted", False, True), ("status", "failed_partial", True),
                    ("before", {"known": False}, False),
                    ("archive_after", {"known": False}, False)):
                with self.subTest(field=field):
                    altered = deepcopy(receipt)
                    altered["effect_receipts"][0][field] = value
                    broken = SyntheticPairHook((f.new, f.old))
                    with self.forbid_target_io(f.opaque), self.assertRaisesRegex(
                            PhaseError, "inspection.effect_receipts_mismatch"):
                        broken.inspect_receipt_result(altered, f.plan, f.opaque,
                            f.registry, f.evidence)
                    if before_pair:self.assertEqual(broken.calls, [])
                    else:self.assert_pair_call(broken, f)
            broken = SyntheticPairHook(error=PhaseError("synthetic.pair.unavailable"))
            with self.forbid_target_io(f.opaque), self.assertRaisesRegex(
                    PhaseError, "synthetic.pair.unavailable"):
                broken.inspect_receipt_result(receipt, f.plan, f.opaque, f.registry, f.evidence)
            self.assert_pair_call(broken, f)

    def test_prior_intent_classification_reuses_instance_pair_and_checks_digest_first(self):
        with self.fixture() as f:
            roots = {"fixture_result_root": f.opaque}
            for pair, state in (((f.old, f.absent), "no_effect_observed"),
                    ((f.old, f.old), "archived_not_published"),
                    ((f.new, f.old), "published_not_finalized"),
                    ((f.new, f.absent), "blocked")):
                hook = SyntheticPairHook(pair)
                with self.forbid_target_io(f.opaque):
                    actual = hook.classify_prior_execution(f.evidence, f.request.run_id,
                        roots, f.registry)
                self.assertEqual(actual, state)
                self.assert_pair_call(hook, f)
            # Tamper only an owned ephemeral fixture. Digest refusal must
            # happen before any target observation, not be repaired by a pair.
            plan_path = f.evidence / ".phase" / "runs" / f.request.run_id / "attachments/effect-plan.json"
            altered = deepcopy(f.plan); altered["write_scope_digest"] = "sha256:" + "0" * 64
            plan_path.write_bytes(canonical_bytes(altered))
            hook = SyntheticPairHook(error=AssertionError("digest refusal queried target"))
            with self.forbid_target_io(f.opaque):
                self.assertEqual(hook.classify_prior_execution(f.evidence,
                    f.request.run_id, roots, f.registry), "blocked")
            self.assertEqual(hook.calls, [])

    def test_missing_receipt_classification_refuses_before_pair_and_never_falls_back(self):
        with self.fixture() as f:
            roots = {"fixture_result_root": f.opaque}
            for pair, state in (((f.old, f.absent), "no_effect_observed"),
                    ((f.old, f.old), "archived_not_published"),
                    ((f.new, f.old), "published_not_finalized")):
                hook = SyntheticPairHook(pair)
                with self.forbid_target_io(f.opaque):
                    actual = hook.inspect_missing_receipt_result(f.plan, roots, f.registry)
                self.assertEqual(actual, state)
                self.assert_pair_call(hook, f)
            unsupported = [
                f.plan | {"operation_intent": "create"},
                f.plan | {"effects": []},
                f.plan | {"effects": [f.plan["effects"][0] | {"kind": "exclusive_create"}]},
            ]
            for plan in unsupported:
                hook = SyntheticPairHook(error=AssertionError("unsupported plan queried target"))
                with self.forbid_target_io(f.opaque):
                    self.assertEqual(hook.inspect_missing_receipt_result(plan, roots, f.registry), "blocked")
                self.assertEqual(hook.calls, [])
            hook = SyntheticPairHook(error=AssertionError("missing root binding queried target"))
            with self.forbid_target_io(f.opaque):
                self.assertEqual(hook.inspect_missing_receipt_result(f.plan, {}, f.registry), "blocked")
            self.assertEqual(hook.calls, [])
            broken = SyntheticPairHook(error=PhaseError("synthetic.pair.unavailable"))
            with self.forbid_target_io(f.opaque):
                self.assertEqual(broken.inspect_missing_receipt_result(f.plan, roots, f.registry), "blocked")
            self.assert_pair_call(broken, f)
            # The explicit legacy module API still selects the default Host
            # implementation, whose actual current/archive facts agree here.
            self.assertEqual(publish._inspect_plan_state(f.plan,
                {"fixture_result_root": f.target}), "no_effect_observed")


if __name__ == "__main__":unittest.main()
