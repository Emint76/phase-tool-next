"""Actual qualified Host/Core capture assertions; no native admission.

Evidence corruption below is explicit fixture-only fault injection after real
Core execution. It does not assert authenticity of rehashed evidence or code.
Local Windows execution is not authorized; these run in the existing Linux CI.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run, _verify_expected_capture
from phase_tool.installation import qualify_host_authority_roots, _linux_filesystem_type
from phase_tool.registry import BundledRegistry


@unittest.skipUnless(sys.platform.startswith("linux"), "NOT_VERIFIED: qualified Linux/ext4 required")
class InspectionCaptureTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="phase-inspection-capture-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.target = self.root / "target"; self.target.mkdir()
        self.evidence = self.root / "evidence"; self.evidence.mkdir()
        qualify_host_authority_roots({"target": self.target, "evidence": self.evidence})
        self.assertEqual(_linux_filesystem_type(self.evidence), "ext4")
        self.registry = BundledRegistry.load()
        self.core = PhaseCore(self.registry)
        self.source = self.root / "source.bin"
        self.payload = b"synthetic-capture-assertion\x00\xff\r\n"
        self.source.write_bytes(self.payload)
        self.value = {"operation_id": "synthetic-operation", "idempotency_key": "synthetic-key",
            "target_locator": "result.bin", "input_binding": "payload"}
        self.candidate = self.root / "candidate.json"
        # Noncanonical caller formatting; the assertion concerns captured VALUE.
        self.candidate.write_text(json.dumps(self.value, indent=4) + "\n", encoding="utf-8")
        binding = self.registry.contract_bindings()["file_create.v1@1.0.0"]
        self.request = PhaseRequest(binding["id"], binding["version"], binding["package_digest"],
            self.candidate, self.evidence, "synthetic-first", {"payload": self.source},
            {"phase_result_root": self.target}, timestamp="2026-10-25T00:00:00Z")
        self.expected = {"_expected_candidate_digest": profile_digest("candidate", self.value),
            "_expected_frozen_input": ("payload", digest_bytes(self.payload))}

    def execute(self, run_id="synthetic-first"):
        outcome = self.core.run(replace(self.request, run_id=run_id), execute=True)
        self.assertEqual(outcome.exit_code, 0, outcome.receipt)
        return outcome

    def read(self, run_id="synthetic-first", **kwargs):
        return inspect_run(self.evidence, run_id, self.registry,
            root_bindings=self.request.root_bindings, **kwargs)

    def run_root(self, run_id="synthetic-first"):
        return self.evidence / ".phase" / "runs" / run_id

    def rewrite(self, name, transform, run_id="synthetic-first"):
        path = self.run_root(run_id) / name
        value = parse_json_bytes(path.read_bytes())
        transform(value)
        path.write_bytes(canonical_bytes(value))
        return value

    def rebind_intent(self, transform):
        intent = self.rewrite("intent.json", transform)
        self.rewrite("receipt.json", lambda receipt: receipt["evidence"].update(
            intent_digest=profile_digest("intent", intent)))

    def assert_error(self, code, **kwargs):
        with self.assertRaises(PhaseError) as caught:
            self.read(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
            for p in self.root.rglob("*") if p.is_file()}

    def test_created_canonical_value_and_explicit_none_preserve_legacy_result_and_bytes(self):
        self.execute()
        before = self.snapshot()
        legacy = self.read()
        self.assertTrue(legacy["target_verified"])
        self.assertEqual(self.read(**self.expected), legacy)
        self.assertEqual(self.read(_expected_candidate_digest=None, _expected_frozen_input=None), legacy)
        self.assertEqual(self.snapshot(), before)

    def test_existing_recursion_checks_multihop_leaf_and_preserves_current_receipt(self):
        first = self.execute()
        second = self.execute("synthetic-second")
        third = self.execute("synthetic-third")
        self.assertEqual(second.receipt["execution_disposition"], "reused_existing")
        self.assertEqual(third.receipt["execution_disposition"], "reused_existing")
        # Core normally points at the executed receipt. Explicit fixture overlay
        # exercises its existing legal receipt-chain reader, not a new effect.
        self.rewrite("receipt.json", lambda receipt: receipt.update(
            prior_verified_receipt_digest=second.receipt_digest), "synthetic-third")
        before = self.snapshot()
        legacy = self.read("synthetic-third")
        checked = self.read("synthetic-third", **self.expected)
        self.assertEqual(checked, legacy)
        self.assertEqual(checked["run_id"], "synthetic-third")
        self.assertIsNone(checked["intent_digest"])
        self.assertIsNone(checked["effect_plan_digest"])
        self.assertNotEqual(checked["receipt_digest"], first.receipt_digest)
        self.assertEqual(self.snapshot(), before)
        wrong = dict(self.expected, _expected_candidate_digest="sha256:" + "0" * 64)
        self.assert_error("inspection.captured_candidate_mismatch", run_id="synthetic-third", **wrong)

    def test_independently_rehashed_different_valid_candidate_does_not_match_literal(self):
        self.execute()
        def change(intent):
            item = intent["candidate"]
            item["storage"]["value"]["operation_id"] = "different-valid-operation"
            item["digest"] = profile_digest("candidate", item["storage"]["value"])
            item["length"] = len(canonical_bytes(item["storage"]["value"]))
        self.rebind_intent(change)
        self.assertTrue(self.read()["target_verified"])
        self.assert_error("inspection.captured_candidate_mismatch", **self.expected)

    def test_canonical_value_distinguishes_boolean_integer_and_normalizes_unicode(self):
        # Pure data oracle complements real Core/receipt tests above.
        def intent(value):
            return {"candidate": {"input_mode": "structured_json",
                "digest": profile_digest("candidate", value), "length": len(canonical_bytes(value)),
                "storage": {"mode": "inline", "value": value, "attachment_digest": None}},
                "inputs": []}
        _verify_expected_capture(intent({"text": "e\u0301"}), profile_digest("candidate", {"text": "\u00e9"}), None)
        with self.assertRaisesRegex(PhaseError, "inspection.captured_candidate_mismatch"):
            _verify_expected_capture(intent({"flag": True}), profile_digest("candidate", {"flag": 1}), None)

    def test_stale_recorded_candidate_digest_and_length_are_not_accepted(self):
        self.execute()
        originals = self.snapshot()
        for field, value in (("digest", "sha256:" + "0" * 64), ("length", 1)):
            with self.subTest(field=field):
                for name, data in originals.items(): (self.root / name).write_bytes(data)
                self.rebind_intent(lambda intent: intent["candidate"].update({field: value}))
                self.assertTrue(self.read()["target_verified"])
                self.assert_error("inspection.captured_candidate_mismatch", **self.expected)

    def test_frozen_input_is_optional_but_exact_binding_and_both_digests_are_required(self):
        self.execute()
        self.assertTrue(self.read(_expected_candidate_digest=self.expected["_expected_candidate_digest"])["target_verified"])
        for binding, digest in (("different", digest_bytes(self.payload)), ("payload", "sha256:" + "0" * 64)):
            with self.subTest(binding=binding, digest=digest):
                self.assert_error("inspection.captured_input_mismatch", **dict(
                    self.expected, _expected_frozen_input=(binding, digest)))
        self.rebind_intent(lambda intent: intent["inputs"][0].update(digest="sha256:" + "1" * 64))
        self.assertTrue(self.read()["target_verified"])
        self.assert_error("inspection.captured_input_mismatch", **self.expected)

    def test_duplicate_matching_frozen_binding_cannot_be_collapsed_to_one(self):
        self.execute()
        value = parse_json_bytes((self.run_root() / "intent.json").read_bytes())
        value["inputs"].append(deepcopy(value["inputs"][0]))
        with self.assertRaisesRegex(PhaseError, "inspection.captured_input_mismatch"):
            _verify_expected_capture(value, self.expected["_expected_candidate_digest"],
                self.expected["_expected_frozen_input"])

    def test_planned_and_missing_receipt_cannot_satisfy_active_assertion(self):
        outcome = self.core.run(self.request, execute=False)
        self.assertEqual(outcome.receipt["terminal_status"], "validated_planned")
        self.assertIsNone(self.read()["target_verified"])
        self.assert_error("inspection.captured_request_unavailable", **self.expected)
        (self.run_root() / "receipt.json").unlink()  # Disposable planned fixture only.
        legacy = self.read()
        self.assertFalse(legacy["receipt_present"])
        self.assertEqual(self.read(_expected_candidate_digest=None, _expected_frozen_input=None), legacy)
        self.assert_error("inspection.captured_request_unavailable", **self.expected)

    def test_preintent_rejection_has_no_captured_request(self):
        outcome = self.core.run(replace(self.request, contract_digest="sha256:" + "0" * 64), execute=True)
        self.assertEqual(outcome.receipt["terminal_status"], "rejected")
        self.assertFalse(self.read()["intent_present"])
        self.assert_error("inspection.captured_request_unavailable", **self.expected)

    def test_existing_cycle_missing_prior_and_target_checks_still_fail(self):
        first = self.execute()
        reused = self.execute("synthetic-second")
        self.assert_error("inspection.prior_receipt_cycle", _visited_receipts=frozenset({first.receipt_digest}), **self.expected)
        self.rewrite("receipt.json", lambda receipt: receipt.update(
            prior_verified_receipt_digest="sha256:" + "0" * 64), "synthetic-second")
        self.assert_error("inspection.prior_receipt_missing", run_id="synthetic-second", **self.expected)
        (self.target / "result.bin").write_bytes(b"synthetic-tampered")
        self.assert_error("inspection.target_mismatch", **self.expected)
        self.assertIsNotNone(reused.receipt_digest)

    def test_invalid_mutable_or_malformed_expectations_refuse_before_run_resolution(self):
        valid = self.expected["_expected_candidate_digest"]
        cases = [(False, None), ("SHA256:" + "0" * 64, None), ("sha256:" + "A" * 64, None),
            (None, ("payload", valid)), (valid, ["payload", valid]),
            (valid, ("", valid)), (valid, ("payload", True)), (valid, ("payload", valid, 1))]
        for candidate, frozen in cases:
            with self.subTest(candidate=candidate, frozen=frozen):
                with patch("phase_tool.inspection.validate_run_id", side_effect=AssertionError("resolution reached")):
                    with self.assertRaisesRegex(PhaseError, "inspection.invalid_capture_expectation"):
                        self.read(_expected_candidate_digest=candidate, _expected_frozen_input=frozen)

    def test_application_forwards_active_assertions_without_changing_command_result(self):
        self.execute()
        application = PhaseApplication(registry=self.registry)
        kwargs = dict(evidence_root=self.evidence, run_id=self.request.run_id, root_bindings=self.request.root_bindings)
        legacy = application.inspect(**kwargs)
        good = application.inspect(**kwargs, **self.expected)
        self.assertEqual(good.payload, legacy.payload)
        self.assertEqual(good.exit_code, 0)
        bad = application.inspect(**kwargs, **dict(self.expected, _expected_candidate_digest="sha256:" + "0" * 64))
        self.assertFalse(bad.payload["success"])
        self.assertEqual(bad.payload["error"], "inspection.captured_candidate_mismatch")

    def test_opt_in_current_result_is_detached_and_default_result_is_unchanged(self):
        outcome = self.execute()
        before = self.snapshot()
        default = self.read(**self.expected)
        self.assertNotIn("canonical_result", default)
        self.assertEqual(self.read(**self.expected, _include_canonical_result=False), default)
        details = self.read(**self.expected, _include_canonical_result=True)
        self.assertEqual({k:v for k,v in details.items() if k!="canonical_result"}, default)
        self.assertEqual(details["canonical_result"], outcome.receipt["canonical_result"])
        self.assertEqual(details["canonical_result"]["state"]["digest"], digest_bytes(self.payload))
        self.assertEqual(details["canonical_result"]["state"]["length"], len(self.payload))
        details["canonical_result"]["state"]["length"] = 999
        self.assertEqual(self.read(_include_canonical_result=True)["canonical_result"],
            outcome.receipt["canonical_result"])
        self.assertEqual(self.snapshot(), before)

    def test_multihop_returns_current_reference_without_projecting_prior_or_new_walk(self):
        first = self.execute()
        second = self.execute("projection-second")
        self.execute("projection-third")
        def current(receipt):
            receipt["prior_verified_receipt_digest"] = second.receipt_digest
            # Valid fixture history differs from the prior. This timestamp is
            # not a new observation or an authenticity/freshness assertion.
            receipt["canonical_result"]["observed_at"] = "2026-10-25T01:02:03Z"
        receipt = self.rewrite("receipt.json", current, "projection-third")
        before = self.snapshot()
        with patch("phase_tool.inspection.inspect_run", wraps=inspect_run) as recursion:
            got = self.read("projection-third", **self.expected, _include_canonical_result=True)
        self.assertEqual(recursion.call_count, 2)
        self.assertTrue(all("_include_canonical_result" not in call.kwargs
            for call in recursion.call_args_list))
        self.assertEqual(got["canonical_result"], receipt["canonical_result"])
        self.assertNotEqual(got["canonical_result"], first.receipt["canonical_result"])
        self.assertEqual(got["receipt_digest"], profile_digest("receipt", receipt))
        self.assertEqual(got["run_id"], "projection-third")
        self.assertIsNone(got["intent_digest"])
        self.assertIsNone(got["effect_plan_digest"])
        self.assertEqual(self.snapshot(), before)

    def test_planned_missing_and_rejected_receipts_never_project_successful_result(self):
        planned = self.core.run(self.request, execute=False)
        self.assertEqual(planned.receipt["terminal_status"], "validated_planned")
        self.assertIsNone(self.read(_include_canonical_result=True).get("canonical_result"))
        self.assert_error("inspection.captured_request_unavailable",
            _include_canonical_result=True, **self.expected)
        (self.run_root() / "receipt.json").unlink()  # Disposable planned fixture.
        self.assertIsNone(self.read(_include_canonical_result=True).get("canonical_result"))
        bad = replace(self.request, run_id="projection-rejected", contract_digest="sha256:"+"0"*64)
        self.assertEqual(self.core.run(bad, execute=True).receipt["terminal_status"], "rejected")
        self.assertIsNone(self.read("projection-rejected",
            _include_canonical_result=True).get("canonical_result"))

    def test_application_details_share_one_inspection_and_preserve_public_payload(self):
        outcome = self.execute()
        app = PhaseApplication(registry=self.registry)
        kwargs = dict(evidence_root=self.evidence, run_id=self.request.run_id,
            root_bindings=self.request.root_bindings, **self.expected)
        default = app.inspect(**kwargs)
        before = self.snapshot()
        with patch("phase_tool.application.inspect_run", wraps=inspect_run) as boundary:
            response, reference = app._inspect_with_result(**kwargs, _include_canonical_result=True)
        self.assertEqual(boundary.call_count, 1)
        self.assertEqual(response.payload, default.payload)
        self.assertEqual(response.exit_code, default.exit_code)
        self.assertEqual(reference, outcome.receipt["canonical_result"])
        self.assertEqual(app._inspect_with_result(**kwargs)[1], None)
        self.assertEqual(self.snapshot(), before)
        wrong = dict(kwargs, _expected_candidate_digest="sha256:"+"0"*64)
        failed, reference = app._inspect_with_result(**wrong, _include_canonical_result=True)
        self.assertFalse(failed.payload["success"])
        self.assertEqual(failed.payload["error"], "inspection.captured_candidate_mismatch")
        self.assertIsNone(reference)

    def test_projection_flag_is_strict_before_read_and_existing_failures_are_preserved(self):
        for value in (None, 0, 1, "", [], {}):
            with self.subTest(value=value):
                with patch("phase_tool.inspection.validate_run_id",
                        side_effect=AssertionError("run resolution reached")):
                    self.assert_error("inspection.invalid_result_projection", _include_canonical_result=value)
                app = PhaseApplication(registry=self.registry)
                with patch("phase_tool.application.inspect_run",
                        side_effect=AssertionError("inspection reached")) as boundary:
                    response, reference = app._inspect_with_result(
                        evidence_root=self.evidence, run_id=self.request.run_id,
                        root_bindings=self.request.root_bindings, _include_canonical_result=value)
                self.assertEqual(boundary.call_count, 0)
                self.assertFalse(response.payload["success"])
                self.assertEqual(response.payload["error"], "inspection.invalid_result_projection")
                self.assertIsNone(reference)
        self.execute()
        self.assert_error("inspection.captured_candidate_mismatch", _include_canonical_result=True,
            **dict(self.expected, _expected_candidate_digest="sha256:"+"0"*64))
        (self.target / "result.bin").write_bytes(b"synthetic-tampered-projection")
        self.assert_error("inspection.target_mismatch", _include_canonical_result=True, **self.expected)

    def test_empty_and_one_MiB_actual_core_results_project_exact_digest_and_length(self):
        for size in (0, 1024**2):
            with self.subTest(size=size):
                payload = b"x"*size
                self.source.write_bytes(payload)
                value = dict(self.value, operation_id=f"projection-{size}",
                    idempotency_key=f"projection-{size}", target_locator=f"projection-{size}.bin")
                path = self.root / f"projection-{size}.json"
                path.write_bytes(canonical_bytes(value))
                request = replace(self.request, candidate_path=path, run_id=f"projection-{size}")
                outcome = self.core.run(request, execute=True)
                self.assertEqual(outcome.exit_code, 0, outcome.receipt)
                got = self.read(request.run_id, _include_canonical_result=True,
                    _expected_candidate_digest=profile_digest("candidate", value),
                    _expected_frozen_input=("payload", digest_bytes(payload)))
                self.assertEqual(got["canonical_result"], outcome.receipt["canonical_result"])
                self.assertEqual(got["canonical_result"]["state"]["digest"], digest_bytes(payload))
                self.assertEqual(got["canonical_result"]["state"]["length"], size)
