"""Projection/root-check regressions; native data never grants authority.

Golden hashes use the pre-refactor 3bb protocol fields and canonical prefix,
computed independently with stdlib while preparing this source, not by calling
new helpers at test runtime. No Core dispatch/worker/native filesystem test.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phase_tool import planning
from phase_tool.candidate import CapturedCandidate
from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.freeze import FrozenInput
from phase_tool.mutation.ntfs.intent import parse_original_file_create
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers

_HOST_RECORDS = [{'binding_id': 'phase_result_root', 'resolved_path': '/synthetic-root', 'device': 7, 'inode': 19}]
_HOST_HASHES = ['sha256:314191450cbfd73ffa3ee65374f6ad8fb86e67163b207016b26dc0bfc6d4a857', 'sha256:d4ae6435fe284b1a1d1384138cdeafe164634088d07361aaa10348f5c5914b89', 'sha256:468d556272bbfa5ee9adfb427e4f82edfdb89c2dbfd250f4355d5d3a487bebe4']
_NATIVE_HASHES = ['sha256:7ce57018a511410a6f11ec77499d98afd74deaac2cd9443be635464905b4fa97', 'sha256:59f4680ce01d0819d0b28ce9c5c759bb977487789c78e98d4fa34a0041800836', 'sha256:5e2a8296f49e9a0172ea8cb81061f56b1157f1185be2ab0a340820c3c772cfe0']
_PLAN_RAW_DIGEST = 'sha256:554d3d7f8e1b301f0858f740fda2867d68c7764078912827e39db6da46b3dbb8'


class NativePlanningReuseTests(unittest.TestCase):
    def setUp(self):
        self.registry = BundledRegistry.load()
        self.intent, self.old_plan, self.pre, self.content, self.contract = buffers(self.registry)
        value = self.intent["candidate"]["storage"]["value"]
        encoded = canonical_bytes(value)
        self.candidate = CapturedCandidate("structured_json", encoded, encoded,
            profile_digest("candidate", value), len(encoded), value)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "result"; self.root.mkdir()
        self.blob = self.base / "payload"; self.blob.write_bytes(self.content)
        sha = digest_bytes(self.content)
        self.frozen = {"payload": FrozenInput("payload", "copy_and_hash", sha, len(self.content),
            self.intent["created_at"], blob_digest=sha, blob_path=self.blob)}
        self.kwargs = {"root_bindings": {"phase_result_root": self.root}, "run_id": self.intent["run_id"],
            "generated_at": self.intent["created_at"]}

    def public_plan(self):
        return planning.build_static_plan(self.contract, self.candidate, self.frozen, self.pre, **self.kwargs)

    def project(self, domain, records):
        value = self.candidate.value
        return planning._idempotency_from_root_records(self.contract, self.candidate, self.frozen,
            locator=value["target_locator"], key=value["idempotency_key"],
            root_identities=records, root_identity_profile=domain)

    def test_public_host_plan_keeps_exact_golden_bytes(self):
        plan = self.public_plan()
        self.assertEqual(digest_bytes(canonical_bytes(plan)), _PLAN_RAW_DIGEST)
        self.assertEqual(plan["effects"], self.old_plan["effects"])
        self.assertEqual(self.frozen["payload"].intent_record(), self.intent["inputs"][0])

    def test_public_missing_root_refuses_before_factory(self):
        args = dict(self.kwargs, root_bindings={})
        with patch.object(planning, "_build_static_plan_after_root_checks") as factory:
            with self.assertRaisesRegex(PhaseError, "plan.root_binding_missing"):
                planning.build_static_plan(self.contract, self.candidate, self.frozen, self.pre, **args)
            factory.assert_not_called()

    def test_public_post_factory_root_loss_refuses_before_logical_validation(self):
        original = planning._build_static_plan_after_root_checks
        def remove_own_empty_root(*args, **kwargs):
            plan = original(*args, **kwargs)
            self.root.rmdir()  # This test owns this empty synthetic directory.
            return plan
        with patch.object(planning, "_build_static_plan_after_root_checks", side_effect=remove_own_empty_root) as factory:
            with patch.object(planning, "_validate_logical_plan", wraps=planning._validate_logical_plan) as logical:
                with self.assertRaisesRegex(PhaseError, "plan.root_unavailable"):
                    self.public_plan()
                self.assertEqual(factory.call_count, 1)
                logical.assert_not_called()

    def test_public_host_identity_formula_keeps_exact_golden_hashes(self):
        # Synthetic identity records test byte compatibility only. The preceding
        # tests separately exercise real filesystem root checks; no qualifier is mocked.
        with patch.object(planning, "root_identity_records", return_value=deepcopy(_HOST_RECORDS)):
            result = planning.build_idempotency_digests(self.contract, self.candidate,
                self.frozen, {"phase_result_root": self.root})
        self.assertEqual([result[0], result[1], result[3]], _HOST_HASHES)
        self.assertEqual(result[4], _HOST_RECORDS)

    def test_host_locator_hook_still_precedes_real_identity_capture(self):
        events = []
        class Hook:
            def idempotency_locator(self, value, frozen, *, default):
                events.append("hook"); return default
        original = planning.root_identity_records
        def records(*args):
            events.append("roots"); return original(*args)
        with patch.object(planning, "load_contract_hook", return_value=Hook()):
            with patch.object(planning, "root_identity_records", side_effect=records):
                planning.build_idempotency_digests(self.contract, self.candidate, self.frozen,
                    {"phase_result_root": self.root})
        self.assertEqual(events, ["hook", "roots"])

    def test_native_projection_roundtrips_existing_original_parser_without_posix_roots(self):
        records = deepcopy(self.intent["idempotency"]["root_identities"])
        result = self.project("native-root-identity-v1", records)
        self.assertEqual([result[0], result[1], result[3]], _NATIVE_HASHES)
        self.assertNotEqual(result[3], _HOST_HASHES[2])
        args = dict(self.kwargs, root_bindings={})
        with patch.object(planning, "_resolved_root") as target_lookup:
            plan = planning._build_static_plan_after_root_checks(self.contract, self.candidate,
                self.frozen, self.pre, **args)
            target_lookup.assert_not_called()
        planning._validate_logical_plan(plan, self.contract, self.registry)
        self.assertEqual(digest_bytes(canonical_bytes(plan)), _PLAN_RAW_DIGEST)
        self.intent["idempotency"].update(scope_digest=result[0], request_digest=result[1],
            key=result[2], root_identity_digest=result[3], root_identities=result[4])
        self.intent["effect_plan_digest"] = profile_digest("effect-plan", plan)
        self.intent["implementation_binding"]["effect_plan_digest"] = self.intent["effect_plan_digest"]
        self.intent["evidence"]["effect_plan_attachment_digest"] = digest_bytes(canonical_bytes(plan))
        self.intent["evidence"]["pre_validator_results_digest"] = digest_bytes(canonical_bytes(self.pre))
        parsed = parse_original_file_create(intent_bytes=canonical_bytes(self.intent),
            plan_bytes=canonical_bytes(plan), pre_validator_bytes=canonical_bytes(self.pre),
            blob_bytes=self.content, registry=self.registry, expected_run_id=self.intent["run_id"],
            expected_intent_digest=profile_digest("intent", self.intent),
            installed_core_binding=canonical_bytes(self.intent["core"]),
            installed_native_binding=canonical_bytes(self.intent["native_binding"]),
            installed_root_grants=canonical_bytes(records),
            installed_implementation_binding=canonical_bytes(self.intent["implementation_binding"]))
        self.assertEqual(parsed.content_bytes, self.content)
        self.assertEqual(parse_json_bytes(parsed.effect_bytes), plan["effects"][0])

    def test_full_native_fileid_and_volume_bits_affect_scope(self):
        records = deepcopy(self.intent["idempotency"]["root_identities"])
        baseline = self.project("native-root-identity-v1", records)
        self.assertGreater(records[0]["native_identity"]["volume_serial"], 2**32)
        for field, value in (("volume_serial", records[0]["native_identity"]["volume_serial"] + 2**32),
            ("file_id", "1123456789abcdeffedcba9876543210")):
            with self.subTest(field=field):
                changed = deepcopy(records); changed[0]["native_identity"][field] = value
                projected = self.project("native-root-identity-v1", changed)
                self.assertNotEqual(projected[0], baseline[0])
                self.assertNotEqual(projected[1], baseline[1])
                self.assertNotEqual(projected[3], baseline[3])
                self.assertEqual(projected[4], changed)
                self.assertNotIn("inode", projected[4][0])

    def test_unknown_or_malformed_root_digest_domain_refuses(self):
        for domain in ("", "other-domain", None, True, [], {}):
            with self.subTest(domain=domain):
                with self.assertRaisesRegex(PhaseError, "plan.root_identity_profile_unsupported"):
                    self.project(domain, deepcopy(_HOST_RECORDS))
