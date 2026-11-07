"""Pure publication projection components; no native qualification or authority.

The small JSON fixtures are not accepted Core intents, manifests or profiles.
Rehashed tampering tests the literal correlations after digest consistency.
Existing Host integration tests exercise the caller and cleanup semantics.
"""
from copy import deepcopy
import hashlib
import unittest

from phase_tool.canonical import profile_digest
from phase_tool.errors import PhaseError
from phase_tool.publish_file import (
    _file_publication_candidate, _require_file_publication_evidence,
)


class FilePublicationFactsTests(unittest.TestCase):
    def facts(self):
        candidate = {
            'operation_id': 'ready-file', 'idempotency_key': 'ready-file',
            'input_binding': 'payload', 'target_locator': 'document.bin',
        }
        binding = {'id': 'file_create.v1', 'version': '1.0.0',
                   'package_digest': 'sha256:' + '1'*64}
        content_digest = 'sha256:' + hashlib.sha256(b'fixture').hexdigest()
        intent = {
            'candidate': {'storage': {'value': deepcopy(candidate)}},
            'contract': deepcopy(binding), 'idempotency': {'key': 'ready-file'},
        }
        plan = {'effects': [{
            'target': {'root_binding': 'phase_result_root',
                       'relative_locator': 'document.bin'},
            'content_digest': content_digest, 'content_length': 7,
            'kind': 'exclusive_create',
        }]}
        return dict(intent=intent, plan=plan, binding=binding, candidate=candidate,
                    intent_digest=profile_digest('intent', intent),
                    effect_plan_digest=profile_digest('effect-plan', plan),
                    content_digest=content_digest, content_length=7,
                    target_locator='document.bin', request_id='ready-file')

    def rehash(self, facts):
        facts['intent_digest'] = profile_digest('intent', facts['intent'])
        facts['effect_plan_digest'] = profile_digest('effect-plan', facts['plan'])

    def rejected(self, facts):
        with self.assertRaises(PhaseError) as raised:
            _require_file_publication_evidence(**facts)
        self.assertEqual(raised.exception.code, 'publish_file.evidence_mismatch')

    def test_valid_literal_projection_matches(self):
        self.assertIsNone(_require_file_publication_evidence(**self.facts()))

    def test_rehashed_idempotency_still_requires_original_request_id(self):
        facts = self.facts()
        facts['intent']['idempotency']['key'] = 'other-request'
        self.rehash(facts)
        self.rejected(facts)

    def test_rehashed_candidate_and_contract_mismatches_rejected(self):
        for field in ('candidate', 'contract'):
            with self.subTest(field=field):
                facts = self.facts()
                if field == 'candidate':
                    facts['intent']['candidate']['storage']['value']['target_locator'] = 'other.bin'
                else:
                    facts['intent']['contract']['package_digest'] = 'sha256:' + '2'*64
                self.rehash(facts)
                self.rejected(facts)

    def test_rehashed_effect_projection_and_count_mismatches_rejected(self):
        for field in ('root', 'locator', 'digest', 'length', 'kind', 'zero', 'two'):
            with self.subTest(field=field):
                facts = self.facts()
                effect = facts['plan']['effects'][0]
                if field == 'root':
                    effect['target']['root_binding'] = 'another_root'
                elif field == 'locator':
                    effect['target']['relative_locator'] = 'other.bin'
                elif field == 'digest':
                    effect['content_digest'] = 'sha256:' + '3'*64
                elif field == 'length':
                    effect['content_length'] = 8
                elif field == 'kind':
                    effect['kind'] = 'atomic_replace'
                elif field == 'zero':
                    facts['plan']['effects'] = []
                else:
                    facts['plan']['effects'].append(deepcopy(effect))
                self.rehash(facts)
                self.rejected(facts)

    def test_profile_digest_mismatch_rejected(self):
        for field in ('intent_digest', 'effect_plan_digest'):
            with self.subTest(field=field):
                facts = self.facts()
                facts[field] = 'sha256:' + '0'*64
                self.rejected(facts)

    def test_candidate_literal_bytes_preserved(self):
        candidate, raw = _file_publication_candidate('ready-file', 'document.bin')
        self.assertEqual(candidate, self.facts()['candidate'])
        self.assertEqual(raw,
            b'{"idempotency_key":"ready-file","input_binding":"payload",'
            b'"operation_id":"ready-file","target_locator":"document.bin"}')

    def test_candidate_byte_bound_is_unchanged(self):
        # Pure builder bound only; ordinary locator validation remains at caller.
        empty = (b'{"idempotency_key":"ready-file","input_binding":"payload",'
                 b'"operation_id":"ready-file","target_locator":""}')
        locator = 'a' * (1_048_576-len(empty))
        _, raw = _file_publication_candidate('ready-file', locator)
        self.assertEqual(len(raw), 1_048_576)
        with self.assertRaises(PhaseError) as raised:
            _file_publication_candidate('ready-file', locator+'a')
        self.assertEqual(raised.exception.code, 'candidate.too_large')
