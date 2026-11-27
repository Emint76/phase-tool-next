"""Synthetic closed catalogue with the real terminal-proof path, no native dispatch."""

import base64
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import owner_directory as owner, proof
from phase_tool.mutation.ntfs import owner_directory_installation as factory
from tests.owner_directory_test_data import mutate_manifest, owner_document, synthetic_catalog


def no_dispatch_proof(binding, *, invalid_ack=False):
    manifest = parse_json_bytes(binding.manifest_bytes)
    contract = manifest['contract']
    request = PhaseRequest(contract['id'], contract['version'], contract['package_digest'],
        Path('unused-candidate.json'), Path(manifest['evidence_root']), 'ordinary-proof-model', {}, {},
        timestamp='2026-10-26T00:00:00Z')
    receipt = PhaseCore(binding.registry)._rejection_receipt(request, [], request.timestamp,
        'idempotency.same_key_conflict')
    ack = {'finish_ack_version': '1.0', 'run_id': request.run_id, 'intent_digest': None,
        'operation_nonce': '1' * 32, 'installation_digest': binding.manifest_digest,
        'ingress_state': 'consumed', 'worker_started': False, 'worker_spawn_attempted': invalid_ack,
        'worker_count': 0, 'required_resources_finalized': True}
    physical = {'run_id': request.run_id, 'local_channel_sealed': True, 'server_ingress_sealed': True,
        'parent_safety_established': False, 'no_dispatch_safety_established': True,
        'possible_dispatch': False, 'no_dispatch_finalization': ack, 'parent_response': None,
        'observations': {}}
    return receipt, proof.make_native_terminal_proof(binding, request,
        SimpleNamespace(receipt=receipt, intent=None), physical=physical,
        idempotency={'enter_started': False, 'entered': False, 'finalized': False},
        common_guard_finalized=True)


class OrdinaryTerminalProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = synthetic_catalog().check()
        cls.document = owner_document(cls.catalog)
        body = canonical_bytes(cls.document)
        row = cls.document['manifests'][0]
        _, cls.bindings = factory._owner_directory_bindings_with_catalog(configuration_bytes=body,
            expected_configuration_digest=digest_bytes(body), manifest_bytes=base64.b64decode(row['manifest_base64']),
            expected_manifest_digest=row['manifest_digest'], _catalog=cls.catalog)

    def test_genuine_proof_maker_and_historical_correlation_accept_six_ordinary_bindings(self):
        for role, binding in zip(owner.ROLES, self.bindings, strict=True):
            with self.subTest(role=role):
                self.assertIsNone(binding.experimental_admission)
                receipt, terminal = no_dispatch_proof(binding)
                self.assertEqual(terminal['installation']['descriptor_digest'], binding.manifest_digest)
                self.assertEqual(terminal['prepared_receipt_digest'], profile_digest('receipt', receipt))
                self.assertIsNone(proof._check(binding, receipt, terminal))
                self.assertEqual(receipt['terminal_status'], 'rejected')
                self.assertFalse(receipt['mutation_attempted'])

    def test_cross_role_profile_rejected_even_with_consistent_manifest_and_configuration_pins(self):
        for index, role in enumerate(owner.ROLES):
            with self.subTest(role=role):
                binding = self.bindings[index]
                foreign = parse_json_bytes(self.bindings[(index + 1) % len(owner.ROLES)].manifest_bytes)['authority']
                document = mutate_manifest(self.document, role,
                    lambda manifest: manifest.update(authority=deepcopy(foreign)))
                config = canonical_bytes(document)
                row = document['manifests'][index]
                context = replace(binding._owner_directory_context, configuration_bytes=config,
                    configuration_digest=digest_bytes(config))
                changed = replace(binding, manifest_bytes=base64.b64decode(row['manifest_base64']),
                    manifest_digest=row['manifest_digest'], _owner_directory_context=context)
                with self.assertRaises(PhaseError) as error:
                    no_dispatch_proof(changed)
                self.assertEqual(error.exception.code, 'ntfs.original_implementation_mismatch')

    def test_real_finish_ack_check_still_refuses_a_worker_spawn_claim(self):
        for role, binding in zip(owner.ROLES, self.bindings, strict=True):
            with self.subTest(role=role):
                with self.assertRaises(PhaseError) as error:
                    no_dispatch_proof(binding, invalid_ack=True)
                self.assertEqual(error.exception.code, 'ntfs.native_finish_binding_mismatch')

    def test_fixed_catalog_remains_closed(self):
        with self.assertRaises(PhaseError) as error:
            factory._fixed_owner_directory_catalog()
        self.assertEqual(error.exception.code, 'ntfs.native_profile_not_qualified')
