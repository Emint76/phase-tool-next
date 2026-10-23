"""Fixed-delivery correlation regressions, not native qualification.

The malformed successful/evidence-bearing data below are synthetic protocol
inputs, never Core receipts or evidence that an actual runtime emitted them.
Real parent/finalizer/seal and MCP owner/schema code are exercised on Linux;
OS, process creation, worker-context facts and ACKs are explicitly synthetic.
No native profile/qualification guard is replaced and no NativeIO is called.
"""
from copy import deepcopy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes
from phase_tool.command_result import validate_command_result
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_inspection_file_create_registry
from phase_tool.mutation.ntfs import entrypoint, inspection_mcp, parent
from phase_tool.mutation.ntfs.uncertainty import _NativeLifecycleUnresolved
from . import test_native_composition_delivery as composition


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux delivery component boundary')
class NativeCommandResultBindingTests(unittest.TestCase):
    def failure(self, command='execute'):
        return PhaseApplication()._failure(command, PhaseError('synthetic.startup.refused')).payload

    def positive(self, command):
        # A structurally valid, intentionally uncorrelated PROTOCOL INPUT.
        # These tokens never refer to a real receipt or target operation.
        result = self.failure(command)
        result.update(success=True, terminal_status='succeeded_verified',
            execution_disposition='executed', mutation_attempted=True,
            effect_plan_digest='sha256:'+'a'*64, intent_digest='sha256:'+'b'*64,
            receipt_digest='sha256:'+'c'*64, target_verified=True,
            blockers=[], error=None, exit_code=0)
        return result

    def malformed(self, command):
        values = []
        for key, value in (
                ('mutation_attempted', True), ('mutation_attempted', 0),
                ('success', 0), ('receipt_digest', 'sha256:'+'c'*64),
                ('intent_digest', 'sha256:'+'b'*64),
                ('effect_plan_digest', 'sha256:'+'a'*64),
                ('terminal_status', 'failed_partial'),
                ('execution_disposition', 'executed'),
                ('target_verified', False), ('target_verified', True),
                ('error', None), ('blockers', []), ('exit_code', 20),
                ('stage3_command_result_version', '1.1')):
            item = self.failure(command); item[key] = value
            values.append((key+'='+repr(value), item))
        # Missing is not explicit null, including at the direct parent boundary
        # which intentionally has no full execute-result schema validator.
        for key in ('run_id', 'receipt_digest', 'intent_digest',
                    'effect_plan_digest', 'target_verified'):
            item = self.failure(command); del item[key]
            values.append(('missing:'+key, item))
        return values

    def owner(self):
        return inspection_mcp._InspectionMCPCallOwner(config_bytes=b'',
            expected_config_digest=None, manifest_bytes=b'', expected_manifest_digest=None)

    def call_owner(self, owner, command, run='synthetic-null-binding'):
        if command == 'inspect':
            return owner.inspect(run)
        return owner.execute_prepared(run, '/synthetic/prepared/candidate.json', {})

    def assert_unavailable(self, owner, launch, factory):
        self.assertIs(owner._held_launch, launch)
        self.assertTrue(owner._unavailable)
        for command in ('execute', 'inspect'):
            with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_mcp_unavailable'):
                self.call_owner(owner, command)
        factory.assert_called_once()

    def set_frame(self, fixture, result):
        frame = fixture.frame | {'result': result, 'exit_code': result['exit_code']}
        fixture.pipe.receive_frame.return_value = canonical_bytes(frame), None
        fixture.witness.wait_for_exit.return_value = {
            'worker_exit_established': True, 'exit_code': result['exit_code']}
        return frame

    def unknown(self):
        result = _NativeLifecycleUnresolved(
            request=SimpleNamespace(run_id='synthetic-delivery'),
            context=SimpleNamespace(intent_recording_started=True,
                proof_publication_attempted=False, publication_attempted=True,
                common_guard_finalized=False, original_intent_digest='sha256:'+'b'*64,
                prepared=SimpleNamespace(effect_plan_digest='sha256:'+'a'*64)),
            authority=SimpleNamespace(channel=SimpleNamespace(possible_dispatch=True)),
            primary=OSError('synthetic completion unknown')).command_result('execute')
        result['run_id'] = None
        return result

    def test_mcp_refuses_schema_valid_null_success_and_retains_owner(self):
        for command in ('execute', 'inspect'):
            with self.subTest(command=command):
                result = self.positive(command)
                # Establish the old-schema counterexample, without claiming
                # that an actual native Core ever emitted this payload.
                validate_command_result(result, _native_inspection_file_create_registry())
                owner = self.owner(); launch = object()
                with (patch.object(inspection_mcp, '_NativeAcceptedLaunch', return_value=launch) as factory,
                        patch.object(inspection_mcp, 'run_native_parent',
                            return_value={'result': result, 'exit_code': 0}) as transport):
                    with self.assertRaisesRegex(PhaseError, 'ntfs.parent_command_binding_mismatch'):
                        self.call_owner(owner, command)
                    self.assert_unavailable(owner, launch, factory)
                    transport.assert_called_once_with(launch)

    def test_mcp_refuses_unscoped_claims_and_missing_fields(self):
        for command in ('execute', 'inspect'):
            for label, result in self.malformed(command):
                with self.subTest(command=command, variant=label):
                    owner = self.owner(); launch = object()
                    with (patch.object(inspection_mcp, '_NativeAcceptedLaunch', return_value=launch) as factory,
                            patch.object(inspection_mcp, 'run_native_parent',
                                return_value={'result': result, 'exit_code': result['exit_code']})):
                        # Some malformed inputs fail the existing full schema;
                        # valid-shaped ones must fail the new contextual check.
                        with self.assertRaises(Exception):self.call_owner(owner, command)
                        self.assert_unavailable(owner, launch, factory)

    def test_parent_refuses_null_success_after_real_finalizer(self):
        component = composition.NativeComposedDeliveryTests()
        for command in ('execute', 'inspect'):
            with self.subTest(command=command), component.delivery(inspection=command=='inspect') as fixture:
                result = self.positive(command)
                validate_command_result(result, _native_inspection_file_create_registry())
                frame = self.set_frame(fixture, result)
                self.assertEqual(frame['run_id'], fixture.launch.run_id)
                self.assertIsNone(frame['result']['run_id'])
                with self.assertRaisesRegex(PhaseError, 'ntfs.parent_command_binding_mismatch'):
                    entrypoint.run_native_parent(fixture.launch)
                component.assert_finalized_once(fixture)

    def test_parent_refuses_missing_claims_and_post_dispatch_null_refusal(self):
        component = composition.NativeComposedDeliveryTests()
        for command in ('execute', 'inspect'):
            for label, result in self.malformed(command):
                with self.subTest(command=command, variant=label):
                    with component.delivery(inspection=command=='inspect') as fixture:
                        self.set_frame(fixture, result)
                        with self.assertRaisesRegex(PhaseError, 'ntfs.parent_command_binding_mismatch'):
                            entrypoint.run_native_parent(fixture.launch)
                        component.assert_finalized_once(fixture)
        # Simulate independently held parent facts, not a physical worker.
        # In particular a finalized worker cannot justify a false no-dispatch
        # null-run startup refusal. Exercise the real parent through MCP too.
        contexts = [
            {'_spawn_attempted': True, '_go_attempted': True,
             '_worker': object(), '_worker_count': 1, '_worker_finalized': True},
            {'_spawn_attempted': True, '_worker_finalized': True},
            {'_go_attempted': True}, {'_worker': object()}, {'_worker_count': 1},
            {'_worker_count': False}, {'_spawn_attempted': None}, {'_go_attempted': None}]
        actual_parent = parent._NativeWindowsParent
        for index, context in enumerate(contexts):
            with self.subTest(parent_context=index), component.delivery() as fixture:
                result = self.failure(); self.set_frame(fixture, result)
                created = []
                def contextual_parent(launch, pipe):
                    owned = actual_parent(launch, pipe)
                    for key, value in context.items():setattr(owned, key, value)
                    owned._consumed = True  # Simulated previously consumed GO slot.
                    created.append(owned)
                    return owned
                owner = self.owner()
                with (patch.object(parent, '_NativeWindowsParent', side_effect=contextual_parent),
                        patch.object(inspection_mcp, '_NativeAcceptedLaunch', return_value=fixture.launch) as factory):
                    with self.assertRaisesRegex(PhaseError, 'ntfs.parent_command_binding_mismatch'):
                        self.call_owner(owner, 'execute', run=fixture.launch.run_id)
                    self.assert_unavailable(owner, fixture.launch, factory)
                self.assertEqual(len(created), 1); self.assertTrue(created[0]._failed)
                component.assert_finalized_once(fixture)

    def test_parent_accepts_exact_null_startup_refusal(self):
        component = composition.NativeComposedDeliveryTests()
        for command in ('execute', 'inspect'):
            with self.subTest(command=command), component.delivery(inspection=command=='inspect') as fixture:
                result = self.failure(command); before = canonical_bytes(result)
                frame = self.set_frame(fixture, result)
                actual = entrypoint.run_native_parent(fixture.launch)
                self.assertEqual(actual, frame)
                self.assertEqual(canonical_bytes(actual['result']), before)
                self.assertIsNone(actual['result']['run_id'])
                component.assert_finalized_once(fixture)

    def test_parent_preserves_typed_null_uncertainty_and_rejects_missing_nulls(self):
        component = composition.NativeComposedDeliveryTests(); original = self.unknown()
        validate_command_result(original, _native_inspection_file_create_registry())
        with component.delivery() as fixture:
            before = canonical_bytes(original); self.set_frame(fixture, original)
            actual = entrypoint.run_native_parent(fixture.launch)['result']
            self.assertEqual(canonical_bytes(actual), before)
            self.assertEqual(actual['intent_digest'], 'sha256:'+'b'*64)
            self.assertEqual(actual['effect_plan_digest'], 'sha256:'+'a'*64)
            self.assertTrue(actual['possible_dispatch']); self.assertTrue(actual['receipt_publication_attempted'])
            self.assertIsNone(actual['mutation_attempted']); self.assertIsNone(actual['receipt_digest'])
            component.assert_finalized_once(fixture)
        for key in ('run_id', 'terminal_status', 'execution_disposition',
                    'mutation_attempted', 'receipt_digest', 'target_verified'):
            with self.subTest(missing=key), component.delivery() as fixture:
                result = deepcopy(original); del result[key]; self.set_frame(fixture, result)
                with self.assertRaisesRegex(PhaseError, 'ntfs.parent_command_binding_mismatch'):
                    entrypoint.run_native_parent(fixture.launch)
                component.assert_finalized_once(fixture)


if __name__ == '__main__':unittest.main()
