"""Regression for the native observation block of the actual inspector.

The modeled boundary supplies the already checked Original identity and one
advisory observation. No acceptance, Original parsing, worker, disk or target
effect is exercised. Both the observation block and its exception handler come
from inspect_run. The real application failure and channel seal paths consume
the outcome.
"""

import ast
from inspect import getsource
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from phase_tool import inspection
from phase_tool.application import PhaseApplication
from phase_tool.command_result import validate_command_result
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.entrypoint import _inspect_with_channel_seal


RUN = 'historical-inspection-component'
ROOT = 'phase_result_root'
LOCATOR = 'current.bin'
ORIGINAL = {'file_id': '1' * 32, 'volume_serial': 17}
OTHER_FILE = ORIGINAL | {'file_id': '2' * 32}
OTHER_VOLUME = ORIGINAL | {'volume_serial': 18}
ROLES = ('file_create.v1', 'file_create.v2', 'publish_new_version.v1', 'publish_new_version.v2')
IDENTITY_MISMATCH = 'inspection.native_identity_mismatch'
TARGET_MISMATCH = 'inspection.target_mismatch'


def observation_code():
    module = ast.parse(getsource(inspection.inspect_run))
    owner, = module.body
    region, = [node for node in ast.walk(owner) if isinstance(node, ast.Try)
               and isinstance(node.body[0], ast.If)
               and ast.unparse(node.body[0].test) == 'host_bundle and bundle_prior is not None']
    return compile(ast.Module(body=[region], type_ignores=[]), '<inspect_run target observation>', 'exec')


def comparison(role, *, current, original=ORIGINAL, disposition='executed', error=None):
    state = {'known': True, 'exists': current is not None,
             'digest': 'sha256:' + '3' * 64 if current is not None else None,
             'length': 13 if current is not None else None, 'head_token': None}
    observe = Mock(return_value={'native': {'exists': current is not None, 'native_identity': current},
                                 'state': state}, side_effect=error)
    authority = SimpleNamespace(observe=observe, observe_advisory=observe, observe_version2_advisory=observe,
                                seal=Mock())
    target = original
    if original is not None and role.startswith('publish_new_version'):
        target = {'current': original, 'archive': OTHER_FILE} if role.endswith('.v1') else {
            'current': original, 'old_object': OTHER_FILE, 'new_object': original}
    namespace = vars(inspection) | {
        'host_bundle': False, 'native_bundle': False, 'bundle_prior': None, 'appended': None,
        '_native_authority': authority, 'native_proof': {'target_identity': target},
        'contract': SimpleNamespace(document={'identity': {'id': role}}),
        'receipt': {'execution_disposition': disposition}, 'run_id': RUN, 'root_id': ROOT,
        'canonical_result': {'locator': LOCATOR},
    }
    observation = observation_code()

    def sample():
        exec(observation, namespace)
        return namespace['native_target_identity'], namespace['streamed_state']

    return state, authority, sample


class NativeHistoricalIdentityRefusalTests(unittest.TestCase):
    def assert_observed_without_remote_identity(self, role, authority):
        expected = {'root_binding': ROOT, 'locator': LOCATOR, 'expected_identity': None}
        if role.startswith('file_create'):
            expected['run_id'] = RUN
        authority.observe.assert_called_once_with(**expected)

    def assert_known_failure(self, role, *, current, code, error=None):
        _, authority, sample = comparison(role, current=current, error=error)
        application = PhaseApplication()

        def inspect_component(**request):
            self.assertEqual(request['run_id'], RUN)
            try:
                sample()
            except PhaseError as failure:
                return application._failure('inspect', failure)
            self.fail('The target observation must refuse before the success path')

        result = _inspect_with_channel_seal(SimpleNamespace(inspect=inspect_component), authority,
            evidence_root=None, run_id=RUN, root_bindings={ROOT: 'unopened'})
        self.assert_observed_without_remote_identity(role, authority)
        authority.seal.assert_called_once_with(intent_digest=None)
        self.assertEqual(result.exit_code, 10)
        self.assertEqual(result.payload, {
            'stage3_command_result_version': '1.0', 'command': 'inspect', 'success': False,
            'run_id': None, 'terminal_status': 'rejected', 'execution_disposition': 'not_executed',
            'mutation_attempted': False, 'effect_plan_digest': None, 'intent_digest': None,
            'receipt_digest': None, 'target_verified': None, 'blockers': [code], 'error': code, 'exit_code': 10,
        })
        validate_command_result(result.payload, application.registry)

    def test_replaced_current_has_known_local_identity_refusal(self):
        for role in ROLES:
            for current in (OTHER_FILE, OTHER_VOLUME):
                with self.subTest(role=role, current=current):
                    self.assert_known_failure(role, current=current, code=IDENTITY_MISMATCH)

    def test_missing_current_and_observer_error_keep_generic_refusal(self):
        for role in ROLES:
            for failure in (None, PhaseError(IDENTITY_MISMATCH), OSError('modeled observer failure')):
                with self.subTest(role=role, provider_error=failure):
                    self.assert_known_failure(role, current=None, code=TARGET_MISMATCH, error=failure)

    def test_same_identity_and_receipt_only_reuse_reach_existing_continuation(self):
        for role in ROLES:
            for original, disposition in ((ORIGINAL, 'executed'), (None, 'reused_existing')):
                with self.subTest(role=role, disposition=disposition):
                    state, authority, sample = comparison(role, current=ORIGINAL, original=original,
                                                          disposition=disposition)
                    identity, observed = sample()
                    self.assertEqual(identity, ORIGINAL)
                    self.assertIs(observed, state)
                    self.assert_observed_without_remote_identity(role, authority)
