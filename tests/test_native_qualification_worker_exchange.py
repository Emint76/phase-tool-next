"""Model the fixed bulk Worker cutoff without starting a Native process."""
import base64
from copy import deepcopy
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bundle_execution, file2_execution
from phase_tool.mutation.ntfs import owner_directory_installation, owner_directory_launch
from phase_tool.mutation.ntfs.handoff import _OriginalControlProjection
from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames

from .owner_directory_test_data import owner_document, synthetic_catalog
from .test_native_bundle2_prepared import b2_projection
from .test_native_bundle_protocol import projection as bundle_projection
from .test_native_file2_binary_chunks import CHANNEL, CONTEXT
from .test_native_worker import grant


FIELD = '_qualification_exchange_deadline_ns'
NOW = 1_000_000_000
CUTOFF = NOW + 90_000_000_000


def file2_projection():
    body = b'abc'
    digest = digest_bytes(body)
    context = CONTEXT | {'worker_protocol': 'phase.native.file-worker', 'worker_version': '1.2',
        'effect_plan_digest': 'sha256:' + '7' * 64, 'native_binding_digest': 'sha256:' + '8' * 64,
        'implementation_artifact_digest': 'sha256:' + '9' * 64}
    effect = {'effect_id': 'native-file2-create', 'kind': 'exclusive_create',
        'target': {'root_binding': 'phase_result_root', 'relative_locator': 'data.bin'}, 'input_binding': 'payload',
        'content_source': {'kind': 'frozen_input', 'binding_id': 'payload', 'source_digest': digest},
        'content_digest': digest, 'content_length': len(body), 'preconditions': {'existence': 'absent',
        'expected_digest': None, 'expected_head': None, 'concurrency_token': None}, 'lock_scope': None,
        'durability_policy_id': 'file_data_synced', 'on_failure': 'stop_and_classify'}
    return _OriginalControlProjection(canonical_bytes(context), canonical_bytes(grant()), canonical_bytes(effect),
        '2026-11-11T00:00:00Z', 'payload', digest, len(body))


class QualificationWorkerExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        launcher = Path(__file__).resolve().parents[1] / 'src/phase_tool/data/native/native_phase_candidate_launcher_v1.py.in'
        cls.accept = staticmethod(runpy.run_path(str(launcher))['_worker_exchange_original'])
        cls.catalog = synthetic_catalog().check()
        cls.owner = owner_document(cls.catalog)
        raw = canonical_bytes(cls.owner)
        cls.config = dict.fromkeys(owner_directory_launch._FIELDS)
        cls.config.update(native_launch_version='4.0', phase_wheel_digest=cls.owner['phase_wheel_digest'],
            owner_directory_configuration_base64=base64.b64encode(raw).decode(),
            owner_directory_configuration_digest=digest_bytes(raw), qualification_cold_publication_seconds=900)

    def fixture(self, index, *, sealed=True):
        row = self.owner['manifests'][index]
        manifest = base64.b64decode(row['manifest_base64'])
        config = self.config.copy()
        if not sealed:
            del config['qualification_cold_publication_seconds']
        raw = canonical_bytes(config)
        startup = {'manifest_digest': row['manifest_digest'], 'config_digest': digest_bytes(raw)}
        if index == 1:
            projection = file2_execution._file2_projection_value(file2_projection())
            version = '2.0'
        else:
            project = bundle_projection() if index == 4 else b2_projection()
            projection = bundle_execution._bundle_projection_value(project)
            projection['contract'] = parse_json_bytes(manifest)['contract']
            version = '3.0'
        projection['context']['installation_digest'] = startup['manifest_digest']
        original = {'native_worker_original_version': version, 'channel_id': CHANNEL, 'projection': projection}
        return original, (startup, raw, manifest, None)

    def test_worker_original_keeps_same_cutoff_and_strips_private_field(self):
        with patch.object(owner_directory_installation, '_fixed_owner_directory_catalog', return_value=self.catalog):
            with patch('time.perf_counter_ns', return_value=NOW):
                for index in (1, 4, 5):
                    with self.subTest(index=index):
                        original, startup = self.fixture(index)
                        wire = original | {FIELD: CUTOFF}
                        self.assertEqual(self.accept(wire, *startup), (original, CUTOFF))
                        self.assertEqual(wire[FIELD], CUTOFF)
                        self.assertIs(self.accept(original, *startup)[0], original)

    def test_recovery_foreign_or_expired_cutoff_cannot_enter_bound_worker(self):
        original, startup = self.fixture(5)
        unsealed, unsealed_startup = self.fixture(5, sealed=False)
        foreign = deepcopy(original)
        foreign['projection']['context']['installation_digest'] = 'sha256:' + 'f' * 64
        with patch.object(owner_directory_installation, '_fixed_owner_directory_catalog', return_value=self.catalog):
            with patch('time.perf_counter_ns', return_value=NOW):
                for bad in (NOW, True, CUTOFF + 900_000_000_000):
                    with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                        self.accept(original | {FIELD: bad}, *startup)
                for value, binding in (
                    (original | {'native_worker_original_version': '4.0'}, startup),
                    (foreign, startup),
                    (unsealed, unsealed_startup),
                ):
                    with self.assertRaises(RuntimeError):
                        self.accept(value | {FIELD: CUTOFF}, *binding)
            with patch('time.perf_counter_ns', side_effect=(NOW, CUTOFF)):
                with self.assertRaises(RuntimeError):
                    self.accept(original | {FIELD: CUTOFF}, *startup)

    def test_worker_inputs_require_exact_bound_pipe_and_stop_on_original_deadline(self):
        pipe = WindowsPipeFrames.__new__(WindowsPipeFrames)
        cases = (
            (file2_execution._File2WorkerInput, file2_projection()),
            (bundle_execution._BundleWorkerInput, b2_projection()),
        )
        for constructor, projection in cases:
            with self.subTest(constructor=constructor.__name__), patch('os.name', 'nt'):
                pipe._qualification_exchange_deadline_ns = None
                with patch('time.perf_counter_ns', return_value=NOW):
                    with self.assertRaisesRegex(PhaseError, 'ntfs.worker_go_deadline'):
                        constructor(pipe, projection, CHANNEL, CUTOFF)
                    legacy = constructor(pipe, projection, CHANNEL, NOW + 29_000_000_000)
                    self.assertFalse(legacy._qualification_exchange)
                    pipe._qualification_exchange_deadline_ns = CUTOFF
                    with self.assertRaisesRegex(PhaseError, 'ntfs.worker_go_deadline'):
                        constructor(pipe, projection, CHANNEL, CUTOFF - 1)
                    source = constructor(pipe, projection, CHANNEL, CUTOFF)
                    self.assertTrue(source._qualification_exchange)
                with patch('time.perf_counter_ns', return_value=NOW + 31_000_000_000):
                    source._check()
                with patch('time.perf_counter_ns', return_value=CUTOFF):
                    with self.assertRaisesRegex(PhaseError, 'ntfs.pipe_deadline_expired'):
                        source._check()
