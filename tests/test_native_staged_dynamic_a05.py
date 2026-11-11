"""Portable source component. The six manifest readers and Original parsers are real.

Installed files, cold acceptance, and Win32 events are recording boundaries.
No source, target, evidence, transport, subprocess, Worker or GO is opened.
"""
import base64
from copy import deepcopy
from importlib.resources import files
import os
from pathlib import Path, PureWindowsPath
import subprocess
from types import SimpleNamespace
import unittest
import zipimport
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes
from phase_tool.errors import PhaseError
import phase_tool
from phase_tool.mutation.ntfs import (
    bootstrap, dynamic_a05_test, input_stage, inspection_mcp, native, parent, staged_dynamic_a05 as staged,
)
from phase_tool.mutation.ntfs.bundle_execution import _bundle_projection_from_value, _bundle_projection_value
from phase_tool.mutation.ntfs.file2_execution import _file2_projection_from_value, _file2_projection_value
from .native_staged_original14_data import builders
from .native_staged_original14_records import parse_claim, record_for


class StagedDynamicA05Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = builders()
        cls.owner = source['owner']
        cls.doc, _, cls.manifests, cls.graph = source['prepared']('3.0')
        # The source-tree fixture carries a synthetic wheel pin. A wheel-based
        # model reads the actual package bytes for the real Owner3 data checks.
        loader = phase_tool.__spec__.loader
        if type(loader) is zipimport.zipimporter:
            with Path(loader.archive).open('rb') as stream:
                wheel = stream.read(16*1024**2+1)
            assert 0 < len(wheel) <= 16*1024**2
            cls.doc['wheel_digest'] = cls.graph['phase_wheel_digest'] = digest_bytes(wheel)
        cls.fixture_root = PureWindowsPath('S:/Phase-NTFS-Qualification') / staged._FIXTURE
        cls.doc.update(fixture_uuid=staged._FIXTURE, owner_scope_id='phase.qualification.owner.' + staged._FIXTURE)
        cls.doc['request_limits']['run_prefix'] = 'od3-' + staged._FIXTURE + '-'
        for name, leaf in (('current_root', 'results'), ('objects_root', 'objects')):
            cls.doc['windows_roots'][name] = str(cls.fixture_root / leaf)
        for grant, leaf in zip(cls.doc['root_grants'], ('results', 'objects'), strict=True):
            grant['components'] = list((cls.fixture_root / leaf).parts[1:])

    def setUp(self):
        self.installation = Path.cwd().absolute() / 'staged-a05-recording-installation-never-opened'
        self.launcher = self.installation / 'launcher.py'
        self.scope_path = self.installation / 'native-input-scope.json'
        self.binding_path = self.installation / 'dynamic-a05-staged-test.json'
        self.events = []
        self.reports = []
        self.clock = SimpleNamespace(now=1_000_000_000)
        self.launcher_raw = (Path(__file__).parent / 'fixtures/native_phase_staged_dynamic_a05_launcher_v1.py.in').read_bytes()
        self.assertEqual(digest_bytes(self.launcher_raw), staged._LAUNCHER_DIGEST)
        model_os = SimpleNamespace(name='nt', getpid=os.getpid)
        model_time = SimpleNamespace(perf_counter_ns=lambda: self.clock.now)
        model_sys = SimpleNamespace(argv=[str(self.launcher), 'publish-input'],
            modules={'__main__': SimpleNamespace(__file__=str(self.launcher))})
        self.model_sys = model_sys
        self.fixed_reads = []
        self.fixed = {self.launcher: self.launcher_raw}
        for mod, key, val in ((staged, 'os', model_os), (input_stage, 'os', model_os),
                (staged, 'sys', model_sys), (staged, 'time', model_time), (input_stage, 'time', model_time),
                (dynamic_a05_test, 'time', model_time), (staged, '_read_dynamic_a05_fixed', self.read_fixed),
                (dynamic_a05_test, '_Win32A05Events', self.record_events),
                (dynamic_a05_test, '_write_fixed', self.record_report)):
            guard = patch.object(mod, key, val)
            guard.start()
            self.addCleanup(guard.stop)
        for mod, key in ((native.NativeIO, '__init__'), (subprocess, 'Popen'), (subprocess, 'run')):
            guard = patch.object(mod, key, side_effect=AssertionError(f'{key} is outside this test'))
            guard.start()
            self.addCleanup(guard.stop)
        boundary = patch.object(bootstrap._NativeAcceptedLaunch, 'check_runtime', autospec=True)
        self.runtime_model = boundary.start()
        self.addCleanup(boundary.stop)

    def read_fixed(self, path):
        self.fixed_reads.append(path)
        return self.fixed[path]

    def record_events(self):
        trace = self.events

        def open_events(names):
            trace.append(('open', names))
            return ('recorded-handles',)

        def hold(handles, deadline):
            trace.append(('hold', handles, deadline))

        def close():
            trace.append(('close',))
            return []

        return SimpleNamespace(events=[], environment=lambda: {}, open_events=open_events, hold=hold, close=close)

    def record_report(self, path, value):
        self.reports.append((path.name, deepcopy(value)))

    def vector(self, role, *, change_fixture=None, change_scope=None, change_sidecar=None, change_config=None):
        doc, manifests, graph = deepcopy((self.doc, self.manifests, self.graph))
        if change_fixture:
            change_fixture(doc)
        raw = canonical_bytes(doc)
        role_rows = {row['role']: row for row in doc['roles']}
        for name, kind in self.owner._kinds().items():
            row, manifest = role_rows[name], manifests[name]
            manifest['installation_id'] = self.owner.installation_id(kind, raw)
            view = self.owner.role_projection(kind, raw)
            manifest['root_grants'] = view.get('root_grants', [view.get('root_grant')])
            manifest['root_projections'] = (doc['root_projections'] if name == 'Version2'
                else {row['root_binding']: '/ntfs-result'})
        manifest = manifests[role]
        grants = manifest['root_grants']
        source_grant = self.doc['root_grants'][0]
        source_volume = {key: source_grant[key] for key in ('device', 'volume_guid', 'volume_serial32')}
        scope = {'native_input_scope_version': '1.0', 'scope_id': 'source-model.' + role.lower(),
            'owner_scope_id': doc['owner_scope_id'], 'fixture_digest': digest_bytes(raw),
            'installation_id': manifest['installation_id'], 'contract': manifest['contract'],
            'windows_root': str(self.fixture_root / 'inputs'), 'volume': dict(source_volume, filesystem='NTFS', flags=0),
            'root_identity': {'volume_serial': source_grant['native_identity']['volume_serial'], 'file_id': 'f' * 32},
            'preparation_root': manifest['preparation_root'], 'preparation_identity': manifest['preparation_identity']}
        if change_scope:
            change_scope(scope)
        scope_raw = canonical_bytes(scope)
        call = {'input_scope': scope['scope_id'], 'source_locator': 'unopened-source',
            'request_id': 'original14-request-' + role.lower(),
            'target_locator': 'target-' + role.lower() + ('' if role.startswith('Bundle') else '.bin'),
            'members': ['empty.bin', 'nested/payload.bin'] if role.startswith('Bundle') else None,
            'expected_current_digest': (digest_bytes(b'A' * 4096 + b'\n') if role == 'Version2'
                else digest_bytes(b'old original14\n') if role == 'Version1' else None)}
        run_id = doc['request_limits']['run_prefix'] + 'original14-' + role.lower() + '-source'
        sidecar = {'staged_dynamic_a05_test_version': '1.0', 'fixture_id': staged._FIXTURE,
            'case_id': 'source-model-' + role.lower(), 'cutpoint': staged._CUT, 'run_id': run_id,
            'installation_id': manifest['installation_id'], 'contract': manifest['contract'],
            'root_grants_digest': canonical_digest(grants),
            'evidence_identity_digest': canonical_digest(manifest['evidence_identity']),
            'preparation_identity_digest': canonical_digest(manifest['preparation_identity']),
            'intent_binding': 'genuine-first-original', 'input_scope_digest': digest_bytes(scope_raw),
            'call_digest': canonical_digest(call)}
        if change_sidecar:
            change_sidecar(sidecar)
        sidecar_raw = canonical_bytes(sidecar)
        self.fixed.update({self.scope_path: scope_raw, self.binding_path: sidecar_raw})
        deps = {str(path): digest_bytes(body) for path, body in self.fixed.items() if path != self.launcher}
        graph['launcher_digest'] = staged._LAUNCHER_DIGEST
        graph['windows']['dependency_file_digests'] = deps
        for value in manifests.values():
            value['composition']['artifact_graph_digest'] = canonical_digest(graph)
        history = {'history_manifest_set_version': '3.0', 'fixture_base64': base64.b64encode(raw).decode(),
            'fixture_digest': digest_bytes(raw), 'manifests': [], 'predecessors': []}
        for name, value in manifests.items():
            body = canonical_bytes(value)
            history['manifests'].append({'role': name, 'manifest_base64': base64.b64encode(body).decode(),
                'manifest_digest': digest_bytes(body)})
        history_raw = canonical_bytes(history)
        config = {'native_launch_version': '3.0', 'phase_wheel_digest': doc['wheel_digest'],
            'dependency_file_digests': deepcopy(deps), 'windows_launcher': str(self.launcher), 'artifact_graph': graph,
            'phase_wheel': str(self.installation / 'candidate.whl'), 'linux_launcher': '/unopened/launcher.py',
            'docker_executable': str(self.installation / 'docker.exe'), 'core_container_id': 'a' * 64,
            'reader_container_id': 'b' * 64, 'image_digest': 'sha256:' + 'c' * 64,
            'linux_python': '/opt/phase/bin/python', 'expected_linux_contours': {},
            'history_manifest_set_base64': base64.b64encode(history_raw).decode(),
            'history_manifest_set_digest': digest_bytes(history_raw)}
        if change_config:
            change_config(config)
        record = record_for(role, (doc, raw, manifests, graph))
        config_raw = canonical_bytes(config)
        return SimpleNamespace(record=record, call=call, run_id=run_id, startup=dict(config_bytes=config_raw,
            expected_config_digest=digest_bytes(config_raw), manifest_bytes=record['binding'].manifest_bytes,
            expected_manifest_digest=record['binding'].manifest_digest,
            _experimental_admission_context=record['admission']))

    @staticmethod
    def select(vector):
        return staged._StagedA05Selection(config_bytes=vector.startup['config_bytes'],
            manifest_bytes=vector.startup['manifest_bytes'], admission=vector.record['admission'])

    def exercise(self, role):
        vector = self.vector(role)
        selection = self.select(vector)
        record = vector.record
        parsed = parse_claim(record)
        if role == 'File2':
            parsed = _file2_projection_from_value(_file2_projection_value(parsed))
        if role.startswith('Bundle'):
            parsed = _bundle_projection_from_value(_bundle_projection_value(parsed))
        header = digest_bytes(b'synthetic-component-header')
        arguments = record['request_literals']
        request = input_stage._staged_publication_request(role=role, prepared={'header_digest': header,
            'source_locator': 'phase-native-input-' + header[7:39] + '/payload' + ('' if role.startswith('Bundle') else '/payload'),
            'expected_digest': arguments['source_digest'], 'expected_length': arguments['source_length']},
            input_scope=vector.call['input_scope'], request_id=arguments['request_id'], target_locator=arguments['target_locator'],
            members=arguments['members'], expected_current_digest=arguments['expected_current_digest'], content_utf8=arguments['content_utf8'])
        launch = bootstrap._NativeAcceptedLaunch(**vector.startup, _inspection_only=False,
            invocation_bytes=canonical_bytes({'run_id': vector.run_id, 'channel_id': '1' * 32,
                'operation_nonce': '2' * 32, 'request': request}))
        deadline = input_stage._InputOperationDeadline()
        exchange = self.clock.now + 2_000_000_000
        with input_stage._input_operation_scope(deadline):
            selection.begin(vector.startup, run_id=vector.run_id, call=vector.call, deadline_ns=deadline.deadline_ns)
            cut = selection.attach(launch)
            self.assertEqual(self.events, [])
            parent_owner = object.__new__(parent._NativeWindowsParent)
            parent_owner._dynamic_a05_test = cut
            parent_owner._launch = launch
            parent_owner._file2_exchange_deadline = exchange
            # Recording boundary only. The focused forwarding models exercise
            # the real owner method; these six retain their real Original parser.
            with self.assertRaisesRegex(PhaseError, 'ntfs.staged_dynamic_a05_reader_witness_required'):
                # Do not consume the attached token to test a prerequisite.
                cut._original_reader_observation({}, record['intent_digest'])
            with patch.object(input_stage, '_scope_for_launch', return_value=({}, role, header)):
                query = bootstrap._original_query_request(launch, 'read_executing', record['intent_digest'])
            fact = {'process_witness_version': '1.0', 'pid': 741, 'creation_filetime': 123456,
                    'wait_result': 0, 'worker_exit_established': True, 'exit_code': 0,
                    'scope': 'recording component; no native reader launched', 'events': []}
            cut._record_original_reader(launch, query, fact)
            parent_owner._after_original_read(parsed, record['intent_digest'])
            self.assertEqual(self.reports[0][1]['original_reader_witness']['reader_exit_fact'], fact)
            self.assertIs(self.reports[0][1]['original_reader_witness']['owner_finalized'], True)
            with self.assertRaises(PhaseError):
                selection.attach(launch)
            with self.assertRaises(PhaseError):
                cut.original_read_complete(launch, parsed, record['intent_digest'])
        self.assertEqual([row[0] for row in self.events], ['open', 'hold', 'close'])
        self.assertEqual(self.events[1][2], exchange)
        self.assertEqual([name for name, _ in self.reports], ['dynamic-a05-cutpoint.json', 'dynamic-a05-cutpoint-final.json'])
        for _, row in self.reports:
            self.assertEqual(row['intent_digest'], record['intent_digest'])
            self.assertFalse(row['authoritative'])
            self.assertFalse(row['worker_spawn_attempted'])
            self.assertIsNone(row['final_acceptance'])

    def test_real_file1_reader_and_recorded_cut(self):
        self.exercise('File1')

    def test_real_file2_reader_and_recorded_cut(self):
        self.exercise('File2')

    def test_real_version1_reader_and_recorded_cut(self):
        self.exercise('Version1')

    def test_real_version2_current_and_objects_reader_and_recorded_cut(self):
        self.exercise('Version2')

    def test_real_bundle1_reader_and_recorded_cut(self):
        self.exercise('Bundle1')

    def test_real_bundle2_reader_and_recorded_cut(self):
        self.exercise('Bundle2')

    def test_valid_reader_does_not_select_different_target_volume(self):
        def foreign_volume(doc):
            for grant in doc['root_grants']:
                grant['device'] = r'\Device\HarddiskVolume999'

        vector = self.vector('Version2', change_fixture=foreign_volume)
        with self.assertRaisesRegex(PhaseError, staged._CODE):
            self.select(vector)
        self.assertEqual(self.events, [])

    def test_rejects_source_alias_of_one_target_by_full_identity(self):
        def alias_objects(scope):
            scope['root_identity'] = deepcopy(self.doc['root_grants'][1]['native_identity'])

        with self.assertRaisesRegex(PhaseError, staged._CODE):
            self.select(self.vector('Version2', change_scope=alias_objects))
        self.assertEqual(self.events, [])

    def test_sidecar_must_not_select_a_run_outside_its_fixture(self):
        with self.assertRaisesRegex(PhaseError, staged._CODE):
            self.select(self.vector('File1', change_sidecar=lambda value: value.update(run_id='other-run')))
        self.assertEqual(self.events, [])

    def test_nonstring_run_does_not_escape_closed_binding_validation(self):
        with self.assertRaisesRegex(PhaseError, staged._CODE):
            self.select(self.vector('File1', change_sidecar=lambda value: value.update(run_id=[])))
        self.assertEqual(self.events, [])

    def test_startup4_does_not_select_even_with_bound_sidecar(self):
        vector = self.vector('File2', change_config=lambda value: value.update(native_launch_version='4.0'))
        with self.assertRaisesRegex(PhaseError, staged._CODE):
            self.select(vector)
        self.assertEqual(self.fixed_reads, [])

    def test_non_test_launcher_cannot_select_with_graph_pinned_test_sidecar(self):
        vector = self.vector('File2')
        ordinary = files('phase_tool').joinpath('data/native/native_phase_candidate_launcher_v1.py.in').read_bytes()
        self.fixed[self.launcher] = ordinary
        with self.assertRaisesRegex(PhaseError, staged._CODE):
            self.select(vector)
        self.assertEqual(self.fixed_reads, [self.launcher])

    def test_other_fixed_role_cannot_select(self):
        vector = self.vector('Bundle2')
        self.model_sys.argv[1] = 'parent'
        with self.assertRaisesRegex(PhaseError, staged._CODE):
            self.select(vector)
        self.assertEqual(self.fixed_reads, [])

    def test_mcp_action_is_selected_only_with_fixed_graph(self):
        vector = self.vector('Bundle2')
        self.model_sys.argv[1] = 'input-mcp'
        self.assertIs(type(self.select(vector)), staged._StagedA05Selection)
        self.assertEqual(self.events, [])

    def test_fixture_sdk_exposes_only_two_bound_calls(self):
        vector = self.vector('File2')
        self.model_sys.argv[1] = 'input-mcp'
        selection = self.select(vector)
        with patch.object(inspection_mcp.FastMCP, 'run', autospec=True) as run:
            self.assertEqual(inspection_mcp._run_staged_a05_input_mcp(
                _staged_a05=selection, **vector.startup), 0)
        run.assert_called_once()
        tools = run.call_args.args[0]._tool_manager._tools
        self.assertEqual(set(tools), {'phase_publish_input', 'phase_inspect'})
        self.assertEqual(set(tools['phase_inspect'].parameters['properties']), {'run_id'})
        self.assertEqual(set(tools['phase_publish_input'].parameters['properties']), set(vector.call) | {'run_id'})
        self.assertTrue(all(tool.parameters['additionalProperties'] is False for tool in tools.values()))
        session = tools['phase_inspect'].fn.__self__
        with patch.object(inspection_mcp, '_InspectionMCPCallOwner') as owner:
            owner.return_value._unavailable = False
            session.inspect(vector.run_id)
            owner.return_value.inspect.assert_called_once_with(run_id=vector.run_id)
            owner.reset_mock()
            with self.assertRaisesRegex(PhaseError, staged._CODE):
                session._invoke('publish_staged_file', {'run_id': vector.run_id})
            owner.assert_not_called()

    def test_staged_owner_binds_selection_before_stage_and_hands_off_exact_token(self):
        class RecordedParent(RuntimeError):
            pass

        vector = self.vector('File1')
        selection = self.select(vector)
        owner = inspection_mcp._InspectionMCPCallOwner(**vector.startup)
        header = digest_bytes(b'modeled-header')
        request = vector.record['request_literals']
        prepared = {'header_digest': header, 'expected_digest': request['source_digest'],
            'expected_length': request['source_length'],
            'source_locator': 'phase-native-input-' + header[7:39] + '/payload/payload'}

        def record_stage(actual_owner, run_id, input_scope, source_locator, members, deadline_ns, **options):
            self.assertIs(actual_owner, owner)
            self.assertEqual(run_id, vector.run_id)
            self.assertEqual(deadline_ns, input_stage._active_input_deadline_ns())
            self.assertEqual(deadline_ns, selection._deadline)
            self.assertTrue(selection._begun)
            return prepared, 'File1', None, None

        def record_parent(launch, *, _dynamic_a05_test):
            self.assertIs(owner._held_launch, launch)
            self.assertIs(type(_dynamic_a05_test), staged._StagedDynamicA05Test)
            self.assertIs(_dynamic_a05_test._selection, selection)
            self.assertNotIn('_staged_a05', launch.invocation['request'])
            self.assertEqual(launch.invocation['request']['stage_header_digest'], header)
            _dynamic_a05_test.check_launch(launch)
            raise RecordedParent('transport boundary modeled')

        with patch.object(input_stage, 'run_windows_input_stage', side_effect=record_stage) as stage_call, \
                patch.object(inspection_mcp, 'run_native_parent', side_effect=record_parent) as parent_call:
            with self.assertRaises(RecordedParent):
                owner.publish_input(run_id=vector.run_id, **vector.call, _staged_a05=selection)
        stage_call.assert_called_once()
        parent_call.assert_called_once()
        self.assertTrue(owner._unavailable)
        self.assertTrue(selection._attached)
        self.assertIsNone(input_stage._active_input_deadline_ns())
        self.assertEqual(self.events, [])

    def test_rejected_call_consumes_selection_in_same_process(self):
        vector = self.vector('File1')
        selection = self.select(vector)
        deadline = input_stage._InputOperationDeadline()
        with input_stage._input_operation_scope(deadline):
            with self.assertRaisesRegex(PhaseError, staged._CODE):
                selection.begin(vector.startup, run_id=vector.run_id,
                    call=dict(vector.call, source_locator='foreign'), deadline_ns=deadline.deadline_ns)
            with self.assertRaisesRegex(PhaseError, staged._CODE):
                selection.begin(vector.startup, run_id=vector.run_id, call=vector.call, deadline_ns=deadline.deadline_ns)
        self.assertEqual(self.events, [])
