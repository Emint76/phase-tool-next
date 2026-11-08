"""Portable fixture/owner ordering models, never native A05 acceptance.

Exact accepted-launch data shells model the pre-existing immutable runtime
boundary. Fake events never call Windows APIs. The real parent bodies execute
only until a deliberately unavailable modeled spawn; no Core/worker is launched.
"""
import ast
from copy import deepcopy
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import time

import pytest

from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import dynamic_a05_test as module
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
from phase_tool.mutation.ntfs.entrypoint import run_native_parent
from phase_tool.mutation.ntfs.experimental_file2 import _ExperimentalFile2Admission
from phase_tool.mutation.ntfs.experimental_file1 import _ExperimentalFile1Admission
from phase_tool.mutation.ntfs.experimental_version1 import _ExperimentalVersion1Admission
from phase_tool.mutation.ntfs.experimental_version2 import _ExperimentalVersion2Admission
from phase_tool.mutation.ntfs.experimental_bundle1 import _ExperimentalBundle1Admission
from phase_tool.mutation.ntfs.experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
from phase_tool.mutation.ntfs.parent import _NativeWindowsParent


RESOURCE = Path(__file__).absolute().parent/'fixtures/native_phase_dynamic_a05_test_launcher_v1.py.in'
DIGEST = 'sha256:'+'1'*64
INTENT = 'sha256:'+'2'*64


def launch_shell(tmp_path, family='file2', *, binding_change=None, graph_change=None):
    installed = tmp_path/'installed'
    installed.mkdir()
    launcher = installed/'launcher.py'
    launcher.write_bytes(RESOURCE.read_bytes())
    launch = object.__new__(_NativeAcceptedLaunch)
    launch._inspection_only = False
    kinds = {'file1': _ExperimentalFile1Admission, 'file2': _ExperimentalFile2Admission,
        'version1': _ExperimentalVersion1Admission, 'version2': _ExperimentalVersion2Admission,
        'bundle1': _ExperimentalBundle1Admission, 'bundle2': _ExperimentalBundle2AdmissionV3}
    kind = kinds[family]
    launch._experimental_admission_context = kind(b'{}')
    contract = deepcopy(launch._experimental_admission_context._contract)
    grant = {'root_binding': 'bundle_root' if family == 'bundle2' else 'phase_result_root',
        'components': ['Phase-NTFS-Qualification', module._FIXTURE, 'results'],
        'device': r'\Device\HarddiskVolume2', 'volume_guid': '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\',
        'volume_serial32': 1, 'native_identity': {'volume_serial': '0000000000000001', 'file_id': 'a'*32}}
    grants = [grant]
    if family == 'version2':
        current = deepcopy(grant); current['root_binding'] = 'current_root'; current['components'].append('current')
        objects = deepcopy(grant); objects['root_binding'] = 'objects_root'; objects['components'].append('objects')
        objects['native_identity']['file_id'] = 'b'*32
        grants = [current, objects]
    launch._manifest_digest = DIGEST
    launch._invocation_bytes = canonical_bytes({'run_id': 'ntfs-dynamic-a05-component',
        'channel_id': 'c'*32, 'operation_nonce': 'd'*32, 'request': {'operation': 'execute'}})
    binding = {'dynamic_a05_test_version': '1.0', 'fixture_id': module._FIXTURE,
        'case_id': 'component-00', 'cutpoint': module._CUT, 'run_id': launch.run_id,
        'installation_id': 'native-component', 'contract': contract,
        'evidence_identity_digest': canonical_digest({'device': 1, 'inode': 2}),
        'preparation_identity_digest': canonical_digest({'device': 1, 'inode': 3}),
        'root_grants_digest': canonical_digest(grants), 'intent_binding': 'genuine-first-original'}
    if binding_change:
        binding_change(binding)
    fixed = installed/'dynamic-a05-test.json'
    fixed.write_bytes(canonical_bytes(binding))
    dependencies = {str(fixed): digest_bytes(fixed.read_bytes())}
    graph = {'artifact_graph_version': '1.0', 'phase_wheel_digest': DIGEST,
             'launcher_digest': module._LAUNCHER_DIGEST, 'windows': {'dependency_file_digests': dependencies}, 'linux': {}}
    if graph_change:
        graph_change(graph)
    manifest = {'native_read_installation_version': kind._manifest_version,
        'installation_id': 'native-component', 'evidence_identity': {'device': 1, 'inode': 2},
        'preparation_identity': {'device': 1, 'inode': 3},
        'contract': contract, 'root_grants': grants, 'composition': {'artifact_graph_digest': canonical_digest(graph)}}
    launch._manifest_bytes = canonical_bytes(manifest)
    launch._config_bytes = canonical_bytes({'windows_launcher': str(launcher), 'artifact_graph': graph,
                                           'dependency_file_digests': dependencies})
    launch.check_runtime = Mock()  # Explicit portable model of accepted immutable startup.
    launch.spawn_core = Mock(side_effect=AssertionError('No Core in component tests'))
    launch.spawn_inspection = Mock(side_effect=AssertionError('No inspector in component tests'))
    return launch


def parsed(launch):
    versions = {'file_create.v1': '1.0', 'file_create.v2': '1.2', 'publish_new_version.v1': '1.1',
                'publish_new_version.v2': '1.3', 'bundle_create.v1': '1.4', 'bundle_create.v2': '1.5'}
    return SimpleNamespace(context_bytes=canonical_bytes({'run_id': launch.run_id, 'intent_digest': INTENT,
        'operation_nonce': launch.operation_nonce, 'installation_digest': launch.installation_digest,
        'worker_version': versions[launch.manifest['contract']['id']]}), effect_bytes=b'{}',
        grant_bytes=canonical_bytes(launch.root_grants if launch._version2 else launch.root_grant))


class Events:
    def __init__(self, fault=None, calls=None):
        self.events = []
        self.fault = fault
        self.calls = [] if calls is None else calls
        self.closed = False
    def environment(self):
        self.calls.append('environment_MODELED')
        return {'pid': os.getpid(), 'token_elevated': False, 'scope': 'SYNTHETIC'}
    def open_events(self, names):
        self.calls.append('events_MODELED')
        assert set(names) == {'held', 'release', 'abort'}
        assert all(n.startswith('Local\\Phase-A05-'+module._FIXTURE+'-component-00-') for n in names.values())
        return {'held': 101, 'release': 102, 'abort': 103}
    def hold(self, handles, deadline):
        self.deadline = deadline
        self.calls.append('cutpoint_MODELED')
        self.events.append({'api': 'MODELED_WAIT', 'deadline': deadline})
        if self.fault:
            raise PhaseError('ntfs.dynamic_a05_test_'+self.fault)
    def close(self):
        self.calls.append('closed_MODELED')
        self.closed = True
        return []


def token(launch):
    return module._DynamicA05Test(launch, _initial_deadline_ns=time.perf_counter_ns()+25_000_000_000)


def test_fixture_exact_source_and_owner_startup_delta_are_code_pinned():
    need = RESOURCE.read_bytes()
    assert digest_bytes(need) == module._LAUNCHER_DIGEST
    ordinary = RESOURCE.parents[1]/'../src/phase_tool/data/native/native_phase_candidate_launcher_v1.py.in'
    normal = ast.parse(ordinary.read_bytes())
    fixed = ast.parse(need)
    normal_functions = {n.name: n for n in normal.body if isinstance(n, ast.FunctionDef)}
    fixed_functions = {n.name: n for n in fixed.body if isinstance(n, ast.FunctionDef)}
    assert normal_functions.keys() == fixed_functions.keys()
    # The historical A05 launcher stays byte-pinned at startup1.1/1.2.
    # Closed owner3/input startup deliberately changed exactly these four
    # helpers. Pin both complete ASTs, including every admission check;
    # compare every other helper directly. Empty type_params is the
    # sole AST serialization difference between CPython3.11 and3.12.
    from hashlib import sha256
    reviewed_owner_delta = {'fixed_admission': {'ordinary': 'c2558cdb925497f1c9397a831c080baaf2a2d45b8a507e1ba6c31bb5db7791dd', 'historical_a05': 'b0ec48f145a99e1e5f2b77885212a799a2f3def65afd1e3cb6c5fde2a2742f49'}, 'fixed_windows_mcp_sdk_bootstrap': {'ordinary': '07839a3dc19a095a215fbe440994058835a4394516f8511f4c059f365ca48f67', 'historical_a05': '9c160d04f16c3253f0b422606f9d2e57b55faa3d898bd6ecce33bf62de2e9d25'}, 'fixed_startup': {'ordinary': '3ad0bdad5f7b3e9a90fd05196ab8ef4f21594769c628ae014c08aea7eaf9d11b', 'historical_a05': 'a3a96a44d8ecc92ec55350fc4aed159ab838a2ac29f99005aec36d5f3592c53d'}, 'fixed_startup_version': {'ordinary': '37178615a01255c24adff4910a2be007a34e1bd4b2e2e435a17fa982330c2777', 'historical_a05': '0ab49cbb580624cd803b3d29a6729ca3a02f2be71b068bf688f8eed241bd2f7d'}}
    def stable_ast(node):
        normalized = deepcopy(node)
        for part in ast.walk(normalized):
            if isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and getattr(part, 'type_params', None) == []:
                delattr(part, 'type_params')
        return ast.dump(normalized, include_attributes=False)
    for name in normal_functions.keys()-{'main'}:
        if name in reviewed_owner_delta:
            expected = reviewed_owner_delta[name]
            assert sha256(stable_ast(normal_functions[name]).encode()).hexdigest() == expected['ordinary'], name
            assert sha256(stable_ast(fixed_functions[name]).encode()).hexdigest() == expected['historical_a05'], name
        else:
            assert stable_ast(normal_functions[name]) == stable_ast(fixed_functions[name]), name
    assert not any(isinstance(n, ast.Name) and n.id == '_DynamicA05Test' for n in ast.walk(normal))
    calls = [n for n in ast.walk(fixed_functions['main']) if isinstance(n, ast.Call)
             and any(k.arg == '_dynamic_a05_test' for k in n.keywords)]
    assert len(calls) == 1
    assert not any(isinstance(n, ast.keyword) and n.arg == '_dynamic_a05_test'
                   for fn in ('fixed_startup', 'fixed_windows_mcp_sdk_bootstrap') for n in ast.walk(fixed_functions[fn]))


@pytest.mark.parametrize('field,value', [('fixture_id', 'foreign'), ('run_id', 'foreign'),
    ('cutpoint', 'scope-pinned-before-effect'), ('intent_binding', 'arbitrary-digest'),
    ('installation_id', 'foreign'), ('root_grants_digest', INTENT), ('evidence_identity_digest', INTENT),
    ('preparation_identity_digest', INTENT)])
def test_wrong_fixed_binding_is_rejected_before_events(tmp_path, field, value):
    launch = launch_shell(tmp_path, binding_change=lambda b: b.update({field: value}))
    with patch.object(module, '_Win32A05Events') as native, pytest.raises(PhaseError) as caught:
        token(launch)
    assert caught.value.code == 'ntfs.dynamic_a05_test_binding'
    native.assert_not_called(); launch.spawn_core.assert_not_called()


def test_ordinary_launcher_digest_cannot_activate_fixture(tmp_path):
    launch = launch_shell(tmp_path, graph_change=lambda g: g.update(launcher_digest=INTENT))
    with pytest.raises(PhaseError) as caught:
        token(launch)
    assert caught.value.code == 'ntfs.dynamic_a05_test_launcher_required'


def test_data_file_must_be_bound_in_actual_artifact_graph(tmp_path):
    launch = launch_shell(tmp_path)
    config = launch._config
    config['dependency_file_digests'] = {}
    launch._config_bytes = canonical_bytes(config)
    with pytest.raises(PhaseError) as caught:
        token(launch)
    assert caught.value.code == 'ntfs.dynamic_a05_test_binding'


def test_foreign_type_and_foreign_launch_fail_before_spawn(tmp_path):
    launch = launch_shell(tmp_path)
    with pytest.raises(PhaseError) as caught:
        run_native_parent(launch, _dynamic_a05_test=Mock())
    assert caught.value.code == 'ntfs.dynamic_a05_test_role_required'
    launch.check_runtime.assert_not_called(); launch.spawn_core.assert_not_called()
    owner = token(launch)
    other_path = tmp_path/'other'; other_path.mkdir()
    other = launch_shell(other_path)
    with pytest.raises(PhaseError) as caught:
        run_native_parent(other, _dynamic_a05_test=owner)
    assert caught.value.code == 'ntfs.dynamic_a05_test_role_required'
    other.spawn_core.assert_not_called()


@pytest.mark.parametrize('mode', ['inspect', 'inspect-request', 'recover-request', 'ordinary-admission', 'foreign-grant'])
def test_no_read_recovery_or_foreign_fixture_role(tmp_path, mode):
    launch = launch_shell(tmp_path)
    if mode == 'inspect':
        launch._inspection_only = True
    elif mode.endswith('-request'):
        invocation = launch.invocation
        invocation['request']['operation'] = 'inspect' if mode == 'inspect-request' else 'recover_publication'
        launch._invocation_bytes = canonical_bytes(invocation)
    elif mode == 'ordinary-admission':
        launch._experimental_admission_context = None
    else:
        manifest = launch.manifest; manifest['root_grants'][0]['components'][1] = 'foreign'
        launch._manifest_bytes = canonical_bytes(manifest)
    with pytest.raises(PhaseError):
        token(launch)
    launch.spawn_core.assert_not_called()


def test_subclass_is_not_an_arbitrary_callback(tmp_path):
    class Foreign(module._DynamicA05Test):
        pass
    with pytest.raises(PhaseError) as caught:
        Foreign(launch_shell(tmp_path), _initial_deadline_ns=time.perf_counter_ns()+1_000_000_000)
    assert caught.value.code == 'ntfs.dynamic_a05_test_role_required'


@pytest.mark.parametrize('fault', [None, 'timeout', 'aborted'])
def test_one_shot_bounded_wait_and_raw_closure(tmp_path, fault):
    launch = launch_shell(tmp_path); owner = token(launch)
    api = Events(fault)
    deadline = time.perf_counter_ns()+1_000_000_000
    with patch.object(module, '_Win32A05Events', return_value=api):
        if fault is None:
            owner.original_read_complete(launch, parsed(launch), INTENT, _exchange_deadline_ns=deadline)
        else:
            with pytest.raises(PhaseError) as caught:
                owner.original_read_complete(launch, parsed(launch), INTENT, _exchange_deadline_ns=deadline)
            assert caught.value.code == 'ntfs.dynamic_a05_cutpoint_unavailable'
            assert caught.value.details['primary']['code'] == 'ntfs.dynamic_a05_test_'+fault
            assert caught.value.details['worker_spawn_attempted'] is False
        assert owner._consumed is True and api.closed is True and api.deadline == deadline
        with pytest.raises(PhaseError) as caught:
            owner.original_read_complete(launch, parsed(launch), INTENT)
        assert caught.value.code == 'ntfs.dynamic_a05_test_consumed'
    record = parse_json_bytes((Path(launch._config['windows_launcher']).parent/'dynamic-a05-cutpoint-final.json').read_bytes())
    assert record['intent_digest'] == INTENT and record['deadline_reset'] is False
    assert record['observed_handle_close_errors_before_report'] == [] and record['worker_spawn_attempted'] is False
    assert record['authoritative'] is False and record['return_established'] is None and record['final_acceptance'] is None


def test_bad_original_consumes_token_without_opening_events(tmp_path):
    launch = launch_shell(tmp_path); owner = token(launch)
    wrong = parsed(launch); value = parse_json_bytes(wrong.context_bytes); value['operation_nonce'] = 'e'*32
    wrong.context_bytes = canonical_bytes(value)
    with patch.object(module, '_Win32A05Events') as native, pytest.raises(PhaseError):
        owner.original_read_complete(launch, wrong, INTENT)
    assert owner._consumed is True
    native.assert_not_called()


def test_reinitialization_cannot_rearm_same_token(tmp_path):
    launch = launch_shell(tmp_path); owner = token(launch)
    owner._consumed = True
    with pytest.raises(PhaseError) as caught:
        owner.__init__(launch, _initial_deadline_ns=time.perf_counter_ns()+1_000_000_000)
    assert caught.value.code == 'ntfs.dynamic_a05_test_initialization_consumed'
    assert owner._consumed is True


@pytest.mark.parametrize('family', ['file1', 'file2', 'version1', 'version2', 'bundle1', 'bundle2'])
@pytest.mark.parametrize('fault', [None, 'timeout', 'aborted'])
def test_real_parent_body_order_original_binding_cut_then_single_spawn(tmp_path, family, fault):
    launch = launch_shell(tmp_path, family); opaque = token(launch); calls = []
    original = parsed(launch)
    def read(_):
        calls.append('genuine_original_return_MODELED')
        return original
    def spawn():
        calls.append('spawn_MODELED')
        raise RuntimeError('deliberately unavailable modeled spawn; no native process')
    launch.read_original = read; launch.spawn_worker = Mock(side_effect=spawn)
    parent = object.__new__(_NativeWindowsParent)
    parent._launch = launch; parent._inspection_only = False; parent._consumed = True
    parent._spawn_attempted = False; parent._file2 = launch._file2; parent._bundle = launch._bundle
    parent._version1 = launch._version1; parent._version2 = launch._version2
    parent._file2_exchange_deadline = time.perf_counter_ns()+20_000_000_000 if parent._file2 or parent._bundle else None
    parent._dynamic_a05_test = opaque
    api = Events(fault, calls)
    with patch.object(module, '_Win32A05Events', return_value=api), pytest.raises(PhaseError if fault else RuntimeError) as caught:
        parent._execute(INTENT, _common={})
    assert calls[0] == 'genuine_original_return_MODELED'
    assert calls.index('cutpoint_MODELED') < calls.index('closed_MODELED')
    if fault is None:
        assert str(caught.value) == 'deliberately unavailable modeled spawn; no native process'
        assert calls[-1] == 'spawn_MODELED' and parent._spawn_attempted is True
        launch.spawn_worker.assert_called_once()
    else:
        assert caught.value.code == 'ntfs.dynamic_a05_cutpoint_unavailable'
        assert 'spawn_MODELED' not in calls and parent._spawn_attempted is False
        launch.spawn_worker.assert_not_called()
        assert parent._consumed is True and opaque._consumed is True


def test_normal_none_does_not_parse_fixture_or_open_events():
    parent = object.__new__(_NativeWindowsParent)
    parent._dynamic_a05_test = None
    with patch.object(module, '_Win32A05Events') as native:
        assert parent._after_original_read(None, None) is None
    native.assert_not_called()


def test_original_binding_rejects_before_cut_or_spawn(tmp_path):
    launch = launch_shell(tmp_path); opaque = token(launch); original = parsed(launch)
    context = parse_json_bytes(original.context_bytes); context['operation_nonce'] = 'e'*32
    original.context_bytes = canonical_bytes(context)
    launch.read_original = Mock(return_value=original); launch.spawn_worker = Mock()
    parent = object.__new__(_NativeWindowsParent)
    parent._launch = launch; parent._inspection_only = False; parent._consumed = True
    parent._spawn_attempted = False; parent._file2 = True; parent._bundle = False
    parent._version1 = parent._version2 = False; parent._dynamic_a05_test = opaque
    parent._file2_exchange_deadline = time.perf_counter_ns()+20_000_000_000
    with patch.object(module, '_Win32A05Events') as native, pytest.raises(PhaseError) as caught:
        parent._execute(INTENT)
    assert caught.value.code == 'ntfs.parent_original_binding_mismatch'
    assert opaque._consumed is False
    native.assert_not_called(); launch.spawn_worker.assert_not_called()


def test_expired_existing_exchange_consumes_without_native_event(tmp_path):
    launch = launch_shell(tmp_path); opaque = token(launch)
    with patch.object(module, '_Win32A05Events') as native, pytest.raises(PhaseError) as caught:
        opaque.original_read_complete(launch, parsed(launch), INTENT, _exchange_deadline_ns=0)
    assert caught.value.code == 'ntfs.dynamic_a05_test_timeout'
    assert opaque._consumed is True
    native.assert_not_called()


def test_finalization_past_existing_deadline_cannot_proceed(tmp_path):
    launch = launch_shell(tmp_path)
    clock = [100]
    class LateClose(Events):
        def close(self):
            clock[0] = 201
            return super().close()
    api = LateClose()
    with patch.object(module.time, 'perf_counter_ns', side_effect=lambda: clock[0]):
        opaque = module._DynamicA05Test(launch, _initial_deadline_ns=200)
        with patch.object(module, '_Win32A05Events', return_value=api), pytest.raises(PhaseError) as caught:
            opaque.original_read_complete(launch, parsed(launch), INTENT)
    assert caught.value.code == 'ntfs.dynamic_a05_cutpoint_unavailable'
    assert caught.value.details['primary']['code'] == 'ntfs.dynamic_a05_test_timeout'
    assert api.closed is True and caught.value.details['worker_spawn_attempted'] is False
    saved = parse_json_bytes((Path(launch._config['windows_launcher']).parent/'dynamic-a05-cutpoint-final.json').read_bytes())
    assert saved['telemetry_stage'] == 'pre_return_observation'
    assert saved['authoritative'] is False and saved['return_established'] is None and saved['final_acceptance'] is None
    assert 'primary' not in saved and saved['observed_error_before_report'] is None
    assert saved['observation_before_report_ns'] >= saved['barrier_deadline_ns']


class Function:
    def __init__(self, call):
        self.call = call
    def __call__(self, *args):
        return self.call(*args)


class Kernel:
    """Synthetic ctypes boundary; numeric handles never reach Windows."""
    def __init__(self, wait_status=1, initial_state=258, failure=None, failure_occurrence=1):
        self.wait_status, self.initial_state = wait_status, initial_state
        self.failure, self.failure_occurrence, self.counts = failure, failure_occurrence, {}
        self.opened, self.closed, self.waited = [], [], []
        for name in ('OpenEventW', 'SetEvent', 'WaitForSingleObject', 'WaitForMultipleObjects',
                     'CloseHandle', 'GetCurrentProcess', 'OpenProcessToken', 'GetTokenInformation'):
            setattr(self, name, Function(lambda *args, name=name: self.invoke(name, args)))
    def invoke(self, name, args):
        self.counts[name] = self.counts.get(name, 0)+1
        fails = name == self.failure and self.counts[name] == self.failure_occurrence
        if fails and name != 'CloseHandle':
            return 0
        if name == 'OpenEventW':
            handle = 20+len(self.opened); self.opened.append((handle, args)); return handle
        if name == 'WaitForSingleObject':
            assert args[1] == 0; return self.initial_state
        if name == 'WaitForMultipleObjects':
            self.waited.append(args)
            assert args[0] == 2 and list(args[1]) == [22, 21] and args[2] is False
            assert 0 <= args[3] <= 1000
            return self.wait_status
        if name == 'GetCurrentProcess':
            return -1
        if name == 'OpenProcessToken':
            assert args[1] == 8; args[2]._obj.value = 99
        if name == 'GetTokenInformation':
            assert args[1] == 20; args[2]._obj.value = 0; args[4]._obj.value = 4
        if name == 'CloseHandle':
            self.closed.append(args[0])
            if fails:
                return 0
        return 1


@pytest.mark.parametrize('status,code', [(1, None), (0, 'ntfs.dynamic_a05_test_aborted'),
    (258, 'ntfs.dynamic_a05_test_timeout'), (0xffffffff, 'ntfs.dynamic_a05_test_wait_unknown')])
def test_native_wait_wrapper_abort_priority_bounded_wait_and_all_closes(status, code):
    kernel = Kernel(status)
    with patch.object(module.os, 'name', 'nt'), patch.object(module.C, 'WinDLL', return_value=kernel, create=True):
        api = module._Win32A05Events()
    with patch.object(module.C, 'set_last_error', create=True), patch.object(module.C, 'get_last_error', return_value=0, create=True), \
            patch.object(module.os.sys, 'getwindowsversion', return_value=SimpleNamespace(build=19045), create=True):
        assert api.environment()['token_elevated'] is False
        handles = api.open_events({'held': 'held', 'release': 'release', 'abort': 'abort'})
        deadline = time.perf_counter_ns()+1_000_000_000
        if code is None:
            api.hold(handles, deadline)
        else:
            with pytest.raises(PhaseError) as caught:
                api.hold(handles, deadline)
            assert caught.value.code == code
        assert api.close() == []
    assert kernel.closed == [22, 21, 20, 99]
    assert all(args[1] is False for _, args in kernel.opened)
    assert any(event['api'] == 'GetCurrentProcess' for event in api.events)
    assert any(event['api'] == 'WaitForMultipleObjects' for event in api.events)


def test_fixed_windows_reader_keeps_method_specific_ctime(tmp_path):
    path = tmp_path/'fixed.json'; path.write_bytes(b'{"fixed":true}')
    original = module.os.fstat
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink', 'st_birthtime_ns')
    def opened(fd):
        value = original(fd)
        values = {name: getattr(value, name) for name in fields if hasattr(value, name)}
        values['st_ctime_ns'] += 1_000_000
        return SimpleNamespace(**values)
    with patch.object(module.os, 'fstat', side_effect=opened):
        assert module._fixed_read(path) == b'{"fixed":true}'


def test_fixed_reader_rejects_opened_identity_drift_and_closes_fd(tmp_path):
    path = tmp_path/'fixed.json'; path.write_bytes(b'{}')
    original, close = module.os.fstat, module.os.close
    calls = []
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink', 'st_birthtime_ns')
    def opened(fd):
        value = original(fd); calls.append(fd)
        values = {name: getattr(value, name) for name in fields if hasattr(value, name)}
        if len(calls) == 2:
            values['st_ino'] += 1
        return SimpleNamespace(**values)
    with patch.object(module.os, 'fstat', side_effect=opened), patch.object(module.os, 'close', wraps=close) as closed, pytest.raises(PhaseError):
        module._fixed_read(path)
    closed.assert_called_once_with(calls[0])


def test_fixed_reader_refuses_over_bound_before_open(tmp_path):
    path = tmp_path/'large.json'; path.write_bytes(b'x'*(module._MAX_RAW+1))
    with patch.object(module.os, 'open') as opened, pytest.raises(PhaseError):
        module._fixed_read(path)
    opened.assert_not_called()


def modeled_api(kernel):
    with patch.object(module.os, 'name', 'nt'), patch.object(module.C, 'WinDLL', return_value=kernel, create=True):
        return module._Win32A05Events()


def modeled_winerror(code):
    error = OSError(code, 'MODELED Win32 boundary failure')
    error.winerror = code
    return error


@pytest.mark.parametrize('api_name,occurrence,closed', [
    ('OpenProcessToken', 1, []), ('GetTokenInformation', 1, [99]),
    ('OpenEventW', 2, [20, 99]), ('CloseHandle', 2, [22, 21, 20, 99])])
def test_event_token_api_failures_close_every_owned_handle_once_and_cannot_claim_return(tmp_path, api_name, occurrence, closed):
    launch = launch_shell(tmp_path); opaque = token(launch)
    kernel = Kernel(failure=api_name, failure_occurrence=occurrence)
    api = modeled_api(kernel)
    with patch.object(module, '_Win32A05Events', return_value=api), \
            patch.object(module.C, 'set_last_error', create=True), \
            patch.object(module.C, 'get_last_error', return_value=5, create=True), \
            patch.object(module.C, 'WinError', side_effect=modeled_winerror, create=True), \
            patch.object(module.os.sys, 'getwindowsversion', return_value=SimpleNamespace(build=19045), create=True), \
            pytest.raises(PhaseError) as caught:
        opaque.original_read_complete(launch, parsed(launch), INTENT)
    assert caught.value.code == 'ntfs.dynamic_a05_cutpoint_unavailable'
    assert kernel.closed == closed and opaque._consumed is True
    assert caught.value.details['worker_spawn_attempted'] is False
    saved = parse_json_bytes((Path(launch._config['windows_launcher']).parent/'dynamic-a05-cutpoint-final.json').read_bytes())
    assert saved['telemetry_stage'] == 'pre_return_observation'
    assert saved['authoritative'] is False and saved['return_established'] is None and saved['final_acceptance'] is None
    assert 'primary' not in saved
    if api_name == 'CloseHandle':
        assert len(saved['observed_handle_close_errors_before_report']) == 1
    else:
        assert saved['observed_error_before_report'] is not None
    assert any(e['api'] == api_name and e['result'] == 0 for e in saved['native_events'])


def test_final_telemetry_fsync_failure_closes_file_and_event_handles(tmp_path):
    launch = launch_shell(tmp_path); opaque = token(launch); api = Events()
    actual = module.os.fsync; files = []
    def fsync(fd):
        files.append(fd)
        if len(files) == 2:
            raise OSError('MODELED final telemetry fsync failure')
        actual(fd)
    with patch.object(module, '_Win32A05Events', return_value=api), patch.object(module.os, 'fsync', side_effect=fsync), pytest.raises(PhaseError) as caught:
        opaque.original_read_complete(launch, parsed(launch), INTENT)
    assert caught.value.code == 'ntfs.dynamic_a05_cutpoint_unavailable' and api.closed is True
    assert len(files) == 2
    with pytest.raises(OSError):
        os.fstat(files[-1])  # Actual owned telemetry FD was closed on fsync error.
    saved = parse_json_bytes((Path(launch._config['windows_launcher']).parent/'dynamic-a05-cutpoint-final.json').read_bytes())
    assert saved['observed_error_before_report'] is None
    assert saved['authoritative'] is False and saved['return_established'] is None and saved['final_acceptance'] is None
    assert 'primary' not in saved


def test_late_final_write_persisted_snapshot_never_substitutes_outer_outcome_or_allows_spawn(tmp_path):
    launch = launch_shell(tmp_path); clock = [100]; original_write = module._write_fixed
    api = Events()
    def late_write(path, value):
        original_write(path, value)
        if path.name == 'dynamic-a05-cutpoint-final.json':
            clock[0] = 201
    with patch.object(module.time, 'perf_counter_ns', side_effect=lambda: clock[0]):
        opaque = module._DynamicA05Test(launch, _initial_deadline_ns=200)
        original = parsed(launch)
        launch.read_original = Mock(return_value=original); launch.spawn_worker = Mock()
        parent = object.__new__(_NativeWindowsParent)
        parent._launch = launch; parent._inspection_only = False; parent._consumed = True
        parent._spawn_attempted = False; parent._file2 = True; parent._bundle = False
        parent._version1 = parent._version2 = False; parent._dynamic_a05_test = opaque
        parent._file2_exchange_deadline = 200
        with patch.object(module, '_Win32A05Events', return_value=api), patch.object(module, '_write_fixed', side_effect=late_write), pytest.raises(PhaseError) as caught:
            parent._execute(INTENT)
    assert caught.value.code == 'ntfs.dynamic_a05_cutpoint_unavailable'
    assert caught.value.details['primary']['code'] == 'ntfs.dynamic_a05_test_timeout'
    assert caught.value.details['raw_test_observation']['after_report_check_ns'] == 201
    assert api.closed is True and parent._spawn_attempted is False
    launch.spawn_worker.assert_not_called()
    saved = parse_json_bytes((Path(launch._config['windows_launcher']).parent/'dynamic-a05-cutpoint-final.json').read_bytes())
    assert saved['observed_error_before_report'] is None and saved['observation_before_report_ns'] == 100
    assert saved['authoritative'] is False and saved['return_established'] is None and saved['final_acceptance'] is None
    assert saved['telemetry_stage'] == 'pre_return_observation' and 'primary' not in saved
    assert 'after_report_check_ns' not in saved  # That fact is known only AFTER its own close.


def test_fixed_artifact_io_is_owned_by_evidence_boundary():
    assert module._fixed_read.__module__ == 'phase_tool.evidence'
    assert module._write_fixed.__module__ == 'phase_tool.evidence'


def test_fixed_telemetry_remains_bounded_exclusive_and_fsynced(tmp_path):
    from phase_tool import evidence
    path = tmp_path/'raw.json'
    real_fsync = evidence.os.fsync
    with patch.object(evidence.os, 'fsync', wraps=real_fsync) as synced:
        module._write_fixed(path, {'raw': True})
    assert path.read_bytes() == b'{"raw":true}'
    synced.assert_called_once()
    with pytest.raises(FileExistsError):
        module._write_fixed(path, {'raw': False})
    assert path.read_bytes() == b'{"raw":true}'
    large = tmp_path/'too-large.json'
    with pytest.raises(PhaseError) as caught:
        module._write_fixed(large, {'raw': 'x'*module._MAX_RAW})
    assert caught.value.code == 'ntfs.dynamic_a05_test_telemetry_bound'
    assert not large.exists()
