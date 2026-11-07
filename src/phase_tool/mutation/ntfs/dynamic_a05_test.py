"""Closed qualification fixture: original read complete, before sole worker.

No public request selector, callback, Core, receipt, retry or effect is supplied.
Only the exact code-owned external test launcher can construct this token. Its
fixed adjacent data is bound by the EXISTING accepted dependency/artifact graph.
Ordinary CLI/MCP launchers never pass this optional token. Native observations
here concern the fixture's event/token handles, not worker exit or qualification.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import re
import stat
import threading
import time

from ...canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import _require
from .uncertainty import _diagnostic


_FIXTURE = '74a6fb65-5af8-48f2-96e3-04c094272a9b'
_CUT = 'original-read-complete-before-worker'
_VERSION = 'phase.test.dynamic-a05-cutpoint/1'
_LAUNCHER_DIGEST = 'sha256:f79404f8487b6f53ab17bd9ffe4e672d4044deb58d086aa6536dacb2fff87d49'
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_MAX_RAW = 65536


def _fixed_read(path):
    """Bounded fixed installation data; no request-selected path or loader."""
    _require(type(path) is type(Path()) and path.is_absolute(), 'ntfs.dynamic_a05_test_binding')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        _require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0)&0x400,
                 'ntfs.dynamic_a05_test_binding')
    before = path.stat()
    _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= _MAX_RAW,
             'ntfs.dynamic_a05_test_binding')
    def cross(info):
        # CPython3.12 Windows named stat/fstat may expose different meanings of
        # ctime. Keep each method's full before/after check; do not compare that
        # field across methods or weaken size/identity/mtime/birthtime checks.
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                getattr(info, 'st_birthtime_ns', None))
    def same_method(info):
        return (*cross(info), info.st_ctime_ns, info.st_mode, info.st_nlink)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                 | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(fd)
        _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                 and cross(before) == cross(opened), 'ntfs.dynamic_a05_test_binding')
        raw = bytearray()
        while True:
            part = os.read(fd, min(65536, _MAX_RAW-len(raw)+1))
            if not part:
                break
            raw.extend(part)
            _require(len(raw) <= _MAX_RAW, 'ntfs.dynamic_a05_test_binding')
        after_opened = os.fstat(fd)
        after = path.stat()
        _require(len(raw) == before.st_size == after.st_size
                 and same_method(before) == same_method(after)
                 and same_method(opened) == same_method(after_opened)
                 and cross(after) == cross(after_opened), 'ntfs.dynamic_a05_test_binding')
        for parent in (*reversed(path.parents), path):
            info = parent.lstat()
            _require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0)&0x400,
                     'ntfs.dynamic_a05_test_binding')
        return bytes(raw)
    finally:
        os.close(fd)


def _write_fixed(path, value):
    raw = canonical_bytes(value)
    _require(len(raw) <= _MAX_RAW, 'ntfs.dynamic_a05_test_telemetry_bound')
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class _Win32A05Events:
    """One actual bounded native wait; no process search, kill or effect API."""
    def __init__(self):
        _require(os.name == 'nt', 'ntfs.dynamic_a05_test_windows_required')
        self.events = []
        self._handles = []
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.advapi = C.WinDLL('advapi32', use_last_error=True)
        for name, arguments, result in (
            ('OpenEventW', [W.DWORD, W.BOOL, W.LPCWSTR], W.HANDLE),
            ('SetEvent', [W.HANDLE], W.BOOL),
            ('WaitForSingleObject', [W.HANDLE, W.DWORD], W.DWORD),
            ('WaitForMultipleObjects', [W.DWORD, C.POINTER(W.HANDLE), W.BOOL, W.DWORD], W.DWORD),
            ('CloseHandle', [W.HANDLE], W.BOOL),
            ('GetCurrentProcess', [], W.HANDLE)):
            api = getattr(self.kernel, name)
            api.argtypes, api.restype = arguments, result
        self.advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
        self.advapi.OpenProcessToken.restype = W.BOOL
        self.advapi.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
        self.advapi.GetTokenInformation.restype = W.BOOL

    def _call(self, name, *args, _api=None, _boolean=True, **facts):
        started = time.perf_counter_ns()
        C.set_last_error(0)
        value = getattr(self.kernel if _api is None else _api, name)(*args)
        code = C.get_last_error()
        self.events.append({'api': name, 'result': value, 'winerror': code,
                            'started_ns': started, 'returned_ns': time.perf_counter_ns(), **facts})
        if _boolean and not value:
            raise C.WinError(code)
        return value

    def environment(self):
        token = W.HANDLE()
        process = self._call('GetCurrentProcess', _boolean=False, pseudo_handle=True)
        self._call('OpenProcessToken', process, 8, C.byref(token), _api=self.advapi,
                   desired_access='TOKEN_QUERY')
        self._handles.append(token.value)
        elevated, count = C.c_uint32(), C.c_uint32()
        self._call('GetTokenInformation', token, 20, C.byref(elevated), C.sizeof(elevated), C.byref(count),
                   _api=self.advapi, information_class='TokenElevation')
        _require(count.value == C.sizeof(elevated) and elevated.value == 0,
                 'ntfs.dynamic_a05_test_ordinary_token_required')
        return {'pid': os.getpid(), 'windows_build': os.sys.getwindowsversion().build,
                'token_elevated': bool(elevated.value), 'token_elevation_bytes': count.value}

    def open_events(self, names):
        result = {}
        for kind in ('held', 'release', 'abort'):
            access = 0x100002 if kind == 'held' else 0x100000
            handle = self._call('OpenEventW', access, False, names[kind], event_name=names[kind],
                                desired_access=access, inherit_handle=False)
            self._handles.append(handle)
            result[kind] = handle
            state = self._call('WaitForSingleObject', handle, 0, _boolean=False, timeout_ms=0)
            _require(state == 258, 'ntfs.dynamic_a05_test_event_not_fresh')
        return result

    def hold(self, handles, deadline_ns):
        _require(time.perf_counter_ns() < deadline_ns, 'ntfs.dynamic_a05_test_timeout')
        self._call('SetEvent', handles['held'])
        remaining = deadline_ns-time.perf_counter_ns()
        _require(remaining > 0, 'ntfs.dynamic_a05_test_timeout')
        # Abort comes first, so simultaneous release+abort cannot authorize work.
        pair = (W.HANDLE*2)(handles['abort'], handles['release'])
        milliseconds = max(0, remaining//1_000_000)
        status = self._call('WaitForMultipleObjects', 2, pair, False, milliseconds,
                            _boolean=False, timeout_ms=milliseconds, deadline_ns=deadline_ns)
        if status == 0:
            raise PhaseError('ntfs.dynamic_a05_test_aborted')
        _require(status == 1 and time.perf_counter_ns() < deadline_ns,
                 'ntfs.dynamic_a05_test_timeout' if status in (1, 258) else 'ntfs.dynamic_a05_test_wait_unknown')

    def close(self):
        errors = []
        for handle in reversed(self._handles):
            try:
                self._call('CloseHandle', handle, handle=handle)
            except BaseException as error:
                errors.append(error)
        self._handles.clear()
        return errors


class _DynamicA05Test:
    """Opaque one-shot token, executable only in one exact test installation."""
    __slots__ = ('_launch', '_owner', '_binding_bytes', '_initial_deadline', '_consumed',
                 '_intent_digest', '_telemetry_parent', '_initialization_attempted')

    def __init__(self, launch, *, _initial_deadline_ns):
        from .bootstrap import _NativeAcceptedLaunch
        _require(type(self) is _DynamicA05Test and type(launch) is _NativeAcceptedLaunch,
                 'ntfs.dynamic_a05_test_role_required')
        _require(not getattr(self, '_initialization_attempted', False), 'ntfs.dynamic_a05_test_initialization_consumed')
        self._initialization_attempted = True
        self._launch = launch
        self._owner = os.getpid(), threading.get_ident()
        self._consumed = False
        self._intent_digest = None
        self._initial_deadline = _initial_deadline_ns
        _require(type(_initial_deadline_ns) is int
                 and 0 < _initial_deadline_ns-time.perf_counter_ns() <= 30_000_000_000,
                 'ntfs.dynamic_a05_test_deadline_required')
        self.check_launch(launch)
        config = launch._config
        launcher = Path(config['windows_launcher'])
        path = launcher.parent/'dynamic-a05-test.json'
        raw = _fixed_read(path)
        pin = config['dependency_file_digests'].get(str(path))
        _require(type(pin) is str and _DIGEST.fullmatch(pin) is not None
                 and digest_bytes(raw) == pin
                 and config['artifact_graph']['windows']['dependency_file_digests'].get(str(path)) == pin,
                 'ntfs.dynamic_a05_test_binding')
        self._binding_bytes = raw
        self._telemetry_parent = launcher.parent
        self._binding(launch)

    def check_launch(self, launch):
        from .bootstrap import _NativeAcceptedLaunch
        from .experimental_history_set import _mixed_history_contexts
        _require(type(self) is _DynamicA05Test and type(launch) is _NativeAcceptedLaunch
                 and launch is self._launch and self._owner == (os.getpid(), threading.get_ident()),
                 'ntfs.dynamic_a05_test_role_required')
        _require(not self._consumed, 'ntfs.dynamic_a05_test_consumed')
        request = launch.invocation['request']
        _require(launch._inspection_only is False and type(launch._experimental_admission_context) in _mixed_history_contexts()
                 and type(request) is dict and request.get('operation') == 'execute',
                 'ntfs.dynamic_a05_test_role_required')
        launch.check_runtime()
        config = launch._config
        graph = config['artifact_graph']
        _require(graph['launcher_digest'] == _LAUNCHER_DIGEST
                 and canonical_digest(graph) == launch.manifest['composition']['artifact_graph_digest']
                 and digest_bytes(_fixed_read(Path(config['windows_launcher']))) == _LAUNCHER_DIGEST,
                 'ntfs.dynamic_a05_test_launcher_required')
        prefix = ['Phase-NTFS-Qualification', _FIXTURE, 'results']
        _require(all(type(g.get('components')) is list and g['components'][:3] == prefix
                     for g in launch.root_grants), 'ntfs.dynamic_a05_test_fixture_required')

    def _binding(self, launch):
        value = parse_json_bytes(self._binding_bytes, maximum_bytes=_MAX_RAW)
        fields = {'dynamic_a05_test_version', 'fixture_id', 'case_id', 'cutpoint', 'run_id',
                  'installation_id', 'contract', 'root_grants_digest', 'evidence_identity_digest',
                  'preparation_identity_digest', 'intent_binding'}
        _require(type(value) is dict and set(value) == fields and canonical_bytes(value) == self._binding_bytes
                 and value['dynamic_a05_test_version'] == '1.0' and value['fixture_id'] == _FIXTURE
                 and value['cutpoint'] == _CUT and value['intent_binding'] == 'genuine-first-original'
                 and type(value['case_id']) is str and re.fullmatch('[a-z0-9-]{1,96}', value['case_id']) is not None
                 and value['run_id'] == launch.run_id and value['installation_id'] == launch.manifest['installation_id']
                 and value['contract'] == launch.manifest['contract']
                 and value['root_grants_digest'] == canonical_digest(launch.root_grants)
                 and value['evidence_identity_digest'] == canonical_digest(launch.manifest['evidence_identity'])
                 and value['preparation_identity_digest'] == canonical_digest(launch.manifest['preparation_identity']),
                 'ntfs.dynamic_a05_test_binding')
        return value

    def original_read_complete(self, launch, parsed, intent_digest, *, _exchange_deadline_ns=None):
        self.check_launch(launch)
        _require(not self._consumed, 'ntfs.dynamic_a05_test_consumed')
        self._consumed = True  # Sticky before any original/clock/event/reporting failure.
        binding = self._binding(launch)
        context = parse_json_bytes(parsed.context_bytes, maximum_bytes=4096)
        _require(type(intent_digest) is str and _DIGEST.fullmatch(intent_digest) is not None
                 and context['intent_digest'] == intent_digest and context['run_id'] == launch.run_id
                 and context['operation_nonce'] == launch.operation_nonce
                 and context['installation_digest'] == launch.installation_digest,
                 'ntfs.dynamic_a05_test_original_binding')
        self._intent_digest = intent_digest
        now = time.perf_counter_ns()
        deadlines = [self._initial_deadline, now+5_000_000_000]
        if _exchange_deadline_ns is not None:
            _require(type(_exchange_deadline_ns) is int, 'ntfs.dynamic_a05_test_deadline_required')
            deadlines.append(_exchange_deadline_ns)
        deadline = min(deadlines)
        _require(0 < deadline-now <= 5_000_000_000, 'ntfs.dynamic_a05_test_timeout')
        case_id = binding['case_id']
        names = {kind: 'Local\\Phase-A05-'+_FIXTURE+'-'+case_id+'-'+kind for kind in ('held', 'release', 'abort')}
        record = {'schema': _VERSION, 'case_id': case_id, 'cutpoint': _CUT,
            'run_id': launch.run_id, 'intent_digest': intent_digest,
            'installation_digest': launch.installation_digest, 'operation_nonce': launch.operation_nonce,
            'original_read_returned': True, 'original_reader_exit_basis': 'existing genuine read_original return contract; internal retained-HANDLE fact is not re-emitted here',
            'effect_calls_before_barrier': 0, 'worker_spawn_attempted': False,
            'fixture_binding_digest': digest_bytes(self._binding_bytes),
            'initial_deadline_ns': self._initial_deadline, 'exchange_deadline_ns': _exchange_deadline_ns,
            'barrier_deadline_ns': deadline, 'entered_ns': now, 'deadline_reset': False,
            'qualification': 'NOT_VERIFIED', 'retry_authorized': False,
            'telemetry_stage': 'pre_wait_attestation', 'authoritative': False,
            'return_established': None, 'final_acceptance': None,
            'interpretation': 'Pre-return observations only. No value in this file establishes successful return, deadline compliance, worker exit, effect or acceptance. Require outer Phase outcome/native proof and complete clock/finalization evidence.',
            'scope': 'raw test event/token observations; not Core evidence, receipt, worker-exit proof or native qualification'}
        api = None
        primary = None
        close_errors = []
        try:
            api = _Win32A05Events()
            record['native_events'] = api.events
            record['environment'] = api.environment()
            handles = api.open_events(names)
            _require(time.perf_counter_ns() < deadline, 'ntfs.dynamic_a05_test_timeout')
            _write_fixed(self._telemetry_parent/'dynamic-a05-cutpoint.json', record)
            api.hold(handles, deadline)
            launch.check_runtime()
            _require(time.perf_counter_ns() < deadline, 'ntfs.dynamic_a05_test_timeout')
        except BaseException as error:
            primary = error
        finally:
            if api is not None:
                close_errors = api.close()
            record['telemetry_stage'] = 'pre_return_observation'
            record['observation_before_report_ns'] = time.perf_counter_ns()
            record['observed_error_before_report'] = None if primary is None else _diagnostic(primary)
            record['observed_handle_close_errors_before_report'] = [_diagnostic(error) for error in close_errors]
            try:
                _write_fixed(self._telemetry_parent/'dynamic-a05-cutpoint-final.json', record)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    close_errors.append(error)
        # Reporting/finalization may itself have consumed the remaining window.
        # A late successful release cannot start a worker under a fresh clock.
        record['after_report_check_ns'] = time.perf_counter_ns()
        if primary is None and record['after_report_check_ns'] >= deadline:
            primary = PhaseError('ntfs.dynamic_a05_test_timeout')
        if primary is not None or close_errors:
            raise PhaseError('ntfs.dynamic_a05_cutpoint_unavailable', details={
                'primary': None if primary is None else _diagnostic(primary),
                'finalization': [_diagnostic(error) for error in close_errors],
                'raw_test_observation': record, 'worker_spawn_attempted': False,
                'retry_authorized': False}) from primary
