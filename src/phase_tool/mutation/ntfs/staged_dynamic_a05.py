"""Closed startup3 fixture selection for the existing first dynamic A05 cut."""
from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
import re
import sys
import threading
import time

from ...canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from ...evidence import _read_dynamic_a05_fixed, validate_run_id
from .dynamic_a05_test import _CUT, _FIXTURE, _DynamicA05Test
from .native import NativeIdentity, _require


_LAUNCHER_DIGEST = 'sha256:5578642465bf1ddf627b6220712747eafb8c134f713f105793e9b8cab5e5d9ac'
_SIDECAR = 'dynamic-a05-staged-test.json'
_SCOPE = 'native-input-scope.json'
_CODE = 'ntfs.staged_dynamic_a05_binding'
_REQUEST_FIELDS = ('input_scope', 'source_locator', 'target_locator', 'request_id', 'members', 'expected_current_digest')
_FIXTURE_ROOT = PureWindowsPath('S:/Phase-NTFS-Qualification') / _FIXTURE


def _canonical(raw):
    value = parse_json_bytes(raw, maximum_bytes=2*1024**2)
    _require(type(raw) is bytes and type(value) is dict and canonical_bytes(value) == raw, _CODE)
    return value


def _owned_launcher(config, manifest):
    path = Path(config['windows_launcher'])
    graph = config['artifact_graph']
    main_file = getattr(sys.modules.get('__main__'), '__file__', None)
    _require(os.name == 'nt' and sys.argv[1:] in (['publish-input'], ['input-mcp'])
        and type(main_file) is str and path.is_absolute()
        and Path(main_file).absolute() == Path(sys.argv[0]).absolute() == path
        and config.get('native_launch_version') == '3.0'
        and graph['launcher_digest'] == _LAUNCHER_DIGEST
        and canonical_digest(graph) == manifest['composition']['artifact_graph_digest']
        and digest_bytes(_read_dynamic_a05_fixed(path)) == _LAUNCHER_DIGEST, _CODE)
    return path


def _fixed_data(config, path):
    raw = _read_dynamic_a05_fixed(path)
    pin = digest_bytes(raw)
    _require(config['dependency_file_digests'].get(str(path)) == pin
        and config['artifact_graph']['windows']['dependency_file_digests'].get(str(path)) == pin, _CODE)
    return raw


def _require_fixture_domain(admission, fixture, manifest, manifest_digest, scope, role):
    """Require the installed owner3 role and the physical volume of the actor fixture."""
    from .owner_directory_fixture import check_manifest
    from .owner_semantic_fixture import semantic_owner_role
    from .worker import _grant

    kind = type(admission)
    _require(fixture['fixture_uuid'] == _FIXTURE and role == semantic_owner_role(kind)
        and PureWindowsPath(scope['windows_root']) == _FIXTURE_ROOT / 'inputs', _CODE)
    # This also verifies the exact role's projection: Version2 has both
    # current and object roots; all other roles use only the current root.
    check_manifest(kind, admission.raw, manifest, manifest_digest)
    volume = scope['volume']
    source = NativeIdentity.parse(scope['root_identity'])
    for row in manifest['root_grants']:
        target = _grant(row)
        _require(target.device == volume['device']
            and target.volume_guid == volume['volume_guid']
            and target.volume_serial32 == volume['volume_serial32']
            and target.root_identity.volume_serial == source.volume_serial
            and target.root_identity != source, _CODE)


class _StagedA05Selection:
    """Exact installation-only state. One publication can attach one cut."""
    __slots__ = ('_initialized', '_pid', '_owner', '_startup', '_manifest', '_path', '_scope', '_role',
                 '_raw', '_binding', '_begun', '_attached', '_cut_created', '_deadline', '_call')

    def __init__(self, *, config_bytes, manifest_bytes, admission):
        from .input_stage import _input_scope_document
        from .experimental_history_set import _mixed_history_contexts
        _require(type(self) is _StagedA05Selection and not getattr(self, '_initialized', False), _CODE)
        self._initialized = True
        self._pid = os.getpid()
        self._owner = None
        self._begun = self._attached = self._cut_created = False
        self._startup = (config_bytes, manifest_bytes, admission)
        config, manifest = _canonical(config_bytes), _canonical(manifest_bytes)
        _require(type(admission) in _mixed_history_contexts(), _CODE)
        fixture = admission.document()
        _require(fixture['experimental_admission_version'] == '3.0', _CODE)
        self._path = _owned_launcher(config, manifest)
        scope_path = self._path.parent / _SCOPE
        scope_raw = _fixed_data(config, scope_path)
        scope, self._role = _input_scope_document(scope_raw, config=config, manifest=manifest,
            scope_path=scope_path, fixture_raw=admission.raw)
        _require_fixture_domain(admission, fixture, manifest, digest_bytes(manifest_bytes), scope, self._role)
        self._scope = scope['scope_id']
        self._manifest = manifest
        self._raw = _fixed_data(config, self._path.parent / _SIDECAR)
        value = _canonical(self._raw)
        fields = {'staged_dynamic_a05_test_version', 'fixture_id', 'case_id', 'cutpoint', 'run_id',
            'installation_id', 'contract', 'root_grants_digest', 'evidence_identity_digest',
            'preparation_identity_digest', 'intent_binding', 'input_scope_digest', 'call_digest'}
        grants = manifest['root_grants']
        _require(set(value) == fields and value['staged_dynamic_a05_test_version'] == '1.0'
            and value['fixture_id'] == _FIXTURE and value['cutpoint'] == _CUT
            and value['intent_binding'] == 'genuine-first-original'
            and type(value['case_id']) is str and re.fullmatch('[a-z0-9-]{1,96}', value['case_id']) is not None
            and value['installation_id'] == manifest['installation_id'] and value['contract'] == manifest['contract']
            and value['root_grants_digest'] == canonical_digest(grants)
            and value['evidence_identity_digest'] == canonical_digest(manifest['evidence_identity'])
            and value['preparation_identity_digest'] == canonical_digest(manifest['preparation_identity'])
            and value['input_scope_digest'] == digest_bytes(scope_raw)
            and type(value['run_id']) is str
            and type(value['call_digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}', value['call_digest']) is not None, _CODE)
        run_prefix = fixture['request_limits']['run_prefix']
        run_id = validate_run_id(value['run_id'])
        _require(run_id.startswith(run_prefix) and len(run_id) > len(run_prefix), _CODE)
        self._binding = value

    def _require_mcp_startup(self, startup):
        _require(type(self) is _StagedA05Selection and self._initialized
            and not self._begun and self._pid == os.getpid() and sys.argv[1:] == ['input-mcp'], _CODE)
        config, manifest, admission = self._startup
        _require(set(startup) == {'config_bytes', 'expected_config_digest', 'manifest_bytes',
                'expected_manifest_digest', '_experimental_admission_context'}
            and startup['config_bytes'] == config and startup['manifest_bytes'] == manifest
            and startup['expected_config_digest'] == digest_bytes(config)
            and startup['expected_manifest_digest'] == digest_bytes(manifest)
            and startup['_experimental_admission_context'] is admission, _CODE)
        return self._binding['run_id']

    def begin(self, startup, *, run_id, call, deadline_ns):
        from .input_stage import _active_input_deadline_ns
        _require(type(self) is _StagedA05Selection and not self._begun and self._pid == os.getpid(), _CODE)
        self._begun = True
        self._owner = os.getpid(), threading.get_ident()
        config, manifest, admission = self._startup
        _require(startup['config_bytes'] == config and startup['manifest_bytes'] == manifest
            and startup['expected_config_digest'] == digest_bytes(config)
            and startup['expected_manifest_digest'] == digest_bytes(manifest)
            and startup.get('_experimental_admission_context') is admission
            and run_id == self._binding['run_id'] and type(call) is dict and set(call) == set(_REQUEST_FIELDS)
            and call['input_scope'] == self._scope and canonical_digest(call) == self._binding['call_digest']
            and type(deadline_ns) is int and deadline_ns == _active_input_deadline_ns()
            and time.perf_counter_ns() < deadline_ns, _CODE)
        self._deadline = deadline_ns
        self._call = canonical_bytes(call)

    def attach(self, launch):
        from .bootstrap import _NativeAcceptedLaunch
        from .input_stage import _require_staged_publication_request
        _require(type(self) is _StagedA05Selection and self._begun and not self._attached and hasattr(self, '_call')
            and self._owner == (os.getpid(), threading.get_ident()) and type(launch) is _NativeAcceptedLaunch, _CODE)
        self._attached = True
        request = launch.invocation['request']
        call = parse_json_bytes(self._call)
        _require(launch._inspection_only is False and launch.run_id == self._binding['run_id']
            and launch.installation_digest == digest_bytes(self._startup[1])
            and (launch._config_bytes, launch._manifest_bytes) == self._startup[:2]
            and launch._experimental_admission_context is self._startup[2] and launch.manifest == self._manifest, _CODE)
        checked = _require_staged_publication_request(request, role=self._role)
        _require(all(checked[key] == call[key] for key in _REQUEST_FIELDS if key != 'source_locator'), _CODE)
        cut = _StagedDynamicA05Test(self, launch)
        cut.check_launch(launch)
        _require(launch._staged_a05_reader is None, _CODE)
        launch._staged_a05_reader = cut
        return cut


class _StagedDynamicA05Test:
    """Typed adapter to the original cut implementation and event protocol."""
    __slots__ = ('_selection', '_launch', '_owner', '_binding_bytes', '_initial_deadline',
                 '_consumed', '_intent_digest', '_telemetry_parent', '_invocation_bytes', '_reader_witness')

    def __init__(self, selection, launch):
        _require(type(self) is _StagedDynamicA05Test and not hasattr(self, '_launch')
            and type(selection) is _StagedA05Selection and selection._attached and not selection._cut_created, _CODE)
        selection._cut_created = True
        self._selection, self._launch, self._owner = selection, launch, selection._owner
        self._binding_bytes, self._initial_deadline = selection._raw, selection._deadline
        self._consumed, self._intent_digest = False, None
        self._reader_witness = None
        self._telemetry_parent = selection._path.parent
        self._invocation_bytes = launch._invocation_bytes

    def check_launch(self, launch):
        from .bootstrap import _NativeAcceptedLaunch
        from .input_stage import _active_input_deadline_ns
        _require(type(self) is _StagedDynamicA05Test and type(launch) is _NativeAcceptedLaunch
            and launch is self._launch and self._owner == (os.getpid(), threading.get_ident())
            and not self._consumed and launch._inspection_only is False
            and launch._invocation_bytes == self._invocation_bytes
            and _active_input_deadline_ns() == self._initial_deadline
            and time.perf_counter_ns() < self._initial_deadline, _CODE)
        launch.check_runtime()
        _require(_owned_launcher(launch._config, launch.manifest) == self._selection._path
            and _fixed_data(launch._config, self._telemetry_parent / _SIDECAR) == self._binding_bytes, _CODE)

    def _binding(self, launch):
        _require(launch is self._launch, _CODE)
        return self._selection._binding

    def _record_original_reader(self, launch, query, fact):
        # Only called by the exact accepted query owner after real closure.
        from .input_stage import _active_input_deadline_ns
        _require(type(self) is _StagedDynamicA05Test and launch is self._launch
            and launch._staged_a05_reader is self and self._reader_witness is None
            and not self._consumed and self._owner == (os.getpid(), threading.get_ident())
            and _active_input_deadline_ns() == self._initial_deadline, _CODE)
        recorded = time.perf_counter_ns()
        _require(recorded < self._initial_deadline and query['action'] == 'read_executing'
            and query['native_original_query_version'] == '1.4' and query['run_id'] == launch.run_id
            and query['installation_digest'] == launch.installation_digest
            and query['operation_nonce'] == launch.operation_nonce and query['channel_id'] == launch.channel_id
            and type(fact) is dict and type(fact['wait_result']) is int and fact['wait_result'] == 0
            and fact['worker_exit_established'] is True and type(fact['exit_code']) is int and fact['exit_code'] == 0, _CODE)
        self._reader_witness = canonical_bytes({
            'schema': 'phase.test.staged-a05-original-reader/1', 'reader_query_digest': canonical_digest(query),
            'run_id': query['run_id'], 'intent_digest': query['intent_digest'], 'installation_digest': query['installation_digest'],
            'operation_nonce': query['operation_nonce'], 'channel_id': query['channel_id'],
            'reader_exit_fact': fact, 'owner_finalized': True, 'recorded_ns': recorded,
        })

    def _original_reader_observation(self, context, intent_digest):
        _require(type(self._reader_witness) is bytes, 'ntfs.staged_dynamic_a05_reader_witness_required')
        observed = parse_json_bytes(self._reader_witness, maximum_bytes=16384)
        _require(observed['intent_digest'] == intent_digest and all(
            observed[key] == context[key] for key in ('run_id', 'intent_digest', 'installation_digest', 'operation_nonce')), _CODE)
        return observed

    original_read_complete = _DynamicA05Test.original_read_complete
