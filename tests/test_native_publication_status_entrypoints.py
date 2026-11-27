"""Check installed status dispatch and the closed historical delivery result."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap, entrypoint, inspection_mcp
from phase_tool.mutation.ntfs import process_witness
from phase_tool.publication_status import PublicationStatus


RUN = 'historical-run'
REQUEST = {'operation': 'publication_status', 'wait_seconds': 17}


def accepted(inspection_only=True):
    launch = object.__new__(bootstrap._NativeAcceptedLaunch)
    launch._inspection_only = inspection_only
    launch._core_spawn_attempted = False
    launch._manifest_digest = 'sha256:' + 'a' * 64
    launch._invocation_bytes = canonical_bytes({'run_id': RUN, 'channel_id': 'b' * 32,
        'operation_nonce': 'c' * 32, 'request': REQUEST})
    launch.check_runtime = Mock()
    return launch


def test_status_is_only_an_original_query():
    launch = accepted()
    query = bootstrap._original_query_request(launch, 'publication_status', None)
    assert query == {'native_original_query_version': '1.0', 'action': 'publication_status',
        'run_id': RUN, 'intent_digest': None, 'wait_seconds': 17, 'channel_id': 'b' * 32,
        'operation_nonce': 'c' * 32, 'installation_digest': 'sha256:' + 'a' * 64}
    for method in (launch.spawn_input_stage, launch.spawn_core, launch.spawn_worker, launch.spawn_inspection):
        with pytest.raises(PhaseError):
            method()
    with pytest.raises(PhaseError, match='inspection_only_operation_forbidden'):
        launch._query_original('read_executing', 'sha256:' + 'd' * 64)
    with pytest.raises(PhaseError, match='inspection_only_operation_forbidden'):
        accepted(False)._query_original('publication_status', None)


def test_parent_correlates_full_metadata_and_rejects_partial_or_foreign_result():
    launch = accepted()
    payload = PublicationStatus(run_id=RUN, stage='receipt_recorded',
        receipt_digest='sha256:' + 'd' * 64).model_dump()
    launch._query_original = Mock(return_value=payload)
    delivery = entrypoint.run_native_parent(launch)
    assert delivery == {'protocol': 'phase.native.command', 'version': '1.0', 'channel_id': 'b' * 32,
        'run_id': RUN, 'result': payload, 'exit_code': 0}
    launch._query_original.assert_called_once_with('publication_status', None)
    for invalid in ({'run_id': RUN}, payload | {'run_id': 'wrong-run'}):
        launch._query_original.return_value = invalid
        with pytest.raises(PhaseError, match='parent_command_binding_mismatch'):
            entrypoint.run_native_parent(launch)


def test_long_status_wait_uses_bound_first_byte_deadline_and_closes(monkeypatch):
    launch = accepted()
    launch._config_bytes = canonical_bytes({'native_launch_version': '4.0'})
    launch._staged_a05_reader = None
    launch._original_query_attempted = False
    request = bootstrap._original_query_request(launch, 'publication_status', None)
    value = PublicationStatus(run_id=RUN).model_dump()
    transport = Mock()
    transport._receive_inspection_frame.return_value = canonical_bytes({
        'query': request, 'value': value, 'required_evidence_reads_finalized': True}), {}
    launch._windows_required = Mock()
    launch._linux_command = Mock(return_value=['fixed-docker', 'original'])
    launch._spawn = Mock(return_value=object())
    launch._pipe = Mock(return_value=transport)
    launch._finalize_exited = Mock()
    witness = Mock()
    witness.wait_for_exit.return_value = {'worker_exit_established': True, 'exit_code': 0}
    monkeypatch.setattr(process_witness, 'WindowsProcessWitness', Mock(return_value=witness))
    start = bootstrap.time.perf_counter_ns()
    assert launch._query_original('publication_status', None) == value
    cutoff, = transport._bind_qualification_exchange_deadline.call_args.args
    assert cutoff - start >= 47 * 10**9
    transport._receive_inspection_frame.assert_called_once_with(cutoff, maximum_bytes=8192)
    transport._expect_eof.assert_called_once_with(cutoff)
    transport.receive_frame.assert_not_called()
    launch._finalize_exited.assert_called_once_with(launch._spawn.return_value, transport)


def test_original_status_contour_does_not_query_core(monkeypatch):
    launch = accepted()
    core, reader = 'a' * 64, 'b' * 64
    image = 'sha256:' + 'c' * 64
    row = {'id': reader, 'image': image, 'user': '10001:10001', 'readonly_rootfs': True,
           'cap_drop': ['ALL'], 'security_options': ['no-new-privileges'], 'network_mode': 'none',
           'mounts': [{'Destination': '/qualification/evidence', 'RW': False}],
           'pids_limit': 128, 'memory': 2 * 1024**3, 'nano_cpus': 2 * 10**9, 'running': True}
    launch._config_bytes = canonical_bytes({'core_container_id': core, 'reader_container_id': reader,
        'image_digest': image, 'docker_executable': 'fixed-docker',
        'expected_linux_contours': {'original': row, 'core': row | {'id': core}}})
    launch._linux_contours_checked = False
    observe = Mock(return_value=SimpleNamespace(stdout=canonical_bytes(row)))
    monkeypatch.setattr(bootstrap.subprocess, 'CREATE_NO_WINDOW', 0, raising=False)
    monkeypatch.setattr(bootstrap.subprocess, 'run', observe)
    launch._check_linux_contours(_original_only=True)
    command, = observe.call_args.args
    assert command[-1] == reader and core not in command and observe.call_count == 1


def test_mcp_exposes_strict_status_only_for_new_fixed_startup():
    kwargs = {'expected_config_digest': None, 'manifest_bytes': b'', 'expected_manifest_digest': None}
    before = inspection_mcp._inspection_server(config_bytes=canonical_bytes({'native_launch_version': '2.0'}), **kwargs)
    assert [tool.name for tool in before._tool_manager.list_tools()] == ['phase_inspect']
    for version in ('3.0', '4.0'):
        current = inspection_mcp._inspection_server(config_bytes=canonical_bytes({'native_launch_version': version}), **kwargs)
        inspect, status = current._tool_manager.list_tools()
        assert (inspect.name, status.name) == ('phase_inspect', 'phase_publication_status')
        assert set(status.parameters['properties']) == {'run_id', 'wait_seconds'}
        assert status.parameters['additionalProperties'] is False
        assert status.parameters['properties']['wait_seconds']['maximum'] == 60
