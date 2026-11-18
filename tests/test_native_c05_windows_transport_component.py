"""Portable C05 Raw-sink and ordinary-frontdoor regressions."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from phase_tool import evidence
from phase_tool.canonical import canonical_bytes
from phase_tool.mutation.ntfs import c05_windows_transport as transport
from phase_tool.mutation.ntfs import inspection_mcp, owner_directory_fixture


@pytest.mark.parametrize('mode', ('known', 'ancestor_close_failed', 'deadline_after_close'))
def test_c05_completion_follows_all_raw_readback_parent_close_and_deadline(monkeypatch, mode):
    root = Path('modeled-c05-capture')
    raw = {name: name.encode() for name in transport.MEMBERS}
    ids = {name: format(index, '032x') for index, name in enumerate(raw, 1)}
    stored, readbacks, closes, signals = {}, [], [], []
    deadline = 1000
    now = 100

    class NativeReadback:
        def entries(self, parent, maximum):
            assert parent is self and maximum == 3
            return {name: {'directory': False, 'file_id': ids[name]} for name in stored}

        @contextmanager
        def _open(self, name, *, parent, directory, sharing, _input_name):
            assert parent is self and not directory and sharing == 1 and _input_name is True
            yield name

        def input_state(self, name):
            return {'links': 1, 'length': len(stored[name]), 'native_identity': {'file_id': ids[name]}}

        def read_chunks(self, name, cap):
            assert cap == len(stored[name])
            readbacks.append(name)
            yield stored[name]

    native = NativeReadback()
    volume, identity = {'model': 'volume'}, {'model': 'identity'}

    @contextmanager
    def opened(parent, *, expected_volume, expected_identity):
        nonlocal now
        assert parent == root and expected_volume == volume and expected_identity == identity
        yield native, native, volume, identity, lambda: None
        closes.append('attempt')
        if mode == 'ancestor_close_failed':
            raise OSError('injected final ancestor close error')
        closes.append('returned')
        if mode == 'deadline_after_close':
            now = deadline

    def write(path, data, *, native, parent, identity):
        assert type(native) is NativeReadback and parent is native and identity == {'model': 'identity'}
        assert path.parent == root and path.name not in stored
        stored[path.name] = data

    def signal(owner):
        assert owner is capture and closes == ['attempt', 'returned'] and now < deadline
        signals.append(owner)

    monkeypatch.setattr(transport, '_opened_parent', opened)
    monkeypatch.setattr(transport, '_parent', lambda slot: root)
    monkeypatch.setattr(transport, '_signal_c05_raw_completion', signal)
    monkeypatch.setattr(transport, 'time', SimpleNamespace(perf_counter_ns=lambda: now))
    monkeypatch.setattr(evidence, '_write_c05_fixture_raw_member', write)
    policy = {'volume': volume, 'slots': [{'parent_full128': identity}]}
    capture = transport._C05WindowsTransport(transport._FIXED_FIXTURE_SELECTION, 'cli', b'config', b'manifest',
        object(), policy, 'sha256:'+'1'*64)
    capture._slot, capture._deadline = 0, deadline
    capture._owner = (transport.os.getpid(), transport.threading.get_ident())
    capture._pending = raw

    capture.flush()
    capture.flush()
    assert stored == raw and readbacks == list(raw)
    assert closes.count('attempt') == 1
    assert signals == ([capture] if mode == 'known' else [])


@pytest.mark.parametrize('startup_version,fixture_id', [('4.0', None), ('3.0', 'unrelated-owner3')])
def test_ordinary_or_other_fixture_startup_never_selects_c05_raw_capture(monkeypatch, startup_version, fixture_id):
    class FixtureAdmission:
        raw = b'modeled unselected admission'

    def forbidden(*args, **kwargs):
        pytest.fail('unselected startup used the C05 artifact or signal route')

    def document(raw):
        assert fixture_id is not None and raw == FixtureAdmission.raw
        return {'fixture_uuid': fixture_id}

    monkeypatch.setattr(transport, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(owner_directory_fixture, '_kinds', lambda: {'File1': FixtureAdmission})
    monkeypatch.setattr(owner_directory_fixture, 'fixture_document', document)
    monkeypatch.setattr(evidence, '_read_qualification_catalog_chunk', forbidden)
    monkeypatch.setattr(transport, '_signal_c05_raw_completion', forbidden)
    assert transport._load_c05_windows_transport({'native_fixed_startup_version': startup_version},
        b'unparsed-config', b'unparsed-manifest', FixtureAdmission(), 'input-mcp') is None


def test_ordinary_input_mcp_uses_stock_file_tool_without_c05_owner(monkeypatch):
    tools, calls, servers = {}, [], []

    class Server:
        def __init__(self, name):
            servers.append(name)

        def tool(self, *, name):
            return lambda call: tools.setdefault(name, call)

        def run(self, *, transport):
            assert transport == 'stdio'

    class CallOwner:
        _unavailable = False

        def __init__(self, **startup):
            assert set(startup) == {'manifest_bytes'}

        def publish_staged_file(self, **kwargs):
            calls.append(kwargs)
            return {'stock': True}

    monkeypatch.setattr(inspection_mcp, 'FastMCP', Server)
    monkeypatch.setattr(inspection_mcp, '_closed_arguments', lambda server: server)
    monkeypatch.setattr(inspection_mcp, '_InspectionMCPCallOwner', CallOwner)
    manifest = canonical_bytes({'contract': {'id': 'file_create.v1'}})
    assert inspection_mcp.run_native_input_mcp(manifest_bytes=manifest) == 0
    assert servers == ['phase-native-input']
    assert tuple(tools) == ('phase_publish_input', 'phase_publish_file', 'phase_inspect')
    request = {'run_id': 'ordinary-run', 'input_scope': 'ordinary-input', 'source_locator': 'source.bin',
        'target_locator': 'target.bin', 'request_id': 'ordinary-request', 'publication_version': '1.0',
        'expected_digest': 'sha256:'+'2'*64, 'root_binding': 'phase_result_root'}
    assert tools['phase_publish_file'](**request) == {'stock': True}
    assert calls == [request]
