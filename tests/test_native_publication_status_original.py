"""Status reads over the fixed Original boundary, with no Worker authority."""

import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from phase_tool import installation, publication_status, streaming
from phase_tool.canonical import canonical_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import original_endpoint
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch


RUN = 'native-status-test'
CONTRACT = {'id': 'file_create.v1', 'version': '1.0.0', 'package_digest': 'sha256:' + 'b' * 64}
IDENTITY = {'device': 1, 'inode': 2}
REGISTRY = 'sha256:' + 'a' * 64


def original_query(inspection_only=True):
    query = {
        'native_original_query_version': '1.0',
        'action': 'publication_status',
        'run_id': RUN,
        'intent_digest': None,
        'operation_nonce': '1' * 32,
        'installation_digest': 'sha256:' + 'c' * 64,
        'channel_id': '2' * 32,
        'wait_seconds': 0,
    }
    launch = object.__new__(_NativeAcceptedLaunch)
    launch._inspection_only = inspection_only
    launch._manifest_digest = query['installation_digest']
    launch._manifest_bytes = canonical_bytes({'contract': CONTRACT, 'evidence_identity': IDENTITY})
    launch._invocation_bytes = canonical_bytes({
        'run_id': RUN,
        'operation_nonce': query['operation_nonce'],
        'channel_id': query['channel_id'],
        'request': query,
    })
    return launch, query


@pytest.fixture
def bound_original(monkeypatch, tmp_path):
    registry = SimpleNamespace(digest=REGISTRY)
    binding = SimpleNamespace(registry=registry, check_evidence_root=Mock(return_value=tmp_path))
    select = Mock(return_value=binding)
    monkeypatch.setattr(installation, '_native_read_binding_for_launch', select)
    monkeypatch.setattr(_NativeAcceptedLaunch, 'check_runtime', lambda self: None)
    monkeypatch.setattr(original_endpoint, 'sys', SimpleNamespace(platform='linux'))
    os_api = SimpleNamespace(ST_RDONLY=1, statvfs=Mock(return_value=SimpleNamespace(f_flag=1)))
    monkeypatch.setattr(original_endpoint, 'os', os_api)
    # The mounted evidence records and their canonical digests are real files.
    # The small synthetic bodies isolate the reducer from the contract schemas.
    monkeypatch.setattr(publication_status, 'validate_intent', Mock())
    monkeypatch.setattr(publication_status, 'validate_receipt', Mock())
    if os.name == 'nt':
        # The endpoint runs only on Linux. Model Linux's comparable timestamps
        # when Windows descriptor and pathname stat disagree about ctime.
        fingerprint = streaming.fingerprint
        monkeypatch.setattr(streaming, 'fingerprint', lambda info: fingerprint(info)[:-1])
    return binding, select, os_api


def test_original_reuses_historical_status_for_every_saved_cut(bound_original, tmp_path):
    launch, query = original_query()
    run = tmp_path / '.phase' / 'runs' / RUN

    def status(stage):
        reply = original_endpoint.native_original_query(launch, query)
        assert reply['query'] == query and reply['required_evidence_reads_finalized'] is True
        value = reply['value']
        assert value['stage'] == stage and value['query_succeeded'] is True
        assert value['target_verified'] is False and value['verification_performed'] is False
        assert value['process_liveness'] == 'not_checked'
        return value

    status('not_observed')
    run.mkdir(parents=True)
    status('preparing')
    intent = {
        'phase_intent_version': '1.2',
        'run_id': RUN,
        'contract': CONTRACT,
        'registry_snapshot_digest': REGISTRY,
        'native_binding': {'evidence_identity': IDENTITY},
        'idempotency': {'key': 'retained-request'},
    }
    (run / 'intent.json').write_bytes(canonical_bytes(intent))
    digest = profile_digest('intent', intent)
    assert status('intent_recorded')['intent_digest'] == digest
    (run / 'attachments').mkdir()
    (run / 'attachments' / 'effect-receipts.json').write_bytes(canonical_bytes([]))
    status('effects_recorded')
    receipt = {
        'contract': CONTRACT,
        'run_id': RUN,
        'terminal_status': 'succeeded_verified',
        'mutation_attempted': True,
        'evidence': {'intent_digest': digest},
    }
    (run / 'receipt.json').write_bytes(canonical_bytes(receipt))
    actual = status('receipt_recorded')
    assert actual['receipt_digest'] == profile_digest('receipt', receipt)
    assert actual['recorded_terminal_status'] == 'succeeded_verified'


@pytest.mark.parametrize('change', [
    {'wait_seconds': True},
    {'wait_seconds': 61},
    {'run_id': 'another-run'},
    {'operation_nonce': 'f' * 32},
    {'intent_digest': 'sha256:' + 'd' * 64},
    {'native_original_query_version': '1.1'},
    {'evidence_root': '/tmp'},
])
def test_original_rejects_unbound_queries_before_root_selection(bound_original, change):
    _, select, _ = bound_original
    launch, query = original_query()
    with pytest.raises(PhaseError, match='ntfs.original_query_binding_mismatch'):
        original_endpoint.native_original_query(launch, query | change)
    select.assert_not_called()


def test_status_role_cannot_read_worker_authority(bound_original):
    _, select, _ = bound_original
    launch, query = original_query()
    with pytest.raises(PhaseError, match='ntfs.inspection_only_operation_forbidden'):
        original_endpoint.native_original_query(launch, query | {'action': 'read_executing'})
    select.assert_not_called()

    launch, query = original_query(inspection_only=False)
    with pytest.raises(PhaseError, match='ntfs.original_query_binding_mismatch'):
        original_endpoint.native_original_query(launch, query)
    select.assert_not_called()


def test_other_contract_receipt_returns_no_history(bound_original, tmp_path):
    launch, query = original_query()
    run = tmp_path / '.phase' / 'runs' / RUN
    run.mkdir(parents=True)
    (run / 'receipt.json').write_bytes(canonical_bytes({'contract': CONTRACT | {'id': 'file_create.v2'}}))
    actual = original_endpoint.native_original_query(launch, query)['value']
    assert actual['query_succeeded'] is False and actual['error'] == 'publication.status_contract_mismatch'
    assert actual['stage'] == 'not_observed' and actual['receipt_digest'] is None
    publication_status.validate_receipt.assert_not_called()


def test_lost_root_or_rw_mount_cannot_close_original_read(bound_original, tmp_path):
    binding, _, os_api = bound_original
    launch, query = original_query()
    binding.check_evidence_root.side_effect = [tmp_path, PhaseError('ntfs.original_evidence_identity_mismatch')]
    with pytest.raises(PhaseError, match='ntfs.original_evidence_identity_mismatch'):
        original_endpoint.native_original_query(launch, query)

    binding.check_evidence_root.side_effect = None
    os_api.statvfs.return_value = SimpleNamespace(f_flag=0)
    with pytest.raises(PhaseError, match='ntfs.original_readonly_contour_required'):
        original_endpoint.native_original_query(launch, query)
