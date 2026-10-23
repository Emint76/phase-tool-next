"""Pure native parent-response checks shared by dispatch and readonly inspect.
DRAFT source only, no I/O, admission, process ownership or receipt publication.
Matching data is historical correlation, not authentication of its producer.
"""
from __future__ import annotations
import re
from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import NativeIdentity, _require
from .worker import _grant, validate_worker_completion


def _observation(raw: object, grant: dict, locator: str) -> dict:
    """Check a reply from the accepted RO role; data alone is not role auth."""
    _require(type(raw) is dict and set(raw) == {
        'observation_version', 'state', 'native', 'grant', 'locator', 'handles_finalized'},
        'ntfs.observer_response_shape')
    _grant(raw['grant'])
    _require(raw['observation_version'] == '1.0'
        and canonical_bytes(raw['grant']) == canonical_bytes(grant)
        and raw['locator'] == locator and raw['handles_finalized'] is True,
        'ntfs.observer_response_binding_mismatch')
    state, native = raw['state'], raw['native']
    _require(type(state) is dict and set(state) == {'known', 'exists', 'digest', 'length', 'head_token'}
        and state['known'] is True and type(state['exists']) is bool
        and state['head_token'] is None and type(native) is dict
        and type(native.get('exists')) is bool and native['exists'] is state['exists'],
        'ntfs.observer_response_shape')
    if state['exists']:
        _require(set(native) == {'exists', 'native_identity', 'length', 'digest', 'link_count'}
            and type(native['link_count']) is int and native['link_count'] == 1
            and type(state['length']) is int and state['length'] >= 0
            and type(native['length']) is int and native['length'] == state['length'] and native['digest'] == state['digest'],
            'ntfs.observer_response_shape')
        identity = NativeIdentity.parse(native['native_identity'])
        expected = _grant(grant).root_identity
        _require(identity.volume_serial == expected.volume_serial, 'ntfs.observer_volume_mismatch')
        # A larger pre-existing file may truthfully be observed without its hash.
        if state['length'] <= 1024**2:
            _require(type(state['digest']) is str and re.fullmatch(
                r'sha256:[0-9a-f]{64}', state['digest']) is not None, 'ntfs.observer_digest_required')
        else:
            _require(state['digest'] is None, 'ntfs.observer_response_shape')
    else:
        _require(native == {'exists': False, 'native_identity': None}
            and state['digest'] is None and state['length'] is None,
            'ntfs.observer_response_shape')
    return parse_json_bytes(canonical_bytes(raw))


def validate_parent_completion(reply, *, context, grant_data, effect):
    _require(type(reply) is dict and set(reply) == {'parent_execution_version', 'context',
        'completion', 'process_witness', 'owner_finalization', 'post_observation', 'ingress_state'}
        and reply['parent_execution_version'] == '1.0' and reply['context'] == context
        and reply['ingress_state'] == 'consumed', 'ntfs.parent_execution_binding_mismatch')
    completion = reply['completion']
    _require(type(completion) is dict and type(completion.get('pid')) is int,
        'ntfs.worker_completion_binding_mismatch')
    checked = validate_worker_completion(canonical_bytes(completion), context=context,
        grant_data=grant_data, effect=effect, expected_pid=completion['pid'])
    if checked['error'] is not None:
        raise PhaseError('ntfs.effect_outcome_unavailable', details={'worker_error': checked['error']})
    return checked


def validate_parent_finalization(reply, checked, *, grant_data, effect):
    completion = checked
    receipt = checked['effect_receipt']
    witness = reply['process_witness']
    _require(type(witness) is dict and witness.get('process_witness_version') == '1.0'
        and type(witness.get('pid')) is int and witness['pid'] == completion['pid']
        and type(witness.get('wait_result')) is int and witness['wait_result'] == 0
        and witness.get('worker_exit_established') is True
        and type(witness.get('exit_code')) is int and witness['exit_code'] == 0,
        'ntfs.worker_exit_not_established')
    _require(reply['owner_finalization'] == {'worker_stdin': 'closed', 'worker_stdout': 'closed',
        'worker_stderr': 'closed', 'creation_handle': 'closed', 'errors': []},
        'ntfs.worker_finalization_unknown')
    observed = _observation(reply['post_observation'], grant_data,
        effect['target']['relative_locator'])
    _require(receipt['after'] == observed['state'], 'ntfs.worker_observer_mismatch')
    physical = checked['physical_evidence']
    _require(physical['handle_finalization'] == 'closed'
        and type(physical['remaining_handle_count']) is int and physical['remaining_handle_count'] == 0
        and physical['mutex_state'] == 'closed' and physical['mutation_session_state'] == 'sealed'
        and type(physical['finalization_errors']) is list and physical['finalization_errors'] == [],
        'ntfs.worker_finalization_unknown')
    # Parse the worker's claimed native after-state with the SAME strict
    # data validator, then correlate it with a separately executed RO
    # observation. A missing worker after/NativeID never skips this check.
    worker_after = _observation({'observation_version': '1.0', 'state': receipt['after'],
        'native': physical['after'], 'grant': physical['grant'], 'locator': physical['locator'],
        'handles_finalized': True}, grant_data,
        effect['target']['relative_locator'])
    _require(canonical_bytes(worker_after['native']) == canonical_bytes(observed['native']),
        'ntfs.worker_observer_mismatch')
    return observed
