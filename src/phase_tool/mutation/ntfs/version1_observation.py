"""Closed read-only version1 observations; no admission or effect executor.

The existing Core lifecycle remains authoritative. Each response is a sampled
read, not a pair snapshot, namespace reservation or all-alias exclusion proof.
This unselected generation preserves the original file-create observer 1.0.
"""
from __future__ import annotations

import re

from ...canonical import canonical_bytes, parse_json_bytes
from ...paths import safe_relative_locator
from .file_create import _observe
from .native import NativeIO, NativeIdentity, _require
from .scoped import NativeRootGrant, NativeScopedTarget


_VERSION1_LIMIT = 16*1024**2


def observe_version1_file(grant: NativeRootGrant, locator: str,
                          *, expected: NativeIdentity | None = None) -> dict:
    """Use real pinned prefix/leaf reads; never treat an access error as absent."""
    _require(type(grant) is NativeRootGrant,'ntfs.invalid_root_grant')
    locator = safe_relative_locator(locator)
    if expected is not None:
        _require(type(expected) is NativeIdentity,'ntfs.invalid_identity')
        NativeIdentity.parse(expected.as_dict())
    io = NativeIO()
    with NativeScopedTarget(io,grant,locator,_allow_missing_ancestors=True) as scope:
        absence = scope.ancestor_absence()
        if absence is None:
            state,proof = _observe(scope,expected=expected,_maximum_bytes=_VERSION1_LIMIT)
            _require(expected is None or state['exists'],'ntfs.expected_file_absent')
        else:
            # An expected object cannot match an absent ancestor. Missing is
            # useful for planning, never a substitute for an expected FileID.
            _require(expected is None,'ntfs.expected_file_absent')
            state = {'known':True,'exists':False,'digest':None,'length':None,'head_token':None}
            proof = {'exists':False,'native_identity':None}
    _require(not io._handles,'ntfs.observer_handle_finalization_unknown')
    response = {'observation_version':'1.1','state':state,'native':proof,
        'grant':grant.as_dict(),'locator':locator,'handles_finalized':True,'ancestor_absence':absence}
    # The same strict data rules apply before sending and after receiving.
    return validate_version1_observation(response,grant.as_dict(),locator)


def validate_version1_observation(raw: object, grant: dict, locator: str) -> dict:
    """Pure correlation/shape checks; this does not authenticate a producer."""
    from .worker import _grant
    accepted = _grant(grant)
    locator = safe_relative_locator(locator)
    _require(type(raw) is dict and set(raw) == {'observation_version','state','native','grant',
        'locator','handles_finalized','ancestor_absence'},'ntfs.version1_observer_response_shape')
    _grant(raw['grant'])
    _require(raw['observation_version'] == '1.1' and raw['handles_finalized'] is True
        and canonical_bytes(raw['grant']) == canonical_bytes(grant) and raw['locator'] == locator,
        'ntfs.version1_observer_binding_mismatch')
    state,proof,absence = raw['state'],raw['native'],raw['ancestor_absence']
    _require(type(state) is dict and set(state) == {'known','exists','digest','length','head_token'}
        and state['known'] is True and type(state['exists']) is bool and state['head_token'] is None
        and type(proof) is dict and type(proof.get('exists')) is bool
        and proof['exists'] is state['exists'],'ntfs.version1_observer_response_shape')
    if state['exists']:
        _require(absence is None and set(proof) == {'exists','native_identity','length','digest','link_count'}
            and type(proof['link_count']) is int and proof['link_count'] == 1
            and type(state['length']) is int and 0 <= state['length'] <= _VERSION1_LIMIT
            and type(proof['length']) is int and proof['length'] == state['length']
            and proof['digest'] == state['digest'] and type(state['digest']) is str
            and re.fullmatch(r'sha256:[0-9a-f]{64}',state['digest']) is not None,
            'ntfs.version1_observer_response_shape')
        identity = NativeIdentity.parse(proof['native_identity'])
        _require(identity.volume_serial == accepted.root_identity.volume_serial,
            'ntfs.observer_volume_mismatch')
    else:
        _require(proof == {'exists':False,'native_identity':None}
            and state['digest'] is None and state['length'] is None,
            'ntfs.version1_observer_response_shape')
        if absence is not None:
            _require(type(absence) is dict and set(absence) == {'existing_relative_components',
                'missing_relative_components','existing_parent_identity'},
                'ntfs.version1_ancestor_absence_shape')
            prefix,tail = absence['existing_relative_components'],absence['missing_relative_components']
            _require(type(prefix) is list and type(tail) is list and len(tail) >= 2
                and prefix+tail == locator.split('/'),'ntfs.version1_ancestor_absence_shape')
            identity = NativeIdentity.parse(absence['existing_parent_identity'])
            _require(identity.volume_serial == accepted.root_identity.volume_serial
                and (bool(prefix) or identity == accepted.root_identity),
                'ntfs.version1_ancestor_absence_identity_mismatch')
    return parse_json_bytes(canonical_bytes(raw))
