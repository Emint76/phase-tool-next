"""Minimal STATIC selector correlation only; never an accepted installation.

No roots/grants/composition/runtime authority are present. These bytes merely
let existing negative and transport-shell tests reach their intended boundary.
The real native qualification guard remains unmocked and refuses admission.
"""
from phase_tool.canonical import canonical_bytes,digest_bytes

def startup_shell():
    raw=canonical_bytes({'native_read_installation_version':'1.1',
        'registry_snapshot_digest':'sha256:2af8bac33feb42a583a14d6bff7b403de2ab0b63be3a962acc45807634a6ecca',
        'contract':{'id':'file_create.v1'}})
    return raw,digest_bytes(raw)


def legacy_config_bytes(version='1.1'):
    """Canonical generation metadata ONLY; never a complete accepted config."""
    if type(version)is not str or version not in {'1.1','1.2'}:
        raise ValueError('fixed historical fixture generation required')
    return canonical_bytes({'native_launch_version':version})


def legacy_data_launch(*,manifest_bytes,invocation,inspection_only=False):
    """Exact-class static data fixture; runtime remains an explicit boundary.

    No accepted constructor, roots, grant, SDK/process/Native channel is made.
    The real fixed selector/profile guards consume these canonical bytes.
    """
    from unittest.mock import Mock
    from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
    launch=object.__new__(_NativeAcceptedLaunch)
    launch._config_bytes=legacy_config_bytes()
    launch._manifest_bytes=manifest_bytes
    launch._manifest_digest=digest_bytes(manifest_bytes)
    launch._invocation_bytes=canonical_bytes(invocation)
    launch._inspection_only=inspection_only
    launch._experimental_admission_context=None
    launch.check_runtime=Mock()  # Explicit modeled immutable-runtime boundary.
    return launch


def legacy_negative_launch(**fields):
    """Canonical exact-class data shell for existing early-refusal tests only.

    Preserve every original selector/token/request/history and modeled runtime
    check. This never constructs an accepted installation or mocks a guard.
    """
    required={'_inspection_only','check_runtime','invocation','_manifest_bytes',
        'installation_digest','run_id','operation_nonce','channel_id'}
    if not (required <= set(fields) <= required|{'history_manifest_set'}):
        raise AssertionError('fixed negative launch fields required')
    if digest_bytes(fields['_manifest_bytes']) != fields['installation_digest']:
        raise AssertionError('negative manifest digest mismatch')
    invocation=dict(fields['invocation'])
    if set(invocation) not in ({'request'},{'request','run_id','operation_nonce','channel_id'}):
        raise AssertionError('fixed negative request wrapper required')
    invocation.update({key:fields[key] for key in ('run_id','operation_nonce','channel_id')})
    launch=legacy_data_launch(manifest_bytes=fields['_manifest_bytes'],
        invocation=invocation,inspection_only=fields['_inspection_only'])
    launch.check_runtime=fields['check_runtime']
    launch._history_manifest_set=fields.get('history_manifest_set',(None,None))
    return launch
