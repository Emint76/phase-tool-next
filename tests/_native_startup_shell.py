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
