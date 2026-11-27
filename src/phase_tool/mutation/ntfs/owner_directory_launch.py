"""Fixed ordinary launch data composition; no authority, I/O or activation flag."""
from __future__ import annotations
import base64, re
from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from .native import _require

_FIELDS = {'native_launch_version','phase_wheel','phase_wheel_digest',
    'dependency_file_digests','windows_launcher','linux_launcher','docker_executable',
    'core_container_id','reader_container_id','image_digest','linux_python',
    'expected_linux_contours','artifact_graph','owner_directory_configuration_base64',
    'owner_directory_configuration_digest'}
_COLD_PUBLICATION_FIELD = 'qualification_cold_publication_seconds'


def _qualification_cold_publication_seconds(config):
    if _COLD_PUBLICATION_FIELD not in config:
        return None
    seconds = config[_COLD_PUBLICATION_FIELD]
    _require(config.get('native_launch_version') in {'3.0', '4.0'}
        and type(seconds) is int and seconds == 900, 'ntfs.owner_directory_launch_shape')
    return seconds


def _owner_configuration_from_launch_config(config):
    """Decode installation-owned canonical bytes, never operation arguments."""
    _require(type(config) is dict and set(config) in (_FIELDS, _FIELDS | {_COLD_PUBLICATION_FIELD})
        and config['native_launch_version'] == '4.0'
        and len(canonical_bytes(config)) <= 2*1024**2,
        'ntfs.owner_directory_launch_shape')
    _qualification_cold_publication_seconds(config)
    encoded = config['owner_directory_configuration_base64']
    expected = config['owner_directory_configuration_digest']
    _require(type(encoded) is str and 0 < len(encoded) <= 2*1024**2
        and type(expected) is str and re.fullmatch('sha256:[0-9a-f]{64}', expected) is not None,
        'ntfs.owner_directory_configuration_binding')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as error:
        from ...errors import PhaseError
        raise PhaseError('ntfs.owner_directory_configuration_binding') from error
    _require(0 < len(raw) <= 2*1024**2 and base64.b64encode(raw).decode('ascii') == encoded
        and digest_bytes(raw) == expected, 'ntfs.owner_directory_configuration_binding')
    return raw, expected


def _owner_directory_launch_binding(config, manifest_bytes, expected_manifest_digest):
    """Same read binding; fixed catalogue must admit all six before any channel."""
    from .owner_directory_installation import _native_owner_directory_bindings
    raw, expected = _owner_configuration_from_launch_config(config)
    from .owner_directory import owner_directory_configuration
    document=owner_directory_configuration(raw,expected)
    _require(document['phase_wheel_digest']==config['phase_wheel_digest'],
        'ntfs.owner_directory_wheel_binding_mismatch')
    return _native_owner_directory_bindings(configuration_bytes=raw,
        expected_configuration_digest=expected, manifest_bytes=manifest_bytes,
        expected_manifest_digest=expected_manifest_digest)


def _require_semantic_cold_publication_fixture(config, admission):
    """Use only the existing six exact semantic test admissions."""
    from .experimental_history_set import _mixed_history_contexts
    from .owner_semantic_fixture import semantic_fixture_document
    _require(config.get('native_launch_version') == '3.0'
        and _qualification_cold_publication_seconds(config) == 900
        and type(admission) in _mixed_history_contexts(), 'ntfs.owner_fixture_startup_required')
    fixture = semantic_fixture_document(admission.raw)
    _require('c02_current_root_alias' not in fixture
        and fixture['wheel_digest'] == config.get('phase_wheel_digest'),
        'ntfs.owner_fixture_scope')


def _accepted_cold_publication_seconds(*, config_bytes, expected_config_digest,
        manifest_bytes, expected_manifest_digest, _experimental_admission_context=None):
    """Recognize the optional policy only in an actual fixed launch binding."""
    if not config_bytes:
        return None
    config = parse_json_bytes(config_bytes, maximum_bytes=2*1024**2)
    _require(type(config) is dict, 'ntfs.accepted_launch_shape')
    seconds = _qualification_cold_publication_seconds(config)
    if seconds is not None:
        _require(canonical_bytes(config) == config_bytes
            and digest_bytes(config_bytes) == expected_config_digest, 'ntfs.accepted_launch_shape')
        if config['native_launch_version'] == '4.0':
            _require(_experimental_admission_context is None,'ntfs.owner_directory_context_required')
            _owner_directory_launch_binding(config, manifest_bytes, expected_manifest_digest)
        else:
            from .bootstrap import _accepted_launch_history
            from ...installation import _native_experimental_read_binding, _resolve_native_history_bindings
            admission = _experimental_admission_context
            _require_semantic_cold_publication_fixture(config, admission)
            history = _accepted_launch_history(config, manifest_bytes, expected_manifest_digest)
            binding = _native_experimental_read_binding(manifest_bytes=manifest_bytes,
                expected_manifest_digest=expected_manifest_digest, admission=admission)
            _resolve_native_history_bindings(binding, *history)
    return seconds


def _owner_directory_installation_arguments(launch):
    """Carry only the exact accepted context into the existing Core factory."""
    from .bootstrap import _NativeAcceptedLaunch
    _require(type(launch) is _NativeAcceptedLaunch, 'ntfs.accepted_launch_binding_required')
    if launch._config.get('native_launch_version') != '4.0':
        _require(getattr(launch, '_owner_directory_context', None) is None,
            'ntfs.owner_directory_context_required')
        return {}
    _require(getattr(launch, '_experimental_admission_context', None) is None,
        'ntfs.owner_directory_context_required')
    from .owner_directory import _OwnerDirectoryContext
    context = getattr(launch, '_owner_directory_context', None)
    _require(type(context) is _OwnerDirectoryContext, 'ntfs.owner_directory_context_required')
    binding, _ = _owner_directory_launch_binding(launch._config,
        launch._manifest_bytes, launch.installation_digest)
    from .owner_directory import owner_directory_context_identity
    _require(owner_directory_context_identity(binding._owner_directory_context) == owner_directory_context_identity(context),
        'ntfs.owner_directory_context_required')
    return {'_owner_directory_context': binding._owner_directory_context}


def _require_owner_directory_recovery_startup(config, manifest_bytes, expected_manifest_digest):
    """The same fully qualified fixed Bundle2 binding owns recovery exposure."""
    from .owner_directory import require_owner_directory_binding
    binding,_=_owner_directory_launch_binding(config,manifest_bytes,expected_manifest_digest)
    role,_=require_owner_directory_binding(binding)
    _require(role=='Bundle2','ntfs.owner_directory_recovery_role_required')
