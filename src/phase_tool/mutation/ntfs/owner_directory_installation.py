"""Fixed ordinary owner-directory selection, all six roles, gate CLOSED.

No resource/generation/profile bytes are published here. A future reviewed
qualified immutable catalogue must fill both literal pins after evidence. The
factory cannot accept a request/env/provider-selected catalogue. Pure metadata
resolution is Windows-safe; Linux authority imports happen only afterward.
"""
from dataclasses import replace
import re

from ...canonical import canonical_bytes
from ...registry import _native_schema_check_pass
from .native import _require
from .owner_directory import (_DirectoryCatalog, _OwnerDirectoryContext, ROLES, _manifest_row,
    owner_directory_configuration, owner_directory_role_for_manifest, validate_owner_directory_history)

_NATIVE_OWNER_DIRECTORY_CATALOG_RESOURCE = 'registries/native-owner-directory-qualified-v1.json'
_NATIVE_OWNER_DIRECTORY_CATALOG_DIGEST = None
_NATIVE_OWNER_DIRECTORY_LEGACY_FILE1_PACKAGE = 'sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a'


def _fixed_owner_directory_catalog():
    _require(type(_NATIVE_OWNER_DIRECTORY_CATALOG_DIGEST) is str
             and re.fullmatch('sha256:[0-9a-f]{64}', _NATIVE_OWNER_DIRECTORY_CATALOG_DIGEST) is not None,
             'ntfs.native_profile_not_qualified')
    from ...installation import _load_native_file_create_registry
    registry = _load_native_file_create_registry(_NATIVE_OWNER_DIRECTORY_CATALOG_RESOURCE,
        _NATIVE_OWNER_DIRECTORY_CATALOG_DIGEST, _NATIVE_OWNER_DIRECTORY_LEGACY_FILE1_PACKAGE)
    return _DirectoryCatalog(registry, _NATIVE_OWNER_DIRECTORY_CATALOG_DIGEST).check()


@_native_schema_check_pass()
def _owner_directory_bindings_with_catalog(*, configuration_bytes, expected_configuration_digest,
        manifest_bytes, expected_manifest_digest, _catalog):
    """Private pure resolver; fixed production factory is its only selector.

    Explicit synthetic catalogue fixtures exercise the identical full resolver
    in component tests. This argument is never on a public/native request API.
    """
    from ...installation import _resolve_native_file_create_read_binding
    _require(type(_catalog) is _DirectoryCatalog, 'ntfs.owner_directory_catalog_required')
    _catalog.check()
    doc = owner_directory_configuration(configuration_bytes, expected_configuration_digest)
    active_role = owner_directory_role_for_manifest(configuration_bytes, expected_configuration_digest,
                                                     manifest_bytes, expected_manifest_digest)
    bindings = []
    for role, body, digest, manifest in map(_manifest_row, doc['manifests'] + doc['predecessors']):
        context = _OwnerDirectoryContext(configuration_bytes, expected_configuration_digest, role, _catalog)
        binding = replace(_resolve_native_file_create_read_binding(manifest_bytes=body,
            expected_manifest_digest=digest, registry=_catalog.registry), _owner_directory_context=context)
        context.check(binding)
        bindings.append(binding)
    active = next(row for row in bindings[:6] if row._owner_directory_context.role == active_role)
    history = validate_owner_directory_history(active, tuple(bindings))
    return active, history


@_native_schema_check_pass()
def _native_owner_directory_bindings(*, configuration_bytes, expected_configuration_digest,
                                     manifest_bytes, expected_manifest_digest):
    # Deliberately first: no channel/authority import or filesystem/evidence I/O
    # before the literal qualified generation has actually been accepted.
    catalog = _fixed_owner_directory_catalog()
    return _owner_directory_bindings_with_catalog(configuration_bytes=configuration_bytes,
        expected_configuration_digest=expected_configuration_digest, manifest_bytes=manifest_bytes,
        expected_manifest_digest=expected_manifest_digest, _catalog=catalog)


def _installation_from_owner_directory_bindings(binding, history, *, run_id, operation_nonce,
                                                channel_id, _inspection_only=False):
    """Same installation/Core/physical roles; never an alternative executor."""
    import sys
    from ...installation import _NativeFileCreateInstallation
    from .owner_directory import require_owner_directory_binding
    _require(sys.platform.startswith('linux'), 'ntfs.original_linux_reader_required')
    _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
    role, manifest = require_owner_directory_binding(binding)
    validate_owner_directory_history(binding, history)
    # These imports are intentionally BELOW all fixed/static qualification.
    from .owner_directory_authorities import _ordinary_authority_types
    from .channel_v2 import LinuxNativeChannelV2
    from .channel_v3 import LinuxNativeChannelV3, LinuxNativeChannelV5
    from .channel_v4 import LinuxNativeChannelV4, LinuxNativeBundleChannel
    from .bundle_recovery_channel import LinuxNativeBundleRecoveryChannel
    authority_type = dict(zip(ROLES, _ordinary_authority_types()))[role]
    channel_types = dict(zip(ROLES, (LinuxNativeChannelV2, LinuxNativeChannelV4, LinuxNativeChannelV3,
                                    LinuxNativeChannelV5, LinuxNativeBundleChannel, LinuxNativeBundleRecoveryChannel)))
    kwargs = {'channel_id': channel_id, '_inspection_only': _inspection_only}
    if role == 'Version1':
        kwargs['_version1'] = True
    channel = channel_types[role](**kwargs)
    profile = binding._owner_directory_context.catalog.profile(role)
    authority = authority_type(binding, profile, canonical_bytes(manifest['root_projections']), channel,
        run_id=run_id, operation_nonce=operation_nonce, _inspection_only=_inspection_only)
    return binding.registry, _NativeFileCreateInstallation(binding, authority, history_bindings=history)


def _native_owner_directory_installation(*, configuration_bytes, expected_configuration_digest,
        manifest_bytes, expected_manifest_digest, run_id, operation_nonce, channel_id, _inspection_only=False):
    binding, history = _native_owner_directory_bindings(configuration_bytes=configuration_bytes,
        expected_configuration_digest=expected_configuration_digest, manifest_bytes=manifest_bytes,
        expected_manifest_digest=expected_manifest_digest)
    return _installation_from_owner_directory_bindings(binding, history, run_id=run_id,
        operation_nonce=operation_nonce, channel_id=channel_id, _inspection_only=_inspection_only)
