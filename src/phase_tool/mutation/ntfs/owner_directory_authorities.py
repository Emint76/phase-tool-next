"""Six ordinary qualified roles over the existing native physical lifecycles.

Linux-only factory import after fixed catalogue qualification. This module adds
no Core, worker, store, queue, verifier, journal, version or recovery mechanism.
Historical provider files and their registry-bound bytes stay unchanged.
"""
import os
from pathlib import PurePosixPath
import re
import threading

from ...canonical import canonical_bytes, parse_json_bytes
from ...evidence import validate_run_id
from ..guarantees import GuaranteeProfileBinding, verify_guarantee_coverage
from .authority import _NativeFileCreateAuthority
from .channel_v4 import LinuxNativeBundleChannel
from .bundle_recovery_channel import LinuxNativeBundleRecoveryChannel
from .experimental_version2_authority_v2 import _ExperimentalVersion2AuthorityV2
from .experimental_bundle1_authority import _ExperimentalBundle1Authority
from .experimental_bundle2_authority_v3 import _ExperimentalBundle2AuthorityV3
from .native import _require
from .owner_directory import READ_VERSIONS, require_owner_directory_binding
from .owner_semantic_contracts import semantic_owner_contract
from .worker import _grant


class _OrdinaryDirectoryAuthority:
    """Only static profile/contract/idempotency admission differs from fixture3."""
    _directory_role = None

    def __init__(self, read_binding, *args, **kwargs):
        require_owner_directory_binding(read_binding, self._directory_role)
        super().__init__(read_binding, *args, **kwargs)

    def _admitted_profile(self):
        role, manifest = require_owner_directory_binding(self.read_binding, self._directory_role)
        context = self.read_binding._owner_directory_context
        _require(context.catalog.profile(role) == self.profile and manifest == self._manifest,
                 'guarantee.profile_implementation_mismatch')
        return self.registry.resolve_guarantee_profile(self.profile.as_dict())

    def require_contract(self, contract):
        self._usable()
        role, manifest = require_owner_directory_binding(self.read_binding, self._directory_role)
        operation = contract.document['operation']
        version = role in ('Version1', 'Version2')
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'],
                  'package_digest': contract.package_digest} == manifest['contract'] == semantic_owner_contract(role)
                 and operation['intent'] == ('publish_new_version' if version else 'create')
                 and operation['maximum_effects'] == 1
                 and operation['allowed_effects'] == (['publish_new_version'] if version else ['exclusive_create'])
                 and {k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')} == manifest['mechanism']
                 and not operation.get('effect_mechanisms'), 'ntfs.original_single_effect_required')
        return verify_guarantee_coverage(operation['required_guarantees'], [operation['mechanism']],
                                         self.profile, self.registry)

    def idempotency(self, contract, candidate, frozen, roots):
        # Ordinary owner-once authorization does not capture or approve each
        # file. The SAME generic planner/Core computes scope and semantic input
        # identity; all existing unresolved/same-key/manifest checks still run.
        return _NativeFileCreateAuthority.idempotency(self, contract, candidate, frozen, roots)


class _OwnerDirectoryFile1Authority(_OrdinaryDirectoryAuthority, _NativeFileCreateAuthority):
    _directory_role = 'File1'


class _OwnerDirectoryFile2Authority(_OrdinaryDirectoryAuthority, _NativeFileCreateAuthority):
    _directory_role = 'File2'


class _OwnerDirectoryVersion1Authority(_OrdinaryDirectoryAuthority, _NativeFileCreateAuthority):
    _directory_role = 'Version1'


class _OwnerDirectoryVersion2Authority(_OrdinaryDirectoryAuthority, _ExperimentalVersion2AuthorityV2):
    _directory_role = 'Version2'


def _initialize_bundle(authority, read_binding, profile, root_projections, channel, *, role,
                       run_id, operation_nonce, _inspection_only):
    """Exact existing Bundle constructor state, with ordinary static admission.

    Physical methods, checkpoint capture, late failure, seal and B2 recovery
    remain inherited. No fake experimental admission is attached or consulted.
    """
    _require(not getattr(authority, '_initialization_attempted', False), 'ntfs.native_role_initialization_consumed')
    authority._initialization_attempted = True
    require_owner_directory_binding(read_binding, role)
    _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
    authority._inspection_only = _inspection_only
    from ...installation import _NativeFileCreateReadBinding
    channel_type = LinuxNativeBundleChannel if role == 'Bundle1' else LinuxNativeBundleRecoveryChannel
    _require(type(read_binding) is _NativeFileCreateReadBinding and type(profile) is GuaranteeProfileBinding
             and type(channel) is channel_type, 'ntfs.closed_native_installation_required')
    _require(channel._inspection_only is _inspection_only, 'ntfs.fixed_role_mismatch')
    authority.read_binding, authority.profile, authority.channel = read_binding, profile, channel
    authority._manifest = parse_json_bytes(read_binding.manifest_bytes)
    _require(authority._manifest['native_read_installation_version'] == READ_VERSIONS[role]
             and authority._manifest['contract'] == semantic_owner_contract(role), 'ntfs.fixed_role_mismatch')
    authority._version1, authority._file2, authority._bundle = False, False, True
    validate_run_id(run_id)
    authority._run_id = run_id
    _require(type(operation_nonce) is str and re.fullmatch('[0-9a-f]{32}', operation_nonce) is not None,
             'ntfs.worker_nonce_shape')
    authority._operation_nonce = operation_nonce
    authority._finish_bytes = None
    authority._no_dispatch_safety_established = False
    authority._server_ingress_sealed = False
    authority._owner = os.getpid(), threading.get_ident()
    authority._sealed = False
    authority._seal_attempted = False
    authority._channel_sealed = False
    authority._response_bytes = None
    authority._failure_bytes = None
    authority._dispatch_attempted = False
    authority._parent_safety_established = False
    authority._observations = {}
    authority._version1_post_attempted = False
    projections = parse_json_bytes(root_projections)
    _require(type(root_projections) is bytes and canonical_bytes(projections) == root_projections
             and type(projections) is dict, 'ntfs.installed_root_projections_required')
    grants = [_grant(row) for row in authority._manifest['root_grants']]
    _require(len(grants) == 1 and set(projections) == {grants[0].binding}, 'ntfs.installed_root_projections_required')
    for value in projections.values():
        _require(type(value) is str and PurePosixPath(value).is_absolute() and value != '/'
                 and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts,
                 'ntfs.installed_root_projections_required')
    authority._projections_bytes = root_projections
    authority._grant_bytes = canonical_bytes(grants[0].as_dict())
    authority._admitted_profile()


class _OwnerDirectoryBundle1Authority(_OrdinaryDirectoryAuthority, _ExperimentalBundle1Authority):
    _directory_role = 'Bundle1'

    def __init__(self, read_binding, profile, root_projections, channel, *, run_id, operation_nonce,
                 _inspection_only=False):
        _initialize_bundle(self, read_binding, profile, root_projections, channel, role='Bundle1',
                           run_id=run_id, operation_nonce=operation_nonce, _inspection_only=_inspection_only)


class _OwnerDirectoryBundle2Authority(_OrdinaryDirectoryAuthority, _ExperimentalBundle2AuthorityV3):
    _directory_role = 'Bundle2'

    def __init__(self, read_binding, profile, root_projections, channel, *, run_id, operation_nonce,
                 _inspection_only=False):
        _initialize_bundle(self, read_binding, profile, root_projections, channel, role='Bundle2',
                           run_id=run_id, operation_nonce=operation_nonce, _inspection_only=_inspection_only)


def _ordinary_authority_types():
    return (_OwnerDirectoryFile1Authority, _OwnerDirectoryFile2Authority, _OwnerDirectoryVersion1Authority,
            _OwnerDirectoryVersion2Authority, _OwnerDirectoryBundle1Authority, _OwnerDirectoryBundle2Authority)
