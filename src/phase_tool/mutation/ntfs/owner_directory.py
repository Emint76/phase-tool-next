"""Ordinary immutable owner-directory data and static reader correlation.

This is not experimental admission. It has no per-file grants, attempts, run
prefix, candidate/input hash or test authorization. The fixed installation
factory must first select a separately qualified code-owned catalogue. These
pure data checks do not authenticate a launcher, inspect NTFS or issue GO.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
import re
from uuid import UUID

from ...canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...registry import RegistrySnapshot
from ..guarantees import GuaranteeProfileBinding, verify_guarantee_coverage
from .native import _require
from .owner_semantic_contracts import semantic_owner_contract

ROLES = ('File1', 'File2', 'Version1', 'Version2', 'Bundle1', 'Bundle2')
READ_VERSIONS = dict(zip(ROLES, ('1.1', '1.3', '1.2', '1.5', '1.6', '1.9')))
ROOT_BINDINGS = dict(zip(ROLES, ('phase_result_root', 'phase_result_root',
                                'fixture_result_root', 'current_root',
                                'phase_result_root', 'phase_result_root')))
MAX_CONFIGURATION_BYTES = 2 * 1024**2
MAX_PREDECESSORS = 32
PROFILE_IDS = {role: 'phase.native.ntfs.directory.' + role.lower() + '.authority.v1' for role in ROLES}
PROFILE_ARTIFACT = 'phase_tool/mutation/ntfs/owner_directory_authorities.py'
_CONFIGURATION_KEYS = {'owner_directory_configuration_version', 'owner_scope_id', 'core', 'compositions', 'phase_wheel_digest',
    'root_grants', 'windows_roots', 'evidence_root', 'evidence_identity', 'preparation_root',
    'preparation_identity', 'root_projections', 'manifests', 'predecessors'}
_SCOPE_KEYS = ('owner_scope_id', 'core', 'root_grants', 'windows_roots', 'evidence_root',
               'evidence_identity', 'preparation_root', 'preparation_identity', 'root_projections')


def _digest(value):
    _require(type(value) is str and re.fullmatch('sha256:[0-9a-f]{64}', value) is not None,
             'ntfs.owner_directory_digest_required')


def _physical(grant):
    return canonical_bytes({key: value for key, value in grant.items() if key != 'root_binding'})


def owner_directory_installation_id(owner_scope_id, role):
    _require(role in ROLES, 'ntfs.owner_directory_role_unsupported')
    return 'phase.native.owner.directory.' + owner_scope_id + '.' + role.lower()


def owner_directory_scope_digest(doc):
    """Noncyclic immutable owner domain for graph-pinned source scopes.

    No manifest, composition/graph, profile or full configuration digest may
    enter this projection: scopes themselves are executable graph members.
    The accepted config independently pins the complete owner document.
    """
    _require(type(doc) is dict and all(key in doc for key in _SCOPE_KEYS),
             'ntfs.owner_directory_configuration_shape')
    return digest_bytes(canonical_bytes({'owner_directory_scope_profile': '1.0',
                                         **{key: doc[key] for key in _SCOPE_KEYS}}))


def _manifest_row(row):
    _require(type(row) is dict and set(row) == {'role', 'manifest_base64', 'manifest_digest'}
             and row['role'] in ROLES and type(row['manifest_base64']) is str,
             'ntfs.owner_directory_manifest_shape')
    _digest(row['manifest_digest'])
    try:
        raw = base64.b64decode(row['manifest_base64'], validate=True)
    except (ValueError, UnicodeError) as exc:
        raise PhaseError('ntfs.owner_directory_manifest_shape') from exc
    _require(len(raw) <= MAX_CONFIGURATION_BYTES and digest_bytes(raw) == row['manifest_digest']
             and base64.b64encode(raw).decode('ascii') == row['manifest_base64'],
             'ntfs.owner_directory_manifest_digest_mismatch')
    value = parse_json_bytes(raw, maximum_bytes=MAX_CONFIGURATION_BYTES)
    _require(type(value) is dict and canonical_bytes(value) == raw,
             'ntfs.owner_directory_manifest_shape')
    return row['role'], raw, row['manifest_digest'], value


def owner_directory_configuration(raw, expected_digest):
    """Parse a closed owner-once document; never selects a registry/profile."""
    from .worker import _grant
    _digest(expected_digest)
    _require(type(raw) is bytes and len(raw) <= MAX_CONFIGURATION_BYTES and digest_bytes(raw) == expected_digest,
             'ntfs.owner_directory_configuration_digest_mismatch')
    doc = parse_json_bytes(raw, maximum_bytes=MAX_CONFIGURATION_BYTES)
    _require(type(doc) is dict and set(doc) == _CONFIGURATION_KEYS and canonical_bytes(doc) == raw
             and doc['owner_directory_configuration_version'] == '1.0',
             'ntfs.owner_directory_configuration_shape')
    try:
        valid_id = type(doc['owner_scope_id']) is str and str(UUID(doc['owner_scope_id'])) == doc['owner_scope_id']
    except (ValueError, AttributeError):
        valid_id = False
    _require(valid_id, 'ntfs.owner_directory_identity_required')
    _digest(doc['phase_wheel_digest'])
    _require(type(doc['root_grants']) is list and len(doc['root_grants']) == 2,
             'ntfs.owner_directory_grants_required')
    grants = [_grant(row) for row in doc['root_grants']]
    _require(tuple(row.binding for row in grants) == ('current_root', 'objects_root'),
             'ntfs.owner_directory_grants_required')
    current, objects = grants
    _require(current.volume_guid == objects.volume_guid
             and current.volume_serial32 == objects.volume_serial32 and current.device == objects.device
             and current.root_identity.volume_serial == objects.root_identity.volume_serial,
             'ntfs.owner_directory_same_volume_required')
    a, b = tuple(x.casefold() for x in current.components), tuple(x.casefold() for x in objects.components)
    _require(current.root_identity != objects.root_identity and not (a == b[:len(a)] or b == a[:len(b)]),
             'ntfs.owner_directory_overlapping_grants')
    _require(type(doc['windows_roots']) is dict and set(doc['windows_roots']) == {'current_root', 'objects_root'},
             'ntfs.owner_directory_unsupported_root')
    for grant in grants:
        name = doc['windows_roots'][grant.binding]
        _require(type(name) is str, 'ntfs.owner_directory_unsupported_root')
        path = PureWindowsPath(name)
        # The initial qualified scope remains the explicitly tested local S:
        # NTFS contour. No drive alias, UNC, relative, reparse or Unicode scope
        # is inferred from a user request. NativeIO uses the exact device grant.
        _require(path.drive == 'S:' and path.is_absolute() and str(path) == name
                 and tuple(path.parts[1:]) == grant.components,
                 'ntfs.owner_directory_unsupported_root')
    _require(type(doc['root_projections']) is dict
             and set(doc['root_projections']) == {'current_root', 'objects_root'},
             'ntfs.owner_directory_projection_required')
    roots = [doc['evidence_root'], doc['preparation_root'], *doc['root_projections'].values()]
    _require(all(type(p) is str and PurePosixPath(p).is_absolute() and str(PurePosixPath(p)) == p
                 and p != '/' and '..' not in PurePosixPath(p).parts for p in roots),
             'ntfs.owner_directory_projection_required')
    for index, first in enumerate(roots):
        for second in roots[index+1:]:
            _require(not PurePosixPath(first).is_relative_to(second)
                     and not PurePosixPath(second).is_relative_to(first),
                     'ntfs.owner_directory_projection_overlap')
    _require(type(doc['manifests']) is list and len(doc['manifests']) == 6
             and type(doc['predecessors']) is list and len(doc['predecessors']) <= MAX_PREDECESSORS,
             'ntfs.owner_directory_history_shape')
    active = [_manifest_row(row) for row in doc['manifests']]
    _require(tuple(row[0] for row in active) == ROLES, 'ntfs.owner_directory_history_shape')
    _require(type(doc['compositions']) is dict and set(doc['compositions']) == set(ROLES),
             'ntfs.owner_directory_history_domain_mismatch')
    for composition in doc['compositions'].values():
        _require(type(composition) is dict and set(composition) == {'id', 'version', 'artifact_graph_digest'},
                 'ntfs.owner_directory_history_domain_mismatch')
        _digest(composition['artifact_graph_digest'])
    _require(len({canonical_bytes({key: value for key, value in c.items() if key != 'artifact_graph_digest'})
                  for c in doc['compositions'].values()}) == 1,
             'ntfs.owner_directory_history_domain_mismatch')
    rows = active + [_manifest_row(row) for row in doc['predecessors']]
    tuples = set()
    for index, (role, body, digest, manifest) in enumerate(rows):
        _require(manifest.get('native_read_installation_version') == READ_VERSIONS[role]
                 and manifest.get('contract') == semantic_owner_contract(role)
                 and manifest.get('installation_id') == owner_directory_installation_id(doc['owner_scope_id'], role)
                 and manifest.get('core') == doc['core'], 'ntfs.owner_directory_manifest_binding_mismatch')
        for key in ('evidence_root', 'evidence_identity', 'preparation_root', 'preparation_identity'):
            _require(manifest.get(key) == doc[key], 'ntfs.owner_directory_history_domain_mismatch')
        if index < 6:
            _require(manifest.get('composition') == doc['compositions'][role], 'ntfs.owner_directory_history_domain_mismatch')
        expected_grants = parse_json_bytes(canonical_bytes(doc['root_grants']))
        if role != 'Version2':
            expected_grants = [expected_grants[0]]
            expected_grants[0]['root_binding'] = ROOT_BINDINGS[role]
        projections = ({'current_root': doc['root_projections']['current_root'],
                        'objects_root': doc['root_projections']['objects_root']} if role == 'Version2'
                       else {ROOT_BINDINGS[role]: doc['root_projections']['current_root']})
        _require(manifest.get('root_grants') == expected_grants and manifest.get('root_projections') == projections,
                 'ntfs.owner_directory_history_domain_mismatch')
        identity = canonical_bytes({'core': manifest['core'], 'contract': manifest['contract'],
                    'installation': {'id': manifest['installation_id'], 'descriptor_digest': digest},
                    'registry_snapshot_digest': manifest.get('registry_snapshot_digest')})
        _require(identity not in tuples, 'ntfs.owner_directory_duplicate_history')
        tuples.add(identity)
    return doc


def owner_directory_role_for_manifest(configuration_bytes, configuration_digest, manifest_bytes, manifest_digest):
    doc = owner_directory_configuration(configuration_bytes, configuration_digest)
    matches = [role for role, raw, digest, manifest in map(_manifest_row, doc['manifests'])
               if raw == manifest_bytes and digest == manifest_digest]
    _require(len(matches) == 1, 'ntfs.owner_directory_active_binding_required')
    return matches[0]


@dataclass(frozen=True)
class _DirectoryCatalog:
    """Private pure catalogue handle. Only the fixed factory selects one.

    Unit fixtures may construct this exact type with a synthetic snapshot.
    No JSON, public factory argument, profile override or caller object may
    replace the code-owned production snapshot.
    """
    registry: RegistrySnapshot
    expected_digest: str

    def check_identity(self):
        _require(type(self.registry) is RegistrySnapshot, 'ntfs.owner_directory_catalog_required')
        _digest(self.expected_digest)
        _require(self.registry.digest == self.expected_digest == canonical_digest(self.registry.to_document()),
                 'ntfs.owner_directory_catalog_mismatch')
        return self

    def check(self):
        self.check_identity()
        for role in ROLES:
            binding = semantic_owner_contract(role)
            _require(self.registry.contract_bindings().get(binding['id'] + '@' + binding['version']) == binding,
                     'ntfs.owner_directory_contract_unsupported')
            self.profile(role)
        return self

    def profile(self, role):
        _require(role in ROLES, 'ntfs.owner_directory_role_unsupported')
        exact = self.registry.guarantee_profile_bindings().get(PROFILE_IDS[role] + '@1.0.0')
        _require(exact is not None, 'ntfs.native_profile_not_qualified')
        descriptor = self.registry.resolve_guarantee_profile(exact)
        implementation = descriptor['implementation']
        _require(descriptor['descriptor_version'] == '1.1' and descriptor['classification'] == 'production'
                 and descriptor['provided_guarantees'] and descriptor['conformance']
                 and implementation['artifact'] == PROFILE_ARTIFACT
                 and implementation['id'] == 'phase.native.ntfs.directory.' + role.lower() + '.authority'
                 and implementation['version'] == '1.0.0'
                 and descriptor['storage_scope']['filesystem'] == 'ntfs'
                 and descriptor['storage_scope']['cooperating_processes_only'] is True,
                 'ntfs.native_profile_not_qualified')
        profile = GuaranteeProfileBinding(exact['id'], exact['version'], exact['descriptor_digest'],
                    implementation['id'], implementation['version'], implementation['artifact_digest'])
        binding = semantic_owner_contract(role)
        from ... import __version__
        contract = self.registry.resolve_contract(binding['id'], binding['version'], binding['package_digest'],
                                                   core_version=__version__)
        operation = contract.document['operation']
        verify_guarantee_coverage(operation['required_guarantees'], [operation['mechanism']], profile, self.registry)
        return profile


@dataclass(frozen=True)
class _OwnerDirectoryContext:
    configuration_bytes: bytes
    configuration_digest: str
    role: str
    catalog: _DirectoryCatalog

    def check(self, binding):
        from ...installation import _NativeFileCreateReadBinding
        _require(type(binding) is _NativeFileCreateReadBinding
                 and type(self) is _OwnerDirectoryContext and type(self.catalog) is _DirectoryCatalog
                 and getattr(binding, '_owner_directory_context', None) is self
                 and binding.experimental_admission is None and binding.registry is self.catalog.registry,
                 'ntfs.owner_directory_context_required')
        # The complete factory/history checks all roles. A read of one trusted
        # Original revalidates this exact snapshot and its selected production
        # profile (including actual implementation hash), without re-resolving
        # five unrelated profiles. No result/evidence/proof is cached here.
        self.catalog.check_identity()
        doc = owner_directory_configuration(self.configuration_bytes, self.configuration_digest)
        choices = [_manifest_row(row) for row in doc['manifests'] + doc['predecessors']]
        matches = [manifest for role, raw, digest, manifest in choices
                   if role == self.role and raw == binding.manifest_bytes and digest == binding.manifest_digest]
        _require(len(matches) == 1, 'ntfs.owner_directory_context_mismatch')
        manifest = matches[0]
        profile = self.catalog.profile(self.role)
        provider = {'id': profile.implementation_id, 'version': profile.implementation_version,
                    'artifact_digest': profile.implementation_artifact_digest}
        _require(manifest['registry_snapshot_digest'] == binding.registry.digest
                 and manifest['authority'] == {'usage': 'provider_backed', 'profile': profile.as_dict(), 'provider': provider},
                 'ntfs.original_implementation_mismatch')
        return self.role, manifest


def require_owner_directory_binding(binding, role=None):
    context = getattr(binding, '_owner_directory_context', None)
    _require(type(context) is _OwnerDirectoryContext and (role is None or role == context.role),
             'ntfs.owner_directory_context_required')
    return context.check(binding)


def owner_directory_context_identity(context):
    """Stable metadata equality across fresh, fully revalidated resolutions.

    A RegistrySnapshot object is deliberately not equality/capability state
    across calls. Within one resolved history the exact objects still match.
    Callers must run the fresh fixed factory, not use this tuple as admission.
    """
    _require(type(context) is _OwnerDirectoryContext and type(context.catalog) is _DirectoryCatalog
             and context.role in ROLES, 'ntfs.owner_directory_context_required')
    owner_directory_configuration(context.configuration_bytes, context.configuration_digest)
    _digest(context.catalog.expected_digest)
    return (context.configuration_bytes, context.configuration_digest, context.role, context.catalog.expected_digest)


def require_owner_or_semantic_binding(binding, role):
    """Exact ordinary branch beside the unchanged closed owner3 branch."""
    if getattr(binding, '_owner_directory_context', None) is not None:
        require_owner_directory_binding(binding, role)
        return
    from .owner_semantic_contracts import require_semantic_owner_admission
    require_semantic_owner_admission(binding, role)


def is_owner_directory_authority(value, role):
    """Closed exact ordinary role predicate; safe to import on Windows."""
    import sys
    if not sys.platform.startswith('linux') or role not in ROLES:
        return False
    from .owner_directory_authorities import _ordinary_authority_types
    expected = dict(zip(ROLES, _ordinary_authority_types()))[role]
    if type(value) is not expected:
        return False
    require_owner_directory_binding(value.read_binding, role)
    return True


def validate_owner_directory_history(active, bindings):
    from ...installation import _NativeFileCreateReadBinding, _resolve_native_file_create_read_binding
    _require(type(active) is _NativeFileCreateReadBinding and type(bindings) is tuple
             and 6 <= len(bindings) <= 6 + MAX_PREDECESSORS,
             'ntfs.original_history_binding_mismatch')
    context = getattr(active, '_owner_directory_context', None)
    _require(type(context) is _OwnerDirectoryContext, 'ntfs.owner_directory_context_required')
    doc = owner_directory_configuration(context.configuration_bytes, context.configuration_digest)
    expected = [_manifest_row(row) for row in doc['manifests'] + doc['predecessors']]
    _require(len(expected) == len(bindings), 'ntfs.original_history_binding_mismatch')
    for binding, (role, raw, digest, manifest) in zip(bindings, expected):
        _require(type(binding) is _NativeFileCreateReadBinding and binding.registry is active.registry
                 and binding.manifest_bytes == raw and binding.manifest_digest == digest,
                 'ntfs.original_history_binding_mismatch')
        other = getattr(binding, '_owner_directory_context', None)
        _require(type(other) is _OwnerDirectoryContext and other.catalog is context.catalog
                 and other.configuration_bytes == context.configuration_bytes
                 and other.configuration_digest == context.configuration_digest and other.role == role,
                 'ntfs.original_history_binding_mismatch')
        require_owner_directory_binding(binding, role)
        _resolve_native_file_create_read_binding(manifest_bytes=raw, expected_manifest_digest=digest,
                                                 registry=binding.registry)
    _require(sum(row is active for row in bindings) == 1, 'ntfs.original_history_binding_mismatch')
    return bindings


def owner_directory_original_binding(bindings, *, run_id, contract, core, installation=None,
                                     registry_snapshot_digest=None, pre_intent_rejection=False):
    from ...evidence import validate_run_id
    validate_run_id(run_id)
    _require(type(bindings) is tuple and bool(bindings) and type(pre_intent_rejection) is bool,
             'ntfs.original_history_binding_mismatch')
    validate_owner_directory_history(bindings[0], bindings)
    rows = bindings[:6] if pre_intent_rejection else bindings
    if pre_intent_rejection:
        _require(installation is None and registry_snapshot_digest is None,
                 'ntfs.original_history_binding_mismatch')
    matches = []
    for row in rows:
        role, manifest = require_owner_directory_binding(row)
        if contract != manifest['contract'] or core != manifest['core']:
            continue
        if not pre_intent_rejection and (installation != {'id': manifest['installation_id'],
                'descriptor_digest': row.manifest_digest} or registry_snapshot_digest != row.registry.digest):
            continue
        matches.append(row)
    _require(len(matches) == 1, 'ntfs.original_history_binding_mismatch')
    return matches[0]
