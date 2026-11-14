"""Explicit installed read expectations for composed native experiments.

This format reuses the existing fixed registries, per-run admissions and Core
history lock. It has no execution authority and never discovers bindings from
evidence. Ordinary qualification and all historical formats remain unchanged.
"""
import base64
import re

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from .native import _require


def _mixed_history_contexts():
    from .experimental_file1 import _ExperimentalFile1Admission
    from .experimental_file2 import _ExperimentalFile2Admission
    from .experimental_version1 import _ExperimentalVersion1Admission
    from .experimental_version2 import _ExperimentalVersion2Admission
    from .experimental_bundle1 import _ExperimentalBundle1Admission
    from .experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
    return (_ExperimentalFile1Admission, _ExperimentalFile2Admission,
        _ExperimentalVersion1Admission, _ExperimentalVersion2Admission,
        _ExperimentalBundle1Admission, _ExperimentalBundle2AdmissionV3)


def mixed_history_buffers(raw, expected_digest, *, active_bytes, active_digest):
    """Bounded canonical configuration only; companions grant no dispatch."""
    _require(type(raw) is bytes and len(raw) <= 2*1024**2
        and type(expected_digest) is str and digest_bytes(raw) == expected_digest,
        'ntfs.accepted_history_binding_mismatch')
    value = parse_json_bytes(raw, maximum_bytes=2*1024**2)
    if type(value) is dict and value.get('history_manifest_set_version')in {'2.0','3.0'}:
        from .owner_directory_fixture import owner_history_buffers
        return owner_history_buffers(raw,expected_digest,active_bytes=active_bytes,active_digest=active_digest)
    _require(type(value) is dict and canonical_bytes(value) == raw
        and set(value) == {'history_manifest_set_version', 'manifests'}
        and value['history_manifest_set_version'] == '1.3'
        and type(value['manifests']) is list and len(value['manifests']) >= 2,
        'ntfs.accepted_history_shape')
    contexts = _mixed_history_contexts()
    buffers = []
    runs = set()
    installations = set()
    for row in value['manifests']:
        _require(type(row) is dict and set(row) == {'manifest_base64', 'manifest_digest',
            'experimental_admission_base64', 'experimental_admission_digest'},
            'ntfs.accepted_history_shape')
        decoded = []
        for stem, limit in (('manifest', 2*1024**2), ('experimental_admission', 32768)):
            encoded, sha = row[stem+'_base64'], row[stem+'_digest']
            _require(type(encoded) is str and type(sha) is str
                and re.fullmatch('sha256:[0-9a-f]{64}', sha) is not None,
                'ntfs.accepted_history_shape')
            try:
                leaf = base64.b64decode(encoded, validate=True)
            except (ValueError, UnicodeError) as error:
                from ...errors import PhaseError
                raise PhaseError('ntfs.accepted_history_shape') from error
            _require(len(leaf) <= limit and base64.b64encode(leaf).decode('ascii') == encoded
                and digest_bytes(leaf) == sha, 'ntfs.accepted_history_binding_mismatch')
            document = parse_json_bytes(leaf, maximum_bytes=limit)
            _require(type(document) is dict and canonical_bytes(document) == leaf,
                'ntfs.accepted_history_shape')
            decoded.append((leaf, sha, document))
        manifest, admission = (part[2] for part in decoded)
        kinds = [kind for kind in contexts if admission.get('contract') == kind._contract
            and manifest.get('native_read_installation_version') == kind._manifest_version]
        _require(len(kinds) == 1 and manifest.get('contract') == admission.get('contract'),
            'ntfs.accepted_history_shape')
        kind = kinds[0]
        checked = kind(decoded[1][0]).document()
        identifier = manifest.get('installation_id')
        _require(type(identifier) is str and identifier == kind._installation_prefix + digest_bytes(decoded[1][0])[7:]
            and identifier not in installations and checked['run_id'] not in runs,
            'ntfs.accepted_history_binding_mismatch')
        runs.add(checked['run_id'])
        installations.add(identifier)
        buffers.append((decoded[0][0], decoded[0][1], decoded[1][0], kind))
    _require(type(active_bytes) is bytes and type(active_digest) is str
        and digest_bytes(active_bytes) == active_digest
        and sum(leaf == active_bytes and sha == active_digest for leaf, sha, _, _ in buffers) == 1,
        'ntfs.accepted_history_binding_mismatch')
    return tuple(buffers)


def validate_mixed_history_bindings(active, bindings):
    from ...installation import _NativeFileCreateReadBinding
    from .owner_directory_fixture import is_fixture,validate_owner_history_bindings
    if type(active) is _NativeFileCreateReadBinding and type(active.experimental_admission) in _mixed_history_contexts() and is_fixture(active.experimental_admission.raw):
        return validate_owner_history_bindings(active,bindings)
    context = (bindings[0]._qualification_context if type(bindings) is tuple and bindings
        and type(bindings[0]) is _NativeFileCreateReadBinding else None)
    if context is None:
        return _validate_mixed_history_bindings(active,bindings)
    from .qualification_catalog import _CatalogRegistryContext
    _require(type(context) is _CatalogRegistryContext,'ntfs.history_catalog_context_mismatch')
    with context.validation_pass():
        return _validate_mixed_history_bindings(active,bindings)


def _validate_mixed_history_bindings(active, bindings):
    """Validate every exact reader and its complete common physical domain."""
    from pathlib import PurePosixPath
    from ...installation import _NativeFileCreateReadBinding, _native_experimental_read_binding
    from .version2_observation import _version2_grants
    from .experimental_version2 import _ExperimentalVersion2Admission
    contexts = _mixed_history_contexts()
    _require(type(active) is _NativeFileCreateReadBinding and type(bindings) is tuple
        and len(bindings) >= 2 and type(active.experimental_admission) in contexts,
        'ntfs.original_history_binding_mismatch')
    context = None
    if bindings and type(bindings[0]) is _NativeFileCreateReadBinding:
        context = bindings[0]._qualification_context
    if context is not None:
        from .qualification_catalog import _CatalogRegistryContext
        _require(type(context) is _CatalogRegistryContext
            and all(type(row) is _NativeFileCreateReadBinding and row._qualification_context is context for row in bindings),
            'ntfs.history_catalog_context_mismatch')
    manifests = []
    admissions = []
    current_domains = []
    object_domains = []
    runs = set()
    installations = set()
    for row in bindings:
        _require(type(row) is _NativeFileCreateReadBinding
            and type(row.experimental_admission) in contexts, 'ntfs.original_history_binding_mismatch')
        checked = _native_experimental_read_binding(manifest_bytes=row.manifest_bytes,
            expected_manifest_digest=row.manifest_digest, admission=row.experimental_admission, _catalog_context=context)
        if context is None:
            _require(type(row.registry) is type(checked.registry)
                and row.registry.digest == checked.registry.digest
                and canonical_bytes(row.registry.to_document()) == canonical_bytes(checked.registry.to_document()),
                'ntfs.original_history_binding_mismatch')
        else:
            context.check(row.registry)
            context.check(checked.registry)
            _require(row.registry is checked.registry, 'ntfs.original_history_binding_mismatch')
        manifest = parse_json_bytes(row.manifest_bytes, maximum_bytes=2*1024**2)
        admission = row.experimental_admission.check_binding(row)
        row.experimental_admission.profile(row)
        _require(admission['run_id'] not in runs and manifest['installation_id'] not in installations,
            'ntfs.original_history_binding_mismatch')
        runs.add(admission['run_id'])
        installations.add(manifest['installation_id'])
        if type(row.experimental_admission) is _ExperimentalVersion2Admission:
            grants = _version2_grants(manifest['root_grants'])
            current = grants['current_root'].as_dict()
            current_path = admission['windows_roots']['current_root']
            current_projection = manifest['root_projections']['current_root']
            objects = grants['objects_root'].as_dict()
            object_projection = manifest['root_projections']['objects_root']
            left, right = PurePosixPath(current_projection), PurePosixPath(object_projection)
            _require(not left.is_relative_to(right) and not right.is_relative_to(left),
                'ntfs.original_history_domain_mismatch')
            object_domains.append(canonical_bytes({'grant': objects,
                'windows_root': admission['windows_roots']['objects_root'],
                'projection': object_projection}))
        else:
            _require(len(manifest['root_grants']) == 1, 'ntfs.original_history_domain_mismatch')
            current = manifest['root_grants'][0]
            current_path = admission['windows_root']
            current_projection = manifest['root_projections'][current['root_binding']]
        current_domains.append(canonical_bytes({'grant': {k: v for k, v in current.items() if k != 'root_binding'},
            'windows_root': current_path, 'projection': current_projection}))
        manifests.append(manifest)
        admissions.append(admission)
    _require(sum(row.manifest_bytes == active.manifest_bytes and row.manifest_digest == active.manifest_digest
        and row.experimental_admission.raw == active.experimental_admission.raw for row in bindings) == 1,
        'ntfs.original_history_binding_mismatch')
    common = ('core', 'composition', 'evidence_root', 'evidence_identity', 'preparation_root', 'preparation_identity')
    _require(len(set(current_domains)) == 1 and len(set(object_domains)) <= 1
        and all(all(canonical_bytes(leaf[key]) == canonical_bytes(manifests[0][key]) for key in common)
            for leaf in manifests[1:])
        and all(all(doc[key] == admissions[0][key] for key in ('authorization_digest', 'wheel_digest'))
            for doc in admissions[1:]), 'ntfs.original_history_domain_mismatch')
    return bindings
