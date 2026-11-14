"""Synthetic closed catalog over genuine six semantic packages and real metadata.

Profiles exist ONLY as in-memory unit data. No package resource/generation,
accepted runtime, authority qualification or native effect is introduced.
"""
import base64
from copy import deepcopy
from importlib import resources as package_resources
from pathlib import Path

from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from phase_tool.registry import RegistrySnapshot
from phase_tool.mutation.ntfs import owner_semantic_registries as fixed
from phase_tool.mutation.ntfs.owner_directory import (ROLES, PROFILE_IDS, PROFILE_ARTIFACT,
    ROOT_BINDINGS, READ_VERSIONS, _DirectoryCatalog, owner_directory_installation_id)
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract

HERE = Path(__file__).absolute().parent
OWNER_ID = 'f46211e7-fc18-49df-812e-b2e0500b4e90'
_METADATA = HERE / 'fixtures/CLOSED_CI148_METADATA_VECTORS_v1.json'


def synthetic_catalog():
    factories = (fixed._native_owner_semantic_file1_registry, fixed._native_owner_semantic_file2_registry,
        fixed._native_owner_semantic_version1_registry, fixed._native_owner_semantic_version2_registry,
        fixed._native_owner_semantic_bundle1_registry, fixed._native_owner_semantic_bundle2_registry)
    snapshots = [factory() for factory in factories]
    document = snapshots[0].to_document()
    document['snapshot_id'] = 'SYNTHETIC-TEST-ONLY-ordinary-owner-directory'
    template_entry = next(e for e in document['entries'] if e.get('kind') == 'guarantee_profile'
                          and e['id'] == 'phase.native.ntfs.experiment.owner3.file1.authority.v1')
    resources = dict(snapshots[0]._resources)
    # Existing snapshots deliberately have DIFFERENT historical current rows.
    # A synthetic six-role fixture therefore declares its selected exact
    # contracts, then copies verified immutable dependency bindings once. It
    # does not pretend that naive whole-snapshot union is a registry successor.
    wanted = {(b['id'], b['version'], b['package_digest']) for b in map(semantic_owner_contract, ROLES)}
    wanted.add(('file_create.v1', '1.0.0', 'sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a'))
    document['entries'] = []
    entries_seen = set()
    for snapshot in snapshots:
        for name, raw in snapshot._resources.items():
            if name in resources and resources[name] != raw:
                raise AssertionError('Conflicting immutable package bytes: ' + name)
            resources[name] = raw
        for entry in snapshot.to_document()['entries']:
            if entry.get('kind') == 'guarantee_profile':
                continue
            if entry.get('kind') == 'contract' and (entry['id'], entry['version'], entry['package_digest']) not in wanted:
                continue
            snapshot._verify_entry(entry)
            key = tuple(entry.get(k) for k in ('kind', 'id', 'version', 'capability', 'package_digest', 'artifact_digest'))
            if key not in entries_seen:
                document['entries'].append(deepcopy(entry))
                entries_seen.add(key)
    template = parse_json_bytes(resources[template_entry.get('archive_resource', template_entry['artifact'])])
    # Read the actual selected package artifact without importing its Linux
    # authority module. This works in the standard src snapshot and wheel;
    # never fall back to a lab/source origin or a missing candidate directory.
    artifact = package_resources.files('phase_tool').joinpath(*PROFILE_ARTIFACT.split('/')[1:])
    artifact_digest = digest_bytes(artifact.read_bytes())
    for role in ROLES:
        binding = semantic_owner_contract(role)
        source = next(s for s in snapshots if s.contract_bindings().get(binding['id'] + '@' + binding['version']) == binding)
        contract = source.resolve_contract(binding['id'], binding['version'], binding['package_digest'], core_version='1.2.0-rc.1')
        guarantees = contract.document['operation']['required_guarantees']['mechanisms'][0]['all_of']
        descriptor = deepcopy(template)
        descriptor.update(id=PROFILE_IDS[role], classification='production',
            provided_guarantees=deepcopy(guarantees),
            conformance=[{'guarantee': g, 'test_id': 'SYNTHETIC-UNIT-DATA-ONLY/' + role + '/' + g} for g in guarantees],
            storage_scope={'filesystem': 'ntfs', 'mount_boundary': 'SYNTHETIC UNIT SCOPE ONLY', 'cooperating_processes_only': True},
            limitations=['SYNTHETIC UNIT DATA. No qualification certificate or runtime admission.'])
        descriptor['implementation'] = {'id': 'phase.native.ntfs.directory.' + role.lower() + '.authority',
            'version': '1.0.0', 'artifact': PROFILE_ARTIFACT, 'artifact_digest': artifact_digest}
        name = 'SYNTHETIC-TEST-ONLY/' + role + '.json'
        raw = canonical_bytes(descriptor)
        resources[name] = raw
        entry = deepcopy(template_entry)
        entry.update(id=descriptor['id'], artifact=name, artifact_digest=digest_bytes(raw))
        entry.pop('archive_resource', None)
        document['entries'].append(entry)
    registry = RegistrySnapshot.from_document(document, resources)
    return _DirectoryCatalog(registry, registry.digest)


def owner_document(catalog, *, directory=None):
    raw = _METADATA.read_bytes()
    assert digest_bytes(raw) == 'sha256:37db82a84d896a823d77d5fe0707f03d80b77b6beed6c38bc225c1f47716fad9'
    vectors = {r['role']: r for r in parse_json_bytes(raw)['rows']}
    original = vectors['Version2']['manifest']
    grants = deepcopy(original['root_grants'])
    value = {'owner_directory_configuration_version': '1.0', 'owner_scope_id': OWNER_ID,
        'core': deepcopy(original['core']), 'compositions': {}, 'phase_wheel_digest': 'sha256:' + '3' * 64,
        'root_grants': grants, 'windows_roots': deepcopy(vectors['Version2']['admission']['windows_roots']),
        'root_projections': {'current_root': '/ntfs-result', 'objects_root': '/ntfs-objects'},
        'evidence_root': original['evidence_root'], 'evidence_identity': deepcopy(original['evidence_identity']),
        'preparation_root': original['preparation_root'], 'preparation_identity': deepcopy(original['preparation_identity']),
        'manifests': [], 'predecessors': []}
    if directory is not None:
        for key in ('evidence', 'preparation'):
            path = directory / key
            path.mkdir(mode=0o700)
            value[key + '_root'] = str(path)
            value[key + '_identity'] = {'stable_id': 'ordinary.synthetic.' + key,
                                      'device': path.stat().st_dev, 'inode': path.stat().st_ino}
    for ordinal, role in enumerate(ROLES):
        contract_binding = semantic_owner_contract(role)
        contract = catalog.registry.resolve_contract(contract_binding['id'], contract_binding['version'],
            contract_binding['package_digest'], core_version=value['core']['version'])
        profile = catalog.profile(role)
        manifest = deepcopy(vectors[role]['manifest'])
        composition = {'id': 'phase.native.ntfs.owner-directory', 'version': '1.0.0',
                       'artifact_graph_digest': digest_bytes(('synthetic-role-graph:' + role).encode())}
        value['compositions'][role] = composition
        root_grants = deepcopy(grants) if role == 'Version2' else [deepcopy(grants[0])]
        if role != 'Version2':
            root_grants[0]['root_binding'] = ROOT_BINDINGS[role]
        projections = deepcopy(value['root_projections']) if role == 'Version2' else {ROOT_BINDINGS[role]: '/ntfs-result'}
        manifest.update(native_read_installation_version=READ_VERSIONS[role],
            installation_id=owner_directory_installation_id(OWNER_ID, role), contract=contract_binding,
            registry_snapshot_digest=catalog.registry.digest, composition=composition,
            root_grants=root_grants, root_projections=projections,
            mechanism={k: contract.document['operation']['mechanism'][k] for k in ('id', 'version', 'package_digest')},
            authority={'usage': 'provider_backed', 'profile': profile.as_dict(),
                'provider': {'id': profile.implementation_id, 'version': profile.implementation_version,
                             'artifact_digest': profile.implementation_artifact_digest}})
        for key in ('core', 'evidence_root', 'evidence_identity', 'preparation_root', 'preparation_identity'):
            manifest[key] = deepcopy(value[key])
        body = canonical_bytes(manifest)
        value['manifests'].append({'role': role, 'manifest_base64': base64.b64encode(body).decode('ascii'),
                                  'manifest_digest': digest_bytes(body)})
    return value


def mutate_manifest(document, role, update):
    value = deepcopy(document)
    row = next(r for r in value['manifests'] if r['role'] == role)
    manifest = parse_json_bytes(base64.b64decode(row['manifest_base64']))
    update(manifest)
    raw = canonical_bytes(manifest)
    row.update(manifest_base64=base64.b64encode(raw).decode('ascii'), manifest_digest=digest_bytes(raw))
    return value


def altered_profile_catalog(catalog, role, update):
    """Self-consistent synthetic bytes, so semantic coverage guards must run."""
    document = catalog.registry.to_document()
    resources = dict(catalog.registry._resources)
    entry = next(e for e in document['entries'] if e.get('kind') == 'guarantee_profile' and e['id'] == PROFILE_IDS[role])
    name = entry.get('archive_resource', entry['artifact'])
    descriptor = parse_json_bytes(resources[name])
    update(descriptor)
    raw = canonical_bytes(descriptor)
    resources[name] = raw
    entry['artifact_digest'] = digest_bytes(raw)
    registry = RegistrySnapshot.from_document(document, resources)
    return _DirectoryCatalog(registry, registry.digest)
