"""Closed owner3 fixture parser; qualification candidate only, no request selector."""
from ...canonical import canonical_bytes,parse_json_bytes,digest_bytes
from ...errors import PhaseError
from ..guarantees import GuaranteeProfileBinding
from pathlib import PureWindowsPath
import re
from .owner_directory_fixture import _need,_kinds,_digest,_identity,_posix,_ROLES,_UUID,_AUTHORIZATION
from .owner_semantic_contracts import semantic_owner_contract

_C02_CURRENT_ALIAS = 'c02_current_root_alias'
_C02_CURRENT_LEAVES = ('results', 'RESULTS')

def _semantic_profile_key(role):
    _need(role in _ROLES,'ntfs.semantic_owner_role_required')
    return 'phase.native.ntfs.experiment.owner3.'+role.lower()+'.authority.v1@1.0.0'

def semantic_fixture_document(raw):
    """Pure closed parser. A fixture cannot choose a class/factory/policy."""
    _need(type(raw) is bytes and 0 < len(raw) <= 32768, 'ntfs.owner_fixture_shape')
    return _validate_semantic_fixture_document(raw, parse_json_bytes(raw, maximum_bytes=32768))


def _c02_current_grant(grant, leaf):
    _need(leaf in _C02_CURRENT_LEAVES, 'ntfs.c02_alias_binding')
    return dict(grant, components=[*grant['components'][:-1], leaf])


def _c02_alias_domain_digest(doc, observations):
    roots = doc['windows_roots']
    primary = str(PureWindowsPath(roots['current_root']).parent / 'results')
    base = {key: value for key, value in doc.items() if key != _C02_CURRENT_ALIAS}
    base['windows_roots'] = dict(roots, current_root=primary)
    current, objects = doc['root_grants']
    base['root_grants'] = [_c02_current_grant(current, 'results'), objects]
    return digest_bytes(canonical_bytes({'version': '1.0', 'owner_fixture': base,
                                        'no_follow_observations': observations}))


def _validate_c02_current_root_alias(doc, current):
    # These are bound setup observations. Actual NativeIO still opens the exact
    # selected grant and checks its namespace and identity at use time.
    alias = doc[_C02_CURRENT_ALIAS]
    _need(type(alias) is dict and set(alias) == {'version', 'domain_digest', 'no_follow_observations'}
          and alias['version'] == '1.0', 'ntfs.c02_alias_binding')
    observations = alias['no_follow_observations']
    _need(type(observations) is dict and set(observations) == set(_C02_CURRENT_LEAVES),
          'ntfs.c02_alias_binding')
    raw_digests = []
    grant = current.as_dict()
    for leaf in _C02_CURRENT_LEAVES:
        row = observations[leaf]
        _need(type(row) is dict and set(row) == {'components', 'device', 'volume_guid',
              'volume_serial32', 'native_identity', 'reparse_tag', 'all_handles_closed', 'raw_digest'}
              and row['components'] == _c02_current_grant(grant, leaf)['components']
              and canonical_bytes({key: row[key] for key in (
                  'device', 'volume_guid', 'volume_serial32', 'native_identity')}) == canonical_bytes({
                  key: grant[key] for key in ('device', 'volume_guid', 'volume_serial32', 'native_identity')})
              and type(row['reparse_tag']) is int and row['reparse_tag'] == 0
              and row['all_handles_closed'] is True, 'ntfs.c02_alias_observation')
        _digest(row['raw_digest'])
        raw_digests.append(row['raw_digest'])
    _need(len(set(raw_digests)) == 2 and alias['domain_digest'] == _c02_alias_domain_digest(doc, observations),
          'ntfs.c02_alias_binding')


def _validate_semantic_fixture_document(raw, doc):
    _need(type(doc) is dict and canonical_bytes(doc) == raw and (set(doc) - {_C02_CURRENT_ALIAS} == {'experimental_admission_version', 'authorization_digest', 'fixture_uuid', 'owner_scope_id', 'wheel_digest', 'core', 'windows_roots', 'root_grants', 'root_projections', 'evidence_root', 'evidence_identity', 'preparation_root', 'preparation_identity', 'roles', 'request_limits', 'qualification', 'release_eligible'}), 'ntfs.owner_fixture_shape')
    _need(doc['experimental_admission_version'] == '3.0' and doc['authorization_digest'] == _AUTHORIZATION and (doc['release_eligible'] is False) and (doc['qualification'] == {'A05': 'NOT_VERIFIED', 'G01': 'NOT_VERIFIED'}), 'ntfs.owner_fixture_scope')
    _need(type(doc['fixture_uuid']) is str and _UUID.fullmatch(doc['fixture_uuid']) is not None and (doc['owner_scope_id'] == 'phase.qualification.owner.' + doc['fixture_uuid']))
    _digest(doc['wheel_digest'])
    _need(type(doc['core']) is dict and set(doc['core']) == {'id', 'version', 'package_digest'} and (doc['core']['id'] == 'phase.core') and (type(doc['core']['version']) is str))
    _digest(doc['core']['package_digest'])
    roots = doc['windows_roots']
    _need(type(roots) is dict and set(roots) == {'current_root', 'objects_root'})
    parent = PureWindowsPath('S:/Phase-NTFS-Qualification') / doc['fixture_uuid']
    leaves = _C02_CURRENT_LEAVES if _C02_CURRENT_ALIAS in doc else ('results',)
    _need(type(roots['current_root']) is str and roots['current_root'] in tuple(str(parent / leaf) for leaf in leaves)
          and type(roots['objects_root']) is str and roots['objects_root'] == str(parent / 'objects'))
    from .version2_observation import _version2_grants
    grants = _version2_grants(doc['root_grants'])
    _need(all((grants[key].components == PureWindowsPath(roots[key]).parts[1:] for key in roots)))
    projections = doc['root_projections']
    _need(type(projections) is dict and set(projections) == set(roots) and (projections == {'current_root': '/ntfs-result', 'objects_root': '/ntfs-objects'}))
    evidence, preparation = (_posix(doc[key]) for key in ('evidence_root', 'preparation_root'))
    _need(not evidence.is_relative_to(preparation) and (not preparation.is_relative_to(evidence)))
    for key in ('evidence_identity', 'preparation_identity'):
        _identity(doc[key])
    _need(doc['evidence_identity'] != doc['preparation_identity'])
    for projection in projections.values():
        value = _posix(projection)
        _need(all((not value.is_relative_to(root) and (not root.is_relative_to(value)) for root in (evidence, preparation))))
    limits = doc['request_limits']
    _need(type(limits) is dict and set(limits) == {'run_prefix', 'maximum_attempts', 'maximum_retained_bytes'} and (limits['run_prefix'] == 'od3-' + doc['fixture_uuid'] + '-') and (type(limits['maximum_attempts']) is int) and (1 <= limits['maximum_attempts'] <= 65536) and (type(limits['maximum_retained_bytes']) is int) and (1 <= limits['maximum_retained_bytes'] <= 32 * 1024 ** 3))
    rows = doc['roles']
    kinds = _kinds()
    _need(type(rows) is list and len(rows) == 6 and all((type(row) is dict for row in rows)) and ([row.get('role') for row in rows] == list(_ROLES)))
    for row in rows:
        kind = kinds[row['role']]
        _need(set(row) == {'role', 'contract', 'native_read_installation_version', 'registry_snapshot_digest', 'authority', 'root_binding'} and row['contract'] == semantic_owner_contract(row['role']) and (row['native_read_installation_version'] == kind._manifest_version))
        _digest(row['registry_snapshot_digest'])
        authority = row['authority']
        profile = authority.get('profile') if type(authority) is dict else None
        _need(type(authority) is dict and set(authority) == {'usage', 'profile', 'provider'} and (authority['usage'] == 'provider_backed') and (type(profile) is dict) and (set(profile) == {'id', 'version', 'descriptor_digest'}) and (type(profile['id']) is str) and (type(profile['version']) is str) and (profile['id'] + '@' + profile['version'] == _semantic_profile_key(row['role'])))
        _digest(profile['descriptor_digest'])
        provider = authority['provider']
        _need(type(provider) is dict and set(provider) == {'id', 'version', 'artifact_digest'} and (type(provider['id']) is str) and (type(provider['version']) is str))
        _digest(provider['artifact_digest'])
        _need(type(row['root_binding']) is str and re.fullmatch('[a-z][a-z0-9_]{0,63}', row['root_binding']) is not None and (row['role'] != 'Version2' or row['root_binding'] == 'current_root'))
    if _C02_CURRENT_ALIAS in doc:
        _validate_c02_current_root_alias(doc, grants['current_root'])
    return doc

def semantic_owner_role(kind):
    rows=[role for role,expected in _kinds().items()if kind is expected]
    _need(len(rows)==1,'ntfs.semantic_owner_role_required')
    return rows[0]

def semantic_owner_registry(kind):
    from .owner_semantic_registries import (_native_owner_semantic_file1_registry,
        _native_owner_semantic_file2_registry,_native_owner_semantic_version1_registry,
        _native_owner_semantic_version2_registry,_native_owner_semantic_bundle1_registry,
        _native_owner_semantic_bundle2_registry)
    fixed=dict(zip(_ROLES,(_native_owner_semantic_file1_registry,_native_owner_semantic_file2_registry,
        _native_owner_semantic_version1_registry,_native_owner_semantic_version2_registry,
        _native_owner_semantic_bundle1_registry,_native_owner_semantic_bundle2_registry),strict=True))
    return fixed[semantic_owner_role(kind)]()

def semantic_owner_authority(kind):
    # Linux installation owner only; never imported by Windows data admission.
    from .owner_semantic_authorities import (_OwnerSemanticFile1Authority,_OwnerSemanticFile2Authority,
        _OwnerSemanticVersion1Authority,_OwnerSemanticVersion2Authority,
        _OwnerSemanticBundle1Authority,_OwnerSemanticBundle2Authority)
    return dict(zip(_ROLES,(_OwnerSemanticFile1Authority,_OwnerSemanticFile2Authority,
        _OwnerSemanticVersion1Authority,_OwnerSemanticVersion2Authority,
        _OwnerSemanticBundle1Authority,_OwnerSemanticBundle2Authority),strict=True))[semantic_owner_role(kind)]

def semantic_owner_profile(admission,binding):
    role=semantic_owner_role(type(admission));doc=semantic_fixture_document(admission.raw)
    exact=binding.registry.guarantee_profile_bindings().get(_semantic_profile_key(role))
    _need(exact is not None,'ntfs.experimental_profile_required')
    descriptor=binding.registry.resolve_guarantee_profile(exact);implementation=descriptor['implementation']
    _need(descriptor['classification']=='qualification_candidate'
        and descriptor['provided_guarantees']==descriptor['conformance']==[]
        and implementation['artifact']=='phase_tool/mutation/ntfs/owner_semantic_authorities.py',
        'ntfs.experimental_profile_required')
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    row=next(row for row in doc['roles']if row['role']==role)
    _need(manifest['authority']==row['authority']=={'usage':'provider_backed','profile':exact,
        'provider':{key:implementation[key]for key in('id','version','artifact_digest')}},
        'ntfs.original_implementation_mismatch')
    return GuaranteeProfileBinding(exact['id'],exact['version'],exact['descriptor_digest'],
        implementation['id'],implementation['version'],implementation['artifact_digest'])


def is_semantic_owner_authority(value,role):
    """Closed exact class/context predicate, never a policy/provider selector."""
    kind=_kinds().get(role)
    if kind is None or type(value)is not semantic_owner_authority(kind):
        return False
    binding=getattr(value,'read_binding',None)
    from ...installation import _NativeFileCreateReadBinding
    if type(binding)is not _NativeFileCreateReadBinding or type(binding.experimental_admission)is not kind:
        return False
    return binding.experimental_admission.document().get('experimental_admission_version')=='3.0'
