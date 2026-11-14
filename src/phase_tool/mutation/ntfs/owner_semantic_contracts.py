"""Fixed unpublished owner3 candidate data, not execution authority.

No request policy/provider/registry override. The existing accepted launch and
strict ownerfixture3 parser remain mandatory. Legacy constants are untouched.
"""
from ...canonical import canonical_bytes,parse_json_bytes
from ...errors import PhaseError

SEMANTIC_OWNER_FIXTURE_VERSION = '3.0'
SEMANTIC_REQUEST_POLICY = 'digest.semantic_request_v2'
_CONTRACTS = {'File1': {'id': 'file_create.v1', 'version': '1.0.1', 'package_digest': 'sha256:1410ce0916fa9c63d101a0659e55a6ded257f9250b9cd0fb24d22365fea46573'}, 'File2': {'id': 'file_create.v2', 'version': '1.0.1', 'package_digest': 'sha256:5fa188c4b19696156bfe1dd3ee4105c5292ba3a48e1ad150fc76682bddf037d2'}, 'Version1': {'id': 'publish_new_version.v1', 'version': '1.0.1', 'package_digest': 'sha256:e3fb07507271493b9c021f3fcbf4b6d7c32799006d21b2e5ee767e8e491531a6'}, 'Version2': {'id': 'publish_new_version.v2', 'version': '1.0.1', 'package_digest': 'sha256:fcd0e687439c56ab0fdedbcd9b9ba791039777df6df437a7bb47f06edff7fe0c'}, 'Bundle1': {'id': 'bundle_create.v1', 'version': '1.1.1', 'package_digest': 'sha256:4d202fcdcf6ce21bd36b1baff7136aa194ec72fef31298c4519b821a47d0cd10'}, 'Bundle2': {'id': 'bundle_create.v2', 'version': '1.2.2', 'package_digest': 'sha256:05afffd7ec924e90abe21c223d6ecfc516aa35ef469dcb62a89c01553d8e2773'}}
_PROFILES = {role:'phase.native.ntfs.experiment.owner3.'+role.lower()+'.authority.v1' for role in _CONTRACTS}

def semantic_owner_contract(role):
    if type(role)is not str or role not in _CONTRACTS:
        raise PhaseError('ntfs.semantic_owner_role_required')
    return dict(_CONTRACTS[role])

def require_semantic_owner_contract(role,binding):
    if type(binding)is not dict or canonical_bytes(binding)!=canonical_bytes(semantic_owner_contract(role)):
        raise PhaseError('ntfs.semantic_owner_contract_mismatch')

def require_semantic_owner_admission(binding,role):
    # The existing fixture parser must gain an explicit reviewed3.0 branch;
    # its present2.0 version refuses this path, deliberately failclosed.
    from ...installation import _NativeFileCreateReadBinding
    from .owner_directory_fixture import _kinds,fixture_document
    if type(binding)is not _NativeFileCreateReadBinding or role not in _CONTRACTS:
        raise PhaseError('ntfs.semantic_owner_admission_required')
    admission=binding.experimental_admission
    if type(admission)is not _kinds()[role]:
        raise PhaseError('ntfs.semantic_owner_admission_required')
    doc=fixture_document(admission.raw)
    if doc['experimental_admission_version']!='3.0':
        raise PhaseError('ntfs.semantic_owner_admission_required')
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    require_semantic_owner_contract(role,manifest['contract'])
    if manifest['authority']['profile']['id']!=_PROFILES[role] or manifest['authority']['profile']['version']!='1.0.0':
        raise PhaseError('ntfs.semantic_owner_admission_required')
    admission.check_binding(binding);admission.profile(binding)
    return admission
