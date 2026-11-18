from __future__ import annotations
from ...canonical import digest_bytes, parse_json_bytes
from .authority import _NativeFileCreateAuthority
from .experimental_file1 import _CONTRACT, _experimental_admission
from .native import _require
from .experimental_authority import _ExperimentalFile1Authority as _LegacyFile1Authority
from .experimental_authority import _ExperimentalFile1Authority
from .experimental_file2 import _FILE2_CONTRACT, _ExperimentalFile2Admission
from .experimental_file2_authority import _ExperimentalFile2Authority as _LegacyFile2Authority
from .experimental_version1 import _VERSION1_CONTRACT, _ExperimentalVersion1Admission
from .experimental_version1_authority import _ExperimentalVersion1Authority as _LegacyVersion1Authority
import os
from pathlib import Path, PurePosixPath
import re
import threading
from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ..guarantees import GuaranteeProfileBinding
from .channel_v3 import LinuxNativeChannelV5
from .experimental_version2_authority import _ExperimentalVersion2Authority
from .native import NativeIdentity, _require
from .version2_observation import _version2_grants, _version2_targets
from pathlib import Path
from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...contracts.publish_new_version_v2 import inline_content
from .experimental_version2 import _VERSION2_CONTRACT, _ExperimentalVersion2Admission
from .version2_observation import _version2_grants, _version2_targets, validate_version2_observation, validate_version2_triple
from .experimental_version2_authority_v2 import _ExperimentalVersion2AuthorityV2 as _LegacyVersion2Authority
from ...canonical import canonical_bytes, parse_json_bytes, profile_digest
from ...paths import safe_relative_locator
from .experimental_bundle1 import _ExperimentalBundle1Admission
from .bundle_execution import _BUNDLE1_CONTRACT
from .channel_v4 import LinuxNativeBundleChannel
from .worker import _grant
from .experimental_bundle1_authority import _ExperimentalBundle1Authority as _LegacyBundle1Authority
from .experimental_bundle1_authority import _ExperimentalBundle1Authority
from .experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
from .bundle_execution import _BUNDLE2_CONTRACT_V2 as _BUNDLE2_CONTRACT
from .bundle_recovery_channel import LinuxNativeBundleRecoveryChannel
from .experimental_bundle2_authority_v3 import _ExperimentalBundle2AuthorityV3 as _LegacyBundle2Authority
from .owner_semantic_contracts import semantic_owner_contract, require_semantic_owner_admission

class _OwnerSemanticFile1Authority(_LegacyFile1Authority):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        require_semantic_owner_admission(self.read_binding, 'File1')

    def require_contract(self, contract):
        self._usable()
        require_semantic_owner_admission(self.read_binding, 'File1')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'], 'package_digest': contract.package_digest} == self._manifest['contract'] == semantic_owner_contract('File1') and operation['intent'] == 'create' and (operation['maximum_effects'] == 1) and (operation['allowed_effects'] == ['exclusive_create']) and ({k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')} == self._manifest['mechanism']) and (not operation.get('effect_mechanisms')), 'ntfs.original_single_effect_required')
        return self.read_binding.experimental_admission.assess(self.read_binding, operation['required_guarantees'], [operation['mechanism']])

class _OwnerSemanticFile2Authority(_LegacyFile2Authority):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        require_semantic_owner_admission(self.read_binding, 'File2')

    def require_contract(self, contract):
        self._usable()
        require_semantic_owner_admission(self.read_binding, 'File2')
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalFile2Admission, 'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'], 'package_digest': contract.package_digest} == self._manifest['contract'] == semantic_owner_contract('File2') and operation['intent'] == 'create' and (operation['maximum_effects'] == 1) and (operation['allowed_effects'] == ['exclusive_create']) and ({k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')} == self._manifest['mechanism']) and (not operation.get('effect_mechanisms')), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'], [operation['mechanism']])

class _OwnerSemanticVersion1Authority(_LegacyVersion1Authority):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        require_semantic_owner_admission(self.read_binding, 'Version1')

    def require_contract(self, contract):
        self._usable()
        require_semantic_owner_admission(self.read_binding, 'Version1')
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalVersion1Admission, 'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'], 'package_digest': contract.package_digest} == self._manifest['contract'] == semantic_owner_contract('Version1') and operation['intent'] == 'publish_new_version' and (operation['maximum_effects'] == 1) and (operation['allowed_effects'] == ['publish_new_version']) and ({k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')} == self._manifest['mechanism']) and (not operation.get('effect_mechanisms')), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'], [operation['mechanism']])

class _OwnerSemanticVersion2Authority(_LegacyVersion2Authority):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        require_semantic_owner_admission(self.read_binding, 'Version2')

    def require_contract(self, contract):
        self._usable()
        require_semantic_owner_admission(self.read_binding, 'Version2')
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalVersion2Admission, 'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'], 'package_digest': contract.package_digest} == self._manifest['contract'] == semantic_owner_contract('Version2') and operation['intent'] == 'publish_new_version' and (operation['maximum_effects'] == 1) and (operation['allowed_effects'] == ['publish_new_version']) and ({k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')} == self._manifest['mechanism']) and (not operation.get('effect_mechanisms')), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'], [operation['mechanism']])

class _OwnerSemanticBundle1Authority(_LegacyBundle1Authority):

    def __init__(self, read_binding, profile: GuaranteeProfileBinding, root_projections: bytes, channel: LinuxNativeBundleChannel, *, run_id: str, operation_nonce: str, _inspection_only: bool=False):
        _require(not getattr(self, '_initialization_attempted', False), 'ntfs.native_role_initialization_consumed')
        self._initialization_attempted = True
        require_semantic_owner_admission(read_binding, 'Bundle1')
        _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
        self._inspection_only = _inspection_only
        from ...installation import _NativeFileCreateReadBinding
        _require(type(read_binding) is _NativeFileCreateReadBinding and type(profile) is GuaranteeProfileBinding and (type(channel) is LinuxNativeBundleChannel), 'ntfs.closed_native_installation_required')
        _require(channel._inspection_only is _inspection_only, 'ntfs.fixed_role_mismatch')
        self.read_binding, self.profile, self.channel = (read_binding, profile, channel)
        self._manifest = parse_json_bytes(read_binding.manifest_bytes)
        _require(self._manifest['native_read_installation_version'] == '1.6' and self._manifest['contract'] == semantic_owner_contract('Bundle1'), 'ntfs.fixed_role_mismatch')
        self._version1, self._file2, self._bundle = (False, False, True)
        from ...evidence import validate_run_id
        validate_run_id(run_id)
        self._run_id = run_id
        _require(type(operation_nonce) is str and re.fullmatch('[0-9a-f]{32}', operation_nonce) is not None, 'ntfs.worker_nonce_shape')
        self._operation_nonce = operation_nonce
        self._finish_bytes = None
        self._no_dispatch_safety_established = False
        self._server_ingress_sealed = False
        self._owner = (os.getpid(), threading.get_ident())
        self._sealed = False
        self._seal_attempted = False
        self._channel_sealed = False
        self._response_bytes = None
        self._failure_bytes = None
        self._dispatch_attempted = False
        self._parent_safety_established = False
        self._observations = {}
        self._version1_post_attempted = False
        projections = parse_json_bytes(root_projections)
        _require(type(root_projections) is bytes and canonical_bytes(projections) == root_projections and (type(projections) is dict), 'ntfs.installed_root_projections_required')
        grants = [_grant(row) for row in self._manifest['root_grants']]
        _require(len(grants) == 1 and set(projections) == {grants[0].binding}, 'ntfs.installed_root_projections_required')
        for value in projections.values():
            _require(type(value) is str and PurePosixPath(value).is_absolute() and (value != '/') and (str(PurePosixPath(value)) == value) and ('..' not in PurePosixPath(value).parts), 'ntfs.installed_root_projections_required')
        self._projections_bytes = root_projections
        self._grant_bytes = canonical_bytes(grants[0].as_dict())
        self._admitted_profile()

    def require_contract(self, contract):
        self._usable()
        require_semantic_owner_admission(self.read_binding, 'Bundle1')
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalBundle1Admission, 'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'], 'package_digest': contract.package_digest} == self._manifest['contract'] == semantic_owner_contract('Bundle1') and operation['intent'] == 'create' and (operation['maximum_effects'] == 1) and (operation['allowed_effects'] == ['exclusive_create']) and ({k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')} == self._manifest['mechanism']) and (not operation.get('effect_mechanisms')), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'], [operation['mechanism']])

class _OwnerSemanticBundle2Authority(_LegacyBundle2Authority):

    def __init__(self, read_binding, profile: GuaranteeProfileBinding, root_projections: bytes, channel: LinuxNativeBundleRecoveryChannel, *, run_id: str, operation_nonce: str, _inspection_only: bool=False):
        _require(not getattr(self, '_initialization_attempted', False), 'ntfs.native_role_initialization_consumed')
        self._initialization_attempted = True
        require_semantic_owner_admission(read_binding, 'Bundle2')
        _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
        self._inspection_only = _inspection_only
        from ...installation import _NativeFileCreateReadBinding
        _require(type(read_binding) is _NativeFileCreateReadBinding and type(profile) is GuaranteeProfileBinding and (type(channel) is LinuxNativeBundleRecoveryChannel), 'ntfs.closed_native_installation_required')
        _require(channel._inspection_only is _inspection_only, 'ntfs.fixed_role_mismatch')
        self.read_binding, self.profile, self.channel = (read_binding, profile, channel)
        self._manifest = parse_json_bytes(read_binding.manifest_bytes)
        _require(self._manifest['native_read_installation_version'] == '1.9' and self._manifest['contract'] == semantic_owner_contract('Bundle2'), 'ntfs.fixed_role_mismatch')
        self._version1, self._file2, self._bundle = (False, False, True)
        from ...evidence import validate_run_id
        validate_run_id(run_id)
        self._run_id = run_id
        _require(type(operation_nonce) is str and re.fullmatch('[0-9a-f]{32}', operation_nonce) is not None, 'ntfs.worker_nonce_shape')
        self._operation_nonce = operation_nonce
        self._finish_bytes = None
        self._no_dispatch_safety_established = False
        self._server_ingress_sealed = False
        self._owner = (os.getpid(), threading.get_ident())
        self._sealed = False
        self._seal_attempted = False
        self._channel_sealed = False
        self._response_bytes = None
        self._failure_bytes = None
        self._dispatch_attempted = False
        self._parent_safety_established = False
        self._observations = {}
        self._version1_post_attempted = False
        projections = parse_json_bytes(root_projections)
        _require(type(root_projections) is bytes and canonical_bytes(projections) == root_projections and (type(projections) is dict), 'ntfs.installed_root_projections_required')
        grants = [_grant(row) for row in self._manifest['root_grants']]
        _require(len(grants) == 1 and set(projections) == {grants[0].binding}, 'ntfs.installed_root_projections_required')
        for value in projections.values():
            _require(type(value) is str and PurePosixPath(value).is_absolute() and (value != '/') and (str(PurePosixPath(value)) == value) and ('..' not in PurePosixPath(value).parts), 'ntfs.installed_root_projections_required')
        self._projections_bytes = root_projections
        self._grant_bytes = canonical_bytes(grants[0].as_dict())
        self._admitted_profile()

    def require_contract(self, contract):
        self._usable()
        require_semantic_owner_admission(self.read_binding, 'Bundle2')
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalBundle2AdmissionV3, 'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'], 'package_digest': contract.package_digest} == self._manifest['contract'] == semantic_owner_contract('Bundle2') and operation['intent'] == 'create' and (operation['maximum_effects'] == 1) and (operation['allowed_effects'] == ['exclusive_create']) and ({k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')} == self._manifest['mechanism']) and (not operation.get('effect_mechanisms')), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'], [operation['mechanism']])
