"""B2-only extension of the unchanged historical B1 native authority.

This new provider reuses the existing lifecycle, seal, proof and receipt owner.
Its closed constructor is needed because the frozen provider rejects generation
1.7; no old provider artifact or descriptor is modified for this experiment.
"""
import os
import re
from pathlib import Path, PurePosixPath
import threading

from ...canonical import canonical_bytes, parse_json_bytes, profile_digest
from ...paths import safe_relative_locator
from ..guarantees import GuaranteeProfileBinding
from .experimental_bundle1_authority import _ExperimentalBundle1Authority
from .experimental_bundle2 import _ExperimentalBundle2Admission
from .bundle_execution import _BUNDLE2_CONTRACT
from .bundle2_channel import LinuxNativeBundle2Channel
from .native import _require
from .worker import _grant


class _ExperimentalBundle2Authority(_ExperimentalBundle1Authority):
    def __init__(self, read_binding, profile: GuaranteeProfileBinding,
                 root_projections: bytes, channel: LinuxNativeBundle2Channel, *, run_id: str, operation_nonce: str,
                 _inspection_only: bool = False):
        _require(not getattr(self, '_initialization_attempted', False),
            'ntfs.native_role_initialization_consumed')
        self._initialization_attempted = True
        _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
        self._inspection_only = _inspection_only
        from ...installation import _NativeFileCreateReadBinding
        _require(type(read_binding) is _NativeFileCreateReadBinding
            and type(profile) is GuaranteeProfileBinding and type(channel) is LinuxNativeBundle2Channel,
            'ntfs.closed_native_installation_required')
        _require(channel._inspection_only is _inspection_only, 'ntfs.fixed_role_mismatch')
        self.read_binding, self.profile, self.channel = read_binding, profile, channel
        self._manifest = parse_json_bytes(read_binding.manifest_bytes)
        _require(self._manifest['native_read_installation_version']=='1.7'
            and self._manifest['contract']==_BUNDLE2_CONTRACT,'ntfs.fixed_role_mismatch')
        self._version1,self._file2,self._bundle=False,False,True
        from ...evidence import validate_run_id
        validate_run_id(run_id)
        self._run_id = run_id
        _require(type(operation_nonce) is str and re.fullmatch(r'[0-9a-f]{32}', operation_nonce) is not None,
            'ntfs.worker_nonce_shape')
        self._operation_nonce = operation_nonce
        self._finish_bytes = None
        self._no_dispatch_safety_established = False
        self._server_ingress_sealed = False
        self._owner = os.getpid(), threading.get_ident()
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
        _require(type(root_projections) is bytes and canonical_bytes(projections) == root_projections
            and type(projections) is dict, 'ntfs.installed_root_projections_required')
        grants = [_grant(row) for row in self._manifest['root_grants']]
        _require(len(grants) == 1 and set(projections) == {grants[0].binding},
            'ntfs.installed_root_projections_required')
        for value in projections.values():
            _require(type(value) is str and PurePosixPath(value).is_absolute()
                and value != '/' and str(PurePosixPath(value)) == value
                and '..' not in PurePosixPath(value).parts, 'ntfs.installed_root_projections_required')
        self._projections_bytes = root_projections
        self._grant_bytes = canonical_bytes(grants[0].as_dict())
        self._admitted_profile()

    def require_contract(self, contract):
        self._usable()
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalBundle2Admission,
            'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'],
            'version': contract.document['identity']['version'], 'package_digest': contract.package_digest}
            == self._manifest['contract'] == _BUNDLE2_CONTRACT
            and operation['intent'] == 'create' and operation['maximum_effects'] == 1
            and operation['allowed_effects'] == ['exclusive_create']
            and {k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')}
            == self._manifest['mechanism']
            and not operation.get('effect_mechanisms'), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'],
            [operation['mechanism']])

    def bind_prepared_checkpoint(self,store,contract,plan,intent_path,intent_digest,attachment_digests):
        """Called by the ONE Core after saving its original intent, before broker."""
        from .bundle_prepared import _CoreBundleCheckpoint
        self._execution_required()
        self.require_contract(contract)
        checkpoint=_CoreBundleCheckpoint(self.read_binding,store,contract,plan,intent_path,
            intent_digest,self._operation_nonce,attachment_digests)
        self.channel.bind_checkpoint(checkpoint)
