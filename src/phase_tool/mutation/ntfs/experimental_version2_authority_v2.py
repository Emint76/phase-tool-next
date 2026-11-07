"""Version2-only extension of the unchanged historical native authority.

The frozen original artifact cannot accept inline content or two roots. These
overrides preserve its existing lifecycle, evidence and interruption vocabulary;
they do not introduce a separate Core, journal, receipt or version owner.
"""
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


class _ExperimentalVersion2AuthorityV2(_ExperimentalVersion2Authority):
    def __init__(self,read_binding,profile,root_projections,channel,*,run_id,operation_nonce,
                 _inspection_only=False):
        _require(not getattr(self,'_initialization_attempted',False),'ntfs.native_role_initialization_consumed')
        self._initialization_attempted=True
        _require(type(_inspection_only) is bool,'ntfs.fixed_role_required')
        self._inspection_only=_inspection_only
        from ...installation import _NativeFileCreateReadBinding
        _require(type(read_binding) is _NativeFileCreateReadBinding
            and type(profile) is GuaranteeProfileBinding and type(channel) is LinuxNativeChannelV5,
            'ntfs.closed_native_installation_required')
        _require(channel._inspection_only is _inspection_only,'ntfs.fixed_role_mismatch')
        self.read_binding,self.profile,self.channel=read_binding,profile,channel
        self._manifest=parse_json_bytes(read_binding.manifest_bytes)
        _require(self._manifest['native_read_installation_version']=='1.5'
            and self._manifest['contract']['id']=='publish_new_version.v2','ntfs.fixed_role_mismatch')
        self._version1,self._file2,self._version2=False,False,True
        from ...evidence import validate_run_id
        validate_run_id(run_id);self._run_id=run_id
        _require(type(operation_nonce) is str and re.fullmatch('[0-9a-f]{32}',operation_nonce) is not None,
            'ntfs.worker_nonce_shape')
        self._operation_nonce=operation_nonce
        self._finish_bytes=None
        self._no_dispatch_safety_established=False
        self._server_ingress_sealed=False
        self._owner=os.getpid(),threading.get_ident()
        self._sealed=False
        self._seal_attempted=False
        self._channel_sealed=False
        self._response_bytes=None
        self._failure_bytes=None
        self._dispatch_attempted=False
        self._parent_safety_established=False
        self._observations={}
        self._version1_post_attempted=False
        self._version2_post_attempted=False
        grants=_version2_grants(self._manifest['root_grants'])
        projections=parse_json_bytes(root_projections)
        _require(type(root_projections) is bytes and canonical_bytes(projections)==root_projections
            and type(projections) is dict and set(projections)==set(grants),
            'ntfs.installed_root_projections_required')
        for value in projections.values():
            _require(type(value) is str and PurePosixPath(value).is_absolute()
                and value!='/' and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts,
                'ntfs.installed_root_projections_required')
        self._projections_bytes=root_projections
        self._grant_bytes=canonical_bytes(grants['current_root'].as_dict())
        self._admitted_profile()

    def plan(self,*args,**kwargs):
        plan=super().plan(*args,**kwargs)
        _require(len(plan['effects'])==1 and plan['effects'][0]['content_length']<=512*1024,
            'mechanism.content_too_large')
        return plan

    def observe(self,**kwargs):
        self._usable()
        _require(False,'ntfs.original_closed_role_required')

    def expected_after_identity(self,effect):
        self._execution_required();self._usable()
        if not self._parent_safety_established or self._response_bytes is None:return None
        physical=parse_json_bytes(self._response_bytes)['completion']['physical_evidence']
        targets={name:{'root_binding':binding,'relative_locator':locator}
            for name,(binding,locator) in _version2_targets(effect).items()}
        _require(physical['effect_id']==effect['effect_id'] and physical['targets']==targets
            and canonical_bytes(physical['grants'])==canonical_bytes(self._manifest['root_grants']),
            'ntfs.worker_observer_mismatch')
        result={}
        for name in targets:
            sample=physical['after'][name]
            _require(type(sample) is dict and sample.get('exists') is True,'ntfs.worker_observer_mismatch')
            result[name]=NativeIdentity.parse(sample['native_identity']).as_dict()
        return result

    def execute(self,plan,contract,frozen_inputs,roots,intent_path,*,timestamp,receipt_validator,expected_intent_digest):
        self._execution_required()
        from ..broker import BrokerExecutionInterrupted,BrokerExecutionResult
        self.require_contract(contract)
        self.require_request_roots(roots,Path(self._manifest['evidence_root']))
        _require(not self._dispatch_attempted,'ntfs.channel_execution_consumed')
        _require(plan['run_id']==self._run_id,'ntfs.original_current_invocation_mismatch')
        from ...streaming import read_bounded_file
        _require(intent_path==Path(self._manifest['evidence_root'])/'.phase'/'runs'/plan['run_id']/'intent.json',
            'ntfs.original_evidence_path_mismatch')
        intent=parse_json_bytes(read_bounded_file(intent_path,2*1024**2),maximum_bytes=2*1024**2)
        intent_digest=profile_digest('intent',intent)
        _require(intent_digest==expected_intent_digest,'ntfs.original_intent_mismatch')
        parsed=self.read_binding.read(run_id=plan['run_id'],intent_digest=intent_digest)
        effect=parse_json_bytes(parsed.effect_bytes);context=parse_json_bytes(parsed.context_bytes)
        _require(context['operation_nonce']==self._operation_nonce
            and context['effect_plan_digest']==profile_digest('effect-plan',plan)
            and plan['effects']==[effect] and parsed.timestamp==timestamp,'ntfs.original_current_invocation_mismatch')
        from .handoff import ParsedNativeVersion2
        _require(type(parsed) is ParsedNativeVersion2 and not frozen_inputs and intent['inputs']==[]
            and digest_bytes(parsed.content_bytes)==effect['content_digest']
            and len(parsed.content_bytes)==effect['content_length'],'ntfs.original_content_binding_mismatch')
        from ...contracts import load_contract_hook
        hook=load_contract_hook(contract,_native_authority=self)
        hook.before_effect(intent['candidate']['storage']['value'],contract,effect,frozen_inputs,
            roots[effect['target']['root_binding']],Path(self._manifest['evidence_root']),root_bindings=roots)
        from .parent_result import validate_version2_parent_completion,validate_version2_parent_finalization
        validated_receipts=[]
        try:
            self._dispatch_attempted=True
            reply=self.channel.execute_version2(run_id=plan['run_id'],intent_digest=intent_digest)
            # Existing Core remains the evidence owner, including late failures.
            self._response_bytes=canonical_bytes(reply)
            checked=validate_version2_parent_completion(reply,context=context,
                grant_data=parse_json_bytes(parsed.grant_bytes),effect=effect)
            receipt=checked['effect_receipt'];receipt_validator.validate(receipt)
            _require(receipt['started_at']==receipt['finished_at']==timestamp,'ntfs.worker_receipt_binding_mismatch')
            validated_receipts.append(receipt)
            validate_version2_parent_finalization(reply,checked,grant_data=parse_json_bytes(parsed.grant_bytes),effect=effect)
            self._parent_safety_established=True
            self._server_ingress_sealed=True
            return BrokerExecutionResult([receipt])
        except BaseException as error:
            from .channel import NativeChannelError
            remote={}
            try:
                if type(error) is NativeChannelError:
                    primary=error.details.get('primary')
                    details=primary.get('details') if type(primary) is dict else None
                    value=details.get('remote_error') if type(details) is dict else None
                    if type(value) is dict:remote=value
                if remote.get('code')=='ntfs.parent_execution_unresolved':
                    from .failure import make_native_parent_failure
                    self._failure_bytes=make_native_parent_failure(self.read_binding,
                        run_id=plan['run_id'],intent_digest=intent_digest,effect_plan_digest=profile_digest('effect-plan',plan),
                        operation_nonce=self._operation_nonce,remote=remote)
            except BaseException as reporting_error:
                try:error.add_note('Native failure capture unavailable: '+type(reporting_error).__name__)
                except BaseException:pass
            try:
                if remote.get('code')=='ntfs.parent_execution_unresolved' and not validated_receipts:
                    partial=remote['details']['parent_partial']
                    self._response_bytes=canonical_bytes(partial)
                    checked=validate_version2_parent_completion(partial,context=context,
                        grant_data=parse_json_bytes(parsed.grant_bytes),effect=effect)
                    receipt=checked['effect_receipt'];receipt_validator.validate(receipt)
                    _require(receipt['started_at']==receipt['finished_at']==timestamp,'ntfs.worker_receipt_binding_mismatch')
                    validated_receipts.append(receipt)
            except BaseException as secondary:
                try:error.add_note('Native partial completion validation: '+type(secondary).__name__)
                except BaseException:pass
            raise BrokerExecutionInterrupted(error,validated_receipts,None,possible_dispatch=self.channel.possible_dispatch) from error
