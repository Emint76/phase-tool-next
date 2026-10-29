"""Bundle-only extension of the unchanged historical native authority.

This new provider reuses the existing lifecycle, seal, proof and receipt owner.
Its closed constructor is needed because the frozen provider rejects generation
1.6; no old provider artifact or descriptor is modified for this experiment.
"""
import os
import re
from pathlib import Path, PurePosixPath
import threading

from ...canonical import canonical_bytes, parse_json_bytes, profile_digest
from ...paths import safe_relative_locator
from ..guarantees import GuaranteeProfileBinding
from .experimental_authority import _ExperimentalFile1Authority
from .experimental_bundle1 import _ExperimentalBundle1Admission
from .bundle_execution import _BUNDLE1_CONTRACT
from .channel_v4 import LinuxNativeBundleChannel
from .native import _require
from .worker import _grant


class _ExperimentalBundle1Authority(_ExperimentalFile1Authority):
    def __init__(self, read_binding, profile: GuaranteeProfileBinding,
                 root_projections: bytes, channel: LinuxNativeBundleChannel, *, run_id: str, operation_nonce: str,
                 _inspection_only: bool = False):
        _require(not getattr(self, '_initialization_attempted', False),
            'ntfs.native_role_initialization_consumed')
        self._initialization_attempted = True
        _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
        self._inspection_only = _inspection_only
        from ...installation import _NativeFileCreateReadBinding
        _require(type(read_binding) is _NativeFileCreateReadBinding
            and type(profile) is GuaranteeProfileBinding and type(channel) is LinuxNativeBundleChannel,
            'ntfs.closed_native_installation_required')
        _require(channel._inspection_only is _inspection_only, 'ntfs.fixed_role_mismatch')
        self.read_binding, self.profile, self.channel = read_binding, profile, channel
        self._manifest = parse_json_bytes(read_binding.manifest_bytes)
        _require(self._manifest['native_read_installation_version']=='1.6'
            and self._manifest['contract']==_BUNDLE1_CONTRACT,'ntfs.fixed_role_mismatch')
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
        _require(type(admission) is _ExperimentalBundle1Admission,
            'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'],
            'version': contract.document['identity']['version'], 'package_digest': contract.package_digest}
            == self._manifest['contract'] == _BUNDLE1_CONTRACT
            and operation['intent'] == 'create' and operation['maximum_effects'] == 1
            and operation['allowed_effects'] == ['exclusive_create']
            and {k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')}
            == self._manifest['mechanism']
            and not operation.get('effect_mechanisms'), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'],
            [operation['mechanism']])

    def freeze_inputs(self,contract,request,candidate,blob_root,*,frozen_at):
        """Capture only checked ext4 preparation into the same Core blob store."""
        self._execution_required()
        self.require_contract(contract)
        _require(request.run_id==self._run_id and type(candidate) is dict
            and candidate.get('input_binding')=='payload'
            and set(request.input_paths)=={'payload'},
            'ntfs.original_bundle_effect_required')
        # Repeat the existing preparation/evidence/ownership/mount admission at
        # this capture boundary; target projections are never resolved/stat'ed.
        from ...installation import _NativeFileCreateInstallation
        checked=_NativeFileCreateInstallation(self.read_binding,self)
        evidence=checked.check_request(request)
        _require(blob_root==evidence/'.phase'/'runs'/self._run_id/'blobs',
            'ntfs.original_evidence_path_mismatch')
        from ...bundle import freeze_bundle
        frozen=freeze_bundle('payload',Path(request.input_paths['payload']),candidate['members'],
            blob_root,frozen_at=frozen_at)
        checked.check_request(request)
        return {'payload':frozen}

    def observe(self, *, run_id, root_binding, locator, expected_identity=None):
        self._usable()
        _require(not self._version1,'ntfs.original_closed_role_required')
        grant = parse_json_bytes(self._grant_bytes)
        _require(root_binding == grant['root_binding'], 'ntfs.effect_grant_mismatch')
        locator = safe_relative_locator(locator)
        # Independent inspection can revisit current and reused historical runs.
        # These reads are not causal slots for a new executing invocation.
        slot = (('post_operation' if self._dispatch_attempted else 'pre_operation')
            if not self._inspection_only and run_id == self._run_id else None)
        _require(slot is None or slot not in self._observations, 'ntfs.duplicate_current_observation')
        reply = self.channel.observe_file(run_id=run_id, root_binding=root_binding,
            locator=locator, expected_identity=expected_identity)
        from .bundle_execution import validate_bundle_observation
        value=validate_bundle_observation(reply,grant,locator)
        if expected_identity is not None:
            _require(value['native']['exists'] is True
                and value['native']['native_identity'] == expected_identity, 'ntfs.observer_identity_mismatch')
        if slot is not None:
            self._observations[slot] = canonical_bytes({'run_id': run_id, 'observation': value})
        return value

    def execute(self, plan, contract, frozen_inputs, roots, intent_path, *, timestamp, receipt_validator, expected_intent_digest):
        """Only EffectBroker invokes this after selecting the exact closed role."""
        self._execution_required()
        from ..broker import BrokerExecutionInterrupted, BrokerExecutionResult
        self.require_contract(contract)
        self.require_request_roots(roots, Path(self._manifest['evidence_root']))
        _require(not self._dispatch_attempted, 'ntfs.channel_execution_consumed')
        _require(plan['run_id'] == self._run_id, 'ntfs.original_current_invocation_mismatch')
        from ...streaming import read_bounded_file
        _require(intent_path == Path(self._manifest['evidence_root']) / '.phase' / 'runs'
            / plan['run_id'] / 'intent.json', 'ntfs.original_evidence_path_mismatch')
        parsed_intent = parse_json_bytes(read_bounded_file(intent_path, 2*1024**2), maximum_bytes=2*1024**2)
        intent_digest = profile_digest('intent', parsed_intent)
        _require(intent_digest == expected_intent_digest, 'ntfs.original_intent_mismatch')
        parsed = self.read_binding.read(run_id=plan['run_id'], intent_digest=intent_digest)
        effect = parse_json_bytes(parsed.effect_bytes)
        context = parse_json_bytes(parsed.context_bytes)
        _require(context['operation_nonce'] == self._operation_nonce
            and context['effect_plan_digest'] == profile_digest('effect-plan', plan)
            and plan['effects'] == [effect] and parsed.timestamp == timestamp,
            'ntfs.original_current_invocation_mismatch')
        frozen = frozen_inputs.get(effect['input_binding'])
        from ...freeze import FrozenInput
        from .handoff import _BundleControlProjection
        _require(type(parsed) is _BundleControlProjection and type(frozen) is FrozenInput
            and frozen.binding_id==parsed.input_binding=='payload'
            and frozen.strategy=='manifest_and_hash' and frozen.streamed is True
            and type(frozen.length) is int and frozen.length==parsed.content_length
            and frozen.digest==frozen.blob_digest==parsed.content_digest
            and canonical_bytes(frozen.intent_record())==canonical_bytes(parsed_intent['inputs'][0])
            and frozen.blob_path==intent_path.parent/'blobs'/parsed.content_digest.removeprefix('sha256:'),
            'ntfs.original_content_binding_mismatch')
        from .bundle_execution import validate_bundle_parent_completion,validate_bundle_parent_finalization
        completion_check=validate_bundle_parent_completion
        def finalization_check(reply,checked,*,grant_data,effect):
            return validate_bundle_parent_finalization(reply,checked,grant_data=grant_data,
                effect=effect,projection=parsed,expected_channel_id=self.channel.channel_id)
        validated_receipts = []
        try:
            from .bundle_stream import _bundle_verified_source
            compact={k:context[k]for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
            manager=_bundle_verified_source(intent_path.parent/'blobs',context_bytes=canonical_bytes(compact),
                channel_id=self.channel.channel_id,manifest_bytes=parsed.manifest_bytes)
            with manager as source:
                self._dispatch_attempted=True
                reply=self.channel.execute_bundle(run_id=plan['run_id'],intent_digest=intent_digest,
                    projection=parsed,source=source)
                # Retain exact response BEFORE any validation that could fail. The
                # Core wrapper, not this role, owns the single proof attachment.
                self._response_bytes = canonical_bytes(reply)
                checked = completion_check(reply, context=context,
                    grant_data=parse_json_bytes(parsed.grant_bytes), effect=effect)
                receipt = checked['effect_receipt']
                receipt_validator.validate(receipt)
                _require(receipt['started_at'] == receipt['finished_at'] == timestamp,
                    'ntfs.worker_receipt_binding_mismatch')
                # Retain an already schema-valid/context-bound receipt through late
                # observation/owner failures. possible_dispatch still forces the
                # existing Core to classify interruption as indeterminate.
                validated_receipts.append(receipt)
                finalization_check(reply, checked,
                    grant_data=parse_json_bytes(parsed.grant_bytes), effect=effect)
            self._parent_safety_established = True
            self._server_ingress_sealed = True
            return BrokerExecutionResult([receipt])
        except BaseException as error:
            # A closed negative parent response may contain an already received
            # worker completion. Validate that receipt before retaining it in
            # Core's EXISTING interruption/effect attachment; never claim worker
            # quiescence or discharge an original from this partial response.
            # Negative raw evidence is independent of an optional effect receipt.
            # Capture it BEFORE any partial-completion validation can throw.
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
                        run_id=plan['run_id'],intent_digest=intent_digest,
                        effect_plan_digest=profile_digest('effect-plan',plan),
                        operation_nonce=self._operation_nonce,remote=remote)
            except BaseException as reporting_error:
                try:error.add_note('Native failure capture unavailable: '+type(reporting_error).__name__)
                except BaseException:pass
            try:
                if not validated_receipts:
                    captured=self.channel.captured_file2_completion()
                    if captured is not None:
                        self._response_bytes=captured
                        partial=parse_json_bytes(captured,maximum_bytes=2*1024**2)
                        checked=completion_check(partial,context=context,
                            grant_data=parse_json_bytes(parsed.grant_bytes),effect=effect)
                        receipt=checked['effect_receipt']
                        receipt_validator.validate(receipt)
                        _require(receipt['started_at']==receipt['finished_at']==timestamp,
                            'ntfs.worker_receipt_binding_mismatch')
                        validated_receipts.append(receipt)
                if remote.get('code')=='ntfs.parent_execution_unresolved' and not validated_receipts:
                    # Optional diagnostic formatting MUST NOT discard an
                    # independently schema/context-valid partial receipt.
                    partial=remote['details']['parent_partial']
                    self._response_bytes=canonical_bytes(partial)
                    checked=completion_check(partial,context=context,
                        grant_data=parse_json_bytes(parsed.grant_bytes),effect=effect)
                    receipt=checked['effect_receipt']
                    receipt_validator.validate(receipt)
                    _require(receipt['started_at']==receipt['finished_at']==timestamp,
                        'ntfs.worker_receipt_binding_mismatch')
                    validated_receipts.append(receipt)
            except BaseException as secondary:
                try:error.add_note('Native partial completion validation: '+type(secondary).__name__)
                except BaseException:pass
            raise BrokerExecutionInterrupted(error, validated_receipts, None, possible_dispatch=self.channel.possible_dispatch) from error
