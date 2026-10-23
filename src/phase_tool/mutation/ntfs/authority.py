"""DRAFT connected Linux role for a closed native file-create installation.

Not selected, imported, executed or qualified. This is part of the pending whole
Core/Broker/parent/inspect slice. It is not a POSIX AuthorityProvider and never
returns a simulated descriptor. The accepted installation owns its construction;
requests cannot supply a profile, registry, callback, command or root grant.
"""
from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
import threading

from ...canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from ...errors import PhaseError
from ...paths import safe_relative_locator
from ...planning import _build_static_plan_after_root_checks, _idempotency_from_root_records, _validate_logical_plan
from ..guarantees import GuaranteeProfileBinding, verify_guarantee_coverage
from .channel_v2 import LinuxNativeChannelV2
from .native import NativeIdentity, _require
from .worker import _grant
from .parent_result import _observation, validate_parent_completion, validate_parent_finalization


class _NativeFileCreateAuthority:
    """Whole-effect role, not an FD adapter, scheduler or evidence owner.

    The fixed bootstrap must check its accepted executable/runtime/deployment
    graph and candidate-vs-qualified admission BEFORE constructing this role.
    This role repeats descriptor/profile/coverage checks. None of the supplied
    immutable data authenticates the bootstrap itself. Public requests never
    construct this object; the fixed installation selector is still required.
    """

    def __init__(self, read_binding, profile: GuaranteeProfileBinding,
                 root_projections: bytes, channel: LinuxNativeChannelV2, *, run_id: str, operation_nonce: str):
        _require(not getattr(self, '_initialization_attempted', False),
            'ntfs.native_role_initialization_consumed')
        self._initialization_attempted = True
        from ...installation import _NativeFileCreateReadBinding
        _require(type(read_binding) is _NativeFileCreateReadBinding
            and type(profile) is GuaranteeProfileBinding and type(channel) is LinuxNativeChannelV2,
            'ntfs.closed_native_installation_required')
        self.read_binding, self.profile, self.channel = read_binding, profile, channel
        self._manifest = parse_json_bytes(read_binding.manifest_bytes)
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

    @property
    def registry(self):
        return self.read_binding.registry

    def _usable(self):
        _require(self._owner == (os.getpid(), threading.get_ident()) and not self._sealed,
            'ntfs.native_role_unavailable')
        _require(self.registry.digest == self._manifest['registry_snapshot_digest']
            == canonical_digest(self.registry.to_document()), 'ntfs.original_registry_mismatch')
        self._admitted_profile()
        self.read_binding.check_evidence_root()

    def _admitted_profile(self):
        from ...installation import _native_qualified_profile
        admitted = _native_qualified_profile(self.registry,self.profile.as_dict())
        _require(admitted == self.profile, 'guarantee.profile_implementation_mismatch')
        provider = {'id':admitted.implementation_id,'version':admitted.implementation_version,
            'artifact_digest':admitted.implementation_artifact_digest}
        _require(self._manifest['authority'] == {'usage':'provider_backed',
            'profile':admitted.as_dict(),'provider':provider}, 'ntfs.original_implementation_mismatch')
        return self.registry.resolve_guarantee_profile(admitted.as_dict())

    def require_request_roots(self, roots, evidence_root):
        self._usable()
        expected = parse_json_bytes(self._projections_bytes)
        _require(set(roots) == set(expected) and all(str(roots[key]) == value
            for key, value in expected.items()), 'ntfs.installed_root_projection_mismatch')
        _require(str(evidence_root) == self._manifest['evidence_root'],
            'ntfs.original_evidence_identity_mismatch')
        # Lexical projections are NOT target filesystem observations. Do not call
        # resolve/stat/open on them or create a local directory with that name.
        evidence = PurePosixPath(self._manifest['evidence_root'])
        for value in expected.values():
            root = PurePosixPath(value)
            _require(not root.is_relative_to(evidence) and not evidence.is_relative_to(root),
                'evidence.overlaps_target_root')

    def require_contract(self, contract):
        self._usable()
        _require({'id': contract.document['identity']['id'], 'version': contract.document['identity']['version'],
            'package_digest': contract.package_digest} == self._manifest['contract']
            and contract.document['operation']['intent'] == 'create'
            and contract.document['operation']['maximum_effects'] == 1
            and contract.document['operation']['allowed_effects'] == ['exclusive_create']
            and contract.document['operation']['mechanism'] == self._manifest['mechanism'],
            'ntfs.original_single_effect_required')
        mechanisms = [contract.document['operation']['mechanism']]
        _require(not contract.document['operation'].get('effect_mechanisms'),
            'ntfs.original_single_effect_required')
        return verify_guarantee_coverage(contract.document['operation']['required_guarantees'],
            mechanisms, self.profile, self.registry)

    def implementation_binding(self, plan):
        self._usable()
        _require(plan['mechanism'] == self._manifest['mechanism'], 'ntfs.original_implementation_mismatch')
        return parse_json_bytes(canonical_bytes({'authority': self._manifest['authority'],
            'mechanism': plan['mechanism'], 'effect_plan_digest': profile_digest('effect-plan', plan)}))

    def native_binding(self):
        self._usable()
        return parse_json_bytes(canonical_bytes({'native_binding_version': '1.0', 'installation': {
            'id': self._manifest['installation_id'], 'descriptor_digest': self.read_binding.manifest_digest},
            'composition': self._manifest['composition'], 'evidence_identity': self._manifest['evidence_identity'],
            'operation_nonce': self._operation_nonce}))

    def idempotency(self, contract, candidate, frozen, roots):
        self.require_contract(contract)
        self.require_request_roots(roots, Path(self._manifest['evidence_root']))
        value = parse_json_bytes(candidate.canonical_bytes)
        return _idempotency_from_root_records(contract, candidate, frozen,
            locator=safe_relative_locator(value['target_locator']), key=value['idempotency_key'],
            root_identities=parse_json_bytes(canonical_bytes(self._manifest['root_grants'])),
            root_identity_profile='native-root-identity-v1')

    def plan(self, contract, candidate, frozen, results, *, roots, run_id, timestamp, request_digest):
        self.require_contract(contract)
        self.require_request_roots(roots, Path(self._manifest['evidence_root']))
        plan = _build_static_plan_after_root_checks(contract, candidate, frozen, results,
            root_bindings=roots, run_id=run_id, generated_at=timestamp, request_digest=request_digest)
        _validate_logical_plan(plan, contract, self.registry)
        _require(len(plan['effects']) == 1 and plan['effects'][0]['content_length'] <= 1024**2,
            'mechanism.content_too_large')
        return plan

    def observe(self, *, run_id, root_binding, locator, expected_identity=None):
        self._usable()
        grant = parse_json_bytes(self._grant_bytes)
        _require(root_binding == grant['root_binding'], 'ntfs.effect_grant_mismatch')
        locator = safe_relative_locator(locator)
        slot = ('post_operation' if self._dispatch_attempted else 'pre_operation') if run_id == self._run_id else None
        _require(slot is None or slot not in self._observations, 'ntfs.duplicate_current_observation')
        reply = self.channel.observe_file(run_id=run_id, root_binding=root_binding,
            locator=locator, expected_identity=expected_identity)
        value = _observation(reply, grant, locator)
        if expected_identity is not None:
            _require(value['native']['exists'] is True
                and value['native']['native_identity'] == expected_identity, 'ntfs.observer_identity_mismatch')
        if slot is not None:
            self._observations[slot] = canonical_bytes({'run_id': run_id, 'observation': value})
        return value

    def execute(self, plan, contract, frozen_inputs, roots, intent_path, *, timestamp, receipt_validator, expected_intent_digest):
        """Only EffectBroker invokes this after selecting the exact closed role."""
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
        _require(frozen is not None and frozen.digest == digest_bytes(parsed.content_bytes)
            and frozen.length == len(parsed.content_bytes), 'ntfs.original_content_binding_mismatch')
        self._dispatch_attempted = True
        validated_receipts = []
        try:
            reply = self.channel.execute_file_create(run_id=plan['run_id'], intent_digest=intent_digest)
            # Retain exact response BEFORE any validation that could fail. The
            # Core wrapper, not this role, owns the single proof attachment.
            self._response_bytes = canonical_bytes(reply)
            checked = validate_parent_completion(reply, context=context,
                grant_data=parse_json_bytes(parsed.grant_bytes), effect=effect)
            receipt = checked['effect_receipt']
            receipt_validator.validate(receipt)
            _require(receipt['started_at'] == receipt['finished_at'] == timestamp,
                'ntfs.worker_receipt_binding_mismatch')
            # Retain an already schema-valid/context-bound receipt through late
            # observation/owner failures. possible_dispatch still forces the
            # existing Core to classify interruption as indeterminate.
            validated_receipts.append(receipt)
            validate_parent_finalization(reply, checked,
                grant_data=parse_json_bytes(parsed.grant_bytes), effect=effect)
            self._parent_safety_established = True
            self._server_ingress_sealed = True
            return BrokerExecutionResult([receipt])
        except BaseException as error:
            # A closed negative parent response may contain an already received
            # worker completion. Validate that receipt before retaining it in
            # Core's EXISTING interruption/effect attachment; never claim worker
            # quiescence or discharge an original from this partial response.
            try:
                from .channel import NativeChannelError
                if type(error) is NativeChannelError and not validated_receipts:
                    remote=error.details.get('primary',{}).get('details',{}).get('remote_error',{})
                    if remote.get('code')=='ntfs.parent_execution_unresolved':
                        try:
                            from .failure import make_native_parent_failure
                            self._failure_bytes=make_native_parent_failure(self.read_binding,
                                run_id=plan['run_id'],intent_digest=intent_digest,
                                effect_plan_digest=profile_digest('effect-plan',plan),
                                operation_nonce=self._operation_nonce,remote=remote)
                        except BaseException as reporting_error:
                            try:error.add_note('Native failure capture unavailable: '+type(reporting_error).__name__)
                            except BaseException:pass
                        # Optional diagnostic formatting MUST NOT discard an
                        # independently schema/context-valid partial receipt.
                        partial=remote['details']['parent_partial']
                        self._response_bytes=canonical_bytes(partial)
                        checked=validate_parent_completion(partial,context=context,
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

    def expected_after_identity(self, effect):
        self._usable()
        if not self._parent_safety_established or self._response_bytes is None:
            return None
        completion = parse_json_bytes(self._response_bytes)['completion']
        physical = completion['physical_evidence']
        _require(physical['effect_id'] == effect['effect_id']
            and physical['locator'] == effect['target']['relative_locator'],
            'ntfs.worker_observer_mismatch')
        after = physical['after']
        return None if after is None else after['native_identity']

    def seal(self, *, intent_digest: str | None):
        # One finite no-dispatch exchange only when no execute could have been
        # sent. A complete execute ACK already established consumed ingress.
        # Neither path closes descriptors, revokes OS privileges or persists.
        _require(not self._seal_attempted, 'ntfs.native_role_seal_consumed')
        self._seal_attempted = True
        self._sealed = True
        _require(self._owner == (os.getpid(), threading.get_ident()), 'ntfs.native_role_owner_changed')
        if not self._parent_safety_established:
            _require(not self._dispatch_attempted and not self.channel.possible_dispatch,
                'ntfs.native_parent_completion_unresolved')
            response = self.channel.finish_without_execution(run_id=self._run_id,
                intent_digest=intent_digest, operation_nonce=self._operation_nonce,
                installation_digest=self.read_binding.manifest_digest)
            self._finish_bytes = canonical_bytes(response)
            expected = {'finish_ack_version': '1.0', 'run_id': self._run_id,
                'intent_digest': intent_digest, 'operation_nonce': self._operation_nonce,
                'installation_digest': self.read_binding.manifest_digest,
                'ingress_state': 'consumed', 'worker_started': False,
                'worker_spawn_attempted': False, 'worker_count': 0,
                'required_resources_finalized': True}
            # Canonical comparison distinguishes bool/int at every nested field.
            _require(canonical_bytes(response) == canonical_bytes(expected),
                'ntfs.native_finish_binding_mismatch')
            self._no_dispatch_safety_established = True
            self._server_ingress_sealed = True
        self.channel.seal()
        self._channel_sealed = True

    def prepared_physical_proof(self):
        """Exact transient facts for the existing Core evidence owner."""
        _require(self._seal_attempted, 'ntfs.native_role_seal_not_attempted')
        return {'parent_response': None if self._response_bytes is None else parse_json_bytes(self._response_bytes),
            'run_id': self._run_id,
            'observations': {slot: parse_json_bytes(raw) for slot, raw in self._observations.items()},
            'possible_dispatch': self.channel.possible_dispatch, 'local_channel_sealed': self._channel_sealed,
            'parent_safety_established': self._parent_safety_established,
            'no_dispatch_safety_established': self._no_dispatch_safety_established,
            'server_ingress_sealed': self._server_ingress_sealed,
            'no_dispatch_finalization': None if self._finish_bytes is None else parse_json_bytes(self._finish_bytes)}
