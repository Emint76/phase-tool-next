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
from .channel_v3 import LinuxNativeChannelV3
from .channel_v4 import LinuxNativeChannelV4
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
                 root_projections: bytes, channel: LinuxNativeChannelV2, *, run_id: str, operation_nonce: str,
                 _inspection_only: bool = False):
        _require(not getattr(self, '_initialization_attempted', False),
            'ntfs.native_role_initialization_consumed')
        self._initialization_attempted = True
        _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
        self._inspection_only = _inspection_only
        from ...installation import _NativeFileCreateReadBinding
        _require(type(read_binding) is _NativeFileCreateReadBinding
            and type(profile) is GuaranteeProfileBinding and type(channel) in (LinuxNativeChannelV2,LinuxNativeChannelV3,LinuxNativeChannelV4),
            'ntfs.closed_native_installation_required')
        _require(channel._inspection_only is _inspection_only, 'ntfs.fixed_role_mismatch')
        self.read_binding, self.profile, self.channel = read_binding, profile, channel
        self._manifest = parse_json_bytes(read_binding.manifest_bytes)
        self._version1 = self._manifest['contract']['id'] == 'publish_new_version.v1'
        self._file2 = self._manifest['contract']['id']=='file_create.v2'
        generation = self._manifest['native_read_installation_version']
        _require(generation in {'1.1','1.2','1.3','1.4'}, 'ntfs.fixed_role_mismatch')
        if generation == '1.4':
            # Composition generation does not create a worker/channel protocol.
            matching = (type(channel) is LinuxNativeChannelV4 if self._file2 else
                type(channel) is LinuxNativeChannelV3 and channel._version1 is self._version1)
            _require(self._manifest['contract']['id'] in {
                'file_create.v1','publish_new_version.v1','file_create.v2'} and matching,
                'ntfs.fixed_role_mismatch')
        else:
            _require((not self._version1 or generation == '1.2')
                and (type(channel) is LinuxNativeChannelV4 and self._file2
                    if generation == '1.3' else
                    not self._file2 and (type(channel) is LinuxNativeChannelV3 and channel._version1 is self._version1
                    if generation == '1.2' else type(channel) is LinuxNativeChannelV2 and not self._version1)),
                'ntfs.fixed_role_mismatch')
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
        operation = contract.document['operation']
        _require({'id':contract.document['identity']['id'],'version':contract.document['identity']['version'],
            'package_digest':contract.package_digest} == self._manifest['contract']
            and operation['intent'] == ('publish_new_version' if self._version1 else 'create')
            and operation['maximum_effects'] == 1
            and operation['allowed_effects'] == (['publish_new_version'] if self._version1 else ['exclusive_create'])
            and operation['mechanism'] == self._manifest['mechanism'],
            'ntfs.original_single_effect_required')
        mechanisms = [contract.document['operation']['mechanism']]
        _require(not contract.document['operation'].get('effect_mechanisms'),
            'ntfs.original_single_effect_required')
        return verify_guarantee_coverage(contract.document['operation']['required_guarantees'],
            mechanisms, self.profile, self.registry)

    def _execution_required(self):
        _require(not self._inspection_only, 'ntfs.inspection_only_operation_forbidden')

    def implementation_binding(self, plan):
        self._execution_required()
        self._usable()
        _require(plan['mechanism'] == self._manifest['mechanism'], 'ntfs.original_implementation_mismatch')
        return parse_json_bytes(canonical_bytes({'authority': self._manifest['authority'],
            'mechanism': plan['mechanism'], 'effect_plan_digest': profile_digest('effect-plan', plan)}))

    def native_binding(self):
        self._execution_required()
        self._usable()
        return parse_json_bytes(canonical_bytes({'native_binding_version': '1.0', 'installation': {
            'id': self._manifest['installation_id'], 'descriptor_digest': self.read_binding.manifest_digest},
            'composition': self._manifest['composition'], 'evidence_identity': self._manifest['evidence_identity'],
            'operation_nonce': self._operation_nonce}))

    def idempotency(self, contract, candidate, frozen, roots):
        self._execution_required()
        self.require_contract(contract)
        self.require_request_roots(roots, Path(self._manifest['evidence_root']))
        value = parse_json_bytes(candidate.canonical_bytes)
        return _idempotency_from_root_records(contract, candidate, frozen,
            locator=safe_relative_locator(value['target_locator']), key=value['idempotency_key'],
            root_identities=parse_json_bytes(canonical_bytes(self._manifest['root_grants'])),
            root_identity_profile='native-root-identity-v1')

    def plan(self, contract, candidate, frozen, results, *, roots, run_id, timestamp, request_digest):
        self._execution_required()
        self.require_contract(contract)
        self.require_request_roots(roots, Path(self._manifest['evidence_root']))
        plan = _build_static_plan_after_root_checks(contract, candidate, frozen, results,
            root_bindings=roots, run_id=run_id, generated_at=timestamp, request_digest=request_digest,
            _native_authority=self)
        _validate_logical_plan(plan, contract, self.registry)
        _require(len(plan['effects']) == 1 and plan['effects'][0]['content_length'] <= (2*1024**3 if self._file2 else 16*1024**2 if self._version1 else 1024**2),
            'mechanism.content_too_large')
        return plan

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
        if self._file2:
            from .file2_execution import validate_file2_observation
            value=validate_file2_observation(reply,grant,locator)
        else:
            value = _observation(reply, grant, locator)
        if expected_identity is not None:
            _require(value['native']['exists'] is True
                and value['native']['native_identity'] == expected_identity, 'ntfs.observer_identity_mismatch')
        if slot is not None:
            self._observations[slot] = canonical_bytes({'run_id': run_id, 'observation': value})
        return value

    def hook_root_binding(self, root):
        self._usable()
        projections = parse_json_bytes(self._projections_bytes)
        matches = [key for key,value in projections.items() if str(root) == value]
        _require(len(matches) == 1,'ntfs.installed_root_projection_mismatch')
        return matches[0]

    def observe_advisory(self, *, root_binding, locator, expected_identity=None):
        self._usable()
        _require(self._version1,'ntfs.original_closed_role_required')
        grant = parse_json_bytes(self._grant_bytes)
        _require(root_binding == grant['root_binding'],'ntfs.effect_grant_mismatch')
        locator = safe_relative_locator(locator)
        from .version1_observation import validate_version1_observation
        reply = self.channel.observe_file(run_id=self._run_id,root_binding=root_binding,
            locator=locator,expected_identity=expected_identity)
        value = validate_version1_observation(reply,grant,locator)
        if expected_identity is not None:
            _require(value['native']['exists'] is True
                and value['native']['native_identity'] == expected_identity,'ntfs.observer_identity_mismatch')
        # Never enter a causal slot: planning, prechecks, prior classification,
        # before-effect and independent inspect each obtain their own samples.
        return value

    def observe_version1_post_pair(self, *, run_id, effect):
        self._execution_required()
        self._usable()
        _require(self._version1 and run_id == self._run_id and self._dispatch_attempted
            and self._parent_safety_established and not self._version1_post_attempted,
            'ntfs.native_parent_completion_unresolved')
        # Consume before any fallible expected-ID check/read/validation. A
        # failed pair has no positive record and can never obtain a new slot.
        self._version1_post_attempted = True
        expected = self.expected_after_identity(effect)
        _require(type(expected) is dict and set(expected) == {'current','archive'},
            'ntfs.worker_observer_mismatch')
        pair = {'observation_pair_version':'1.0',
            'current':self.observe_advisory(root_binding=effect['target']['root_binding'],
                locator=effect['target']['relative_locator'],expected_identity=expected['current']),
            'archive':self.observe_advisory(root_binding=effect['archive_target']['root_binding'],
                locator=effect['archive_target']['relative_locator'],expected_identity=expected['archive'])}
        from .parent_result import validate_version1_pair
        pair = validate_version1_pair(pair,parse_json_bytes(self._grant_bytes),effect)
        self._observations['post_operation'] = canonical_bytes({'run_id':run_id,'observation':pair})
        return pair

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
        if self._file2:
            from ...freeze import FrozenInput
            from .handoff import _OriginalControlProjection
            _require(type(parsed) is _OriginalControlProjection and type(frozen) is FrozenInput
                and frozen.binding_id==parsed.input_binding=='payload'
                and frozen.strategy=='copy_and_hash' and frozen.streamed is True
                and type(frozen.length) is int and frozen.length==parsed.content_length
                and frozen.digest==frozen.blob_digest==parsed.content_digest
                and canonical_bytes(frozen.intent_record())==canonical_bytes(parsed_intent['inputs'][0])
                and frozen.blob_path==intent_path.parent/'blobs'/parsed.content_digest.removeprefix('sha256:'),
                'ntfs.original_content_binding_mismatch')
        else:
            _require(frozen is not None and frozen.digest == digest_bytes(parsed.content_bytes)
                and frozen.length == len(parsed.content_bytes), 'ntfs.original_content_binding_mismatch')
        if self._version1:
            from ...contracts import load_contract_hook
            hook = load_contract_hook(contract,_native_authority=self)
            hook.before_effect(parsed_intent['candidate']['storage']['value'],contract,effect,
                frozen_inputs,roots[effect['target']['root_binding']],Path(self._manifest['evidence_root']),
                root_bindings=roots)
        from .parent_result import validate_version1_parent_completion,validate_version1_parent_finalization
        completion_check = validate_version1_parent_completion if self._version1 else validate_parent_completion
        finalization_check = validate_version1_parent_finalization if self._version1 else validate_parent_finalization
        if self._file2:
            from .file2_execution import validate_file2_parent_completion,validate_file2_parent_finalization
            completion_check=validate_file2_parent_completion
            def finalization_check(reply,checked,*,grant_data,effect):
                return validate_file2_parent_finalization(reply,checked,grant_data=grant_data,
                    effect=effect,expected_channel_id=self.channel.channel_id)
        validated_receipts = []
        try:
            from contextlib import nullcontext
            if self._file2:
                from .file2_stream import _file2_verified_source
                compact={k:context[k] for k in ('run_id','intent_digest','installation_digest','operation_nonce')}
                manager=_file2_verified_source(frozen.blob_path,context_bytes=canonical_bytes(compact),
                    channel_id=self.channel.channel_id,content_digest=parsed.content_digest,
                    content_length=parsed.content_length)
            else:manager=nullcontext(None)
            with manager as source:
                self._dispatch_attempted = True
                if self._file2:
                    reply=self.channel.execute_file2(run_id=plan['run_id'],intent_digest=intent_digest,
                        projection=parsed,source=source)
                else:
                    execute=self.channel.execute_version1 if self._version1 else self.channel.execute_file_create
                    reply=execute(run_id=plan['run_id'],intent_digest=intent_digest)
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
                if self._file2 and not validated_receipts:
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

    def expected_after_identity(self, effect):
        self._execution_required()
        self._usable()
        if not self._parent_safety_established or self._response_bytes is None:
            return None
        completion = parse_json_bytes(self._response_bytes)['completion']
        physical = completion['physical_evidence']
        _require(physical['effect_id'] == effect['effect_id']
            and physical['locator'] == effect['target']['relative_locator'],
            'ntfs.worker_observer_mismatch')
        if self._version1:
            _require(physical['archive_locator'] == effect['archive_target']['relative_locator'],
                'ntfs.worker_observer_mismatch')
            from .native import NativeIdentity
            current,archive = physical['after'],physical['archive_after']
            _require(type(current) is dict and type(archive) is dict,
                'ntfs.worker_observer_mismatch')
            current_id = NativeIdentity.parse(current['native_identity']) if current['exists'] else None
            archive_id = NativeIdentity.parse(archive['native_identity']) if archive['exists'] else None
            _require(current_id is None or archive_id is None or current_id != archive_id,
                'ntfs.version1_current_archive_alias')
            return {'current':None if current_id is None else current_id.as_dict(),
                'archive':None if archive_id is None else archive_id.as_dict()}
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
        if self._inspection_only:
            # Read role started with consumed parent GO. No original-query,
            # executing nonce, finish exchange or mutation proof is applicable.
            # Failed channel cannot deliver even a rendered positive inspect.
            self.channel._usable()
            _require(not self._dispatch_attempted and not self.channel.possible_dispatch,
                'ntfs.inspection_only_operation_forbidden')
            self.channel.seal()
            self._channel_sealed = True
            return
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
        self._execution_required()
        _require(self._seal_attempted, 'ntfs.native_role_seal_not_attempted')
        return {'parent_response': None if self._response_bytes is None else parse_json_bytes(self._response_bytes),
            'run_id': self._run_id,
            'observations': {slot: parse_json_bytes(raw) for slot, raw in self._observations.items()},
            'possible_dispatch': self.channel.possible_dispatch, 'local_channel_sealed': self._channel_sealed,
            'parent_safety_established': self._parent_safety_established,
            'no_dispatch_safety_established': self._no_dispatch_safety_established,
            'server_ingress_sealed': self._server_ingress_sealed,
            'no_dispatch_finalization': None if self._finish_bytes is None else parse_json_bytes(self._finish_bytes)}
