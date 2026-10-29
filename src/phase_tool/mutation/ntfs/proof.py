"""DRAFT native terminal attachment in the EXISTING Core evidence store.

No receipt owner, mutation, recovery permission, journal or persistent index.
Readonly verification never fsyncs. A separately checked successor may confirm
current ext4 durability under the original common lock; this module cannot.
Not installed, imported, executed or qualified.
"""
from __future__ import annotations

from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ...errors import PhaseError
from ...evidence import validate_intent, validate_receipt, validate_run_id
from ...streaming import read_bounded_file
from .native import _require
from .parent_result import _observation, validate_parent_completion, validate_parent_finalization


_RESOURCE = 'schemas/native-terminal-proof-1.0.schema.json'
_PROOF = 'native-terminal-proof.json'
_CONTROL = 2*1024**2


def _schema(binding, manifest):
    registry = binding.registry
    exact = manifest['contract']
    contract = registry.resolve_contract(exact['id'], exact['version'], exact['package_digest'],
        core_version=manifest['core']['version'])
    pins = [row['digest'] for row in contract.entry['package_artifacts']
        if row['resource'] == _RESOURCE]
    _require(len(pins) == 1, 'ntfs.native_proof_schema_unbound')
    schema = registry.schema_document('https://phase-tool.local/'+_RESOURCE, pins[0])
    return Draft202012Validator(schema, format_checker=FormatChecker(),
        registry=registry.schema_registry())


def _facts(binding, manifest, receipt, proof):
    """Historical trusted-parent claims, not authentication by self-report."""
    physical = proof['physical']
    _require(physical['run_id'] == receipt['run_id']
        and physical['local_channel_sealed'] is True
        and physical['server_ingress_sealed'] is True
        and proof['common_guard_finalized'] is True, 'ntfs.native_terminal_unresolved')
    key = proof['idempotency']
    _require(all(type(key[name]) is bool for name in ('enter_started','entered','finalized'))
        and (key['enter_started'],key['entered'],key['finalized'])
            in {(False,False,False),(True,True,True)},
        'ntfs.native_idempotency_finalization_unknown')
    ran, no_dispatch = physical['parent_safety_established'], physical['no_dispatch_safety_established']
    _require(type(ran) is bool and type(no_dispatch) is bool and ran != no_dispatch,
        'ntfs.native_terminal_unresolved')
    version1 = manifest['contract']['id'] == 'publish_new_version.v1'
    version2 = manifest['contract']['id'] == 'publish_new_version.v2'
    file2=manifest['contract']['id']=='file_create.v2'
    bundle=manifest['contract']['id']=='bundle_create.v1'
    grant = manifest['root_grants'] if version2 else manifest['root_grants'][0]
    _require(set(physical['observations']) <= {'pre_operation','post_operation'},
        'ntfs.native_proof_shape')
    for wrapped in physical['observations'].values():
        _require(set(wrapped) == {'run_id','observation'} and wrapped['run_id'] == receipt['run_id'],
            'ntfs.native_proof_shape')
        item = wrapped['observation']
        if bundle:
            from .bundle_execution import validate_bundle_observation
            validate_bundle_observation(item,grant,item['locator'])
        elif file2:
            from .file2_execution import validate_file2_observation
            validate_file2_observation(item,grant,item['locator'])
        elif not version1 and not version2:
            _observation(item, grant, item['locator'])
    if no_dispatch:
        _require(not (version1 or version2) or not physical['observations'],'ntfs.native_proof_shape')
        _require(physical['possible_dispatch'] is False and physical['parent_response'] is None,
            'ntfs.native_terminal_unresolved')
        ack = physical['no_dispatch_finalization']
        _require(type(ack) is dict and type(ack.get('operation_nonce')) is str
            and re.fullmatch('[0-9a-f]{32}', ack['operation_nonce']) is not None,
            'ntfs.native_finish_binding_mismatch')
        expected = {'finish_ack_version':'1.0','run_id':receipt['run_id'],
            'intent_digest':receipt['evidence']['intent_digest'],
            'operation_nonce':ack['operation_nonce'], 'installation_digest':binding.manifest_digest,
            'ingress_state':'consumed','worker_started':False,'worker_spawn_attempted':False,
            'worker_count':0,'required_resources_finalized':True}
        _require(canonical_bytes(ack) == canonical_bytes(expected), 'ntfs.native_finish_binding_mismatch')
        _require(receipt['execution_disposition'] != 'executed'
            and receipt['mutation_attempted'] is False, 'ntfs.native_terminal_unresolved')
        return ack['operation_nonce'], None
    _require(physical['possible_dispatch'] is True and physical['no_dispatch_finalization'] is None
        and receipt['evidence']['intent_digest'] is not None, 'ntfs.native_terminal_unresolved')
    parsed = binding.read(run_id=receipt['run_id'], intent_digest=receipt['evidence']['intent_digest'])
    context = parse_json_bytes(parsed.context_bytes)
    effect = parse_json_bytes(parsed.effect_bytes)
    raw = physical['parent_response']
    from .parent_result import validate_version1_parent_completion,validate_version1_parent_finalization,validate_version1_pair
    completion_check = validate_version1_parent_completion if version1 else validate_parent_completion
    finalization_check = validate_version1_parent_finalization if version1 else validate_parent_finalization
    if version2:
        from .parent_result import validate_version2_parent_completion,validate_version2_parent_finalization
        completion_check=validate_version2_parent_completion
        finalization_check=validate_version2_parent_finalization
    if file2:
        from .file2_execution import validate_file2_parent_completion,validate_file2_parent_finalization
        completion_check=validate_file2_parent_completion
        finalization_check=validate_file2_parent_finalization
    if bundle:
        from .bundle_execution import validate_bundle_parent_completion,validate_bundle_parent_finalization
        completion_check=validate_bundle_parent_completion
        def finalization_check(reply,checked,*,grant_data,effect):
            return validate_bundle_parent_finalization(reply,checked,grant_data=grant_data,
                effect=effect,projection=parsed)
    checked = completion_check(raw, context=context, grant_data=grant, effect=effect)
    _require(len(receipt['effect_receipts']) == 1
        and checked['effect_receipt'] == receipt['effect_receipts'][0]
        and checked['effect_receipt']['started_at'] == checked['effect_receipt']['finished_at'] == parsed.timestamp,
        'ntfs.native_effect_receipt_mismatch')
    observed = finalization_check(raw, checked, grant_data=grant, effect=effect)
    if version1 or version2:
        _require(set(physical['observations']) <= {'post_operation'},'ntfs.native_proof_shape')
        for wrapped in physical['observations'].values():
            if version2:
                from .version2_observation import validate_version2_triple
                pair=validate_version2_triple(wrapped['observation'],grant,effect)
            else:pair = validate_version1_pair(wrapped['observation'],grant,effect)
            # The causal Core post sample must refer to the SAME two objects
            # independently pinned by the parent's post-worker observation.
            # Byte states may change and truthfully fail postvalidation; equal
            # bytes on substituted objects cannot discharge this proof.
            _require(all(observed[name]['native']['native_identity'] is None or
                pair[name]['native']['native_identity'] == observed[name]['native']['native_identity']
                for name in (('current','old_object','new_object') if version2 else ('current','archive'))),
                'ntfs.native_identity_mismatch')
    _require(receipt['execution_disposition'] == 'executed' and receipt['mutation_attempted'] is True,
        'ntfs.native_terminal_unresolved')
    identity = ({name:observed[name]['native']['native_identity'] for name in
        (('current','old_object','new_object') if version2 else ('current','archive'))}
        if version1 or version2 else observed['native']['native_identity'])
    return context['operation_nonce'], identity


def _verify_original_semantics(binding, manifest, receipt, proof):
    digest = receipt['evidence']['intent_digest']
    if digest is None:return
    run = Path(manifest['evidence_root'])/'.phase'/'runs'/receipt['run_id']
    intent,_ = _canonical(run/'intent.json')
    # ONE existing full semantic parser, with a non-dispatching planned wrapper.
    if intent['execution_requested'] is True:
        binding.read(run_id=receipt['run_id'],intent_digest=digest)
    else:
        binding.validate_planned(run_id=receipt['run_id'],intent_digest=digest)
    plan,_ = _canonical(run/'attachments'/'effect-plan.json')
    pre_name = ('pre-validator-results.json' if intent['execution_requested']
        else 'validator-results.json')
    pre,_ = _canonical(run/'attachments'/pre_name)
    _require(receipt['implementation_binding'] == intent['implementation_binding']
        and receipt['started_at'] == receipt['finished_at'] == intent['created_at'],
        'ntfs.native_receipt_semantic_mismatch')
    if receipt['terminal_status'] == 'validated_planned':
        _require(intent['execution_requested'] is False
            and canonical_bytes(receipt['validator_results']) == canonical_bytes(pre),
            'ntfs.native_receipt_semantic_mismatch')
    if receipt['execution_disposition'] != 'executed':return
    from ...core import _classify_effect_outcome,PhaseCore
    exact = manifest['contract']
    contract = binding.registry.resolve_contract(exact['id'],exact['version'],exact['package_digest'],
        core_version=manifest['core']['version'])
    effects = receipt['effect_receipts']
    _require(len(effects) == len(plan['effects']) == 1
        and effects[0]['attempted'] is True, 'ntfs.native_receipt_semantic_mismatch')
    version1 = manifest['contract']['id'] == 'publish_new_version.v1'
    version2 = manifest['contract']['id'] == 'publish_new_version.v2'
    versioned = version1 or version2
    bundle=manifest['contract']['id']=='bundle_create.v1'
    effect,actual_effect = plan['effects'][0],effects[0]
    _require(actual_effect['effect_id'] == effect['effect_id']
        and actual_effect['kind'] == effect['kind'] == ('publish_new_version' if versioned else 'exclusive_create'),
        'ntfs.native_receipt_semantic_mismatch')
    if not versioned and actual_effect['status'] == 'applied_verified':
        _require(type(actual_effect['bytes_written']) is int
            and (bundle or actual_effect['bytes_written'] == effect['content_length'])
            and actual_effect['after']['digest'] == effect['content_digest']
            and actual_effect['after']['length'] == effect['content_length'],
            'ntfs.native_receipt_semantic_mismatch')
    elif not versioned and actual_effect['status'] == 'failed_no_effect':
        _require(type(actual_effect['bytes_written']) is int and actual_effect['bytes_written'] == 0
            and actual_effect['error']['code'] == 'target.destination_exists'
            and actual_effect['after']['known'] is True and actual_effect['after']['exists'] is True,
            'ntfs.native_receipt_semantic_mismatch')
    declarations = contract.document['validators']
    results = receipt['validator_results']
    _require(len(results) == len(pre) == len(declarations), 'ntfs.native_validator_semantic_mismatch')
    from ...validation import ValidatorRunner
    runner = ValidatorRunner(binding.registry)  # Only its pure result constructor, never target I/O.
    observation = proof['physical']['observations'].get('post_operation')
    for declaration,record,previous in zip(declarations,results,pre):
        if declaration['phase'] != 'post_operation':
            _require(canonical_bytes(record) == canonical_bytes(previous),
                'ntfs.native_validator_semantic_mismatch')
            continue
        if version2:
            _require(declaration['binding']['id']=='publish_new_version.result_v2'
                and observation is not None,'ntfs.native_validator_semantic_mismatch')
            from .version2_observation import validate_version2_triple
            from ...contracts.publish_new_version_v2 import _postcondition_result
            triple=validate_version2_triple(observation['observation'],manifest['root_grants'],effect)
            states={name:{key:row['state'][key] for key in ('exists','digest','length')}
                for name,row in triple.items()}
            status,code,expected,actual,blockers=_postcondition_result(effect,states)
            projected=runner._result(declaration,run_id=receipt['run_id'],timestamp=intent['created_at'],
                status=status,code=code,expected=expected,actual=actual,blockers=blockers)
            _require(canonical_bytes(projected)==canonical_bytes(record),'ntfs.native_validator_semantic_mismatch')
            continue
        if version1:
            _require(declaration['binding']['id'] == 'publish_new_version.result_v1'
                and observation is not None,'ntfs.native_validator_semantic_mismatch')
            from .parent_result import validate_version1_pair
            from ...contracts.publish_new_version_v1 import _postcondition_result
            pair = validate_version1_pair(observation['observation'],manifest['root_grants'][0],effect)
            current,archive = ({key:pair[name]['state'][key] for key in ('exists','digest','length')}
                for name in ('current','archive'))
            status,code,expected,actual,blockers = _postcondition_result(effect,current,archive)
            projected = runner._result(declaration,run_id=receipt['run_id'],timestamp=intent['created_at'],
                status=status,code=code,expected=expected,actual=actual,blockers=blockers)
            _require(canonical_bytes(projected) == canonical_bytes(record),'ntfs.native_validator_semantic_mismatch')
            continue
        if bundle:
            _require(declaration['binding']['id']=='bundle.result_v1','ntfs.original_bundle_effect_required')
            from .bundle_execution import bundle_postcondition
            parsed=binding.read(run_id=receipt['run_id'],intent_digest=digest)
            status,code,expected,actual,blockers=bundle_postcondition(
                None if observation is None else observation['observation'],
                grant_data=manifest['root_grants'][0],effect=effect,projection=parsed)
            projected=runner._result(declaration,run_id=receipt['run_id'],timestamp=intent['created_at'],
                status=status,code=code,expected=expected,actual=actual,blockers=blockers)
            _require(canonical_bytes(projected)==canonical_bytes(record),'ntfs.native_validator_semantic_mismatch')
            continue
        _require(declaration['binding']['id'] == 'validator.result_digest_v1',
            'ntfs.original_single_effect_required')
        expected = [{'locator':effect['target']['relative_locator'],
            'digest':effect['content_digest'],'length':effect['content_length']}]
        state = None if observation is None else observation['observation']['state']
        if state is None or state['exists'] is not True or state['digest'] is None:
            actual = [{'locator':effect['target']['relative_locator'],'digest':None,'length':None}]
            blockers = ['verification.target_unavailable']
        else:
            _require(observation['observation']['locator'] == effect['target']['relative_locator'],
                'ntfs.native_validator_semantic_mismatch')
            actual = [{'locator':effect['target']['relative_locator'],'digest':state['digest'],'length':state['length']}]
            blockers = [] if canonical_bytes(expected) == canonical_bytes(actual) else ['verification.result_mismatch']
        projected = runner._result(declaration,run_id=receipt['run_id'],timestamp=intent['created_at'],
            status='fail' if blockers else 'pass',code=blockers[0] if blockers else 'validation.pass',
            expected=expected,actual=actual,blockers=blockers)
        _require(canonical_bytes(projected) == canonical_bytes(record), 'ntfs.native_validator_semantic_mismatch')
    # Reuse Core's ONE original classifier; a schema-valid status cannot override
    # contradictory effect/validator facts. GO-sent is distinct from UNKNOWN GO.
    terminal,state,code,recovery,blockers = _classify_effect_outcome(plan,results,effects,
        finalization_failed=receipt['evidence']['finalization_status'] != 'finalized')
    _require((receipt['terminal_status'],receipt['result_state'],receipt['exit_code'],
        receipt['recovery_required'],receipt['blockers']) == (terminal,state,code,recovery,blockers),
        'ntfs.native_receipt_semantic_mismatch')
    result = (PhaseCore._canonical_result(contract,effect,actual_effect['after'],intent['created_at'])
        if terminal in {'succeeded_verified','committed_unverified'} else None)
    _require(canonical_bytes(receipt['canonical_result']) == canonical_bytes(result),
        'ntfs.native_receipt_semantic_mismatch')


def _check(binding, receipt, proof):
    from ...installation import _NativeFileCreateReadBinding, _resolve_native_file_create_read_binding
    _require(type(binding) is _NativeFileCreateReadBinding, 'ntfs.original_read_binding_required')
    _resolve_native_file_create_read_binding(manifest_bytes=binding.manifest_bytes,
        expected_manifest_digest=binding.manifest_digest, registry=binding.registry)
    manifest = parse_json_bytes(binding.manifest_bytes, maximum_bytes=_CONTROL)
    from ...installation import _native_qualified_profile
    from ..guarantees import verify_guarantee_coverage
    contract_binding = manifest['contract']
    contract = binding.registry.resolve_contract(contract_binding['id'],contract_binding['version'],
        contract_binding['package_digest'],core_version=manifest['core']['version'])
    from .experimental_file1 import _experimental_admission
    admission = _experimental_admission(binding)
    if admission is None:
        profile = _native_qualified_profile(binding.registry,manifest['authority']['profile'])
        verify_guarantee_coverage(contract.document['operation']['required_guarantees'],
            [manifest['mechanism']],profile,binding.registry)
    else:
        admission.verify_attachment(binding, receipt['run_id'], receipt)
        admission.assess(binding,contract.document['operation']['required_guarantees'],[manifest['mechanism']])
    if receipt.get('implementation_binding') is not None:
        _require(receipt['implementation_binding']['authority'] == manifest['authority']
            and receipt['implementation_binding']['mechanism'] == manifest['mechanism'],
            'ntfs.original_implementation_mismatch')
    _schema(binding, manifest).validate(proof)
    validate_receipt(receipt, binding.registry)
    _require(receipt['contract'] == manifest['contract'] and receipt['core'] == manifest['core']
        and proof['run_id'] == receipt['run_id']
        and proof['installation'] == {'id':manifest['installation_id'],'descriptor_digest':binding.manifest_digest}
        and proof['registry_snapshot_digest'] == binding.registry.digest,
        'ntfs.native_proof_binding_mismatch')
    nonce, identity = _facts(binding, manifest, receipt, proof)
    _verify_original_semantics(binding,manifest,receipt,proof)
    native = {'native_binding_version':'1.0', 'installation':proof['installation'],
        'composition':manifest['composition'], 'evidence_identity':manifest['evidence_identity'],
        'operation_nonce':nonce}
    _require(canonical_bytes(native) == canonical_bytes(proof['native_binding']),
        'ntfs.native_proof_binding_mismatch')
    return identity


def make_native_terminal_proof(binding, request, prepared, *, physical, idempotency, common_guard_finalized):
    manifest = parse_json_bytes(binding.manifest_bytes, maximum_bytes=_CONTROL)
    nonce = (physical['parent_response']['context']['operation_nonce'] if physical['parent_safety_established']
        else physical['no_dispatch_finalization']['operation_nonce'])
    installation = {'id':manifest['installation_id'],'descriptor_digest':binding.manifest_digest}
    proof = {'native_terminal_proof_version':'1.0','run_id':request.run_id,
        'installation':installation,'registry_snapshot_digest':binding.registry.digest,
        'native_binding':{'native_binding_version':'1.0','installation':installation,
            'composition':manifest['composition'],'evidence_identity':manifest['evidence_identity'],
            'operation_nonce':nonce},
        'prepared_receipt_digest':profile_digest('receipt',prepared.receipt),
        'physical':physical,'idempotency':idempotency,'common_guard_finalized':common_guard_finalized}
    _check(binding, prepared.receipt, proof)
    if prepared.intent is not None:
        _require(canonical_bytes(prepared.intent['native_binding']) == canonical_bytes(proof['native_binding']),
            'ntfs.native_proof_binding_mismatch')
    _require(len(canonical_bytes(proof)) <= _CONTROL, 'ntfs.native_proof_limit')
    return parse_json_bytes(canonical_bytes(proof), maximum_bytes=_CONTROL)


def _canonical(path):
    raw = read_bounded_file(path, _CONTROL)
    value = parse_json_bytes(raw, maximum_bytes=_CONTROL)
    _require(canonical_bytes(value) == raw, 'ntfs.original_evidence_not_canonical')
    return value, raw


def verify_native_terminal_proof(binding, run_root, receipt):
    """Readonly validation and ephemeral dependency projection, never recovery."""
    binding.check_evidence_root()
    manifest = parse_json_bytes(binding.manifest_bytes, maximum_bytes=_CONTROL)
    validate_run_id(receipt['run_id'])
    expected = Path(manifest['evidence_root'])/'.phase'/'runs'/receipt['run_id']
    _require(run_root == expected, 'ntfs.original_evidence_path_mismatch')
    proof, raw = _canonical(run_root/'attachments'/_PROOF)
    proof_digest = digest_bytes(raw)
    _require(receipt['evidence']['attachment_digests'].count(proof_digest) == 1,
        'ntfs.native_proof_digest_mismatch')
    prepared = parse_json_bytes(canonical_bytes(receipt))
    prepared['evidence']['attachment_digests'].remove(proof_digest)
    # Core's completeness flag was preserved, not repaired by the attachment.
    _require(profile_digest('receipt',prepared) == proof['prepared_receipt_digest'],
        'ntfs.native_prepared_receipt_mismatch')
    identity = _check(binding, prepared, proof)
    files = {'receipt.json':(digest_bytes(canonical_bytes(receipt)),len(canonical_bytes(receipt)))}
    attached = set()
    for path in (run_root/'attachments').iterdir():
        value, data = _canonical(path)
        attached.add(digest_bytes(data));files['attachments/'+path.name] = (digest_bytes(data),len(data))
    _require(attached == set(receipt['evidence']['attachment_digests']),
        'inspection.attachment_set_mismatch')
    if receipt['evidence']['intent_digest'] is not None:
        intent, original = _canonical(run_root/'intent.json')
        validate_intent(intent, binding.registry)
        _require(profile_digest('intent',intent) == receipt['evidence']['intent_digest']
            and intent['native_binding'] == proof['native_binding'], 'ntfs.original_intent_mismatch')
        from ...inspection import _verify_bound_pre_validators, _verify_intent_blobs
        plan, _ = _canonical(run_root/'attachments'/'effect-plan.json')
        _verify_bound_pre_validators(run_root,intent);_verify_intent_blobs(run_root,intent,plan)
        files['intent.json'] = digest_bytes(original),len(original)
    else:
        _require(not (run_root/'intent.json').exists(), 'ntfs.original_intent_mismatch')
    # Pre-intent rejection/reuse may retain frozen blobs without an intent.
    # Preserve and confirm them by their existing content-addressed leaf hashes;
    # that does not invent input provenance or promote them to Sources.
    blobs = run_root/'blobs'
    if blobs.exists():
        for path in blobs.iterdir():
            _require(re.fullmatch('[0-9a-f]{64}',path.name) is not None,
                'ntfs.original_frozen_input_required')
            digest = 'sha256:'+path.name
            if manifest['contract']['id']=='file_create.v2':
                from ...streaming import FILE_LIMIT,hash_file
                actual,length=hash_file(path,FILE_LIMIT)
                _require(actual==digest,'ntfs.original_evidence_bytes_mismatch')
            else:
                data=read_bounded_file(path,16*1024**2 if manifest['contract']['id']=='publish_new_version.v1' else 1024**2)
                _require(digest_bytes(data)==digest,'ntfs.original_evidence_bytes_mismatch')
                length=len(data)
            files['blobs/'+path.name]=digest,length
    binding.check_evidence_root()
    return {'attachment_digest':proof_digest,'target_identity':identity,
        'immutable_files':files,'proof':proof}
