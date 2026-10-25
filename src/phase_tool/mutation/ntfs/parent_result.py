"""Pure native parent-response checks shared by dispatch and readonly inspect.
DRAFT source only, no I/O, admission, process ownership or receipt publication.
Matching data is historical correlation, not authentication of its producer.
"""
from __future__ import annotations
import re
from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import NativeIdentity, _require
from .worker import _grant, validate_worker_completion


def _observation(raw: object, grant: dict, locator: str) -> dict:
    """Check a reply from the accepted RO role; data alone is not role auth."""
    _require(type(raw) is dict and set(raw) == {
        'observation_version', 'state', 'native', 'grant', 'locator', 'handles_finalized'},
        'ntfs.observer_response_shape')
    _grant(raw['grant'])
    _require(raw['observation_version'] == '1.0'
        and canonical_bytes(raw['grant']) == canonical_bytes(grant)
        and raw['locator'] == locator and raw['handles_finalized'] is True,
        'ntfs.observer_response_binding_mismatch')
    state, native = raw['state'], raw['native']
    _require(type(state) is dict and set(state) == {'known', 'exists', 'digest', 'length', 'head_token'}
        and state['known'] is True and type(state['exists']) is bool
        and state['head_token'] is None and type(native) is dict
        and type(native.get('exists')) is bool and native['exists'] is state['exists'],
        'ntfs.observer_response_shape')
    if state['exists']:
        _require(set(native) == {'exists', 'native_identity', 'length', 'digest', 'link_count'}
            and type(native['link_count']) is int and native['link_count'] == 1
            and type(state['length']) is int and state['length'] >= 0
            and type(native['length']) is int and native['length'] == state['length'] and native['digest'] == state['digest'],
            'ntfs.observer_response_shape')
        identity = NativeIdentity.parse(native['native_identity'])
        expected = _grant(grant).root_identity
        _require(identity.volume_serial == expected.volume_serial, 'ntfs.observer_volume_mismatch')
        # A larger pre-existing file may truthfully be observed without its hash.
        if state['length'] <= 1024**2:
            _require(type(state['digest']) is str and re.fullmatch(
                r'sha256:[0-9a-f]{64}', state['digest']) is not None, 'ntfs.observer_digest_required')
        else:
            _require(state['digest'] is None, 'ntfs.observer_response_shape')
    else:
        _require(native == {'exists': False, 'native_identity': None}
            and state['digest'] is None and state['length'] is None,
            'ntfs.observer_response_shape')
    return parse_json_bytes(canonical_bytes(raw))


def validate_parent_completion(reply, *, context, grant_data, effect):
    _require(type(reply) is dict and set(reply) == {'parent_execution_version', 'context',
        'completion', 'process_witness', 'owner_finalization', 'post_observation', 'ingress_state'}
        and reply['parent_execution_version'] == '1.0' and reply['context'] == context
        and reply['ingress_state'] == 'consumed', 'ntfs.parent_execution_binding_mismatch')
    completion = reply['completion']
    _require(type(completion) is dict and type(completion.get('pid')) is int,
        'ntfs.worker_completion_binding_mismatch')
    checked = validate_worker_completion(canonical_bytes(completion), context=context,
        grant_data=grant_data, effect=effect, expected_pid=completion['pid'])
    if checked['error'] is not None:
        raise PhaseError('ntfs.effect_outcome_unavailable', details={'worker_error': checked['error']})
    return checked


def validate_parent_finalization(reply, checked, *, grant_data, effect):
    completion = checked
    receipt = checked['effect_receipt']
    witness = reply['process_witness']
    _require(type(witness) is dict and witness.get('process_witness_version') == '1.0'
        and type(witness.get('pid')) is int and witness['pid'] == completion['pid']
        and type(witness.get('wait_result')) is int and witness['wait_result'] == 0
        and witness.get('worker_exit_established') is True
        and type(witness.get('exit_code')) is int and witness['exit_code'] == 0,
        'ntfs.worker_exit_not_established')
    _require(reply['owner_finalization'] == {'worker_stdin': 'closed', 'worker_stdout': 'closed',
        'worker_stderr': 'closed', 'creation_handle': 'closed', 'errors': []},
        'ntfs.worker_finalization_unknown')
    observed = _observation(reply['post_observation'], grant_data,
        effect['target']['relative_locator'])
    _require(receipt['after'] == observed['state'], 'ntfs.worker_observer_mismatch')
    physical = checked['physical_evidence']
    _require(physical['handle_finalization'] == 'closed'
        and type(physical['remaining_handle_count']) is int and physical['remaining_handle_count'] == 0
        and physical['mutex_state'] == 'closed' and physical['mutation_session_state'] == 'sealed'
        and type(physical['finalization_errors']) is list and physical['finalization_errors'] == [],
        'ntfs.worker_finalization_unknown')
    # Parse the worker's claimed native after-state with the SAME strict
    # data validator, then correlate it with a separately executed RO
    # observation. A missing worker after/NativeID never skips this check.
    worker_after = _observation({'observation_version': '1.0', 'state': receipt['after'],
        'native': physical['after'], 'grant': physical['grant'], 'locator': physical['locator'],
        'handles_finalized': True}, grant_data,
        effect['target']['relative_locator'])
    _require(canonical_bytes(worker_after['native']) == canonical_bytes(observed['native']),
        'ntfs.worker_observer_mismatch')
    return observed


def validate_version1_pair(raw, grant_data, effect):
    """Two fresh samples, not a simultaneous snapshot or lifecycle authority."""
    from .version1_observation import validate_version1_observation
    _require(type(raw) is dict and set(raw) == {'observation_pair_version','current','archive'}
        and raw['observation_pair_version'] == '1.0','ntfs.version1_pair_shape')
    current = validate_version1_observation(raw['current'],grant_data,effect['target']['relative_locator'])
    archive = validate_version1_observation(raw['archive'],grant_data,effect['archive_target']['relative_locator'])
    if current['native']['exists'] and archive['native']['exists']:
        _require(current['native']['native_identity'] != archive['native']['native_identity'],
            'ntfs.version1_current_archive_alias')
    return {'observation_pair_version':'1.0','current':current,'archive':archive}


def validate_version1_parent_completion(reply, *, context, grant_data, effect):
    from .worker import validate_version1_worker_completion
    _require(type(reply) is dict and set(reply) == {'parent_execution_version','context',
        'completion','process_witness','owner_finalization','post_observation','ingress_state'}
        and reply['parent_execution_version'] == '1.1'
        and canonical_bytes(reply['context']) == canonical_bytes(context)
        and reply['ingress_state'] == 'consumed','ntfs.parent_execution_binding_mismatch')
    completion = reply['completion']
    _require(type(completion) is dict and type(completion.get('pid')) is int,
        'ntfs.worker_completion_binding_mismatch')
    checked = validate_version1_worker_completion(canonical_bytes(completion),context=context,
        grant_data=grant_data,effect=effect,expected_pid=completion['pid'])
    if checked['error'] is not None:
        raise PhaseError('ntfs.effect_outcome_unavailable',details={'worker_error':checked['error']})
    receipt = checked['effect_receipt']
    _require(receipt.get('attempted') is True and receipt.get('archive_target') == effect['archive_target']
        and receipt.get('started_at') == receipt.get('finished_at'),'ntfs.worker_receipt_binding_mismatch')
    if receipt.get('status') == 'applied_verified':
        _require(receipt.get('error') is None
            and receipt.get('verification_refs') == ['native.current.after','native.archive.after'],
            'ntfs.worker_receipt_binding_mismatch')
    return checked


def _version1_physical_sample(native, grant_data, locator):
    from .version1_observation import validate_version1_observation
    _require(type(native) is dict and type(native.get('exists')) is bool,
        'ntfs.worker_physical_binding_mismatch')
    state = {'known':True,'exists':native['exists'],
        'digest':native.get('digest'),'length':native.get('length'),'head_token':None}
    return validate_version1_observation({'observation_version':'1.1','state':state,
        'native':native,'grant':grant_data,'locator':locator,
        'handles_finalized':True,'ancestor_absence':None},grant_data,locator)


def validate_version1_parent_finalization(reply, checked, *, grant_data, effect):
    from .version1_observation import validate_version1_observation
    witness = reply['process_witness']
    _require(type(witness) is dict and witness.get('process_witness_version') == '1.0'
        and type(witness.get('pid')) is int and witness['pid'] == checked['pid']
        and type(witness.get('wait_result')) is int and witness['wait_result'] == 0
        and witness.get('worker_exit_established') is True
        and type(witness.get('exit_code')) is int and witness['exit_code'] == 0,
        'ntfs.worker_exit_not_established')
    _require(reply['owner_finalization'] == {'worker_stdin':'closed','worker_stdout':'closed',
        'worker_stderr':'closed','creation_handle':'closed','errors':[]},
        'ntfs.worker_finalization_unknown')
    observed = validate_version1_pair(reply['post_observation'],grant_data,effect)
    physical,receipt = checked['physical_evidence'],checked['effect_receipt']
    _require(physical['handle_finalization'] == 'closed'
        and type(physical['remaining_handle_count']) is int and physical['remaining_handle_count'] == 0
        and physical['mutex_state'] == 'closed' and physical['mutation_session_state'] == 'sealed'
        and type(physical['finalization_errors']) is list and not physical['finalization_errors'],
        'ntfs.worker_finalization_unknown')
    for name,field,locator in (('current','after',effect['target']['relative_locator']),
                              ('archive','archive_after',effect['archive_target']['relative_locator'])):
        worker_after = validate_version1_observation({'observation_version':'1.1',
            'state':receipt[field],'native':physical[field],'grant':physical['grant'],
            'locator':locator,'handles_finalized':True,'ancestor_absence':None},grant_data,locator)
        _require(canonical_bytes(worker_after['state']) == canonical_bytes(observed[name]['state'])
            and canonical_bytes(worker_after['native']) == canonical_bytes(observed[name]['native']),
            'ntfs.worker_observer_mismatch')
    if receipt['status'] == 'applied_verified':
        _require(physical['primary_error'] is None,'ntfs.worker_physical_binding_mismatch')
        expected_current = {'known':True,'exists':True,'digest':effect['content_digest'],
            'length':effect['content_length'],'head_token':None}
        expected_archive = {'known':True,'exists':True,'digest':effect['archive_digest'],
            'length':effect['archive_length'],'head_token':None}
        _require(receipt['before'] == receipt['archive_after'] == expected_archive
            and receipt['after'] == expected_current,'ntfs.worker_receipt_binding_mismatch')
        before_current = _version1_physical_sample(physical['before'],grant_data,
            effect['target']['relative_locator'])
        before_archive = _version1_physical_sample(physical['archive_before'],grant_data,
            effect['archive_target']['relative_locator'])
        _require(before_current['native']['exists'] is True
            and before_current['native']['native_identity'] == observed['current']['native']['native_identity']
            and receipt['archive_before'] == before_archive['state'],
            'ntfs.worker_observer_mismatch')
        if before_archive['native']['exists']:
            _require(before_archive['native']['native_identity'] == observed['archive']['native']['native_identity']
                and before_current['native']['native_identity'] != before_archive['native']['native_identity'],
                'ntfs.worker_observer_mismatch')
        from ...contracts.publish_new_version_v1 import _classify_states
        state = _classify_states(current={k:before_current['state'][k] for k in ('exists','digest','length')},
            archive={k:before_archive['state'][k] for k in ('exists','digest','length')},
            before_digest=effect['archive_digest'],before_length=effect['archive_length'],
            after_digest=effect['content_digest'],after_length=effect['content_length'])
        _require(state in {'no_effect_observed','archived_not_published','published_not_finalized'},
            'ntfs.worker_physical_binding_mismatch')
        trace = physical['mutation_trace']
        _require(type(trace) is dict and type(trace.get('acknowledged_recorded_event_count')) is int
            and trace['acknowledged_recorded_event_count'] >= 0
            and trace.get('capture_complete') is True
            and type(trace.get('unacknowledged_records_upper_bound')) is int
            and trace['unacknowledged_records_upper_bound'] == 0
            and trace.get('capture_errors') == [],'ntfs.worker_physical_binding_mismatch')
        count = trace['acknowledged_recorded_event_count']
        if before_current['state'] == expected_current and before_archive['state'] == expected_archive:
            # This is the only zero-mutation contract continuation. Physical
            # BEFORE is kept separate from receipt's logical archived-before.
            _require(count == 0 and type(receipt['bytes_written']) is int
                and receipt['bytes_written'] == 0,'ntfs.worker_physical_binding_mismatch')
        else:
            expected_written = effect['content_length'] + (0 if before_archive['native']['exists'] else effect['archive_length'])
            _require(type(receipt['bytes_written']) is int and receipt['bytes_written'] == expected_written,
                'ntfs.worker_receipt_binding_mismatch')
            _require(count > 0 and physical['current_data_flushed'] is True
                and physical['current_namespace_flushed'] is True,
                'ntfs.worker_physical_binding_mismatch')
            if not before_archive['native']['exists']:
                _require(physical['archive_data_flushed'] is True
                    and physical['archive_namespace_flushed'] is True,
                    'ntfs.worker_physical_binding_mismatch')
    return observed


def _require_command_run_binding(result: dict, run_id: str) -> None:
    """Correlate fixed-delivery data; this does not authenticate its producer.

    A null run can describe an early startup refusal or typed uncertainty. It
    cannot identify a successful/receipt-bearing operation. Parent still owns
    the separate actual no-dispatch check for the startup-refusal exception.
    Full schemas remain checked by the existing command-result validator.
    """
    _require(type(result) is dict and type(run_id) is str and bool(run_id),
        'ntfs.parent_command_binding_mismatch')
    _require('run_id' in result, 'ntfs.parent_command_binding_mismatch')
    reported = result['run_id']
    if type(reported) is str and reported == run_id:
        return
    _require(reported is None, 'ntfs.parent_command_binding_mismatch')
    version = result.get('stage3_command_result_version')
    no_original_claim = all(key in result and result[key] is None for key in
        ('terminal_status', 'execution_disposition', 'mutation_attempted',
         'receipt_digest', 'target_verified'))
    if version == '1.2':
        # Preserve independently known intent/plan/dispatch/publication facts.
        # Null here is uncertainty, never a no-effect or completion assertion.
        allowed = (no_original_claim and result.get('success') is False
            and type(result.get('exit_code')) is int and result['exit_code'] == 40
            and result.get('inspection_required') is True
            and result.get('retry_authorized') is False
            and result.get('error') == 'ntfs.native_lifecycle_unresolved'
            and result.get('blockers') == ['ntfs.native_lifecycle_unresolved'])
    elif version == '1.0':
        error = result.get('error')
        allowed = (result.get('success') is False
            and result.get('terminal_status') == 'rejected'
            and result.get('execution_disposition') == 'not_executed'
            and result.get('mutation_attempted') is False
            and type(result.get('exit_code')) is int and result['exit_code'] == 10
            and all(key in result and result[key] is None for key in
                ('effect_plan_digest', 'intent_digest', 'receipt_digest', 'target_verified'))
            and type(error) is str and bool(error)
            and type(result.get('blockers')) is list and result['blockers'] == [error])
    else:
        allowed = False
    _require(allowed, 'ntfs.parent_command_binding_mismatch')


def _native_file_result_mode(request) -> bool:
    """Only a wire-generation selector; never admission or an operation grant."""
    return (type(request) is dict
        and request.get('native_file_publication_inspection_request_version') == '1.1')


def validate_native_file_inspection_result(result, reference, *, request, run_id,
        manifest_bytes, expected_manifest_digest, registry):
    """Correlate one CURRENT reference after the SAME existing inspection.

    This is data validation only: no target reads, lifecycle, qualification,
    receipt ownership or fresh-source claim. Fixed startup remains mandatory.
    """
    from jsonschema import Draft202012Validator, FormatChecker
    from ...command_result import validate_command_result
    from ...installation import _resolve_native_file_create_read_binding
    from ...publish_file import CONTRACT_BINDING, MAX_BYTES
    from .entrypoint import _native_file_inspection_expectations

    _native_file_inspection_expectations(request)
    _require(_native_file_result_mode(request), 'ntfs.file_result_request_version_required')
    validate_command_result(result, registry)
    _require_command_run_binding(result, run_id)
    _require(result['command'] == 'inspect', 'ntfs.file_result_binding_mismatch')
    binding = _resolve_native_file_create_read_binding(manifest_bytes=manifest_bytes,
        expected_manifest_digest=expected_manifest_digest, registry=registry)
    manifest = parse_json_bytes(binding.manifest_bytes, maximum_bytes=2*1024**2)
    exact = registry.contract_bindings().get(CONTRACT_BINDING)
    _require(exact is not None and manifest['contract'] == exact,
        'ntfs.original_single_effect_required')
    if result['success'] is True:
        _require(result['receipt_digest'] == request['expected_receipt_digest'],
            'ntfs.file_publication_receipt_mismatch')
    if reference is None:
        # Successful planning/recovery is not an inspected file publication.
        _require(not (result['success'] is True and result['target_verified'] is True),
            'ntfs.file_result_required')
        return None
    _require(result['success'] is True and result['exit_code'] == 0
        and result['target_verified'] is True
        and result['error'] is None and result['blockers'] == []
        and result['terminal_status'] == 'succeeded_verified'
        and result['execution_disposition'] in {'executed', 'reused_existing'}
        and result['receipt_digest'] == request['expected_receipt_digest'],
        'ntfs.file_result_binding_mismatch')
    contract = registry.resolve_contract(exact['id'], exact['version'], exact['package_digest'],
        core_version=manifest['core']['version']).document
    declaration = contract['canonical_result']
    schema = registry.schema_document(declaration['result_reference_schema_ref'])
    _require(type(reference) is dict and not list(Draft202012Validator(schema,
        registry=registry.schema_registry(), format_checker=FormatChecker()).iter_errors(reference)),
        'ntfs.file_result_binding_mismatch')
    state = reference['state']
    _require(reference['contract'] == exact
        and reference['owner_id'] == declaration['owner_id']
        and reference['authority_rule'] == declaration['authority_rule']
        and reference['root_binding'] == declaration['root_binding']
        and reference['root_binding'] in manifest['root_projections']
        and reference['locator'] == request['target_locator']
        and state['exists'] is True and state['head_token'] is None
        and type(state['length']) is int and 0 <= state['length'] <= MAX_BYTES
        and type(state['digest']) is str
        and re.fullmatch(r'sha256:[0-9a-f]{64}', state['digest']) is not None
        and reference.get('appended_record') is None,
        'ntfs.file_result_binding_mismatch')
    _require(request['expected_digest'] is None or state['digest'] == request['expected_digest'],
        'ntfs.file_result_binding_mismatch')
    # Preserve CURRENT owner/observed_at/head semantics; no new authority claim.
    return parse_json_bytes(canonical_bytes(reference))


def validate_native_file_result_delivery(value, *, request, run_id, channel_id,
        manifest_bytes, expected_manifest_digest, registry):
    """Closed 1.1 frame; reject downgrade, unsolicited sidecar and cross-call data."""
    _require(type(value) is dict and set(value) == {'protocol', 'version', 'channel_id',
        'run_id', 'result', 'exit_code', 'canonical_result'}
        and value['protocol'] == 'phase.native.command' and value['version'] == '1.1'
        and value['channel_id'] == channel_id and value['run_id'] == run_id
        and type(value['result']) is dict and type(value['exit_code']) is int
        and value['result'].get('exit_code') == value['exit_code'],
        'ntfs.parent_command_binding_mismatch')
    return validate_native_file_inspection_result(value['result'], value['canonical_result'],
        request=request, run_id=run_id, manifest_bytes=manifest_bytes,
        expected_manifest_digest=expected_manifest_digest, registry=registry)


def _require_version1_inspection_delivery(result, *, request, run_id, inspection_only):
    """Correlate raw bound-inspect delivery, never evidence or fresh authority.

    Callers retain existing full schema/command/run/channel checks first. Only
    the separate version1 request is recognized; legacy grammars are unchanged.
    A failed raw result keeps its original error/facts, without a success claim.
    """
    if type(request) is not dict or (
            'native_version1_publication_inspection_request_version' not in request):
        return
    from .entrypoint import _native_version1_inspection_expectations
    _native_version1_inspection_expectations(request)
    _require(inspection_only is True, 'ntfs.fixed_inspection_role_required')
    _require_command_run_binding(result, run_id)
    _require(result['command'] == 'inspect', 'ntfs.version1_inspection_binding_mismatch')
    if result['success'] is True:
        _require(result['exit_code'] == 0 and result['target_verified'] is True
            and result['error'] is None and result['blockers'] == []
            and result['terminal_status'] == 'succeeded_verified'
            and result['execution_disposition'] in {'executed','reused_existing'}
            and result['receipt_digest'] == request['expected_receipt_digest'],
            'ntfs.version1_inspection_binding_mismatch')
