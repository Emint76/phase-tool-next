"""Closed original-quiescence and immutable recovery closure verification.

No target opens, worker dispatch or interpretation of negative flags as proof.
Only the fixed successor installation can issue a selected-original token.
"""
from __future__ import annotations
import base64
from dataclasses import dataclass
from pathlib import Path
import re
import stat
import os

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ...errors import PhaseError
from .native import _require


def _record(path):
    from ...evidence import _reject_existing_links
    from ...streaming import read_bounded_file
    _reject_existing_links(path)
    raw=read_bounded_file(path,2*1024**2)
    value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
    _require(type(value) is dict and canonical_bytes(value)==raw,'recovery.invalid_record')
    return value


def _wire(record):
    _require(type(record) is dict and set(record)=={'sha256','length','bytes_base64'}
        and type(record['length']) is int and 0<record['length']<=512*1024,
        'recovery.original_completion_unproven')
    raw=base64.b64decode(record['bytes_base64'],validate=True)
    _require(len(raw)==record['length'] and digest_bytes(raw)==record['sha256'],
        'recovery.original_completion_unproven')
    return raw


def verify_quiescence(parent, completion):
    """Affirmative retained creation-HANDLE calls, not EOF/PID/negative flags."""
    witness=parent['process_witness']
    _require(type(witness) is dict and witness.get('process_witness_version')=='1.0'
        and type(witness.get('pid')) is int and witness['pid']==completion['pid']
        and type(witness.get('creation_filetime')) is int and witness['creation_filetime']>0
        and type(witness.get('wait_result')) is int and witness['wait_result']==0
        and witness.get('worker_exit_established') is True
        and type(witness.get('exit_code')) is int and witness['exit_code']==0,
        'recovery.original_worker_not_quiescent')
    events=witness.get('events')
    expected=['GetProcessId','GetProcessTimes','GetProcessId','GetProcessTimes',
        'WaitForSingleObject','GetExitCodeProcess','GetProcessId','GetProcessTimes']
    _require(type(events) is list and [e.get('api')for e in events]==expected,
        'recovery.original_worker_not_quiescent')
    for event in events:
        _require(event.get('outcome')=='returned' and type(event.get('started_ns')) is int
            and type(event.get('returned_ns')) is int and event['returned_ns']>=event['started_ns']
            and type(event.get('result')) is int and type(event.get('winerror')) is int,
            'recovery.original_worker_not_quiescent')
        wanted=(witness['pid'] if event['api']=='GetProcessId' else
            0 if event['api']=='WaitForSingleObject' else 1)
        _require(event['result']==wanted,'recovery.original_worker_not_quiescent')
    _require(all(events[i]['returned_ns']<=events[i+1]['started_ns']for i in range(len(events)-1)),
        'recovery.original_worker_not_quiescent')
    _require(parent.get('owner_finalization')=={'worker_stdin':'closed','worker_stdout':'closed',
        'worker_stderr':'closed','creation_handle':'closed','errors':[]},
        'recovery.original_owner_not_closed')


def verify_trace(physical):
    trace=physical['mutation_trace']
    _require(type(trace) is dict and trace.get('capture_complete') is True
        and trace.get('capture_errors')==[]
        and type(trace.get('unacknowledged_records_upper_bound')) is int
        and trace['unacknowledged_records_upper_bound']==0
        and trace.get('raw_records_complete') is True
        and type(trace.get('omitted_middle_records')) is int and trace['omitted_middle_records']==0
        and type(trace.get('records')) is list
        and type(trace.get('acknowledged_recorded_event_count')) is int
        and trace['acknowledged_recorded_event_count']==len(trace['records']),
        'recovery.original_trace_incomplete')
    import hashlib
    _require(trace['canonical_jsonl_digest']=='sha256:'+hashlib.sha256(
        b''.join(canonical_bytes(row)+b'\n'for row in trace['records'])).hexdigest(),
        'recovery.original_trace_incomplete')
    return trace['records']


def verify_physical_closed(physical):
    _require(physical.get('handle_finalization')=='closed'
        and type(physical.get('remaining_handle_count')) is int and physical['remaining_handle_count']==0
        and physical.get('unproven_handle_ownership') is False
        and physical.get('mutex_state')=='closed' and physical.get('mutation_session_state')=='sealed'
        and physical.get('finalization_errors')==[], 'recovery.original_resources_unknown')
    events=physical.get('mutex_events')
    _require(type(events) is list and [e.get('api')for e in events]==[
        'CreateMutexExW','WaitForSingleObject','ReleaseMutex','CloseHandle'],
        'recovery.original_resources_unknown')
    _require(all(e.get('outcome')=='returned' and type(e.get('result')) is int
        and type(e.get('started_ns')) is int and type(e.get('returned_ns')) is int
        and e['returned_ns']>=e['started_ns']for e in events)
        and events[0]['result']>0 and events[1]['result']==0
        and events[2]['result']!=0 and events[3]['result']!=0,
        'recovery.original_resources_unknown')


def native_inventory(binding, run):
    """Full no-follow census; known JSON leaves, no ignored subtrees."""
    from ...streaming import hash_file
    manifest=parse_json_bytes(binding.manifest_bytes)
    device=manifest['evidence_identity']['device'];files={}
    for directory in (run,run/'attachments',run/'blobs'):
        info=directory.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_dev==device
            and info.st_uid==os.geteuid() and not info.st_mode&0o022,
            'recovery.original_inventory_unsafe')
    pending=[run]
    while pending:
        directory=pending.pop()
        with os.scandir(directory) as rows:
            for row in rows:
                path=directory/row.name;relative=path.relative_to(run).as_posix()
                info=row.stat(follow_symlinks=False)
                _require(info.st_dev==device and info.st_uid==os.geteuid() and not info.st_mode&0o022,
                    'recovery.original_inventory_unsafe')
                if stat.S_ISDIR(info.st_mode):
                    _require(relative in {'attachments','blobs','recovery'},'recovery.original_inventory_unsafe')
                    pending.append(path);continue
                _require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'recovery.original_inventory_unsafe')
                if relative.startswith('blobs/'):
                    _require(re.fullmatch('[0-9a-f]{64}',row.name) is not None,'recovery.original_inventory_unsafe')
                    digest,length=hash_file(path,2*1024**3)
                    _require(digest[7:]==row.name,'recovery.original_blob_mismatch')
                else:
                    _require(info.st_size<=2*1024**2,'recovery.original_inventory_unsafe')
                    raw=path.read_bytes();value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
                    _require(canonical_bytes(value)==raw,'recovery.original_inventory_unsafe')
                    if relative.startswith('recovery/'):
                        _require(row.name in {'commit-intent.json','commit-receipt.json','native-commit-proof.json'}
                            or re.fullmatch(r'[0-9a-f]{64}\.json',row.name) is not None,
                            'recovery.original_inventory_unsafe')
                    elif '/' not in relative:
                        _require(relative in {'intent.json','receipt.json','preparation-binding.json'},
                            'recovery.original_inventory_unsafe')
                    digest,length=digest_bytes(raw),len(raw)
                    if relative.startswith('recovery/') and re.fullmatch(r'[0-9a-f]{64}\.json',row.name):
                        from ...recovery import NativeRecoveryResult
                        checked=NativeRecoveryResult.model_validate(value)
                        original=_record(run/'intent.json')
                        _require(row.name==digest[7:]+'.json' and checked.run_id==original['run_id']
                            and checked.request_id==original['idempotency']['key']
                            and checked.intent_digest==profile_digest('intent',original)
                            and checked.effect_plan_digest==original['effect_plan_digest'],
                            'recovery.observation_mismatch')
                        if checked.success:
                            _require(checked.status=='verified_existing' and checked.target_verified is True
                                and checked.error is None and checked.exit_code==0 and checked.inspection_required is False
                                and checked.lock_finalization is not None
                                and checked.lock_finalization.unlock=='succeeded' and checked.lock_finalization.close=='succeeded'
                                and checked.native_error_details==[] and checked.error_details==[],
                                'recovery.observation_mismatch')
                            if checked.recovery_mode=='commit_prepared':
                                _require(checked.commit_finalization_verified is True,'recovery.observation_mismatch')
                        if checked.recovery_mode=='observe':
                            _require(checked.recovery_mutation_attempted is False,'recovery.observation_mismatch')
                files[relative]=(digest,length)
    return files


@dataclass(frozen=True)
class _NativeRecoverySelection:
    binding: object
    run_id: str
    intent_digest: str
    request_id: str
    files: tuple

    def check(self, run):
        _require(run.name==self.run_id and run==Path(parse_json_bytes(self.binding.manifest_bytes)['evidence_root'])/'.phase/runs'/self.run_id,
            'recovery.selected_original_mismatch')
        checked=verify_original(self.binding,self.run_id,self.request_id,self.intent_digest)
        _require(tuple(sorted(checked['files'].items()))==self.files,'recovery.original_changed')
        return checked


def verify_original(binding, run_id, request_id, expected_intent_digest):
    from ...installation import _NativeFileCreateReadBinding
    from ...evidence import validate_run_id,validate_receipt
    from ...prepared_binding import verify_prepared_binding
    from .bundle_execution import validate_bundle_worker_completion,_bundle_projection_value
    from .bundle_prepared import validate_prepared_message,prepared_locator
    from .failure import validate_native_parent_failure
    _require(type(binding) is _NativeFileCreateReadBinding,'recovery.closed_native_role_required')
    manifest=parse_json_bytes(binding.manifest_bytes)
    _require(manifest['native_read_installation_version']=='1.9','recovery.closed_native_role_required')
    validate_run_id(run_id);root=binding.check_evidence_root();run=root/'.phase/runs'/run_id
    intent=_record(run/'intent.json');plan=_record(run/'attachments/effect-plan.json')
    _require(profile_digest('intent',intent)==expected_intent_digest
        and intent['execution_requested'] is True and intent['run_id']==run_id
        and intent['idempotency']['key']==request_id
        and intent['effect_plan_digest']==profile_digest('effect-plan',plan), 'recovery.request_conflict')
    projection=binding.read(run_id=run_id,intent_digest=expected_intent_digest)
    value=_bundle_projection_value(projection);context=value['context'];effect=value['effect']
    contract=binding.registry.resolve_contract(intent['contract']['id'],intent['contract']['version'],
        intent['contract']['package_digest'],core_version=intent['core']['version'])
    prepared=verify_prepared_binding(binding.registry,contract,intent,plan,run)
    _require(prepared['stage_locator']==prepared_locator(projection),'recovery.preparation_mismatch')
    failure=_record(run/'attachments/native-parent-failure.json')
    validate_native_parent_failure(binding,failure)
    _require(failure['run_id']==run_id and failure['intent_digest']==expected_intent_digest
        and failure['effect_plan_digest']==intent['effect_plan_digest']
        and failure['operation_nonce']==context['operation_nonce'],'recovery.original_failure_mismatch')
    details=failure['parent_error']['details']
    _require(details.get('capture_version')=='1.1','recovery.original_capture_unavailable')
    parent=details['parent_partial'];raw=_wire(details['worker_completion_wire'])
    _require(parent['context']==context and parent['parent_execution_version']=='1.5'
        and parent['ingress_state']=='consumed' and canonical_bytes(parent['completion'])==raw,
        'recovery.original_completion_unproven')
    completion=validate_bundle_worker_completion(raw,context=context,grant_data=value['grant'],
        effect=effect,expected_pid=parent['completion']['pid'])
    verify_quiescence(parent,completion)
    physical=completion['physical_evidence'];verify_physical_closed(physical);trace=verify_trace(physical)
    checkpoint=physical['prepared_checkpoint']
    message=validate_prepared_message(checkpoint['message'],projection=projection,
        channel_id=checkpoint['message']['channel_id'],expected_pid=completion['pid'])
    _require(message['stage_locator']==physical['stage_locator']==prepared['stage_locator']
        and message['native']['native_identity']==physical['stage_identity']
        and message['native']['stat_identity']=={'device':prepared['device'],'inode':prepared['inode']},
        'recovery.preparation_mismatch')
    # The checkpoint's exact complete tree/owner proof binds all member bytes.
    # ACK and error/failed booleans are never used to establish death/absence.
    renames=[row for row in trace if row.get('api')=='NtSetInformationFile']
    _require(len(renames)<=1 and all(row.get('class')==10 and row.get('replace_if_exists') is False
        and row.get('return_status')==row.get('io_status')=='0x00000000'
        and row.get('effect_state')=='committed' for row in renames),
        'recovery.original_mutation_unknown')
    receipt=None
    if (run/'receipt.json').exists():
        receipt=_record(run/'receipt.json');validate_receipt(receipt,binding.registry)
        _require(receipt['run_id']==run_id and receipt['evidence']['intent_digest']==expected_intent_digest,
            'recovery.original_receipt_mismatch')
        # Existing but invalid final evidence is never a missing-receipt case.
        # The original terminal verifier repeats installation, receipt algebra,
        # exact attachment set and full immutable semantic closure without a
        # current-target observation. Prepared-only originals normally have no
        # final receipt; a present one must meet this existing stronger oracle.
        from .proof import verify_native_terminal_proof
        verify_native_terminal_proof(binding,run,receipt)
    files=native_inventory(binding,run)
    required={'effect-plan.json','pre-validator-results.json','prepared-stage.json',
        'native-parent-failure.json','experimental-admission.json'}
    actual={name.split('/',1)[1]for name in files if name.startswith('attachments/')}
    # Optional original Core terminal records remain immutable and validated;
    # no arbitrary claimed/actual attachment may be used as a recovery exemption.
    _require(required<=actual and actual<=required|{'effect-receipts.json','validator-results.json',
        'native-terminal-proof.json'},'recovery.original_attachment_mismatch')
    binding.check_evidence_root()
    return {'intent':intent,'plan':plan,'contract':contract,'projection':projection,'prepared':prepared,
        'parent':parent,'original_receipt':receipt,'files':files,'run':run}


def select_original(binding,run_id,request_id,intent_digest):
    value=verify_original(binding,run_id,request_id,intent_digest)
    return _NativeRecoverySelection(binding,run_id,intent_digest,request_id,
        tuple(sorted(value['files'].items())))
