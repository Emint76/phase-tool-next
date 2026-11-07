"""B2 checkpoint messages and the existing Core prepared-record writer.

Transient frames within one execution, not a journal, queue or second receipt.
The Windows worker retains its mutex/stage lease until the same Core confirms
both existing ext4 records. These messages never confer storage qualification.
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ...mutation.bundle_create import stage_name
from .native import _require

_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_CHANNEL = re.compile(r'[0-9a-f]{32}')
_LIMIT = 32768


def prepared_locator(projection):
    from .bundle_execution import _bundle_projection_value, _BUNDLE2_CONTRACTS
    value = _bundle_projection_value(projection)
    _require(value['contract'] in _BUNDLE2_CONTRACTS, 'ntfs.bundle2_projection_required')
    target = value['effect']['target']['relative_locator']
    parent = target.rsplit('/',1)[0]+'/' if '/' in target else ''
    return parent+stage_name(value['context']['run_id'],value['effect'])


def prepared_message(projection, channel_id, pid, stage_native):
    """The supplied native data are from verify_bundle_handle, still leased."""
    from .bundle_execution import _bundle_projection_value
    value = _bundle_projection_value(projection)
    message = {'bundle_prepared_version':'1.0','context':value['context'],
        'channel_id':channel_id,'pid':pid,'stage_locator':prepared_locator(projection),
        'root_mutex_state':'held','stage_lease':'retained','native':stage_native}
    return validate_prepared_message(message,projection=projection,channel_id=channel_id,expected_pid=pid)


def validate_prepared_message(message, *, projection, channel_id, expected_pid=None):
    from .bundle_execution import _bundle_projection_value, _validate_bundle_content, _BUNDLE2_CONTRACTS
    value = _bundle_projection_value(projection)
    _require(value['contract'] in _BUNDLE2_CONTRACTS
        and type(channel_id) is str and _CHANNEL.fullmatch(channel_id) is not None,
        'ntfs.bundle2_projection_required')
    _require(type(message) is dict and set(message) == {'bundle_prepared_version','context',
        'channel_id','pid','stage_locator','root_mutex_state','stage_lease','native'}
        and message['bundle_prepared_version'] == '1.0'
        and canonical_bytes(message['context']) == canonical_bytes(value['context'])
        and message['channel_id'] == channel_id and type(message['pid']) is int and message['pid'] > 0
        and (expected_pid is None or type(expected_pid) is int and message['pid'] == expected_pid)
        and message['stage_locator'] == prepared_locator(projection)
        and message['root_mutex_state'] == 'held' and message['stage_lease'] == 'retained',
        'ntfs.bundle_prepared_binding_mismatch')
    native = message['native']
    state = {'known':True,'exists':True,'digest':projection.content_digest,
        'length':projection.content_length,'head_token':None}
    # Byte/identity validation does not falsely claim the retained stage HANDLE
    # is finalized. Finished-observer closure belongs to its separate wrapper.
    _validate_bundle_content(state,native,value['grant'],projection=projection)
    raw = canonical_bytes(message)
    _require(len(raw) <= _LIMIT, 'ntfs.bundle_prepared_frame_limit')
    return parse_json_bytes(raw)


def prepared_ack(message, prepared_digest, binding_digest):
    _require(all(type(x) is str and _DIGEST.fullmatch(x) is not None
                 for x in (prepared_digest,binding_digest)), 'ntfs.bundle_prepared_digest_required')
    return {'bundle_prepared_ack_version':'1.0','context':message['context'],
        'channel_id':message['channel_id'],'prepared_message_digest':digest_bytes(canonical_bytes(message)),
        'prepared_stage_digest':prepared_digest,'preparation_binding_digest':binding_digest}


def validate_prepared_ack(raw, *, message):
    _require(type(raw) is bytes and 0 < len(raw) <= _LIMIT, 'ntfs.bundle_prepared_frame_limit')
    ack = parse_json_bytes(raw,maximum_bytes=_LIMIT)
    _require(type(ack) is dict and set(ack) == {'bundle_prepared_ack_version','context','channel_id',
        'prepared_message_digest','prepared_stage_digest','preparation_binding_digest'}
        and canonical_bytes(ack) == raw, 'ntfs.bundle_prepared_ack_shape')
    expected = prepared_ack(message,ack['prepared_stage_digest'],ack['preparation_binding_digest'])
    _require(canonical_bytes(ack) == canonical_bytes(expected), 'ntfs.bundle_prepared_ack_binding_mismatch')
    return ack


class _CoreBundleCheckpoint:
    """One callback owned by the existing Core native authority and exchange.

    It writes only prepared-stage.json and preparation-binding.json in the
    original run. It cannot publish a target, receipt, new intent or recovery.
    """
    def __init__(self, binding, store, contract, plan, intent_path, expected_intent_digest, operation_nonce,
                 attachment_digests):
        from ...installation import _NativeFileCreateReadBinding
        from ...evidence import EvidenceStore
        from .bundle_execution import _BUNDLE2_CONTRACT, _BUNDLE2_CONTRACT_V2, _BUNDLE2_CONTRACTS
        _require(type(binding) is _NativeFileCreateReadBinding and type(store) is EvidenceStore
            and type(attachment_digests) is list
            and all(type(d) is str and _DIGEST.fullmatch(d) is not None for d in attachment_digests)
            and type(expected_intent_digest) is str and _DIGEST.fullmatch(expected_intent_digest) is not None,
            'ntfs.original_closed_checkpoint_required')
        exact={'id':contract.document['identity']['id'],'version':contract.document['identity']['version'],
            'package_digest':contract.package_digest}
        _require(exact in _BUNDLE2_CONTRACTS and plan['contract'] == exact, 'ntfs.bundle2_projection_required')
        manifest = parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
        _require(((manifest['native_read_installation_version']=='1.7' and exact==_BUNDLE2_CONTRACT)
            or (manifest['native_read_installation_version'] in {'1.8','1.9'} and exact==_BUNDLE2_CONTRACT_V2))
            and intent_path == Path(manifest['evidence_root'])/'.phase'/'runs'/plan['run_id']/'intent.json'
            and store.run_root == intent_path.parent and store.evidence_root == Path(manifest['evidence_root'])
            and type(operation_nonce) is str and _CHANNEL.fullmatch(operation_nonce) is not None,
            'ntfs.original_evidence_path_mismatch')
        self._owner = os.getpid(),threading.get_ident()
        self._binding,self._store,self._contract = binding,store,contract
        self._attachment_digests=attachment_digests  # The original Core receipt's list, not another owner.
        self._plan_bytes,self._intent_path = canonical_bytes(plan),intent_path
        self._intent_digest = expected_intent_digest
        self._nonce = operation_nonce
        self._attempted = False
        self._ack_bytes = None
        self._projection_bytes = None
        self._prepared_bytes = None
        self._bind_attempted = False

    def bind_projection(self,projection):
        """Correlate the already payload-verified original without rereading it.

        Reuse the existing pure original parser for installation, precondition,
        native binding, plan and full projection checks. No second blob stream.
        """
        from .bundle_execution import _bundle_projection_value
        from .intent import _parse_bundle_control_projection
        from ...streaming import read_bounded_file
        _require(self._owner == (os.getpid(),threading.get_ident())
            and not self._bind_attempted and self._projection_bytes is None and not self._attempted,
            'ntfs.bundle_prepared_checkpoint_consumed')
        self._bind_attempted=True
        original=read_bounded_file(self._intent_path,2*1024**2)
        intent=parse_json_bytes(original,maximum_bytes=2*1024**2)
        pre=read_bounded_file(self._intent_path.parent/'attachments/pre-validator-results.json',2*1024**2)
        parsed=_parse_bundle_control_projection(intent_bytes=original,plan_bytes=self._plan_bytes,
            pre_validator_bytes=pre,manifest_bytes=projection.manifest_bytes,registry=self._binding.registry,
            expected_run_id=self._store.run_root.name,expected_intent_digest=self._intent_digest,
            _execution_requested=True,**self._binding._parser_bindings(intent))
        value=_bundle_projection_value(parsed)
        _require(value['context']['operation_nonce']==self._nonce
            and canonical_bytes(value)==canonical_bytes(_bundle_projection_value(projection)),
            'ntfs.original_prepared_intent_mismatch')
        self._projection_bytes=canonical_bytes(value)

    def persist(self, projection, message, *, channel_id, expected_pid):
        from .bundle_execution import _bundle_projection_value
        from ...continuation import prepared_record, save_prepared_record, validate_record_schema
        from ...prepared_binding import verify_prepared_binding
        from ...recovery import read_record
        from ...streaming import read_bounded_file
        _require(self._owner == (os.getpid(),threading.get_ident()) and not self._attempted,
            'ntfs.bundle_prepared_checkpoint_consumed')
        self._attempted = True  # Sticky before any write, including partial failure.
        _require(type(expected_pid) is int and expected_pid > 0,'ntfs.worker_pid_required')
        self._binding.check_evidence_root()
        message = validate_prepared_message(message,projection=projection,channel_id=channel_id,
            expected_pid=expected_pid)
        value = _bundle_projection_value(projection); context = value['context']
        _require(self._projection_bytes is not None and canonical_bytes(value)==self._projection_bytes,
            'ntfs.original_prepared_intent_mismatch')
        original = read_bounded_file(self._intent_path,2*1024**2)
        intent = parse_json_bytes(original,maximum_bytes=2*1024**2)
        plan = parse_json_bytes(self._plan_bytes)
        _require(canonical_bytes(intent) == original
            and profile_digest('intent',intent) == self._intent_digest == context['intent_digest']
            and intent['run_id'] == plan['run_id'] == context['run_id']
            and intent['effect_plan_digest'] == context['effect_plan_digest'] == profile_digest('effect-plan',plan)
            and intent['contract'] == plan['contract'] == value['contract']
            and plan['effects'] == [value['effect']], 'ntfs.original_prepared_intent_mismatch')
        native = message['native']; pair = native['stat_identity']
        prepared = prepared_record(intent,value['effect'],message['stage_locator'],
            device=pair['device'],inode=pair['inode'])
        run = self._intent_path.parent
        validate_record_schema(self._binding.registry,self._contract,'schemas/prepared-stage.schema.json',prepared)
        self._prepared_bytes=canonical_bytes(prepared)
        primary=None
        try:
            save_prepared_record(intent,value['effect'],prepared,run,
                _native_store=self._store,_native_binding=self._binding)
        except BaseException as error:
            primary=error
            raise
        finally:
            try:
                digest=self.attachment_digest()
                if digest is not None and digest not in self._attachment_digests:
                    self._attachment_digests.append(digest)
            except BaseException as secondary:
                if primary is None:raise
                try:primary.add_note('Prepared attachment readback: '+type(secondary).__name__)
                except BaseException:pass
        # Existing helpers verify schema, complete original lineage and the
        # durable binding file; no ACK after only the first write.
        checked = verify_prepared_binding(self._binding.registry,self._contract,intent,plan,run)
        _require(checked == prepared, 'recovery.preparation_mismatch')
        binding = read_record(run/'preparation-binding.json')
        ack = prepared_ack(message,digest_bytes(canonical_bytes(checked)),digest_bytes(canonical_bytes(binding)))
        self._binding.check_evidence_root()
        self._ack_bytes = canonical_bytes(ack)
        return ack

    def attachment_digest(self):
        """Only actually saved bytes enter the original Core receipt, even on failure."""
        from ...streaming import read_bounded_file
        _require(self._owner == (os.getpid(),threading.get_ident()),'ntfs.channel_owner_changed')
        if self._prepared_bytes is None:return None
        try:raw=read_bounded_file(self._store.run_root/'attachments/prepared-stage.json',32768)
        except FileNotFoundError:return None
        _require(raw==self._prepared_bytes,'recovery.preparation_mismatch')
        return digest_bytes(raw)
