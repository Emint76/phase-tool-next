"""Unselected physical file step; no Core admission, IPC or completion proof.

The future trusted caller must first authenticate original intent/installation
grant, and establish process exit afterwards. Existing parents; fixed1MiB file1
and2GiB file2 roles. Never deletes, retries or creates document versions.
"""
from __future__ import annotations

from collections import deque
import hashlib
import json
import re
from typing import Any

from ...canonical import canonical_bytes, digest_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from ..exclusive_create import _receipt, _unknown
from .native import NativeIO, NativeIdentity, _require
from .mutating import NativeMutationIO
from .root_lock import NativeRootMutex
from .uncertainty import _diagnostic
from .scoped import NativeRootGrant, NativeScopedTarget


_CONTENT_LIMIT = 1024**2


class NativeFileCreateOutcomeUnavailable(PhaseError):
    """No valid effect receipt; retain physical evidence, do not invent one.

    A relay that has sent work must preserve possible-dispatch classification.
    This exception alone never authorizes replay or resolves the Core intent.
    """
    def __init__(self, evidence: dict[str, Any]):
        self.evidence = evidence
        super().__init__('ntfs.effect_outcome_unavailable')


class _MutationTrace:
    """Bound diagnostics, not execution: hash every completed recorded event.

    NativeMutationIO appends before its postchecks; collect only after each
    method returned/raised so the committed event includes final postcheck data.
    Prefix/suffix omission is explicit. This is not every native syscall, an
    execution log authority, or a replacement for independent qualification.
    """
    def __init__(self, *, _maximum_creates: int = 1):
        _require(type(_maximum_creates) is int and _maximum_creates in (1,4,6),
                 'ntfs.invalid_trace_role')
        self._maximum_creates = _maximum_creates
        self._create_events: list[dict] = []
        self._hash = hashlib.sha256()
        self._first: list[dict] = []
        self._last: deque[dict] = deque(maxlen=64)
        self.count = 0
        self.create_event: dict | None = None
        self.capture_complete = True
        self.capture_errors: list[dict] = []
        self.unprocessed_records = 0

    def collect(self, io: NativeMutationIO) -> None:
        pending,io.events = io.events,[]
        completed = 0
        try:
            for event in pending:
                raw = canonical_bytes(event)
                value = json.loads(raw)
                # Every successful hash commit is counted before any later
                # bookkeeping that could fail. No detached list is reprocessed.
                self._hash.update(raw+b'\n')
                self.count += 1
                completed += 1
                if len(self._first) < 64:
                    self._first.append(value)
                self._last.append(value)
                if value.get('api') == 'NtCreateFile' and value.get('disposition') == 2:
                    _require(len(self._create_events) < self._maximum_creates,'ntfs.multiple_create_calls_forbidden')
                    self._create_events.append(value)
                    if self.create_event is None:
                        self.create_event = value
        except BaseException as caught:
            self.capture_complete = False
            self.unprocessed_records += len(pending)-completed
            self.capture_errors.append(_diagnostic(caught))
            raise

    def snapshot(self) -> dict:
        records = self._first if self.count <= 64 else self._first+list(self._last)[-(self.count-64):]
        return {'acknowledged_recorded_event_count':self.count,
                'canonical_jsonl_digest':'sha256:'+self._hash.hexdigest() if self.capture_complete else None,
                'partial_hasher_digest':None if self.capture_complete else 'sha256:'+self._hash.hexdigest(),
                'records':records,'raw_records_complete':self.capture_complete and self.count <= 128,
                'capture_complete':self.capture_complete,'unacknowledged_records_upper_bound':self.unprocessed_records,
                'capture_errors':self.capture_errors,
                'omitted_middle_records':self.count-len(records),
                'scope':'NativeMutationIO mutation/flush event records, not every OS syscall'}


def _observe(scope: NativeScopedTarget, *, expected: NativeIdentity | None = None,
             _maximum_bytes: int = _CONTENT_LIMIT) -> tuple[dict[str, Any], dict[str, Any]]:
    # Four code-owned contract bounds; the default file-create role retains
    # its original 1 MiB behavior. No request supplies a size selector.
    _require(type(_maximum_bytes) is int and _maximum_bytes in (_CONTENT_LIMIT,16*1024**2,2*1024**3,512*1024),
             'ntfs.invalid_observation_bound')
    _require(not scope._missing_ancestors,'ntfs.partial_scope_has_no_leaf_parent')
    io = scope.io
    scope.assert_bound()
    try:
        # This catch covers ONLY the final-leaf open, not ancestor postchecks.
        handle = io.child(scope.parent,scope.name,directory=False)
    except PhaseError as error:
        if error.code == 'ntfs.open_failed' and error.details == {'ntstatus':'0xc0000034'}:
            scope.assert_bound()
            return ({'known':True,'exists':False,'digest':None,'length':None,'head_token':None},
                    {'exists':False,'native_identity':None})
        raise
    with handle:
        facts = io.assert_object(handle,directory=False,expected=expected)
        identity = io.identity(handle)
        length = facts['length']
        digest = None
        if _maximum_bytes in (16*1024**2,512*1024):
            _require(length <= _maximum_bytes,
                'ntfs.version2_file_too_large' if _maximum_bytes==512*1024 else 'ntfs.version1_file_too_large')
        if length <= _maximum_bytes:
            digest,observed = io.hash_file(handle,length)
            _require(observed == length,'ntfs.observation_length_mismatch')
        if _maximum_bytes != _CONTENT_LIMIT:
            final = io.assert_object(handle,directory=False,expected=identity)
            _require(final['length'] == length and final['links'] == facts['links'] == 1,
                     'ntfs.version1_observation_changed' if _maximum_bytes==16*1024**2 else
                     'ntfs.version2_observation_changed' if _maximum_bytes==512*1024 else 'ntfs.file2_observation_changed')
        scope.assert_file_name(handle,identity)
        state = {'known':True,'exists':True,'digest':digest,'length':length,'head_token':None}
        proof = {'exists':True,'native_identity':identity.as_dict(),'length':length,
                 'digest':digest,'link_count':facts['links']}
    scope.assert_bound()
    return state,proof


def observe_file(grant: NativeRootGrant, locator: str, *, expected: NativeIdentity | None = None) -> dict[str, Any]:
    """Read-only native role: no NativeMutationIO, mutable opens or fallback."""
    _require(type(grant) is NativeRootGrant,'ntfs.invalid_root_grant')
    locator = safe_relative_locator(locator)
    io = NativeIO()
    with NativeScopedTarget(io,grant,locator) as scope:
        state,proof = _observe(scope,expected=expected)
    _require(not io._handles,'ntfs.observer_handle_finalization_unknown')
    return {'observation_version':'1.0','state':state,'native':proof,
            'grant':grant.as_dict(),'locator':locator,'handles_finalized':True}


def execute_file_create(grant: NativeRootGrant, effect: dict[str, Any], content: bytes,
                        *, run_id: str, timestamp: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """One actual FILE_CREATE call and standard effect receipt, never fake attempt.

    Already-existing files still receive the safe exclusive FILE_CREATE request:
    a documented collision plus native readback supports failed_no_effect. If
    no native call result was recorded, raise OutcomeUnavailable with evidence.
    A supervisor must independently establish worker termination in either case.
    """
    _require(type(grant) is NativeRootGrant and type(effect) is dict,'ntfs.invalid_effect_owner')
    _require(type(content) is bytes and len(content) <= _CONTENT_LIMIT,'mechanism.content_too_large')
    _require(type(run_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',run_id) is not None,
             'evidence.invalid_run_id')
    _require(type(timestamp) is str and bool(timestamp),'ntfs.invalid_effect_timestamp')
    _require(effect.get('kind') == 'exclusive_create' and type(effect.get('effect_id')) is str,'ntfs.unsupported_effect')
    target = effect.get('target')
    _require(type(target) is dict and set(target) == {'root_binding','relative_locator'}
             and target['root_binding'] == grant.binding,'ntfs.effect_grant_mismatch')
    locator = safe_relative_locator(target['relative_locator'])
    _require(effect.get('preconditions') == {'existence':'absent','expected_digest':None,
             'expected_head':None,'concurrency_token':None},'ntfs.unsupported_preconditions')
    _require(type(effect.get('content_length')) is int and effect['content_length'] == len(content)
             and effect.get('content_digest') == digest_bytes(content),'mechanism.content_binding_mismatch')
    return _execute_bound_file_create(grant,effect,content,run_id=run_id,timestamp=timestamp)


def execute_file2_create(grant: NativeRootGrant, effect: dict[str, Any], source,
                         *, run_id: str, timestamp: str):
    """Same native create step; fixed verified replay, no bytes/size callback selector."""
    from .file2_execution import _File2WorkerInput,_file2_effect
    _require(type(grant) is NativeRootGrant and type(source) is _File2WorkerInput,
        'ntfs.original_file2_projection_required')
    source._check()
    _require(source._go_attempted and not source.complete
        and source._receiver._state=='replay','ntfs.worker_go_binding_mismatch')
    accepted=_file2_effect(grant.as_dict(),effect,source.content_digest,source.content_length)
    _require(canonical_bytes(accepted.as_dict())==canonical_bytes(grant.as_dict())
        and canonical_bytes(effect)==source.projection.effect_bytes
        and source.projection.timestamp==timestamp,'ntfs.original_current_invocation_mismatch')
    context=json.loads(source.projection.context_bytes)
    _require(context['run_id']==run_id and type(timestamp) is str and 0<len(timestamp)<=128,
        'ntfs.original_current_invocation_mismatch')
    return _execute_bound_file_create(grant,effect,None,run_id=run_id,
        timestamp=timestamp,_file2_source=source)


def _execute_bound_file_create(grant,effect,content,*,run_id,timestamp,_file2_source=None):
    # One physical implementation/trace. Public fixed wrappers above own all
    # role checks; operation input cannot select this private source or a bound.
    locator=safe_relative_locator(effect['target']['relative_locator'])
    file2=_file2_source is not None
    length=_file2_source.content_length if file2 else len(content)
    maximum=2*1024**3 if file2 else _CONTENT_LIMIT
    io,trace = NativeMutationIO(),_MutationTrace()
    before,after = _unknown(),_unknown()
    before_native,after_native = None,None
    written = 0
    status,error,primary = 'indeterminate',None,None
    finalization_errors = []
    lock = NativeRootMutex(io,grant)
    try:
        with lock:
            with NativeScopedTarget(io,grant,locator,namespace_flush=True) as scope:
                before,before_native = _observe(scope,_maximum_bytes=maximum)
                lock.assert_held()
                scope.assert_bound()
                try:
                    with io.create_exclusive(scope.parent,scope.name,directory=False,
                                             expected_parent=scope.parent_identity) as handle:
                        trace.collect(io)
                        identity = io.identity(handle)
                        if not file2:
                            # Historical bytes branch and partial-write order.
                            while written < len(content):
                                lock.assert_held()
                                scope.assert_bound()
                                try:
                                    written += io.write_chunk(handle,content[written:],offset=written,expected=identity)
                                finally:
                                    trace.collect(io)
                        else:
                            while written < length:
                                chunk=_file2_source.next_chunk()  # Hash-vector check BEFORE native partial writes.
                                _require(type(chunk) is bytes and 0<len(chunk)<=256*1024,
                                    'ntfs.file2_chunk_bound')
                                offset=0
                                while offset<len(chunk):
                                    lock.assert_held();scope.assert_bound()
                                    try:
                                        count=io.write_chunk(handle,chunk[offset:],offset=written,expected=identity)
                                        offset+=count;written+=count
                                    finally:
                                        trace.collect(io)
                            _file2_source.finish_remaining()  # Exact replay END/hash/length before flush/readback.

                        try:
                            io.flush_file(handle,identity)
                        finally:
                            trace.collect(io)
                        try:
                            io.flush_namespace(scope.parent,scope.parent_identity)
                        finally:
                            trace.collect(io)
                        digest,observed = io.hash_file(handle,length)
                        scope.assert_file_name(handle,identity)
                        lock.assert_held()
                        after = {'known':True,'exists':True,'digest':digest,'length':observed,'head_token':None}
                        after_native = {'exists':True,'native_identity':identity.as_dict(),
                                        'digest':digest,'length':observed,'link_count':io.info(handle)['links']}
                        status = 'applied_verified' if digest == effect['content_digest'] and observed == effect['content_length'] else 'applied_unverified'
                        if status == 'applied_unverified':
                            error = {'code':'verification.result_mismatch','message':'verification.result_mismatch'}
                except PhaseError as caught:
                    trace.collect(io)
                    event = trace.create_event
                    if (caught.code == 'ntfs.create_failed' and event is not None
                            and event.get('return_status') == '0xc0000035'
                            and event.get('effect_state') == 'not_committed_by_this_call'
                            and event.get('output_handle_present') is False
                            and 'close_error' not in event):
                        after,after_native = _observe(scope,_maximum_bytes=maximum)
                        status = 'failed_no_effect'
                        error = {'code':'target.destination_exists','message':'target.destination_exists'}
                    else:
                        raise
                finally:
                    trace.collect(io)
            lock.assert_held()
    except BaseException as caught:
        # Keep the original error without invoking its diagnostic methods.
        primary = caught
        status,after,after_native = 'indeterminate',_unknown(),None
    finally:
        # A collision/native failure must still consume the healthy SAME data
        # stream so the sole sender can finish. This is data drain, not an effect
        # retry or a second RPC. A poisoned receiver never resynchronizes.
        if file2:
            try:
                if not _file2_source.complete:
                    _file2_source.finish_remaining()
            except BaseException as caught:
                finalization_errors.append(caught)
        # Both are monotonic terminal operations, no native handle-close retry.
        # Preserve the original error if either diagnostic/seal step fails.
        try:
            trace.collect(io)
        except BaseException as caught:
            finalization_errors.append(caught)
        try:
            io.seal_mutations()
        except BaseException as caught:
            finalization_errors.append(caught)
    # Every drain/trace/seal action has now been attempted. Rendering cannot
    # prevent another essential finalizer or change the acknowledged byte count.
    primary_info = None if primary is None else _diagnostic(primary)
    if primary_info is not None:
        error = {'code':primary_info['code'] if type(primary_info['code']) is str
            else 'ntfs.native_execution_failed','message':primary_info['message']}
    finalization_info = [_diagnostic(caught) for caught in finalization_errors]
    prior_effect={'status':status,'error':error,'acknowledged_bytes_written':written}
    closed = not io._handles and lock.state == 'closed' and io.mutation_state == 'sealed' and not finalization_errors
    if not closed:
        status,after,after_native = 'indeterminate',_unknown(),None
        error = {'code':'ntfs.worker_finalization_unknown','message':'ntfs.worker_finalization_unknown'}
    evidence = {'native_file_create_version':'2.0' if file2 else '1.0','run_id':run_id,'effect_id':effect['effect_id'],
        'grant':grant.as_dict(),'locator':locator,'before':before_native,'after':after_native,
        'mutation_trace':trace.snapshot(),'mutex_events':lock.events,'mutex_state':lock.state,
        'mutation_session_state':io.mutation_state,'handle_finalization':'closed' if closed else 'unknown',
        'remaining_handle_count':len(io._handles),'primary_error':primary_info,'finalization_errors':finalization_info,
        'worker_exit_established':False}
    if file2:
        evidence['stream_binding']=_file2_source.stream_facts()
        evidence['effect_before_finalization']=prior_effect
    if trace.create_event is None:
        unavailable = NativeFileCreateOutcomeUnavailable(evidence)
        unavailable.primary_error = primary
        unavailable.finalization_errors = tuple(finalization_errors)
        raise unavailable from primary
    refs = ['native.file.readback'] if status == 'applied_verified' else ['native.create.collision','native.target.after'] if status == 'failed_no_effect' else []
    receipt = _receipt(effect,run_id=run_id,timestamp=timestamp,status=status,attempted=True,
        before=before,after=after,bytes_written=written,verification_refs=refs,
        error_code=None if error is None else error['code'],error_message=None if error is None else error['message'])
    return receipt,evidence
