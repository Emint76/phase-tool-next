"""Unselected native version1 physical step; existing contract/evidence owners.

Only the fixed worker may call after original verification and consumed GO.
This is archive-first/in-place, atomicity:none, not a new history store. Pins
confine operations to intended objects, not every external alias of an object.
No retry, cleanup deletion, journal, queue, fallback or independent receipt owner.
"""
from __future__ import annotations

from contextlib import ExitStack
import re

from ...canonical import digest_bytes
from ...contracts.publish_new_version_v1 import archive_locator
from ...errors import PhaseError
from ...evidence import validate_run_id
from ...paths import safe_relative_locator
from ..archive_then_publish import _receipt, _same, _unknown
from .file_create import _MutationTrace, _observe, NativeFileCreateOutcomeUnavailable
from .mutating import NativeMutationIO
from .native import NativeIdentity, _require
from .uncertainty import _diagnostic
from .root_lock import NativeRootMutex
from .scoped import NativeRootGrant, NativeScopedTarget
from .version1_observation import observe_version1_file


_LIMIT = 16*1024**2


def _version1_effect_binding(grant: NativeRootGrant, effect: dict, content: bytes) -> tuple[str,str]:
    """Closed structural binding; installation/intent authentication is external."""
    _require(type(grant) is NativeRootGrant and type(effect) is dict
        and type(content) is bytes and len(content) <= _LIMIT,'ntfs.version1_effect_binding')
    _require(effect.get('kind') == 'publish_new_version' and type(effect.get('effect_id')) is str
        and bool(effect['effect_id']) and type(effect.get('target')) is dict
        and set(effect['target']) == {'root_binding','relative_locator'}
        and effect['target']['root_binding'] == grant.binding,'ntfs.version1_effect_binding')
    current = safe_relative_locator(effect['target']['relative_locator'])
    digest = effect.get('archive_digest')
    _require(type(digest) is str and re.fullmatch('sha256:[0-9a-f]{64}',digest) is not None,
        'ntfs.version1_effect_binding')
    archive = archive_locator(digest)
    _require(current != archive and effect.get('archive_target') == {
        'root_binding':grant.binding,'relative_locator':archive}
        and type(effect.get('archive_length')) is int and 0 <= effect['archive_length'] <= _LIMIT
        and type(effect.get('content_length')) is int and effect['content_length'] == len(content)
        and effect.get('content_digest') == digest_bytes(content)
        and effect.get('preconditions') == {'existence':'present','expected_digest':digest,
            'expected_head':None,'concurrency_token':digest}
        and effect.get('lock_scope') == 'publish.'+digest_bytes(current.encode('utf-8')).removeprefix('sha256:')
        and effect.get('durability_policy_id') == 'file_data_synced'
        and effect.get('on_failure') == 'stop_and_classify','ntfs.version1_effect_binding')
    return current,archive


def _native_state(io, scope, handle, identity, length):
    scope.assert_file_name(handle,identity)
    digest,observed = io.hash_file(handle,length)
    facts = io.assert_object(handle,directory=False,expected=identity)
    _require(facts['links'] == 1 and facts['length'] == observed,'ntfs.version1_observation_changed')
    scope.assert_file_name(handle,identity)
    return ({'known':True,'exists':True,'digest':digest,'length':observed,'head_token':None},
        {'exists':True,'native_identity':identity.as_dict(),'length':observed,'digest':digest,'link_count':1})


def execute_version1(grant: NativeRootGrant, effect: dict, content: bytes,
                     *, run_id: str, timestamp: str) -> tuple[dict,dict]:
    current_locator,archive_target = _version1_effect_binding(grant,effect,content)
    validate_run_id(run_id)
    _require(type(timestamp) is str and bool(timestamp),'ntfs.invalid_effect_timestamp')
    io,trace = NativeMutationIO(),_MutationTrace(_maximum_creates=4)
    lock = NativeRootMutex(io,grant)
    before,after,archive_before,archive_after = _unknown(),_unknown(),_unknown(),_unknown()
    before_native,after_native,archive_before_native,archive_after_native = None,None,None,None
    status,error,primary = 'indeterminate',None,None
    written = 0
    finalization_errors = []
    archive_data_flushed = False
    current_data_flushed = False
    current_namespace_flushed = False
    archive_namespace_flushed = False
    try:
        with lock:
            try:
                with ExitStack() as pins:
                    current_scope = pins.enter_context(NativeScopedTarget(io,grant,current_locator,namespace_flush=True))
                    before,before_native = _observe(current_scope,_maximum_bytes=_LIMIT)
                    observed_archive = observe_version1_file(grant,archive_target)
                    archive_before,archive_before_native = observed_archive['state'],observed_archive['native']
                    after,after_native = before,before_native
                    archive_after,archive_after_native = archive_before,archive_before_native
                    lock.assert_held()
                    current_scope.assert_bound()
                    if before_native['exists'] and archive_before_native['exists']:
                        _require(before_native['native_identity'] != archive_before_native['native_identity'],
                            'ntfs.version1_current_archive_alias')
                    current_before = _same(before,effect['archive_digest'],effect['archive_length'])
                    current_after = _same(before,effect['content_digest'],effect['content_length'])
                    archive_exact = _same(archive_before,effect['archive_digest'],effect['archive_length'])
                    if current_after and archive_exact:
                        # Existing contract continuation. Receipt before is its
                        # logical archived-before state, physical samples stay
                        # separately truthful in the single Core attachment.
                        before = archive_before
                        status = 'applied_verified'
                    elif not current_before:
                        status = 'failed_no_effect'
                        error = {'code':'publish.current_mismatch','message':'publish.current_mismatch'}
                    elif archive_before['exists'] and not archive_exact:
                        status = 'failed_no_effect'
                        error = {'code':'publish.archive_conflict','message':'publish.archive_conflict'}
                    else:
                        current_id = NativeIdentity.parse(before_native['native_identity'])
                        try:
                            current = pins.enter_context(io.open_writable(current_scope.parent,current_scope.name,
                                expected_parent=current_scope.parent_identity,expected=current_id))
                        finally:
                            trace.collect(io)
                        latest,_ = _native_state(io,current_scope,current,current_id,effect['archive_length'])
                        _require(_same(latest,effect['archive_digest'],effect['archive_length']),
                            'publish.current_changed_during_archive')
                        # Provision only deterministic declared archive parents,
                        # AFTER GO, with active same-session mutations under the
                        # same root mutex. Any error seals and aborts this attempt.
                        try:
                            archive_scope = pins.enter_context(NativeScopedTarget(io,grant,archive_target,
                                namespace_flush=True,_create_ancestors=not archive_before['exists']))
                        finally:
                            trace.collect(io)
                        scoped_archive,scoped_native = _observe(archive_scope,_maximum_bytes=_LIMIT)
                        _require(scoped_archive == archive_before and scoped_native == archive_before_native,
                            'publish.archive_changed_before_publication')
                        if scoped_archive['exists']:
                            _require(_same(scoped_archive,effect['archive_digest'],effect['archive_length']),
                                'publish.archive_conflict')
                            archive_id = NativeIdentity.parse(scoped_native['native_identity'])
                            archive = pins.enter_context(archive_scope.open_file(expected=archive_id))
                        else:
                            try:
                                archive = pins.enter_context(io.create_exclusive(archive_scope.parent,
                                    archive_scope.name,directory=False,expected_parent=archive_scope.parent_identity))
                            finally:
                                trace.collect(io)
                            archive_id = io.identity(archive)
                            # Stream old bytes from the SAME pinned current
                            # object. Bound/hash the copy before truncating it.
                            offset = 0
                            for chunk in io.read_chunks(current,effect['archive_length']):
                                done = 0
                                while done < len(chunk):
                                    lock.assert_held()
                                    current_scope.assert_file_name(current,current_id)
                                    archive_scope.assert_file_name(archive,archive_id)
                                    try:
                                        count = io.write_chunk(archive,chunk[done:],offset=offset,expected=archive_id)
                                    finally:
                                        trace.collect(io)
                                    offset += count
                                    done += count
                                    written += count
                            _require(offset == effect['archive_length'],'publish.current_changed_during_archive')
                            try:
                                io.flush_file(archive,archive_id)
                                archive_data_flushed = True
                            finally:
                                trace.collect(io)
                            try:
                                io.flush_namespace(archive_scope.parent,archive_scope.parent_identity)
                                archive_namespace_flushed = True
                            finally:
                                trace.collect(io)
                        _require(current_id != archive_id,'ntfs.version1_current_archive_alias')
                        archive_after,archive_after_native = _native_state(io,archive_scope,archive,
                            archive_id,effect['archive_length'])
                        _require(_same(archive_after,effect['archive_digest'],effect['archive_length']),
                            'publish.archive_verification_failed')
                        latest,_ = _native_state(io,current_scope,current,current_id,effect['archive_length'])
                        _require(_same(latest,effect['archive_digest'],effect['archive_length']),
                            'publish.current_changed_during_archive')
                        lock.assert_held()
                        archive_scope.assert_file_name(archive,archive_id)
                        current_scope.assert_file_name(current,current_id)
                        try:
                            io.truncate(current,length=0,expected=current_id)
                        finally:
                            trace.collect(io)
                        offset = 0
                        while offset < len(content):
                            lock.assert_held()
                            archive_scope.assert_file_name(archive,archive_id)
                            current_scope.assert_file_name(current,current_id)
                            try:
                                count = io.write_chunk(current,content[offset:offset+1024**2],
                                    offset=offset,expected=current_id)
                            finally:
                                trace.collect(io)
                            offset += count
                            written += count
                        try:
                            io.flush_file(current,current_id)
                            current_data_flushed = True
                        finally:
                            trace.collect(io)
                        try:
                            io.flush_namespace(current_scope.parent,current_scope.parent_identity)
                            current_namespace_flushed = True
                        finally:
                            trace.collect(io)
                        after,after_native = _native_state(io,current_scope,current,current_id,len(content))
                        archive_after,archive_after_native = _native_state(io,archive_scope,archive,
                            archive_id,effect['archive_length'])
                        lock.assert_held()
                        verified = _same(after,effect['content_digest'],effect['content_length']) and _same(
                            archive_after,effect['archive_digest'],effect['archive_length'])
                        status = 'applied_verified' if verified else 'applied_unverified'
                        if not verified:
                            error = {'code':'verification.result_mismatch','message':'verification.result_mismatch'}
            except BaseException as caught:
                # No further mutating call after ANY exception. Preserve unknown
                # partial bytes (including a failed write's unacknowledged count)
                # rather than claiming bytes_written=0 or resuming a new session.
                status,written = 'indeterminate',None
                primary = _diagnostic(caught)
                error = {'code':primary['code'] if type(primary['code']) is str else 'ntfs.native_execution_failed',
                    'message':primary['message']}
                try:
                    io.seal_mutations()
                except BaseException as sealing_error:
                    finalization_errors.append(_diagnostic(sealing_error))
                status,written = 'indeterminate',None
                after,after_native,archive_after,archive_after_native = _unknown(),None,_unknown(),None
                # The mutex is still held. Read-only observations may refine
                # target facts, but cannot establish process quiescence/retry.
                try:
                    observed = observe_version1_file(grant,current_locator)
                    after,after_native = observed['state'],observed['native']
                    observed = observe_version1_file(grant,archive_target)
                    archive_after,archive_after_native = observed['state'],observed['native']
                except BaseException as observing_error:
                    finalization_errors.append(_diagnostic(observing_error))
                raise
    except BaseException as caught:
        status,written = 'indeterminate',None
        secondary = _diagnostic(caught)
        if primary is None:
            primary = secondary
            error = {'code':primary['code'] if type(primary['code']) is str else 'ntfs.native_execution_failed',
                'message':primary['message']}
        elif secondary != primary:
            # NativeRootMutex may wrap a body error with a separate release,
            # close or root-scope finalization failure. Preserve both facts.
            finalization_errors.append(secondary)
    finally:
        try:
            trace.collect(io)
        except BaseException as caught:
            finalization_errors.append(_diagnostic(caught))
        try:
            io.seal_mutations()
        except BaseException as caught:
            finalization_errors.append(_diagnostic(caught))
    closed = not io._handles and lock.state == 'closed' and io.mutation_state == 'sealed' and not finalization_errors
    if not closed:
        status,after,after_native,archive_after,archive_after_native = 'indeterminate',_unknown(),None,_unknown(),None
        error = {'code':'ntfs.worker_finalization_unknown','message':'ntfs.worker_finalization_unknown'}
    evidence = {'native_version1_effect_version':'1.0','run_id':run_id,'effect_id':effect['effect_id'],
        'grant':grant.as_dict(),'locator':current_locator,'archive_locator':archive_target,
        'before':before_native,'after':after_native,'archive_before':archive_before_native,'archive_after':archive_after_native,
        'archive_data_flushed':archive_data_flushed,'archive_namespace_flushed':archive_namespace_flushed,
        'current_data_flushed':current_data_flushed,'current_namespace_flushed':current_namespace_flushed,
        'mutation_trace':trace.snapshot(),'mutex_events':lock.events,'mutex_state':lock.state,
        'mutation_session_state':io.mutation_state,'handle_finalization':'closed' if closed else 'unknown',
        'remaining_handle_count':len(io._handles),'primary_error':primary,'finalization_errors':finalization_errors,
        'worker_exit_established':False}
    if not before['known'] or not archive_before['known']:
        raise NativeFileCreateOutcomeUnavailable(evidence)
    receipt = _receipt(effect,run_id=run_id,timestamp=timestamp,status=status,attempted=True,
        before=before,after=after,archive_before=archive_before,archive_after=archive_after,
        bytes_written=written,verification_refs=['native.current.after','native.archive.after'] if status == 'applied_verified' else [],
        error_code=None if error is None else error['code'],error_message=None if error is None else error['message'])
    return receipt,evidence
