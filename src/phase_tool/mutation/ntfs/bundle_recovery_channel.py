"""Fixed B2 successor channel: consumed GO and terminal-only failure capture."""
from __future__ import annotations
import time

from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from .bundle2_channel import LinuxNativeBundle2Channel
from .bundle_recovery_capture import CORE_TERMINAL_SECONDS, wire_record
from .channel import _COMMON, _RESPONSE
from .native import _require
from .uncertainty import _diagnostic


class LinuxNativeBundleRecoveryChannel(LinuxNativeBundle2Channel):
    _PROTOCOL_VERSION = '1.7'

    def recover_bundle(self, checkpoint):
        """Same consumed exchange/gate: READY, existing intent readback, one GO."""
        from .bundle_recovery import _NativeCommitCheckpoint
        from .channel import NativeChannelError,_primary
        _require(type(checkpoint) is _NativeCommitCheckpoint,'recovery.closed_checkpoint_required')
        acquired=False;primary=None;answer=None
        try:
            self._usable()
            _require(not self._inspection_only and not self._possible_dispatch
                and self._gate.acquire(blocking=False),'ntfs.channel_execution_consumed')
            acquired=True
            common={'protocol':'phase.native.pipe','version':'1.7','channel_id':self.channel_id,
                'sequence':self._sequence+1,'kind':'recover_bundle','run_id':checkpoint.context['run_id'],
                'intent_digest':checkpoint.context['intent_digest']}
            deadline=time.monotonic()+30.0
            self._sequence+=1;self._possible_dispatch=True
            self._send_frame(canonical_bytes(common|{'prepared':checkpoint.prepared,
                'recovery_context':checkpoint.context}),deadline)
            ready=self._receive_bound(common,deadline)
            self._terminal_read_boundary=True
            # Failed record persistence cannot emit GO. Its original error is
            # sticky while the parent/worker complete their negative report.
            record_error=None
            try:
                go=checkpoint.persist(ready)
                self._send_frame(canonical_bytes(go),deadline)
            except BaseException as error:
                record_error=error;self._failed=True
            until=time.perf_counter_ns()+max(0,int((deadline-time.monotonic())*1e9))+70_000_000_000
            response=self._terminal_bound(common,until)
            _require(response['ok'] is True and response['error'] is None
                and type(response['value']) is dict,'recovery.parent_response_unavailable')
            answer=response['value']
            self._terminal_value_bytes=canonical_bytes(answer)  # Before validation/late gate failure.
            if record_error is not None:
                raise PhaseError('recovery.continuation_or_go_failed',details={
                    'primary':_primary(record_error),'native_recovery_partial':answer}) from record_error
        except BaseException as error:
            self._failed=True;primary=error
        finally:
            if acquired:
                try:self._gate.release()
                except BaseException as error:
                    raise NativeChannelError('ntfs.channel_gate_finalization_unknown',possible_dispatch=self._possible_dispatch,
                        details={'primary':None if primary is None else _primary(primary),
                            'finalization':_primary(error),'native_recovery_partial':answer}) from primary
        if primary is not None:
            raise NativeChannelError('ntfs.channel_exchange_unknown',possible_dispatch=self._possible_dispatch,
                details={'primary':_primary(primary),'native_recovery_partial':answer}) from primary
        self._usable()
        return answer

    def _terminal_bound(self, common, deadline_ns):
        from .bundle_recovery_terminal import linux_terminal
        raw, _ = linux_terminal(self, deadline_ns=deadline_ns)
        value = parse_json_bytes(raw, maximum_bytes=2*1024**2)
        _require(type(value) is dict and set(value) == _RESPONSE and canonical_bytes(value) == raw
                 and type(value['ok']) is bool and type(value['sequence']) is int
                 and canonical_bytes({k:value[k] for k in _COMMON}) == canonical_bytes(common),
                 'ntfs.channel_response_binding_mismatch')
        return value

    def _bundle_terminal(self, common, deadline, *, projection, expected_pid):
        from .bundle_prepared import validate_prepared_message
        value = self._receive_bound(common, deadline)
        if 'parent_execution_version' in value:
            return value
        _require(set(value) == {'bundle_stage', 'prepared'} and value['bundle_stage'] == 'prepared',
                 'ntfs.bundle_prepared_binding_mismatch')
        message = validate_prepared_message(value['prepared'], projection=projection,
            channel_id=self.channel_id, expected_pid=expected_pid)
        self._terminal_read_boundary = True  # Complete PREPARED response, no partial reader state.
        # One absolute reporting budget. It is never passed to checkpoint ACK,
        # rewind, GO or any effect. Starvation at this boundary stays UNKNOWN.
        terminal_deadline = time.perf_counter_ns()+max(0,int((deadline-time.monotonic())*1_000_000_000))+int(CORE_TERMINAL_SECONDS*1_000_000_000)
        primary = None
        try:
            ack = self._checkpoint.persist(projection, message, channel_id=self.channel_id,
                                           expected_pid=expected_pid)
            self._send_frame(canonical_bytes(ack), deadline)
        except BaseException as error:
            primary = error
            self._failed = True
        try:
            response = self._terminal_bound(common, terminal_deadline)
        except BaseException as secondary:
            self._failed = True
            if primary is None:
                raise
            raise PhaseError('ntfs.bundle_terminal_capture_unknown', details={
                'primary': _diagnostic(primary), 'terminal_capture': ({'code':secondary.code,'details':secondary.details}
                    if isinstance(secondary,PhaseError) and secondary.code=='ntfs.terminal_frame_unknown'
                    else _diagnostic(secondary)),
                'possible_dispatch': True, 'retry_authorized': False}) from primary
        if response['ok'] is not True:
            remote = response['error']
            _require(response['value'] is None and type(remote) is dict
                     and set(remote) == {'code','message','details'}
                     and remote['code'] == 'ntfs.parent_execution_unresolved'
                     and type(remote['details']) is dict, 'ntfs.channel_response_shape')
            remote = parse_json_bytes(canonical_bytes(remote))
            if primary is not None:
                remote['details']['core_operation_primary'] = _diagnostic(primary)
            partial = remote['details'].get('parent_partial')
            if type(partial) is dict:
                self._terminal_value_bytes = canonical_bytes(partial)
            self._failed = True
            raise PhaseError('ntfs.channel_remote_failure', details={'remote_error':remote}) from primary
        answer = response['value']
        _require(response['error'] is None and type(answer) is dict, 'ntfs.channel_response_shape')
        self._terminal_value_bytes = canonical_bytes(answer)
        if primary is not None:
            # ACK exception may follow partial/complete delivery: the worker may
            # already have committed. Preserve the exact complete reply; do not
            # return PASS or authorize another effect over the failed exchange.
            remote = {'code':'ntfs.parent_execution_unresolved',
                'message':'Core ACK delivery failed; exact terminal facts retained',
                'details':{'capture_version':'1.1','parent_partial':answer,
                    'worker_completion_wire':wire_record(canonical_bytes(answer['completion'])),
                    'operation_primary':None,'operation_secondary':[],
                    'resource_closure_errors':answer['owner_finalization']['errors'],
                    'core_operation_primary':_diagnostic(primary),
                    'possible_dispatch':True,'retry_authorized':False}}
            self._failed = True
            raise PhaseError('ntfs.channel_remote_failure', details={'remote_error':remote}) from primary
        return answer
