"""UNQUALIFIED closed file2 exchange in the existing Core control pipe/gate.

One execute epoch, no second RPC/queue/process owner. The thirty-second local
protocol window is deliberately NOT a qualified full2GiB performance envelope.
Only a fixed authenticated installation constructs this role; data cannot.
"""
from __future__ import annotations

import os
import re
import threading
import time

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from .channel import NativeChannelError, _COMMON, _RESPONSE, _MAX_FRAME, _primary
from .channel_v2 import LinuxNativeChannelV2
from .native import _require
from .file2_stream import _File2SnapshotSource
from .file2_execution import _file2_projection_value, _file2_header, validate_file2_worker_ready


class LinuxNativeChannelV4(LinuxNativeChannelV2):
    _PROTOCOL_VERSION='1.3'
    _EXECUTE_KINDS=frozenset({'execute_file2'})

    def __init__(self,channel_id,*,_inspection_only=False):
        super().__init__(channel_id,_inspection_only=_inspection_only)
        self._terminal_value_bytes=None

    def _request(self,kind,run_id,intent_digest,payload):
        _require(kind not in {'execute_file_create','execute_version1'},'ntfs.original_closed_role_required')
        if kind!='execute_file2':return super()._request(kind,run_id,intent_digest,payload)
        _require(not self._inspection_only and not self._finish_attempted,
            'ntfs.inspection_only_operation_forbidden')
        from .channel import _RUN,_DIGEST
        _require(type(run_id) is str and _RUN.fullmatch(run_id) is not None,
            'evidence.invalid_run_id')
        _require(type(intent_digest) is str and _DIGEST.fullmatch(intent_digest) is not None
            and type(payload) is dict and not payload,'ntfs.invalid_intent_reference')
        return payload

    def _send_frame(self,raw,deadline):
        _require(type(raw) is bytes and 0<len(raw)<=_MAX_FRAME,'ntfs.channel_frame_limit')
        self._write(f'{len(raw):08x}\n'.encode('ascii')+raw+b'\n',deadline)

    def _receive_bound(self,common,deadline):
        header=self._read(9,deadline)
        _require(re.fullmatch(b'[0-9a-f]{8}\n',header) is not None,'ntfs.channel_bad_header')
        length=int(header[:8],16)
        _require(0<length<=_MAX_FRAME,'ntfs.channel_frame_limit')
        raw=self._read(length,deadline)
        _require(self._read(1,deadline)==b'\n','ntfs.channel_bad_terminator')
        value=parse_json_bytes(raw,maximum_bytes=_MAX_FRAME)
        _require(type(value) is dict and set(value)==_RESPONSE and canonical_bytes(value)==raw
            and type(value['sequence']) is int and type(value['ok']) is bool
            and canonical_bytes({k:value[k]for k in _COMMON})==canonical_bytes(common),
            'ntfs.channel_response_binding_mismatch')
        if value['ok'] is not True:
            remote=value['error']
            _require(value['value'] is None and type(remote) is dict
                and set(remote)=={'code','message','details'} and type(remote['code']) is str
                and type(remote['message']) is str and type(remote['details']) is dict,
                'ntfs.channel_response_shape')
            # Retained raw partial data are diagnosis, never a positive result.
            partial=remote['details'].get('parent_partial')
            if type(partial) is dict:self._terminal_value_bytes=canonical_bytes(partial)
            raise PhaseError('ntfs.channel_remote_failure',details={'remote_error':remote})
        _require(value['error'] is None and type(value['value']) is dict,'ntfs.channel_response_shape')
        return value['value']

    def captured_file2_completion(self):
        """Bounded transport data after failure; never revives a poisoned channel.

        Core validates its context/effect/schema before retaining a partial
        receipt in its EXISTING evidence. This is not another evidence owner.
        """
        _require(self._owner==(os.getpid(),threading.get_ident()),'ntfs.channel_owner_changed')
        return self._terminal_value_bytes

    def execute_file2(self,*,run_id,intent_digest,projection,source):
        acquired=False;primary=None;request_raw=None;answer=None
        try:
            self._usable()
            _require(self._gate.acquire(blocking=False),'ntfs.channel_reentrant_call')
            acquired=True;self._usable()
            self._request('execute_file2',run_id,intent_digest,{})
            _require(not self._possible_dispatch,'ntfs.channel_execution_consumed')
            value=_file2_projection_value(projection)
            _require(value['context']['run_id']==run_id
                and value['context']['intent_digest']==intent_digest
                and type(source) is _File2SnapshotSource
                and source._header_raw==_file2_header(projection,self.channel_id),
                'ntfs.original_current_invocation_mismatch')
            source._check('first-unused')
            common={'protocol':'phase.native.pipe','version':self._PROTOCOL_VERSION,
                'channel_id':self.channel_id,'sequence':self._sequence+1,
                'kind':'execute_file2','run_id':run_id,'intent_digest':intent_digest}
            request_raw=canonical_bytes(common)
            deadline=time.monotonic()+30.0  # One local window, NEVER reset for another frame.
            self._sequence+=1
            self._possible_dispatch=True  # Sticky BEFORE any execute byte can leave.
            self._send_frame(request_raw,deadline)
            for raw in source.first_frames():self._send_frame(raw,deadline)
            ready=self._receive_bound(common,deadline)
            if 'parent_execution_version' in ready:
                self._terminal_value_bytes=canonical_bytes(ready)
            _require(set(ready)=={'file2_stage','worker_ready'} and ready['file2_stage']=='ready'
                and type(ready['worker_ready']) is dict
                and type(ready['worker_ready'].get('pid')) is int,'ntfs.worker_ready_binding_mismatch')
            # Parent already compares PID with its retained creation HANDLE.
            # This second check correlates data; it cannot authenticate a HANDLE.
            checked=validate_file2_worker_ready(canonical_bytes(ready['worker_ready']),
                projection=projection,channel_id=self.channel_id,
                expected_pid=ready['worker_ready']['pid'])
            rewind=source.rewind_after_ready(canonical_bytes(checked['ready_token']))  # REAL SAME-FD lseek.
            self._send_frame(rewind,deadline)
            # The SAME gate remains held through rewind, sole parent GO, checked
            # replay, terminal response and all channel checks. No repeated RPC.
            for raw in source.replay_frames():self._send_frame(raw,deadline)
            answer=self._receive_bound(common,deadline)
            self._terminal_value_bytes=canonical_bytes(answer)  # BEFORE release/late owner failure.
            self._usable()
        except BaseException as error:
            self._failed=True;primary=error
        finally:
            if acquired:
                try:self._gate.release()
                except BaseException as error:
                    self._failed=True
                    raise NativeChannelError('ntfs.channel_gate_finalization_unknown',
                        possible_dispatch=self._possible_dispatch,details={
                            'primary':None if primary is None else _primary(primary),
                            'finalization':_primary(error)}) from primary
        if primary is None:
            try:self._usable()
            except BaseException as error:self._failed=True;primary=error
        if primary is not None:
            raise NativeChannelError('ntfs.channel_exchange_unknown',possible_dispatch=self._possible_dispatch,
                details={'request_digest':None if request_raw is None else digest_bytes(request_raw),
                    'sequence':self._sequence,'primary':_primary(primary)}) from primary
        return answer


class LinuxNativeBundleChannel(LinuxNativeChannelV4):
    """Fixed bundle role of the SAME owned exchange, gate and process lifetime."""
    _PROTOCOL_VERSION='1.5'
    _EXECUTE_KINDS=frozenset({'execute_bundle'})

    def _request(self,kind,run_id,intent_digest,payload):
        _require(kind not in {'execute_file_create','execute_version1','execute_version2','execute_file2'},
            'ntfs.original_closed_role_required')
        if kind!='execute_bundle':return super()._request(kind,run_id,intent_digest,payload)
        from .channel import _RUN,_DIGEST
        _require(not self._inspection_only and not self._finish_attempted,'ntfs.inspection_only_operation_forbidden')
        _require(type(run_id) is str and _RUN.fullmatch(run_id) is not None
            and type(intent_digest) is str and _DIGEST.fullmatch(intent_digest) is not None
            and type(payload) is dict and not payload,'ntfs.invalid_intent_reference')
        return payload

    def execute_bundle(self,*,run_id,intent_digest,projection,source):
        from .bundle_execution import _bundle_projection_value, _bundle_wire_header, validate_bundle_worker_ready
        from .bundle_stream import _BundleSnapshotSource
        acquired=False;primary=None;request_raw=None;answer=None
        try:
            self._usable()
            _require(self._gate.acquire(blocking=False),'ntfs.channel_reentrant_call')
            acquired=True;self._usable()
            self._request('execute_bundle',run_id,intent_digest,{})
            _require(not self._possible_dispatch,'ntfs.channel_execution_consumed')
            value=_bundle_projection_value(projection)
            _require(value['context']['run_id']==run_id
                and value['context']['intent_digest']==intent_digest
                and type(source) is _BundleSnapshotSource
                and source._header_raw==_bundle_wire_header(projection,self.channel_id),
                'ntfs.original_current_invocation_mismatch')
            source._check('first-unused')
            common={'protocol':'phase.native.pipe','version':self._PROTOCOL_VERSION,
                'channel_id':self.channel_id,'sequence':self._sequence+1,
                'kind':'execute_bundle','run_id':run_id,'intent_digest':intent_digest}
            request_raw=canonical_bytes(common)
            deadline=time.monotonic()+30.0  # One local window, NEVER reset for another frame.
            self._sequence+=1
            self._possible_dispatch=True  # Sticky BEFORE any execute byte can leave.
            self._send_frame(request_raw,deadline)
            for raw in source.first_frames():self._send_frame(raw,deadline)
            ready=self._receive_bound(common,deadline)
            if 'parent_execution_version' in ready:
                self._terminal_value_bytes=canonical_bytes(ready)
            _require(set(ready)=={'bundle_stage','worker_ready'} and ready['bundle_stage']=='ready'
                and type(ready['worker_ready']) is dict
                and type(ready['worker_ready'].get('pid')) is int,'ntfs.worker_ready_binding_mismatch')
            # Parent already compares PID with its retained creation HANDLE.
            # This second check correlates data; it cannot authenticate a HANDLE.
            checked=validate_bundle_worker_ready(canonical_bytes(ready['worker_ready']),
                projection=projection,channel_id=self.channel_id,
                expected_pid=ready['worker_ready']['pid'])
            rewind=source.rewind_after_ready(canonical_bytes(checked['ready_token']))  # REAL SAME-FD lseek.
            self._send_frame(rewind,deadline)
            # The SAME gate remains held through rewind, sole parent GO, checked
            # replay, terminal response and all channel checks. No repeated RPC.
            for raw in source.replay_frames():self._send_frame(raw,deadline)
            answer=self._receive_bound(common,deadline)
            self._terminal_value_bytes=canonical_bytes(answer)  # BEFORE release/late owner failure.
            self._usable()
        except BaseException as error:
            self._failed=True;primary=error
        finally:
            if acquired:
                try:self._gate.release()
                except BaseException as error:
                    self._failed=True
                    raise NativeChannelError('ntfs.channel_gate_finalization_unknown',
                        possible_dispatch=self._possible_dispatch,details={
                            'primary':None if primary is None else _primary(primary),
                            'finalization':_primary(error)}) from primary
        if primary is None:
            try:self._usable()
            except BaseException as error:self._failed=True;primary=error
        if primary is not None:
            raise NativeChannelError('ntfs.channel_exchange_unknown',possible_dispatch=self._possible_dispatch,
                details={'request_digest':None if request_raw is None else digest_bytes(request_raw),
                    'sequence':self._sequence,'primary':_primary(primary)}) from primary
        return answer
