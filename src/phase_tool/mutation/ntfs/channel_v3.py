"""Fixed lifecycle control generation; same owner/gate/pipe, no new service.

Only an authenticated immutable installation chooses its contract role. All
execution kinds consume the inherited possible-dispatch bit BEFORE writing.
This candidate is unqualified and cannot be selected by a public request.
"""
from __future__ import annotations

from .channel import _DIGEST, _RUN
from .channel_v2 import LinuxNativeChannelV2
from .native import _require


class LinuxNativeChannelV3(LinuxNativeChannelV2):
    _PROTOCOL_VERSION = '1.2'
    _EXECUTE_KINDS = frozenset({'execute_file_create','execute_version1'})

    def __init__(self, channel_id: str, *, _inspection_only: bool = False, _version1: bool):
        super().__init__(channel_id,_inspection_only=_inspection_only)
        _require(type(_version1) is bool,'ntfs.original_closed_role_required')
        self._version1 = _version1

    def _request(self, kind, run_id, intent_digest, payload):
        _require(not self._inspection_only or kind == 'observe_file',
            'ntfs.inspection_only_operation_forbidden')
        _require(not self._finish_attempted,'ntfs.channel_terminal_consumed')
        _require(not (self._version1 and kind == 'execute_file_create'),
            'ntfs.original_closed_role_required')
        if kind != 'execute_version1':
            return super()._request(kind,run_id,intent_digest,payload)
        _require(self._version1,'ntfs.original_closed_role_required')
        _require(type(run_id) is str and _RUN.fullmatch(run_id) is not None,
            'evidence.invalid_run_id')
        _require(type(intent_digest) is str and _DIGEST.fullmatch(intent_digest) is not None
            and type(payload) is dict and not payload,'ntfs.invalid_intent_reference')
        return payload

    def execute_version1(self, *, run_id: str, intent_digest: str):
        return self._exchange('execute_version1',run_id,intent_digest,{})


class LinuxNativeChannelV5(LinuxNativeChannelV3):
    """Fixed Version2 role, same exchange ownership and consumed-dispatch gate."""
    _PROTOCOL_VERSION='1.4'
    _EXECUTE_KINDS=frozenset({'execute_version2'})

    def __init__(self,channel_id,*,_inspection_only=False):
        super().__init__(channel_id,_inspection_only=_inspection_only,_version1=False)

    def _request(self,kind,run_id,intent_digest,payload):
        _require(not self._inspection_only or kind=='observe_file','ntfs.inspection_only_operation_forbidden')
        _require(not self._finish_attempted,'ntfs.channel_terminal_consumed')
        _require(kind not in {'execute_file_create','execute_version1','execute_file2'},'ntfs.original_closed_role_required')
        if kind!='execute_version2':return super()._request(kind,run_id,intent_digest,payload)
        _require(type(run_id) is str and _RUN.fullmatch(run_id) is not None,'evidence.invalid_run_id')
        _require(type(intent_digest) is str and _DIGEST.fullmatch(intent_digest) is not None
            and type(payload) is dict and not payload,'ntfs.invalid_intent_reference')
        return payload

    def execute_version2(self,*,run_id,intent_digest):
        return self._exchange('execute_version2',run_id,intent_digest,{})
