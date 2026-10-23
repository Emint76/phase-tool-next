"""Thin fixed-startup native inspection MCP adapter, never the default server.

The accepted namespace/lifetime is mandatory. A transient owner retains failed
launches and refuses more calls; this is not a store, queue or Phase lifecycle.
No request roots, command/provider/registry selector, receipt or retry exists.
"""
from __future__ import annotations
import threading

from mcp.server.fastmcp import FastMCP

from ...canonical import canonical_bytes
from ...command_result import validate_command_result
from ...evidence import validate_run_id
from ...installation import _native_inspection_file_create_registry
from .bootstrap import _NativeAcceptedLaunch
from .entrypoint import run_native_parent
from .native import _require


class _InspectionMCPCallOwner:
    """Retain one actual launch until checked completion; unknown stays held.

    Core owns records, but cannot own a caller's Docker process after its tool
    exception. This finite transport owner supplies only that missing lifetime.
    Concurrent calls fail immediately; there is no queued or persistent work.
    """
    def __init__(self,*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
        self._startup=dict(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
            manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
        self._gate=threading.Lock()
        self._held_launch=None
        self._unavailable=False

    def inspect(self,run_id:str)->dict:
        """Inspect one known run in the accepted fixed installation."""
        validate_run_id(run_id)
        _require(self._gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        primary=None
        result=None
        try:
            _require(not self._unavailable,'ntfs.inspection_mcp_unavailable')
            import secrets
            invocation={'run_id':run_id,'request':{'operation':'inspect'},
                'channel_id':secrets.token_hex(16),'operation_nonce':secrets.token_hex(16)}
            launch=_NativeAcceptedLaunch(**self._startup,
                invocation_bytes=canonical_bytes(invocation),_inspection_only=True)
            self._held_launch=launch  # Retain BEFORE any process/pipe can be created.
            result=run_native_parent(launch)
            validate_command_result(result['result'],_native_inspection_file_create_registry())
            self._held_launch=None  # run_native_parent checked actual owner finalization.
        except BaseException as error:
            self._unavailable=True
            primary=error
        finally:
            try:self._gate.release()
            except BaseException as error:
                self._unavailable=True
                if primary is None:primary=error
                else:
                    try:primary.add_note('Native inspection MCP call gate: '+type(error).__name__)
                    except BaseException:pass
        if primary is not None:raise primary
        return result['result']


def _inspection_server(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
    """Only the fixed accepted launcher supplies these installation bytes."""
    owner=_InspectionMCPCallOwner(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    server=FastMCP('Phase native inspection candidate',
        instructions='Fixed installation, read-only inspection; qualification required.',json_response=True)
    server.tool(name='phase_inspect')(owner.inspect)
    return server


def run_native_inspection_mcp(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
    server=_inspection_server(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    server.run(transport='stdio')
    return 0
