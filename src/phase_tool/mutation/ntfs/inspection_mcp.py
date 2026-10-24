"""Thin fixed-startup native MCP adapters, never the default server.

Core owns candidate capture, intent, locking, effects, receipts and recovery.
This existing finite transport owner retains uncertain launches and refuses
further calls. No journal, queue, preparation writer or retry mechanism exists.
Accepted startup/lifetime and profile qualification remain mandatory.
"""
from __future__ import annotations
import threading
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field, StrictInt, StrictStr

from ...canonical import canonical_bytes
from ...command_result import validate_command_result
from ...evidence import validate_run_id
from ...installation import _native_registry_for_manifest
from .bootstrap import _NativeAcceptedLaunch
from .entrypoint import run_native_parent
from .native import _require
from .parent_result import _require_command_run_binding


def _prepared_request(candidate_path,input_paths,expected_inputs,maximum_candidate_bytes):
    """Only wire-shape checks; Core still captures/freezes/validates all bytes."""
    _require(type(candidate_path) is str and type(input_paths) is dict
        and all(type(k) is str and type(v) is str for k,v in input_paths.items())
        and type(maximum_candidate_bytes) is int and 0<maximum_candidate_bytes<=1024**2,
        'ntfs.fixed_native_request_required')
    expected=None
    if expected_inputs is not None:
        _require(type(expected_inputs) is dict and all(type(k) is str
            and type(v) in (list,tuple) and len(v)==2 and type(v[0]) is str
            and type(v[1]) is int and v[1]>=0 for k,v in expected_inputs.items()),
            'ntfs.fixed_native_request_required')
        expected={k:list(v) for k,v in expected_inputs.items()}
    return {'operation':'execute','candidate_path':candidate_path,'input_paths':dict(input_paths),
        'expected_inputs':expected,'maximum_candidate_bytes':maximum_candidate_bytes}


class _InspectionMCPCallOwner:
    """One shared finite call owner; legacy read-only entry stays read-only.

    Core cannot own the caller's Docker process after a tool exception. Retain
    the actual launch on exceptions AND normally delivered typed uncertainty:
    Docker CLI finalization alone cannot establish a native worker's exit.
    Concurrent calls fail immediately; there is no queued or persistent work.
    """
    def __init__(self,*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
        self._startup=dict(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
            manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
        self._gate=threading.Lock()
        self._held_launch=None
        self._unavailable=False

    def _call(self,run_id,request,*,inspection_only):
        validate_run_id(run_id)
        _require(self._gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        primary=None
        result=None
        try:
            _require(not self._unavailable,'ntfs.inspection_mcp_unavailable')
            import secrets
            invocation={'run_id':run_id,'request':request,
                'channel_id':secrets.token_hex(16),'operation_nonce':secrets.token_hex(16)}
            launch=_NativeAcceptedLaunch(**self._startup,
                invocation_bytes=canonical_bytes(invocation),_inspection_only=inspection_only)
            self._held_launch=launch  # Retain BEFORE any process/pipe can be created.
            response=run_native_parent(launch)
            _require(type(response) is dict and type(response.get('result')) is dict
                and type(response.get('exit_code')) is int,'ntfs.parent_command_binding_mismatch')
            result=response['result']
            validate_command_result(result,_native_registry_for_manifest(
                self._startup['manifest_bytes'],self._startup['expected_manifest_digest']))
            _require(result['command']==request['operation']
                and result['exit_code']==response['exit_code'],
                'ntfs.parent_command_binding_mismatch')
            _require_command_run_binding(result,run_id)
            if (result.get('stage3_command_result_version')=='1.2'
                    or result.get('inspection_required') is True or result['exit_code']==40):
                # Keep the SAME result and actual launch. A finalization attempt
                # or Docker CLI exit is not proof of native worker completion.
                self._unavailable=True
            else:
                self._held_launch=None  # Parent established checked finalization.
        except BaseException as error:
            self._unavailable=True
            primary=error
        finally:
            try:self._gate.release()
            except BaseException as error:
                self._unavailable=True
                if primary is None:primary=error
                else:
                    try:primary.add_note('Native MCP call gate: '+type(error).__name__)
                    except BaseException:pass
        if primary is not None:raise primary
        return result

    def inspect(self,run_id:StrictStr)->dict:
        """Inspect a known run using only fixed read-only installation bindings."""
        return self._call(run_id,{'operation':'inspect'},inspection_only=True)

    def execute_prepared(self,run_id:StrictStr,candidate_path:StrictStr,
            input_paths:dict[StrictStr,StrictStr],
            expected_inputs:dict[StrictStr,tuple[StrictStr,Annotated[StrictInt,Field(ge=0)]]]|None=None,
            maximum_candidate_bytes:Annotated[StrictInt,Field(gt=0,le=1024**2)]=1024**2)->dict:
        """Execute an already prepared candidate through the existing Core.

        Paths name prepared Linux input files; this adapter never resolves,
        reads, copies, stages or deletes them. Fixed installation supplies the
        contract, registry, roots and evidence. No retry is authorized here.
        """
        request=_prepared_request(candidate_path,input_paths,expected_inputs,maximum_candidate_bytes)
        return self._call(run_id,request,inspection_only=False)


def _closed_arguments(server):
    # Same SDK validation pattern as the ordinary MCP adapter. Do not import
    # that default server or instantiate its Host application in this contour.
    for tool in server._tool_manager.list_tools():
        model=tool.fn_metadata.arg_model
        model.model_config['extra']='forbid'
        model.model_rebuild(force=True)
        tool.parameters=model.model_json_schema(by_alias=True)
    return server


def _inspection_server(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
    """Only the fixed accepted launcher supplies these installation bytes."""
    owner=_InspectionMCPCallOwner(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    server=FastMCP('Phase native inspection candidate',
        instructions='Fixed installation, read-only inspection; qualification required.',json_response=True)
    server.tool(name='phase_inspect')(owner.inspect)
    return _closed_arguments(server)


def _prepared_server(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
    owner=_InspectionMCPCallOwner(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    server=FastMCP('Phase native prepared candidate',
        instructions='Fixed installation, prepared Core execution; qualification required. '
            'After uncertainty use a fresh independent read-only inspection process; do not retry.',
        json_response=True)
    server.tool(name='phase_execute_prepared')(owner.execute_prepared)
    server.tool(name='phase_inspect')(owner.inspect)
    return _closed_arguments(server)


def run_native_inspection_mcp(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
    server=_inspection_server(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    server.run(transport='stdio')
    return 0


def run_native_prepared_mcp(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest):
    server=_prepared_server(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    server.run(transport='stdio')
    return 0
