"""Thin finite tool exposure; same fixed owner, Core, receipts and recovery."""
from typing import Literal
from pydantic import StrictStr,StrictInt
from mcp.server.fastmcp import FastMCP
from ...canonical import parse_json_bytes
from ...recovery import NativeRecoveryResult
from .inspection_mcp import _InspectionMCPCallOwner,_closed_arguments
from .recovery_frontdoor import require_reconciliation_startup


def run_native_reconciliation_mcp(**startup):
    role=require_reconciliation_startup(parse_json_bytes(startup['config_bytes']),
        startup['manifest_bytes'],startup['expected_manifest_digest'],startup.get('_experimental_admission_context'))
    owner=_InspectionMCPCallOwner(**startup)
    server=FastMCP('Phase fixed reconciliation')
    if role in {'File1','File2','Bundle1','Bundle2'}:
        @server.tool(name='phase_recover_publication')
        def recover(run_id:StrictStr,request_id:StrictStr,expected_intent_digest:StrictStr,
                mode:Literal['observe','commit_prepared']='observe')->NativeRecoveryResult:
            return NativeRecoveryResult.model_validate(owner.recover_publication(run_id,request_id,expected_intent_digest,mode))
    else:
        @server.tool(name='phase_continue_version')
        def continue_version(run_id:StrictStr,original_run_id:StrictStr,request_id:StrictStr,
                expected_intent_digest:StrictStr,candidate_path:StrictStr,
                input_paths:dict[StrictStr,StrictStr],expected_inputs:dict[StrictStr,list]|None=None,
                maximum_candidate_bytes:StrictInt=1024**2)->dict:
            return owner.continue_version(run_id,original_run_id,request_id,expected_intent_digest,
                candidate_path,input_paths,expected_inputs,maximum_candidate_bytes)
    server.tool(name='phase_inspect')(owner.inspect)
    _closed_arguments(server).run(transport='stdio');return 0
