"""Fixed native tool adapter. Existing Core owns recovery and all records."""
from typing import Literal
from mcp.server.fastmcp import FastMCP
from pydantic import StrictStr

from ...recovery import NativeRecoveryResult
from .inspection_mcp import _InspectionMCPCallOwner
from .bundle_recovery_entrypoint import validate_request


def run_native_recovery_mcp(**startup):
    owner=_InspectionMCPCallOwner(**startup)
    server=FastMCP('Phase native B2 recovery experiment')

    @server.tool(name='phase_recover_publication')
    def recover(run_id:StrictStr,request_id:StrictStr,expected_intent_digest:StrictStr,
                mode:Literal['observe','commit_prepared']='observe')->NativeRecoveryResult:
        request=validate_request({'operation':'recover_publication','native_bundle_recovery_request_version':'1.0',
            'request_id':request_id,'expected_intent_digest':expected_intent_digest,'mode':mode})
        return NativeRecoveryResult.model_validate(owner._call(run_id,request,inspection_only=False))

    @server.tool(name='phase_inspect')
    def inspect(run_id:StrictStr)->dict:
        return owner.inspect(run_id)

    from .inspection_mcp import _closed_arguments
    _closed_arguments(server)
    server.run(transport='stdio')
