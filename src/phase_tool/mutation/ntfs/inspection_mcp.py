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

from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
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


def _file_publication_request(source_locator,target_locator,request_id,expected_digest):
    """Exact raw execute grammar; semantic checks remain in Core preparation."""
    _require(all(type(v) is str for v in (source_locator,target_locator,request_id))
        and (expected_digest is None or type(expected_digest) is str),
        'ntfs.fixed_native_request_required')
    return {'operation':'execute','native_file_publication_request_version':'1.0',
        'source_locator':source_locator,'target_locator':target_locator,
        'request_id':request_id,'expected_digest':expected_digest}


def _version1_publication_request(source_locator, target_locator, request_id,
        expected_current_digest, expected_digest):
    """Closed caller literals validated before the existing gate/nonce/launch."""
    import re
    from ...paths import safe_relative_locator
    from .preparation import _version1_publication_candidate
    _require(type(source_locator) is str, 'ntfs.fixed_native_request_required')
    source_locator = safe_relative_locator(source_locator)
    candidate, _ = _version1_publication_candidate(request_id, target_locator,
        expected_current_digest)
    _require(expected_digest is None or (type(expected_digest) is str
        and re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest)),
        'publish.invalid_expected_digest')
    return {'operation': 'execute', 'native_version1_publication_request_version': '1.0',
        'source_locator': source_locator, 'target_locator': candidate['target_locator'],
        'request_id': request_id, 'expected_current_digest': expected_current_digest,
        'expected_digest': expected_digest}


def _file_publication_inspection_request(request_id, target_locator, expected_digest, expected_receipt_digest,
        *, _include_canonical_result=False):
    """Shared pure validator runs before any owner gate, nonce or launch."""
    from .entrypoint import _native_file_inspection_expectations
    _require(type(_include_canonical_result) is bool, 'ntfs.file_result_request_version_required')
    request = {'operation': 'inspect', 'native_file_publication_inspection_request_version':
        '1.1' if _include_canonical_result else '1.0',
        'request_id': request_id, 'target_locator': target_locator,
        'expected_digest': expected_digest, 'expected_receipt_digest': expected_receipt_digest}
    _native_file_inspection_expectations(request)
    return request


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
        self._publication_ack=None  # One transient ACK, never a durable journal or retry record.

    def _call(self,run_id,request,*,inspection_only,_include_canonical_result=False):
        from .parent_result import _native_file_result_mode
        _require(type(_include_canonical_result) is bool
            and _include_canonical_result is _native_file_result_mode(request)
            and (not _include_canonical_result or inspection_only is True),
            'ntfs.file_result_request_version_required')
        validate_run_id(run_id)
        _require(self._gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        primary=None
        value=None
        try:
            value=self._call_locked(run_id,request,inspection_only=inspection_only,
                _include_canonical_result=_include_canonical_result)
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
        return value

    def _call_locked(self,run_id,request,*,inspection_only,_include_canonical_result=False,_retain_launch=False):
        from .parent_result import _native_file_result_mode
        _require(type(_include_canonical_result) is bool
            and _include_canonical_result is _native_file_result_mode(request)
            and (not _include_canonical_result or inspection_only is True),
            'ntfs.file_result_request_version_required')
        validate_run_id(run_id)
        _require(type(_retain_launch)is bool and (not _retain_launch
            or (inspection_only is False and not _include_canonical_result
                and type(request)is dict and request.get('operation')=='execute')),
            'ntfs.publication_retention_required')
        result=None
        reference=None
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
            registry=_native_registry_for_manifest(self._startup['manifest_bytes'],
                self._startup['expected_manifest_digest'])
            validate_command_result(result,registry)
            _require(result['command']==request['operation']
                and result['exit_code']==response['exit_code'],
                'ntfs.parent_command_binding_mismatch')
            _require_command_run_binding(result,run_id)
            if _include_canonical_result:
                from .parent_result import validate_native_file_result_delivery
                reference=validate_native_file_result_delivery(response,request=request,run_id=run_id,
                    channel_id=invocation['channel_id'],manifest_bytes=self._startup['manifest_bytes'],
                    expected_manifest_digest=self._startup['expected_manifest_digest'],registry=registry)
            else:
                _require('canonical_result' not in response and response.get('version','1.0')=='1.0',
                    'ntfs.parent_command_binding_mismatch')
            if (result.get('stage3_command_result_version')=='1.2'
                    or result.get('inspection_required') is True or result['exit_code']==40):
                # Keep the SAME result and actual launch. A finalization attempt
                # or Docker CLI exit is not proof of native worker completion.
                self._unavailable=True
            else:
                # Highlevel classification may still find a schema-valid
                # nullable/partial ACK indeterminate. Keep this SAME actual
                # launch until that classification, after checked finalization.
                if not _retain_launch:self._held_launch=None
        except BaseException:
            self._unavailable=True
            raise
        return (result,reference) if _include_canonical_result else result

    def inspect(self,run_id:StrictStr)->dict:
        """Inspect a known run using only fixed read-only installation bindings."""
        return self._call(run_id,{'operation':'inspect'},inspection_only=True)

    def inspect_prepared(self, run_id: StrictStr, request_id: StrictStr | None = None,
            target_locator: StrictStr | None = None, expected_digest: StrictStr | None = None,
            expected_receipt_digest: StrictStr | None = None) -> dict:
        """Inspect normally, or pin file1 caller literals and its CURRENT ACK receipt.

        All extra fields absent/null preserve the original known-run inspection,
        including unknown execute delivery without an ACK. An uncertain owner
        stays unavailable; a separate accepted read-only owner permits no retry.
        """
        if all(value is None for value in (request_id, target_locator, expected_digest, expected_receipt_digest)):
            return self.inspect(run_id)
        request = _file_publication_inspection_request(request_id, target_locator,
            expected_digest, expected_receipt_digest)
        return self._call(run_id, request, inspection_only=True)

    def _inspect_file_result(self,run_id,request_id,target_locator,expected_digest,expected_receipt_digest):
        """Internal CURRENT projection; existing public raw MCP tools stay unchanged."""
        request=_file_publication_inspection_request(request_id,target_locator,
            expected_digest,expected_receipt_digest,_include_canonical_result=True)
        return self._call(run_id,request,inspection_only=True,_include_canonical_result=True)

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


    def execute_file_publication(self,run_id:StrictStr,source_locator:StrictStr,
            target_locator:StrictStr,request_id:StrictStr,
            expected_digest:StrictStr|None=None)->dict:
        """Execute file1 from the fixed preparation namespace through Core.

        Returns the unchanged raw CommandResult, not PublishFileResult. This
        adapter reads or stages nothing and cannot choose roots or a profile.
        Inspect through a fresh accepted read-only invocation; after uncertainty
        the same owner remains unavailable and retains its actual launch.
        """
        request=_file_publication_request(source_locator,target_locator,request_id,expected_digest)
        return self._call(run_id,request,inspection_only=False)


    def execute_version1_publication(self, run_id: StrictStr, source_locator: StrictStr,
            target_locator: StrictStr, request_id: StrictStr, expected_current_digest: StrictStr,
            expected_digest: StrictStr | None = None) -> dict:
        """One raw version1 Core request through the same finite call owner.

        Returns unchanged CommandResult, never PublishFileResult or a verified
        highlevel claim. The fixed installation supplies all roots and bindings.
        Inspect a known run independently after unknown delivery; do not retry.
        No timestamp, key or root substitution masks an idempotency conflict.
        """
        request = _version1_publication_request(source_locator, target_locator,
            request_id, expected_current_digest, expected_digest)
        return self._call(run_id, request, inspection_only=False)


    def publish_file(self,run_id:StrictStr,source_locator:StrictStr,
            target_locator:StrictStr,request_id:StrictStr,
            expected_digest:StrictStr|None=None)->dict:
        """Fixed file1 execute then fresh CURRENT inspection under the SAME gate.

        Core owns all preparation/effects/receipts. The original validated ACK
        remains in this finite owner before any fallible projection/rendering.
        SDK/stdio loss after return is unknown delivery, never permission to retry.
        """
        import re
        from ...installation import _resolve_native_file_create_read_binding
        from ...paths import safe_relative_locator
        from ...publish_file import (CONTRACT_BINDING, PublishFileResult,
            _native_file_publication_ack, _native_file_publication_inspected)

        request=_file_publication_request(source_locator,target_locator,request_id,expected_digest)
        validate_run_id(run_id)
        safe_relative_locator(source_locator);safe_relative_locator(target_locator)
        _require(len(request_id)<=128 and re.fullmatch(r'[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*',request_id),
            'publish_file.invalid_request_id')
        _require(expected_digest is None or re.fullmatch(r'sha256:[0-9a-f]{64}',expected_digest),
            'publish_file.invalid_expected_digest')
        registry=_native_registry_for_manifest(self._startup['manifest_bytes'],
            self._startup['expected_manifest_digest'])
        binding=_resolve_native_file_create_read_binding(manifest_bytes=self._startup['manifest_bytes'],
            expected_manifest_digest=self._startup['expected_manifest_digest'],registry=registry)
        manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
        _require(manifest['contract']==registry.contract_bindings().get(CONTRACT_BINDING)
            and manifest['native_read_installation_version']in {'1.1','1.2'},
            'ntfs.original_single_effect_required')
        result=PublishFileResult(status='rejected_before_write',request_id=request_id,run_id=run_id,
            evidence_root=manifest['evidence_root'],target_locator=target_locator,
            contract_digest=manifest['contract']['package_digest']).model_dump()
        _require(self._gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        primary=None
        handed_off=False
        verified=None
        try:
            _require(not self._unavailable,'ntfs.inspection_mcp_unavailable')
            self._publication_ack=None
            result.update(status='indeterminate',mutation_attempted=None,exit_code=40,inspection_required=True)
            handed_off=True
            ack=self._call_locked(run_id,request,inspection_only=False,_retain_launch=True)
            self._publication_ack=ack  # Plain store BEFORE copying, models, diagnostics or another invocation.
            can_inspect=_native_file_publication_ack(result,ack)
            if result['status']=='indeterminate':self._unavailable=True
            elif not self._unavailable:self._held_launch=None
            if can_inspect:
                inspection_request=_file_publication_inspection_request(request_id,target_locator,
                    expected_digest,ack['receipt_digest'],_include_canonical_result=True)
                inspected,reference=self._call_locked(run_id,inspection_request,
                    inspection_only=True,_include_canonical_result=True)
                _native_file_publication_inspected(result,ack,inspected,reference)
                candidate=dict(result,success=True,status='verified',target_verified=True,
                    inspection_required=False,error=None,exit_code=0)
                verified=PublishFileResult.model_validate(candidate).model_dump()
                canonical_bytes(verified)  # Fail here, while the ACK/gate are still owned.
        except BaseException as error:
            self._unavailable=True
            primary=error
            if handed_off:
                result.update(success=False,target_verified=False,inspection_required=True,
                    error=error.code if type(error)is PhaseError else 'publish_file.failure')
        finally:
            try:self._gate.release()
            except BaseException as error:
                self._unavailable=True
                verified=None
                if primary is not None:
                    try:primary.add_note('Native MCP call gate: '+type(error).__name__)
                    except BaseException:pass
                else:
                    primary=error
                    if handed_off:
                        result.update(success=False,target_verified=False,inspection_required=True,
                            error=(result['error'] if result['error'] is not None
                                else 'publish_file.gate_finalization_failed'))
        if primary is not None and not handed_off:raise primary
        # No model/serialization call follows checked release. Failed rendering
        # returns the already constructed plain result, preserving ACK fields.
        return verified if verified is not None and not self._unavailable else result



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
    server.tool(name='phase_execute_file_publication')(owner.execute_file_publication)
    server.tool(name='phase_publish_file')(owner.publish_file)
    server.tool(name='phase_execute_version1_publication')(owner.execute_version1_publication)
    server.tool(name='phase_inspect')(owner.inspect_prepared)
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
