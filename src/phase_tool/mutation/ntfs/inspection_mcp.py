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
from .entrypoint import _ClosedStagedFileInspectionLoss, run_native_parent
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


def _version1_publication_inspection_request(request_id, target_locator,
        expected_current_digest, expected_digest, expected_receipt_digest):
    from .entrypoint import _native_version1_inspection_expectations
    request = {'operation':'inspect',
        'native_version1_publication_inspection_request_version':'1.0',
        'request_id':request_id,'target_locator':target_locator,
        'expected_current_digest':expected_current_digest,'expected_digest':expected_digest,
        'expected_receipt_digest':expected_receipt_digest}
    _native_version1_inspection_expectations(request)
    return request


def _bundle_publication_inspection_request(request_id,target_locator,members,expected_receipt_digest):
    from .parent_result import _native_bundle_inspection_expectations
    request={'operation':'inspect','native_bundle_publication_inspection_request_version':'1.0',
        'request_id':request_id,'target_locator':target_locator,'members':members,
        'expected_receipt_digest':expected_receipt_digest}
    _native_bundle_inspection_expectations(request)
    return request


def _native_bundle_cli_request(value):
    """Closed fixed frontend grammar shared by launcher and owner builder."""
    from .parent_result import _native_bundle_publication_request
    _require(type(value)is dict and set(value)=={'run_id','request'}
        and type(value['run_id'])is str and type(value['request'])is dict,
        'ntfs.fixed_native_request_required')
    validate_run_id(value['run_id']);request=value['request']
    _require(set(request)=={'operation','source_locator','target_locator','request_id','members'}
        and request['operation']=='publish_bundle','ntfs.fixed_native_request_required')
    checked=_native_bundle_publication_request(request['source_locator'],request['target_locator'],
        request['request_id'],request['members'])
    _require(request['members']==checked['members'],'ntfs.fixed_native_request_required')
    return {'run_id':value['run_id'],'source_locator':checked['source_locator'],
        'target_locator':checked['target_locator'],'request_id':checked['request_id'],'members':checked['members']}


class _InspectionMCPCallOwner:
    """One shared finite call owner; legacy read-only entry stays read-only.

    Core cannot own the caller's Docker process after a tool exception. Retain
    the actual launch on exceptions AND normally delivered typed uncertainty:
    Docker CLI finalization alone cannot establish a native worker's exit.
    Concurrent calls fail immediately; there is no queued or persistent work.
    """
    def __init__(self,*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest,
                 _experimental_admission_context=None):
        self._startup=dict(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
            manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
        if _experimental_admission_context is not None:
            from .experimental_file1 import _ExperimentalFile1Admission
            from .experimental_file2 import _ExperimentalFile2Admission
            from .experimental_version1 import _ExperimentalVersion1Admission
            from .experimental_version2 import _ExperimentalVersion2Admission
            from .experimental_bundle1 import _ExperimentalBundle1Admission
            from .experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
            from .experimental_history import (_ExperimentalHistoryFile1Admission,
                _ExperimentalHistoryVersion1Admission)
            _require(type(_experimental_admission_context) in (
                _ExperimentalFile1Admission,_ExperimentalFile2Admission,
                _ExperimentalVersion1Admission,_ExperimentalVersion2Admission,
                _ExperimentalBundle1Admission,_ExperimentalBundle2AdmissionV3,
                _ExperimentalHistoryFile1Admission,_ExperimentalHistoryVersion1Admission),
                'ntfs.experimental_admission_required')
            self._startup['_experimental_admission_context']=_experimental_admission_context
        self._gate=threading.Lock()
        self._held_launch=None
        self._held_input_source=None
        self._held_input_io=None
        self._unavailable=False
        self._publication_ack=None  # One transient ACK, never a durable journal or retry record.
        self._closed_staged_inspection_deadline=None

    def _call(self,run_id,request,*,inspection_only,_include_canonical_result=False,_include_bundle_manifest=False):
        from .parent_result import _native_file_result_mode,_native_bundle_result_mode
        _require(type(_include_canonical_result)is bool and type(_include_bundle_manifest)is bool
            and not(_include_canonical_result and _include_bundle_manifest)
            and _include_canonical_result is _native_file_result_mode(request)
            and _include_bundle_manifest is _native_bundle_result_mode(request)
            and(not(_include_canonical_result or _include_bundle_manifest)or inspection_only is True),
            'ntfs.fixed_result_request_version_required')
        validate_run_id(run_id)
        _require(self._gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        primary=None
        value=None
        try:
            value=self._call_locked(run_id,request,inspection_only=inspection_only,
                _include_canonical_result=_include_canonical_result,_include_bundle_manifest=_include_bundle_manifest)
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

    def _call_locked(self,run_id,request,*,inspection_only,_include_canonical_result=False,_include_bundle_manifest=False,
            _retain_launch=False,_staged_a05=None,_c05_transport=None,_report_closed_staged_inspection_loss=False):
        from .parent_result import _native_file_result_mode,_native_bundle_result_mode
        from .bootstrap import _is_bundle_recovery_launch
        _require(type(_include_canonical_result)is bool and type(_include_bundle_manifest)is bool
            and not(_include_canonical_result and _include_bundle_manifest)
            and _include_canonical_result is _native_file_result_mode(request)
            and _include_bundle_manifest is _native_bundle_result_mode(request)
            and(not(_include_canonical_result or _include_bundle_manifest)or inspection_only is True),
            'ntfs.fixed_result_request_version_required')
        validate_run_id(run_id)
        _require(type(_retain_launch)is bool and (not _retain_launch
            or (inspection_only is False and not _include_canonical_result
                and type(request)is dict and request.get('operation')=='execute')),
            'ntfs.publication_retention_required')
        result=None
        reference=None
        projection=None
        try:
            _require(not self._unavailable,'ntfs.inspection_mcp_unavailable')
            import secrets
            invocation={'run_id':run_id,'request':request,
                'channel_id':secrets.token_hex(16),'operation_nonce':secrets.token_hex(16)}
            launch=_NativeAcceptedLaunch(**self._startup,
                invocation_bytes=canonical_bytes(invocation),_inspection_only=inspection_only)
            self._held_launch=launch  # Retain BEFORE any process/pipe can be created.
            if _c05_transport is not None:
                from .c05_windows_transport import _C05WindowsTransport
                _require(type(_c05_transport) is _C05WindowsTransport and _retain_launch
                    and not inspection_only and _staged_a05 is None,'ntfs.fixed_c05_transport_required')
                response=run_native_parent(launch,_c05_transport=_c05_transport)
            elif _report_closed_staged_inspection_loss and getattr(launch,'_owner_directory_context',None) is not None:
                response=run_native_parent(launch,_report_closed_staged_inspection_loss=True)
            elif _staged_a05 is None:
                response=run_native_parent(launch)
            else:
                from .staged_dynamic_a05 import _StagedA05Selection
                _require(type(_staged_a05) is _StagedA05Selection and _retain_launch and not inspection_only,
                    'ntfs.staged_dynamic_a05_binding')
                response=run_native_parent(launch,_dynamic_a05_test=_staged_a05.attach(launch))
            _require(type(response) is dict and type(response.get('result')) is dict
                and type(response.get('exit_code')) is int,'ntfs.parent_command_binding_mismatch')
            result=response['result']
            if request.get('operation')=='continue_version' or (inspection_only and request.get('operation')=='recover_publication'):
                from .recovery_frontdoor import validate_observe_delivery,validate_continuation_delivery
                if inspection_only:validate_observe_delivery(response,launch)
                else:validate_continuation_delivery(response,launch)
                if (result.get('stage3_command_result_version')=='1.2'
                        or result.get('inspection_required')is True or result['exit_code']==40):
                    self._unavailable=True
                else:self._held_launch=None
                return result
            if _is_bundle_recovery_launch(launch) and not _include_bundle_manifest:
                from ...installation import _native_registry_for_launch
                registry=_native_registry_for_launch(launch)
                if request.get('operation')=='recover_publication':
                    from .bundle_recovery_entrypoint import validate_delivery
                    validate_delivery(response,launch)
                else:
                    validate_command_result(result,registry)
                    _require(set(response)=={'protocol','version','channel_id','run_id','result','exit_code'}
                        and response['protocol']=='phase.native.command' and response['version']=='1.0'
                        and response['channel_id']==launch.channel_id and response['run_id']==run_id
                        and type(response['exit_code']) is int and type(result['exit_code']) is int
                        and result['exit_code']==response['exit_code']
                        and request['operation'] in {'execute','inspect'}
                        and result['command']==request['operation']
                        and (request['operation']!='inspect' or result['run_id']==run_id),
                        'ntfs.parent_command_binding_mismatch')
                    _require_command_run_binding(result,run_id)
                if result.get('inspection_required') is True or result['exit_code']!=0:
                    self._unavailable=True
                elif not _retain_launch:self._held_launch=None
                return result
            if _include_bundle_manifest:
                from ...installation import _native_read_binding_for_launch
                bundle_binding=_native_read_binding_for_launch(launch)
                registry=bundle_binding.registry
            elif self._startup.get('_experimental_admission_context') is not None or getattr(launch,'_owner_directory_context',None) is not None:
                from ...installation import _native_registry_for_launch
                registry=_native_registry_for_launch(launch)
            else:
                registry=_native_registry_for_manifest(self._startup['manifest_bytes'],
                    self._startup['expected_manifest_digest'])
            validate_command_result(result,registry)
            _require(result['command']==request['operation']
                and result['exit_code']==response['exit_code'],
                'ntfs.parent_command_binding_mismatch')
            _require_command_run_binding(result,run_id)
            from .parent_result import _require_version1_inspection_delivery
            _require_version1_inspection_delivery(result, request=request,
                run_id=run_id, inspection_only=inspection_only)
            if _include_bundle_manifest:
                from .parent_result import validate_native_bundle_result_delivery
                reference,projection=validate_native_bundle_result_delivery(response,request=request,run_id=run_id,
                    channel_id=invocation['channel_id'],read_binding=bundle_binding,
                    expected_manifest_digest=launch.installation_digest,registry=registry)
            elif _include_canonical_result:
                from .parent_result import validate_native_file_result_delivery
                reference=validate_native_file_result_delivery(response,request=request,run_id=run_id,
                    channel_id=invocation['channel_id'],manifest_bytes=self._startup['manifest_bytes'],
                    expected_manifest_digest=self._startup['expected_manifest_digest'],registry=registry)
            else:
                _require('canonical_result' not in response and 'bundle_manifest'not in response
                    and response.get('version','1.0')=='1.0',
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
        if _include_bundle_manifest:return result,reference,projection
        return (result,reference) if _include_canonical_result else result

    def publish_input(self,run_id,input_scope,source_locator,target_locator,request_id,members=None,expected_current_digest=None,
            *,_operation_deadline=None,_file_assertions=None,_staged_a05=None,_c05_transport=None):
        """One Windows input stage, genuine execute and fresh unary inspection.

        A transient delivery pairs actual native results; it is never a receipt.
        All data paths are Windows-relative under one installed input scope.
        """
        from .input_stage import (_InputOperationDeadline,_input_operation_scope,_left,
            _stage_request,run_windows_input_stage,_staged_publication_request,_ClosedInputFileRefusal,
            _ClosedInputBundleRefusal,_ClosedFileAssertionRefusal,_FileInputAssertions)
        validate_run_id(run_id);_stage_request(input_scope,source_locator)
        _require(self._gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        primary=None;result=None;inspection_failure=None
        self._input_publication_phase='stage'
        try:
            _require(not self._unavailable,'ntfs.inspection_mcp_unavailable')
            _require(_operation_deadline is None or type(_operation_deadline)is _InputOperationDeadline,
                'input_stage.deadline_owner_required')
            token=_InputOperationDeadline()if _operation_deadline is None else _operation_deadline
            with _input_operation_scope(token):
                if _c05_transport is not None:
                    from .c05_windows_transport import _C05WindowsTransport
                    _require(type(_c05_transport) is _C05WindowsTransport and _staged_a05 is None
                        and members is None and expected_current_digest is None,'ntfs.fixed_c05_transport_required')
                    _c05_transport.begin(self._startup,run_id,input_scope,source_locator,target_locator,
                        request_id,_file_assertions,token.deadline_ns)
                if _staged_a05 is not None:
                    from .staged_dynamic_a05 import _StagedA05Selection
                    _require(type(_staged_a05) is _StagedA05Selection and _file_assertions is None,
                        'ntfs.staged_dynamic_a05_binding')
                    _staged_a05.begin(self._startup,run_id=run_id,deadline_ns=token.deadline_ns,call=dict(
                        input_scope=input_scope,source_locator=source_locator,target_locator=target_locator,
                        request_id=request_id,members=members,expected_current_digest=expected_current_digest))
                stage_options={}
                if _file_assertions is not None:
                    _require(type(_file_assertions)is _FileInputAssertions,'publish_file.file_input_assertions_required')
                    stage_options['_file_assertions']=_file_assertions
                staged=run_windows_input_stage(self,run_id,input_scope,source_locator,members,token.deadline_ns,
                    request_id=request_id,target_locator=target_locator,expected_current_digest=expected_current_digest,
                    **stage_options)
                observed_source=None
                if _file_assertions is not None and type(staged)is tuple:
                    prepared,_,_,_=staged
                    if prepared['expected_digest']!=_file_assertions.expected_digest:
                        observed_source=(prepared['expected_digest'],prepared['expected_length'])
                        staged=_ClosedFileAssertionRefusal('publish_file.source_digest_mismatch')
                if type(staged)is _ClosedFileAssertionRefusal:
                    _require(_file_assertions is not None,'publish_file.file_input_assertions_required')
                    result=self._staged_file_result(run_id,request_id,target_locator,error=staged.code,
                        observed_source=observed_source)
                elif _file_assertions is not None and type(staged)is _ClosedInputFileRefusal:
                    result=self._staged_file_result(run_id,request_id,target_locator,error='input_stage.member_bound')
                elif type(staged) in {_ClosedInputFileRefusal,_ClosedInputBundleRefusal}:
                    from ...application import PhaseApplication
                    registry=staged.registry
                    is_file=type(staged) is _ClosedInputFileRefusal
                    code='input_stage.member_bound'if is_file else staged.code
                    refusal=PhaseApplication(registry=registry)._failure('execute',PhaseError(code))
                    validate_command_result(refusal.payload,registry)
                    result={'native_input_publication_refusal_version':'1.0'if is_file else'1.1',
                        'run_id':run_id,'input_scope':input_scope,'role':staged.role,'source_locator':source_locator,
                        'request_id':request_id,'target_locator':target_locator,'preparation_started':False,'refusal':refusal.payload,
                        'exit_code':refusal.exit_code,'retry_authorized':False}
                    if is_file:
                        result.update(source_length=staged.length,maximum_source_length=staged.maximum,source_handles_closed=True)
                    else:
                        result.update(bound={'kind':staged.kind,'observed':staged.observed,'maximum':staged.maximum},
                            source_finalization=staged.source_finalization)
                else:
                    prepared,role,scope,content=staged
                    request=_staged_publication_request(role=role,prepared=prepared,input_scope=input_scope,
                        request_id=request_id,target_locator=target_locator,members=members,
                        expected_current_digest=expected_current_digest,content_utf8=content)
                    self._input_publication_phase='execute'
                    _left(token.deadline_ns)
                    if _c05_transport is not None:
                        ack=self._call_locked(run_id,request,inspection_only=False,_retain_launch=True,
                            _c05_transport=_c05_transport)
                    elif _staged_a05 is None:
                        ack=self._call_locked(run_id,request,inspection_only=False,_retain_launch=True)
                    else:
                        ack=self._call_locked(run_id,request,inspection_only=False,_retain_launch=True,_staged_a05=_staged_a05)
                    self._publication_ack=ack
                    result={'native_input_publication_result_version':'1.0','run_id':run_id,'input_scope':input_scope,
                        'role':role,'source_digest':prepared['expected_digest'],'source_length':prepared['expected_length'],
                        'request_id':request_id,'target_locator':target_locator,'command_ack':ack,'independent_inspection':None,
                        'exit_code':ack['exit_code'],'retry_authorized':False}
                    if ack['exit_code']==0 and not self._unavailable:
                        # The unchanged validated CommandResult1.0 has NO
                        # inspection_required member. New/uncertain generations
                        # cannot be treated as a legacy completed execute ACK.
                        _require(ack.get('stage3_command_result_version')=='1.0'
                            and 'inspection_required'not in ack and ack.get('success')is True
                            and ack.get('terminal_status')=='succeeded_verified'
                            and ack.get('execution_disposition')in {'executed','reused_existing'}
                            and ack.get('error')is None and ack.get('blockers')==[]
                            and all(ack.get(field)is not None for field in
                                ('run_id','receipt_digest','intent_digest','effect_plan_digest')),
                            'input_stage.execute_uncertain')
                        self._held_launch=None  # Actual known finalized execute only.
                        self._input_publication_phase='inspect'
                        report_loss=(_c05_transport is None and _staged_a05 is None
                            and self._startup.get('_experimental_admission_context') is None)
                        options={'_report_closed_staged_inspection_loss':True} if report_loss else {}
                        try:
                            inspected=self._call_locked(run_id,{'operation':'inspect'},inspection_only=True,**options)
                        except _ClosedStagedFileInspectionLoss as error:
                            if (type(error) is not _ClosedStagedFileInspectionLoss or not report_loss
                                    or error.launch is not self._held_launch or not self._unavailable):
                                raise
                            # The same CommandResult1.0 has a wider schema for
                            # other execute outcomes. Preserve only this exact
                            # completed execute and its literal evidence IDs.
                            if (_file_assertions is None and (ack['run_id']!=run_id
                                    or 'target_verified' not in ack or ack['target_verified'] is not None)):
                                raise
                            inspection_failure=error.code
                        else:
                            for field in('run_id','receipt_digest','intent_digest','effect_plan_digest'):
                                _require(inspected.get(field)==ack.get(field)and ack.get(field)is not None,
                                    'input_stage.inspect_ack_mismatch')
                            _require(inspected['exit_code']==0
                                and inspected.get('stage3_command_result_version')=='1.0'
                                and 'inspection_required'not in inspected and inspected.get('success')is True
                                and inspected.get('terminal_status')=='succeeded_verified'
                                and inspected.get('execution_disposition')in {'executed','reused_existing'}
                                and inspected.get('target_verified')is True
                                and inspected.get('error')is None and inspected.get('blockers')==[],
                                'input_stage.inspect_unverified')
                            result['independent_inspection']=inspected
                    if _file_assertions is not None:
                        result=self._staged_file_result(run_id,request_id,target_locator,delivery=result,error=inspection_failure)
                    elif inspection_failure is not None:
                        result.update(native_input_publication_result_version='1.1',
                            status='committed_unverified',inspection_required=True,exit_code=30)
                self._input_publication_phase='delivery'
                _left(token.deadline_ns)
                _require(len(canonical_bytes(result))<=2*1024**2,'input_stage.delivery_bound')
        except BaseException as error:
            self._unavailable=True;primary=error
        finally:
            try:self._gate.release()
            except BaseException as error:
                self._unavailable=True
                primary=error if primary is None else BaseExceptionGroup('input publication and gate failed',[primary,error])
        if primary is not None:raise primary
        if inspection_failure is not None:
            _left(token.deadline_ns)
            self._closed_staged_inspection_deadline=token.deadline_ns
        return result

    def _staged_file_result(self,run_id,request_id,target_locator,*,delivery=None,error=None,observed_source=None):
        from ...publish_file import PublishFileResult,_native_file_publication_ack

        manifest=parse_json_bytes(self._startup['manifest_bytes'],maximum_bytes=2*1024**2)
        contract=manifest['contract']
        result=PublishFileResult(status='rejected_before_write',run_id=run_id,request_id=request_id,
            evidence_root=manifest['evidence_root'],target_locator=target_locator,
            contract_binding=contract['id']+'@'+contract['version'],contract_digest=contract['package_digest'],
            error=error).model_dump()
        if observed_source is not None:
            result['content_digest'],result['content_length']=observed_source
        if delivery is not None:
            result.update(content_digest=delivery['source_digest'],content_length=delivery['source_length'])
            if _native_file_publication_ack(result,delivery['command_ack']):
                if delivery['independent_inspection'] is not None:
                    result.update(success=True,status='verified',target_verified=True,
                        inspection_required=False,error=None,exit_code=0)
                else:
                    _require(error==_ClosedStagedFileInspectionLoss.code,'input_stage.inspect_unverified')
        return PublishFileResult.model_validate(result).model_dump()

    def publish_staged_file(self,run_id,input_scope,source_locator,target_locator,request_id,
            publication_version,expected_digest,root_binding,*,_operation_deadline=None,_c05_transport=None):
        from .input_stage import _FileInputAssertions
        assertions=_FileInputAssertions(publication_version,expected_digest,root_binding)
        if _c05_transport is None:
            return self.publish_input(run_id,input_scope,source_locator,target_locator,request_id,
                _operation_deadline=_operation_deadline,_file_assertions=assertions)
        from .c05_windows_transport import _C05WindowsTransport
        _require(type(_c05_transport) is _C05WindowsTransport,'ntfs.fixed_c05_transport_required')
        try:
            return self.publish_input(run_id,input_scope,source_locator,target_locator,request_id,
                _operation_deadline=_operation_deadline,_file_assertions=assertions,_c05_transport=_c05_transport)
        finally:_c05_transport.flush()

    def recover_publication(self,run_id,request_id,expected_intent_digest,mode='observe'):
        from .recovery_frontdoor import publication_request,_manifest_role,_OBSERVE_ROLES
        role=_manifest_role(parse_json_bytes(self._startup['manifest_bytes']))
        _require(role in _OBSERVE_ROLES or role=='Bundle2','recovery.unsupported_contract')
        _require(role=='Bundle2' or mode=='observe','recovery.unsupported_mode')
        request=publication_request(request_id,expected_intent_digest,mode)
        return self._call(run_id,request,inspection_only=role in _OBSERVE_ROLES)

    def continue_version(self,run_id,original_run_id,request_id,expected_intent_digest,
            candidate_path,input_paths,expected_inputs=None,maximum_candidate_bytes=1024**2):
        from .recovery_frontdoor import continuation_request,_manifest_role,_VERSION_ROLES
        _require(_manifest_role(parse_json_bytes(self._startup['manifest_bytes']))in _VERSION_ROLES,
            'recovery.closed_native_version_required')
        _require(run_id!=original_run_id,'recovery.version_continuation_run_conflict')
        request=continuation_request(original_run_id,request_id,expected_intent_digest,candidate_path,
            input_paths,expected_inputs,maximum_candidate_bytes)
        return self._call(run_id,request,inspection_only=False)

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

    def inspect_version1_publication(self, run_id: StrictStr, request_id: StrictStr,
            target_locator: StrictStr, expected_current_digest: StrictStr,
            expected_receipt_digest: StrictStr, expected_digest: StrictStr | None = None) -> dict:
        """Fresh raw inspection with caller literals and the CURRENT receipt pin.

        expected_current_digest denotes pre-publication bytes in the original
        candidate, not the new current file. Known-run unary inspection remains
        available when unknown execute delivery supplied no ACK receipt.
        """
        request = _version1_publication_inspection_request(request_id, target_locator,
            expected_current_digest, expected_digest, expected_receipt_digest)
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
            and manifest['native_read_installation_version']in {'1.1','1.2','1.4'},
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


    def _bundle_frontdoor_binding(self,run_id):
        """Accepted no-dispatch probe; same fixed admission/runtime/history checks."""
        import secrets
        from ...installation import _native_read_binding_for_launch
        from .parent_result import _native_bundle_result_binding
        probe=_NativeAcceptedLaunch(**self._startup,_inspection_only=True,
            invocation_bytes=canonical_bytes({'run_id':run_id,'request':{'operation':'inspect'},
                'channel_id':secrets.token_hex(16),'operation_nonce':secrets.token_hex(16)}))
        probe.check_runtime()
        _require(probe._bundle,'ntfs.original_bundle_effect_required')
        binding=_native_read_binding_for_launch(probe)
        manifest,exact=_native_bundle_result_binding(binding,probe.installation_digest,binding.registry)
        probe.check_runtime()
        return manifest,exact

    def execute_bundle_publication(self,run_id:StrictStr,source_locator:StrictStr,
            target_locator:StrictStr,request_id:StrictStr,members:list[StrictStr])->dict:
        """Raw Core ACK; fixed installation owns all roots and admission."""
        from .parent_result import _native_bundle_publication_request
        request=_native_bundle_publication_request(source_locator,target_locator,request_id,members)
        return self._call(run_id,request,inspection_only=False)

    def publish_bundle(self,run_id:StrictStr,source_locator:StrictStr,
            target_locator:StrictStr,request_id:StrictStr,members:list[StrictStr])->dict:
        """Existing finite owner: one Core execute then fresh sealed inspection."""
        from ...publish_bundle import (PublishBundleResult,_native_bundle_publication_ack,
            _native_bundle_publication_inspected)
        from .parent_result import _native_bundle_publication_request
        request=_native_bundle_publication_request(source_locator,target_locator,request_id,members)
        validate_run_id(run_id)
        _require(self._gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        primary=None;handed_off=False;verified=None;result=None
        try:
            _require(not self._unavailable,'ntfs.inspection_mcp_unavailable')
            manifest,exact=self._bundle_frontdoor_binding(run_id)
            result=PublishBundleResult(publish_bundle_result_version='1.1',
                request_id=request_id,run_id=run_id,evidence_root=manifest['evidence_root'],
                target_locator=request['target_locator'],contract_binding=exact['id']+'@'+exact['version'],
                contract_digest=exact['package_digest'],execution_disposition='not_executed').model_dump()
            self._publication_ack=None
            result.update(status='indeterminate',mutation_attempted=None,exit_code=40,inspection_required=True)
            handed_off=True
            ack=self._call_locked(run_id,request,inspection_only=False,_retain_launch=True)
            self._publication_ack=ack
            can_inspect=_native_bundle_publication_ack(result,ack)
            if result['status']=='indeterminate':self._unavailable=True
            elif not self._unavailable:self._held_launch=None
            if can_inspect:
                inspection_request=_bundle_publication_inspection_request(request_id,request['target_locator'],
                    request['members'],ack['receipt_digest'])
                inspected,reference,projection=self._call_locked(run_id,inspection_request,
                    inspection_only=True,_include_bundle_manifest=True)
                _native_bundle_publication_inspected(result,ack,inspected,reference,projection,
                    binding=exact,members=request['members'])
                candidate=dict(result,success=True,status='verified',target_verified=True,
                    inspection_required=False,error=None,exit_code=0)
                verified=PublishBundleResult.model_validate(candidate).model_dump()
                canonical_bytes(verified)
        except BaseException as error:
            self._unavailable=True;primary=error
            if handed_off:
                result.update(success=False,target_verified=False,inspection_required=True,
                    error=error.code if type(error)is PhaseError else 'bundle.failure')
        finally:
            try:self._gate.release()
            except BaseException as error:
                self._unavailable=True;verified=None
                if primary is not None:
                    try:primary.add_note('Native MCP call gate: '+type(error).__name__)
                    except BaseException:pass
                else:
                    primary=error
                    if handed_off:result.update(success=False,target_verified=False,inspection_required=True,
                        error=result['error'] if result['error'] is not None else 'bundle.gate_finalization_failed')
        if primary is not None and not handed_off:raise primary
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


def _inspection_server(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest,
        _experimental_admission_context=None):
    """Only the fixed accepted launcher supplies these installation bytes."""
    startup=dict(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    if _experimental_admission_context is not None:
        startup['_experimental_admission_context']=_experimental_admission_context
    owner=_InspectionMCPCallOwner(**startup)
    server=FastMCP('Phase native inspection candidate',
        instructions='Fixed installation, read-only inspection; qualification required.',json_response=True)
    server.tool(name='phase_inspect')(owner.inspect)
    return _closed_arguments(server)


def _prepared_server(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest,
        _experimental_admission_context=None):
    startup=dict(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    if _experimental_admission_context is not None:
        startup['_experimental_admission_context']=_experimental_admission_context
    owner=_InspectionMCPCallOwner(**startup)
    server=FastMCP('Phase native prepared candidate',
        instructions='Fixed installation, prepared Core execution; qualification required. '
            'After uncertainty use a fresh independent read-only inspection process; do not retry.',
        json_response=True)
    server.tool(name='phase_execute_prepared')(owner.execute_prepared)
    if _experimental_admission_context is None:
        server.tool(name='phase_execute_file_publication')(owner.execute_file_publication)
        server.tool(name='phase_publish_file')(owner.publish_file)
        server.tool(name='phase_execute_version1_publication')(owner.execute_version1_publication)
        server.tool(name='phase_inspect_version1_publication')(owner.inspect_version1_publication)
        server.tool(name='phase_inspect')(owner.inspect_prepared)
    else:
        # Exact installed capability is validated by the same owner/accepted launch.
        # No request field can select it or expose unrelated file/version tools.
        from .experimental_bundle1 import _ExperimentalBundle1Admission
        from .experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
        if type(_experimental_admission_context)in (_ExperimentalBundle1Admission,_ExperimentalBundle2AdmissionV3):
            # Exposure grants no authority. Each call passes the exact accepted launch.
            server.tool(name='phase_execute_bundle_publication')(owner.execute_bundle_publication)
            server.tool(name='phase_publish_bundle')(owner.publish_bundle)
        server.tool(name='phase_inspect')(owner.inspect)
    return _closed_arguments(server)


def run_native_inspection_mcp(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest,
        _experimental_admission_context=None):
    startup=dict(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    if _experimental_admission_context is not None:
        startup['_experimental_admission_context']=_experimental_admission_context
    server=_inspection_server(**startup)
    server.run(transport='stdio')
    return 0


def run_native_prepared_mcp(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest,
        _experimental_admission_context=None):
    startup=dict(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
        manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest)
    if _experimental_admission_context is not None:
        startup['_experimental_admission_context']=_experimental_admission_context
    server=_prepared_server(**startup)
    server.run(transport='stdio')
    return 0


class _InputScopeSession:
    """One fixed contract scope; fresh one-shot native owners on every tool.

    A session never resets or reuses consumed execution authority. Uncertain
    calls retain their actual finite owner and poison later tool dispatch.
    Six statically configured endpoints expose the six installed contracts.
    """
    def __init__(self,**startup):
        self.startup=dict(startup);self.gate=threading.Lock();self.unknown=False;self.held=[]
        self._staged_a05=None
        self._c05_transport=None
    def _invoke(self,method,arguments):
        _require(self.gate.acquire(blocking=False),'ntfs.inspection_mcp_call_active')
        owner=None
        partial_deadline=None
        try:
            _require(not self.unknown,'ntfs.inspection_mcp_unavailable')
            selection=None
            if self._staged_a05 is not None:
                selection,bound_run=self._staged_a05
                _require(method in {'publish_input','inspect'} and arguments.get('run_id')==bound_run,
                    'ntfs.staged_dynamic_a05_binding')
            capture=self._c05_transport
            if capture is not None:
                _require(selection is None and method in {'publish_staged_file','inspect'},
                    'ntfs.fixed_c05_transport_required')
            owner=_InspectionMCPCallOwner(**self.startup);self.held.append(owner)
            if method=='publish_input':
                if selection is None:
                    result=owner.publish_input(**arguments)
                else:
                    result=owner.publish_input(**arguments,_staged_a05=selection)
            elif method=='publish_staged_file':
                result=(owner.publish_staged_file(**arguments) if capture is None else
                    owner.publish_staged_file(**arguments,_c05_transport=capture))
            else:
                _require(method=='inspect','ntfs.fixed_native_request_required')
                result=owner.inspect(**arguments)
            if owner._unavailable:
                self.unknown=True
                # A returned, validated execute uncertainty describes the
                # existing effect. Retain the owner and deliver its facts.
                ack=owner._publication_ack
                if owner._closed_staged_inspection_deadline is not None:
                    _require(owner._held_launch is not None and type(ack) is dict and ack.get('exit_code')==0
                        and type(result) is dict and result.get('status')=='committed_unverified'
                        and result.get('exit_code')==30 and result.get('inspection_required') is True
                        and ((method=='publish_staged_file' and result.get('error')==_ClosedStagedFileInspectionLoss.code)
                            or (method=='publish_input' and result.get('native_input_publication_result_version')=='1.1'
                                and result.get('command_ack') is ack and result.get('retry_authorized') is False
                                and result.get('independent_inspection') is None)),
                        'input_stage.session_unknown')
                    partial_deadline=owner._closed_staged_inspection_deadline
                    return result
                _require(method in {'publish_input','publish_staged_file'}
                    and owner._held_launch is not None and type(ack)is dict and ack.get('exit_code')==40
                    and type(result)is dict and result.get('exit_code')==40
                    and (result.get('command_ack')is ack if method=='publish_input'
                        else result.get('status')=='indeterminate' and result.get('inspection_required')is True),
                    'input_stage.session_unknown')
                return result
            self.held.remove(owner)
            return result
        except BaseException:
            self.unknown=True;raise
        finally:
            self.gate.release()
            if partial_deadline is not None:
                from .input_stage import _left
                _left(partial_deadline)
    def publish_input(self,run_id:StrictStr,input_scope:StrictStr,source_locator:StrictStr,target_locator:StrictStr,
            request_id:StrictStr,members:list[StrictStr]|None=None,expected_current_digest:StrictStr|None=None)->dict:
        return self._invoke('publish_input',dict(run_id=run_id,input_scope=input_scope,source_locator=source_locator,
            target_locator=target_locator,request_id=request_id,members=members,expected_current_digest=expected_current_digest))
    def publish_staged_file(self,run_id:StrictStr,input_scope:StrictStr,source_locator:StrictStr,
            target_locator:StrictStr,request_id:StrictStr,publication_version:StrictStr,
            expected_digest:StrictStr,root_binding:StrictStr)->dict:
        """Publish a file from the installed input scope, asserting the installed root and SHA-256."""
        return self._invoke('publish_staged_file',_native_staged_file_cli_request({
            'run_id':run_id,'request':{'operation':'publish_file','input_scope':input_scope,
                'source_locator':source_locator,'target_locator':target_locator,'request_id':request_id,
                'publication_version':publication_version,'expected_digest':expected_digest,
                'root_binding':root_binding}}))
    def inspect(self,run_id:StrictStr)->dict:
        return self._invoke('inspect',dict(run_id=run_id))
    def inspect_file(self,run_id:StrictStr,root_binding:StrictStr|None=None)->dict:
        """Read a known run with an optional assertion of the fixed file root."""
        if root_binding is not None:
            from ...publish_file import TARGET_ROOT_BINDING
            from .worker import _grant
            _require(root_binding==TARGET_ROOT_BINDING,'publish_file.wrong_root_binding')
            manifest=parse_json_bytes(self.startup['manifest_bytes'],maximum_bytes=2*1024**2)
            grants=manifest.get('root_grants')
            _require(type(grants)is list and len(grants)==1 and _grant(grants[0]).binding==root_binding,
                'publish_file.invalid_installed_root_binding')
        return self.inspect(run_id)


def run_native_input_mcp(**startup):
    return _serve_native_input_mcp(_InputScopeSession(**startup),startup)


def _run_c05_input_mcp(*,_c05_transport,**startup):
    from .c05_windows_transport import _C05WindowsTransport
    _require(type(_c05_transport) is _C05WindowsTransport,'ntfs.fixed_c05_transport_required')
    owner=_InputScopeSession(**startup)
    owner._c05_transport=_c05_transport
    return _serve_native_input_mcp(owner,startup)


def _serve_native_input_mcp(owner,startup):
    server=FastMCP('phase-native-input')
    server.tool(name='phase_publish_input')(owner.publish_input)
    manifest=parse_json_bytes(startup['manifest_bytes'],maximum_bytes=2*1024**2)
    is_file=manifest['contract']['id'] in {'file_create.v1','file_create.v2'}
    if is_file:
        server.tool(name='phase_publish_file')(owner.publish_staged_file)
    server.tool(name='phase_inspect')(owner.inspect_file if is_file else owner.inspect)
    _closed_arguments(server).run(transport='stdio');return 0


def _run_staged_a05_input_mcp(*,_staged_a05,**startup):
    """Closed startup3 fixture entry. Ordinary MCP registration stays separate."""
    from .staged_dynamic_a05 import _StagedA05Selection
    _require(type(_staged_a05) is _StagedA05Selection,'ntfs.staged_dynamic_a05_binding')
    owner=_InputScopeSession(**startup)
    bound_run=_staged_a05._require_mcp_startup(owner.startup)
    owner._staged_a05=(_staged_a05,bound_run)
    server=FastMCP('phase-native-input')
    server.tool(name='phase_publish_input')(owner.publish_input)
    server.tool(name='phase_inspect')(owner.inspect)
    _closed_arguments(server).run(transport='stdio');return 0


def _native_input_cli_request(value):
    _require(type(value)is dict and set(value)=={'run_id','request'}and type(value['request'])is dict,
        'ntfs.fixed_native_request_required')
    validate_run_id(value['run_id']);request=value['request']
    fields={'operation','input_scope','source_locator','target_locator','request_id','members','expected_current_digest'}
    _require(set(request)==fields and request['operation']=='publish_input','ntfs.fixed_native_request_required')
    from .input_stage import _stage_request
    _stage_request(request['input_scope'],request['source_locator'])
    members=request['members']
    _require(members is None or type(members)is list and all(type(member)is str for member in members),
        'ntfs.fixed_native_request_required')
    return dict(run_id=value['run_id'],**{key:request[key]for key in fields-{'operation'}})


def _native_staged_file_cli_request(value):
    from ...paths import safe_relative_locator
    from .input_stage import _FILE_PUBLICATION_ROLES,_FileInputAssertions,_publication_candidate,_stage_request

    _require(type(value)is dict and set(value)=={'run_id','request'} and type(value['request'])is dict,
        'ntfs.fixed_native_request_required')
    validate_run_id(value['run_id'])
    request=value['request']
    fields={'operation','input_scope','source_locator','target_locator','request_id','publication_version',
        'expected_digest','root_binding'}
    _require(set(request)==fields and request['operation']=='publish_file','ntfs.fixed_native_request_required')
    assertions=_FileInputAssertions(request['publication_version'],request['expected_digest'],request['root_binding'])
    _stage_request(request['input_scope'],request['source_locator'])
    _publication_candidate(_FILE_PUBLICATION_ROLES[assertions.publication_version],request['request_id'],
        safe_relative_locator(request['target_locator']),None,None)
    return dict(run_id=value['run_id'],**{key:request[key] for key in fields-{'operation'}})
