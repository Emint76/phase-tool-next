"""Fixed transport/application adapters over the EXISTING recovery owners.

SOURCE candidate. No authority, channel, profile, store, worker or new journal
is constructed here. The existing installation factory still admits the exact
closed binding before existing Core/observer APIs can perform any operation.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
from ...canonical import parse_json_bytes
from .native import _require

_OBSERVE_ROLES=frozenset({'File1','File2','Bundle1'})
_VERSION_ROLES=frozenset({'Version1','Version2'})


def _manifest_role(manifest):
    """Advisory grammar routing only; never an admission or binding resolver."""
    families={'file_create.v1':'File1','file_create.v2':'File2',
        'publish_new_version.v1':'Version1','publish_new_version.v2':'Version2',
        'bundle_create.v1':'Bundle1','bundle_create.v2':'Bundle2'}
    _require(type(manifest)is dict and type(manifest.get('contract'))is dict,
        'recovery.closed_native_role_required')
    role=families.get(manifest['contract'].get('id'))
    _require(role is not None,'recovery.closed_native_role_required')
    return role


def _binding_role(binding):
    """Exact existing context, contract and profile checks; no generic policy."""
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    role=_manifest_role(manifest)
    if role in _OBSERVE_ROLES:
        from .publication_observe import publication_observe_role
        actual,_=publication_observe_role(binding)
    elif role in _VERSION_ROLES:
        from .version_original_closure import version_original_role
        actual,_=version_original_role(binding)
    else:
        from .bundle_execution import _BUNDLE2_CONTRACT_V2
        from .owner_semantic_contracts import semantic_owner_contract
        _require(manifest.get('native_read_installation_version')=='1.9'
            and manifest.get('contract')in(_BUNDLE2_CONTRACT_V2,semantic_owner_contract('Bundle2')),
            'recovery.closed_native_role_required')
        context=getattr(binding,'_owner_directory_context',None)
        if context is not None:
            from .owner_directory import require_owner_directory_binding
            actual,_=require_owner_directory_binding(binding,'Bundle2')
        else:
            from .owner_directory_fixture import _kinds
            admission=binding.experimental_admission
            _require(type(admission)is _kinds()['Bundle2'],'recovery.closed_native_role_required')
            admission.check_binding(binding);admission.profile(binding);actual='Bundle2'
    _require(actual==role,'recovery.closed_native_role_required')
    return role


def require_reconciliation_startup(config,manifest_bytes,manifest_digest,admission):
    """New literal MCP role: only fixed owner2/owner3 or qualified ordinary4.

    The old Bundle2 recovery-mcp role and its startup checks remain unchanged.
    Source-only fixture checks confer no qualified profile or runtime credit.
    """
    _require(type(config)is dict,'recovery.fixed_startup_required')
    if config.get('native_launch_version')=='4.0':
        _require(admission is None,'ntfs.owner_directory_context_required')
        from .owner_directory_launch import _owner_directory_launch_binding
        binding,_=_owner_directory_launch_binding(config,manifest_bytes,manifest_digest)
    else:
        from .owner_directory_fixture import _kinds,is_fixture
        _require(config.get('native_launch_version')in{'2.0','3.0'}
            and type(admission)in tuple(_kinds().values())and is_fixture(admission.raw)
            and admission.document()['experimental_admission_version']==config['native_launch_version'],
            'recovery.fixed_startup_required')
        from ...installation import _native_experimental_read_binding
        binding=_native_experimental_read_binding(manifest_bytes=manifest_bytes,
            expected_manifest_digest=manifest_digest,admission=admission)
    return _binding_role(binding)


def publication_request(request_id,expected_intent_digest,mode='observe'):
    from .bundle_recovery_entrypoint import validate_request
    return validate_request({'operation':'recover_publication','native_bundle_recovery_request_version':'1.0',
        'request_id':request_id,'expected_intent_digest':expected_intent_digest,'mode':mode})


@dataclass(frozen=True)
class _VersionContinuationArguments:
    """Data only; never an Original selection, authority or acceptance token."""
    original_run_id:str
    request_id:str
    expected_intent_digest:str
    def __post_init__(self):
        from ...evidence import validate_run_id
        validate_run_id(self.original_run_id)
        _require(type(self.request_id)is str and 0<len(self.request_id)<=128
            and type(self.expected_intent_digest)is str
            and re.fullmatch(r'sha256:[0-9a-f]{64}',self.expected_intent_digest)is not None,
            'recovery.native_request_mismatch')


def continuation_request(original_run_id,request_id,expected_intent_digest,candidate_path,
        input_paths,expected_inputs=None,maximum_candidate_bytes=1024**2):
    value={'operation':'continue_version','native_version_continuation_request_version':'1.0',
        'original_run_id':original_run_id,'request_id':request_id,'expected_intent_digest':expected_intent_digest,
        'candidate_path':candidate_path,'input_paths':input_paths,'expected_inputs':expected_inputs,
        'maximum_candidate_bytes':maximum_candidate_bytes}
    return validate_continuation_request(value)


def validate_continuation_request(value):
    keys={'operation','native_version_continuation_request_version','original_run_id','request_id',
        'expected_intent_digest','candidate_path','input_paths','expected_inputs','maximum_candidate_bytes'}
    _require(type(value)is dict and set(value)==keys and value['operation']=='continue_version'
        and value['native_version_continuation_request_version']=='1.0','recovery.native_request_mismatch')
    _VersionContinuationArguments(value['original_run_id'],value['request_id'],value['expected_intent_digest'])
    _require(type(value['candidate_path'])is str and bool(value['candidate_path'])
        and type(value['input_paths'])is dict
        and all(type(k)is str and type(v)is str for k,v in value['input_paths'].items())
        and type(value['maximum_candidate_bytes'])is int and 0<value['maximum_candidate_bytes']<=1024**2,
        'recovery.native_request_mismatch')
    expected=value['expected_inputs']
    _require(expected is None or type(expected)is dict and all(type(k)is str and type(v)is list and len(v)==2
        and type(v[0])is str and re.fullmatch(r'sha256:[0-9a-f]{64}',v[0])is not None
        and type(v[1])is int and v[1]>=0 for k,v in expected.items()),'recovery.native_request_mismatch')
    return value


def continue_application(application,*,run_id,original_run_id,request_id,expected_intent_digest,
        candidate_path,input_paths,expected_inputs=None,maximum_candidate_bytes=1024**2):
    """Use SAME factory installation; selection happens inside continue_version."""
    from ...application import PhaseApplication
    from ...installation import _NativeFileCreateInstallation
    from ...evidence import validate_run_id
    _require(type(application)is PhaseApplication
        and type(application.installation)is _NativeFileCreateInstallation,
        'recovery.closed_native_version_required')
    installed=application.installation;binding=installed.read_binding
    _require(application.registry is binding.registry and installed.authority.read_binding is binding
        and _binding_role(binding)in _VERSION_ROLES,'recovery.closed_native_version_required')
    validate_run_id(run_id)
    _require(run_id!=original_run_id,'recovery.version_continuation_run_conflict')
    request=continuation_request(original_run_id,request_id,expected_intent_digest,candidate_path,
        input_paths,expected_inputs,maximum_candidate_bytes)
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2);exact=manifest['contract']
    expected=request['expected_inputs']
    return application.run('execute',contract_binding=exact['id']+'@'+exact['version'],
        contract_digest=exact['package_digest'],candidate_path=Path(request['candidate_path']),
        evidence_root=Path(manifest['evidence_root']),run_id=run_id,
        input_paths={key:Path(path)for key,path in request['input_paths'].items()},
        root_bindings={key:Path(path)for key,path in manifest['root_projections'].items()},
        expected_inputs=None if expected is None else {key:tuple(row)for key,row in expected.items()},
        maximum_candidate_bytes=request['maximum_candidate_bytes'],
        _native_version_continuation=_VersionContinuationArguments(original_run_id,request_id,expected_intent_digest))


def _installation(launch,*,inspection_only):
    from .bootstrap import _NativeAcceptedLaunch
    from ...installation import _native_installation_for_manifest
    from .owner_directory_launch import _owner_directory_installation_arguments
    _require(type(launch)is _NativeAcceptedLaunch and launch._inspection_only is inspection_only,
        'recovery.closed_native_role_required')
    history_bytes,history_digest=launch.history_manifest_set
    return _native_installation_for_manifest(manifest_bytes=launch._manifest_bytes,
        expected_manifest_digest=launch.installation_digest,run_id=launch.run_id,
        operation_nonce=launch.operation_nonce,channel_id=launch.channel_id,_inspection_only=inspection_only,
        history_manifest_set_bytes=history_bytes,history_manifest_set_digest=history_digest,
        _experimental_admission_context=launch._experimental_admission_context,
        **_owner_directory_installation_arguments(launch))



def validate_observe_result(result, *, request, run_id, evidence_root):
    """Strict existing public type, not a registry or an admission substitute.

    All fields must be present and strict; caller correlation/finalization
    predicates preserve the existing Bundle2 response rules for observe. The
    separate old Bundle2 registered-schema validator is never changed.
    """
    from ...recovery import NativeRecoveryResult
    from .bundle_recovery_entrypoint import validate_request
    validate_request(request)
    _require(request['mode']=='observe'and type(result)is dict
        and set(result)==set(NativeRecoveryResult.model_fields),'recovery.native_result_version_required')
    checked=NativeRecoveryResult.model_validate(result).model_dump()
    _require(checked==result and result['recovery_mode']=='observe'
        and result['run_id']==run_id and result['request_id']==request['request_id']
        and result['intent_digest']in{None,request['expected_intent_digest']}
        and result['recovery_mutation_attempted']in{False,None},
        'recovery.native_result_binding_mismatch')
    if result['success']:
        digest = result['observation_digest']
        _require(type(digest) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', digest) is not None
            and result['observation_path'] == str(PurePosixPath(evidence_root) / '.phase' / 'runs'
                / run_id / 'recovery' / (digest[7:] + '.json')),
            'recovery.publication_observation_binding_mismatch')
        _require(result['status']=='verified_existing'and result['target_verified']is True
            and result['intent_digest']==request['expected_intent_digest']
            and result['effect_plan_digest']is not None and result['error']is None
            and result['exit_code']==0 and result['inspection_required']is False
            and result['lock_finalization']=={'unlock':'succeeded','close':'succeeded'}
            and not result['error_details']and not result['native_error_details'],
            'recovery.native_result_binding_mismatch')
    else:
        _require(result['exit_code']in{10,40}and result['inspection_required']is True
            and result['observation_digest'] is None and result['observation_path'] is None,
            'recovery.native_result_binding_mismatch')
    return result


def validate_observe_delivery(value,launch):
    from .bootstrap import _NativeAcceptedLaunch
    from ...installation import _native_registry_for_launch
    from .bundle_recovery_entrypoint import validate_request
    _require(type(launch)is _NativeAcceptedLaunch and launch._inspection_only is True
        and _manifest_role(launch.manifest)in _OBSERVE_ROLES,
        'recovery.closed_publication_observer_required')
    request=launch.invocation['request']
    validate_request(request)
    _require(request['mode']=='observe'and set(value)=={'protocol','version','channel_id','run_id','result','exit_code'}
        and value['protocol']=='phase.native.command'and value['version']=='1.4'
        and value['channel_id']==launch.channel_id and value['run_id']==launch.run_id,
        'recovery.native_delivery_mismatch')
    _native_registry_for_launch(launch)  # Existing exact context/profile revalidation remains.
    validate_observe_result(value['result'], request=request, run_id=launch.run_id,
        evidence_root=launch.manifest['evidence_root'])
    _require(type(value['exit_code'])is int and value['exit_code']==value['result']['exit_code'],
        'recovery.native_delivery_mismatch')
    return value


def validate_continuation_delivery(value,launch):
    from .bootstrap import _NativeAcceptedLaunch
    from ...installation import _native_registry_for_launch
    from ...command_result import validate_command_result
    from .parent_result import _require_command_run_binding
    _require(type(launch)is _NativeAcceptedLaunch and launch._inspection_only is False
        and _manifest_role(launch.manifest)in _VERSION_ROLES,'recovery.closed_native_version_required')
    validate_continuation_request(launch.invocation['request'])
    _require(set(value)=={'protocol','version','channel_id','run_id','result','exit_code'}
        and value['protocol']=='phase.native.command'and value['version']=='1.0'
        and value['channel_id']==launch.channel_id and value['run_id']==launch.run_id,
        'recovery.native_delivery_mismatch')
    result=value['result'];validate_command_result(result,_native_registry_for_launch(launch))
    _require(result['command']=='execute'and type(value['exit_code'])is int
        and value['exit_code']==result['exit_code'],'recovery.native_delivery_mismatch')
    _require_command_run_binding(result,launch.run_id)
    return value


def run_publication_observe_core(launch):
    from ...application import PhaseApplication
    from .bundle_recovery_entrypoint import validate_request
    from .entrypoint import _linux_stdio_identity,_deliver_linux_frame
    request=validate_request(launch.invocation['request'])
    _require(launch._inspection_only is True and request['mode']=='observe'
        and _manifest_role(launch.manifest)in _OBSERVE_ROLES,'recovery.unsupported_mode')
    launch.check_runtime();identity=_linux_stdio_identity()
    registry,installed=_installation(launch,inspection_only=True)
    _require(_binding_role(installed.read_binding)in _OBSERVE_ROLES,
        'recovery.closed_publication_observer_required')
    manifest=launch.manifest;exact=manifest['contract']
    contract=registry.resolve_contract(exact['id'],exact['version'],exact['package_digest'],
        core_version=manifest['core']['version'])
    response=PhaseApplication(registry=registry,installation=installed).recover_publication(
        evidence_root=Path(manifest['evidence_root']),run_id=launch.run_id,
        target_root=Path(manifest['root_projections'][contract.document['canonical_result']['root_binding']]),request_id=request['request_id'],
        expected_intent_digest=request['expected_intent_digest'],mode='observe')
    validate_observe_result(response.payload, request=request, run_id=launch.run_id,
        evidence_root=manifest['evidence_root'])
    launch.check_runtime()
    _deliver_linux_frame({'protocol':'phase.native.command','version':'1.4','channel_id':launch.channel_id,
        'run_id':launch.run_id,'result':response.payload,'exit_code':response.exit_code},identity)
    return response.exit_code


def run_version_continuation_core(launch):
    from ...application import PhaseApplication
    from ...command_result import validate_command_result
    from .entrypoint import _linux_stdio_identity,_deliver_linux_frame
    request=validate_continuation_request(launch.invocation['request'])
    _require(launch._inspection_only is False and _manifest_role(launch.manifest)in _VERSION_ROLES,
        'recovery.closed_native_version_required')
    launch.check_runtime();identity=_linux_stdio_identity()
    registry,installed=_installation(launch,inspection_only=False)
    app=PhaseApplication(registry=registry,installation=installed)
    response=continue_application(app,run_id=launch.run_id,**{key:request[key]for key in(
        'original_run_id','request_id','expected_intent_digest','candidate_path','input_paths','expected_inputs','maximum_candidate_bytes')})
    validate_command_result(response.payload,registry);launch.check_runtime()
    _deliver_linux_frame({'protocol':'phase.native.command','version':'1.0','channel_id':launch.channel_id,
        'run_id':launch.run_id,'result':response.payload,'exit_code':response.exit_code},identity)
    return response.exit_code
