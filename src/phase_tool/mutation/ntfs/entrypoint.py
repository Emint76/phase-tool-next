"""DRAFT fixed role entrypoints; all publication stays in PhaseApplication/Core.
The accepted external launcher owns cold source-wheel lifetime and stdio.
No ordinary CLI fallback, new journal, receipt, target copy or recovery verb.
"""
from __future__ import annotations
import base64
import io
import os
from pathlib import Path
import select
import stat
import sys
import time

from ...canonical import canonical_bytes,parse_json_bytes
from ...errors import PhaseError
from .native import _require


def _windows_stdio():
    from .windows_pipe import WindowsPipeFrames
    reader=sys.stdin.buffer
    if type(reader) is not io.FileIO:reader=reader.raw
    writer=sys.stdout.buffer
    _require(type(reader) is io.FileIO and type(writer) is io.FileIO,
        'ntfs.exact_open_fileio_required')
    import msvcrt
    for stream in (reader,writer):
        msvcrt.setmode(stream.fileno(),os.O_BINARY)  # Own startup CRT stdio, before borrowing.
        os.set_blocking(stream.fileno(),False)
    return WindowsPipeFrames(reader,writer)


def _close_worker_stdio(primary):
    errors=[]
    for stream in (sys.stdin,sys.stdout,sys.stderr):
        try:
            stream.close()
            _require(stream.closed,'ntfs.worker_stdio_finalization_unknown')
        except BaseException as error:errors.append(error)
    if primary is None and errors:primary=errors.pop(0)
    if primary is not None:
        for error in errors:
            try:primary.add_note('Native worker stdio close: '+type(error).__name__)
            except BaseException:pass
        raise primary


def run_native_worker(launch,original,initial_pipe,*,_transfer_deadline_ns=None):
    """Only accepted Popen parent provides this owned stdin; no public service."""
    from .worker import run_file_create_worker
    _require(not launch._inspection_only, 'ntfs.inspection_only_operation_forbidden')
    launch.check_runtime()
    if getattr(launch,'_bundle',False):
        return _run_bundle_worker_transfer(launch,original,initial_pipe,_transfer_deadline_ns)
    if launch._file2:
        return _run_file2_worker_transfer(launch,original,initial_pipe,_transfer_deadline_ns)
    if launch._version2:
        return _run_version1_worker_transfer(launch,original,initial_pipe,_transfer_deadline_ns,_version2=True)
    if launch._version1:
        return _run_version1_worker_transfer(launch,original,initial_pipe,_transfer_deadline_ns)
    _require(type(original) is dict and set(original)=={'native_worker_original_version','context',
        'grant','effect','content_base64','timestamp','channel_id'}
        and original['native_worker_original_version']=='1.0'
        and original['grant']==launch.root_grant
        and original['channel_id']==launch.channel_id
        and original['context']['run_id']==launch.run_id
        and original['context']['operation_nonce']==launch.operation_nonce
        and original['context']['installation_digest']==launch.installation_digest,
        'ntfs.worker_original_binding_mismatch')
    content=base64.b64decode(original['content_base64'],validate=True)
    _require(len(content)<=1024**2,'mechanism.content_too_large')
    primary=None
    try:
        from .windows_pipe import WindowsPipeFrames
        _require(type(initial_pipe) is WindowsPipeFrames,
            'ntfs.exact_worker_initial_pipe_required')
        pipe=initial_pipe
        launch.check_runtime()  # Full actual imported physical graph before any READY/GO.
        run_file_create_worker(pipe,original['context'],original['grant'],original['effect'],
            content,original['timestamp'])
        launch.check_runtime()
    except BaseException as error:primary=error
    _close_worker_stdio(primary)
    return 0


def _linux_stdio_identity():
    _require(sys.platform.startswith('linux'),'ntfs.linux_channel_required')
    for fd in (0,1):
        info=os.fstat(fd)
        _require(stat.S_ISFIFO(info.st_mode) and not os.isatty(fd),'ntfs.pipe_stdio_required')
        os.set_blocking(fd,False)  # Own fresh process stdio, BEFORE channel borrows it.
    from .channel import LinuxNativeChannel
    return tuple(LinuxNativeChannel._pipe(fd) for fd in (0,1))


def _deliver_linux_frame(value,identities,*,_deadline=None):
    """Delivery only after the authority's irreversible seal; cannot dispatch.

    Reuses existing frame shape/readiness/pipeline checks without reopening a
    sealed channel, resetting flags or claiming EOF/cancellation/process exit.
    A partial/failed send is unknown delivery; never ordinary no-effect failure.
    """
    from .channel import LinuxNativeChannel
    raw=canonical_bytes(value)
    _require(0<len(raw)<=2*1024**2,'ntfs.channel_frame_limit')
    wire=f'{len(raw):08x}\n'.encode('ascii')+raw+b'\n'
    offset=0
    deadline=time.monotonic()+30 if _deadline is None else _deadline
    _require(type(deadline) is float and 0 < deadline-time.monotonic() <= 30,
        'ntfs.channel_deadline_expired')
    while offset<len(wire):
        _require(tuple(LinuxNativeChannel._pipe(fd) for fd in (0,1))==identities,
            'ntfs.channel_descriptor_changed')
        LinuxNativeChannel._ready(1,True,deadline)
        _require(tuple(LinuxNativeChannel._pipe(fd) for fd in (0,1))==identities,
            'ntfs.channel_descriptor_changed')
        try:count=os.write(1,wire[offset:offset+65536])
        except BlockingIOError:continue
        _require(count>0,'ntfs.channel_write_no_progress')
        offset+=count
        _require(time.monotonic()<deadline,'ntfs.channel_deadline_expired')


def run_native_core(launch):
    if (launch.manifest['native_read_installation_version']=='1.9'
            and launch.invocation['request'].get('operation')=='recover_publication'):
        from .bundle_recovery_entrypoint import run_recovery_core
        return run_recovery_core(launch)
    from ...application import PhaseApplication
    from ...command_result import validate_command_result
    from ...installation import (_native_registry_for_launch,
        _native_installation_for_manifest)
    from .uncertainty import _NativeLifecycleUnresolved
    _require(not launch._inspection_only, 'ntfs.inspection_only_operation_forbidden')
    launch.check_runtime()
    identities=_linux_stdio_identity()
    request=launch.invocation['request']
    prepared_request = (type(request) is dict and set(request)=={'operation','candidate_path','input_paths',
        'expected_inputs','maximum_candidate_bytes'}
        and request['operation'] in {'validate','plan','execute'}
        and type(request['candidate_path']) is str and type(request['input_paths']) is dict
        and all(type(k) is str and type(v) is str for k,v in request['input_paths'].items())
        and type(request['maximum_candidate_bytes']) is int
        and 0<request['maximum_candidate_bytes']<=1024**2)
    publication_request = (type(request) is dict and set(request)=={'operation',
        'native_file_publication_request_version','source_locator','target_locator','request_id','expected_digest'}
        and request['operation']=='execute' and request['native_file_publication_request_version']=='1.0'
        and all(type(request[k]) is str for k in ('source_locator','target_locator','request_id'))
        and (request['expected_digest'] is None or type(request['expected_digest']) is str))
    version1_publication_request = (type(request) is dict and set(request)=={'operation',
        'native_version1_publication_request_version','source_locator','target_locator',
        'request_id','expected_current_digest','expected_digest'}
        and request['operation']=='execute' and request['native_version1_publication_request_version']=='1.0'
        and all(type(request[k]) is str for k in ('source_locator','target_locator',
            'request_id','expected_current_digest'))
        and (request['expected_digest'] is None or type(request['expected_digest']) is str))
    _require(prepared_request or publication_request or version1_publication_request,
        'ntfs.fixed_native_request_required')
    # Resolve fixed packaged generation before any native role/channel. Profile
    # admission still refuses the unqualified candidate, even empty requirements.
    registry=_native_registry_for_launch(launch)
    try:
        history_bytes,history_digest=getattr(launch,'history_manifest_set',(None,None))
        registry,installation=_native_installation_for_manifest(manifest_bytes=launch._manifest_bytes,
            expected_manifest_digest=launch.installation_digest,run_id=launch.run_id,
            operation_nonce=launch.operation_nonce,channel_id=launch.channel_id,
            history_manifest_set_bytes=history_bytes,history_manifest_set_digest=history_digest,
            _experimental_admission_context=getattr(launch,'_experimental_admission_context',None))
    except (PhaseError,OSError,ValueError) as error:
        # ONLY this pre-installation boundary is a known ordinary refusal.
        # No Core lifecycle, native request or evidence reservation has begun.
        response=PhaseApplication(registry=registry)._failure(request['operation'],error)
    else:
        app=PhaseApplication(registry=registry,installation=installation)
        manifest=launch.manifest
        if publication_request:
            from .preparation import _prepare_file_publication
            try:
                candidate_path, inputs, expected, candidate_bytes = _prepare_file_publication(app,
                    source_locator=request['source_locator'], target_locator=request['target_locator'],
                    request_id=request['request_id'], expected_digest=request['expected_digest'])
            except (PhaseError,OSError,ValueError) as error:
                # Preparation ONLY: no Core call, channel request, worker or GO.
                # The real parent independently checks all four no-effect facts.
                response=app._failure('execute',error)
            else:
                # Never catch a Core result/failure as an early preparation error.
                response=app.run('execute',contract_binding=manifest['contract']['id']+'@'+manifest['contract']['version'],
                    contract_digest=manifest['contract']['package_digest'],candidate_path=candidate_path,
                    evidence_root=Path(manifest['evidence_root']),run_id=launch.run_id,
                    input_paths=inputs,root_bindings={k:Path(v) for k,v in manifest['root_projections'].items()},
                    expected_inputs=expected,_expected_candidate_bytes=candidate_bytes)
        elif version1_publication_request:
            from .preparation import _prepare_version1_publication
            try:
                candidate_path, inputs, expected, candidate_bytes = _prepare_version1_publication(app,
                    source_locator=request['source_locator'], target_locator=request['target_locator'],
                    request_id=request['request_id'], expected_current_digest=request['expected_current_digest'],
                    expected_digest=request['expected_digest'])
            except (PhaseError,OSError,ValueError) as error:
                # Preparation only. Core errors cannot become pre-write refusals.
                response=app._failure('execute',error)
            else:
                response=app.run('execute',contract_binding=manifest['contract']['id']+'@'+manifest['contract']['version'],
                    contract_digest=manifest['contract']['package_digest'],candidate_path=candidate_path,
                    evidence_root=Path(manifest['evidence_root']),run_id=launch.run_id,
                    input_paths=inputs,root_bindings={k:Path(v) for k,v in manifest['root_projections'].items()},
                    expected_inputs=expected,_expected_candidate_bytes=candidate_bytes)
        else:
            expected=request['expected_inputs']
            if expected is not None:
                _require(type(expected) is dict and all(type(v) is list and len(v)==2
                    and type(v[0]) is str and type(v[1]) is int and v[1]>=0 for v in expected.values()),
                    'ntfs.fixed_native_request_required')
                expected={k:tuple(v) for k,v in expected.items()}
            # Core owns capture/freeze, intent, common/per-key locks, effect,
            # validation, ONE proof/receipt and original-intent recovery barrier.
            response=app.run(request['operation'],contract_binding=manifest['contract']['id']+'@'+manifest['contract']['version'],
                contract_digest=manifest['contract']['package_digest'],candidate_path=Path(request['candidate_path']),
                evidence_root=Path(manifest['evidence_root']),run_id=launch.run_id,
                input_paths={k:Path(v) for k,v in request['input_paths'].items()},
                root_bindings={k:Path(v) for k,v in manifest['root_projections'].items()},
                maximum_candidate_bytes=request['maximum_candidate_bytes'],expected_inputs=expected)
    # Use EXACT installed registry. The ordinary default CLI writer must never
    # recast a post-dispatch render/schema/delivery failure as mutationFalse.
    validate_command_result(response.payload,registry)
    launch.check_runtime()
    _deliver_linux_frame({'protocol':'phase.native.command','version':'1.0','channel_id':launch.channel_id,
        'run_id':launch.run_id,'result':response.payload,'exit_code':response.exit_code},identities)
    return response.exit_code


def _native_file_inspection_expectations(request):
    """Pure closed caller assertions; no paths, code identity or admission I/O."""
    if type(request) is dict and request == {'operation': 'inspect'}:
        return {}
    _require(type(request) is dict and set(request) == {'operation',
        'native_file_publication_inspection_request_version', 'request_id',
        'target_locator', 'expected_digest', 'expected_receipt_digest'}
        and request['operation'] == 'inspect'
        and type(request['native_file_publication_inspection_request_version']) is str
        and request['native_file_publication_inspection_request_version'] in {'1.0', '1.1'},
        'ntfs.fixed_native_request_required')
    import re
    from ...paths import safe_relative_locator
    from ...canonical import profile_digest
    from ...publish_file import _file_publication_candidate
    request_id = request['request_id']
    _require(type(request_id) is str and len(request_id) <= 128
        and re.fullmatch(r'[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*', request_id),
        'publish_file.invalid_request_id')
    _require(type(request['target_locator']) is str, 'ntfs.fixed_native_request_required')
    locator = safe_relative_locator(request['target_locator'])
    def digest(value):
        return type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None
    _require(digest(request['expected_receipt_digest']), 'ntfs.invalid_expected_receipt_digest')
    expected = request['expected_digest']
    _require(expected is None or digest(expected), 'publish_file.invalid_expected_digest')
    candidate, _ = _file_publication_candidate(request_id, locator)
    result = {'_expected_candidate_digest': profile_digest('candidate', candidate),
        '_expected_receipt_digest': request['expected_receipt_digest']}
    if expected is not None:
        result['_expected_frozen_input'] = ('payload', expected)
    return result


def _native_version1_inspection_expectations(request):
    """Pure caller assertions, using the existing exact version1 candidate."""
    import re
    from ...canonical import profile_digest
    from .preparation import _version1_publication_candidate
    _require(type(request) is dict and set(request) == {'operation',
        'native_version1_publication_inspection_request_version','request_id',
        'target_locator','expected_current_digest','expected_digest','expected_receipt_digest'}
        and request['operation'] == 'inspect'
        and type(request['native_version1_publication_inspection_request_version']) is str
        and request['native_version1_publication_inspection_request_version'] == '1.0',
        'ntfs.fixed_native_request_required')
    candidate, _ = _version1_publication_candidate(request['request_id'],
        request['target_locator'], request['expected_current_digest'])
    def digest(value):
        return type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None
    _require(digest(request['expected_receipt_digest']), 'ntfs.invalid_expected_receipt_digest')
    _require(request['expected_digest'] is None or digest(request['expected_digest']),
        'publish.invalid_expected_digest')
    capture = {'_expected_candidate_digest': profile_digest('candidate', candidate),
        '_expected_receipt_digest': request['expected_receipt_digest']}
    if request['expected_digest'] is not None:
        capture['_expected_frozen_input'] = ('payload', request['expected_digest'])
    return capture


def _inspect_with_channel_seal(application,authority,*,evidence_root,run_id,root_bindings,
        _expected_candidate_digest=None, _expected_frozen_input=None, _expected_receipt_digest=None,
        _canonical_result_context=None):
    """Read invocation only: always revoke channel, preserve primary failure."""
    primary=None
    response=None
    reference=None
    try:
        assertions=({} if _expected_candidate_digest is None and _expected_frozen_input is None else {
            '_expected_candidate_digest': _expected_candidate_digest,
            '_expected_frozen_input': _expected_frozen_input})
        if _canonical_result_context is None:
            response=application.inspect(evidence_root=evidence_root,run_id=run_id,
                root_bindings=root_bindings,**assertions)
        else:
            response,reference=application._inspect_with_result(evidence_root=evidence_root,
                run_id=run_id,root_bindings=root_bindings,_include_canonical_result=True,**assertions)
        if _expected_receipt_digest is not None and response.payload['success'] is True:
            # Compare the CURRENT ACK receipt, including reused_existing. Failed
            # application responses retain their original error and raw payload.
            _require(response.payload.get('receipt_digest') == _expected_receipt_digest,
                'ntfs.file_publication_receipt_mismatch')
        if _canonical_result_context is not None:
            from .parent_result import validate_native_file_inspection_result
            reference=validate_native_file_inspection_result(response.payload,reference,
                run_id=run_id,**_canonical_result_context)
    except BaseException as error:
        primary=error
    finally:
        try:authority.seal(intent_digest=None)
        except BaseException as error:
            if primary is None:primary=error
            else:
                try:primary.add_note('Native inspection channel seal: '+type(error).__name__)
                except BaseException:pass
    if primary is not None:raise primary
    return response if _canonical_result_context is None else (response,reference)


def run_native_inspection(launch):
    """One fresh read-only invocation through the existing application inspector.

    Only the fixed accepted launcher selects this role. The request contains no
    path/profile/registry/command selector. The manifest supplies all roots.
    No Core.run, EvidenceStore, recovery, proof or receipt publication occurs.
    """
    from ...application import PhaseApplication
    from ...command_result import validate_command_result
    from ...installation import (_native_registry_for_launch,
        _native_installation_for_manifest)
    launch.check_runtime()
    _require(launch._inspection_only, 'ntfs.fixed_inspection_role_required')
    identities=_linux_stdio_identity()
    request=launch.invocation['request']
    version1_inspection = (type(request) is dict
        and 'native_version1_publication_inspection_request_version' in request)
    capture = (_native_version1_inspection_expectations(request) if version1_inspection
        else _native_file_inspection_expectations(request))
    from .parent_result import _native_file_result_mode
    include_result=_native_file_result_mode(request)
    reference=None
    registry=_native_registry_for_launch(launch)
    if capture:
        from ...publish_file import CONTRACT_BINDING
        manifest = parse_json_bytes(launch._manifest_bytes, maximum_bytes=2*1024**2)
        exact = 'publish_new_version.v1@1.0.0' if version1_inspection else CONTRACT_BINDING
        binding = registry.contract_bindings().get(exact)
        _require(binding is not None and manifest.get('contract') == binding
            and (not version1_inspection or manifest.get('native_read_installation_version') in {'1.2','1.4'}),
            'ntfs.original_single_effect_required')
    try:
        history_bytes,history_digest=getattr(launch,'history_manifest_set',(None,None))
        registry,installation=_native_installation_for_manifest(manifest_bytes=launch._manifest_bytes,
            expected_manifest_digest=launch.installation_digest,run_id=launch.run_id,
            operation_nonce=launch.operation_nonce,channel_id=launch.channel_id,
            _inspection_only=True,history_manifest_set_bytes=history_bytes,
            history_manifest_set_digest=history_digest,
            _experimental_admission_context=getattr(launch,'_experimental_admission_context',None))
    except (PhaseError,OSError,ValueError) as error:
        # Only pre-installation refusal: no channel/evidence/target read begun.
        response=PhaseApplication(registry=registry)._failure('inspect',error)
    else:
        manifest=launch.manifest
        context=({'request':request,'manifest_bytes':launch._manifest_bytes,
            'expected_manifest_digest':launch.installation_digest,'registry':registry}
            if include_result else None)
        inspected=_inspect_with_channel_seal(PhaseApplication(registry=registry,installation=installation),
            installation.authority,evidence_root=Path(manifest['evidence_root']),run_id=launch.run_id,
            root_bindings={k:Path(v) for k,v in manifest['root_projections'].items()}, **capture,
            **({'_canonical_result_context':context} if include_result else {}))
        if include_result:response,reference=inspected
        else:response=inspected
    validate_command_result(response.payload,registry)
    launch.check_runtime()
    frame={'protocol':'phase.native.command','version':'1.0','channel_id':launch.channel_id,
        'run_id':launch.run_id,'result':response.payload,'exit_code':response.exit_code}
    if include_result:
        frame.update(version='1.1',canonical_result=reference)
        from .parent_result import validate_native_file_result_delivery
        validate_native_file_result_delivery(frame,request=request,run_id=launch.run_id,
            channel_id=launch.channel_id,manifest_bytes=launch._manifest_bytes,
            expected_manifest_digest=launch.installation_digest,registry=registry)
    _deliver_linux_frame(frame,identities)
    return response.exit_code


def run_native_original(launch):
    from .original_endpoint import native_original_query
    _require(not launch._inspection_only, 'ntfs.inspection_only_operation_forbidden')
    launch.check_runtime()
    identities=_linux_stdio_identity()
    # Existing reader/parser return only after their evidence FDs are closed.
    # Delivery stdio is not evidence ownership and cannot authorize mutation.
    response=native_original_query(launch,launch.invocation['request'])
    if (launch._version1 or launch._version2) and launch.invocation['request']['action'] == 'read_executing':
        from .original_transfer import original_version1_frames,original_version2_frames
        from ...canonical import digest_bytes
        deadline=time.monotonic()+30
        frames=original_version2_frames if launch._version2 else original_version1_frames
        for raw in frames(response,channel_id=launch.channel_id,leg='reader',
                query_digest=digest_bytes(canonical_bytes(launch.invocation['request']))):
            _deliver_linux_frame(parse_json_bytes(raw),identities,_deadline=deadline)
    else:
        _deliver_linux_frame(response,identities)
    return 0


def run_native_parent(launch):
    from .parent import _NativeWindowsParent
    from .process_witness import WindowsProcessWitness
    launch.check_runtime()
    process=(launch.spawn_inspection() if launch._inspection_only else launch.spawn_core())
    witness=pipe=None
    response=fact=None
    primary=None
    try:
        witness=WindowsProcessWitness(process)
        pipe=launch._pipe(process)
        pipe.send_frame(launch._invocation_bytes,time.perf_counter_ns()+30_000_000_000)
        response=_NativeWindowsParent(launch,pipe).serve()
    except BaseException as error:primary=error
    finally:
        try:
            _require(witness is not None,'ntfs.core_creation_witness_unavailable')
            fact=witness.wait_for_exit(60000)
            _require(fact['worker_exit_established'] is True,'ntfs.core_delivery_process_exit_unknown')
            launch._finalize_exited(process,pipe)
        except BaseException as error:
            if primary is None:primary=error
            else:
                try:primary.add_note('Native Core delivery finalization: '+type(error).__name__)
                except BaseException:pass
    if primary is not None:raise primary
    _require(response is not None and fact['exit_code']==response['exit_code'],
        'ntfs.core_command_delivery_unconfirmed')
    # This HANDLE belongs to Docker CLI, NOT Linux exec. No Linux-process exit
    # or original closure proof is derived from it; server ingress is consumed.
    return response

def _run_version1_worker_transfer(launch,original,pipe,deadline,*,_version2=False):
    from .windows_pipe import WindowsPipeFrames
    from .original_transfer import _Version1OriginalDecoder,_Version2OriginalDecoder
    from .worker import run_version1_worker,run_version2_worker
    _require(type(_version2) is bool and _version2==launch._version2,'ntfs.original_closed_role_required')
    _require(type(pipe) is WindowsPipeFrames and type(deadline) is int,
        'ntfs.version1_owned_deadline_required')
    primary=None
    try:
        decoder_type=_Version2OriginalDecoder if _version2 else _Version1OriginalDecoder
        decoder=decoder_type(channel_id=launch.channel_id,leg='worker',query_digest=None,
            expected_context={'run_id':launch.run_id,'operation_nonce':launch.operation_nonce,
                'installation_digest':launch.installation_digest},
            **({'expected_grants':canonical_bytes(launch.root_grants)} if _version2 else
                {'expected_grant':canonical_bytes(launch.root_grant)}))
        decoder.feed(canonical_bytes(original))
        while not decoder.ended:
            raw,_=pipe.receive_frame(deadline)
            decoder.feed(raw)
        parsed=decoder.finish()
        launch.check_runtime()
        # Worker pipe remains open for READY/GO; no reader EOF is invented.
        run_worker=run_version2_worker if _version2 else run_version1_worker
        run_worker(pipe,parse_json_bytes(parsed.context_bytes),parse_json_bytes(parsed.grant_bytes),
            parse_json_bytes(parsed.effect_bytes),parsed.content_bytes,parsed.timestamp,
            _handshake_deadline_ns=deadline)
        launch.check_runtime()
    except BaseException as error:primary=error
    _close_worker_stdio(primary)
    return 0


def _run_file2_worker_transfer(launch,original,pipe,deadline):
    """Metadata initial frame; fixed worker verifies first-pass bytes before native I/O."""
    from .file2_execution import _file2_projection_from_value,run_file2_worker
    _require(type(deadline) is int and 0<deadline-time.perf_counter_ns()<=30_000_000_000,
        'ntfs.file2_owned_deadline_required')
    _require(type(original) is dict and set(original)=={'native_worker_original_version','channel_id','projection'}
        and original['native_worker_original_version']=='2.0'
        and original['channel_id']==launch.channel_id,'ntfs.worker_original_binding_mismatch')
    parsed=_file2_projection_from_value(original['projection'])
    context=parse_json_bytes(parsed.context_bytes)
    _require(context['run_id']==launch.run_id and context['operation_nonce']==launch.operation_nonce
        and context['installation_digest']==launch.installation_digest
        and parse_json_bytes(parsed.grant_bytes)==launch.root_grant,'ntfs.worker_original_binding_mismatch')
    primary=None
    try:
        launch.check_runtime()
        run_file2_worker(pipe,parsed,launch.channel_id,_transfer_deadline_ns=deadline)
        launch.check_runtime()
    except BaseException as error:primary=error
    _close_worker_stdio(primary)
    return 0


def _run_bundle_worker_transfer(launch,original,pipe,deadline):
    """Metadata initial frame; fixed worker verifies first-pass bytes before native I/O."""
    from .bundle_execution import _bundle_projection_from_value,run_bundle_worker
    if launch.manifest['native_read_installation_version']=='1.9' and original.get('native_worker_original_version')=='4.0':
        from .bundle_recovery_worker import run_recovery_worker
        primary=None
        try:run_recovery_worker(launch,original,pipe,deadline)
        except BaseException as error:primary=error
        _close_worker_stdio(primary)
        return 0
    _require(type(deadline) is int and 0<deadline-time.perf_counter_ns()<=30_000_000_000,
        'ntfs.bundle_owned_deadline_required')
    _require(type(original) is dict and set(original)=={'native_worker_original_version','channel_id','projection'}
        and original['native_worker_original_version']=='3.0'
        and original['channel_id']==launch.channel_id,'ntfs.worker_original_binding_mismatch')
    parsed=_bundle_projection_from_value(original['projection'])
    context=parse_json_bytes(parsed.context_bytes)
    _require(context['run_id']==launch.run_id and context['operation_nonce']==launch.operation_nonce
        and context['installation_digest']==launch.installation_digest
        and parse_json_bytes(parsed.grant_bytes)==launch.root_grant,'ntfs.worker_original_binding_mismatch')
    primary=None
    try:
        launch.check_runtime()
        if launch.manifest['native_read_installation_version']=='1.9':
            from .bundle_recovery_capture import run_bundle_worker_capture
            run_bundle_worker_capture(pipe,parsed,launch.channel_id,_transfer_deadline_ns=deadline)
        else:
            run_bundle_worker(pipe,parsed,launch.channel_id,_transfer_deadline_ns=deadline)
        launch.check_runtime()
    except BaseException as error:primary=error
    _close_worker_stdio(primary)
    return 0
