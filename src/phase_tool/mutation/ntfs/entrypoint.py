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


def run_native_worker(launch,original,initial_pipe):
    """Only accepted Popen parent provides this owned stdin; no public service."""
    from .worker import run_file_create_worker
    _require(not launch._inspection_only, 'ntfs.inspection_only_operation_forbidden')
    launch.check_runtime()
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


def _deliver_linux_frame(value,identities):
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
    deadline=time.monotonic()+30
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
    from ...application import PhaseApplication
    from ...command_result import validate_command_result
    from ...installation import (_native_inspection_file_create_registry,
        _native_file_create_installation)
    from .uncertainty import _NativeLifecycleUnresolved
    _require(not launch._inspection_only, 'ntfs.inspection_only_operation_forbidden')
    launch.check_runtime()
    identities=_linux_stdio_identity()
    request=launch.invocation['request']
    _require(type(request) is dict and set(request)=={'operation','candidate_path','input_paths',
        'expected_inputs','maximum_candidate_bytes'}
        and request['operation'] in {'validate','plan','execute'}
        and type(request['candidate_path']) is str and type(request['input_paths']) is dict
        and all(type(k) is str and type(v) is str for k,v in request['input_paths'].items())
        and type(request['maximum_candidate_bytes']) is int
        and 0<request['maximum_candidate_bytes']<=1024**2,
        'ntfs.fixed_native_request_required')
    # Resolve fixed packaged generation before any native role/channel. Profile
    # admission still refuses the unqualified candidate, even empty requirements.
    registry=_native_inspection_file_create_registry()
    try:
        registry,installation=_native_file_create_installation(manifest_bytes=launch._manifest_bytes,
            expected_manifest_digest=launch.installation_digest,run_id=launch.run_id,
            operation_nonce=launch.operation_nonce,channel_id=launch.channel_id)
    except (PhaseError,OSError,ValueError) as error:
        # ONLY this pre-installation boundary is a known ordinary refusal.
        # No Core lifecycle, native request or evidence reservation has begun.
        response=PhaseApplication(registry=registry)._failure(request['operation'],error)
    else:
        app=PhaseApplication(registry=registry,installation=installation)
        manifest=launch.manifest
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


def _inspect_with_channel_seal(application,authority,*,evidence_root,run_id,root_bindings):
    """Read invocation only: always revoke channel, preserve primary failure."""
    primary=None
    response=None
    try:
        response=application.inspect(evidence_root=evidence_root,run_id=run_id,root_bindings=root_bindings)
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
    return response


def run_native_inspection(launch):
    """One fresh read-only invocation through the existing application inspector.

    Only the fixed accepted launcher selects this role. The request contains no
    path/profile/registry/command selector. The manifest supplies all roots.
    No Core.run, EvidenceStore, recovery, proof or receipt publication occurs.
    """
    from ...application import PhaseApplication
    from ...command_result import validate_command_result
    from ...installation import (_native_inspection_file_create_registry,
        _native_file_create_installation)
    launch.check_runtime()
    _require(launch._inspection_only, 'ntfs.fixed_inspection_role_required')
    identities=_linux_stdio_identity()
    _require(launch.invocation['request']=={'operation':'inspect'},
        'ntfs.fixed_native_request_required')
    registry=_native_inspection_file_create_registry()
    try:
        registry,installation=_native_file_create_installation(manifest_bytes=launch._manifest_bytes,
            expected_manifest_digest=launch.installation_digest,run_id=launch.run_id,
            operation_nonce=launch.operation_nonce,channel_id=launch.channel_id,
            _inspection_only=True)
    except (PhaseError,OSError,ValueError) as error:
        # Only pre-installation refusal: no channel/evidence/target read begun.
        response=PhaseApplication(registry=registry)._failure('inspect',error)
    else:
        manifest=launch.manifest
        response=_inspect_with_channel_seal(PhaseApplication(registry=registry,installation=installation),
            installation.authority,evidence_root=Path(manifest['evidence_root']),run_id=launch.run_id,
            root_bindings={k:Path(v) for k,v in manifest['root_projections'].items()})
    validate_command_result(response.payload,registry)
    launch.check_runtime()
    _deliver_linux_frame({'protocol':'phase.native.command','version':'1.0','channel_id':launch.channel_id,
        'run_id':launch.run_id,'result':response.payload,'exit_code':response.exit_code},identities)
    return response.exit_code


def run_native_original(launch):
    from .original_endpoint import native_original_query
    _require(not launch._inspection_only, 'ntfs.inspection_only_operation_forbidden')
    launch.check_runtime()
    identities=_linux_stdio_identity()
    # Existing reader/parser return only after their evidence FDs are closed.
    # Delivery stdio is not evidence ownership and cannot authorize mutation.
    response=native_original_query(launch,launch.invocation['request'])
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
