"""SOURCE ONLY closed C01 observation over the existing Core flock.

No operation/request selector, alternate lock, Core journal, queue, proof or
retry permission. The normal launcher never selects this ContextVar scope.
Only a distinct exact qualification launcher can construct the opaque token.
"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
import errno,json,os,re,socket,stat,struct,threading,time
from pathlib import Path
from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes
from ...errors import PhaseError

_LAUNCHER = 'sha256:c13f905261304fc7c9b7089043b521bac6b7f10f3ffcd1436f62ea26800b2931'
_TIMEOUT_LAUNCHER = 'sha256:85f63625f18679c8db5d0419d51d09dfd605a5a117cf149bf951bea001f318fa'
_TIMEOUT_RUN = 'od3-de456bc6-f16a-5a4a-8e69-6c20d64c3613-c01-contender-000'
_TIMEOUT_FRESH_LAUNCHER = 'sha256:8043fd34ba6fec59db59c083c618ab4fcdbbb7104c9ee8d5609f4b387bd97438'
_TIMEOUT_FRESH_CASE = 'c5c6e22e-765e-5664-a655-1ea97e08bb5c'
_TIMEOUT_FRESH_RUN = 'od3-c5c6e22e-765e-5664-a655-1ea97e08bb5c-c01-contender-000'
_TIMEOUT_FRESH_SCOPE = 'owner3-input-c5c6e22e-765e-5664-a655-1ea97e08bb5c-file2'
_SELECTED=ContextVar('phase_closed_c01_flock_test',default=None)
_PROTOCOL='phase.test.common-core-flock/1'
_STAGES={'hello','bound','acquire_return','acquire_timeout','acquired','history_begin','unlock_return','close_return','guard_return','scope_finish'}

def _need(value,code='ntfs.c01_flock_test_binding'):
    if not value:raise PhaseError(code)

def _remaining(deadline):
    value=deadline-time.monotonic()
    _need(value>0,'ntfs.c01_flock_test_deadline')
    return value


class _PosixFlockIPC:
    """Fixed local qualification coordination only, never a Phase transport."""
    def __init__(self,path,expected_identity,peer_pid,peer_uid,deadline):
        _need(os.name=='posix' and hasattr(socket,'SO_PEERCRED') and hasattr(socket,'SOCK_SEQPACKET'),
            'ntfs.c01_flock_test_linux_required')
        self.socket=None;self.close_attempted=False
        def named():
            for parent in reversed(path.parents):
                info=parent.lstat();_need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                    and not info.st_mode&0o022,'ntfs.c01_flock_test_ipc_unsafe')
            info=path.lstat();_need(stat.S_ISSOCK(info.st_mode) and info.st_uid==peer_uid and info.st_nlink==1
                and not info.st_mode&0o077,'ntfs.c01_flock_test_ipc_unsafe')
            _need((info.st_dev,info.st_ino)==tuple(expected_identity),'ntfs.c01_flock_test_ipc_identity')
        named()
        try:
            self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.socket.set_inheritable(False);self.socket.setblocking(False)
            result=self.socket.connect_ex(str(path))
            _need(result in (0,errno.EINPROGRESS,errno.EAGAIN,errno.EWOULDBLOCK),'ntfs.c01_flock_test_ipc_connect')
            if result:self._ready(True,deadline)
            _need(self.socket.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)==0,'ntfs.c01_flock_test_ipc_connect')
            pid,uid,_gid=struct.unpack('3i',self.socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            _need(pid==peer_pid and uid==peer_uid,'ntfs.c01_flock_test_ipc_peer')
            named();_remaining(deadline)
        except BaseException as primary:
            try:self.close()
            except BaseException as secondary:primary.add_note('C01 IPC close incomplete: '+str(secondary))
            raise

    def _ready(self,write,deadline):
        import select
        poll=select.poll();poll.register(self.socket.fileno(),select.POLLOUT if write else select.POLLIN)
        result=poll.poll(max(0,int(_remaining(deadline)*1000)))
        _need(result and all(mask&(select.POLLOUT if write else select.POLLIN) and not mask&(select.POLLERR|select.POLLNVAL)
            for _,mask in result),'ntfs.c01_flock_test_ipc_wait')
        _remaining(deadline)

    def send(self,raw):
        _need(type(raw) is bytes and 0<len(raw)<=4096,'ntfs.c01_flock_test_ipc_limit')
        # Exactly one nonblocking syscall; no retry or new clock on telemetry.
        _need(self.socket.send(raw)==len(raw),'ntfs.c01_flock_test_ipc_short_send')

    def receive(self,deadline):
        self._ready(False,deadline);raw,_,flags,_=self.socket.recvmsg(4096)
        _need(raw and not flags&socket.MSG_TRUNC,'ntfs.c01_flock_test_ipc_frame')
        _remaining(deadline);return parse_json_bytes(raw,maximum_bytes=4096)

    def close(self):
        _need(not self.close_attempted,'ntfs.c01_flock_test_ipc_close_consumed')
        self.close_attempted=True
        if self.socket is not None:self.socket.close()


def _closed_timeout_launcher(launch, fixture):
    config=launch._config
    if config['native_launch_version']=='2.0' and fixture['experimental_admission_version']=='2.0':
        return _LAUNCHER
    from .owner_directory_fixture import _kinds
    from .owner_semantic_contracts import semantic_owner_contract
    _need(config['native_launch_version']=='3.0' and fixture['experimental_admission_version']=='3.0'
        and type(launch._experimental_admission_context)is _kinds()['File2']
        and launch.manifest['contract']==semantic_owner_contract('File2'),'ntfs.c01_flock_test_scope')
    run,_,launcher=_timeout_installation_binding(config,fixture)
    _need(launch.run_id==run,'ntfs.c01_flock_test_scope')
    return launcher


_TIMEOUT_CASE = 'de456bc6-f16a-5a4a-8e69-6c20d64c3613'
_TIMEOUT_SCOPE = 'owner3-input-de456bc6-f16a-5a4a-8e69-6c20d64c3613-file2'
_TIMEOUT_SOURCE = 'file2.bin'
_TIMEOUT_TARGET = 'c01-timeout-file2.bin'
_TIMEOUT_DIGEST = 'sha256:65b8df4a0d55dbcb861b8584fde023f745e515c75ed9ad09798767e2c4f05c21'
_TIMEOUT_BYTES = 65536
_TIMEOUT_REQUEST = 'c01.file2.timeout.component.v1'
_TIMEOUT_CONTRACT = {'id':'file_create.v2','version':'1.0.1',
    'package_digest':'sha256:5fa188c4b19696156bfe1dd3ee4105c5292ba3a48e1ad150fc76682bddf037d2'}


def _timeout_installation_binding(config,fixture):
    launcher=config['artifact_graph']['launcher_digest']
    if fixture['fixture_uuid']==_TIMEOUT_CASE and launcher==_TIMEOUT_LAUNCHER:
        return _TIMEOUT_RUN,_TIMEOUT_SCOPE,launcher
    _need(fixture['fixture_uuid']==_TIMEOUT_FRESH_CASE and launcher==_TIMEOUT_FRESH_LAUNCHER,
        'ntfs.c01_timeout_scope')
    return _TIMEOUT_FRESH_RUN,_TIMEOUT_FRESH_SCOPE,launcher


def _timeout_startup_identity(value):
    _need(type(value) is tuple and value in ((_TIMEOUT_RUN,_TIMEOUT_SCOPE),
        (_TIMEOUT_FRESH_RUN,_TIMEOUT_FRESH_SCOPE)),'ntfs.c01_timeout_scope')
    return value


def _require_timeout_startup(config, manifest, admission):
    from .owner_directory_fixture import fixture_document, _kinds
    from .owner_semantic_contracts import semantic_owner_contract
    _need(type(admission) is _kinds()['File2'] and config['native_launch_version']=='3.0'
        and config['artifact_graph']['launcher_digest'] in (_TIMEOUT_LAUNCHER,_TIMEOUT_FRESH_LAUNCHER)
        and manifest['contract']==_TIMEOUT_CONTRACT==semantic_owner_contract('File2'),'ntfs.c01_timeout_scope')
    fixture=fixture_document(admission.raw)
    _need(fixture['experimental_admission_version']=='3.0','ntfs.c01_timeout_scope')
    run,scope,_=_timeout_installation_binding(config,fixture)
    return run,scope


def _require_timeout_frontend(value,*,_startup=(_TIMEOUT_RUN,_TIMEOUT_SCOPE)):
    run,scope=_timeout_startup_identity(_startup)
    _need(type(value) is dict and value=={'run_id':run,'request':{
        'operation':'publish_file','input_scope':scope,'source_locator':_TIMEOUT_SOURCE,
        'target_locator':_TIMEOUT_TARGET,'request_id':_TIMEOUT_REQUEST,'publication_version':'2.0',
        'expected_digest':_TIMEOUT_DIGEST,'root_binding':'phase_result_root'}},'ntfs.c01_timeout_frontend_request')


def _require_timeout_stage(launch, scope, role, header):
    run,scope_id=_require_timeout_startup(launch._config,launch.manifest,launch._experimental_admission_context)
    rows=header['members']
    _need(launch.run_id==run and role=='File2' and scope['scope_id']==scope_id
        and header['run_id']==run and header['input_scope']==scope_id and header['role']=='File2'
        and header['source_locator']==_TIMEOUT_SOURCE and header['payload_kind']=='file'
        and type(header['member_count']) is int and header['member_count']==1
        and type(header['total_length']) is int and header['total_length']==_TIMEOUT_BYTES
        and type(rows) is list and len(rows)==1 and rows[0]['path']=='payload'
        and type(rows[0]['length']) is int and rows[0]['length']==_TIMEOUT_BYTES,
        'ntfs.c01_timeout_stage_request')


def _require_timeout_stage_payload(raw):
    _need(type(raw) is bytes and len(raw)==_TIMEOUT_BYTES and digest_bytes(raw)==_TIMEOUT_DIGEST,
        'ntfs.c01_timeout_stage_payload')


def _require_timeout_core(value,*,_startup=(_TIMEOUT_RUN,_TIMEOUT_SCOPE)):
    run,scope=_timeout_startup_identity(_startup)
    _need(type(value) is dict and set(value)=={'run_id','request','channel_id','operation_nonce'}
        and value['run_id']==run and all(type(value[key]) is str and
        re.fullmatch('[0-9a-f]{32}',value[key]) is not None for key in ('channel_id','operation_nonce')),
        'ntfs.c01_timeout_core_invocation')
    request=value['request']
    _need(type(request) is dict and set(request)=={'operation','native_staged_publication_request_version','input_scope',
        'stage_header_digest','source_locator','source_digest','source_length','request_id','target_locator','members',
        'expected_current_digest','content_utf8'},'ntfs.c01_timeout_core_request')
    header=request['stage_header_digest']
    _need(type(header) is str and re.fullmatch('sha256:[0-9a-f]{64}',header) is not None,
        'ntfs.c01_timeout_core_stage_identity')
    _need(type(request['source_length']) is int and request=={'operation':'execute','native_staged_publication_request_version':'1.0','input_scope':scope,
        'stage_header_digest':header,'source_locator':'phase-native-input-'+header[7:39]+'/payload/payload',
        'source_digest':_TIMEOUT_DIGEST,'source_length':_TIMEOUT_BYTES,'request_id':_TIMEOUT_REQUEST,
        'target_locator':_TIMEOUT_TARGET,'members':None,'expected_current_digest':None,'content_utf8':None},
        'ntfs.c01_timeout_core_request')


class _CommonCoreFlockTest:
    """Opaque one-shot token. Its observations never establish Phase success."""
    __slots__=('_initialized','_owner','_launch','_selected','_taken','_bound','_fd','_acquired',
        '_history','_unlock','_closed','_guard','_finished','events','errors','_sequence','_ipc',
        '_initial','_mode','_case','_campaign','_fixture_digest','_run','_manifest_digest','_nonce',
        '_evidence_identity','_deadline','_lock_deadline','_ipc_closed','_snapshot_write_attempted')
    def __init__(self,launch,*,_initial_deadline):
        from .bootstrap import _NativeAcceptedLaunch
        from .owner_directory_fixture import fixture_document,_kinds
        from ...streaming import read_bounded_file
        _need(type(self) is _CommonCoreFlockTest and type(launch) is _NativeAcceptedLaunch,
            'ntfs.c01_flock_test_type')
        _need(not getattr(self,'_initialized',False),'ntfs.c01_flock_test_consumed')
        self._initialized=True;self._owner=(os.getpid(),threading.get_ident());self._launch=launch
        self._selected=False;self._taken=False;self._bound=False;self._fd=None;self._acquired=False
        self._history=False;self._unlock=False;self._closed=False;self._guard=False;self._finished=False
        self.events=[];self.errors=[];self._sequence=0;self._ipc=None;self._snapshot_write_attempted=False
        _need(type(_initial_deadline) is float and 0<_initial_deadline-time.monotonic()<=30,
            'ntfs.c01_flock_test_deadline')
        self._initial=_initial_deadline
        _need(os.sys.platform.startswith('linux') and not launch._inspection_only
            and type(launch._experimental_admission_context) in tuple(_kinds().values())
            and launch.invocation['request'].get('operation')=='execute','ntfs.c01_flock_test_scope')
        fixture=fixture_document(launch._experimental_admission_context.raw)
        launch.check_runtime();config=launch._config;graph=config['artifact_graph']
        selected_launcher=_closed_timeout_launcher(launch,fixture)
        _need(graph['launcher_digest']==selected_launcher,
            'ntfs.c01_flock_test_launcher')
        launcher=Path(config['linux_launcher']);_need(digest_bytes(read_bounded_file(launcher,2*1024**2))==selected_launcher,
            'ntfs.c01_flock_test_launcher')
        path=launcher.parent/'common-core-flock-test.json';raw=read_bounded_file(path,65536)
        _need(digest_bytes(raw)==config['dependency_file_digests'].get(str(path))
            ==graph['linux']['dependency_file_digests'].get(str(path)),'ntfs.c01_flock_test_fixture')
        binding=parse_json_bytes(raw,maximum_bytes=65536)
        _need(type(binding) is dict and canonical_bytes(binding)==raw and set(binding)=={
            'common_core_flock_test_version','fixture_uuid','owner_scope_digest','campaign_id','run_prefix',
            'maximum_cases','case_watchdog_seconds','controller_socket','controller_identity','controller_pid','controller_uid'}
            and binding['common_core_flock_test_version']=='1.0' and binding['fixture_uuid']==fixture['fixture_uuid']
            and binding['owner_scope_digest']==digest_bytes(launch._experimental_admission_context.raw)
            and binding['run_prefix']==fixture['request_limits']['run_prefix']+'c01-'
            and binding['maximum_cases']==100 and binding['case_watchdog_seconds']==15,
            'ntfs.c01_flock_test_fixture')
        _need(type(binding['campaign_id']) is str and re.fullmatch('[a-z0-9-]{1,64}',binding['campaign_id']) is not None)
        match=re.fullmatch(re.escape(binding['run_prefix'])+'(holder|contender)-([0-9]{3})',launch.run_id)
        _need(match is not None and int(match[2])<100,'ntfs.c01_flock_test_run')
        self._mode=match[1];self._case=int(match[2]);self._campaign=binding['campaign_id'];self._fixture_digest=digest_bytes(raw)
        expected=Path(launch.manifest['preparation_root'])/'qualification-c01'/self._campaign/'control.sock'
        _need(binding['controller_socket']==str(expected) and type(binding['controller_identity']) is list
            and len(binding['controller_identity'])==2 and all(type(value) is int and value>=0 for value in binding['controller_identity'])
            and type(binding['controller_pid']) is int and binding['controller_pid']>0
            and type(binding['controller_uid']) is int and binding['controller_uid']==os.geteuid())
        self._run=launch.run_id;self._manifest_digest=launch.installation_digest;self._nonce=launch.operation_nonce
        self._evidence_identity=canonical_bytes(launch.manifest['evidence_identity'])
        self._deadline=self._initial
        try:
            self._ipc=_PosixFlockIPC(expected,binding['controller_identity'],binding['controller_pid'],binding['controller_uid'],self._initial)
            self._record('hello',strict=True)
            begin=self._ipc.receive(self._initial)
            _need(type(begin) is dict and set(begin)=={'protocol','action','campaign_id','run_id','operation_nonce','case_started_ns','case_deadline_ns'}
                and begin['protocol']==_PROTOCOL and begin['action']=='BEGIN' and begin['campaign_id']==self._campaign
                and begin['run_id']==self._run and begin['operation_nonce']==self._nonce
                and type(begin['case_started_ns']) is int and type(begin['case_deadline_ns']) is int
                and begin['case_deadline_ns']==begin['case_started_ns']+15_000_000_000
                and begin['case_started_ns']<=time.monotonic_ns(),
                'ntfs.c01_flock_test_begin')
            self._deadline=min(self._initial,begin['case_deadline_ns']/1e9);_remaining(self._deadline)
        except BaseException as primary:
            if self._ipc is not None:
                try:self._ipc.close()
                except BaseException as secondary:primary.add_note('C01 IPC close incomplete: '+str(secondary))
            raise

    def _owner_check(self):
        _need(type(self) is _CommonCoreFlockTest and self._owner==(os.getpid(),threading.get_ident()) and not self._finished,
            'ntfs.c01_flock_test_owner')

    def _record(self,stage,*,strict=False,**facts):
        try:
            self._owner_check();_need(stage in _STAGES and self._sequence<128,'ntfs.c01_flock_test_event_limit')
            _remaining(self._deadline)
            value={'scope':'RAW_C01_TEST_OBSERVATION_NOT_PHASE_PROOF','protocol':_PROTOCOL,'campaign_id':self._campaign,
                'run_id':self._run,'operation_nonce':self._nonce,'pid':os.getpid(),'sequence':self._sequence,
                'stage':stage,'observed_ns':time.monotonic_ns(),'installation_digest':self._manifest_digest,
                'qualification_count':0,'facts':facts}
            self._sequence+=1;self.events.append(value);self._ipc.send(canonical_bytes(value))
        except BaseException as error:
            self.errors.append({'stage':stage,'type':type(error).__name__,'message':str(error)[:1024]})
            if strict:raise

    def take(self,binding,run_id):
        self._owner_check();_need(not self._taken,'ntfs.c01_flock_test_consumed');self._taken=True
        from ...installation import _NativeFileCreateReadBinding
        _need(type(binding) is _NativeFileCreateReadBinding and binding.manifest_digest==self._manifest_digest and run_id==self._run
            and canonical_bytes(parse_json_bytes(binding.manifest_bytes)['evidence_identity'])==self._evidence_identity,
            'ntfs.c01_flock_test_binding')

    def bind_lock(self,path,descriptor,parent_identity,identity,deadline):
        self._owner_check();_need(self._taken and not self._bound,'ntfs.c01_flock_test_consumed');self._bound=True
        expected=Path(self._launch.manifest['evidence_root'])/'.phase'/'locks'/(digest_bytes(b'phase.native-original-intents.v1')[7:]+'.lock')
        _need(path==expected and type(descriptor) is int and descriptor>=0 and type(deadline) is float,
            'ntfs.c01_flock_test_lock')
        self._fd=descriptor;self._lock_deadline=deadline
        _remaining(min(self._deadline,deadline))
        self._record('bound',strict=True,descriptor=descriptor,parent_identity=parent_identity,identity=identity,
            acquire_deadline_float_hex=deadline.hex(),acquire_deadline_ns=int(deadline*1e9))
        _remaining(min(self._deadline,deadline))

    def acquire_return(self,descriptor,succeeded,error_number):
        self._owner_check();_need(self._bound and descriptor==self._fd and not self._acquired)
        _need(type(succeeded) is bool)
        self._record('acquire_return',strict=True,descriptor=descriptor,succeeded=succeeded,errno=error_number,
            contended=not succeeded and error_number in (errno.EACCES,errno.EAGAIN,errno.EWOULDBLOCK),
            interrupted=not succeeded and error_number==errno.EINTR,
            acquire_deadline_float_hex=self._lock_deadline.hex(),acquire_deadline_ns=int(self._lock_deadline*1e9))

    def observed_acquire_timeout(self,descriptor,deadline):
        if getattr(self,'_run',None) not in (_TIMEOUT_RUN,_TIMEOUT_FRESH_RUN):return
        self._owner_check()
        _need(self._bound and not self._acquired and descriptor==self._fd and deadline==self._lock_deadline,
            'ntfs.c01_flock_test_timeout_binding')
        self._record('acquire_timeout',descriptor=descriptor,reason_code='lock.acquire_timeout',
            acquire_deadline_ns=int(deadline*1e9))

    def acquired(self,descriptor):
        self._owner_check();_need(descriptor==self._fd and not self._acquired);self._acquired=True
        self._record('acquired',strict=True,descriptor=descriptor,namespace_checked=True)
        if getattr(self,'_run',None) in (_TIMEOUT_RUN,_TIMEOUT_FRESH_RUN):
            raise PhaseError('ntfs.c01_timeout_unexpected_acquisition')
        if self._mode=='holder':
            reply=self._ipc.receive(min(self._deadline,self._lock_deadline))
            _need(type(reply) is dict and set(reply)=={'protocol','action','campaign_id','run_id','operation_nonce'}
                and reply['protocol']==_PROTOCOL and reply['campaign_id']==self._campaign
                and reply['run_id']==self._run and reply['operation_nonce']==self._nonce
                and reply['action'] in {'RELEASE','ABORT'},'ntfs.c01_flock_test_control')
            _need(reply['action']=='RELEASE','ntfs.c01_flock_test_aborted')
        _remaining(min(self._deadline,self._lock_deadline))

    def before_history(self,descriptor):
        self._owner_check();_need(self._acquired and descriptor==self._fd and not self._history)
        self._record('history_begin',strict=True,descriptor=descriptor);self._history=True

    def unlock_return(self,descriptor,succeeded,error_number):
        # After body/effects, telemetry failure cannot suppress real Core cleanup
        # or publication. The external test rejects its incomplete observation.
        valid=type(succeeded) is bool and self._bound and descriptor==self._fd
        if not valid:self.errors.append({'stage':'unlock_return','type':'BindingError','message':'foreign descriptor or invalid result'})
        self._unlock=valid and succeeded
        self._record('unlock_return',descriptor=descriptor,succeeded=succeeded,errno=error_number)

    def close_return(self,descriptor,succeeded,error_number):
        valid=type(succeeded) is bool and self._bound and descriptor==self._fd
        if not valid:self.errors.append({'stage':'close_return','type':'BindingError','message':'foreign descriptor or invalid result'})
        self._closed=valid and succeeded
        self._record('close_return',descriptor=descriptor,succeeded=succeeded,errno=error_number)

    def guard_return(self):
        self._guard=True;self._record('guard_return',unlock_observed=self._unlock,close_observed=self._closed)

    def finish(self):
        self._owner_check();self._record('scope_finish',guard_returned=self._guard,
            telemetry_phase='PRE_FINALIZATION_NON_AUTHORITATIVE',
            observation_ready_before_socket_close=self._guard and self._unlock and self._closed and not self.errors)
        self._finished=True
        self._ipc_closed=False
        try:self._ipc.close();self._ipc_closed=True
        except BaseException as error:self.errors.append({'stage':'ipc-close','type':type(error).__name__,'message':str(error)[:1024]})

    def snapshot(self):
        return {'scope':'RAW_C01_TEST_OBSERVER_PRE_RETURN_NOT_PHASE_PROOF','run_id':self._run,
            'events':list(self.events),'errors':list(self.errors),'socket_close_observed':getattr(self,'_ipc_closed',False),
            'guard_return_observed':self._guard,'lock_unlock_observed':self._unlock,'lock_close_observed':self._closed,
            'telemetry_phase':'PRE_RETURN_NON_AUTHORITATIVE','final_acceptance':None,'qualification_count':0}

    def write_snapshot(self):
        """Qualification RAW policy; generic byte I/O stays in Evidence IO owner."""
        from ...evidence import _write_owned_stderr_bytes
        raw=canonical_bytes(self.snapshot())+b'\n'
        _need(len(raw)<=128*1024,'ntfs.c01_flock_test_snapshot_limit')
        _write_owned_stderr_bytes(raw,self._deadline)


    def write_snapshot_to_owned_ext4_raw(self):
        """Fixed qualification RAW only, after actual scope/socket finalization.

        The record does not claim its own write/fsync completion or final Phase
        success. Caller exit, native proof, external clocks and RO readback are
        independently required. A late/failed write remains consumed forever.
        """
        from .bootstrap import _NativeAcceptedLaunch
        from ...streaming import read_bounded_file
        from ...evidence import _write_bytes_exclusive_atomic,_opened_owned_private_directory
        _need(type(self) is _CommonCoreFlockTest and self._initialized
            and self._owner==(os.getpid(),threading.get_ident()) and self._finished,
            'ntfs.c01_raw_snapshot_owner')
        _need(not getattr(self,'_snapshot_write_attempted',False),'ntfs.c01_raw_snapshot_consumed')
        self._snapshot_write_attempted=True
        _remaining(self._deadline)
        launch=self._launch
        _need(type(launch) is _NativeAcceptedLaunch and not launch._inspection_only
            and launch.run_id==self._run and launch.installation_digest==self._manifest_digest,
            'ntfs.c01_raw_snapshot_binding')
        config=launch._config
        fixture=parse_json_bytes(launch._experimental_admission_context.raw,maximum_bytes=32768)
        selected_launcher=_closed_timeout_launcher(launch,fixture)
        _need(config['artifact_graph']['launcher_digest']==selected_launcher
            and digest_bytes(read_bounded_file(Path(config['linux_launcher']),2*1024**2))==selected_launcher,
            'ntfs.c01_flock_test_launcher')
        _remaining(self._deadline)
        _need(fixture['experimental_admission_version']==config['native_launch_version']
            and re.fullmatch('[a-z0-9-]{1,64}',self._campaign) is not None
            and type(self._case) is int and 0<=self._case<100 and self._mode in {'holder','contender'}
            and self._run==fixture['request_limits']['run_prefix']+'c01-'+self._mode+'-'+str(self._case).zfill(3),
            'ntfs.c01_raw_snapshot_binding')
        preparation=Path(launch.manifest['preparation_root'])
        _need(preparation.is_absolute(),'ntfs.c01_raw_snapshot_parent')
        parent_pins=[]
        for ancestor in reversed(preparation.parents):
            info=ancestor.lstat()
            _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and not getattr(info,'st_file_attributes',0)&0x400 and not info.st_mode&0o022,
                'ntfs.c01_raw_snapshot_parent')
            parent_pins.append((ancestor,(info.st_dev,info.st_ino),False))
            _remaining(self._deadline)
        expected=launch.manifest['preparation_identity'];info=preparation.lstat()
        _need((info.st_dev,info.st_ino)==(expected['device'],expected['inode']),
            'ntfs.c01_raw_snapshot_parent_identity')
        directory=preparation
        for name in (None,'qualification-c01',self._campaign,'observations'):
            if name is not None:directory=directory/name
            info=directory.lstat()
            _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and not getattr(info,'st_file_attributes',0)&0x400
                and info.st_uid==os.geteuid() and not info.st_mode&0o077,
                'ntfs.c01_raw_snapshot_parent')
            parent_pins.append((directory,(info.st_dev,info.st_ino),True))
            _remaining(self._deadline)
        parent_identity=(info.st_dev,info.st_ino)
        value=self.snapshot()
        value.update(raw_snapshot_version='2.0',raw_io_phase='PRE_RETURN_BEFORE_RAW_IO',
            raw_io_completion_claimed=False,observation_authoritative=False,
            owner_manifest_digest=self._manifest_digest,controller_fixture_digest=self._fixture_digest,
            owner_fixture_digest=digest_bytes(launch._experimental_admission_context.raw))
        raw=canonical_bytes(value)
        _need(len(raw)<=128*1024,'ntfs.c01_flock_test_snapshot_limit')
        _remaining(self._deadline)
        with _opened_owned_private_directory(directory,parent_identity) as parent_descriptor:
            _remaining(self._deadline)
            _write_bytes_exclusive_atomic(directory/(self._run+'.json'),raw,'C01 qualification RAW observation',
                    _parent_descriptor=parent_descriptor)
            _remaining(self._deadline)
            after=directory.lstat()
            _need((after.st_dev,after.st_ino)==parent_identity and stat.S_ISDIR(after.st_mode)
                and not stat.S_ISLNK(after.st_mode) and after.st_uid==os.geteuid()
                and not after.st_mode&0o077,'ntfs.c01_raw_snapshot_parent_identity')
            for path,expected_identity,private in parent_pins:
                after=path.lstat()
                _need((after.st_dev,after.st_ino)==expected_identity and stat.S_ISDIR(after.st_mode)
                    and not stat.S_ISLNK(after.st_mode) and not getattr(after,'st_file_attributes',0)&0x400
                    and not after.st_mode&0o022 and (not private or after.st_uid==os.geteuid() and not after.st_mode&0o077),
                    'ntfs.c01_raw_snapshot_parent_identity')
                _remaining(self._deadline)
            _remaining(self._deadline)
        _remaining(self._deadline)  # Parent fstat/close may return late; no clock renewal.



@contextmanager
def _common_flock_qualification_scope(token):
    _need(type(token) is _CommonCoreFlockTest and _SELECTED.get() is None,'ntfs.c01_flock_test_type')
    token._owner_check();_need(not token._selected,'ntfs.c01_flock_test_consumed');token._selected=True
    state=_SELECTED.set(token)
    primary=None
    try:yield token
    except BaseException as error:primary=error;raise
    finally:
        _SELECTED.reset(state)
        try:token.finish()
        except BaseException as error:
            token.errors.append({'stage':'finish','type':type(error).__name__,'message':str(error)[:1024]})
            if primary is not None:primary.add_note('C01 observer finalization incomplete: '+str(error))


def _take_common_flock_test(binding,run_id):
    token=_SELECTED.get()
    if token is None:return None
    _need(type(token) is _CommonCoreFlockTest,'ntfs.c01_flock_test_type')
    token.take(binding,run_id);return token
