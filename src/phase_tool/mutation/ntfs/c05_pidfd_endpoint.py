"""Only the fixed first C05 fixture can expose this passive Linux endpoint."""
import os
import select
import socket
import stat
import struct
import sys
from hashlib import sha256
from pathlib import Path

from .c05_pidfd_owner import (WIDTH, Owner, canon, digest, linux_identity, need, offer, peer_notice,
                               _CloseUnknown, _open_proc_process, _proc_birth, _read_proc_record)
from .channel import LinuxNativeChannel


ROLE = 'c05-pidfd-observe'
CASE = '51c05d17-7e2b-4c45-9273-15aa66bdab75'
RUNS = tuple('od3-'+CASE+'-c05-file1-r000-p'+str(index) for index in range(WIDTH))
LAUNCHER = '/opt/experiment/file1/linux/launcher.py'
LAUNCHER_DIGEST = 'sha256:7e80db61c3b70788635f7ac24ae053627e60b76590385c3d750e354b2be67901'
READY_CAP = 2048
FINAL_CAP = 16384
UID = 10001
GID = 10001


def sha(raw):
    return 'sha256:'+sha256(raw).hexdigest()


def binding(config, manifest, manifest_digest, admission):
    """Fixture identity comes from the accepted fixed startup, never a request."""
    from .owner_directory_fixture import _kinds, fixture_document
    from .owner_semantic_contracts import semantic_owner_contract
    need(sys.platform=='linux' and type(admission) is _kinds()['File1']
         and config['native_launch_version']=='3.0' and manifest['contract']==semantic_owner_contract('File1')
         and config['linux_launcher']==LAUNCHER and config['artifact_graph']['launcher_digest']==LAUNCHER_DIGEST
         and manifest['evidence_root']=='/qualification/evidence'
         and manifest['preparation_root']=='/qualification/preparation'
         and digest(manifest_digest),'exact_first_file1_fixture_observer')
    fixture = fixture_document(admission.raw)
    need(fixture['fixture_uuid']==CASE and fixture['experimental_admission_version']=='3.0'
         and 'c02_current_root_alias' not in fixture,
         'exact_first_case_observer')
    python = config['linux_python']
    expected = config['artifact_graph']['linux']['python_executable_digest']
    need(python=='/opt/phase/bin/python' and digest(expected),'exact_fixed_linux_python')
    return {'manifest_digest':manifest_digest,'python':python,'python_digest':expected}


def address(scope):
    material = canon({'case':CASE,'manifest_digest':scope['manifest_digest'],'launcher_digest':LAUNCHER_DIGEST})
    return b'\x00phase-c05-'+sha256(material).hexdigest()[:40].encode('ascii')


def argv(scope):
    return (scope['python'],'-I','-S','-B','-u',LAUNCHER,ROLE)


def process_details(pid):
    """Read only kernel facts about the specific peer already held by a socket."""
    need(type(pid) is int and 0<pid<2**32,'one_actual_peer_pid')
    with _open_proc_process(pid) as parent:
        detail = {'birth':_proc_birth(parent,pid)}
        for ns in ('mnt','net'):
            info = os.stat('ns/'+ns,dir_fd=parent)
            need(info.st_ino>0,'one_actual_peer_namespace')
            detail[ns] = [info.st_dev,info.st_ino]
        executable = os.stat('exe',dir_fd=parent)
        need(stat.S_ISREG(executable.st_mode),'one_actual_peer_executable')
        detail['executable'] = [executable.st_dev,executable.st_ino]
        raw = _read_proc_record(parent,'cmdline')
        need(raw.endswith(b'\x00'),'complete_actual_peer_argv')
        detail['argv'] = tuple(part.decode('utf-8','strict') for part in raw[:-1].split(b'\x00'))
        return detail


def _identity_scope(detail):
    return (detail['mnt'],detail['net'],detail['executable'],
            detail['birth']['pid_namespace'],detail['birth']['time_namespace'])


def credentials(connection):
    return struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))


def producer(launch,lock_claims,owner,initial_deadline):
    """One nonblocking offer before entering stock Core, with no observer reply."""
    from time import monotonic
    scope = binding(launch._config,launch.manifest,launch.installation_digest,launch._experimental_admission_context)
    inv = launch.invocation
    need(type(initial_deadline) is float and monotonic()<initial_deadline and owner['pid']==os.getpid()
         and launch.run_id in RUNS and inv['run_id']==launch.run_id==lock_claims['run_id']
         and lock_claims['manifest_digest']==scope['manifest_digest']
         and lock_claims['staged_request_sha256']==sha(canon(inv['request']))
         and lock_claims['operation_nonce']==inv['operation_nonce']
         and launch._invocation_bytes==canon(inv),'same_current_fixed_c05_invocation')
    value = {'schema':'phase.c05.linux-core-birth/1','scope':'PASSIVE_OBSERVATION_NO_CONTROL',
             'binding':{'run_id':launch.run_id,'installation_digest':scope['manifest_digest'],
                        'staged_request_sha256':lock_claims['staged_request_sha256'],
                        'invocation_sha256':sha(launch._invocation_bytes),'channel_id':inv['channel_id'],
                        'operation_nonce':inv['operation_nonce']},'owner':owner}
    destination = address(scope)
    me = process_details(owner['pid'])
    need(me['birth']==owner and me['argv']==(*argv(scope)[:-1],'core'),'same_fixed_core_producer_birth_and_argv')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_NONBLOCK|socket.SOCK_CLOEXEC) as connection:
        connection.setblocking(False)
        need(monotonic()<initial_deadline,'same_initial_receive_deadline')
        connection.connect(destination)
        pid,uid,gid = credentials(connection)
        need((uid,gid)==(UID,GID) and pid!=owner['pid'] and connection.getpeername()==destination,
             'same_credential_bound_passive_collector')
        collector = process_details(pid)
        need(collector['birth']['pid']==pid and collector['argv']==argv(scope)
             and _identity_scope(collector)==_identity_scope(me)
             and credentials(connection)==(pid,uid,gid) and monotonic()<initial_deadline,
             'same_container_executable_and_fixed_collector_role')
        offer(connection,canon(value))


class _ObserverCutoff(ValueError):
    """The original controller closed its one retained lifetime pipe."""


class _ObserverPipe(LinuxNativeChannel):
    """Reuse the stock owned stdout writer with cutoff-aware readiness."""
    def __init__(self):
        super().__init__('0'*32)

    def _observe_cutoff(self):
        need(os.read(self._identity(0),1)==b'','the_conductor_sends_no_observer_control_frames')
        raise _ObserverCutoff('owner_cutoff')

    def _ready(self,fd,writing,deadline):
        need(deadline is None and writing is True and fd==self._identity(1),'observer_stdout_only')
        wait = select.poll()
        wait.register(self._identity(0),select.POLLIN|select.POLLHUP)
        wait.register(fd,select.POLLOUT)
        while True:
            events = dict(wait.poll(10))
            if 0 in events:
                self._observe_cutoff()
            if fd in events:
                event = events[fd]
                need(event&select.POLLOUT and not event&(select.POLLERR|select.POLLHUP|select.POLLNVAL),
                     'same_ready_observer_stdout')
                return

    def record(self,value,limit):
        raw = canon(value)+b'\n'
        need(0<len(raw)<=limit,'bounded_observer_output')
        self._write(raw,None)


class Collector:
    """Finite peer/descriptor state. No signal, ACK, publication, or receipt."""
    def __init__(self,scope,identity,details,*,owner_type=Owner):
        self.scope,self.identity,self.details = scope,identity,details
        self.owner = owner_type(runs=RUNS,expected_uid=UID,namespace=identity,
                                installation_digest=scope['manifest_digest'])
        self.peers = {}
        self.accepted = 0
        self.listener = None
        self.retired = False
        self.disposition = 'OWNER_CUTOFF_OR_CAPTURE_UNKNOWN'
        self.primary = None
        self.cleanup_unknown = False

    def start(self):
        need(self.listener is None and not self.retired,'one_fresh_listener')
        self.listener = socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_NONBLOCK|socket.SOCK_CLOEXEC)
        self.listener.setblocking(False)
        self.listener.bind(address(self.scope))
        self.listener.listen(WIDTH)
        need(self.listener.getsockname()==address(self.scope),'same_bound_listener')

    def accept(self):
        connection,_ = self.listener.accept()
        try:
            need(self.accepted<WIDTH and not self.retired,'no_additional_candidate_peers')
            self.accepted += 1
            connection.setblocking(False)
            pid,uid,gid = credentials(connection)
            peer = process_details(pid)
            wanted = (*argv(self.scope)[:-1],'core')
            need((uid,gid)==(UID,GID) and pid!=self.identity['pid'] and peer['birth']['pid']==pid
                 and peer['argv']==wanted
                 and _identity_scope(peer)==_identity_scope(self.details)
                 and connection.getsockname()==address(self.scope),
                 'same_container_executable_and_fixed_core_role')
            descriptor = connection.fileno()
            need(descriptor not in self.peers,'unique_current_peer_socket')
            self.peers[descriptor] = connection
        except BaseException as primary:
            self._close_after_peer_failure(connection,primary)
            raise

    def _close_peer(self,connection):
        try:
            connection.close()
        except BaseException as error:
            self.owner.failed = self.cleanup_unknown = True
            if isinstance(error,OSError):
                raise _CloseUnknown('c05.linux_owner.peer_socket_close_unknown') from error
            raise

    def _close_after_peer_failure(self,connection,primary):
        try:
            self._close_peer(connection)
        except BaseException as cleanup:
            raise BaseExceptionGroup('c05.linux_owner.peer_capture_and_cleanup_unknown',
                                     [primary,cleanup]) from None

    def receive(self,descriptor):
        connection = self.peers.pop(descriptor)
        try:
            peer_notice(connection,self.owner)
        except BaseException as primary:
            self._close_after_peer_failure(connection,primary)
            raise
        self._close_peer(connection)

    def ready(self):
        return {'schema':'phase.c05.pidfd-observer-ready/1','case':CASE,'owner':self.identity,
                'installation_digest':self.scope['manifest_digest'],'endpoint_sha256':sha(address(self.scope)),
                'role':ROLE,'diagnostics_only':True}

    def step(self,pipe):
        """Run one cutoff-first pass. The outer controller owns the 30 s clock."""
        poll = select.poll()
        listen = self.listener.fileno()
        poll.register(pipe._identity(0),select.POLLIN|select.POLLHUP)
        poll.register(listen,select.POLLIN)
        for descriptor in self.peers:
            poll.register(descriptor,select.POLLIN|select.POLLHUP)
        events = dict(poll.poll(10))
        if 0 in events:
            pipe._observe_cutoff()
        if listen in events:
            need(events.pop(listen)==select.POLLIN,'same_ready_listener')
            self.accept()
        for descriptor,event in events.items():
            need(event&select.POLLIN and not event&(select.POLLERR|select.POLLNVAL),'complete_ready_peer')
            self.receive(descriptor)
        self.owner.tick()
        if (len(self.owner.rows)==WIDTH and not self.peers and not self.owner.failed
                and all(row['close_ns'] is not None for row in self.owner.rows.values())):
            self.disposition = 'EIGHT_RETAINED_PIDFD_EXITS_AND_CLOSES'
            return False
        return True

    def close(self):
        need(not self.retired,'one_observer_retirement')
        self.retired = True
        errors = []
        for descriptor in tuple(self.peers):
            try:
                self.peers.pop(descriptor).close()
            except OSError as error:
                errors.append(error)
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError as error:
                errors.append(error)
        try:
            self.owner.retire_unproved()
        except Exception as error:
            errors.append(error)
        if errors:
            self.owner.failed = True
            self.disposition = 'OWNER_CUTOFF_OR_CAPTURE_UNKNOWN'
            raise BaseExceptionGroup('c05.observer_close_unknown',errors)

    def report(self):
        need(self.retired,'observer_ownership_must_be_retired')
        observation = self.owner.observation()
        cleanup_unknown = self.cleanup_unknown or self.owner.cleanup_unknown
        complete = (self.disposition=='EIGHT_RETAINED_PIDFD_EXITS_AND_CLOSES' and not observation['invalid']
                    and self.primary is None and cleanup_unknown is False)
        return {'schema':'phase.c05.pidfd-observer-terminal/1','ready':self.ready(),'disposition':self.disposition,
                'accepted_socket_count':self.accepted,'complete_diagnostic':complete,'observation':observation,
                'primary_failure':self.primary,'cleanup_unknown':cleanup_unknown,
                'qualification_credit':0,'retry_authorized':False}


def _run_collector(actor,pipe,identity,details):
    """One retained observation lifetime. Cutoff precedes further stdout."""
    stage = 'listener_bind'
    try:
        actor.start()
        stage = 'ready_output'
        pipe.record(actor.ready(),READY_CAP)
        stage = 'peer_capture'
        while actor.step(pipe):
            pass
    except _ObserverCutoff:
        actor.owner.failed = True
        actor.primary = 'owner_cutoff'
    except _CloseUnknown:
        # A sole close failure must not invent a peer-capture failure.
        actor.owner.failed = True
    except (OSError,ValueError,ExceptionGroup):
        actor.owner.failed = True
        actor.primary = stage
    finally:
        try:
            actor.close()
        except (OSError,ValueError,ExceptionGroup):
            actor.owner.failed = True
            actor.cleanup_unknown = True
    if actor.primary=='owner_cutoff':
        return 50
    try:
        need(linux_identity(os.getpid())==identity and process_details(os.getpid())==details,
             'same_collector_birth_executable_and_namespaces_after_close')
    except (OSError,ValueError,ExceptionGroup):
        actor.owner.failed = True
        actor.primary = actor.primary or 'observer_identity'
    terminal = actor.report()
    try:
        pipe.record(terminal,FINAL_CAP)
    except (OSError,ValueError,ExceptionGroup):
        # The original owner retains the exact ready or partial prefix.
        return 50
    return 0 if terminal['complete_diagnostic'] else 50


def collect(outer,config_raw,manifest_raw,admission):
    """The exact fixed fixture role. No manifest or path is read from stdin."""
    from ...canonical import canonical_bytes,canonical_digest,parse_json_bytes
    from ...evidence import _read_qualification_catalog_chunk
    from .entrypoint import _linux_stdio_identity
    cfg = parse_json_bytes(config_raw,maximum_bytes=2*1024**2)
    manifest = parse_json_bytes(manifest_raw,maximum_bytes=2*1024**2)
    need(outer['native_fixed_startup_version']=='3.0' and (os.geteuid(),os.getegid())==(UID,GID)
         and sha(config_raw)==outer['config_digest'] and sha(manifest_raw)==outer['manifest_digest']
         and canonical_bytes(cfg)==config_raw and canonical_bytes(manifest)==manifest_raw
         and canonical_digest(cfg['artifact_graph'])==manifest['composition']['artifact_graph_digest'],
         'current_private_observer_runtime')
    scope = binding(cfg,manifest,outer['manifest_digest'],admission)
    need(tuple(sys.argv)==(LAUNCHER,ROLE) and sha(_read_qualification_catalog_chunk(Path(LAUNCHER),65536))==LAUNCHER_DIGEST
         and sha(_read_qualification_catalog_chunk(Path('/proc/self/exe').resolve(strict=True),32*1024**2))==scope['python_digest'],
         'same_exact_observer_launcher_and_actual_executable')
    identity = linux_identity(os.getpid())
    details = process_details(os.getpid())
    need(details['birth']==identity and details['argv']==argv(scope),'exact_nonrequest_observer_birth_and_argv')
    _linux_stdio_identity()
    pipe = _ObserverPipe()
    try:
        return _run_collector(Collector(scope,identity,details),pipe,identity,details)
    finally:
        pipe.seal()
