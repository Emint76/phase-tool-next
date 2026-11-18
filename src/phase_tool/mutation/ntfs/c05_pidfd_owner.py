"""Passive Linux identity and retained exit observation. No executable entry."""
from array import array
from contextlib import contextmanager
import json
import os
import re
import select
import socket
import struct
import time


CAP = 2048
WIDTH = 8
IDENTITY = {'pid','start_ticks','pid_namespace','time_namespace'}
JOIN = {'run_id','installation_digest','staged_request_sha256','invocation_sha256','channel_id','operation_nonce'}


class _CloseUnknown(OSError):
    """One already-owned descriptor or peer could not be closed conclusively."""


def need(value,reason):
    if not value:
        raise ValueError('c05.linux_owner.'+reason)


def canon(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def digest(value):
    return type(value)is str and re.fullmatch('sha256:[0-9a-f]{64}',value) is not None


def pair(row):
    return (type(row)is list and len(row)==2 and type(row[0])is type(row[1])is int
            and 0<=row[0]<2**64 and 0<row[1]<2**64)


def notice(raw):
    need(type(raw)is bytes and 0<len(raw)<=CAP,'bounded_peer_frame')
    value = json.loads(raw)
    need(type(value)is dict and canon(value)==raw and set(value)=={'schema','scope','binding','owner'}
         and value['schema']=='phase.c05.linux-core-birth/1' and value['scope']=='PASSIVE_OBSERVATION_NO_CONTROL',
         'closed_peer_frame')
    binding,owner = value['binding'],value['owner']
    need(type(binding)is dict and set(binding)==JOIN and type(binding['run_id'])is str and 0<len(binding['run_id'])<=128
         and all(digest(binding[field]) for field in ('installation_digest','staged_request_sha256','invocation_sha256'))
         and all(type(binding[field])is str and re.fullmatch('[0-9a-f]{32}',binding[field])
                 for field in ('channel_id','operation_nonce')),'exact_executing_invocation')
    need(type(owner)is dict and set(owner)==IDENTITY and type(owner['pid'])is type(owner['start_ticks'])is int
         and 0<owner['pid']<2**32 and 0<owner['start_ticks']<2**63
         and pair(owner['pid_namespace']) and pair(owner['time_namespace']),'typed_linux_birth')
    return value


def _peer_socket(connection):
    need(type(connection)is socket.socket and connection.family==socket.AF_UNIX
         and connection.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_SEQPACKET,
         'one_exact_unix_peer')


def offer(connection,raw):
    """Core lends its own live kernel reference on the fixed connected socket."""
    _peer_socket(connection)
    need(not connection.getblocking(),'no_producer_wait')
    owner = notice(raw)['owner']
    need(owner==linux_identity(os.getpid()),'offer_own_incarnation_only')
    fd = os.pidfd_open(os.getpid(),0)
    try:
        sent = connection.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array('i',[fd]))],
                                  socket.MSG_DONTWAIT|socket.MSG_NOSIGNAL)
        need(sent==len(raw),'one_complete_kernel_lend')
    finally:
        os.close(fd)


def peer_notice(connection,owner):
    """Receive one bounded packet, then give its kernel reference to Owner."""
    _peer_socket(connection)
    need(not connection.getblocking(),'no_observer_wait_inside_tick')
    credentials = struct.unpack('3i',connection.getsockopt(
        socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
    size = array('i').itemsize
    raw,ancillary,flags,_ = connection.recvmsg(CAP+1,socket.CMSG_SPACE(size),socket.MSG_CMSG_CLOEXEC)
    received = []
    clean = True
    for level,kind,data in ancillary:
        if (level,kind)!=(socket.SOL_SOCKET,socket.SCM_RIGHTS):
            clean = False
            continue
        descriptors = array('i')
        descriptors.frombytes(data[:len(data)-len(data)%size])
        received.extend(descriptors)
        clean = clean and len(data)==size
    if (not clean or len(ancillary)!=1 or len(received)!=1
        or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)):
        owner.failed = True
        errors = [ValueError('c05.linux_owner.complete_single_peer_descriptor')]
        for fd in received:
            try:
                owner._close_received_fd(fd)
            except OSError as error:
                errors.append(error)
        if len(errors)==1:
            raise errors[0]
        raise ExceptionGroup('c05.linux_owner.malformed_descriptor_cleanup_unknown',errors)
    owner.adopt(raw,credentials,received[0])


@contextmanager
def _open_proc_process(pid):
    """One current kernel PID directory, borrowed only for fixed observations."""
    need(os.sys.platform=='linux' and type(pid) is int and 0<pid<2**32,'linux_current_pid')
    descriptor = os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _read_proc_record(parent,name):
    """Only these bounded, non-following reads through the retained PID directory."""
    cap = {'stat':4096,'cmdline':1024}.get(name,0)
    if not cap and type(name) is str and re.fullmatch(r'fdinfo/[0-9]{1,10}',name):
        cap = 2048
    need(type(parent) is int and parent>=0 and cap>0,'fixed_proc_read_scope')
    descriptor = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    try:
        result = bytearray()
        while len(result)<=cap:
            chunk = os.read(descriptor,cap+1-len(result))
            if not chunk:
                break
            result.extend(chunk)
        need(0<len(result)<=cap,'bounded_proc_record')
        return bytes(result)
    finally:
        os.close(descriptor)


def _proc_birth(parent,pid):
    raw = _read_proc_record(parent,'stat')
    need(raw.endswith(b'\n') and int(raw.split(b' ',1)[0])==pid,'same_proc_identity')
    ticks = int(raw.rsplit(b') ',1)[1].split()[19])
    need(0<ticks<2**63,'actual_proc_start_ticks')
    out = {'pid':pid,'start_ticks':ticks}
    for leaf,key in (('pid','pid_namespace'),('time','time_namespace')):
        ns = os.stat('ns/'+leaf,dir_fd=parent)
        need(ns.st_ino>0,'namespace_inode')
        out[key] = [ns.st_dev,ns.st_ino]
    return out


def fd_pid(fd):
    """Observe the original received kernel reference without reopening its PID."""
    need(type(fd) is int and 0<=fd<2**31 and not os.get_inheritable(fd),'exact_received_close_on_exec_fd')
    with _open_proc_process(os.getpid()) as parent:
        raw = _read_proc_record(parent,'fdinfo/'+str(fd))
    fields = [line[4:].strip() for line in raw.splitlines() if line.startswith(b'Pid:')]
    need(len(fields)==1 and fields[0].isdigit(),'actual_live_pidfd_pid')
    return int(fields[0])


def linux_identity(pid):
    """Independent kernel current identity. Used only during live pidfd bind."""
    with _open_proc_process(pid) as parent:
        return _proc_birth(parent,pid)


def fd_ready(descriptor):
    poll = select.poll()
    poll.register(descriptor,select.POLLIN)
    events = poll.poll(0)
    if not events:
        return False
    need(len(events)==1 and events[0][0]==descriptor and bool(events[0][1]&select.POLLIN)
         and not events[0][1]&(select.POLLERR|select.POLLNVAL),'actual_pidfd_exit_poll')
    return True


class Owner:
    """One passive reader in the existing case Core container. No signal API."""

    def __init__(self, *, runs, expected_uid, namespace, installation_digest,
                 identify=linux_identity, pid_for_fd=fd_pid, ready=fd_ready, close=os.close, now=time.monotonic_ns):
        need(type(runs)is tuple and len(runs)==len(set(runs))==WIDTH and pair(namespace['pid_namespace'])
             and pair(namespace['time_namespace']) and type(expected_uid)is int and expected_uid>=0
             and digest(installation_digest),'one_exact_width_eight_owner')
        self.runs,self.uid,self.namespace,self.installation = runs,expected_uid,namespace,installation_digest
        self.identify,self.pid_for_fd,self.ready,self.close,self.now = identify,pid_for_fd,ready,close,now
        self.rows = {}
        self.failed = False
        self.cleanup_unknown = False

    def adopt(self,raw,credentials,descriptor):
        """Adopt a kernel reference originating in Core itself, even on refusal."""
        need(type(descriptor)is int and descriptor>=0,'received_descriptor')
        row = {'notice':None,'fd':descriptor,'live_ns':None,'exit_ns':None,'close_ns':None,
               'close_attempted':False,'capture_invalid':False}
        try:
            need(not self.failed and len(self.rows)<WIDTH,'bounded_live_peer_count')
            value = notice(raw)
            run,owner = value['binding']['run_id'],value['owner']
            need(run in self.runs and run not in self.rows
                 and value['binding']['installation_digest']==self.installation,'one_known_run_for_exact_installation')
            need(type(credentials)is tuple and len(credentials)==3 and credentials[0]==owner['pid']
                 and credentials[1]==self.uid and all(owner[key]==self.namespace[key]
                     for key in ('pid_namespace','time_namespace')),'actual_peer_uid_pid_and_namespace')
            need(not any(previous['notice']['owner']==owner for previous in self.rows.values()),
                 'distinct_linux_incarnation')
            need(not self.ready(descriptor) and self.pid_for_fd(descriptor)==owner['pid']
                 and self.identify(owner['pid'])==owner and not self.ready(descriptor),
                 'same_live_peer_and_retained_kernel_reference')
            row['notice'] = value
            row['live_ns'] = self.now()
            self.rows[run] = row
        except BaseException as primary:
            self.failed = row['capture_invalid'] = True
            if row['fd'] is not None:
                try:
                    self._close(row,successful_exit=False)
                except BaseException as cleanup:
                    raise BaseExceptionGroup('c05.linux_owner.refused_descriptor_cleanup_unknown',
                                             [primary,cleanup]) from None
            raise

    def _close_received_fd(self,descriptor):
        try:
            self.close(descriptor)
        except BaseException as error:
            self.failed = self.cleanup_unknown = True
            if isinstance(error,OSError):
                raise _CloseUnknown('c05.linux_owner.received_descriptor_close_unknown') from error
            raise

    def _close(self,row,*,successful_exit):
        need(not row['close_attempted'] and row['fd'] is not None,'single_owned_pidfd_close')
        row['close_attempted'] = True
        try:
            self._close_received_fd(row['fd'])
        except BaseException:
            self.failed = row['capture_invalid'] = True
            raise
        row['fd'] = None
        if successful_exit:
            row['close_ns'] = self.now()

    def tick(self):
        """Current nonblocking poll only. The existing owner holds the clock."""
        for row in self.rows.values():
            if row['live_ns'] is not None and row['fd'] is not None and not row['close_attempted']:
                try:
                    if self.ready(row['fd']):
                        row['exit_ns'] = self.now()
                        self._close(row,successful_exit=True)
                except BaseException:
                    self.failed = row['capture_invalid'] = True
                    raise

    def retire_unproved(self):
        """Release only owned references after the enclosing diagnostics stop."""
        errors = []
        for row in self.rows.values():
            if row['fd'] is not None and not row['close_attempted']:
                self.failed = row['capture_invalid'] = True
                try:
                    self._close(row,successful_exit=False)
                except OSError as error:
                    errors.append(error)
        if errors:
            raise ExceptionGroup('c05.linux_owner.retire_unknown',errors)

    def observation(self):
        self.tick()
        return {'scope':'C05_LINUX_SAME_PEER_RETAINED_PIDFD_ONLY','invalid':self.failed,
            'rows':[{'notice':row['notice'],'pidfd_live_ns':row['live_ns'],'pidfd_exit_poll_ns':row['exit_ns'],
                     'pidfd_close_return_ns':row['close_ns'],'invalid':row['capture_invalid'],
                     'exit_code_from_pidfd':None,'signal_sent':False}
                    for _,row in sorted(self.rows.items())],
            'qualification_credit':0,'retry_authorized':False}
