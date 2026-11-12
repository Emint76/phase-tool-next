"""Kernel-only C05 component for Linux CI. No Native, Docker, WSL or Phase operation."""
import errno
import os
import select
import socket
import sys
import time
from uuid import uuid4

import pytest


pytestmark = pytest.mark.skipif(sys.platform!='linux',reason='Requires actual Linux pidfd and SCM_RIGHTS')


def _readable(handle,deadline):
    remaining = deadline-time.monotonic()
    assert remaining>0 and select.select([handle],[],[],remaining)[0],'bounded component observation'


def test_real_eight_self_pidfds_cross_seqpacket_and_close_on_natural_exit():
    from phase_tool.mutation.ntfs.c05_pidfd_owner import Owner,canon,linux_identity,offer,peer_notice

    assert hasattr(os,'pidfd_open') and hasattr(socket,'MSG_CMSG_CLOEXEC')
    # Random test-only abstract address. No filesystem endpoint or authority.
    address = b'\x00phase-c05-linux-component-'+uuid4().hex.encode()
    deadline = time.monotonic()+15
    observer = linux_identity(os.getpid())
    runs = tuple('linux-pidfd-component-'+str(i) for i in range(8))
    install = 'sha256:'+'9'*64
    owner = Owner(runs=runs,expected_uid=os.geteuid(),namespace=observer,installation_digest=install)
    pending,received = [],[]
    read_release,write_release = os.pipe2(os.O_CLOEXEC)
    listener = socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
    try:
        listener.bind(address)
        listener.listen(8)
        listener.setblocking(False)
        for slot,run in enumerate(runs):
            pid = os.fork()
            if pid==0:
                code = 50
                try:
                    listener.close()
                    os.close(write_release)
                    birth = linux_identity(os.getpid())
                    binding = dict(run_id=run,installation_digest=install,staged_request_sha256='sha256:'+'1'*64,
                                   invocation_sha256='sha256:'+'2'*64,channel_id=f'{slot:032x}',operation_nonce=f'{32+slot:032x}')
                    raw = canon(dict(schema='phase.c05.linux-core-birth/1',scope='PASSIVE_OBSERVATION_NO_CONTROL',
                                     binding=binding,owner=birth))
                    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC) as child:
                        child.setblocking(False)
                        child.connect(address)
                        offer(child,raw)
                    # A disposable kernel-test lifetime, separate from product.
                    _readable(read_release,deadline)
                    assert os.read(read_release,1)==b''
                    code = 0
                finally:
                    os.close(read_release)
                    os._exit(code)
            pending.append(pid)
            _readable(listener,deadline)
            connection,_ = listener.accept()
            with connection:
                connection.setblocking(False)
                _readable(connection,deadline)
                peer_notice(connection,owner)
            row = owner.rows[run]
            assert row['notice']['owner']['pid']==pid and row['live_ns'] is not None
            assert not os.get_inheritable(row['fd'])
            received.append(row['fd'])
        assert len(set(received))==8 and len(owner.observation()['rows'])==8
        assert all(row['exit_ns'] is None for row in owner.rows.values())
        os.close(write_release)
        write_release = None
        while pending:
            assert time.monotonic()<deadline,'all owned test processes must exit'
            owner.tick()
            for pid in tuple(pending):
                done,status = os.waitpid(pid,os.WNOHANG)
                if done==pid:
                    pending.remove(pid)
                    assert os.waitstatus_to_exitcode(status)==0
            if pending:
                time.sleep(.001)
        proof = owner.observation()
        assert proof['invalid'] is False and proof['qualification_credit']==0
        assert all(row['pidfd_live_ns']<=row['pidfd_exit_poll_ns']<=row['pidfd_close_return_ns']
                   and row['exit_code_from_pidfd'] is None for row in proof['rows'])
        for descriptor in received:
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno==errno.EBADF
    finally:
        if write_release is not None:
            os.close(write_release)
        os.close(read_release)
        listener.close()
        try:
            owner.retire_unproved()
        finally:
            # Each direct child has its own original finite read deadline.
            # No product signal path or guessed PID cleanup exists here.
            for pid in pending:
                os.waitpid(pid,0)


from array import array
import struct
from types import SimpleNamespace
from unittest.mock import patch


_MODEL_DIGEST = 'sha256:'+'3'*64
_MODEL_NAMESPACE = {'pid_namespace':[3,39],'time_namespace':[3,40]}


def _modeled_owner(close, *, ready=lambda descriptor:False):
    from phase_tool.mutation.ntfs import c05_pidfd_owner as pids
    from phase_tool.mutation.ntfs.c05_pidfd_endpoint import RUNS

    sender = dict(_MODEL_NAMESPACE,pid=301,start_ticks=801)
    owner = pids.Owner(runs=RUNS,expected_uid=10001,namespace=_MODEL_NAMESPACE,
        installation_digest=_MODEL_DIGEST,identify=lambda pid:sender,pid_for_fd=lambda descriptor:301,
        ready=ready,close=close,now=lambda:1000)
    binding = dict(run_id=RUNS[0],installation_digest=_MODEL_DIGEST,staged_request_sha256=_MODEL_DIGEST,
                   invocation_sha256=_MODEL_DIGEST,channel_id='4'*32,operation_nonce='5'*32)
    raw = pids.canon(dict(schema='phase.c05.linux-core-birth/1',scope='PASSIVE_OBSERVATION_NO_CONTROL',
                          binding=binding,owner=sender))
    return owner,raw


def _modeled_terminal(owner,step):
    from phase_tool.mutation.ntfs import c05_pidfd_endpoint as endpoint

    identity = dict(_MODEL_NAMESPACE,pid=99,start_ticks=699)
    details = {'birth':identity}
    actor = endpoint.Collector({'manifest_digest':_MODEL_DIGEST},identity,details,owner_type=lambda **_:owner)
    actor.start = lambda:None
    actor.step = lambda pipe:step(actor)
    emitted = []
    pipe = SimpleNamespace(record=lambda value,cap:emitted.append(value))
    with patch.object(endpoint,'linux_identity',return_value=identity), patch.object(endpoint,'process_details',return_value=details):
        result = endpoint._run_collector(actor,pipe,identity,details)
    assert result==50 and len(emitted)==2 and actor.retired
    terminal = emitted[-1]
    assert terminal['complete_diagnostic'] is False and terminal['qualification_credit']==0
    assert terminal['retry_authorized'] is False and terminal['observation']['invalid'] is True
    return terminal


def test_refused_new_pidfd_retains_primary_and_unknown_close():
    from phase_tool.mutation.ntfs.c05_pidfd_owner import _CloseUnknown

    attempts = []
    def close(descriptor):
        attempts.append(descriptor)
        if descriptor==42:
            raise OSError(errno.EIO,'synthetic close uncertainty')
    owner,raw = _modeled_owner(close)
    owner.adopt(raw,(301,10001,10001),41)
    captured = []
    def step(actor):
        try:
            actor.owner.adopt(raw,(301,10001,10001),42)
        except ExceptionGroup as error:
            captured.extend(error.exceptions)
            raise
    terminal = _modeled_terminal(owner,step)
    assert attempts==[42,41]
    assert len(captured)==2 and type(captured[0]) is ValueError and isinstance(captured[1],_CloseUnknown)
    assert terminal['primary_failure']=='peer_capture' and terminal['cleanup_unknown'] is True
    assert len(terminal['observation']['rows'])==1
    assert terminal['observation']['rows'][0]['pidfd_close_return_ns'] is None


def test_refused_new_pidfd_with_known_close_retains_only_primary():
    attempts = []
    owner,raw = _modeled_owner(attempts.append)
    terminal = _modeled_terminal(owner,lambda actor:actor.owner.adopt(raw,(301,10002,10001),42))
    assert attempts==[42] and terminal['observation']['rows']==[]
    assert terminal['primary_failure']=='peer_capture' and terminal['cleanup_unknown'] is False


def test_malformed_ancillary_keeps_primary_and_attempts_each_received_close():
    from phase_tool.mutation.ntfs import c05_pidfd_owner as pids

    attempts = []
    def close(descriptor):
        attempts.append(descriptor)
        if descriptor==42:
            raise OSError(errno.EIO,'synthetic ancillary close uncertainty')
    owner,_ = _modeled_owner(close)
    class Peer:
        family = 1
        def getsockopt(self,level,kind,*args):
            return 5 if kind==3 else struct.pack('3i',301,10001,10001)
        def getblocking(self):
            return False
        def recvmsg(self,cap,control,flags):
            assert (cap,control,flags)==(2049,24,1024)
            return b'invalid',[(1,2,array('i',[42,43]).tobytes())],0,None
    socket_model = SimpleNamespace(socket=Peer,AF_UNIX=1,SOCK_SEQPACKET=5,SOL_SOCKET=1,SO_TYPE=3,
            SO_PEERCRED=4,SCM_RIGHTS=2,CMSG_SPACE=lambda length:24,MSG_CMSG_CLOEXEC=1024,MSG_TRUNC=4,MSG_CTRUNC=8)
    captured = []
    def step(actor):
        try:
            pids.peer_notice(Peer(),actor.owner)
        except ExceptionGroup as error:
            captured.extend(error.exceptions)
            raise
    with patch.object(pids,'socket',socket_model):
        terminal = _modeled_terminal(owner,step)
    assert attempts==[42,43] and terminal['observation']['rows']==[]
    assert len(captured)==2 and type(captured[0]) is ValueError and isinstance(captured[1],pids._CloseUnknown)
    assert terminal['primary_failure']=='peer_capture' and terminal['cleanup_unknown'] is True


def test_natural_pidfd_close_failure_is_not_a_new_capture_failure():
    attempts = []
    exited = set()
    def close(descriptor):
        attempts.append(descriptor)
        raise OSError(errno.EIO,'synthetic natural-close uncertainty')
    owner,raw = _modeled_owner(close,ready=exited.__contains__)
    owner.adopt(raw,(301,10001,10001),42)
    exited.add(42)
    terminal = _modeled_terminal(owner,lambda actor:actor.owner.tick())
    assert attempts==[42] and terminal['primary_failure'] is None and terminal['cleanup_unknown'] is True
    row, = terminal['observation']['rows']
    assert row['pidfd_exit_poll_ns'] is not None and row['pidfd_close_return_ns'] is None and row['invalid'] is True


def test_already_owned_peer_socket_failure_preserves_capture_and_cleanup_separately():
    from phase_tool.mutation.ntfs import c05_pidfd_endpoint as endpoint

    attempts = []
    def close():
        attempts.append('peer')
        raise OSError(errno.EIO,'synthetic socket close uncertainty')
    peer = SimpleNamespace(close=close)
    for primary in (None,ValueError('synthetic capture refusal')):
        owner,_ = _modeled_owner(lambda fd:None)
        def step(actor):
            actor.peers[55] = peer
            actor.receive(55)
        with patch.object(endpoint,'peer_notice',side_effect=primary):
            terminal = _modeled_terminal(owner,step)
        expected = 'peer_capture' if primary else None
        assert terminal['primary_failure']==expected and terminal['cleanup_unknown'] is True
    assert attempts==['peer','peer']


def test_refused_new_peer_socket_close_is_sticky_before_insert():
    from phase_tool.mutation.ntfs import c05_pidfd_endpoint as endpoint

    attempts = []
    def close():
        attempts.append('peer')
        raise OSError(errno.EIO,'synthetic socket close uncertainty')
    peer = SimpleNamespace(close=close,setblocking=lambda value:None)
    owner,_ = _modeled_owner(lambda fd:None)
    def step(actor):
        actor.listener = SimpleNamespace(accept=lambda:(peer,None),close=lambda:None)
        actor.accept()
    with patch.object(endpoint,'credentials',return_value=(301,10002,10001)), patch.object(endpoint,'process_details',return_value={}):
        terminal = _modeled_terminal(owner,step)
    assert attempts==['peer'] and terminal['observation']['rows']==[]
    assert terminal['primary_failure']=='peer_capture' and terminal['cleanup_unknown'] is True
