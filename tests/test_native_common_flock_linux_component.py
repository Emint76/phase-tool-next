"""Real Linux/ext4 flock/SEQPACKET/pipe components, NOT Native qualification.

The synthetic opaque token is populated as a test fixture. Its constructor and
installed native admission are deliberately outside this component's claims.
One existing Core lock/observer/IO implementation is exercised; no alternate
Core, evidence journal, worker, receipt or target-operation implementation.
"""
from __future__ import annotations
import errno,json,os,select,socket,stat,struct,subprocess,sys,threading,time
from pathlib import Path
from types import SimpleNamespace
import pytest
from phase_tool.canonical import canonical_bytes,parse_json_bytes,digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.core import _OperationalFileLock
from phase_tool.installation import _NativeFileCreateReadBinding,_linux_filesystem_type
from phase_tool.mutation.ntfs import common_flock_test as m

pytestmark=pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Real POSIX flock/SEQPACKET component requires Linux; not Windows/NTFS evidence')
_PENDING_COMPONENT_CHILDREN=[]

def _root(tmp_path):
    root=tmp_path/'owned-component';root.mkdir(mode=0o700)
    assert _linux_filesystem_type(root)=='ext4'
    assert os.geteuid()>0 and os.getegid()>0
    return root

def _server(root):
    path=root/'control.sock';server=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    server.set_inheritable(False);server.bind(str(path));path.chmod(0o600);server.listen(4);server.setblocking(False)
    info=path.lstat()
    return server,path,(info.st_dev,info.st_ino)

def _wait(sock,deadline,write=False):
    remaining=deadline-time.monotonic();assert remaining>0,'component deadline, no retry'
    r,w,_=select.select([]if write else[sock],[sock]if write else[],[],remaining)
    assert w if write else r,'component IPC observation incomplete'

def _accept(server,deadline,pid):
    _wait(server,deadline);connection,_=server.accept();connection.setblocking(False);connection.set_inheritable(False)
    actual_pid,uid,_gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
    assert actual_pid==pid and uid==os.geteuid()
    return connection

def _event(connection,deadline):
    _wait(connection,deadline);raw,_,flags,_=connection.recvmsg(4096)
    assert raw and not flags&socket.MSG_TRUNC
    value=parse_json_bytes(raw,maximum_bytes=4096)
    assert canonical_bytes(value)==raw and value['qualification_count']==0
    assert value['scope']=='RAW_C01_TEST_OBSERVATION_NOT_PHASE_PROOF'
    return value

def _child(role,root,socket_path,identity,deadline,parent_pid):
    # Literal test-only role, same accepted test sources/sys.path. No native launch.
    program='import json,runpy,sys;sys.path[:0]=json.loads(sys.argv[1]);sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")'
    args=[sys.executable,'-I','-S','-B','-u','-c',program,json.dumps(sys.path),str(Path(__file__).absolute()),
        role,str(root),str(socket_path),json.dumps(identity),deadline.hex(),str(parent_pid)]
    process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    _PENDING_COMPONENT_CHILDREN.append(process)
    return process

def _collect(process,deadline):
    # Children have their own inherited fixed finite deadline. No kill/retry or
    # native-worker inference; on unknown preserve the actual retained process.
    remaining=deadline-time.monotonic();assert remaining>0
    out,err=process.communicate(timeout=remaining)
    assert process.returncode==0,(process.returncode,out,err)
    assert err==b''
    result=parse_json_bytes(out)
    assert result['component_only']is True and result['qualification_count']==0
    for stream in (process.stdout,process.stderr):
        if not stream.closed:stream.close()
    return result

def _fixture_token(root,mode,ipc,deadline):
    # Exact opaque class as controlled unit fixture, not a constructor/admission bypass.
    token=object.__new__(m._CommonCoreFlockTest)
    info=root.lstat();identity={'stable_id':'linux-component-only','device':info.st_dev,'inode':info.st_ino}
    values={'_initialized':True,'_owner':(os.getpid(),threading.get_ident()),'_launch':SimpleNamespace(manifest={'evidence_root':str(root)}),
        '_selected':False,'_taken':False,'_bound':False,'_fd':None,'_acquired':False,'_history':False,
        '_unlock':False,'_closed':False,'_guard':False,'_finished':False,'events':[],'errors':[],'_sequence':0,
        '_initial':deadline,'_deadline':deadline,'_mode':mode,'_case':0,'_campaign':'linux-component-only',
        '_fixture_digest':'sha256:'+'a'*64,'_run':'component-'+mode,'_manifest_digest':'sha256:'+'b'*64,
        '_nonce':'c'*32,'_evidence_identity':canonical_bytes(identity),'_ipc':ipc}
    for key,value in values.items():setattr(token,key,value)
    binding=_NativeFileCreateReadBinding(canonical_bytes({'evidence_identity':identity}),token._manifest_digest,None)
    return token,binding

def test_real_existing_common_flock_handoff_observed_by_actual_seqpacket(tmp_path):
    root=_root(tmp_path);locks=root/'.phase/locks';locks.mkdir(parents=True,mode=0o700)
    # Make every created ancestor owned/private; no ACL/policy changes.
    (root/'.phase').chmod(0o700)
    server,path,identity=_server(root);deadline=time.monotonic()+15.
    connections=[];children=[];events=[]
    try:
        holder=_child('holder',root,path,identity,deadline,os.getpid());children.append(holder)
        hc=_accept(server,deadline,holder.pid);connections.append(hc)
        while True:
            row=_event(hc,deadline);events.append(row)
            if row['stage']=='acquired':break
        contender=_child('contender',root,path,identity,deadline,os.getpid());children.append(contender)
        cc=_accept(server,deadline,contender.pid);connections.append(cc)
        while True:
            row=_event(cc,deadline);events.append(row)
            if row['stage']=='acquire_return'and row['facts']['contended']is True:break
        release_ns=time.monotonic_ns()
        control={'protocol':m._PROTOCOL,'action':'RELEASE','campaign_id':'linux-component-only',
            'run_id':'component-holder','operation_nonce':'c'*32}
        _wait(hc,deadline,True);wire=canonical_bytes(control);assert hc.send(wire)==len(wire)
        finished=set()
        while len(finished)<2:
            remaining=deadline-time.monotonic();assert remaining>0
            ready,_,_=select.select([c for c in connections if c.fileno()not in finished],[],[],remaining)
            assert ready
            for c in ready:
                row=_event(c,deadline);events.append(row)
                if row['stage']=='scope_finish':finished.add(c.fileno())
        results=[_collect(p,deadline)for p in children]
        for result in results:
            snapshot=result['snapshot']
            assert snapshot['socket_close_observed']and snapshot['guard_return_observed']
            assert snapshot['lock_unlock_observed']and snapshot['lock_close_observed']and snapshot['errors']==[]
            assert result['closed_descriptor_errno']==errno.EBADF
        contender_acquired=next(r for r in events if r['run_id']=='component-contender'and r['stage']=='acquired')
        assert contender_acquired['observed_ns']>=release_ns
        assert all(r['qualification_count']==0 for r in events)
        # The existing code, not an observer receipt, establishes all fd checks.
        assert len({r['facts']['identity'][1]for r in events if r['stage']=='bound'})==1
    finally:
        for c in connections:c.close()
        server.close()

def test_real_seqpacket_exact_peer_and_named_identity_refusals_close_owned_socket(tmp_path):
    root=_root(tmp_path);server,path,identity=_server(root);deadline=time.monotonic()+5.
    try:
        for wrong_identity,wrong_pid in (([identity[0],identity[1]+1],os.getpid()),(identity,os.getpid()+1)):
            before=set(os.listdir('/proc/self/fd'))
            with pytest.raises(PhaseError):m._PosixFlockIPC(path,wrong_identity,wrong_pid,os.geteuid(),deadline)
            assert set(os.listdir('/proc/self/fd'))==before
    finally:server.close()

def test_real_seqpacket_same_deadline_bounded_send_and_once_close(tmp_path):
    root=_root(tmp_path);server,path,identity=_server(root);deadline=time.monotonic()+5.
    ipc=m._PosixFlockIPC(path,identity,os.getpid(),os.geteuid(),deadline);connection=None
    try:
        connection=_accept(server,deadline,os.getpid())
        with pytest.raises(PhaseError):ipc.send(b'x'*4097)
        with pytest.raises(PhaseError):ipc.receive(time.monotonic()-1.)
        wire=canonical_bytes({'bounded':'real-component'});ipc.send(wire)
        _wait(connection,deadline);assert connection.recv(4096)==wire
        ipc.close()
        with pytest.raises(PhaseError):ipc.close()
    finally:
        if not ipc.close_attempted:ipc.close()
        if connection is not None:connection.close()
        server.close()

def test_real_owned_stderr_pipe_complete_bytes_and_mode_restored(tmp_path):
    root=_root(tmp_path);deadline=time.monotonic()+15.
    process=_child('stderr',root,root/'unused',[],deadline,os.getpid())
    out,err=process.communicate(timeout=deadline-time.monotonic())
    assert process.returncode==0 and err==b'R'*(64*1024)
    status=parse_json_bytes(out);assert status['mode_before']==status['mode_after']
    assert status['component_only']is True and status['qualification_count']==0

def _main():
    role,root,path,identity,deadline,parent=sys.argv[1:]
    root=Path(root);path=Path(path);identity=json.loads(identity);deadline=float.fromhex(deadline)
    assert role in {'holder','contender','stderr'}and 0<deadline-time.monotonic()<=15
    assert os.geteuid()>0 and os.getegid()>0 and _linux_filesystem_type(root)=='ext4'
    if role=='stderr':
        from phase_tool.evidence import _write_owned_stderr_bytes
        before=os.get_blocking(2);_write_owned_stderr_bytes(b'R'*(64*1024),deadline)
        result={'mode_before':before,'mode_after':os.get_blocking(2),'component_only':True,'qualification_count':0}
    else:
        ipc=m._PosixFlockIPC(path,identity,int(parent),os.geteuid(),deadline)
        token,binding=_fixture_token(root,role,ipc,deadline)
        lockpath=root/'.phase/locks'/(digest_bytes(b'phase.native-original-intents.v1')[7:]+'.lock')
        with m._common_flock_qualification_scope(token):
            m._take_common_flock_test(binding,token._run)
            with _OperationalFileLock(lockpath,_checked_release=True,_common_flock_test=token)as lock:
                actual_descriptor=lock.fileno();token.before_history(actual_descriptor)
            token.guard_return()
        try:os.fstat(actual_descriptor)
        except OSError as error:closed=error.errno
        else:raise AssertionError('actual existing lock descriptor still open')
        result={'snapshot':token.snapshot(),'closed_descriptor_errno':closed,'component_only':True,'qualification_count':0}
    raw=canonical_bytes(result);sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0

if __name__=='__main__':raise SystemExit(_main())
