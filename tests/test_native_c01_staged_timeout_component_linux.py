"""Real Linux/ext4 checked-flock timeout component with synthetic token setup.

Future controlled nonroot Linux test only. This does not start Phase, Docker or
any native publisher and does not qualify the fixed launcher or Windows case.
"""
import errno
import multiprocessing
import os
import sys
import time

import pytest

from phase_tool.canonical import digest_bytes, parse_json_bytes
from phase_tool.core import _OperationalFileLock
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import common_flock_test as observer

from .test_native_common_flock_linux_component import _fixture_token, _root


pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'),reason='real Linux/ext4 checked flock')


def hold_exact_lock(path, connection, absolute):
    with connection, _OperationalFileLock(path,_checked_release=True) as lock:
        fd=lock.fileno()
        state=os.fstat(fd)
        connection.send(('held',os.getpid(),state.st_dev,state.st_ino,time.monotonic_ns()))
        left=absolute-time.monotonic()
        assert left>0 and connection.poll(left) and connection.recv()=='release'
        after=os.fstat(fd)
        assert (after.st_dev,after.st_ino)==(state.st_dev,state.st_ino)


class LocalRecordingIPC:
    def __init__(self):
        self.events=[]
        self.closed=False

    def send(self,raw):
        self.events.append(parse_json_bytes(raw))

    def close(self):
        assert not self.closed
        self.closed=True


@pytest.mark.parametrize('fault_at_observation',[False,True])
def test_real_five_second_checked_lock_timeout_does_not_replace_primary(tmp_path,monkeypatch,fault_at_observation):
    root=_root(tmp_path)
    folder=root/'.phase/locks'
    folder.mkdir(parents=True,mode=0o700)
    (root/'.phase').chmod(0o700)
    path=folder/(digest_bytes(b'phase.native-original-intents.v1')[7:]+'.lock')
    deadline=time.monotonic()+15.0
    context=multiprocessing.get_context('fork')
    client,peer=context.Pipe()
    holder=context.Process(target=hold_exact_lock,args=(path,peer,deadline))
    ipc=LocalRecordingIPC()
    token,binding=_fixture_token(root,'contender',ipc,deadline)
    token._run=observer._TIMEOUT_RUN
    actual_timeout=observer._CommonCoreFlockTest.observed_acquire_timeout
    if fault_at_observation:
        def observe_then_fault(self,descriptor,original_deadline):
            actual_timeout(self,descriptor,original_deadline)
            raise OSError('modeled timeout observer fault after recording')
        monkeypatch.setattr(observer._CommonCoreFlockTest,'observed_acquire_timeout',observe_then_fault)
    holder.start()
    peer.close()
    try:
        left=deadline-time.monotonic()
        assert left>0 and client.poll(left)
        stage,pid,device,inode,held=client.recv()
        assert stage=='held' and pid==holder.pid and pid!=os.getpid()
        now=time.monotonic()
        with observer._common_flock_qualification_scope(token):
            observer._take_common_flock_test(binding,token._run)
            with pytest.raises(PhaseError) as error:
                with _OperationalFileLock(path,_checked_release=True,_common_flock_test=token):
                    pytest.fail('contender acquired while distinct holder retained the same lock')
        assert error.value.code=='lock.acquire_timeout'
        notes=getattr(error.value,'__notes__',[])
        assert ('C01 timeout telemetry unavailable' in notes) is fault_at_observation
        assert time.monotonic()-now>=5.0
        stages=[row['stage'] for row in ipc.events]
        assert stages[0]=='bound' and stages[-4:]==['acquire_timeout','unlock_return','close_return','scope_finish']
        assert set(stages[1:-4])=={'acquire_return'}
        assert any(row['facts']['contended'] for row in ipc.events[1:-4])
        bound=ipc.events[0]['facts'];timeout=ipc.events[-4]
        assert list(bound['identity'])==[device,inode] and timeout['observed_ns']>=bound['acquire_deadline_ns']>held
        assert timeout['facts']=={'descriptor':bound['descriptor'],'reason_code':'lock.acquire_timeout',
                                  'acquire_deadline_ns':bound['acquire_deadline_ns']}
        assert ipc.closed and not token._guard and token._closed and holder.is_alive()
        with pytest.raises(OSError) as closed:
            os.fstat(bound['descriptor'])
        assert closed.value.errno==errno.EBADF
    finally:
        try:
            client.send('release')
        finally:
            client.close()
        holder.join(max(0,deadline-time.monotonic()))
        assert holder.exitcode==0
        holder.close()
