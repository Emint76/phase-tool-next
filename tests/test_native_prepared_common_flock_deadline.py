"""The prepared common lock checks the original clock before another syscall."""
import errno
import os
from pathlib import PurePosixPath
import sys
import threading
from types import SimpleNamespace

import pytest

from phase_tool import core, evidence
from phase_tool.canonical import digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import common_flock_test


@pytest.mark.parametrize('started,oversleep', [(101.,5.1),(114.,1.1)], ids=('original-acquire-five','case-fifteen'))
def test_prepared_checked_lock_refuses_before_overslept_flock_retry(monkeypatch,started,oversleep):
    now=started
    attempts,unlocks,closes=[],[],[]

    def sleep(requested):
        nonlocal now
        assert 0<requested<=core._OPERATIONAL_LOCK_RETRY_SECONDS
        now+=oversleep

    def flock(descriptor,mode):
        assert descriptor==9
        if mode==8:
            unlocks.append(descriptor)
            return
        assert mode==6
        attempts.append(now)
        if len(attempts)==1:
            raise OSError(errno.EAGAIN,'injected actual flock-boundary contention')

    clock=SimpleNamespace(monotonic=lambda:now,monotonic_ns=lambda:int(now*1e9),sleep=sleep)
    monkeypatch.setattr(core,'time',clock)
    monkeypatch.setattr(common_flock_test,'time',clock)
    monkeypatch.setattr(common_flock_test,'Path',PurePosixPath)
    monkeypatch.setattr(core,'os',SimpleNamespace(name='posix',O_NOFOLLOW=1,O_CLOEXEC=2,O_DIRECTORY=4,
        fstat=lambda descriptor:SimpleNamespace(st_dev=5,st_ino=7),close=closes.append))
    monkeypatch.setitem(sys.modules,'fcntl',SimpleNamespace(LOCK_EX=2,LOCK_NB=4,LOCK_UN=8,flock=flock))
    monkeypatch.setattr(core._OperationalFileLock,'_check_checked_namespace',lambda self:None)
    monkeypatch.setattr(evidence,'_open_checked_operational_lock',lambda path:(9,(5,6),(5,7)))
    cls=common_flock_test._CommonCoreFlockTest
    # The separate fixed C01 fixture supplies these exact prepared bytes at use.
    # Model its selected state without opening a socket or launching Phase.
    monkeypatch.setattr(cls,'_prepared_candidate',b'fixed-candidate',raising=False)
    token=object.__new__(cls)
    token._owner=(os.getpid(),threading.get_ident())
    token._selected=token._taken=True
    token._bound=token._acquired=token._finished=False
    token._launch=SimpleNamespace(manifest={'evidence_root':'/qualification/evidence'})
    token._deadline=115.
    token._mode='holder'
    token._run='synthetic-prepared-holder'
    token._campaign='synthetic'
    token._nonce='a'*32
    token._manifest_digest='sha256:'+'b'*64
    token._sequence=0
    token.events=[]
    token.errors=[]
    token._ipc=SimpleNamespace(send=lambda raw:None,receive=lambda deadline:common_flock_test._remaining(deadline))
    name=digest_bytes(b'phase.native-original-intents.v1')[7:]+'.lock'
    lock=core._OperationalFileLock(PurePosixPath('/qualification/evidence/.phase/locks')/name,
                                   _checked_release=True,_common_flock_test=token)
    with pytest.raises(PhaseError,match='ntfs.c01_flock_test_deadline'):
        lock._enter_checked()
    assert attempts==[started]
    assert unlocks==closes==[9]
    acquired=[event['facts']['succeeded'] for event in token.events if event['stage']=='acquire_return']
    assert acquired==[False]
