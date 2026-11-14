"""Real default POSIX IO regressions, fresh roots; never native qualification.

Requires the final candidate Evidence owner installed/imported by Linux runner.
No Phase lifecycle, worker, Docker, NTFS or receipt is created by these tests.
"""
import errno,os,time
from pathlib import Path
import pytest
from phase_tool.errors import PhaseError
from phase_tool.evidence import _OwnedInputStageSink
pytestmark=pytest.mark.skipif(os.name!='posix',reason='actual POSIX descriptor/symlink IO required')

def make(tmp_path):
    ancestor=tmp_path/'owned-ancestor';ancestor.mkdir(mode=0o700)
    root=ancestor/'preparation';root.mkdir(mode=0o700);info=root.stat()
    sink=_OwnedInputStageSink(root,dict(device=info.st_dev,inode=info.st_ino),
        'phase-native-input-'+'1'*32,time.monotonic_ns()+10_000_000_000)
    sink.begin_member(0,'payload',1)
    return sink,ancestor,root

def assert_closed(sink,except_fd=None):
    for row in sink.opened:
        if row['fd']==except_fd:continue
        with pytest.raises(OSError)as failed:os.fstat(row['fd'])
        assert failed.value.errno==errno.EBADF
        assert row['closed']and row['close_attempted']

def test_default_io_renamed_stage_closes_same_owned_fds(tmp_path):
    sink,ancestor,root=make(tmp_path)
    moved=root/'renamed-owned-stage';os.rename(root/sink.name,moved)
    with pytest.raises((PhaseError,FileNotFoundError))as failed:sink.write(b'x')
    with pytest.raises(type(failed.value))as final:sink.abort(failed.value)
    assert final.value is failed.value;assert_closed(sink)
    assert(moved/'payload'/'payload').read_bytes()==b''

def test_default_io_parent_symlink_to_same_original_root_is_rejected(tmp_path):
    sink,ancestor,root=make(tmp_path)
    moved=tmp_path/'same-owned-ancestor';os.rename(ancestor,moved)
    os.symlink(moved,ancestor,target_is_directory=True)
    with pytest.raises(PhaseError,match='preparation_ancestor_changed')as failed:sink.write(b'x')
    with pytest.raises(PhaseError)as final:sink.abort(failed.value)
    assert final.value is failed.value;assert_closed(sink)
    assert(moved/'preparation'/sink.name/'payload'/'payload').read_bytes()==b''

def test_default_io_reused_foreign_descriptor_is_not_closed(tmp_path):
    sink,ancestor,root=make(tmp_path);chosen=sink.current['fd']
    foreign=tmp_path/'foreign-owned-by-test';foreign.write_bytes(b'untouched')
    other=os.open(foreign,os.O_RDONLY|os.O_CLOEXEC)
    try:
        os.dup2(other,chosen,inheritable=False)
        primary=PhaseError('MODEL.original_namespace_failure')
        with pytest.raises(BaseExceptionGroup)as final:sink.abort(primary)
        assert final.value.exceptions[0]is primary;assert_closed(sink,except_fd=chosen)
        assert os.fstat(chosen).st_ino==foreign.stat().st_ino
        assert not sink._record(chosen)['close_attempted']
    finally:
        os.close(other)
        os.close(chosen) # Exact test-owned reused descriptor; never sink cleanup.

def test_default_io_primary_and_close_error_preserved_once(tmp_path,monkeypatch):
    sink,ancestor,root=make(tmp_path);chosen=sink.current['fd'];calls=[];real=sink.io.close
    moved=root/'renamed-owned-stage';os.rename(root/sink.name,moved)
    with pytest.raises((PhaseError,FileNotFoundError))as primary:sink.write(b'x')
    def close(fd):
        calls.append(fd)
        if fd==chosen:raise OSError(errno.EIO,'MODEL.injected_close_failure')
        return real(fd)
    monkeypatch.setattr(sink.io,'close',close)
    try:
        with pytest.raises(BaseExceptionGroup)as final:sink.abort(primary.value)
        assert final.value.exceptions[0]is primary.value
        assert calls.count(chosen)==1;assert_closed(sink,except_fd=chosen)
        assert os.fstat(chosen).st_ino==sink._record(chosen)['identity'][1]
    finally:os.close(chosen) # Explicit test-owner post-failure closure, no PASS credit to sink.
