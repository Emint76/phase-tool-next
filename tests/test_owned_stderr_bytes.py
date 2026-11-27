"""Exact generic IO owner models and unchanged real architecture inventory."""
import ast,errno,importlib.util,json,os,stat,sys,unittest
from pathlib import Path,PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch
from phase_tool.errors import PhaseError
from phase_tool import evidence
import phase_tool
PACKAGE=Path(phase_tool.__file__).parent
SOURCE=PACKAGE/'evidence/__init__.py'
tree=ast.parse(SOURCE.read_bytes());node=next(row for row in tree.body if isinstance(row,ast.FunctionDef) and row.name=='_write_owned_stderr_bytes')

class Clock:
    def __init__(self):self.now=1000.
    def monotonic(self):return self.now

class ModelOS:
    def __init__(self,clock):
        self.clock=clock;self.mode=True;self.mode_calls=[];self.writes=[];self.poll_timeouts=[];self.kind=stat.S_IFIFO
        self.fd_calls=0;self.foreign_on=None;self.write_error=None;self.zero=False;self.advance_write=0.;self.restore_error=False;self.poll_flags=4
    def fstat(self,fd):
        assert fd==2;self.fd_calls+=1
        return SimpleNamespace(st_mode=self.kind|0o600,st_dev=7,st_ino=999 if self.foreign_on is not None and self.fd_calls>=self.foreign_on else 2)
    def get_blocking(self,fd):assert fd==2;return self.mode
    def set_blocking(self,fd,value):
        assert fd==2;self.mode_calls.append(value)
        if value is True and self.restore_error:raise OSError(errno.EIO,'MODELED RESTORE FAILURE')
        self.mode=value
    def write(self,fd,raw):
        assert fd==2;self.writes.append(raw);self.clock.now+=self.advance_write
        if self.write_error is not None:raise self.write_error
        return 0 if self.zero else len(raw)

def call(io,clock,raw=b'RAW',deadline=1005.):
    scope={'PhaseError':PhaseError,'os':io,'stat':stat}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'actual_candidate_evidence_stderr_owner','exec'),scope)
    class Poll:
        def register(self,fd,flag):assert (fd,flag)==(2,4)
        def poll(self,timeout):io.poll_timeouts.append(timeout);return [(2,io.poll_flags)] if io.poll_flags else []
    select=SimpleNamespace(poll=Poll,POLLOUT=4,POLLERR=8,POLLNVAL=32)
    with patch.dict(sys.modules,{'select':select,'time':clock}):return scope['_write_owned_stderr_bytes'](raw,deadline)

class GenericStderrOwnerModels(unittest.TestCase):
    def test_bounded_complete_raw_chunks_and_original_mode_restored(self):
        clock=Clock();io=ModelOS(clock);raw=b'X'*10000
        call(io,clock,raw);self.assertEqual(b''.join(io.writes),raw)
        self.assertEqual([len(row) for row in io.writes],[4096,4096,1808]);self.assertEqual(io.mode_calls,[False,True]);self.assertTrue(io.mode)

    def test_expired_or_extended_deadline_and_nonbytes_rejected_before_mode_change(self):
        for raw,deadline in ((b'raw',999.),(b'raw',1031.),('text',1005.),(b'',1005.),(b'x'*(128*1024+1),1005.)):
            clock=Clock();io=ModelOS(clock)
            with self.assertRaises(PhaseError):call(io,clock,raw,deadline)
            self.assertEqual(io.mode_calls,[]);self.assertEqual(io.writes,[])

    def test_fifo_required_not_arbitrary_file_writer(self):
        clock=Clock();io=ModelOS(clock);io.kind=stat.S_IFREG
        with self.assertRaisesRegex(PhaseError,'pipe_required'):call(io,clock)
        self.assertEqual(io.mode_calls,[]);self.assertEqual(io.writes,[])

    def test_poll_error_and_no_progress_restore_mode_without_retrying_deadline(self):
        for flags,zero in ((0,False),(8,False),(4,True)):
            clock=Clock();io=ModelOS(clock);io.poll_flags=flags;io.zero=zero
            with self.assertRaises(PhaseError):call(io,clock)
            self.assertEqual(io.mode_calls,[False,True]);self.assertLessEqual(len(io.writes),1)

    def test_real_write_error_preserved_with_restoration_failure_grouped(self):
        clock=Clock();io=ModelOS(clock);original=OSError(errno.EPIPE,'MODELED ORIGINAL WRITE FAILURE');io.write_error=original;io.restore_error=True
        with self.assertRaises(BaseExceptionGroup) as caught:call(io,clock)
        self.assertIs(caught.exception.exceptions[0],original);self.assertEqual(len(caught.exception.exceptions),2)
        self.assertEqual(io.mode_calls,[False,True]);self.assertEqual(len(io.writes),1)

    def test_foreign_descriptor_never_restored_or_written(self):
        clock=Clock();io=ModelOS(clock);io.foreign_on=2
        with self.assertRaises(BaseExceptionGroup):call(io,clock)
        self.assertEqual(io.writes,[]);self.assertEqual(io.mode_calls,[False])

    def test_same_absolute_deadline_exceeded_after_write_still_restores_mode(self):
        clock=Clock();io=ModelOS(clock);io.advance_write=5.1
        with self.assertRaisesRegex(PhaseError,'raw_stderr_deadline'):call(io,clock)
        self.assertEqual(len(io.writes),1);self.assertEqual(io.mode_calls,[False,True]);self.assertEqual(io.poll_timeouts,[5000])

    def test_native_observer_only_delegates_bytes_and_existing_deadline(self):
        from phase_tool.mutation.ntfs import common_flock_test as m
        t=object.__new__(m._CommonCoreFlockTest);t._run='source-model';t._deadline=1005.;t.events=[];t.errors=[];t._guard=False;t._unlock=False;t._closed=False
        captured=[]
        with patch.object(evidence,'_write_owned_stderr_bytes',side_effect=lambda raw,deadline:captured.append((raw,deadline)),create=True):t.write_snapshot()
        self.assertEqual(captured[0][1],1005.);value=json.loads(captured[0][0]);self.assertEqual(value['qualification_count'],0)
        self.assertEqual(value['telemetry_phase'],'PRE_RETURN_NON_AUTHORITATIVE');self.assertIsNone(value['final_acceptance'])
        observer_tree=ast.parse((PACKAGE/'mutation/ntfs/common_flock_test.py').read_bytes())
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name)
            and n.func.value.id=='os' and n.func.attr=='write' for n in ast.walk(observer_tree)))



if __name__=='__main__':unittest.main(verbosity=2)
