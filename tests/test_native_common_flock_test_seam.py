"""Portable installed-source C01 regressions with modeled syscalls; no real flock/IPC or admission."""
import ast,errno,importlib.util,json,os,sys,threading,unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from phase_tool.canonical import canonical_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool import evidence
from phase_tool.installation import _NativeFileCreateReadBinding

import phase_tool
from phase_tool.mutation.ntfs import common_flock_test as m
HERE=Path(__file__).absolute().parent
CANDIDATE=Path(phase_tool.__file__).parent
ROOT=Path.cwd()/'MODEL_ONLY_C01_NO_DIRECTORY_CREATED'
LOCK=ROOT/'.phase'/'locks'/(m.digest_bytes(b'phase.native-original-intents.v1')[7:]+'.lock')

class Clock:
    def __init__(self):self.now=1000.;self.sleeps=[]
    def monotonic(self):return self.now
    def monotonic_ns(self):return int(self.now*1e9)
    def sleep(self,n):self.sleeps.append(n);self.now+=n

class RawIPC:
    def __init__(self,token,clock):self.token=token;self.clock=clock;self.sent=[];self.waits=[];self.action='RELEASE';self.advance=0.;self.send_error=False;self.close_error=False;self.close_calls=0
    def send(self,raw):
        if self.send_error:raise BlockingIOError('MODELED NONBLOCKING RAW FAILURE')
        self.sent.append(parse_json_bytes(raw))
    def receive(self,deadline):
        self.waits.append(deadline);self.clock.now+=self.advance
        if self.clock.now>=deadline:raise PhaseError('ntfs.c01_flock_test_deadline')
        return {'protocol':m._PROTOCOL,'action':self.action,'campaign_id':self.token._campaign,'run_id':self.token._run,'operation_nonce':self.token._nonce}
    def close(self):
        self.close_calls+=1
        if self.close_error:raise OSError('MODELED IPC CLOSE FAILURE')

def token(clock,mode='contender'):
    t=object.__new__(m._CommonCoreFlockTest)
    values={'_initialized':True,'_owner':(os.getpid(),threading.get_ident()),'_launch':SimpleNamespace(manifest={'evidence_root':str(ROOT)}),
        '_selected':False,'_taken':False,'_bound':False,'_fd':None,'_acquired':False,'_history':False,'_unlock':False,'_closed':False,
        '_guard':False,'_finished':False,'events':[],'errors':[],'_sequence':0,'_initial':1030.,'_deadline':1015.,
        '_mode':mode,'_case':0,'_campaign':'c01-source-model','_fixture_digest':'sha256:'+'a'*64,'_run':'model-c01-'+mode+'-000',
        '_manifest_digest':'sha256:'+'b'*64,'_nonce':'c'*32,'_evidence_identity':canonical_bytes({'stable_id':'model','device':7,'inode':1})}
    for key,value in values.items():setattr(t,key,value)
    t._ipc=RawIPC(t,clock)
    manifest=canonical_bytes({'evidence_identity':parse_json_bytes(t._evidence_identity)})
    binding=_NativeFileCreateReadBinding(manifest,t._manifest_digest,None)
    return t,binding

class ModelPath:
    def __init__(self,path,directory=False):self.path=Path(path);self.directory=directory
    @property
    def parent(self):return ModelPath(self.path.parent,True)
    def is_absolute(self):return True
    def lstat(self):return info(self.directory)
    def __eq__(self,other):return self.path==Path(other.path if isinstance(other,ModelPath) else other)
    def __str__(self):return str(self.path)

def info(directory=False):return SimpleNamespace(st_mode=0o40700 if directory else 0o100600,st_uid=1000,st_nlink=2 if directory else 1,st_dev=7,st_ino=8 if directory else 9)

@contextmanager
def checked_model(clock,answers=(),*,close_error=False,unlock_error=False,foreign_fd=False):
    calls=[];answers=list(answers);closed=[]
    def flock(fd,flags):
        calls.append((fd,flags))
        if flags==8:
            if unlock_error:raise OSError(errno.EIO,'MODELED UNLOCK FAILURE')
        elif answers:
            value=answers.pop(0)
            if value is not None:raise value
    def close(fd):
        closed.append(fd)
        if close_error:raise OSError(errno.EIO,'MODELED CLOSE FAILURE')
    fake_os=SimpleNamespace(name='posix',O_NOFOLLOW=1,O_CLOEXEC=2,O_DIRECTORY=4,geteuid=lambda:1000,
        fstat=lambda fd:SimpleNamespace(st_dev=7,st_ino=999 if foreign_fd else 9),close=close)
    source=ast.parse((CANDIDATE/'core.py').read_bytes());node=next(row for row in source.body if isinstance(row,ast.ClassDef) and row.name=='_OperationalFileLock')
    scope={'__package__':'phase_tool','PhaseError':PhaseError,'Path':Path,'os':fake_os,'time':clock,'errno':errno,
        '_OPERATIONAL_LOCK_TIMEOUT_SECONDS':5.,'_OPERATIONAL_LOCK_RETRY_SECONDS':.05}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'exact_candidate_OperationalFileLock','exec'),scope)
    fake_fcntl=SimpleNamespace(flock=flock,LOCK_EX=2,LOCK_NB=4,LOCK_UN=8)
    with patch.dict(sys.modules,{'fcntl':fake_fcntl}),patch.object(evidence,'_open_checked_operational_lock',return_value=(17,(7,8),(7,9))),patch.object(evidence,'_reject_existing_links'),patch.object(m,'time',clock):
        yield scope['_OperationalFileLock'],calls,closed


class CommonFlockObserverModels(unittest.TestCase):
    def test_default_none_never_reads_binding_or_constructs_IPC(self):
        self.assertIsNone(m._take_common_flock_test(object(),'anything'))
        clock=Clock()
        with checked_model(clock) as (Lock,calls,closed):
            with Lock(ModelPath(LOCK),_checked_release=True):pass
        self.assertEqual(calls,[(17,6),(17,8)]);self.assertEqual(closed,[17])

    def test_wrong_type_unchecked_path_and_subclass_refused(self):
        clock=Clock()
        with checked_model(clock) as (Lock,_,closed):
            with self.assertRaises(PhaseError):Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=object())
            t,_=token(clock)
            with self.assertRaises(PhaseError):Lock(ModelPath(LOCK),_common_flock_test=t)
            self.assertEqual(closed,[])
        with self.assertRaises(PhaseError):m._common_flock_qualification_scope(object()).__enter__()

    def test_real_checked_code_contends_then_acquires_and_closes_same_descriptor(self):
        clock=Clock();t,b=token(clock)
        with checked_model(clock,[OSError(errno.EAGAIN,'busy'),OSError(errno.EINTR,'signal'),None]) as (Lock,calls,closed):
            with m._common_flock_qualification_scope(t):
                self.assertIs(m._take_common_flock_test(b,t._run),t)
                with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t) as lock:t.before_history(lock.fileno())
                t.guard_return()
        returns=[row['facts'] for row in t.events if row['stage']=='acquire_return']
        self.assertEqual([row['succeeded'] for row in returns],[False,False,True])
        self.assertEqual([row['contended'] for row in returns],[True,False,False])
        self.assertTrue(returns[1]['interrupted']);self.assertEqual({row['acquire_deadline_ns'] for row in returns},{1005000000000})
        self.assertEqual(closed,[17]);self.assertEqual(calls[-1],(17,8));self.assertEqual(t._ipc.close_calls,1)
        self.assertTrue(t.snapshot()['socket_close_observed']);self.assertEqual(t.snapshot()['qualification_count'],0)

    def test_holder_release_wait_is_inside_same_acquire_deadline(self):
        clock=Clock();t,b=token(clock,'holder');t._ipc.advance=4.9
        with checked_model(clock) as (Lock,_,closed):
            with m._common_flock_qualification_scope(t):
                m._take_common_flock_test(b,t._run)
                with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t) as lock:t.before_history(lock.fileno())
                t.guard_return()
        self.assertEqual(t._ipc.waits,[1005.]);self.assertLess(clock.now,1005.);self.assertEqual(closed,[17])

    def test_abort_or_late_release_prevents_history_and_finalizes_actual_owned_fd(self):
        for action,advance in (('ABORT',0.),('RELEASE',5.1)):
            clock=Clock();t,b=token(clock,'holder');t._ipc.action=action;t._ipc.advance=advance
            with checked_model(clock) as (Lock,calls,closed):
                with self.assertRaises(PhaseError) as caught:
                    with m._common_flock_qualification_scope(t):
                        m._take_common_flock_test(b,t._run)
                        with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t):self.fail('history entered after abort/late')
            self.assertEqual(caught.exception.code,'ntfs.c01_flock_test_aborted' if action=='ABORT' else 'ntfs.c01_flock_test_deadline')
            self.assertEqual(t._ipc.waits,[1005.])
            self.assertFalse(t._history);self.assertEqual(calls[-1],(17,8));self.assertEqual(closed,[17])

    def test_pre_history_telemetry_failure_is_fail_closed_not_a_fresh_deadline(self):
        clock=Clock();t,b=token(clock);t._ipc.send_error=True
        with checked_model(clock) as (Lock,calls,closed):
            with self.assertRaises(BlockingIOError):
                with m._common_flock_qualification_scope(t):
                    m._take_common_flock_test(b,t._run)
                    with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t):pass
        self.assertFalse(t._history);self.assertTrue(t.errors);self.assertEqual(closed,[17]);self.assertFalse(t._guard)

    def test_post_history_telemetry_failure_does_not_suppress_real_unlock_close_or_guard(self):
        clock=Clock();t,b=token(clock)
        with checked_model(clock) as (Lock,calls,closed):
            with m._common_flock_qualification_scope(t):
                m._take_common_flock_test(b,t._run)
                with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t) as lock:
                    t.before_history(lock.fileno());t._ipc.send_error=True
                t.guard_return()
        self.assertTrue(t.errors);self.assertTrue(t._guard);self.assertTrue(t._unlock);self.assertTrue(t._closed)
        self.assertEqual(closed,[17]);self.assertEqual(calls[-1],(17,8));self.assertIsNone(t.snapshot()['final_acceptance'])

    def test_actual_unlock_or_close_error_never_claims_success_even_unknown_errno(self):
        for close_error,unlock_error in ((True,False),(False,True)):
            clock=Clock();t,b=token(clock)
            with checked_model(clock,close_error=close_error,unlock_error=unlock_error) as (Lock,_,closed):
                with self.assertRaisesRegex(PhaseError,'checked_finalization_unknown'):
                    with m._common_flock_qualification_scope(t):
                        m._take_common_flock_test(b,t._run)
                        with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t) as lock:t.before_history(lock.fileno())
            self.assertEqual(closed,[17]);self.assertFalse(t._guard)
            self.assertEqual(t._closed,not close_error);self.assertEqual(t._unlock,not unlock_error)
        clock=Clock();t,_=token(clock);t._bound=True;t._fd=17
        t.close_return(17,False,None);self.assertFalse(t._closed)

    def test_foreign_descriptor_is_never_closed_or_reported_as_owned_release(self):
        clock=Clock();t,b=token(clock)
        with checked_model(clock,foreign_fd=True) as (Lock,calls,closed):
            with self.assertRaisesRegex(PhaseError,'checked_finalization_unknown'):
                with m._common_flock_qualification_scope(t):
                    m._take_common_flock_test(b,t._run)
                    with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t):pass
        self.assertEqual(closed,[]);self.assertNotIn((17,8),calls);self.assertFalse(t._unlock);self.assertFalse(t._closed)

    def test_token_duplicate_take_bind_scope_and_foreign_owner_refused(self):
        clock=Clock();t,b=token(clock)
        with patch.object(m,'time',clock):
            with m._common_flock_qualification_scope(t):
                m._take_common_flock_test(b,t._run)
                with self.assertRaises(PhaseError):m._take_common_flock_test(b,t._run)
                with self.assertRaises(PhaseError):
                    with m._common_flock_qualification_scope(t):pass
            with self.assertRaises(PhaseError):
                with m._common_flock_qualification_scope(t):pass
        clock=Clock();t,b=token(clock);t._owner=(os.getpid()+1,threading.get_ident())
        with self.assertRaises(PhaseError):t.take(b,t._run)

    def test_primary_failure_survives_observer_IPC_close_failure_and_context_resets(self):
        clock=Clock();t,_=token(clock);t._ipc.close_error=True;primary=RuntimeError('ORIGINAL TEST BODY FAILURE')
        with patch.object(m,'time',clock):
            with self.assertRaises(RuntimeError) as caught:
                with m._common_flock_qualification_scope(t):raise primary
        self.assertIs(caught.exception,primary);self.assertTrue(t.errors);self.assertFalse(t.snapshot()['socket_close_observed'])
        self.assertIsNone(m._SELECTED.get())

    def test_actual_guard_and_lifecycle_seam_ordering_default_none(self):
        tree=ast.parse((CANDIDATE/'core.py').read_bytes());fn=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='_guard_native_original_intents')
        source=ast.get_source_segment((CANDIDATE/'core.py').read_text(),fn)
        self.assertLess(source.index('_common_flock_test.before_history'),source.index('check_history();check_lock()'))
        self.assertLess(source.index('check_history();check_lock()'),source.index('yield None'))
        lifecycle=(CANDIDATE/'mutation/ntfs/lifecycle.py').read_text()
        self.assertLess(lifecycle.index('installed.admit('),lifecycle.index('_take_common_flock_test('))
        self.assertLess(lifecycle.index('context.common_guard_finalized = True'),lifecycle.index('_common_flock_test.guard_return()'))
        self.assertLess(lifecycle.index('_common_flock_test.guard_return()'),lifecycle.index('make_native_terminal_proof(installed'))

    def test_raw_scope_finish_is_explicitly_pre_finalization_not_acceptance(self):
        clock=Clock();t,_=token(clock)
        with patch.object(m,'time',clock):
            with m._common_flock_qualification_scope(t):pass
        row=t.events[-1]
        self.assertEqual(row['facts']['telemetry_phase'],'PRE_FINALIZATION_NON_AUTHORITATIVE')
        self.assertNotIn('observation_complete',row['facts']);self.assertEqual(row['qualification_count'],0)

    def test_existing_five_second_timeout_unchanged_after_repeated_actual_contended_returns(self):
        clock=Clock();t,b=token(clock)
        with checked_model(clock,[OSError(errno.EAGAIN,'busy') for _ in range(200)]) as (Lock,calls,closed):
            with self.assertRaises(PhaseError) as caught:
                with m._common_flock_qualification_scope(t):
                    m._take_common_flock_test(b,t._run)
                    with Lock(ModelPath(LOCK),_checked_release=True,_common_flock_test=t):self.fail('busy lock entered')
        self.assertEqual(caught.exception.code,'lock.acquire_timeout');self.assertEqual(clock.now,1005.)
        self.assertEqual(closed,[17]);self.assertFalse(t._history)
        deadlines={row['facts']['acquire_deadline_float_hex'] for row in t.events if row['stage']=='acquire_return'}
        self.assertEqual(deadlines,{float(1005).hex()})

    def test_exact_constructor_rejects_subclass_and_foreign_launch_before_IPC(self):
        class Foreign(m._CommonCoreFlockTest):pass
        for kind in (Foreign,m._CommonCoreFlockTest):
            with self.assertRaises(PhaseError) as caught:kind(object(),_initial_deadline=0.)
            self.assertEqual(caught.exception.code,'ntfs.c01_flock_test_type')

if __name__=='__main__':unittest.main(verbosity=2)
