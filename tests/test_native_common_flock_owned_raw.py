"""Actual C01 snapshot/constructor code with explicit private IO/launch models.

These are not an admitted Native launch, real flock, worker or qualification.
Existing six-role fixture metadata is parsed normally. Only IO/runtime/process
dependencies are modeled. One separate Linux test uses the real Evidence IO.
"""
import ast,errno,importlib.resources,json,os,stat,sys,time,unittest
from pathlib import Path,PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import common_flock_test as m
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
from tests.test_native_owner_directory_fixture import fixture,rows

class ModelPath:
    metadata={}
    def __init__(self,value):self.path=PurePosixPath(str(value))
    def __str__(self):return str(self.path)
    def __truediv__(self,other):return ModelPath(self.path/other)
    def __hash__(self):return hash(self.path)
    def __eq__(self,other):return type(other)is ModelPath and self.path==other.path
    @property
    def parent(self):return ModelPath(self.path.parent)
    @property
    def parents(self):return tuple(ModelPath(x)for x in self.path.parents)
    def is_absolute(self):return self.path.is_absolute()
    def lstat(self):return self.metadata[str(self)]

class OwnedRawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document=fixture();cls.raw=canonical_bytes(cls.document);cls.reader=rows(cls.raw)[0]
        cls.root=Path(__file__).absolute().parents[1]
        cls.launcher=(cls.root/'tests/fixtures/native/qualification_fixed_native_launcher_v3.py.in').read_bytes()
        cls.legacy=(cls.root/'tests/fixtures/native/qualification_fixed_native_launcher_v2.py.in')

    def setUp(self):
        self.now=12000.25;self.writes=[];self.sent=[];self.closes=[];self.close_error=None;self.writer_error=None;self.late_writer=False;self.rebind_writer=False;self.late_open=False;self.late_parent_close=False;self.parent_context_closes=[]
        self.primary=None;self.runtime_calls=0
        self.run=self.document['request_limits']['run_prefix']+'c01-holder-000';self.campaign='raw-source-component-only'
        self.controller_path='/opt/experiment/file1/linux/common-core-flock-test.json'
        self.binding={'common_core_flock_test_version':'1.0','fixture_uuid':self.document['fixture_uuid'],
            'owner_scope_digest':digest_bytes(self.raw),'campaign_id':self.campaign,
            'run_prefix':self.document['request_limits']['run_prefix']+'c01-','maximum_cases':100,'case_watchdog_seconds':15,
            'controller_socket':'/qualification/preparation/qualification-c01/'+self.campaign+'/control.sock',
            'controller_identity':[7,90],'controller_pid':999,'controller_uid':10001}
        self.binding_raw=canonical_bytes(self.binding)
        manifest=parse_json_bytes(self.reader.manifest_bytes);manifest['preparation_root']='/qualification/preparation'
        self.launch=object.__new__(_NativeAcceptedLaunch)
        self.launch._manifest_bytes=canonical_bytes(manifest);self.launch._manifest_digest=digest_bytes(self.launch._manifest_bytes)
        self.launch._inspection_only=False;self.launch._experimental_admission_context=type(self.reader.experimental_admission)(self.raw)
        self.launch._invocation_bytes=canonical_bytes({'run_id':self.run,'channel_id':'a'*32,'operation_nonce':'b'*32,'request':{'operation':'execute'}})
        self.launch._config_bytes=canonical_bytes({'native_launch_version':'2.0','linux_launcher':'/opt/experiment/file1/linux/launcher.py',
            'dependency_file_digests':{self.controller_path:digest_bytes(self.binding_raw)},'artifact_graph':{
                'launcher_digest':m._LAUNCHER,'linux':{'dependency_file_digests':{self.controller_path:digest_bytes(self.binding_raw)}}}})
        info=lambda device,inode,mode=stat.S_IFDIR|0o700:SimpleNamespace(st_dev=device,st_ino=inode,st_mode=mode,st_uid=10001,st_file_attributes=0)
        expected=manifest['preparation_identity'];ModelPath.metadata={'/':info(7,1,stat.S_IFDIR|0o755),'/qualification':info(7,2,stat.S_IFDIR|0o755),
            '/qualification/preparation':info(expected['device'],expected['inode']),
            '/qualification/preparation/qualification-c01':info(7,80),
            '/qualification/preparation/qualification-c01/'+self.campaign:info(7,81),
            '/qualification/preparation/qualification-c01/'+self.campaign+'/observations':info(7,82)}
        outer=self
        class IPC:
            def __init__(self,*args):self.args=args
            def send(self,raw):outer.sent.append(parse_json_bytes(raw))
            def receive(self,deadline):return {'protocol':m._PROTOCOL,'action':'BEGIN','campaign_id':outer.campaign,'run_id':outer.run,
                'operation_nonce':'b'*32,'case_started_ns':int(outer.now*1e9),'case_deadline_ns':int(outer.now*1e9)+15_000_000_000}
            def close(self):
                outer.closes.append(True)
                if outer.close_error:raise outer.close_error
        def read(path,limit):
            if str(path)==self.controller_path:return self.binding_raw
            if str(path)=='/opt/experiment/file1/linux/launcher.py':return self.launcher
            raise AssertionError('unselected modeled read '+str(path))
        def runtime(_launch):self.runtime_calls+=1
        def writer(path,raw,label,*,_parent_descriptor=None):
            self.assertEqual(_parent_descriptor,71)
            self.writes.append((str(path),raw,label))
            if self.rebind_writer:
                ModelPath.metadata[str(path.parent)].st_ino+=1
            if self.late_writer:self.now+=31
            if self.writer_error:raise self.writer_error
        @__import__('contextlib').contextmanager
        def parent_context(path,expected):
            self.assertEqual(str(path),'/qualification/preparation/qualification-c01/'+self.campaign+'/observations')
            self.assertEqual(expected,(7,82))
            if self.late_open:self.now+=31
            try:yield 71
            finally:
                self.parent_context_closes.append(71)
                if self.late_parent_close:self.now+=31
        self.stack=__import__('contextlib').ExitStack();self.addCleanup(self.stack.close)
        for context in(patch.object(m,'Path',ModelPath),patch.object(m,'_PosixFlockIPC',IPC),
                patch.object(m.time,'monotonic',lambda:self.now),patch.object(m.time,'monotonic_ns',lambda:int(self.now*1e9)),
                patch.object(m.os,'geteuid',lambda:10001,create=True),patch.object(m.os.sys,'platform','linux'),
                patch.object(_NativeAcceptedLaunch,'check_runtime',runtime),
                patch('phase_tool.streaming.read_bounded_file',read),
                patch('phase_tool.evidence._write_bytes_exclusive_atomic',writer),
                patch('phase_tool.evidence._opened_owned_private_directory',parent_context)):
            self.stack.enter_context(context)
        self.token=m._CommonCoreFlockTest(self.launch,_initial_deadline=self.now+30)

    def finalized(self,*,ready=True):
        with m._common_flock_qualification_scope(self.token):
            self.token._guard=self.token._unlock=self.token._closed=ready
        return self.token

    def test_actual_constructor_receives_same_linux_float_and_case_minimum(self):
        self.assertIs(type(self.token._initial),float);self.assertEqual(self.token._initial,12030.25)
        self.assertEqual(self.token._deadline,12015.25);self.assertEqual(self.runtime_calls,1)

    def test_actual_post_scope_record_sees_socket_closed_and_no_final_acceptance(self):
        token=self.finalized();token.write_snapshot_to_owned_ext4_raw();self.assertEqual(len(self.writes),1)
        path,raw,label=self.writes[0];value=parse_json_bytes(raw)
        self.assertEqual(path,'/qualification/preparation/qualification-c01/'+self.campaign+'/observations/'+self.run+'.json')
        self.assertEqual(label,'C01 qualification RAW observation');self.assertEqual(value['errors'],[])
        self.assertTrue(value['socket_close_observed']);self.assertTrue(value['guard_return_observed'])
        self.assertTrue(value['lock_unlock_observed']);self.assertTrue(value['lock_close_observed'])
        self.assertEqual(value['raw_io_phase'],'PRE_RETURN_BEFORE_RAW_IO');self.assertFalse(value['raw_io_completion_claimed'])
        self.assertFalse(value['observation_authoritative']);self.assertIsNone(value['final_acceptance']);self.assertEqual(value['qualification_count'],0)

    def test_socket_close_error_is_preserved_in_actual_post_close_record(self):
        self.close_error=OSError(errno.EIO,'modeled close failure');token=self.finalized();token.write_snapshot_to_owned_ext4_raw()
        value=parse_json_bytes(self.writes[0][1]);self.assertFalse(value['socket_close_observed'])
        self.assertEqual(value['errors'][0]['stage'],'ipc-close');self.assertIsNone(value['final_acceptance'])

    def test_pre_finish_write_refuses_before_io(self):
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_owner'):self.token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_wrong_owner_refuses_before_io(self):
        token=self.finalized();token._owner=(0,0)
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_owner'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_once_only_after_success(self):
        token=self.finalized();token.write_snapshot_to_owned_ext4_raw()
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_consumed'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(len(self.writes),1)

    def test_atomic_io_error_preserved_and_attempt_stays_consumed(self):
        self.writer_error=OSError(errno.EIO,'modeled fsync/write error');token=self.finalized()
        with self.assertRaises(OSError)as caught:token.write_snapshot_to_owned_ext4_raw()
        self.assertIs(caught.exception,self.writer_error)
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_consumed'):token.write_snapshot_to_owned_ext4_raw()

    def test_late_io_cannot_return_success_or_rewrite_raw(self):
        self.late_writer=True;token=self.finalized()
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_flock_test_deadline'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(len(self.writes),1)
        self.assertFalse(parse_json_bytes(self.writes[0][1])['raw_io_completion_claimed'])
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_consumed'):token.write_snapshot_to_owned_ext4_raw()

    def test_late_parent_open_closes_owned_fd_before_any_publication(self):
        self.late_open=True;token=self.finalized()
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_flock_test_deadline'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[]);self.assertEqual(self.parent_context_closes,[71])
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_consumed'):token.write_snapshot_to_owned_ext4_raw()

    def test_late_successful_parent_close_fails_under_same_deadline(self):
        self.late_parent_close=True;token=self.finalized()
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_flock_test_deadline'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(len(self.writes),1);self.assertEqual(self.parent_context_closes,[71])
        self.assertFalse(parse_json_bytes(self.writes[0][1])['raw_io_completion_claimed'])
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_consumed'):token.write_snapshot_to_owned_ext4_raw()

    def test_changed_parent_identity_after_io_is_not_accepted(self):
        self.rebind_writer=True;token=self.finalized()
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_parent_identity'):token.write_snapshot_to_owned_ext4_raw()

    def test_foreign_preparation_identity_refuses_before_io(self):
        token=self.finalized();ModelPath.metadata['/qualification/preparation'].st_ino+=1
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_parent_identity'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_reparse_parent_refuses_before_io(self):
        token=self.finalized();ModelPath.metadata['/qualification/preparation/qualification-c01'].st_mode=stat.S_IFLNK|0o777
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_parent'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_nonprivate_parent_refuses_before_io(self):
        token=self.finalized();ModelPath.metadata['/qualification/preparation/qualification-c01'].st_mode=stat.S_IFDIR|0o755
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_parent'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_oversize_snapshot_refuses_before_io(self):
        token=self.finalized();token.errors.append({'stage':'test','message':'x'*(128*1024)})
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_flock_test_snapshot_limit'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_exact_new_qualification_launcher_only(self):
        self.assertEqual(digest_bytes(self.launcher),m._LAUNCHER)
        token=self.finalized();config=parse_json_bytes(self.launch._config_bytes)
        config['artifact_graph']['launcher_digest']='sha256:fed74851bdf3ba0e86059fe5765ecc61926d387503f627b2f166030fe46cba31'
        self.launch._config_bytes=canonical_bytes(config)
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_flock_test_launcher'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_foreign_or_out_of_range_run_refuses_before_io(self):
        token=self.finalized();token._case=100
        with self.assertRaisesRegex(PhaseError,'ntfs.c01_raw_snapshot_binding'):token.write_snapshot_to_owned_ext4_raw()
        self.assertEqual(self.writes,[])

    def test_primary_error_and_failed_raw_finalization_keep_primary(self):
        primary=ValueError('primary actual-code body model');self.writer_error=OSError(errno.EIO,'secondary RAW failure')
        source=self.launcher.decode();main=next(node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef)and node.name=='main')
        block=next(node for node in main.body if isinstance(node,ast.If)and isinstance(node.test,ast.Compare)and ast.unparse(node.test)=="role == 'core'")
        class StripImports(ast.NodeTransformer):
            def visit_ImportFrom(self,node):return None
        node=StripImports().visit(block)
        body=ast.FunctionDef(name='invoke_core_branch',args=ast.arguments(posonlyargs=[],args=[],kwonlyargs=[],kw_defaults=[],defaults=[]),body=[node],decorator_list=[])
        env={'role':'core','launch':self.launch,'initial_deadline_ns':self.now+30,'_CommonCoreFlockTest':m._CommonCoreFlockTest,
            '_common_flock_qualification_scope':m._common_flock_qualification_scope,
            'entrypoint':SimpleNamespace(run_native_core=lambda _launch:(_ for _ in()).throw(primary))}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[body],type_ignores=[])),'<exact-new-launcher-core-branch>','exec'),env)
        with self.assertRaises(ValueError)as caught:env['invoke_core_branch']()
        self.assertIs(caught.exception,primary);self.assertTrue(any('RAW delivery incomplete'in value for value in primary.__notes__))

class LauncherClockTests(unittest.TestCase):
    def test_preserved_whole_linux_receive_branch_keeps_original_float_clock(self):
        # Full function control flow, only transport/time dependencies modeled.
        root=Path(__file__).absolute().parents[1]
        source=(root/'tests/fixtures/native/qualification_fixed_native_launcher_v3.py.in').read_text()
        node=next(node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef)and node.name=='receive_initial')
        class StripImports(ast.NodeTransformer):
            def visit_ImportFrom(self,node):return None
            def visit_Import(self,node):return None
        node=StripImports().visit(node);raw=canonical_bytes({'run_id':'clock-model','request':{'operation':'execute'}})
        wire=bytearray(('%08x\n'%len(raw)).encode()+raw+b'\n');calls=[];sealed=[]
        class Channel:
            def __init__(self,*_):pass
            def _read(self,count,deadline):
                calls.append(deadline);value=bytes(wire[:count]);del wire[:count];return value
            def seal(self):sealed.append(True)
        env={'os':SimpleNamespace(name='posix'),'time':SimpleNamespace(monotonic=lambda:123.25),
            'LinuxNativeChannel':Channel,'_linux_stdio_identity':lambda:None,'re':__import__('re'),
            'need':lambda value:None if value else(_ for _ in()).throw(AssertionError('clock model guard')),
            'canonical_bytes':canonical_bytes,'parse_json_bytes':parse_json_bytes}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'<whole-linux-initial-receive>','exec'),env)
        _value,_transport,deadline=env['receive_initial']()
        self.assertIs(type(deadline),float);self.assertEqual(deadline,153.25);self.assertEqual(calls,[153.25]*3);self.assertEqual(sealed,[True]);self.assertFalse(wire)

class EvidenceParentOwnerModels(unittest.TestCase):
    """Actual new generic context code; explicit syscall counterparts only."""
    def setUp(self):
        import phase_tool.evidence as evidence
        self.e=evidence;self.closes=[];self.opens=[];self.close_error=None;self.first_stat_error=None
        self.info=SimpleNamespace(st_dev=7,st_ino=82,st_mode=stat.S_IFDIR|0o700,st_uid=10001,st_file_attributes=0)
        self.opened=SimpleNamespace(**vars(self.info));ModelPath.metadata={'/owned/raw':self.info}
        self.open_callback=None;self.stat_count=0
        def open_parent(path):
            self.opens.append(str(path))
            if self.open_callback:self.open_callback()
            return 71
        def fstat(fd):
            self.assertEqual(fd,71);self.stat_count+=1
            if self.first_stat_error and self.stat_count==1:raise self.first_stat_error
            return self.opened
        def close(fd):
            self.closes.append(fd)
            if self.close_error:raise self.close_error
        fake=SimpleNamespace(name='posix',geteuid=lambda:10001,fstat=fstat,close=close)
        stack=__import__('contextlib').ExitStack();self.addCleanup(stack.close)
        for context in(patch.object(evidence,'Path',ModelPath),patch.object(evidence,'os',fake),patch.object(evidence,'_open_pinned_directory',open_parent)):
            stack.enter_context(context)

    def test_checked_fd_is_borrowed_and_closed_exactly_once(self):
        with self.e._opened_owned_private_directory(ModelPath('/owned/raw'),(7,82))as fd:self.assertEqual(fd,71)
        self.assertEqual(self.opens,['/owned/raw']);self.assertEqual(self.closes,[71])

    def test_wrong_name_identity_refuses_before_open(self):
        with self.assertRaisesRegex(PhaseError,'evidence.private_directory_identity'):
            with self.e._opened_owned_private_directory(ModelPath('/owned/raw'),(7,83)):self.fail('foreign parent yielded')
        self.assertEqual(self.opens,[]);self.assertEqual(self.closes,[])

    def test_swap_between_lstat_and_open_closes_own_unexpected_fd_without_yield(self):
        def swap():self.opened.st_ino=99;self.info.st_ino=99
        self.open_callback=swap
        with self.assertRaisesRegex(PhaseError,'evidence.private_directory_identity'):
            with self.e._opened_owned_private_directory(ModelPath('/owned/raw'),(7,82)):self.fail('foreign inode yielded')
        self.assertEqual(self.closes,[71])

    def test_first_fstat_failure_still_closes_the_unlent_owned_open(self):
        primary=OSError(errno.EIO,'first fstat');self.first_stat_error=primary
        with self.assertRaises(OSError)as caught:
            with self.e._opened_owned_private_directory(ModelPath('/owned/raw'),(7,82)):self.fail('unverified fd yielded')
        self.assertIs(caught.exception,primary);self.assertEqual(self.closes,[71])

    def test_primary_and_close_error_both_preserved_without_second_close(self):
        primary=ValueError('modeled publication error');secondary=OSError(errno.EIO,'modeled parent close');self.close_error=secondary
        with self.assertRaises(BaseExceptionGroup)as caught:
            with self.e._opened_owned_private_directory(ModelPath('/owned/raw'),(7,82)):raise primary
        self.assertEqual(caught.exception.exceptions,(primary,secondary));self.assertEqual(self.closes,[71])

    def test_reused_borrowed_fd_is_never_closed_as_our_directory(self):
        with self.assertRaisesRegex(PhaseError,'evidence.private_directory_descriptor_changed'):
            with self.e._opened_owned_private_directory(ModelPath('/owned/raw'),(7,82)):self.opened.st_ino=99
        self.assertEqual(self.closes,[])

    def test_mode_change_rejects_but_closes_still_owned_inode(self):
        with self.assertRaisesRegex(PhaseError,'evidence.private_directory_identity'):
            with self.e._opened_owned_private_directory(ModelPath('/owned/raw'),(7,82)):self.opened.st_mode=stat.S_IFDIR|0o777
        self.assertEqual(self.closes,[71])

import pytest

def controlled_ext4(tmp_path):
    from phase_tool.installation import _linux_filesystem_type
    if not sys.platform.startswith('linux')or (os.geteuid()==0 or os.getegid()==0) or _linux_filesystem_type(tmp_path)!='ext4':
        pytest.skip('Requires the controlled ordinary nonroot current-UID Linux/ext4 contour.')
    if any(path.lstat().st_mode&0o022 for path in tmp_path.parents):
        pytest.skip('Requires existing private/non-world-writable component ancestors.')

@pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Real anchored dirfd substitution requires controlled Linux/ext4.')
def test_real_parent_substitution_stays_in_original_owned_inode_and_rejects(tmp_path):
    import phase_tool.evidence as evidence
    controlled_ext4(tmp_path)
    parent=tmp_path/'owned';parent.mkdir(mode=0o700);outside=tmp_path/'outside';outside.mkdir(mode=0o700)
    info=parent.lstat();identity=(info.st_dev,info.st_ino);parked=tmp_path/'parked'
    with pytest.raises(OSError)as caught:
        with evidence._opened_owned_private_directory(parent,identity)as fd:
            parent.rename(parked);parent.symlink_to(outside,target_is_directory=True)
            evidence._write_bytes_exclusive_atomic(parent/'raw.json',b'owned anchored bytes','raw test',_parent_descriptor=fd)
    assert caught.value.errno==errno.ESTALE
    assert not(outside/'raw.json').exists()
    assert (parked/'raw.json').read_bytes()==b'owned anchored bytes'
    # A rejected late namespace check does not assert no publication: the
    # complete original-owned-inode result and the negative stay retained.

@pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Real pre-open substitution requires controlled Linux/ext4.')
def test_real_pre_open_foreign_parent_refused_without_publication(tmp_path):
    import phase_tool.evidence as evidence
    controlled_ext4(tmp_path)
    parent=tmp_path/'owned';parent.mkdir(mode=0o700);outside=tmp_path/'outside';outside.mkdir(mode=0o700)
    info=parent.lstat();identity=(info.st_dev,info.st_ino);parked=tmp_path/'parked';parent.rename(parked)
    parent.symlink_to(outside,target_is_directory=True)
    with pytest.raises(PhaseError,match='evidence.private_directory_identity'):
        with evidence._opened_owned_private_directory(parent,identity)as fd:
            evidence._write_bytes_exclusive_atomic(parent/'raw.json',b'forbidden','raw test',_parent_descriptor=fd)
    assert list(outside.iterdir())==[]and list(parked.iterdir())==[]

@pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Real owned parent close fault requires controlled Linux/ext4.')
def test_real_parent_close_fault_preserves_primary_and_never_retries_close(tmp_path,monkeypatch):
    import phase_tool.evidence as evidence
    controlled_ext4(tmp_path)
    parent=tmp_path/'owned';parent.mkdir(mode=0o700);info=parent.lstat();primary=ValueError('primary real-fd body failure')
    secondary=OSError(errno.EIO,'injected API failure after actual close');closed=[];real_close=os.close;target=None
    def close(fd):
        real_close(fd)
        if fd==target and not closed:closed.append(fd);raise secondary
    with pytest.raises(BaseExceptionGroup)as caught:
        with evidence._opened_owned_private_directory(parent,(info.st_dev,info.st_ino))as fd:
            target=fd;monkeypatch.setattr(evidence.os,'close',close);raise primary
    assert caught.value.exceptions==(primary,secondary)and closed==[target]
    with pytest.raises(OSError)as actual:os.fstat(target)
    assert actual.value.errno==errno.EBADF

@pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Real default Evidence IO requires the controlled nonroot Linux/ext4 contour.')
def test_real_default_evidence_atomic_raw_io_in_private_ext4(tmp_path):
    """Real existing Evidence writer; token state is explicitly a unit fixture."""
    from phase_tool.installation import _linux_filesystem_type
    if (os.geteuid()==0 or os.getegid()==0) or _linux_filesystem_type(tmp_path)!='ext4':
        pytest.skip('Outside ordinary nonroot ext4 component contour; no Native claim.')
    if any(path.lstat().st_mode&0o022 for path in tmp_path.parents):
        pytest.skip('Component requires existing private/non-world-writable ancestors.')
    document=fixture();raw=canonical_bytes(document);run=document['request_limits']['run_prefix']+'c01-holder-000'
    prep=tmp_path/'preparation';prep.mkdir(mode=0o700);campaign='real-default-raw-component'
    directory=prep
    for name in('qualification-c01',campaign,'observations'):directory=directory/name;directory.mkdir(mode=0o700)
    info=prep.lstat();manifest={'preparation_root':str(prep),'preparation_identity':{'stable_id':'raw-unit-ext4','device':info.st_dev,'inode':info.st_ino}}
    launcher=Path(__file__).absolute().parents[1]/'tests/fixtures/native/qualification_fixed_native_launcher_v3.py.in'
    assert digest_bytes(launcher.read_bytes())==m._LAUNCHER
    launch=object.__new__(_NativeAcceptedLaunch);launch._manifest_bytes=canonical_bytes(manifest);launch._manifest_digest=digest_bytes(launch._manifest_bytes)
    launch._inspection_only=False;launch._experimental_admission_context=type(rows(raw)[0].experimental_admission)(raw)
    launch._invocation_bytes=canonical_bytes({'run_id':run});launch._config_bytes=canonical_bytes({'native_launch_version':'2.0',
        'linux_launcher':str(launcher),'artifact_graph':{'launcher_digest':m._LAUNCHER}})
    token=object.__new__(m._CommonCoreFlockTest)
    values={'_initialized':True,'_owner':(os.getpid(),__import__('threading').get_ident()),'_finished':True,
        '_snapshot_write_attempted':False,'_launch':launch,'_run':run,'_manifest_digest':launch.installation_digest,
        '_deadline':time.monotonic()+15,'_campaign':campaign,'_case':0,'_mode':'holder','_fixture_digest':digest_bytes(b'unit-controller'),
        'events':[],'errors':[],'_ipc_closed':True,'_guard':True,'_unlock':True,'_closed':True}
    for key,value in values.items():setattr(token,key,value)
    token.write_snapshot_to_owned_ext4_raw();path=directory/(run+'.json');value=parse_json_bytes(path.read_bytes())
    assert value['socket_close_observed']is True and value['errors']==[]and value['final_acceptance']is None
    assert path.lstat().st_nlink==1 and not path.lstat().st_mode&0o077
    with pytest.raises(PhaseError,match='ntfs.c01_raw_snapshot_consumed'):token.write_snapshot_to_owned_ext4_raw()

if __name__=='__main__':unittest.main()
