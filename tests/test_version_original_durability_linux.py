"""Real Linux/ext4 descriptor IO; VERSION CLOSURE TOKEN IS A TEST MODEL.

No genuine worker/proof/Native authorization is asserted. The real Original
parser/proof checks are deliberately not bypassed in product; these cases
isolate existing Evidence IO after a typed closure-token model returns exact
bytes. No FakeParsed, filesystem-reader substitute or target authority.
"""
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import errno,os,stat,threading
import pytest
from phase_tool import evidence as e
from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import _linux_filesystem_type
from phase_tool.mutation.ntfs.version_original_closure import _NativeVersionOriginalClosure


def owned(tmp_path,*,receipt=False,recovery=False,failure=False):
    if os.name!='posix' or not hasattr(os,'O_NOFOLLOW')or os.geteuid()==0:pytest.skip('ordinary nonroot Linux required')
    if _linux_filesystem_type(tmp_path)!='ext4':pytest.skip('real ext4 required')
    root=tmp_path/'evidence';run=root/'.phase/runs/selected-version-original'
    (run/'attachments').mkdir(mode=0o700,parents=True);(run/'blobs').mkdir(mode=0o700)
    for path in(root,root/'.phase',root/'.phase/runs',run):path.chmod(0o700)
    bodies={'intent.json':canonical_bytes({'test_model':'not an authenticated Original'}),
        'attachments/native-terminal-proof.json':canonical_bytes({'test_model':'not an authenticated proof'}),
        'attachments/effect-plan.json':canonical_bytes({'test_model':'not a target effect'})}
    if failure:
        bodies.pop('attachments/native-terminal-proof.json')
        bodies['attachments/native-parent-failure.json']=canonical_bytes({'test_model':'not an authenticated failure completion'})
    if receipt:bodies['receipt.json']=canonical_bytes({'test_model':'physical receipt for IO-only default path'})
    if recovery:
        raw=canonical_bytes({'test_model':'not an authenticated resolution'});name=digest_bytes(raw)[7:]+'.json'
        (run/'recovery').mkdir(mode=0o700);bodies['recovery/'+name]=raw
    for name,raw in bodies.items():
        (run/name).write_bytes(raw);(run/name).chmod(0o600)
    files={name:(digest_bytes(raw),len(raw))for name,raw in bodies.items()}
    info=root.stat();identity=(info.st_dev,info.st_ino)
    token=_NativeVersionOriginalClosure(object(),run.name,'model-key','sha256:'+'1'*64,
        tuple(sorted(files.items())),(os.getpid(),threading.get_ident()))
    return root,run,identity,files,token,bodies


@contextmanager
def claimed_closure_model(token,files,closure_kind='native_terminal_proof'):
    # Exact real class, deliberately mocked private verification ONLY in test.
    # This proves IO namespace/bytes/close behavior, not Original acceptance.
    with patch.object(_NativeVersionOriginalClosure,'check',return_value={'files':files,'closure_kind':closure_kind})as check:yield check


def test_real_existing_default_receipt_dependency_path_unchanged(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path,receipt=True)
    e._confirm_native_immutable_files_durable(root,identity,run.name,files)
    assert {name:(run/name).read_bytes()for name in bodies}==bodies


def test_real_missing_receipt_without_exact_token_rejects(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path)
    with pytest.raises(PhaseError,match='dependency_mismatch'):
        e._confirm_native_immutable_files_durable(root,identity,run.name,files)
    assert not(run/'receipt.json').exists()


def test_real_missing_receipt_exact_token_syncs_all_and_never_creates_receipt(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path)
    with claimed_closure_model(token,files)as check:
        e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
    check.assert_called_once_with(run)
    assert not(run/'receipt.json').exists()
    assert {name:(run/name).read_bytes()for name in bodies}==bodies


def test_real_selected_recovery_directory_is_complete_closed_membership(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path,recovery=True)
    with claimed_closure_model(token,files):
        e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
        extra=run/'recovery'/('a'*64+'.json');extra.write_bytes(b'{}');extra.chmod(0o600)
        with pytest.raises(PhaseError,match='dependency_mismatch'):
            e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
    assert extra.read_bytes()==b'{}' and not(run/'receipt.json').exists()


def test_real_equal_length_byte_tamper_refuses_before_success(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path)
    target=run/'intent.json';raw=bytearray(target.read_bytes());raw[-2]^=1;target.write_bytes(raw)
    with claimed_closure_model(token,files),pytest.raises(PhaseError,match='bytes_mismatch'):
        e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
    assert not(run/'receipt.json').exists()


def test_real_symlink_and_hardlink_never_discharge_owned_original(tmp_path):
    for kind in('symlink','hardlink'):
        local=tmp_path/kind;local.mkdir(mode=0o700)
        root,run,identity,files,token,bodies=owned(local)
        target=run/'intent.json';saved=local/'saved';target.rename(saved)
        if kind=='symlink':target.symlink_to(saved)
        else:os.link(saved,target)
        with claimed_closure_model(token,files),pytest.raises(PhaseError):
            e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
        assert saved.read_bytes()==bodies['intent.json'] and not(run/'receipt.json').exists()


def test_real_fsync_primary_preserved_and_each_owned_descriptor_closed_once(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path)
    real_open,real_close,real_fsync=os.open,os.close,os.fsync;opened=[];closed=[];failed=[]
    def opening(*a,**k):
        fd=real_open(*a,**k);opened.append(fd);return fd
    def closing(fd):closed.append(fd);return real_close(fd)
    def syncing(fd):
        if not failed and stat.S_ISREG(os.fstat(fd).st_mode):failed.append(fd);raise OSError(errno.EIO,'model fsync fault')
        return real_fsync(fd)
    with claimed_closure_model(token,files),patch.object(os,'open',opening),patch.object(os,'close',closing),patch.object(os,'fsync',syncing):
        with pytest.raises(OSError,match='model fsync fault'):
            e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
    assert failed and sorted(opened)==sorted(closed)and len(closed)==len(set(closed))
    for fd in closed:
        with pytest.raises(OSError):os.fstat(fd)
    assert {name:(run/name).read_bytes()for name in bodies}==bodies


def test_real_close_fault_injected_only_once_not_on_reused_fd(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path)
    real_close=os.close;calls=[];injected=[]
    def close_once(fd):
        real_close(fd);calls.append(fd)
        if not injected:injected.append(fd);raise OSError(errno.EIO,'model once-only close fault')
    with claimed_closure_model(token,files),patch.object(os,'close',close_once):
        with pytest.raises(OSError,match='once-only close fault'):
            e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
    assert len(injected)==1 and calls.count(injected[0])==1 and len(calls)==len(set(calls))
    for fd in calls:
        with pytest.raises(OSError):os.fstat(fd)
    assert not(run/'receipt.json').exists()


def test_real_explicit_failure_closure_syncs_actual_failure_not_an_invented_proof(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path,failure=True)
    with claimed_closure_model(token,files,'validated_parent_failure_completion'):
        e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
    assert not(run/'attachments/native-terminal-proof.json').exists()
    assert not(run/'receipt.json').exists()
    assert {name:(run/name).read_bytes()for name in bodies}==bodies


def test_real_unknown_closure_kind_and_absent_exact_closure_leaf_refused(tmp_path):
    root,run,identity,files,token,bodies=owned(tmp_path,failure=True)
    for kind in('negative_exit_flags','native_terminal_proof'):
        with claimed_closure_model(token,files,kind),pytest.raises(PhaseError,match='dependency_mismatch'):
            e._confirm_native_immutable_files_durable(root,identity,run.name,files,_version_selection=token)
    assert not(run/'receipt.json').exists()
