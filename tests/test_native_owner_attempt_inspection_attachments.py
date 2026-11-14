"""Attachment accounting component over real files, never native proof credit.

The portable cases adapt only POSIX metadata and the admitted root in a closed
model. Actual canonical files, bounded reads, attempt/Original verification and
the real inspector attachment block/equality guard execute. The Linux case uses
default unpatched ext4 IO/root validation. No Core/NativeIO/worker is run.
"""
import ast
import os
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from phase_tool import inspection
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import owner_directory_fixture as owner
from tests.test_native_owner_directory_fixture import fixture,rows,capture,original
from tests.test_native_mixed_experimental_history import bindings_fixture


def verifier():
    # Execute exact installed/source-under-test verifier without replacing its
    # IO algorithm. This also lets an external source-only runner compare the
    # preserved pre-fix source and candidate without modifying the product.
    source=Path(owner.__file__).read_text()
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='verify_fixture_attachments')
    scope=dict(owner.__dict__)
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(owner.__file__),'exec'),scope)
    return scope['verify_fixture_attachments']


def inspector_attachment_block():
    source=Path(inspection.__file__).read_text()
    fn=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='inspect_run')
    blocks=[n for n in ast.walk(fn)if isinstance(n,ast.If)and ast.unparse(n.test)=='_native_authority is not None'
        and any(isinstance(x,ast.Call)and isinstance(x.func,ast.Attribute)and x.func.attr=='verify_attachment'for x in ast.walk(n))]
    equality=[n for n in ast.walk(fn)if isinstance(n,ast.If)and ast.unparse(n.test)=='attachment_digests != claimed']
    assert len(blocks)==len(equality)==1
    return compile(ast.Module(body=[blocks[0],equality[0]],type_ignores=[]),str(inspection.__file__),'exec')


class DiskMetadataModel:
    """Actual disk reads/identities, explicit portable POSIX-mode adaptation."""
    uid=0
    def lstat(self,path):
        actual=path.lstat()
        return SimpleNamespace(st_dev=actual.st_dev,st_ino=actual.st_ino,
            st_mode=stat.S_IFMT(actual.st_mode)|0o600,st_uid=0,st_nlink=actual.st_nlink,
            st_size=actual.st_size,st_mtime_ns=actual.st_mtime_ns,st_ctime_ns=actual.st_ctime_ns)
    def read_bounded(self,path,limit):
        # The evidence root is Linux in the real system. The portable model
        # keeps real bounded IO, with Windows birthtime cross-API identity;
        # Linux's named/fd ctime comparison is not a Windows qualification.
        before=path.lstat()
        with path.open('rb')as stream:
            opened=os.fstat(stream.fileno());raw=stream.read(limit+1);after_opened=os.fstat(stream.fileno())
        after=path.lstat()
        def own(info):return(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        def cross(info):return(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,getattr(info,'st_birthtime_ns',None))
        assert own(before)==own(after)and own(opened)==own(after_opened)and cross(before)==cross(opened)
        assert len(raw)==before.st_size<=limit
        return raw


def controls(row,root):
    role=next(name for name,kind in owner._kinds().items()if type(row.experimental_admission)is kind)
    state=capture(row.experimental_admission.raw,role=role)
    intent,plan=original(row,state)
    record=owner.attempt_record(type(row.experimental_admission),row.experimental_admission.raw,row.manifest_digest,state,intent,plan)
    run=state.document()['run_id'];directory=root/'.phase'/'runs'/run
    (directory/'attachments').mkdir(parents=True,mode=0o700)
    documents={'intent.json':intent,'attachments/effect-plan.json':plan,
        'attachments/experimental-attempt.json':record}
    for name,value in documents.items():(directory/name).write_bytes(canonical_bytes(value))
    (directory/'attachments/experimental-admission.json').write_bytes(row.experimental_admission.raw)
    known={digest_bytes(row.experimental_admission.raw),digest_bytes(canonical_bytes(record))}
    base={digest_bytes(canonical_bytes(plan))}
    receipt={'evidence':{'attachment_digests':sorted(known|base)}}
    (directory/'receipt.json').write_bytes(canonical_bytes(receipt))
    return run,directory,receipt,known,base


def inspect_accounting(row,root,run,directory,receipt,base):
    verify=verifier();disk=DiskMetadataModel()
    def actual_bounded_verification(admission,binding,run_id,actual_receipt=None):
        return verify(admission,binding,run_id,actual_receipt,_io=disk)
    scope=dict(inspection.__dict__,_native_authority=SimpleNamespace(read_binding=row),
        run_id=run,run_root=directory,receipt=receipt,attachment_digests=set(base),
        claimed=set(receipt['evidence']['attachment_digests']))
    with patch.object(type(row),'check_evidence_root',return_value=root),patch.object(
        type(row.experimental_admission),'verify_attachment',actual_bounded_verification):
        exec(inspector_attachment_block(),scope)
    return scope['attachment_digests']


@pytest.mark.parametrize('role',owner._ROLES)
def test_owner_attempt_actual_control_bytes_close_the_inspector_attachment_set(tmp_path_factory,role):
    tmp_path=tmp_path_factory.mktemp('o2')
    raw=canonical_bytes(fixture());row=rows(raw)[owner._ROLES.index(role)]
    run,directory,receipt,known,base=controls(row,tmp_path)
    before={str(p.relative_to(tmp_path)):p.read_bytes()for p in tmp_path.rglob('*')if p.is_file()}
    assert inspect_accounting(row,tmp_path,run,directory,receipt,base)==known|base
    assert {str(p.relative_to(tmp_path)):p.read_bytes()for p in tmp_path.rglob('*')if p.is_file()}==before


@pytest.mark.parametrize('role',owner._ROLES)
@pytest.mark.parametrize('damage',['missing-attempt','changed-record','extra-claimed-hash'])
def test_attempt_missing_tampered_or_extra_claimed_never_closes(tmp_path_factory,role,damage):
    tmp_path=tmp_path_factory.mktemp('o2')
    row=rows(canonical_bytes(fixture()))[owner._ROLES.index(role)]
    run,directory,receipt,known,base=controls(row,tmp_path)
    target=directory/'attachments/experimental-attempt.json'
    if damage=='missing-attempt':target.unlink()
    elif damage=='changed-record':
        value=parse_json_bytes(target.read_bytes());value['role']='foreign';target.write_bytes(canonical_bytes(value))
    else:receipt['evidence']['attachment_digests'].append(digest_bytes(b'unverified foreign bytes'))
    if damage=='missing-attempt':
        with pytest.raises(FileNotFoundError)as caught:
            inspect_accounting(row,tmp_path,run,directory,receipt,base)
        assert str(caught.value.filename).endswith('experimental-attempt.json')
    else:
        with pytest.raises(PhaseError)as caught:
            inspect_accounting(row,tmp_path,run,directory,receipt,base)
        assert caught.value.code==('ntfs.owner_fixture_original_mismatch'if damage=='changed-record'else'inspection.attachment_set_mismatch')


@pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Unpatched default owner2 IO needs real Linux/ext4')
def test_default_ext4_attempt_verifier_returns_only_actual_verified_digests(tmp_path):
    legacy=bindings_fixture(tmp_path)[0];manifest=parse_json_bytes(legacy.manifest_bytes);value=fixture()
    for name in('evidence_root','evidence_identity','preparation_root','preparation_identity'):value[name]=manifest[name]
    raw=canonical_bytes(value);kind=type(legacy.experimental_admission)
    manifest['installation_id']=owner.installation_id(kind,raw);body=canonical_bytes(manifest)
    row=replace(legacy,manifest_bytes=body,manifest_digest=digest_bytes(body),experimental_admission=kind(raw))
    root=row.check_evidence_root()  # Actual ext4/owner/no-mount/root identity validation.
    run,directory,receipt,known,base=controls(row,root)
    verified=verifier()(row.experimental_admission,row,run,receipt)
    assert type(verified)is frozenset and verified==known
    # Claimed hashes are not authoritative: the actual digest set is unchanged
    # when a foreign hash is merely appended to the receipt's claim list.
    extra=deepcopy(receipt);extra['evidence']['attachment_digests'].append(digest_bytes(b'foreign'))
    assert verifier()(row.experimental_admission,row,run,extra)==known
    assert verified|base!=set(extra['evidence']['attachment_digests'])
