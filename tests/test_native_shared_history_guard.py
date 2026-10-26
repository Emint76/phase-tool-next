"""Actual disposable ext4/Core/RO/lock components; no native qualification.

Synthetic native intent/receipt claims are explicitly derived from Host plans.
Native admission/proof guards stay real. No target authority or worker exists.
"""
from copy import deepcopy
import errno
import multiprocessing
import os
import sys
from unittest.mock import patch
import pytest
from jsonschema.exceptions import ValidationError

from phase_tool import core,installation,streaming
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import proof
from ._native_shared_history_fixture import ROLES,domain,planned,rejection,set_bytes,binding

pytestmark=pytest.mark.skipif(not sys.platform.startswith('linux'),reason='actual Linux/ext4 components required')


def guard(bindings,history,index=0):
    return core._guard_native_original_intents(bindings[index],history_bindings=history)


def test_missing_mandatory_triple_refuses_before_lock_or_yield(tmp_path):
    registry,leaves,bindings,history,roots=domain(tmp_path)
    for selected in bindings:
        with pytest.raises(PhaseError,match='ntfs.original_history_binding_mismatch'):
            with core._guard_native_original_intents(selected):pytest.fail('incomplete triple yielded')
    assert list((roots['native-claims']/'.phase'/'locks').iterdir())==[]
    assert list((roots['native-claims']/'.phase'/'runs').iterdir())==[]


@pytest.mark.parametrize('index',[0,1,2])
def test_all_real_core_preintent_rejections_share_one_existing_history_lock(index,tmp_path):
    registry,leaves,bindings,history,roots=domain(tmp_path)
    for i in range(3):rejection(registry,leaves,roots,i,'synthetic-rejected-'+str(i))
    before={p:p.read_bytes() for p in (roots['native-claims']/'.phase'/'runs').rglob('*') if p.is_file()}
    with patch.object(core,'validate_receipt',wraps=core.validate_receipt) as checked:
        with guard(bindings,history,index) as value:assert value is None
    assert {call.args[0]['contract']['id'] for call in checked.call_args_list}==set(ROLES)
    locks=roots['native-claims']/'.phase'/'locks'
    first={p.name:(p.stat().st_dev,p.stat().st_ino) for p in locks.iterdir()}
    assert len(first)==1
    for active in range(3):
        with guard(bindings,history,active):pass
        assert {p.name:(p.stat().st_dev,p.stat().st_ino) for p in locks.iterdir()}==first
    assert before=={p:p.read_bytes() for p in (roots['native-claims']/'.phase'/'runs').rglob('*') if p.is_file()}


@pytest.mark.parametrize('index,length',[(0,0),(0,1024**2),(1,1024**2+17),(2,0),(2,1024**2+17)])
def test_full_selected_planned_reader_checks_actual_role_bytes_and_returns_no_go(index,length,tmp_path):
    content=(bytes(range(256))*((length+255)//256))[:length]
    registry,leaves,bindings,history,roots,run,args,receipt=planned(tmp_path,index,content)
    before={p:p.read_bytes() for p in run.rglob('*') if p.is_file()}
    with patch.object(streaming,'hash_file',wraps=streaming.hash_file) as actual:
        assert bindings[index].validate_planned(run_id=run.name,intent_digest=args['expected_intent_digest']) is None
    if index==2:
        assert actual.call_count==1
        assert actual.call_args.args[0].parent==run/'blobs'
        assert actual.call_args.args[1]==streaming.FILE_LIMIT
    assert before=={p:p.read_bytes() for p in run.rglob('*') if p.is_file()}
    with pytest.raises(PhaseError,match='ntfs.original_execution_binding_mismatch'):
        bindings[index].read(run_id=run.name,intent_digest=args['expected_intent_digest'])


@pytest.mark.parametrize('index',[0,1,2])
def test_valid_full_planned_bytes_do_not_discharge_proofless_native_history(index,tmp_path):
    content=b'x'*(1024**2+17 if index else 31)
    registry,leaves,bindings,history,roots,run,args,receipt=planned(tmp_path,index,content)
    actual=installation._NativeFileCreateReadBinding.validate_planned
    observed=[]
    def checked(self,**kwargs):
        result=actual(self,**kwargs);observed.append((self.manifest_digest,kwargs));return result
    with patch.object(installation._NativeFileCreateReadBinding,'validate_planned',checked):
        with pytest.raises(PhaseError,match='inspection.native_installation_required'):
            with guard(bindings,history,(index+1)%3):pytest.fail('proofless native original yielded')
    assert observed==[(bindings[index].manifest_digest,{'run_id':run.name,'intent_digest':args['expected_intent_digest']})]
    assert not (run/'attachments'/'native-terminal-proof.json').exists()


@pytest.mark.parametrize('damage',['same-length','truncate','grow','missing','wrong-name','extra','symlink','hardlink','subdirectory'])
def test_large_planned_blob_corruption_or_namespace_never_reaches_inspector(damage,tmp_path):
    content=b'x'*(1024**2+17)
    registry,leaves,bindings,history,roots,run,args,receipt=planned(tmp_path,2,content)
    blob=next((run/'blobs').iterdir())
    if damage=='same-length':blob.write_bytes(content[:-1]+b'z')
    elif damage=='truncate':blob.write_bytes(content[:-1])
    elif damage=='grow':blob.write_bytes(content+b'z')
    elif damage=='missing':blob.unlink()
    elif damage=='wrong-name':blob.rename(blob.parent/('f'*64))
    elif damage=='extra':(blob.parent/('f'*64)).write_bytes(b'z'*(1024**2+1))
    elif damage=='subdirectory':(blob.parent/('f'*64)).mkdir(mode=0o700)
    elif damage=='symlink':
        other=roots['preparation']/'other';other.write_bytes(content);blob.unlink();blob.symlink_to(other)
    else:os.link(blob,roots['preparation']/'linked')
    with patch.object(core,'inspect_run',side_effect=AssertionError('invalid full bytes reached inspector')) as inspector:
        with pytest.raises((PhaseError,ValueError,FileNotFoundError,ValidationError)):
            with guard(bindings,history,0):pytest.fail('corrupt original yielded')
        inspector.assert_not_called()


@pytest.mark.parametrize('damage',['intent-digest','implementation','validators','extra-pre','unknown-proof','executed','recovery'])
def test_planned_evidence_contradictions_never_yield_or_downgrade_to_rejection(damage,tmp_path):
    registry,leaves,bindings,history,roots,run,args,receipt=planned(tmp_path,2,b'opaque')
    if damage=='intent-digest':receipt['evidence']['intent_digest']='sha256:'+'f'*64
    elif damage=='implementation':receipt['implementation_binding']['authority']['provider']['version']='9.0.0'
    elif damage=='validators':receipt['validator_results'][0]['actual']='synthetic.wrong'
    elif damage=='extra-pre':
        raw=(run/'attachments'/'validator-results.json').read_bytes()
        (run/'attachments'/'pre-validator-results.json').write_bytes(raw)
    elif damage=='unknown-proof':
        raw=canonical_bytes({'installation':{'id':'synthetic.foreign','descriptor_digest':'sha256:'+'f'*64}})
        (run/'attachments'/'native-terminal-proof.json').write_bytes(raw)
        receipt['evidence']['attachment_digests'].append(digest_bytes(raw))
    elif damage=='executed':
        intent=parse_json_bytes(args['intent_bytes']);intent['execution_requested']=True
        (run/'intent.json').write_bytes(canonical_bytes(intent))
    else:receipt['recovery_required']=True
    (run/'receipt.json').write_bytes(canonical_bytes(receipt))
    with patch.object(core,'inspect_run',side_effect=AssertionError('contradiction reached ordinary inspector')) as inspector:
        with pytest.raises((PhaseError,ValueError,ValidationError)):
            with guard(bindings,history,1):pytest.fail('contradictory history yielded')
        inspector.assert_not_called()


def test_orphan_blocks_all_three_roles_without_any_planned_order_dependency(tmp_path):
    registry,leaves,bindings,history,roots=domain(tmp_path)
    for index in range(3):rejection(registry,leaves,roots,index,'synthetic-rejected-'+str(index))
    orphan=roots['native-claims']/'.phase'/'runs'/'synthetic-orphan';orphan.mkdir(mode=0o700)
    with patch.object(core,'inspect_run',side_effect=AssertionError('orphan reached inspector')) as inspector:
        for index in range(3):
            with pytest.raises(PhaseError,match='ntfs.original_history_unresolved'):
                with guard(bindings,history,index):pytest.fail('orphan ignored')
        inspector.assert_not_called()
    assert list(orphan.iterdir())==[]


@pytest.mark.parametrize('index',[0,1,2])
def test_exact_proof_role_selection_keeps_actual_candidate_guard_closed(index,tmp_path):
    registry,leaves,bindings,history,roots=domain(tmp_path)
    run,receipt=rejection(registry,leaves,roots,index,'synthetic-proof')
    raw=canonical_bytes({'installation':{'id':leaves[index]['installation_id'],
        'descriptor_digest':bindings[index].manifest_digest},
        'prepared_receipt_digest':profile_digest('receipt',receipt)})
    (run/'attachments').mkdir(mode=0o700)
    (run/'attachments'/'native-terminal-proof.json').write_bytes(raw)
    receipt['evidence']['attachment_digests']=[digest_bytes(raw)]
    (run/'receipt.json').write_bytes(canonical_bytes(receipt))
    with patch.object(proof,'verify_native_terminal_proof',wraps=proof.verify_native_terminal_proof) as verify:
        with pytest.raises(PhaseError,match='ntfs.native_profile_not_qualified'):
            with guard(bindings,history,(index+1)%3):pytest.fail('synthetic proof admitted')
    assert verify.call_args.args[0].manifest_digest==bindings[index].manifest_digest


def competing_guard(leaves,index,pipe):
    """Report actual kernel contention, with unchanged flock and real guard."""
    import fcntl
    registry=installation._native_shared_history_registry()
    bindings=tuple(binding(registry,leaf) for leaf in leaves)
    raw=set_bytes(leaves)
    history=installation._resolve_native_history_bindings(bindings[index],raw,digest_bytes(raw))
    real=fcntl.flock;observed=False
    def observe(fd,operation):
        nonlocal observed
        try:return real(fd,operation)
        except OSError as error:
            if operation==fcntl.LOCK_EX|fcntl.LOCK_NB and error.errno in {errno.EAGAIN,errno.EACCES,errno.EWOULDBLOCK} and not observed:
                info=os.fstat(fd);pipe.send(('contended',info.st_dev,info.st_ino,error.errno));observed=True
            raise
    try:
        with patch.object(fcntl,'flock',observe):
            with guard(bindings,history,index) as value:pipe.send(('entered',value))
        pipe.send(('done',observed))
    except BaseException as error:
        pipe.send(('error',type(error).__name__,str(error)));raise
    finally:pipe.close()


@pytest.mark.parametrize('holding,contending',[(0,1),(1,2),(2,0)])
def test_actual_cross_process_contention_uses_one_same_inode_for_all_three_roles(holding,contending,tmp_path):
    registry,leaves,bindings,history,roots=domain(tmp_path)
    for index in range(3):rejection(registry,leaves,roots,index,'synthetic-rejected-'+str(index))
    context=multiprocessing.get_context('spawn')
    parent,child=context.Pipe();process=context.Process(target=competing_guard,args=(leaves,contending,child))
    try:
        with guard(bindings,history,holding):
            process.start();child.close()
            assert parent.poll(10),'child did not reach actual kernel contention'
            first=parent.recv();assert first[0]=='contended'
            info=next((roots['native-claims']/'.phase'/'locks').iterdir()).stat()
            assert first[1:3]==(info.st_dev,info.st_ino)
            assert first[3] in {errno.EAGAIN,errno.EACCES,errno.EWOULDBLOCK}
        assert parent.poll(10) and parent.recv()==('entered',None)
        assert parent.poll(10) and parent.recv()==('done',True)
        process.join(10);assert not process.is_alive() and process.exitcode==0
    finally:
        if process.pid is not None and process.is_alive():process.terminate();process.join(10)
        parent.close();child.close()


@pytest.mark.parametrize('primary',[False,True])
def test_actual_lock_cleanup_preserves_primary_or_reports_secondary_failure(primary,tmp_path):
    registry,leaves,bindings,history,roots=domain(tmp_path)
    first=ValueError('synthetic primary');secondary=OSError('synthetic late lock close')
    actual=core._OperationalFileLock.__exit__
    def fail_after_cleanup(lock,*args):actual(lock,*args);raise secondary
    with patch.object(core._OperationalFileLock,'__exit__',fail_after_cleanup):
        with pytest.raises(ValueError if primary else OSError) as caught:
            with guard(bindings,history,2):
                if primary:raise first
    assert caught.value is (first if primary else secondary)
    if primary:assert caught.value.__cause__ is secondary
    with guard(bindings,history,0):pass
