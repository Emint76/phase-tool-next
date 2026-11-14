"""Six real ext4 Original-read negative components; no Native qualification.

Runtime acceptance is explicitly modeled. The genuine full FS reader must
succeed FIRST; missing proof then refuses observation, never fabricates exit.
No FakeParsed, mocked FS reader, synthetic successful Native proof or worker.
"""
from contextlib import contextmanager
from unittest.mock import patch
import os,subprocess
import pytest
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_read_binding_for_launch,_linux_filesystem_type
from phase_tool.mutation.ntfs import bootstrap,native
from phase_tool.mutation.ntfs.publication_observe import verify_closed_publication_original
from tests.native_staged_original14_storage import Original14Storage


@contextmanager
def original_environment(tmp_path,role):
    if os.name!='posix'or os.geteuid()==0:pytest.skip('ordinary nonroot Linux required')
    if _linux_filesystem_type(tmp_path)!='ext4':pytest.skip('actual ext4 required')
    fs=Original14Storage(tmp_path,'3.0');launch=fs.launch(role)
    def forbidden(*a,**kw):raise AssertionError('Native/process forbidden in Original IO component')
    with patch.object(bootstrap._NativeAcceptedLaunch,'check_runtime',lambda _self:None),\
        patch.object(native.NativeIO,'__init__',forbidden),patch.object(subprocess,'run',forbidden),patch.object(subprocess,'Popen',forbidden):
        binding=_native_read_binding_for_launch(launch);record=fs.records[role]
        # This must genuinely parse all exact input/manifest/candidate/frozen
        # bytes before any negative case. A refusal here is NOT a passed test.
        parsed=binding.read(run_id=record['intent']['run_id'],intent_digest=record['intent_digest'])
        assert parsed is not None
        run=fs.evidence/'.phase/runs'/record['intent']['run_id']
        yield fs,binding,record,run


@pytest.mark.parametrize('role',['File1','File2','Bundle1'])
def test_real_reader_success_then_proofless_original_refuses_without_receipt_repair(tmp_path,role):
    with original_environment(tmp_path,role)as(fs,binding,record,run):
        before=(run/'intent.json').read_bytes()
        with pytest.raises(PhaseError)as caught:
            verify_closed_publication_original(binding,record['intent']['run_id'],record['intent']['idempotency']['key'],record['intent_digest'])
        assert caught.value.code=='recovery.original_closed_completion_required'
        assert (run/'intent.json').read_bytes()==before
        assert not(run/'receipt.json').exists()
        assert not(run/'recovery').exists()


@pytest.mark.parametrize('role',['File1','File2','Bundle1'])
def test_real_same_length_blob_mutation_refused_after_positive_full_reader_baseline(tmp_path,role):
    with original_environment(tmp_path,role)as(fs,binding,record,run):
        blobs=sorted((run/'blobs').iterdir());blob=next(p for p in blobs if p.stat().st_size>0)
        original=blob.read_bytes();changed=bytearray(original);changed[len(changed)//2]^=1;blob.write_bytes(changed)
        with pytest.raises(PhaseError):
            binding.read(run_id=record['intent']['run_id'],intent_digest=record['intent_digest'])
        with pytest.raises(PhaseError)as caught:
            verify_closed_publication_original(binding,record['intent']['run_id'],record['intent']['idempotency']['key'],record['intent_digest'])
        assert caught.value.code!='recovery.original_closed_completion_required'
        assert not(run/'receipt.json').exists()
        assert not(run/'recovery').exists()
