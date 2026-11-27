"""Real ext4 Original reader/metadata. Runtime acceptance is a named MODEL.

The old terminal-proof placeholder is NOT authenticated. These test lineage
provenance bytes only, never prior worker closure, Native proof or operation.
No FakeParsed or filesystem-reader substitute. Native/process calls trapped.
"""
from contextlib import contextmanager
from copy import deepcopy
from unittest.mock import patch
import os,subprocess
import pytest
from phase_tool.canonical import canonical_bytes,digest_bytes,profile_digest
from phase_tool.errors import PhaseError
from phase_tool.installation import _linux_filesystem_type,_native_read_binding_for_launch
from phase_tool.mutation.ntfs import bootstrap,native
from phase_tool.mutation.ntfs.bundle_recovery_original import native_inventory
from phase_tool.mutation.ntfs import version_lineage as link
from tests.native_staged_original14_storage import Original14Storage
from tests.native_staged_original14_records import record_for,rehash


@contextmanager
def environment(tmp_path,role):
    if os.name!='posix' or os.geteuid()==0:pytest.skip('ordinary nonroot Linux required')
    if _linux_filesystem_type(tmp_path)!='ext4':pytest.skip('genuine ext4 required')
    fs=Original14Storage(tmp_path,'3.0');launch=fs.launch(role)
    def forbidden(*a,**k):raise AssertionError('Native/process forbidden in provenance component')
    with patch.object(bootstrap._NativeAcceptedLaunch,'check_runtime',lambda _self:None),\
        patch.object(native.NativeIO,'__init__',forbidden),patch.object(subprocess,'run',forbidden),patch.object(subprocess,'Popen',forbidden):
        # Same explicit metadata-only runtime seam as existing Original14 IO
        # tests. The real closed constructor/registry/reader remain active.
        binding=_native_read_binding_for_launch(launch)
        old=fs.records[role];oldrun=fs.evidence/'.phase/runs'/old['intent']['run_id']
        fs.write(oldrun/'attachments/native-terminal-proof.json',canonical_bytes({'provenance_model':'NOT an authenticated terminal proof'}))
        files=native_inventory(binding,oldrun)
        original={'intent':old['intent'],'closure_kind':'native_terminal_proof',
            'original_files':{name:row for name,row in files.items()if not name.startswith('recovery/')}}
        new=record_for(role,fs.data,suffix='lineage-new')
        stamp='2026-11-09T00:00:00Z';new['intent']['created_at']=stamp;new['plan']['generated_at']=stamp
        for row in new['pre']:row['started_at']=row['finished_at']=stamp
        rehash(new)
        # Retained original frozen input metadata is preserved, not reset to
        # fake a natural legacy recapture. No Core continuation is performed.
        run=fs.evidence/'.phase/runs'/new['intent']['run_id']
        fs.write(run/'intent.json',canonical_bytes(new['intent']))
        value=link.lineage_value(binding,original,new['intent']);raw=canonical_bytes(value)
        path=run/'attachments/native-version-lineage.json';fs.write(path,raw)
        yield fs,binding,old,new,run,path,raw


@pytest.mark.parametrize('role',['Version1','Version2'])
def test_real_ext4_original_reader_and_all_old_bytes_define_provenance_only(tmp_path,role):
    with environment(tmp_path,role)as(fs,binding,old,new,run,path,raw):
        digest=link.verify_version_lineage(binding,run,new['intent'])
        assert digest==digest_bytes(raw)
        assert path.read_bytes()==raw
        assert not(run/'receipt.json').exists()
        assert not(run/'attachments/native-terminal-proof.json').exists()


@pytest.mark.parametrize('role',['Version1','Version2'])
def test_real_same_length_original_blob_tamper_rejected_by_genuine_reader(tmp_path,role):
    with environment(tmp_path,role)as(fs,binding,old,new,run,path,raw):
        oldrun=fs.evidence/'.phase/runs'/old['intent']['run_id'];blob=next((oldrun/'blobs').iterdir())
        data=bytearray(blob.read_bytes());data[len(data)//2]^=1;blob.write_bytes(data)
        with pytest.raises(PhaseError):link.verify_version_lineage(binding,run,new['intent'])
        assert not(run/'receipt.json').exists()


@pytest.mark.parametrize('role',['Version1','Version2'])
def test_real_extra_old_canonical_member_invalidates_exact_provenance_set(tmp_path,role):
    with environment(tmp_path,role)as(fs,binding,old,new,run,path,raw):
        oldrun=fs.evidence/'.phase/runs'/old['intent']['run_id']
        fs.write(oldrun/'attachments/extra-retained.json',canonical_bytes({'retained_extra':'not omitted'}))
        with pytest.raises(PhaseError):link.verify_version_lineage(binding,run,new['intent'])
        assert path.read_bytes()==raw
