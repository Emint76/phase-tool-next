"""Real default ext4 resource/attachment IO; no Native/Phase execution claim."""
from dataclasses import replace
import os
from pathlib import Path
import sys

import pytest

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import owner_directory_fixture as fixture_io
from tests.test_native_mixed_experimental_history import bindings_fixture
from tests.test_native_owner_directory_fixture import fixture

pytestmark=pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Default owner fixture evidence IO requires Linux/ext4')


def admitted(tmp_path,*,attempts=16,retained=64*1024**2):
    legacy=bindings_fixture(tmp_path)
    base=legacy[0];manifest=parse_json_bytes(base.manifest_bytes)
    value=fixture()
    for name in ('evidence_root','evidence_identity','preparation_root','preparation_identity'):
        value[name]=manifest[name]
    value['request_limits'].update(maximum_attempts=attempts,maximum_retained_bytes=retained)
    raw=canonical_bytes(value)
    kind=type(base.experimental_admission)
    manifest['installation_id']=fixture_io.installation_id(kind,raw)
    body=canonical_bytes(manifest)
    binding=replace(base,manifest_bytes=body,manifest_digest=digest_bytes(body),experimental_admission=kind(raw))
    root=binding.check_evidence_root()  # Actual default platform/mount/root identity checks.
    run=value['request_limits']['run_prefix']+'actual-ext4'
    directory=root/'.phase'/'runs'/run
    (directory/'attachments').mkdir(mode=0o700,parents=True)
    (directory/'blobs').mkdir(mode=0o700)
    return binding,run,directory


def test_default_ext4_counts_all_negative_and_foreign_original_bytes(tmp_path):
    binding,run,directory=admitted(tmp_path)
    foreign=directory.parent/'foreign-unresolved'
    foreign.mkdir(mode=0o700)
    (foreign/'negative.bin').write_bytes(b'kept-negative')
    (directory/'blobs'/'payload').write_bytes(b'actual-capture')
    before={str(p):p.read_bytes() for p in directory.parent.rglob('*') if p.is_file()}
    result=fixture_io.enforce_owner_evidence_budget(binding,run_id=run)
    assert result['run_count']==2 and result['logical_bytes']==len(b'kept-negativeactual-capture')
    assert result['foreign_or_negative_runs_filtered'] is False
    assert result['authoritative_counter_created'] is False
    assert result['cross_run_cache'] is False
    assert {str(p):p.read_bytes() for p in directory.parent.rglob('*') if p.is_file()}==before


@pytest.mark.parametrize('extra,accepted',[(0,True),(1,False)])
def test_default_ext4_logical_boundary_includes_control_reserve(tmp_path,extra,accepted):
    binding,run,directory=admitted(tmp_path,retained=fixture_io._REMAINING_CORE_CONTROL_BYTES+13)
    (directory/'blobs'/'payload').write_bytes(b'x'*(13+extra))
    if accepted:
        assert fixture_io.enforce_owner_evidence_budget(binding,run_id=run)['logical_bytes']==13
    else:
        with pytest.raises(PhaseError,match='owner_fixture_budget_exceeded'):
            fixture_io.enforce_owner_evidence_budget(binding,run_id=run)


def test_default_ext4_attempt_limit_counts_foreign_run(tmp_path):
    binding,run,directory=admitted(tmp_path,attempts=1)
    (directory.parent/'foreign-negative').mkdir(mode=0o700)
    with pytest.raises(PhaseError,match='owner_fixture_budget_exceeded'):
        fixture_io.enforce_owner_evidence_budget(binding,run_id=run)


@pytest.mark.parametrize('unsafe',['symlink','hardlink','writable'])
def test_default_ext4_refuses_unsafe_retained_entries(tmp_path,unsafe):
    binding,run,directory=admitted(tmp_path)
    original=directory/'blobs'/'data';original.write_bytes(b'original-bytes')
    if unsafe=='symlink':
        (directory/'blobs'/'alias').symlink_to(original)
    elif unsafe=='hardlink':
        os.link(original,directory/'blobs'/'alias')
    else:
        original.chmod(0o622)  # Disposable ext4 test file only, never Windows ACL/policy.
    with pytest.raises(PhaseError,match='owner_fixture_budget_unsafe'):
        fixture_io.enforce_owner_evidence_budget(binding,run_id=run)
    assert original.read_bytes()==b'original-bytes'


def test_default_ext4_orphan_attempt_remains_unresolved(tmp_path):
    binding,run,directory=admitted(tmp_path)
    (directory/'attachments'/'experimental-admission.json').write_bytes(binding.experimental_admission.raw)
    orphan=directory/'attachments'/'experimental-attempt.json'
    orphan.write_bytes(b'{}')
    for _ in range(2):
        with pytest.raises(PhaseError,match='owner_fixture_orphan_attempt_unresolved'):
            fixture_io.verify_fixture_attachments(binding.experimental_admission,binding,run)
    assert orphan.read_bytes()==b'{}' and not(directory/'intent.json').exists()
