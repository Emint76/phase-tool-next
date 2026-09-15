"""RC01 F04: reconcile original evidence without replay or rewriting it."""
from pathlib import Path
import hashlib
import json
import pytest
from phase_tool.application import PhaseApplication
from .test_publish_bundle import bundle_arguments


def snapshot(root: Path) -> dict:
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and 'recovery' not in p.parts}


def test_recover_lost_bundle_response_uses_frozen_not_changed_source(tmp_path: Path) -> None:
    args=bundle_arguments(tmp_path)
    app=PhaseApplication()
    first=app.publish_bundle(**args).payload
    assert first['success'],first
    before=snapshot(args['evidence_root'])
    target=snapshot(args['target_root'])
    for p in args['source_root'].rglob('*'):
        if p.is_file():
            p.write_bytes(b'changed after completed commit')
    query={k:args[k] for k in ('evidence_root','run_id','target_root','request_id')}
    query['expected_intent_digest']=first['intent_digest']
    recovered=app.recover_publication(**query).payload
    assert recovered['success'] and recovered['status']=='verified_existing',recovered
    assert recovered['target_verified'] is True
    assert recovered['recovery_mutation_attempted'] is False
    assert recovered['original_receipt_digest']==first['receipt_digest']
    assert snapshot(args['evidence_root'])==before
    assert snapshot(args['target_root'])==target
    repeat=app.recover_publication(**query).payload
    assert repeat['success'] and snapshot(args['target_root'])==target
    assert Path(recovered['observation_path']).is_file()


def test_recovery_conflicting_key_is_refused_before_target_read(tmp_path: Path,monkeypatch) -> None:
    args=bundle_arguments(tmp_path)
    app=PhaseApplication()
    first=app.publish_bundle(**args).payload
    assert first['success']
    import phase_tool.bundle as bundle
    monkeypatch.setattr(bundle,'verify_bundle',lambda *a,**kw:pytest.fail('conflict must precede target read'))
    result=app.recover_publication(evidence_root=args['evidence_root'],run_id=args['run_id'],
        target_root=args['target_root'],request_id='other',expected_intent_digest=first['intent_digest']).payload
    assert result['success'] is False and result['error']=='recovery.request_conflict'


@pytest.mark.parametrize('kind',['file','bundle'])
def test_missing_receipt_after_effect_reconciles_without_republication(tmp_path: Path,monkeypatch,kind: str) -> None:
    from phase_tool.evidence import EvidenceStore
    from phase_tool.canonical import profile_digest
    args=bundle_arguments(tmp_path)
    app=PhaseApplication()
    original=EvidenceStore.write_canonical
    def fail_receipt(self,relative,value):
        if relative=='receipt.json':
            raise OSError('injected receipt fsync failure')
        return original(self,relative,value)
    with monkeypatch.context() as m:
        m.setattr(EvidenceStore,'write_canonical',fail_receipt)
        if kind=='bundle':
            first=app.publish_bundle(**args).payload
        else:
            args.pop('members')
            args.update(source_locator='a.bin',publication_version='2.0')
            first=app.publish_file(**args).payload
    assert first['success'] is False,first
    run=args['evidence_root']/'.phase/runs'/args['run_id']
    assert not (run/'receipt.json').exists()
    intent=json.loads((run/'intent.json').read_text())
    before=snapshot(args['target_root'])
    saved=snapshot(args['evidence_root'])
    result=app.recover_publication(evidence_root=args['evidence_root'],run_id=args['run_id'],
        target_root=args['target_root'],request_id=args['request_id'],expected_intent_digest=profile_digest('intent',intent)).payload
    assert result['success'] and result['target_verified'],result
    assert result['original_receipt_digest'] is None
    assert result['recovery_mutation_attempted'] is False
    assert snapshot(args['target_root'])==before
    assert snapshot(args['evidence_root'])==saved


@pytest.mark.parametrize('point',['before_intent','before_commit','after_commit'])
def test_actual_process_crash_and_restart(point: str,tmp_path: Path) -> None:
    import subprocess
    import sys
    from phase_tool.canonical import profile_digest
    args=bundle_arguments(tmp_path)
    code='''import json,os,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.evidence import EvidenceStore
from phase_tool.mutation import bundle_create
args=json.loads(sys.argv[1]); point=sys.argv[2]
for k in ('source_root','target_root','preparation_root','evidence_root'): args[k]=Path(args[k])
if point=='before_intent':
 original=EvidenceStore.write_canonical
 def write(self,relative,value):
  if relative=='intent.json': os._exit(73)
  return original(self,relative,value)
 EvidenceStore.write_canonical=write
else:
 original=bundle_create._rename_noreplace
 def rename(*a):
  if point=='before_commit': os._exit(73)
  original(*a)
  os._exit(73)
 bundle_create._rename_noreplace=rename
PhaseApplication().publish_bundle(**args)
'''
    completed=subprocess.run([sys.executable,'-c',code,json.dumps(args,default=str),point],capture_output=True,text=True,timeout=25)
    assert completed.returncode==73,(completed.stdout,completed.stderr)
    run=args['evidence_root']/'.phase/runs'/args['run_id']
    exists=(run/'intent.json').exists()
    expected=profile_digest('intent',json.loads((run/'intent.json').read_text())) if exists else 'sha256:'+'0'*64
    before=snapshot(args['target_root'])
    result=PhaseApplication().recover_publication(evidence_root=args['evidence_root'],run_id=args['run_id'],target_root=args['target_root'],
        request_id=args['request_id'],expected_intent_digest=expected).payload
    assert result['success'] is (point=='after_commit'),result
    assert result['recovery_mutation_attempted'] is False
    assert snapshot(args['target_root'])==before
    if point=='before_commit':
        assert result['error']=='recovery.unpublished_stage_retained'
        assert not (args['target_root']/args['target_locator']).exists()


@pytest.mark.parametrize('tamper',['target','frozen','receipt','root','intent','expected'])
def test_recovery_never_trusts_prior_success_after_tampering(tamper: str,tmp_path: Path) -> None:
    args=bundle_arguments(tmp_path)
    app=PhaseApplication()
    first=app.publish_bundle(**args).payload
    assert first['success']
    run=args['evidence_root']/'.phase/runs'/args['run_id']
    expected=first['intent_digest']
    if tamper=='target':
        (args['target_root']/args['target_locator']/'a.bin').write_bytes(b'corruption')
    elif tamper=='frozen':
        next((run/'blobs').iterdir()).write_bytes(b'corruption')
    elif tamper=='receipt':
        (run/'receipt.json').write_bytes(b'{}')
    elif tamper=='root':
        args['target_root'].rename(tmp_path/'original-target')
        args['target_root'].mkdir()
    elif tamper=='intent':
        (run/'intent.json').write_bytes(b'{}')
    else:
        expected='sha256:'+'1'*64
    before=snapshot(args['target_root'])
    result=app.recover_publication(evidence_root=args['evidence_root'],run_id=args['run_id'],target_root=args['target_root'],
        request_id=args['request_id'],expected_intent_digest=expected).payload
    assert not result['success'] and not result['target_verified'],result
    assert snapshot(args['target_root'])==before


def test_recovery_observation_write_failure_never_claims_success(tmp_path: Path,monkeypatch) -> None:
    args=bundle_arguments(tmp_path)
    app=PhaseApplication(); first=app.publish_bundle(**args).payload
    from phase_tool import recovery
    def full(*a,**kw): raise OSError('ENOSPC in evidence')
    monkeypatch.setattr(recovery,'_write_bytes_exclusive_atomic',full)
    result=app.recover_publication(evidence_root=args['evidence_root'],run_id=args['run_id'],target_root=args['target_root'],
        request_id=args['request_id'],expected_intent_digest=first['intent_digest']).payload
    assert not result['success'] and result['recovery_mutation_attempted'] is False
