"""Opt-in B5 recovery failure boundaries; each root is disposable Linux state."""
import json, os, subprocess, sys
from pathlib import Path
import pytest
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes
from .test_rc01_correction import crash_prepared_bundle
from .test_publication_recovery import snapshot
from .test_publish_bundle import bundle_arguments

pytestmark=pytest.mark.skipif(os.name!='posix',reason='Linux qualified mutation')


@pytest.mark.parametrize('tamper',['missing_member','changed_member','manifest','incomplete','run','request','request_digest','contract','plan','format','preparation','pre_digest','foreign_target','foreign_same_bytes','relocated_stage'])
def test_b5_rejects_without_effect(tmp_path,tamper):
    args,run,query=crash_prepared_bundle(tmp_path,version='2.0')
    stage=next(args['target_root'].glob('phase-stage-*'))
    target=args['target_root']/args['target_locator']
    proof=run/'attachments/prepared-stage.json'
    if tamper=='missing_member': (stage/'a.bin').unlink()
    elif tamper=='changed_member': (stage/'a.bin').write_bytes(b'wrong')
    elif tamper=='manifest': (stage/'phase-bundle.json').write_bytes(b'{}')
    elif tamper=='incomplete': (stage/'unexpected').write_bytes(b'unexpected')
    elif tamper in {'run','request','plan'}:
        value=json.loads(proof.read_text())
        value[{'run':'run_id','request':'request_id','plan':'effect_plan_digest'}[tamper]]='wrong'
        proof.write_bytes(canonical_bytes(value))
    elif tamper in {'request_digest','contract','format'}:
        value=json.loads(proof.read_text())
        if tamper=='format': value.pop('prepared_stage_version')
        elif tamper=='contract': value['contract']['package_digest']='sha256:'+'0'*64
        else: value['request_digest']='sha256:'+'0'*64
        proof.write_bytes(canonical_bytes(value))
    elif tamper=='preparation': proof.unlink()
    elif tamper=='pre_digest':
        pre=run/'attachments/pre-validator-results.json'
        value=json.loads(pre.read_text()); value[0]['detail_attachment']=None
        pre.write_bytes(canonical_bytes(value))
        # Structurally legal alteration and recomputed local hash do not replace
        # the digest authorized by the original externally pinned intent.
        import hashlib
        changed=json.loads(proof.read_text()); changed['pre_validator_results_digest']='sha256:'+hashlib.sha256(pre.read_bytes()).hexdigest()
        proof.write_bytes(canonical_bytes(changed))
    elif tamper=='foreign_target': target.mkdir(); (target/'other').write_bytes(b'foreign')
    elif tamper=='foreign_same_bytes':
        import shutil
        shutil.copytree(stage,target)
    else: stage.rename(args['target_root']/'moved-stage')
    before=snapshot(args['target_root'])
    result=PhaseApplication().recover_publication(**query,mode='commit_prepared').payload
    assert not result['success'] and not result['target_verified'],result
    assert not result['recovery_mutation_attempted'],result
    assert snapshot(args['target_root'])==before


def test_b5_crash_after_resume_commit_before_receipt_is_idempotent(tmp_path):
    args,run,query=crash_prepared_bundle(tmp_path,version='2.0')
    stage=next(args['target_root'].glob('phase-stage-*'))
    inode=stage.stat().st_ino
    code='''import json,os,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.mutation import bundle_create
q=json.loads(sys.argv[1])
for k in ('evidence_root','target_root'): q[k]=Path(q[k])
rename=bundle_create._rename_noreplace
def crash(*a):
 rename(*a); os._exit(74)
bundle_create._rename_noreplace=crash
PhaseApplication().recover_publication(**q,mode='commit_prepared')
'''
    child=subprocess.run([sys.executable,'-c',code,json.dumps(query,default=str)],capture_output=True,text=True,timeout=25)
    assert child.returncode==74,(child.stdout,child.stderr)
    assert (run/'recovery/commit-intent.json').is_file()
    assert not (run/'recovery/commit-receipt.json').exists()
    target=args['target_root']/args['target_locator']
    assert target.stat().st_ino==inode
    before=snapshot(args['target_root'])
    result=PhaseApplication().recover_publication(**query,mode='commit_prepared').payload
    assert result['success'] and not result['recovery_mutation_attempted'],result
    assert snapshot(args['target_root'])==before


def test_b5_concurrent_recovery_commits_only_once(tmp_path):
    args,run,query=crash_prepared_bundle(tmp_path,version='2.0')
    count=tmp_path/'commits'
    code='''import json,os,sys,time
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.mutation import bundle_create
q=json.loads(sys.argv[1])
for k in ('evidence_root','target_root'): q[k]=Path(q[k])
rename=bundle_create._rename_noreplace
def counted(*a):
 time.sleep(.2)
 rename(*a)
 with open(sys.argv[2],'ab') as out: out.write(b'commit\\n')
bundle_create._rename_noreplace=counted
r=PhaseApplication().recover_publication(**q,mode='commit_prepared')
print(json.dumps(r.payload))
'''
    children=[subprocess.Popen([sys.executable,'-c',code,json.dumps(query,default=str),str(count)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
    try:
        outputs=[c.communicate(timeout=25) for c in children]
    finally:
        for child in children:
            if child.poll() is None: child.kill(); child.wait()
    results=[json.loads(out) for out,err in outputs]
    assert all(c.returncode==0 for c in children),outputs
    assert any(r['success'] for r in results),results
    assert count.read_bytes()==b'commit\n'
    assert sum(r['recovery_mutation_attempted'] for r in results)==1,results
    assert all(r['success'] or r['error']=='lock.acquire_timeout' for r in results),results


def test_b5_keeps_original_failed_receipt(tmp_path,monkeypatch):
    from phase_tool.mutation import bundle_create
    args=bundle_arguments(tmp_path)
    def fail(*a): raise OSError('original commit failed')
    with monkeypatch.context() as m:
        m.setattr(bundle_create,'_rename_noreplace',fail)
        first=PhaseApplication().publish_bundle(**args,publication_version='2.0').payload
    assert not first['success'] and first['receipt_digest'],first
    run=args['evidence_root']/'.phase/runs'/args['run_id']
    old=(run/'receipt.json').read_bytes()
    query={k:args[k] for k in ('evidence_root','run_id','target_root','request_id')}
    query['expected_intent_digest']=first['intent_digest']
    result=PhaseApplication().recover_publication(**query,mode='commit_prepared').payload
    assert result['success'],result
    assert (run/'receipt.json').read_bytes()==old
    assert result['original_terminal_status']!='succeeded_verified'


def test_b5_old_none_contract_does_not_gain_commit_authority(tmp_path):
    args,run,query=crash_prepared_bundle(tmp_path)
    before=snapshot(args['target_root'])
    result=PhaseApplication().recover_publication(**query,mode='commit_prepared').payload
    assert not result['success'] and not result['recovery_mutation_attempted'],result
    assert snapshot(args['target_root'])==before


def test_b5_new_normal_publication_still_inspects(tmp_path):
    args=bundle_arguments(tmp_path)
    app=PhaseApplication()
    result=app.publish_bundle(**args,publication_version='2.0').payload
    assert result['success'],result
    inspected=app.inspect(evidence_root=args['evidence_root'],run_id=args['run_id'],root_bindings={'phase_result_root':args['target_root']}).payload
    assert inspected['success'] and inspected['target_verified'],inspected


def test_b5_installed_cli_mcp_entrypoints(tmp_path):
    script=Path(__file__).resolve().parents[1]/'scripts/correction_installed_smoke.py'
    env=os.environ.copy(); env.pop('PYTHONPATH',None)
    child=subprocess.run([sys.executable,str(script),'--root',str(tmp_path/'installed')],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=100)
    assert child.returncode==0,child.stdout+child.stderr
    report=json.loads((tmp_path/'installed/summary.json').read_text())
    assert report['success'] and len(report['trials'])==2
