"""Executable RC01 correction findings; test mutations only on disposable roots."""
import importlib
import os
from pathlib import Path

import pytest
from phase_tool.application import PhaseApplication
from phase_tool.canonical import digest_bytes
from .test_publish_file import roots, arguments

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='qualified Linux mutation required')


@pytest.mark.parametrize('version', ['1.0', '2.0'])
@pytest.mark.parametrize('explicit_digest', [False, True])
def test_b1_prepared_input_replaced_after_revalidation(tmp_path, monkeypatch, version, explicit_digest):
    paths = roots(tmp_path)
    original = b'original binary\x00\xff'
    (paths['source']/'ready.zip').write_bytes(original)
    module = importlib.import_module('phase_tool.publish_file')
    revalidate = module.revalidate_frozen
    def substitute(frozen):
        revalidate(frozen)
        frozen.blob_path.write_bytes(b'substitute bytes!')
    monkeypatch.setattr(module, 'revalidate_frozen', substitute)
    args = arguments(paths) | {'publication_version': version}
    if explicit_digest:
        args['expected_digest'] = digest_bytes(original)
    result = PhaseApplication().publish_file(**args).payload
    assert not (paths['target']/'result.bin').exists(), result
    assert result['success'] is False and result['mutation_attempted'] is False, result
    assert result['status'] == 'rejected_before_write', result
    assert result['error'] == 'freeze.expected_content_mismatch', result
    assert result['receipt_digest'] and result['intent_digest'] is None, result


@pytest.mark.parametrize('operation', ['inspect', 'recovery'])
def test_b2_fifo_target_refuses_and_releases_root_lock(tmp_path, operation):
    import json, subprocess, sys, stat
    from phase_tool.mutation.posix.authority import PosixTargetRootLock
    paths = roots(tmp_path)
    (paths['source']/'ready.zip').write_bytes(b'original')
    args = arguments(paths)
    first = PhaseApplication().publish_file(**args, publication_version='2.0').payload
    assert first['success'], first
    target = paths['target']/'result.bin'
    target.unlink()
    os.mkfifo(target)
    before = target.stat()
    query = {k: args[k] for k in ('evidence_root', 'run_id', 'target_root', 'request_id')}
    query['expected_intent_digest'] = first['intent_digest']
    code = '''import json,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
q=json.loads(sys.argv[1]); q['evidence_root']=Path(q['evidence_root']); q['target_root']=Path(q['target_root'])
a=PhaseApplication()
if sys.argv[2]=='inspect':
 r=a.inspect(evidence_root=q['evidence_root'],run_id=q['run_id'],root_bindings={'phase_result_root':q['target_root']})
else: r=a.recover_publication(**q)
print(json.dumps(r.payload)); sys.exit(r.exit_code)
'''
    try:
        child = subprocess.run([sys.executable,'-c',code,json.dumps(query,default=str),operation], capture_output=True,text=True,timeout=8)
    except subprocess.TimeoutExpired:
        pytest.fail('product hung opening FIFO target; external timeout is NOT success')
    result = json.loads(child.stdout)
    assert child.returncode != 0 and not result['success'], result
    assert result['error'] == ('inspection.target_mismatch' if operation == 'inspect' else 'recovery.original_verification_incomplete'), result
    after = target.stat()
    assert stat.S_ISFIFO(after.st_mode) and (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)
    with PosixTargetRootLock(paths['target'], 'after-fifo-test', timeout_seconds=0):
        pass


@pytest.mark.parametrize('tamper', ['truncated', 'missing', 'validator', 'other_run', 'digest', 'attachment'])
def test_b3_missing_receipt_rejects_incomplete_or_unbound_preconditions(tmp_path, monkeypatch, tamper):
    import json
    from phase_tool.evidence import EvidenceStore
    from phase_tool.canonical import canonical_bytes, profile_digest
    from .test_publish_bundle import bundle_arguments
    args = bundle_arguments(tmp_path)
    app = PhaseApplication()
    write = EvidenceStore.write_canonical
    def fail_receipt(self, relative, value):
        if relative == 'receipt.json':
            raise OSError('receipt unavailable')
        return write(self, relative, value)
    with monkeypatch.context() as m:
        m.setattr(EvidenceStore, 'write_canonical', fail_receipt)
        first = app.publish_bundle(**args).payload
    assert not first['success']
    run = args['evidence_root']/'.phase/runs'/args['run_id']
    intent = json.loads((run/'intent.json').read_text())
    prepath = run/'attachments/pre-validator-results.json'
    pre = json.loads(prepath.read_text())
    if tamper == 'truncated': pre = [{'blocking': False}]
    elif tamper == 'missing': pre.pop(0)
    elif tamper == 'validator': pre[0]['validator']['id'] = 'validator.wrong_v1'
    elif tamper == 'other_run':
        for item in pre: item['run_id'] = 'another-run'
    elif tamper == 'digest':
        item = next(p for p in pre if p['phase'] == 'input')
        item['actual'] = item['expected'] = 'sha256:'+'0'*64
    else:
        pre[0]['detail_attachment'] = 'sha256:'+'1'*64
    prepath.write_bytes(canonical_bytes(pre))
    result = app.recover_publication(evidence_root=args['evidence_root'],run_id=args['run_id'],target_root=args['target_root'],request_id=args['request_id'],expected_intent_digest=profile_digest('intent',intent)).payload
    assert not result['success'] and not result['recovery_mutation_attempted'], result
    assert result['error'] == 'recovery.preconditions_not_proven', result


def test_b3_genuine_preconditions_remain_verifiable(tmp_path):
    import json
    from phase_tool.recovery import verify_preconditions
    from .test_publish_bundle import bundle_arguments
    args = bundle_arguments(tmp_path)
    app = PhaseApplication()
    assert app.publish_bundle(**args).payload['success']
    run = args['evidence_root']/'.phase/runs'/args['run_id']
    intent = json.loads((run/'intent.json').read_text())
    plan = json.loads((run/'attachments/effect-plan.json').read_text())
    assert verify_preconditions(app,run,intent,plan)


def crash_prepared_bundle(tmp_path, *, version='1.0'):
    import json, subprocess, sys
    from .test_publish_bundle import bundle_arguments
    from phase_tool.canonical import profile_digest
    args = bundle_arguments(tmp_path)
    if version != '1.0': args['publication_version'] = version
    code = '''import json,os,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.mutation import bundle_create
q=json.loads(sys.argv[1])
for k in ('source_root','target_root','preparation_root','evidence_root'): q[k]=Path(q[k])
def crash(*a): os._exit(73)
bundle_create._rename_noreplace=crash
print(PhaseApplication().publish_bundle(**q).payload)
'''
    child = subprocess.run([sys.executable,'-c',code,json.dumps(args,default=str)], capture_output=True,text=True,timeout=25)
    assert child.returncode == 73, (child.stdout,child.stderr)
    run = args['evidence_root']/'.phase/runs'/args['run_id']
    intent = json.loads((run/'intent.json').read_text())
    query = {k:args[k] for k in ('evidence_root','run_id','target_root','request_id')}
    query['expected_intent_digest'] = profile_digest('intent',intent)
    return args,run,query


def test_b5_prepared_stage_after_real_process_exit(tmp_path):
    import json, subprocess, sys
    from .test_publication_recovery import snapshot
    args,run,query = crash_prepared_bundle(tmp_path, version='2.0')
    retained = snapshot(args['evidence_root'])
    target = args['target_root']/args['target_locator']
    stage = next(args['target_root'].glob('phase-stage-*'))
    identity = stage.stat().st_ino
    members = {name:((stage/name).read_bytes(),(stage/name).stat().st_ino) for name in args['members']}
    for name in args['members']: (args['source_root']/name).write_bytes(b'changed source')
    observed = PhaseApplication().recover_publication(**query).payload
    assert not observed['success'] and not target.exists()
    code = '''import json,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
q=json.loads(sys.argv[1])
for k in ('evidence_root','target_root'): q[k]=Path(q[k])
r=PhaseApplication().recover_publication(**q,mode='commit_prepared')
print(json.dumps(r.payload)); sys.exit(r.exit_code)
'''
    child = subprocess.run([sys.executable,'-c',code,json.dumps(query,default=str)],capture_output=True,text=True,timeout=25)
    assert child.returncode == 0, (child.stdout,child.stderr)
    result=json.loads(child.stdout)
    assert result['success'] and result['recovery_mutation_attempted'], result
    assert target.stat().st_ino == identity and not stage.exists()
    assert {name:((target/name).read_bytes(),(target/name).stat().st_ino) for name in args['members']} == members
    repeat = PhaseApplication().recover_publication(**query,mode='commit_prepared').payload
    assert repeat['success'] and not repeat['recovery_mutation_attempted'], repeat
    assert snapshot(args['evidence_root']) == retained


@pytest.mark.parametrize('point', ['after_hash', 'at_target_open'])
def test_b1_stream_mechanism_consumes_private_verified_snapshot(tmp_path,monkeypatch,point):
    from phase_tool.mutation import stream_create
    from phase_tool.mutation.posix.authority import PosixTargetAuthority
    paths=roots(tmp_path)
    data=b'original source bytes'
    (paths['source']/'ready.zip').write_bytes(data)
    original_hash=stream_create.hash_file
    open_target=PosixTargetAuthority.open_exclusive
    captured=[]
    def substitute_hash(path,limit):
        value=original_hash(path,limit)
        captured.append(path)
        if point=='after_hash': path.write_bytes(b'wrong replacement')
        return value
    def substitute_open(authority):
        if authority.target==paths['target']/'result.bin' and point=='at_target_open':
            captured[-1].write_bytes(b'wrong replacement')
        return open_target(authority)
    monkeypatch.setattr(stream_create,'hash_file',substitute_hash)
    monkeypatch.setattr(PosixTargetAuthority,'open_exclusive',substitute_open)
    result=PhaseApplication().publish_file(**arguments(paths),publication_version='2.0').payload
    assert captured
    if point=='after_hash':
        assert not (paths['target']/'result.bin').exists(),result
        assert result['mutation_attempted'] is False and not result['success'],result
    else:
        assert (paths['target']/'result.bin').read_bytes()==data,result
