"""C3: provenance is not inferred from mutually editable local metadata."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes
from .test_rc01_correction import crash_prepared_bundle
from .test_publication_recovery import snapshot

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Linux qualified mutation')


def test_c3_coherent_foreign_stage_owner_and_proof_rejected(tmp_path):
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    stage = next(args['target_root'].glob('phase-stage-*'))
    intent_bytes = (run/'intent.json').read_bytes()
    anchor = run/'preparation-binding.json'
    anchor_bytes = anchor.read_bytes() if anchor.exists() else None
    retained = stage.with_name('retained-original-stage')
    stage.rename(retained)
    shutil.copytree(retained, stage)
    assert stage.stat().st_ino != retained.stat().st_ino
    proof_path = run/'attachments/prepared-stage.json'
    proof = json.loads(proof_path.read_bytes())
    owner_path = stage/'phase-owner.json'
    owner = json.loads(owner_path.read_bytes())
    for value in (proof, owner):
        value.update(device=stage.stat().st_dev, inode=stage.stat().st_ino)
    proof_path.write_bytes(canonical_bytes(proof))
    owner_path.write_bytes(canonical_bytes(owner))
    assert (stage/'a.bin').read_bytes() == (retained/'a.bin').read_bytes()
    before = snapshot(args['target_root'])
    result = PhaseApplication().recover_publication(**query, mode='commit_prepared').payload
    assert not result['success'] and not result['target_verified'], result
    assert not result['recovery_mutation_attempted'], result
    assert snapshot(args['target_root']) == before
    assert not (args['target_root']/args['target_locator']).exists()
    assert (run/'intent.json').read_bytes() == intent_bytes
    assert anchor_bytes is not None and anchor.read_bytes() == anchor_bytes


@pytest.mark.parametrize('tamper', ['missing', 'corrupt', 'run', 'request', 'plan', 'contract', 'proof_digest'])
def test_c3_invalid_independent_binding_blocks_before_effect(tmp_path, tamper):
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    anchor = run/'preparation-binding.json'
    value = json.loads(anchor.read_bytes())
    if tamper == 'missing': anchor.unlink()
    elif tamper == 'corrupt': anchor.write_bytes(b'{broken')
    else:
        if tamper == 'contract': value['contract']['package_digest'] = 'sha256:'+'0'*64
        else:
            key = {'run':'run_id', 'request':'request_id', 'plan':'effect_plan_digest', 'proof_digest':'preparation_digest'}[tamper]
            value[key] = 'wrong'
        anchor.write_bytes(canonical_bytes(value))
    before = snapshot(args['target_root'])
    result = PhaseApplication().recover_publication(**query, mode='commit_prepared').payload
    assert not result['success'] and not result['recovery_mutation_attempted'], result
    assert snapshot(args['target_root']) == before
    assert not (run/'recovery/commit-intent.json').exists()


def test_c3_genuine_preparation_is_bound_before_first_recovery(tmp_path):
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    from phase_tool.canonical import digest_bytes
    anchor = json.loads((run/'preparation-binding.json').read_bytes())
    assert anchor['preparation_digest'] == digest_bytes((run/'attachments/prepared-stage.json').read_bytes())
    assert anchor['original_intent_digest'] == query['expected_intent_digest']
    assert anchor['contract']['version'] == '1.1.0'
    assert not (run/'recovery/commit-intent.json').exists()
    stage = next(args['target_root'].glob('phase-stage-*'))
    identity = (stage.stat().st_dev, stage.stat().st_ino)
    old_intent = (run/'intent.json').read_bytes()
    old_anchor = (run/'preparation-binding.json').read_bytes()
    result = PhaseApplication().recover_publication(**query, mode='commit_prepared').payload
    assert result['success'] and result['recovery_mutation_attempted'], result
    target = args['target_root']/args['target_locator']
    assert (target.stat().st_dev, target.stat().st_ino) == identity
    repeat = PhaseApplication().recover_publication(**query, mode='commit_prepared').payload
    assert repeat['success'] and not repeat['recovery_mutation_attempted'], repeat
    assert (run/'intent.json').read_bytes() == old_intent
    assert (run/'preparation-binding.json').read_bytes() == old_anchor


@pytest.mark.parametrize('consumer', ['inspect', 'observe', 'missing_receipt', 'commit_prepared'])
def test_c3_committed_foreign_identity_cannot_bypass_binding(tmp_path, consumer):
    from .test_publish_bundle import bundle_arguments
    args = bundle_arguments(tmp_path)
    app = PhaseApplication()
    first = app.publish_bundle(**args, publication_version='2.0').payload
    assert first['success'], first
    run = args['evidence_root']/'.phase/runs'/args['run_id']
    target = args['target_root']/args['target_locator']
    retained = target.with_name('retained-original-target')
    anchor = (run/'preparation-binding.json').read_bytes()
    intent = (run/'intent.json').read_bytes()
    target.rename(retained)
    shutil.copytree(retained, target)
    assert target.stat().st_ino != retained.stat().st_ino
    for path in (target/'phase-owner.json', run/'attachments/prepared-stage.json'):
        value = json.loads(path.read_bytes())
        value.update(device=target.stat().st_dev, inode=target.stat().st_ino)
        path.write_bytes(canonical_bytes(value))
    if consumer == 'missing_receipt': (run/'receipt.json').unlink()
    before = snapshot(args['target_root'])
    if consumer == 'inspect':
        result = app.inspect(evidence_root=args['evidence_root'], run_id=args['run_id'],
                             root_bindings={'phase_result_root':args['target_root']}).payload
    else:
        query = {k:args[k] for k in ('evidence_root','run_id','target_root','request_id')}
        query['expected_intent_digest'] = first['intent_digest']
        result = app.recover_publication(**query, mode='commit_prepared' if consumer == 'commit_prepared' else 'observe').payload
        assert not result['recovery_mutation_attempted'], result
    assert not result['success'] and not result['target_verified'], result
    assert snapshot(args['target_root']) == before
    assert (run/'intent.json').read_bytes() == intent
    assert (run/'preparation-binding.json').read_bytes() == anchor


@pytest.mark.parametrize('point', ['prepared', 'binding'])
def test_c3_interrupted_mandatory_preparation_not_resumable(tmp_path, point):
    from .test_publish_bundle import bundle_arguments
    from phase_tool.canonical import profile_digest
    args = bundle_arguments(tmp_path)
    code = '''import json,os,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool import continuation,prepared_binding
q=json.loads(sys.argv[1])
for k in ('source_root','target_root','preparation_root','evidence_root'): q[k]=Path(q[k])
def crash(*a,**kw): os._exit(76)
module=continuation if sys.argv[2]=='prepared' else prepared_binding
module._write_bytes_exclusive_atomic=crash
PhaseApplication().publish_bundle(**q,publication_version='2.0')
'''
    child = subprocess.run([sys.executable, '-c', code, json.dumps(args, default=str), point],
                           capture_output=True, text=True, timeout=25)
    assert child.returncode == 76, (child.stdout, child.stderr)
    run = args['evidence_root']/'.phase/runs'/args['run_id']
    assert not (run/'preparation-binding.json').exists()
    assert (run/'attachments/prepared-stage.json').exists() == (point == 'binding')
    intent = json.loads((run/'intent.json').read_bytes())
    query = {k:args[k] for k in ('evidence_root','run_id','target_root','request_id')}
    query['expected_intent_digest'] = profile_digest('intent', intent)
    before = snapshot(args['target_root'])
    result = PhaseApplication().recover_publication(**query, mode='commit_prepared').payload
    assert not result['success'] and not result['recovery_mutation_attempted'], result
    assert snapshot(args['target_root']) == before
