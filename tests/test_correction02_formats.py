"""Additive exact format closure for recovery progress and preparation."""
import json
from phase_tool.application import PhaseApplication
from phase_tool.recovery import RecoveryResult


def test_recovery_result_11_shipped_schema_matches_public_model():
    app = PhaseApplication()
    resource = 'schemas/recovery-result-1.1.schema.json'
    schema = app.registry.schema_document('https://phase-tool.local/'+resource)
    expected = RecoveryResult.model_json_schema()
    expected['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    expected['$id'] = 'https://phase-tool.local/'+resource
    # Observation excludes its self-links; all effect/error facts are mandatory.
    expected['required'] = [key for key in expected['properties'] if key not in {'observation_digest','observation_path'}]
    assert schema == expected


def test_old_exact_bundle_contract_does_not_acquire_stage_provenance(tmp_path):
    import os
    import subprocess
    import sys
    import pytest
    from .test_publish_bundle import bundle_arguments
    from .test_publication_recovery import snapshot
    from phase_tool.canonical import profile_digest
    if os.name != 'posix': pytest.skip('Linux qualified mutation')
    args = bundle_arguments(tmp_path)
    candidate = {'operation_id':args['request_id'], 'idempotency_key':args['request_id'],
                 'input_binding':'payload', 'target_locator':args['target_locator'], 'members':args['members']}
    code = '''import json,os,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.mutation import bundle_create
q=json.loads(sys.argv[1]); candidate=json.loads(sys.argv[2])
def crash(*a): os._exit(77)
bundle_create._rename_noreplace=crash
r=PhaseApplication().run('execute',contract_binding='bundle_create.v2@1.0.0',candidate=candidate,
 evidence_root=Path(q['evidence_root']),run_id=q['run_id'],input_paths={'payload':Path(q['source_root'])},
 root_bindings={'phase_result_root':Path(q['target_root'])})
print(r.payload)
'''
    child = subprocess.run([sys.executable,'-c',code,json.dumps(args,default=str),json.dumps(candidate)],
                           capture_output=True,text=True,timeout=25)
    assert child.returncode == 77, (child.stdout,child.stderr)
    run = args['evidence_root']/'.phase/runs'/args['run_id']
    intent = json.loads((run/'intent.json').read_bytes())
    assert intent['contract']['version'] == '1.0.0'
    assert (run/'attachments/prepared-stage.json').is_file()
    assert not (run/'preparation-binding.json').exists()
    before = snapshot(args['target_root'])
    query = {k:args[k] for k in ('evidence_root','run_id','target_root','request_id')}
    result = PhaseApplication().recover_publication(**query, expected_intent_digest=profile_digest('intent',intent),mode='commit_prepared').payload
    assert not result['success'] and not result['recovery_mutation_attempted'],result
    assert result['error'] == 'recovery.preparation_binding_unsupported',result
    assert snapshot(args['target_root']) == before
    assert not (run/'preparation-binding.json').exists()
