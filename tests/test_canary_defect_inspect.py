"""Exact CANARY01 crash -> recovery -> repeat -> public inspect regression."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator
from phase_tool.application import PhaseApplication
from .test_rc01_correction import crash_prepared_bundle

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='qualified Linux mutation')


def snapshot(root):
    from hashlib import sha256
    return {p.relative_to(root).as_posix(): (p.stat().st_ino, p.stat().st_mtime_ns,
            sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in sorted(root.rglob('*'))}


def public_inspect(args):
    query = {'evidence_root': str(args['evidence_root']), 'run_id': args['run_id'],
             'root_bindings': {'phase_result_root': str(args['target_root'])}}
    child = subprocess.run([sys.executable, '-m', 'phase_tool', 'inspect',
        '--evidence-root', query['evidence_root'], '--run-id', query['run_id'],
        '--root', 'phase_result_root='+str(args['target_root'])],
        capture_output=True, text=True, timeout=30)
    assert child.stdout, (child.returncode, child.stderr)
    cli = json.loads(child.stdout)
    assert child.returncode == cli['exit_code'] and not child.stderr

    async def exchange():
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        params = StdioServerParameters(command=sys.executable,
            args=['-m', 'phase_tool', 'mcp', 'serve', '--stdio'])
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                result = await session.call_tool('phase_inspect', query)
                assert not result.isError, result
                return result.structuredContent
    mcp = asyncio.run(asyncio.wait_for(exchange(), timeout=45))
    assert cli == mcp
    version = cli['stage3_command_result_version']
    name = 'stage3-command-result' if version == '1.0' else 'stage3-command-result-1.1'
    registry = PhaseApplication().registry
    schema = registry.schema_document('https://phase-tool.local/schemas/'+name+'.schema.json')
    Draft202012Validator(schema, registry=registry.schema_registry()).validate(cli)
    return cli


def test_canary_recovery_then_cli_and_mcp_inspect(tmp_path):
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    original = snapshot(run)
    app = PhaseApplication()
    result = app.recover_publication(**query, mode='commit_prepared').payload
    assert result['success'] and result['target_verified'] and result['recovery_mutation_attempted']
    repeated = app.recover_publication(**query, mode='commit_prepared').payload
    assert repeated['success'] and not repeated['recovery_mutation_attempted']
    before = snapshot(tmp_path)
    inspected = public_inspect(args)
    assert inspected['success'] and inspected['target_verified']
    assert inspected['stage3_command_result_version'] == '1.1'
    assert inspected['mutation_attempted'] is None
    assert inspected['terminal_status'] is None and inspected['receipt_digest'] is None
    assert inspected['inspection_status'] == 'recovered_verified'
    assert inspected['recorded_recovery_mutation_attempted'] is True
    assert len(inspected['recovery_observations']) == 2
    assert snapshot(tmp_path) == before
    assert not (run/'receipt.json').exists()
    assert all(snapshot(run)[k] == v for k, v in original.items())


@pytest.mark.parametrize('version', ['1.0', '2.0'])
def test_missing_receipt_without_continuation_is_unknown(tmp_path, version):
    args, run, query = crash_prepared_bundle(tmp_path, version=version)
    before = snapshot(tmp_path)
    result = public_inspect(args)
    assert result['stage3_command_result_version'] == '1.1'
    assert not result['success'] and result['exit_code'] == 40
    assert result['inspection_status'] == 'indeterminate'
    assert result['inspection_required'] is True
    assert result['mutation_attempted'] is None and result['target_verified'] is None
    assert result['recorded_recovery_mutation_attempted'] is None
    assert result['recovery_observations'] == []
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('fault,point,attempted', [
    ('none', 'precheck', False), ('none', 'unknown', True),
    ('unlock', 'committed', True), ('none', 'committed_unverified', True),
])
def test_failed_or_indeterminate_recovery_is_not_verified_success(tmp_path, fault, point, attempted):
    from .test_correction02_finalization import recover_child
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    code, recovery = recover_child(query, fault, point)
    assert code == 40 and not recovery['result']['success']
    before = snapshot(tmp_path)
    result = public_inspect(args)
    assert not result['success'] and result['exit_code'] == 40
    assert result['mutation_attempted'] is None and result['target_verified'] is None
    assert result['recorded_recovery_mutation_attempted'] is (True if attempted else None)
    assert result['recovery_observations'][0]['result']['error'] == recovery['result']['error']
    assert result['recovery_observations'][0]['result']['recovery_mutation_attempted'] is attempted
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('kind', ['bundle2', 'bundle1', 'file1', 'file2'])
def test_ordinary_receipt_retains_v1_envelope_and_meaning(tmp_path, kind):
    from .test_publish_bundle import bundle_arguments
    args = bundle_arguments(tmp_path)
    app = PhaseApplication()
    if kind.startswith('file'):
        args.pop('members')
        args['source_locator'] = 'a.bin'
        original = app.publish_file(**args, publication_version=kind[-1]+'.0').payload
    else:
        original = app.publish_bundle(**args, publication_version=kind[-1]+'.0').payload
    assert original['success'], original
    before = snapshot(tmp_path)
    result = public_inspect(args)
    assert result['stage3_command_result_version'] == '1.0'
    assert result['success'] and result['target_verified']
    assert result['mutation_attempted'] is True
    assert result['terminal_status'] == 'succeeded_verified'
    assert result['receipt_digest'] == original['receipt_digest']
    assert 'recovery_observations' not in result
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('tamper', ['target', 'foreign_root', 'commit_intent', 'commit_receipt',
    'observation_digest', 'observation_context', 'observation_schema', 'missing_commit',
    'missing_observations', 'prepared_binding'])
def test_recovered_inspect_rejects_broken_proof_without_mutation(tmp_path, tamper):
    from phase_tool.canonical import canonical_bytes, digest_bytes
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    recovered = PhaseApplication().recover_publication(**query, mode='commit_prepared').payload
    assert recovered['success']
    if tamper == 'target':
        (args['target_root']/args['target_locator']/'a.bin').write_bytes(b'changed')
    elif tamper == 'foreign_root':
        import shutil
        target = tmp_path/'other'; shutil.copytree(args['target_root'], target)
        args['target_root'] = target
    elif tamper in {'commit_intent', 'commit_receipt', 'prepared_binding'}:
        path = run/({'commit_intent':'recovery/commit-intent.json',
                     'commit_receipt':'recovery/commit-receipt.json',
                     'prepared_binding':'preparation-binding.json'}[tamper])
        value = json.loads(path.read_text()); value['original_intent_digest'] = 'sha256:'+'0'*64
        path.write_bytes(canonical_bytes(value))
    elif tamper == 'missing_commit':
        (run/'recovery/commit-receipt.json').unlink()
    else:
        path = Path(recovered['observation_path'])
        if tamper == 'missing_observations': path.unlink()
        else:
            value = json.loads(path.read_text())
            if tamper == 'observation_schema': value['success'] = 'true'
            elif tamper == 'observation_context': value['request_id'] = 'another-request'
            else: value['recovery_mutation_attempted'] = False
            data = canonical_bytes(value)
            if tamper != 'observation_digest':
                path.unlink(); path = path.parent/(digest_bytes(data).removeprefix('sha256:')+'.json')
            path.write_bytes(data)
    before = snapshot(tmp_path)
    result = public_inspect(args)
    assert not result['success'] and result['target_verified'] is None, result
    assert result['mutation_attempted'] is None
    assert result['inspection_status'] == 'indeterminate'
    assert snapshot(tmp_path) == before


def test_schema_10_rejects_null_and_11_is_inspect_only(tmp_path):
    from jsonschema.exceptions import ValidationError
    from phase_tool.command_result import validate_command_result
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    result = PhaseApplication().inspect(evidence_root=args['evidence_root'], run_id=args['run_id'],
        root_bindings={'phase_result_root': args['target_root']}).payload
    registry = PhaseApplication().registry
    validate_command_result(result, registry)
    old = {k:v for k,v in result.items() if k not in {'inspection_status', 'inspection_required',
        'recorded_recovery_mutation_attempted', 'recovery_observations'}}
    old['stage3_command_result_version'] = '1.0'
    with pytest.raises(ValidationError): validate_command_result(old, registry)
    for key, value in [('command','execute'), ('mutation_attempted',False),
                       ('recorded_recovery_mutation_attempted',False), ('success',True),
                       ('target_verified',True)]:
        with pytest.raises(ValidationError): validate_command_result(result | {key:value}, registry)


def test_inspect_does_not_call_mutating_recovery_or_authority(tmp_path, monkeypatch):
    from phase_tool.mutation import EffectBroker
    from phase_tool import recovery, continuation
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    assert PhaseApplication().recover_publication(**query, mode='commit_prepared').payload['success']
    def forbidden(*args, **kwargs): pytest.fail('inspect entered mutation authority')
    monkeypatch.setattr(PhaseApplication, 'recover_publication', forbidden)
    monkeypatch.setattr(EffectBroker, 'resume_prepared_bundle', forbidden)
    monkeypatch.setattr(recovery, 'save_observation', forbidden)
    monkeypatch.setattr(continuation, 'write_or_verify', forbidden)
    before = snapshot(tmp_path)
    result = PhaseApplication().inspect(evidence_root=args['evidence_root'], run_id=args['run_id'],
        root_bindings={'phase_result_root':args['target_root']}).payload
    assert result['success'] and result['target_verified']
    assert snapshot(tmp_path) == before
