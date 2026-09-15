"""Installed rc4 continuation + post-recovery inspect, no source-tree imports."""
import argparse, asyncio, json, os, subprocess, sys
from pathlib import Path
from importlib import metadata
from phase_tool.canonical import profile_digest


def snapshot(root):
    import hashlib
    return {p.relative_to(root).as_posix(): (p.stat().st_ino, p.stat().st_mtime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in sorted(root.rglob('*'))}


def inspect_both(query):
    from phase_tool.command_result import validate_command_result
    from phase_tool.registry import BundledRegistry
    request = {k:query[k] for k in ('evidence_root','run_id')}
    request['root_bindings'] = {'phase_result_root': query['target_root']}
    child = subprocess.run([str(Path(sys.executable).with_name('phase')), 'inspect',
        '--evidence-root', query['evidence_root'], '--run-id', query['run_id'],
        '--root', 'phase_result_root='+query['target_root']], capture_output=True, text=True, timeout=30)
    assert child.returncode == 0 and child.stdout and not child.stderr, (child.returncode,child.stdout,child.stderr)
    cli = json.loads(child.stdout)
    async def exchange():
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        params = StdioServerParameters(command=str(Path(sys.executable).with_name('phase')),
            args=['mcp','serve','--stdio'])
        async with stdio_client(params) as (reader,writer):
            async with ClientSession(reader,writer) as session:
                await session.initialize()
                result = await session.call_tool('phase_inspect',request)
                assert not result.isError,result
                return result.structuredContent
    mcp = asyncio.run(asyncio.wait_for(exchange(),timeout=45))
    assert cli == mcp
    validate_command_result(cli,BundledRegistry.load())
    assert cli['stage3_command_result_version'] == '1.1'
    assert cli['success'] and cli['target_verified'] and not cli['inspection_required']
    assert cli['inspection_status'] == 'recovered_verified'
    assert cli['mutation_attempted'] is None and cli['receipt_digest'] is None
    assert cli['terminal_status'] is None and cli['execution_disposition'] is None
    assert cli['recorded_recovery_mutation_attempted'] is True
    assert len(cli['recovery_observations']) == 2
    return {'cli_exit_code':child.returncode,'cli':cli,'mcp':mcp,'schema_valid':True}


def main():
    p=argparse.ArgumentParser(); p.add_argument('--root',type=Path,required=True); args=p.parse_args()
    root=args.root.absolute(); root.mkdir(parents=True,exist_ok=False)
    assert metadata.version('phase-tool')=='1.1.0rc4'
    rows=[]
    for transport in ('cli','mcp'):
        trial=root/transport; trial.mkdir()
        for name in ('source','target','prep','evidence'): (trial/name).mkdir()
        (trial/'source/data.bin').write_bytes(b'installed original\x00\xff')
        request={'source_root':str(trial/'source'),'target_root':str(trial/'target'),'preparation_root':str(trial/'prep'),'evidence_root':str(trial/'evidence'),
            'target_locator':'bundle','members':['data.bin'],'run_id':transport,'request_id':transport,'publication_version':'2.0'}
        code='''import json,os,sys
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.mutation import bundle_create
q=json.loads(sys.argv[1])
for k in ('source_root','target_root','preparation_root','evidence_root'): q[k]=Path(q[k])
def crash(*a): os._exit(73)
bundle_create._rename_noreplace=crash
print(PhaseApplication().publish_bundle(**q).payload)
'''
        child=subprocess.run([sys.executable,'-c',code,json.dumps(request)],capture_output=True,text=True,timeout=30)
        assert child.returncode==73,(child.stdout,child.stderr)
        run=trial/'evidence/.phase/runs'/transport
        original_files = {p: p.read_bytes() for p in run.rglob('*') if p.is_file()}
        assert not (run/'receipt.json').exists()
        intent=json.loads((run/'intent.json').read_text())
        from phase_tool.canonical import digest_bytes
        anchor=json.loads((run/'preparation-binding.json').read_text())
        assert anchor['original_intent_digest']==profile_digest('intent',intent)
        assert anchor['preparation_digest']==digest_bytes((run/'attachments/prepared-stage.json').read_bytes())
        assert anchor['contract']['version']=='1.1.0'
        query={k:request[k] for k in ('evidence_root','target_root','run_id','request_id')}
        query.update(expected_intent_digest=profile_digest('intent',intent),mode='commit_prepared')
        stage=next((trial/'target').glob('phase-stage-*')); inode=stage.stat().st_ino
        (trial/'source/data.bin').write_bytes(b'changed source')
        if transport=='cli':
            argv=[sys.executable,'-m','phase_tool','recover-publication']
            for k,v in query.items(): argv += ['--'+k.replace('_','-'),v]
            completed=subprocess.run(argv,capture_output=True,text=True,timeout=30)
            assert completed.returncode==0,(completed.stdout,completed.stderr)
            result=json.loads(completed.stdout)
            repeated=subprocess.run(argv,capture_output=True,text=True,timeout=30)
            assert repeated.returncode==0,repeated.stdout+repeated.stderr
            repeat=json.loads(repeated.stdout)
        else:
            async def exchange():
                from mcp import ClientSession,StdioServerParameters
                from mcp.client.stdio import stdio_client
                params=StdioServerParameters(command=sys.executable,args=['-m','phase_tool','mcp','serve','--stdio'])
                async with stdio_client(params) as (reader,writer):
                    async with ClientSession(reader,writer) as session:
                        await session.initialize()
                        first=await session.call_tool('phase_recover_publication',query)
                        second=await session.call_tool('phase_recover_publication',query)
                        assert not first.isError and not second.isError,(first,second)
                        return first.structuredContent,second.structuredContent
            result,repeat=asyncio.run(asyncio.wait_for(exchange(),timeout=45))
        assert result['success'] and result['recovery_mutation_attempted'],result
        assert repeat['success'] and not repeat['recovery_mutation_attempted'],repeat
        target=trial/'target/bundle'
        assert target.stat().st_ino==inode and (target/'data.bin').read_bytes()==b'installed original\x00\xff'
        assert (run/'recovery/commit-intent.json').is_file() and (run/'recovery/commit-receipt.json').is_file()
        before = snapshot(trial)
        inspected = inspect_both(query)
        assert snapshot(trial) == before
        assert not (run/'receipt.json').exists()
        assert all(p.read_bytes() == data for p,data in original_files.items())
        rows.append({'transport':transport,'result':result,'repeat':repeat,'inspect':inspected,
            'inspect_mutations':0,'original_files_preserved':len(original_files),
            'original_receipt_absent':True,'same_stage_inode':True,'target_bytes_verified':True})
    report={'success':True,'version':metadata.version('phase-tool'),'python':sys.version,'trials':rows}
    (root/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__': main()
