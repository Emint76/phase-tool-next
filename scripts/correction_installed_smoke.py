"""Installed rc2 CLI/MCP prepared-stage continuation, no source-tree imports."""
import argparse, asyncio, json, os, subprocess, sys
from pathlib import Path
from importlib import metadata
from phase_tool.canonical import profile_digest


def main():
    p=argparse.ArgumentParser(); p.add_argument('--root',type=Path,required=True); args=p.parse_args()
    root=args.root.absolute(); root.mkdir(parents=True,exist_ok=False)
    assert metadata.version('phase-tool')=='1.1.0rc2'
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
        intent=json.loads((run/'intent.json').read_text())
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
        rows.append({'transport':transport,'result':result,'repeat':repeat,'same_stage_inode':True,'target_bytes_verified':True})
    report={'success':True,'version':metadata.version('phase-tool'),'python':sys.version,'trials':rows}
    (root/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__': main()
