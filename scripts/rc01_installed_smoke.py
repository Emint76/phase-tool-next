"""Candidate installed-wheel CLI/MCP acceptance, no editable/PYTHONPATH."""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,subprocess,sys
from importlib import metadata
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--root',type=Path,required=True)
    root=parser.parse_args().root.resolve(); root.mkdir(parents=True,exist_ok=False)
    import phase_tool
    module=Path(phase_tool.__file__).resolve()
    assert module.is_relative_to(Path(sys.prefix).resolve()),module
    assert metadata.version('phase-tool')=='1.1.0rc5'
    assert phase_tool.__version__=='1.1.0-rc.5'
    direct=json.loads(metadata.distribution('phase-tool').read_text('direct_url.json') or '{}')
    assert not direct.get('dir_info',{}).get('editable',False)
    assert not os.environ.get('PYTHONPATH')
    for name in ('source','target','prep','evidence'): (root/name).mkdir()
    block=bytes(range(256))*8192
    (root/'source/large.bin').write_bytes(block)
    (root/'source/second.bin').write_bytes(b'\x00\xffsecond')
    env=os.environ.copy(); env.pop('PYTHONPATH',None)
    def cli(command,arguments):
        argv=[sys.executable,'-m','phase_tool',command]
        for k,v in arguments.items(): argv.extend(['--'+k.replace('_','-'),str(v)])
        process=subprocess.run(argv,cwd=root,env=env,capture_output=True,text=True,timeout=30)
        assert process.returncode==0,process.stdout+process.stderr
        return json.loads(process.stdout)
    args={'source_root':str(root/'source'),'source_locator':'large.bin','target_root':str(root/'target'),
          'target_locator':'file.bin','preparation_root':str(root/'prep'),'evidence_root':str(root/'evidence'),
          'request_id':'installed-rc01-file','run_id':'installed-rc01-file','publication_version':'2.0'}
    file=cli('publish-file',args)
    assert file['success'] and file['content_digest']=='sha256:'+hashlib.sha256(block).hexdigest()
    async def exchange():
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        with (root/'mcp-stderr.log').open('w',encoding='utf-8') as errors:
            async with stdio_client(StdioServerParameters(command=sys.executable,args=['-m','phase_tool','mcp','serve','--stdio'],cwd=str(root),env=env),errlog=errors) as (reader,writer):
                async with ClientSession(reader,writer) as session:
                    await session.initialize()
                    inspected=await session.call_tool('phase_inspect',{'evidence_root':str(root/'evidence'),'run_id':args['run_id'],
                        'root_bindings':{'phase_result_root':str(root/'target')}})
                    assert not inspected.isError and inspected.structuredContent['target_verified']
                    bundle_args={k:v for k,v in args.items() if k not in {'source_locator','publication_version'}}
                    bundle_args.update(members=['large.bin','second.bin'],target_locator='bundle',request_id='installed-rc01-bundle',run_id='installed-rc01-bundle')
                    bundle=await session.call_tool('phase_publish_bundle',bundle_args)
                    assert not bundle.isError and bundle.structuredContent['success']
                    status=await session.call_tool('phase_publication_status',{'evidence_root':str(root/'evidence'),'run_id':args['run_id'],'wait_seconds':1})
                    assert not status.isError and not status.structuredContent['verification_performed']
                    recovery=await session.call_tool('phase_recover_publication',{'evidence_root':str(root/'evidence'),'run_id':args['run_id'],
                        'target_root':str(root/'target'),'request_id':args['request_id'],'expected_intent_digest':file['intent_digest']})
                    assert not recovery.isError and recovery.structuredContent['success']
                    return bundle.structuredContent,inspected.structuredContent,status.structuredContent,recovery.structuredContent
    bundle,inspected,status,recovery=asyncio.run(asyncio.wait_for(exchange(),timeout=45))
    cross=cli('inspect',{'evidence_root':root/'evidence','run_id':bundle['run_id'],'root':'phase_result_root='+str(root/'target')})
    assert cross['target_verified'] and cross['receipt_digest']==bundle['receipt_digest']
    assert (root/'target/file.bin').read_bytes()==block
    assert (root/'target/bundle/large.bin').read_bytes()==block
    assert (root/'target/bundle/second.bin').read_bytes()==b'\x00\xffsecond'
    summary={'success':True,'version':metadata.version('phase-tool'),'runtime_version':phase_tool.__version__,
        'installed_module':str(module),'python':sys.version,'file_bytes':len(block),'bundle_members':bundle['member_count'],
        'cross_inspect':True,'recovery':True,'metadata_status_not_verification':True,
        'file':file,'bundle':bundle,'file_cross_inspect':inspected,'bundle_cross_inspect':cross,
        'status':status,'recovery_observation':recovery}
    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
