"""F05 status/wait and installed transport parity, no semantic audit."""
from pathlib import Path
import json
import subprocess
import sys
import time
import pytest
from phase_tool.application import PhaseApplication
from .test_publish_bundle import bundle_arguments


def test_fast_status_does_not_read_target_or_frozen_bytes(tmp_path: Path,monkeypatch) -> None:
    args=bundle_arguments(tmp_path); app=PhaseApplication()
    first=app.publish_bundle(**args).payload
    assert first['success']
    from phase_tool import streaming,bundle
    def forbidden(*a,**kw): pytest.fail('fast status must not hash content')
    monkeypatch.setattr(streaming,'hash_file',forbidden)
    monkeypatch.setattr(bundle,'verify_bundle',forbidden)
    result=app.publication_status(evidence_root=args['evidence_root'],run_id=args['run_id']).payload
    assert result['query_succeeded'] is True
    assert result['stage']=='receipt_recorded'
    assert result['recorded_terminal_status']=='succeeded_verified'
    assert result['verification_performed'] is False and result['target_verified'] is False
    assert result['intent_digest']==first['intent_digest']
    assert result['receipt_digest']==first['receipt_digest']


def test_wait_is_bounded_and_unknown_run_never_becomes_success(tmp_path: Path) -> None:
    app=PhaseApplication(); started=time.monotonic()
    result=app.publication_status(evidence_root=tmp_path,run_id='absent',wait_seconds=1).payload
    assert 0.9<=time.monotonic()-started<3
    assert result['stage']=='not_observed' and result['wait_expired'] is True
    assert result['target_verified'] is False
    for invalid in (-1,61,True,float('nan')):
        result=app.publication_status(evidence_root=tmp_path,run_id='absent',wait_seconds=invalid).payload
        assert result['query_succeeded'] is False and result['error']=='publication.invalid_wait'


def test_publication_limits_are_programmatic_for_both_formats() -> None:
    limits=PhaseApplication().publication_limits().payload
    assert limits['limits_version']=='1.0'
    assert limits['file_v1']['file_bytes']==1048576
    assert limits['file_v2']['file_bytes']==2147483648
    assert limits['bundle_v1']['total_bytes']==4294967296
    assert limits['bundle_v1']['objects']==1024
    assert limits['bundle_v1']['concurrent_operations_per_target_root']==1


def test_installed_cli_and_real_mcp_status_recovery_parity(tmp_path: Path) -> None:
    import asyncio
    args=bundle_arguments(tmp_path)
    first=PhaseApplication().publish_bundle(**args).payload
    assert first['success']
    def cli(command,extra=()):
        completed=subprocess.run([sys.executable,'-m','phase_tool',command,'--evidence-root',str(args['evidence_root']),
            '--run-id',args['run_id'],*extra],capture_output=True,text=True,timeout=30)
        assert completed.returncode==0,completed.stderr+completed.stdout
        return json.loads(completed.stdout)
    status=cli('publication-status')
    recovery=cli('recover-publication',('--target-root',str(args['target_root']),'--request-id',args['request_id'],
        '--expected-intent-digest',first['intent_digest']))
    async def exchange():
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        async with stdio_client(StdioServerParameters(command=sys.executable,args=['-m','phase_tool','mcp','serve','--stdio'])) as (reader,writer):
            async with ClientSession(reader,writer) as session:
                await session.initialize()
                stat=await session.call_tool('phase_publication_status',{'evidence_root':str(args['evidence_root']),'run_id':args['run_id']})
                rec=await session.call_tool('phase_recover_publication',{'evidence_root':str(args['evidence_root']),'run_id':args['run_id'],
                    'target_root':str(args['target_root']),'request_id':args['request_id'],'expected_intent_digest':first['intent_digest']})
                limits=await session.call_tool('phase_publication_limits',{})
                for item in (stat,rec,limits): assert not item.isError,item
                return stat.structuredContent,rec.structuredContent,limits.structuredContent
    stat,rec,limits=asyncio.run(exchange())
    assert stat==status
    assert rec==recovery
    assert limits==PhaseApplication().publication_limits().payload


def test_client_timeout_does_not_kill_or_republish_worker(tmp_path: Path) -> None:
    args=bundle_arguments(tmp_path)
    (args['source_root']/'a.bin').write_bytes(b'0123456789abcdef'*1048576)
    argv=[sys.executable,'-m','phase_tool','publish-bundle']
    for k,v in args.items():
        if k=='members':
            for item in v: argv.extend(['--member',item])
        else: argv.extend(['--'+k.replace('_','-'),str(v)])
    with subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) as process:
        with pytest.raises(subprocess.TimeoutExpired):
            process.communicate(timeout=0)
        status=PhaseApplication().publication_status(evidence_root=args['evidence_root'],run_id=args['run_id'],wait_seconds=30).payload
        stdout,stderr=process.communicate(timeout=10)
    assert process.returncode==0,stderr+stdout
    first=json.loads(stdout)
    assert status['stage']=='receipt_recorded' and status['target_verified'] is False,status
    result=PhaseApplication().recover_publication(evidence_root=args['evidence_root'],run_id=args['run_id'],target_root=args['target_root'],
        request_id=args['request_id'],expected_intent_digest=status['intent_digest']).payload
    assert result['success'] and result['original_receipt_digest']==first['receipt_digest']


@pytest.mark.parametrize('kind',['file','bundle'])
def test_publication_executes_without_network_or_generated_processes(kind: str,tmp_path: Path,monkeypatch) -> None:
    import socket
    args=bundle_arguments(tmp_path); app=PhaseApplication(); calls=[]
    def forbidden(*a,**kw):
        calls.append('forbidden')
        raise AssertionError('publication may not call network or spawn helper processes')
    monkeypatch.setattr(socket.socket,'connect',forbidden)
    monkeypatch.setattr(socket,'create_connection',forbidden)
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    if kind=='file':
        args.pop('members'); args.update(source_locator='a.bin',publication_version='2.0')
        result=app.publish_file(**args).payload
    else:
        result=app.publish_bundle(**args).payload
    assert result['success'] and result['target_verified'],result
    assert calls==[]


def test_real_mcp_timeout_can_query_and_recover_without_second_publish(tmp_path: Path) -> None:
    import asyncio
    from datetime import timedelta
    args=bundle_arguments(tmp_path)
    (args['source_root']/'a.bin').write_bytes(b'abcd'*4194304)
    async def exchange():
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        from mcp.shared.exceptions import McpError
        async with stdio_client(StdioServerParameters(command=sys.executable,args=['-m','phase_tool','mcp','serve','--stdio'])) as (reader,writer):
            async with ClientSession(reader,writer) as session:
                await session.initialize()
                request={k:str(v) if isinstance(v,Path) else v for k,v in args.items()}
                with pytest.raises(McpError):
                    await session.call_tool('phase_publish_bundle',request,read_timeout_seconds=timedelta(seconds=0.01))
                status=await session.call_tool('phase_publication_status',{'evidence_root':str(args['evidence_root']),'run_id':args['run_id'],'wait_seconds':30})
                value=status.structuredContent
                assert not status.isError and value['stage']=='receipt_recorded',status
                assert value['verification_performed'] is False
                recovery=await session.call_tool('phase_recover_publication',{'evidence_root':str(args['evidence_root']),'run_id':args['run_id'],
                    'target_root':str(args['target_root']),'request_id':args['request_id'],'expected_intent_digest':value['intent_digest']})
                assert not recovery.isError and recovery.structuredContent['success'],recovery
    asyncio.run(exchange())
    runs=list((args['evidence_root']/'.phase/runs').iterdir())
    assert [p.name for p in runs]==[args['run_id']]
