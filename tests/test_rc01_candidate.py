"""Final candidate version identity, not a relabelled stable v1.0.0."""
from importlib import metadata
from phase_tool import __version__
from phase_tool.application import PhaseApplication


def test_rc01_has_explicit_prerelease_and_resolves_old_contracts() -> None:
    assert metadata.version('phase-tool')=='1.1.0rc1'
    assert __version__=='1.1.0-rc.1'
    app=PhaseApplication()
    assert app.doctor().payload['version']==__version__
    contracts=app.contracts_list().payload['contracts']
    bindings={row['contract_binding'] for row in contracts}
    assert {'file_create.v1@1.0.0','file_create.v2@1.0.0','bundle_create.v1@1.0.0'}<=bindings


def test_installed_candidate_cli_mcp_smoke(tmp_path) -> None:
    from pathlib import Path
    import json,os,subprocess,sys
    script=Path(__file__).resolve().parents[1]/'scripts/rc01_installed_smoke.py'
    env=os.environ.copy(); env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,str(script),'--root',str(tmp_path/'installed')],cwd=tmp_path,
        env=env,capture_output=True,text=True,timeout=60)
    assert result.returncode==0,result.stdout+result.stderr
    report=json.loads((tmp_path/'installed/summary.json').read_text())
    assert report['success'] and report['version']=='1.1.0rc1'
    assert report['file_bytes']==2097152
    assert report['bundle_members']==2
    assert report['cross_inspect'] and report['recovery'] and report['metadata_status_not_verification']
