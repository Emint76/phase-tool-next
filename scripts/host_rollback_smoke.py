"""Remote CI-only ordinary Host/ext4 rollback, never native qualification.

Stdlib controller; invokes only cold installed CLI children. No production root,
new backend/owner, package install on the developer machine or native call.
"""
from __future__ import annotations
import argparse,hashlib,io,json,os,re,stat,subprocess,sys,urllib.request,venv,zipfile
from pathlib import Path

OLD_NAME='phase_tool-1.1.0-py3-none-any.whl'
OLD_SHA='9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a'
OLD_URL='https://github.com/Emint76/phase-tool-next/releases/download/v1.1.0/'+OLD_NAME
NEW_NAME='phase_tool-1.2.0rc1-py3-none-any.whl'


def require(value,message):
    if not value:raise RuntimeError(message)


def digest(data):return 'sha256:'+hashlib.sha256(data).hexdigest()


def require_installed_inventory(expected_raw,actual,*,expected_count=None):
    """Compare every installed package byte with the exact accepted wheel.

    Only the immutable reference has a pinned count. Candidate membership comes
    from its wheel; extra, missing and changed installed files still fail.
    """
    with zipfile.ZipFile(io.BytesIO(expected_raw)) as z:
        source={n.removeprefix('phase_tool/'):digest(z.read(n)) for n in z.namelist()
            if n.startswith('phase_tool/') and not n.endswith('/')}
    if expected_count is not None:
        require(len(source)==expected_count,'reference wheel member count differs from pin')
    require(actual==source,'installed source differs from exact wheel; stale files forbidden')


def checked_path(path,*,exists):
    path=Path(path)
    require(path.is_absolute() and path==Path(os.path.abspath(path)),'absolute normalized path required')
    current=path
    while current!=current.parent:
        try:info=current.lstat()
        except FileNotFoundError:
            require(current==path and not exists,'missing path ancestor')
        else:require(not stat.S_ISLNK(info.st_mode),'linked path refused')
        current=current.parent
    require(path.exists()==exists,'unexpected existing/missing path')
    return path


def validate_layout(root,wheel,temporary,evidence):
    temporary=checked_path(temporary,exists=True);evidence=checked_path(evidence,exists=True)
    require(evidence!=temporary and evidence.is_relative_to(temporary),'evidence outside runner temp')
    root=checked_path(root,exists=False);wheel=checked_path(wheel,exists=True)
    runtime=checked_path(temporary/'phase-host-rollback-runtime',exists=False)
    require(root==evidence/'installed-host-rollback','fixed evidence child required')
    require(wheel==evidence/'dist'/NEW_NAME and wheel.is_file(),'fixed candidate wheel required')
    require(root!=runtime and not runtime.is_relative_to(root),'overlapping runtime/result roots')
    return root,wheel,runtime


def snapshot(paths):
    result={}
    def fail(error):raise error
    for label,root in paths.items():
        root=checked_path(root,exists=True)
        require(root.is_dir(),'managed snapshot root must be a directory')
        root_info=root.lstat();result[label+':.']={'kind':'directory','device':root_info.st_dev,'inode':root_info.st_ino}
        for directory,dirs,names in os.walk(root,followlinks=False,onerror=fail):
            for name in (*dirs,*names):
                p=Path(directory)/name;info=p.lstat()
                require(not stat.S_ISLNK(info.st_mode),'linked managed object')
                if stat.S_ISREG(info.st_mode):
                    require(info.st_size<=2*1024**2,'unexpected large smoke object')
                    b=p.read_bytes();require(len(b)==info.st_size,'managed object size changed')
                    result[label+':'+p.relative_to(root).as_posix()]={'kind':'regular_file','sha256':digest(b),'length':len(b),'device':info.st_dev,'inode':info.st_ino}
                else:
                    require(stat.S_ISDIR(info.st_mode),'special managed object')
                    result[label+':'+p.relative_to(root).as_posix()]={'kind':'directory','device':info.st_dev,'inode':info.st_ino}
    return result


PROBE=r"""
import hashlib,importlib.metadata,json,sys
from pathlib import Path
import phase_tool
from phase_tool.installation import _linux_filesystem_type
p=Path(phase_tool.__file__).parent
assert p.is_relative_to(Path(sys.prefix))
files={str(q.relative_to(p)):'sha256:'+hashlib.sha256(q.read_bytes()).hexdigest() for q in p.rglob('*') if q.is_file() and '__pycache__' not in q.parts}
print(json.dumps({'distribution':importlib.metadata.version('phase-tool'),'runtime':phase_tool.__version__,'module':str(p),'prefix':sys.prefix,'files':files,'filesystem':_linux_filesystem_type(Path(sys.argv[1]))},sort_keys=True))
"""


def execute(root,wheel,runtime,lock,head):
    root.mkdir(mode=0o700);runtime.mkdir(mode=0o700)
    (root/'.owner.json').write_text(json.dumps({'owner':'phase-host-rollback-smoke','head':head,'scope':'ordinary ext4 only'},sort_keys=True),encoding='utf-8')
    report={'success':False,'scope':'ordinary installed Host/ext4 CLI/historical inspection only; NOT native rollback or qualification',
        'head':head,'operations':{},'installations':[],'native_rollback':'NOT_VERIFIED','a05':'NOT_VERIFIED','g01':'NOT_VERIFIED'}
    stage='setup'
    def command(args,*,timeout=60):
        env=os.environ.copy();env.pop('PYTHONPATH',None);env['PYTHONDONTWRITEBYTECODE']='1'
        p=subprocess.run(args,cwd=root,env=env,capture_output=True,text=True,timeout=timeout)
        require(len(p.stdout.encode())<=2*1024**2 and len(p.stderr.encode())<=2*1024**2,'bounded command output required')
        require(p.returncode==0,'child failed '+str(p.returncode)+': '+p.stdout[-3000:]+p.stderr[-3000:])
        return p.stdout
    try:
        for name in ('source','target','preparation','evidence'):(root/name).mkdir(mode=0o700)
        (root/'target/canary.bin').write_bytes(b'owned synthetic rollback canary')
        before=b'old synthetic opaque bytes\x00';after=b'new synthetic opaque bytes\xff'
        (root/'source/first.bin').write_bytes(before);(root/'source/next.bin').write_bytes(after)
        with urllib.request.urlopen(OLD_URL,timeout=60) as response:old=response.read(317528)
        require(len(old)==317527 and hashlib.sha256(old).hexdigest()==OLD_SHA,'exact published reference wheel required')
        oldwheel=runtime/OLD_NAME;oldwheel.write_bytes(old)
        candidate=wheel.read_bytes();require(len(candidate)<=2*1024**2,'candidate wheel bound')
        sums=(wheel.parent.parent/'build-SHA256SUMS').read_text().splitlines()
        expected=[line.split(' *./',1)[0] for line in sums if line.endswith(' *./'+NEW_NAME)]
        require(len(expected)==1 and expected[0]==hashlib.sha256(candidate).hexdigest(),'candidate build manifest mismatch')
        report['old_package']={'sha256':'sha256:'+OLD_SHA,'bytes':len(old),'url':OLD_URL}
        report['new_package']={'sha256':digest(candidate),'bytes':len(candidate)}
        raw_lock=lock.read_bytes();lines=raw_lock.decode().splitlines()
        exact='phase-tool==1.1.0 --hash=sha256:'+OLD_SHA
        require(lines.count(exact)==1,'reference lock must name exact official wheel')
        dep=runtime/'dependencies.lock';dep.write_text('\n'.join(line for line in lines if line!=exact)+'\n',encoding='utf-8')
        report['dependency_lock']={'original_digest':digest(raw_lock),'filtered_digest':digest(dep.read_bytes()),'removed_exact_phase_line':exact}
        venv.EnvBuilder(with_pip=True,symlinks=False).create(runtime/'venv')
        python=runtime/'venv/bin/python'
        command([str(python),'-I','-B','-m','pip','--isolated','install','--no-compile','--require-hashes','-r',str(dep)],timeout=240)
        def install(package,expected_raw,version,expected_files=None):
            require(package.read_bytes()==expected_raw,'package drift before installation')
            command([str(python),'-I','-B','-m','pip','--isolated','install','--no-compile','--no-deps','--force-reinstall',str(package)],timeout=120)
            diagnostic=json.loads(command([str(python),'-I','-B','-c',PROBE,str(root)]))
            require(diagnostic['distribution']==version and diagnostic['filesystem']=='ext4','wrong installed version/filesystem')
            require(package.read_bytes()==expected_raw,'package drift after installation')
            command([str(python),'-I','-B','-m','pip','--isolated','check'])
            require_installed_inventory(expected_raw,diagnostic['files'],expected_count=expected_files)
            report['installations'].append(diagnostic)
        def cli(name,argv):
            value=json.loads(command([str(python),'-I','-B','-m','phase_tool',*map(str,argv)]))
            require(value.get('success') is True and value.get('exit_code')==0,'Phase command failed')
            report['operations'][name]=value;return value
        def publish(name,source,target):
            return cli(name,['publish-file','--source-root',root/'source','--source-locator',source,
                '--target-root',root/'target','--target-locator',target,'--preparation-root',root/'preparation',
                '--evidence-root',root/'evidence','--request-id',name,'--run-id',name,'--publication-version','2.0',
                '--expected-digest',digest((root/'source'/source).read_bytes())])
        def inspect(name,result,binding='phase_result_root'):
            inspected=cli(name,['inspect','--evidence-root',root/'evidence','--run-id',result['run_id'],'--root',binding+'='+str(root/'target')])
            require(inspected['target_verified'] is True and inspected['receipt_digest']==result['receipt_digest'],'historical inspection mismatch')
        report['dependencies']=command([str(python),'-I','-B','-m','pip','--isolated','freeze']).splitlines()
        stage='old-before';install(oldwheel,old,'1.1.0',193)
        old_result=publish('rollback-old-before','first.bin','old-first.bin');inspect('old-inspect-old',old_result)
        protected={'target':root/'target','runs':root/'evidence/.phase/runs'}
        old_snapshot=snapshot(protected)
        stage='candidate';install(wheel,candidate,'1.2.0rc1')
        require(snapshot(protected)==old_snapshot,'upgrade modified managed data')
        inspect('candidate-inspect-old',old_result)
        new_result=publish('rollback-new-file','next.bin','new-file.bin')
        publish('rollback-document-initial','first.bin','document.bin')
        spec={'operation_id':'rollback-document','target_locator':'document.bin','input_binding':'payload',
            'expected_current_digest':digest(before),'idempotency_key':'rollback-new-version'}
        specpath=root/'source/version.json';specpath.write_text(json.dumps(spec,sort_keys=True),encoding='utf-8')
        version=cli('rollback-new-version',['execute','--contract','publish_new_version.v1@1.0.0','--candidate',specpath,
            '--evidence-root',root/'evidence','--run-id','rollback-new-version','--input','payload='+str(root/'source/next.bin'),
            '--root','fixture_result_root='+str(root/'target'),'--timestamp','2026-10-24T00:00:00Z'])
        bundle=cli('rollback-new-bundle',['publish-bundle','--source-root',root/'source','--target-root',root/'target',
            '--target-locator','bundle','--member','first.bin','--member','next.bin','--preparation-root',root/'preparation',
            '--evidence-root',root/'evidence','--request-id','rollback-new-bundle','--run-id','rollback-new-bundle','--publication-version','1.0'])
        inspect('candidate-inspect-new',new_result);inspect('candidate-inspect-version',version,'fixture_result_root');inspect('candidate-inspect-bundle',bundle)
        archive='archive/sha256/'+hashlib.sha256(before).hexdigest()[:2]+'/'+hashlib.sha256(before).hexdigest()
        require((root/'target'/archive).read_bytes()==before and (root/'target/document.bin').read_bytes()==after,'version/archive bytes mismatch')
        new_snapshot=snapshot(protected);report['before_rollback_snapshot']=new_snapshot
        stage='old-after';install(oldwheel,old,'1.1.0',193)
        require(snapshot(protected)==new_snapshot,'runtime rollback modified managed data')
        for name,result,binding in [('old-after-inspect-old',old_result,'phase_result_root'),
                ('old-after-inspect-new',new_result,'phase_result_root'),('old-after-inspect-version',version,'fixture_result_root'),
                ('old-after-inspect-bundle',bundle,'phase_result_root')]:inspect(name,result,binding)
        require(snapshot(protected)==new_snapshot,'old read-only inspection changed managed data')
        returned=publish('rollback-old-after','first.bin','old-after.bin');inspect('old-after-inspect-returned',returned)
        final=snapshot(protected)
        require(all(final.get(k)==v for k,v in new_snapshot.items()),'old resumed write changed prior managed objects')
        require((root/'target/old-first.bin').read_bytes()==before and (root/'target/new-file.bin').read_bytes()==after
            and (root/'target/canary.bin').read_bytes()==b'owned synthetic rollback canary','preserved bytes mismatch')
        require((root/'target/old-after.bin').read_bytes()==before and (root/'source/first.bin').read_bytes()==before
            and (root/'source/next.bin').read_bytes()==after,'resumed publication/source bytes mismatch')
        require((root/'target/bundle/first.bin').read_bytes()==before and (root/'target/bundle/next.bin').read_bytes()==after,'bundle bytes mismatch')
        require(list((root/'preparation').iterdir())==[],'unexpected retained preparation residue')
        report.update(success=True,sequence=['1.1.0','1.2.0rc1','1.1.0'],historical_inspection=True,
            prior_managed_objects_preserved=True,old_runtime_resumed=True,final_snapshot=final)
    except BaseException as error:
        report.update(success=False,failed_stage=stage,error_type=type(error).__name__,error='rollback smoke failed')
        try:report['error']=str(error)[:4000]
        except BaseException:pass
        raise
    finally:
        with (root/'summary.json').open('x',encoding='utf-8') as stream:json.dump(report,stream,sort_keys=True,indent=2)
    return report


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--wheel',type=Path,required=True);parser.add_argument('--lock',type=Path,required=True)
    args=parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true' and sys.platform.startswith('linux')
        and sys.version_info[:2]==(3,11) and os.geteuid()!=0,'nonroot CPython3.11 Linux GitHub CI only')
    root,wheel,runtime=validate_layout(args.root,args.wheel,Path(os.environ['RUNNER_TEMP']),Path(os.environ['EVIDENCE']))
    lock=checked_path(args.lock,exists=True)
    require(lock==Path(os.environ['GITHUB_WORKSPACE'])/'docker/requirements.lock','fixed dependency lock required')
    identity=(wheel.parent.parent/'git-identity.txt').read_text().splitlines();head=os.environ['EXPECTED_HEAD']
    require(len(identity)==2 and identity[0]==head and re.fullmatch('[0-9a-f]{40}',head) is not None,'exact candidate HEAD required')
    report=execute(root,wheel,runtime,lock,head)
    print(json.dumps({k:report[k] for k in ('success','scope','sequence','historical_inspection','prior_managed_objects_preserved','old_runtime_resumed')},sort_keys=True))


if __name__=='__main__':main()
