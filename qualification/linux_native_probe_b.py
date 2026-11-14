"""H03B: close Linux stage FD, native pin/commit, unchanged bundle verifier.

Fixed campaign, no delete, no network listener, no arbitrary commands/roots.
All long-lived evidence is archived by unchanged Phase/ext4 after this L1 test.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import traceback

CAMPAIGN='936b34d0-4f82-4558-b26e-9a206f20af88'
REPO=Path.cwd()  # Execute from the explicitly selected next source checkout.
PROVISIONAL=REPO.parent/'qualification-campaigns'/CAMPAIGN
REVIEWED_NATIVE='7bacdc37efd02e6ac42aa0d6d473413e2a14f9eaf556bd5d58cfa91716d23df5'

LINUX=r'''
import hashlib,json,os,sys,traceback,signal
from pathlib import Path
from phase_tool.bundle import verify_bundle,MANIFEST_NAME,OWNER_NAME
from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.mutation.posix.authority import PosixTargetAuthority,PosixTargetRootLock
def require(value,message):
 if not value: raise RuntimeError(message)
require(not sys.flags.optimize,'optimized probe forbidden')
signal.alarm(60) # Own peer self-watchdog; never a container/VM/global kill.
campaign='936b34d0-4f82-4558-b26e-9a206f20af88'
root=Path('/ntfs/transport-cases/nt-native-v3')
token=json.loads((root.parent/'.campaign-owner.json').read_bytes())
require(token=={'owner':'phase-ntfs-qualification','campaign':campaign},'Linux root ownership')
index=int(sys.argv[1]); require(0<=index<10,'invalid case index')
parent=root/f'h03b-r{index:02}'
require(parent.is_dir() and not any(parent.iterdir()),'nonempty Linux case root')
run=f'h03b-r{index:02}'
plan='sha256:'+hashlib.sha256(run.encode()).hexdigest()
def identity(info): return {'device':info.st_dev,'inode':info.st_ino}
def emit(value): print(json.dumps(value,sort_keys=True),flush=True)
authority=stage_fd=None
with PosixTargetRootLock(parent,'h03'):
 try:
  authority=PosixTargetAuthority(parent,'target',expected_root_identity=(parent.stat().st_dev,parent.stat().st_ino),create_parents=False)
  os.mkdir('source',0o700,dir_fd=authority.parent_fd)
  stage=parent/'source'
  stage_fd=os.open('source',os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY,dir_fd=authority.parent_fd)
  stage_identity=identity(os.fstat(stage_fd))
  records=[]
  for i in range(16):
   name=f'd{i%2}/nested/m{i:02}.bin'
   path=stage/name
   path.parent.mkdir(parents=True,exist_ok=True)
   data=hashlib.sha256(f'phase-h03|{index}|{i}'.encode()).digest()*2048
   with path.open('xb') as f:
    f.write(data);f.flush();os.fsync(f.fileno())
   records.append({'path':name,'length':len(data),'digest':digest_bytes(data)})
  (stage/'empty.bin').open('xb').close()
  records.append({'path':'empty.bin','length':0,'digest':digest_bytes(b'')})
  manifest=canonical_bytes({'bundle_version':'1.0','members':sorted(records,key=lambda i:i['path'].encode()),'total_length':16*65536})
  owner=canonical_bytes({'owner_version':'1.0','run_id':run,'plan_digest':plan,**stage_identity})
  for name,data in [(MANIFEST_NAME,manifest),(OWNER_NAME,owner)]:
   with (stage/name).open('xb') as f:
    f.write(data);f.flush();os.fsync(f.fileno())
  for directory,_,_ in os.walk(stage,topdown=False):
   fd=os.open(directory,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
   try: os.fsync(fd)
   finally: os.close(fd)
  digest=digest_bytes(manifest)
  verify_bundle(stage,digest,run_id=run,plan_digest=plan)
  authority.assert_namespace_binding()
  os.fsync(stage_fd)
  os.close(stage_fd)
  stage_fd=None
  start_time=Path('/proc/self/stat').read_text().split(') ',1)[1].split()[19]
  emit({'phase':'ready','pid':os.getpid(),'process_start_time':start_time,
        'parent_identity':identity(os.fstat(authority.parent_fd)),
        'stage_identity':stage_identity,'linux_stage_fd_closed':True,
        'manifest':json.loads(manifest),'manifest_digest':digest,
        'owner':json.loads(owner),'owner_digest':digest_bytes(owner)})
  message=json.loads(sys.stdin.readline())
  require(message=={'operation':'observe'},'invalid peer command')
  target=authority.target
  observations={}
  def capture(name,operation):
   try: observations[name]={'value':operation()}
   except Exception as e: observations[name]={'error':str(e),'traceback':traceback.format_exc()}
  def verify():
   verify_bundle(target,digest,run_id=run,plan_digest=plan)
   return 'verified'
  def fresh():
   fd=os.open('target',os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY,dir_fd=authority.parent_fd)
   try: return identity(os.fstat(fd))
   finally: os.close(fd)
  capture('namespace_binding',authority.assert_namespace_binding)
  capture('real_parent_fsync',authority.fsync_parent)
  capture('bundle_verifier',verify)
  capture('parent_identity',lambda:identity(os.fstat(authority.parent_fd)))
  capture('target_identity',lambda:identity(target.stat()))
  capture('fresh_target_identity',fresh)
  capture('source_exists',stage.exists)
  emit({'phase':'observation','operations':observations})
 finally:
  if stage_fd is not None: os.close(stage_fd)
  if authority is not None: authority.close()
'''

def require(value,message):
    if not value:
        raise RuntimeError(message)

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def reader(stream,output):
    try:
        for line in stream:
            output.put(line)
    finally:
        output.put(None)

def receive(output):
    line=output.get(timeout=30)
    if line is None:
        raise RuntimeError('Linux peer EOF')
    if len(line)>65536:
        raise RuntimeError('oversized Linux observation')
    return json.loads(line)

def main():
    require(not sys.flags.optimize,'optimized host probe forbidden')
    probe_path=Path(__file__).with_name('native_rename_probe_v3.py')
    require(hashlib.sha256(probe_path.read_bytes()).hexdigest()==REVIEWED_NATIVE,'native artifact changed')
    native=module('reviewed_native_probe',probe_path)
    native.ownership()
    controller=module('reviewed_campaign_controller',REPO/'qualification/campaign.py')
    state=json.loads((PROVISIONAL/'state.json').read_bytes())
    require(state['campaign']==CAMPAIGN,'wrong campaign')
    require(any(r.get('action')=='h02-v3' and r['result']['primitive_verdict']=='SUPPORTED' for r in state['records']),
            'H02 prerequisite absent')
    worker=controller.verify_owned(state)
    controller.verify_owned(state,read_only=True)
    started=time.time_ns()
    record={'campaign':CAMPAIGN,'case':'H03B','lane':'MIX','requested_repeats':10,
            'completed_repeats':0,'records':[],
            'harness_digest':'sha256:'+hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'native_digest':'sha256:'+REVIEWED_NATIVE,'source_commit':state['source_commit'],
            'environment_freeze':state['records'][0],
            'primitive_verdict':'NOT_VERIFIED','phase_route_verdict':'NOT_VERIFIED'}
    try:
        for i in range(10):
            parent=native.PROBE/f'h03b-r{i:02}'
            native.checked(parent,exists=False)
            parent.mkdir(exist_ok=False)
            item={'repeat':i,'parent':str(parent),'linux_messages':[],'unknown_native_outcome':True}
            record['records'].append(item)
            process=subprocess.Popen(['docker','exec','-i',worker,'/opt/phase/bin/python','-B','-u','-c',LINUX,str(i)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            observations=queue.Queue()
            errors=queue.Queue()
            threads=[threading.Thread(target=reader,args=(process.stdout,observations),daemon=True),
                     threading.Thread(target=reader,args=(process.stderr,errors),daemon=True)]
            for thread in threads: thread.start()
            try:
                ready=receive(observations)
                item['linux_messages'].append(ready)
                require(ready['phase']=='ready','Linux peer not ready')
                require(ready['linux_stage_fd_closed'] is True,'Linux stage fd not closed')
                event=native.do_rename(parent,'source','target')
                item['native_event']=event
                item['unknown_native_outcome']=False
                process.stdin.write(b'{"operation":"observe"}\n')
                process.stdin.flush()
                observed=receive(observations)
                item['linux_messages'].append(observed)
                require(observed['phase']=='observation','invalid Linux observation')
                code=process.wait(timeout=30)
                item['linux_exit_code']=code
                require(code==0,'Linux peer exit failure')
                require(event['success'], 'native commit failed with Linux directory handles')
                wanted={'namespace_binding':None,'real_parent_fsync':None,'bundle_verifier':'verified',
                        'parent_identity':ready['parent_identity'],'target_identity':ready['stage_identity'],
                        'fresh_target_identity':ready['stage_identity'],'source_exists':False}
                require(observed['operations']=={key:{'value':value} for key,value in wanted.items()},
                        'Linux namespace/fsync/bundle/identity observation failed')
                target=parent/'target'
                native.checked(target)
                expected={m['path']:m for m in ready['manifest']['members']}
                expected.update({name:None for name in ('phase-owner.json','phase-bundle.json')})
                actual={p.relative_to(target).as_posix():p for p in target.rglob('*') if p.is_file()}
                require(set(actual)==set(expected),'Windows membership differs')
                for name,path in actual.items():
                    native.checked(path)
                    data=path.read_bytes()
                    if expected[name] is not None:
                        require(native.sha(data)==expected[name]['digest'] and len(data)==expected[name]['length'],
                                'Windows member mismatch')
                    else:
                        key='owner_digest' if name=='phase-owner.json' else 'manifest_digest'
                        require(native.sha(data)==ready[key],'Windows metadata mismatch')
                require(target.stat().st_ino==event['source_before']['file_id'],'Windows target identity mismatch')
                item['independent_windows_readback']=True
            except Exception as exc:
                item['primary_error']={'error':str(exc),'traceback':traceback.format_exc()}
                raise
            finally:
                finalization_errors=[]
                item['finalization_errors']=finalization_errors
                try:
                    if process.stdin:
                        process.stdin.close()
                    if process.poll() is None:
                        # EOF and the peer's own 60s alarm bound this session.
                        process.wait(timeout=65)
                except Exception as exc:
                    finalization_errors.append({'phase':'peer_eof_wait','error':str(exc)})
                    if process.poll() is None:
                        try:
                            process.terminate() # Exact own docker exec client only.
                            process.wait(timeout=10)
                        except Exception as cleanup_error:
                            finalization_errors.append({'phase':'client_termination','error':str(cleanup_error)})
                item['linux_exit_code']=process.returncode
                try:
                    # Independently confirm the exact Linux PID/start-time is gone.
                    controller.verify_owned(state)
                    ready_items=[m for m in item['linux_messages'] if m.get('phase')=='ready']
                    require(len(ready_items)==1,'missing peer identity; peer cleanup not established')
                    peer=ready_items[0]
                    require(type(peer['pid']) is int and peer['pid']>1,'invalid own peer PID')
                    query="import json,sys;from pathlib import Path;p=Path('/proc')/sys.argv[1]/'stat';print(json.dumps({'current':p.read_text().split(') ',1)[1].split()[19] if p.exists() else None}))"
                    metadata=json.loads(controller.docker('exec',worker,'/opt/phase/bin/python','-B','-c',
                                            query,str(peer['pid']),timeout=20))
                    item['peer_after']=metadata
                    require(metadata['current']!=peer['process_start_time'],'own Linux peer remains alive')
                except Exception as exc:
                    finalization_errors.append({'phase':'peer_absence','error':str(exc)})
                try:
                    for thread in threads: thread.join(timeout=2)
                    item['stderr']=[]
                    while not errors.empty():
                        value=errors.get_nowait()
                        if value is not None: item['stderr'].append(value.decode('utf-8','replace'))
                    while not observations.empty():
                        value=observations.get_nowait()
                        if value is not None: item.setdefault('remaining_stdout',[]).append(value.decode('utf-8','replace'))
                    require(not any(thread.is_alive() for thread in threads),'reader threads remain alive')
                except Exception as exc:
                    finalization_errors.append({'phase':'reader_finalization','error':str(exc)})
            require(not item['finalization_errors'],'peer finalization not established')
            require(item['linux_exit_code']==0,'peer nonzero exit')
            record['completed_repeats']=i+1
        record['primitive_verdict']='SUPPORTED'
    except Exception as exc:
        record.update(error=str(exc),traceback=traceback.format_exc())
    record['native_events']=native.NATIVE_EVENTS
    binding=controller.retain(state,PROVISIONAL,record,'g-h03b-linux-native-'+str(started))
    state['records'].append(binding|{'action':'h03b-v3','lane':'MIX','result':{
        'primitive_verdict':record['primitive_verdict'],'phase_route_verdict':'NOT_VERIFIED',
        'completed_repeats':record['completed_repeats']}})
    controller.update_state(PROVISIONAL/'state.json',state)
    print(json.dumps(binding|{'primitive_verdict':record['primitive_verdict'],
        'phase_route_verdict':'NOT_VERIFIED','completed':record['completed_repeats'],
        'error':record.get('error')},indent=2))

if __name__=='__main__':
    main()
