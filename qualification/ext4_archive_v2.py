"""Own ext4-only Phase1.1 archival, independent of reparse test fixtures.

This controller generation does not scan the L1 result tree: A05 deliberately
creates reparse objects there. It checks all actual write roots and invokes
unchanged Phase functions from a frozen read-only artifact. No admission guard,
profile, registry, provider or production allowlist is modified.
"""
import json
import re

PROGRAM=r'''
import hashlib,importlib.util,json,os,sys,zipfile,stat
from pathlib import Path
from phase_tool.installation import _linux_filesystem_type
campaign,name,action=sys.argv[1:]
def require(value,message):
 if not value: raise RuntimeError(message)
require(not sys.flags.optimize,'optimized archival forbidden')
require(campaign=='936b34d0-4f82-4558-b26e-9a206f20af88','wrong campaign')
require(__import__('re').fullmatch('[a-z][a-z0-9-]{0,60}',name) is not None,'bad run id')
require(action in ('archive','inspect'),'unsupported archival action')
import phase_tool
wheel=Path('/artifacts/phase_tool-1.1.0-py3-none-any.whl')
require(hashlib.sha256(wheel.read_bytes()).hexdigest()=='9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a','reference wheel changed')
package=Path(phase_tool.__file__).parent
with zipfile.ZipFile(wheel) as archive:
 expected={name:hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()
           if name.startswith('phase_tool/') and not name.endswith('/')}
actual={'phase_tool/'+p.relative_to(package).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for p in package.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
require(actual==expected,'installed Phase differs from official wheel')
used=0
def scan_error(error): raise error
for value in ('records','preparation','evidence'):
 root=Path('/qualification')/value
 require(str(root)==str(root.resolve(strict=True)),'noncanonical archival root')
 require(_linux_filesystem_type(root)=='ext4','archival requires existing ext4')
 fs=os.statvfs(root)
 require(fs.f_bavail*fs.f_frsize>=4*1024**3,'ext4 archival reserve unavailable')
 token_path=root/'.campaign-owner.json'
 token_fd=os.open(token_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(token_fd)
  require(stat.S_ISREG(info.st_mode) and info.st_size<=4096,'invalid owner token file')
  token=json.loads(os.read(token_fd,4097))
  named=token_path.lstat()
  require((info.st_dev,info.st_ino)==(named.st_dev,named.st_ino),'owner token rebound')
 finally: os.close(token_fd)
 require(token=={'owner':'phase-ntfs-qualification','campaign':campaign},'archival root owner')
 fd=os.open(root,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
 try:
  opened=os.fstat(fd);named=root.stat()
  require((opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino),'archival root identity changed')
 finally: os.close(fd)
 for directory,dirs,files in os.walk(root,followlinks=False,onerror=scan_error):
  for entry_name in (*dirs,*files):
   info=(Path(directory)/entry_name).lstat()
   require(not stat.S_ISLNK(info.st_mode),'link in ext4 archival root')
   if stat.S_ISREG(info.st_mode): used+=info.st_size
require(used<256*1024**2,'small-stage ext4 archival budget exhausted')
path=Path('/artifacts/transport_gates.py')
require(hashlib.sha256(path.read_bytes()).hexdigest()=='b61c57cfaa97d0568acc9da35d3f26b597c3b6089f4952c8e1639e2495e72e92','archival implementation changed')
spec=importlib.util.spec_from_file_location('frozen_ext4_archive',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
if action=='archive':
 payload=sys.stdin.buffer.read(16*1024**2+1)
 require(len(payload)<=16*1024**2,'report limit')
 require(used+5*len(payload)+1024**2<256*1024**2,'archive peak exceeds small-stage budget')
 json.loads(payload)
 result=module.archive(payload,name)
else: result=module.inspect_archive(name)
print(json.dumps(result,sort_keys=True))
'''

def retain(controller,state,provisional,record,name):
    require=controller.require
    require(state['campaign']=='936b34d0-4f82-4558-b26e-9a206f20af88' and state['owner']==controller.OWNER,
            'unexpected archival campaign')
    require(re.fullmatch('[a-z][a-z0-9-]{0,60}',name) is not None,'invalid archival name')
    raw=json.dumps(record,sort_keys=True).encode('utf-8')
    require(len(raw)<=16*1024**2,'report input limit')
    controller.reserve()
    controller.save_exclusive(provisional/(name+'.json'),raw)
    worker=controller.verify_owned(state)
    publication=json.loads(controller.docker('exec','-i',worker,'/opt/phase/bin/python','-B','-c',
        PROGRAM,state['campaign'],name,'archive',payload=raw,timeout=120))
    controller.save_exclusive(provisional/(name+'-publication.json'),publication)
    p=publication['publication']
    require(p['success'] is True and p['target_verified'] is True and p['status']=='verified'
            and p['exit_code']==0,'Phase archival failed')
    require(p['run_id']==name and p['contract_binding']=='file_create.v2@1.0.0','wrong archival binding')
    require(p['content_digest']==publication['input_digest']==controller.sha(raw)
            and p['content_length']==len(raw) and p['receipt_digest'],'archival bytes mismatch')
    verifier=controller.verify_owned(state,read_only=True)
    observed=json.loads(controller.docker('exec',verifier,'/opt/phase/bin/python','-B','-c',
        PROGRAM,state['campaign'],name,'inspect',timeout=120))
    controller.save_exclusive(provisional/(name+'-independent-inspection.json'),observed)
    i=observed['inspection']
    require(i['success'] is True and i['target_verified'] is True
            and i['receipt_digest']==p['receipt_digest'],'independent archival inspect failed')
    require(observed['readback_digest']==controller.sha(raw) and observed['length']==len(raw),
            'independent archival readback mismatch')
    return {'run_id':name,'receipt_digest':p['receipt_digest'],'input_digest':controller.sha(raw),
            'independent_inspect':True,'archival_controller':'ext4-only-v2'}
