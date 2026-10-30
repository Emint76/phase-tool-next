"""Read-only re-observation of the one fixed H03 target; ext4 evidence archival."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback

CAMPAIGN='936b34d0-4f82-4558-b26e-9a206f20af88'
RAW='3bc867baddfcb8b49a9a74a5854f21d39dece7f7e10b6f66163dcea59e56f06b'
LINUX=r'''
import json,os,traceback
from pathlib import Path
from phase_tool.bundle import verify_bundle
from phase_tool.canonical import digest_bytes
expected=json.load(__import__('sys').stdin)
target=Path('/ntfs/transport-cases/nt-native-v2/h03-r00/target')
result={}
def capture(name,operation):
 try: result[name]={'value':operation()}
 except Exception as e: result[name]={'error':str(e),'traceback':traceback.format_exc()}
def identity(info): return {'device':info.st_dev,'inode':info.st_ino}
def fresh_descriptor():
 fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
 try: return identity(os.fstat(fd))
 finally: os.close(fd)
capture('named_identity',lambda:identity(target.stat()))
capture('fresh_descriptor_identity',fresh_descriptor)
capture('owner_digest',lambda:digest_bytes((target/'phase-owner.json').read_bytes()))
capture('manifest_digest',lambda:digest_bytes((target/'phase-bundle.json').read_bytes()))
capture('parent_identity',lambda:identity(target.parent.stat()))
def verify():
 verify_bundle(target,expected['manifest_digest'],run_id='h03-r00',plan_digest=expected['owner']['plan_digest'])
 return 'verified'
capture('unchanged_bundle_verifier',verify)
print(json.dumps(result,sort_keys=True))
'''

def require(value,message):
    if not value: raise RuntimeError(message)

def main():
    require(not sys.flags.optimize,'optimized diagnostic forbidden')
    repo=Path.cwd()
    spec=importlib.util.spec_from_file_location('controller',repo/'qualification/campaign.py')
    controller=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    provisional=repo.parent/'qualification-campaigns'/CAMPAIGN
    state=json.loads((provisional/'state.json').read_bytes())
    require(state['campaign']==CAMPAIGN and state['owner']==controller.OWNER,'wrong campaign ownership')
    raw=(provisional/'g-h03-linux-native-1792576581638087600.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==RAW,'prior raw binding mismatch')
    expected=json.loads(raw)['records'][0]['linux_messages'][0]
    record={'case':'H03_READONLY','campaign':CAMPAIGN,'prior_raw_digest':'sha256:'+RAW,
            'harness_digest':'sha256:'+hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'expected':expected,'observations':{},'property_verdict':'NOT_VERIFIED',
            'phase_route_verdict':'NOT_VERIFIED'}
    try:
        for role in ('worker','verifier'):
            try:
                identifier=controller.verify_owned(state,read_only=role=='verifier')
                observed=json.loads(controller.docker('exec','-i',identifier,'/opt/phase/bin/python','-B','-c',LINUX,
                                                      payload=json.dumps(expected).encode(),timeout=30))
                record['observations'][role]=observed
            except Exception as error:
                record['observations'][role]={'error':str(error),'traceback':traceback.format_exc()}
        wanted={'named_identity':expected['stage_identity'],
                    'fresh_descriptor_identity':expected['stage_identity'],
                    'parent_identity':expected['parent_identity'],
                    'owner_digest':expected['owner_digest'],
                    'manifest_digest':expected['manifest_digest'],
                    'unchanged_bundle_verifier':'verified'}
        require(all(observed=={key:{'value':value} for key,value in wanted.items()}
                    for observed in record['observations'].values()),'read-only mismatch')
        record['property_verdict']='SUPPORTED'
    except Exception as error:
        record.update(error=str(error),traceback=traceback.format_exc())
    name='g-h03-readonly-'+str(time.time_ns())
    binding=controller.retain(state,provisional,record,name)
    state['records'].append(binding|{'action':'h03-readonly','lane':'MIX','result':{
        'property_verdict':record['property_verdict'],'phase_route_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'property_verdict':record['property_verdict'],'error':record.get('error')},indent=2))

if __name__=='__main__': main()
