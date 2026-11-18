"""Bounded L1 file effects of reviewed NativeMutationIO; not Phase lifecycle.

Fixed owned campaign, ten independent synthetic cases, no general dispatcher.
The only deletion is one still-open created temporary link, after its verified
hardlink exists. Replaced files are own L1 fixtures. Flush fault is explicitly
synthetic and never represented as a filesystem-produced failure.
"""
from contextlib import ExitStack
import base64
import ctypes as C
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback

import native_io_probe as common

MUTATING='b1b19f763de31fb3b8077b595207d37ef4c921397266cba5edb53594996c379a'
COMMON='b829c6d0b0126fd166303d0df6d9b2a2c368d32c9715168b1650450d99c6a78f'
CASE='native-file-effects-v2'
require=common.require

def main():
 require(not sys.flags.optimize,'optimized probe forbidden')
 folder=Path(__file__).parent
 require(hashlib.sha256((folder/'native_io_probe.py').read_bytes()).hexdigest()==COMMON,'common drift')
 native=common.load('owned_native',folder/'native_rename_probe_v3.py',common.NATIVE);native.ownership()
 module=common.product_module(folder)
 mutation=common.load('phase_tool.mutation.ntfs.mutating',folder/'product/mutating_v2.py',MUTATING)
 controller=common.load('controller',Path.cwd()/'qualification/campaign.py')
 archive=common.load('archive',folder/'ext4_archive_v2.py',common.ARCHIVE)
 provisional=Path.cwd().parent/'qualification-campaigns'/common.CAMPAIGN
 state=json.loads((provisional/'state.json').read_bytes())
 require(state['owner']==controller.OWNER and state['campaign']==common.CAMPAIGN,'wrong campaign')
 controller.verify_owned(state);controller.verify_owned(state,read_only=True)
 io,old=mutation.NativeMutationIO(),native.Native()
 case=native.PROBE/CASE;native.checked(case,exists=False);case.mkdir(exist_ok=False)
 sentinel=case/'sentinel.bin';sentinel_data=hashlib.sha256(b'file-effects-sentinel').digest()*2048
 sentinel.open('xb').write(sentinel_data);sentinel_before=common.raw_metadata(old,sentinel)
 record={'case':'NATIVE_FILE_EFFECTS_V2','campaign':common.CAMPAIGN,
  'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
  'harness_digest':controller.sha(Path(__file__).read_bytes()),'primitive_verdict':'NOT_VERIFIED',
  'phase_route_verdict':'NOT_VERIFIED','a05_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED',
  'requested':10,'records':[],'sentinel_before':sentinel_before}
 record['source_snapshot']=[{'name':name,'sha256':hashlib.sha256(data).hexdigest(),
  'bytes_base64':base64.b64encode(data).decode('ascii')} for name in
  ('native_file_effects_probe_v2.py','native_io_probe.py','product/native.py','product/mutating_v2.py',
   'native_rename_probe_v3.py','ext4_archive_v2.py') for data in [(folder/name).read_bytes()]]
 def rejected(action,code):
  before=len(io.events)
  try: action()
  except module.PhaseError as error:
   require(error.code==code,'wrong rejection: '+error.code)
   return {'code':error.code,'details':error.details,'new_events':len(io.events)-before}
  raise RuntimeError('unexpected acceptance')
 try:
  with ExitStack() as stack:
   root=stack.enter_context(io.open_device_root(io.volume()))
   for part in ('Phase-NTFS-Qualification',common.CAMPAIGN,'transport-cases','nt-native-v3',CASE):
    root=stack.enter_context(io.child(root,part,directory=True))
   for ordinal in range(10):
    path=case/f'r{ordinal:02}';path.mkdir()
    row={'ordinal':ordinal,'completed':False};record['records'].append(row)
    start=len(io.events);temporary=None;replacement=None
    with io.child(root,path.name,directory=True,namespace_flush=True) as parent:
     parent_id=io.identity(parent)
     first=hashlib.sha256(f'first|{ordinal}'.encode()).digest()*2048
     second=hashlib.sha256(f'second|{ordinal}'.encode()).digest()*2048
     try:
      temporary=io.create_exclusive(parent,'temporary.bin',directory=False,expected_parent=parent_id,delete_access=True)
      first_id=io.identity(temporary)
      require(io.write_chunk(temporary,first,offset=0,expected=first_id)==len(first),'short initial write')
      io.flush_file(temporary,first_id)
      require(io.hash_file(temporary,len(first))==(controller.sha(first),len(first)),'first bytes not bound')
      row['hardlink']=io.hardlink_noreplace(temporary,parent,'current.bin',expected_source=first_id,expected_parent=parent_id)
      require(common.raw_metadata(old,path/'current.bin')['native_identity']==first_id.as_dict(),'hardlink identity mismatch')
      with io._open('current.bin',parent=parent,directory=False,sharing=7) as observer:
       require(io.hash_file(observer,len(first))==(controller.sha(first),len(first)),'hardlink bytes mismatch')
      row['temporary_cleanup']=io.delete_created_link_and_close(temporary,first_id)
      require(temporary.finalization_state=='closed' and not (path/'temporary.bin').exists(),'temporary link not consumed')
      require((path/'current.bin').read_bytes()==first,'published hardlink removed')
      require(common.raw_metadata(old,path/'current.bin')['native_identity']==first_id.as_dict(),'cleanup changed object')
      row['closed_handle_checks']=[rejected(action,'ntfs.invalid_or_closed_handle') for action in (
       lambda:io.identity(temporary),lambda:io.hash_file(temporary,len(first)),
       lambda:io.write_chunk(temporary,b'x',offset=0,expected=first_id),
       lambda:io.delete_created_link_and_close(temporary,first_id))]
      require(all(v['new_events']==0 for v in row['closed_handle_checks']),'closed handle attempted syscall')
      temporary=None
      replacement=io.create_exclusive(parent,'replacement.bin',directory=False,expected_parent=parent_id,delete_access=True)
      second_id=io.identity(replacement)
      require(io.write_chunk(replacement,second,offset=0,expected=second_id)==len(second),'short replacement write')
      io.flush_file(replacement,second_id)
      with io._open('current.bin',parent=parent,directory=False,sharing=7) as old_reader:
       row['old_reader_before']=io.identity(old_reader).as_dict()
       require(row['old_reader_before']==first_id.as_dict(),'old reader initial identity mismatch')
       row['replace']=io.rename(replacement,parent,'current.bin',expected_source=second_id,
                                expected_parent=parent_id,replace=True)
       require(row['replace']['class']==65 and row['replace']['rename_flags']==3,'wrong replacement API/flags')
       io.flush_namespace(parent,parent_id)
       require(io.hash_file(old_reader,len(first))==(controller.sha(first),len(first)),'old-reader bytes changed')
       row['old_reader_after']=io.identity(old_reader).as_dict()
       require(row['old_reader_after']==first_id.as_dict(),'old reader identity changed')
       with io._open('current.bin',parent=parent,directory=False,sharing=7) as fresh:
        require(io.identity(fresh)==second_id,'replacement name not bound')
        require(io.hash_file(fresh,len(second))==(controller.sha(second),len(second)),'replacement bytes mismatch')
      row['rename_cleanup_rejected']=rejected(
       lambda:io.delete_created_link_and_close(replacement,second_id),'ntfs.created_delete_lease_required')
      require(row['rename_cleanup_rejected']['new_events']==0,'published source cleanup attempted')
      # Explicit software fault injection: no real flush is called for this
      # event; raw return/IOS are controlled and labelled, not filesystem evidence.
      original=io.nt.NtFlushBuffersFileEx
      fault={'synthetic':True,'real_api_called':False,'calls':0,'native_event_index':len(io.events)}
      row['flush_fault']=fault
      def injected(handle,flags,parameters,size,ios):
       require(handle==replacement.value and flags==0 and parameters is None and size==0,'wrong flush injection target')
       fault['calls']+=1
       require(fault['calls']==1,'duplicate injected flush')
       C.cast(ios,C.POINTER(module._IoStatus)).contents.Result.Status=-1073741435 # C0000185 IO_DEVICE_ERROR
       return -1073741435
      io.nt.NtFlushBuffersFileEx=injected
      try:
       row['flush_error']=rejected(lambda:io.flush_file(replacement,second_id),'ntfs.flush_failed')
      finally:io.nt.NtFlushBuffersFileEx=original
      require(fault['calls']==1 and row['flush_error']['new_events']==1,'fault not propagated')
      require(io.events[fault['native_event_index']]['accepted'] is False,'synthetic failure accepted')
      require(io.hash_file(replacement,len(second))==(controller.sha(second),len(second)),'flush error changed bytes')
      row['real_flush_after_fault']=io.flush_file(replacement,second_id)
      row['collision']=rejected(lambda:io.create_exclusive(parent,'current.bin',directory=False,
                                       expected_parent=parent_id),'ntfs.create_failed')
      require(row['collision']['details']['event']['return_status']=='0xc0000035','not an actual create collision')
      require((path/'current.bin').read_bytes()==second and not (path/'replacement.bin').exists(),'final named state mismatch')
      row.update(first_identity=first_id.as_dict(),second_identity=second_id.as_dict(),
                 first_digest=controller.sha(first),second_digest=controller.sha(second))
     except BaseException as error:
      row['primary_error']={'error':str(error),'details':getattr(error,'details',{}),'traceback':traceback.format_exc()}
      raise
     finally:
      errors=[]
      for handle in (replacement,temporary):
       if handle is not None and handle.finalization_state=='open':
        try:handle.close()
        except BaseException as error:errors.append(str(error))
       elif handle is not None and handle.finalization_state not in ('closed','open'):
        errors.append('unknown finalization')
      row['close_errors']=errors;row['native_events']=io.events[start:]
      if errors and not row.get('primary_error'):raise RuntimeError('file handle finalization failed')
     require(not row['close_errors'],'file handle finalization failed')
    row['completed']=True
   require(sentinel.read_bytes()==sentinel_data and common.raw_metadata(old,sentinel)==sentinel_before,'sentinel changed')
   record['sentinel_unchanged']=True
  require(not io._handles,'module handles leaked')
  record['primitive_verdict']='SUPPORTED'
 except BaseException as error:
  record.update(error=str(error),error_details=getattr(error,'details',{}),traceback=traceback.format_exc())
 record['all_native_events']=io.events;record['module_open_handle_count']=len(io._handles)
 name='g-native-file-effects-'+str(time.time_ns())
 binding=archive.retain(controller,state,provisional,record,name)
 completed=sum(v['completed'] for v in record['records'])
 state['records'].append(binding|{'action':'native-file-effects-v2','lane':'MIX','result':{
  'primitive_verdict':record['primitive_verdict'],'completed':completed,'phase_route_verdict':'NOT_VERIFIED'}})
 controller.update_state(provisional/'state.json',state)
 print(json.dumps(binding|{'primitive_verdict':record['primitive_verdict'],'completed':completed,
                          'error':record.get('error')},indent=2))

if __name__=='__main__':main()
