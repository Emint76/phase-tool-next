"""L1 candidate: real synchronous NTFS directory flush, flags=0 only.

Own synthetic files/directories, no volume handle, elevation, policy change,
delete or durability claim. API acceptance is not yet G06 qualification.
"""
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import traceback

CAMPAIGN='936b34d0-4f82-4558-b26e-9a206f20af88'
NATIVE='7bacdc37efd02e6ac42aa0d6d473413e2a14f9eaf556bd5d58cfa91716d23df5'
ARCHIVE='0b1461bcf4e91bcb026ab8ed8bef548891c63147afc9d663a582e607b8ea7984'
def require(value,message):
    if not value: raise RuntimeError(message)
def load(name,path,digest=None):
    if digest: require(hashlib.sha256(path.read_bytes()).hexdigest()==digest,'dependency changed')
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def main():
    require(not sys.flags.optimize,'optimized probe forbidden')
    folder=Path(__file__).parent
    native=load('native',folder/'native_rename_probe_v3.py',NATIVE)
    native.ownership()
    controller=load('controller',Path.cwd()/'qualification/campaign.py')
    archival=load('archive_v2',folder/'ext4_archive_v2.py',ARCHIVE)
    provisional=Path.cwd().parent/'qualification-campaigns'/CAMPAIGN
    state=json.loads((provisional/'state.json').read_bytes())
    require(state['owner']==controller.OWNER and state['campaign']==CAMPAIGN,'wrong campaign')
    controller.verify_owned(state);controller.verify_owned(state,read_only=True)
    root=native.PROBE/'native-flush-v1'
    native.checked(root,exists=False);root.mkdir(exist_ok=False)
    api=native.Native()
    api.nt.NtFlushBuffersFileEx.argtypes=[C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(native.IOS)]
    api.nt.NtFlushBuffersFileEx.restype=C.c_int32
    record={'case':'NATIVE_DIRECTORY_FLUSH','campaign':CAMPAIGN,'requested_repeats':10,
            'completed_repeats':0,'records':[],'phase_route_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED',
            'harness_digest':controller.sha(Path(__file__).read_bytes()),'native_digest':'sha256:'+NATIVE,
            'archival_digest':'sha256:'+ARCHIVE,'request_acceptance_verdict':'NOT_VERIFIED'}
    try:
        for i in range(10):
            parent=root/f'r{i:02}';parent.mkdir(exist_ok=False)
            directory=parent/'directory';directory.mkdir()
            payload=hashlib.sha256(f'native-flush|{i}'.encode()).digest()*2048
            file=directory/'member.bin'
            with file.open('xb') as stream:
                stream.write(payload);stream.flush();os.fsync(stream.fileno())
            expected={'file_id':file.stat().st_ino,'directory_id':directory.stat().st_ino,
                      'digest':controller.sha(payload),'length':len(payload)}
            item={'repeat':i,'expected':expected,'operations':[]};record['records'].append(item)
            expected_parent=api.win32_identity(parent)
            native_parent=api.native_path(parent)
            item.update(expected_parent=expected_parent,native_parent=native_parent)
            parent_handle=api.open(native_parent)
            directory_handle=None
            try:
                pinned_parent=api.info(parent_handle)
                item['pinned_parent']=pinned_parent
                require(all(pinned_parent[key]==expected_parent[key] for key in ('volume_serial','file_id')),
                        'native flush parent differs from granted Windows parent')
                require(api.native_path(parent)==native_parent,'DOS mapping changed during flush open')
                for kind,name,parent_fd,is_directory in (
                    ('directory','directory',parent_handle,True),
                    ('file','member.bin',None,False)):
                    selected=directory_handle if parent_fd is None else parent_fd
                    buffer=C.create_unicode_buffer(name);encoded=name.encode('utf-16-le')
                    text=native.USTR(len(encoded),len(encoded)+2,C.cast(buffer,C.c_void_p))
                    attrs=native.ATTR(C.sizeof(native.ATTR),selected,C.pointer(text),0x40|0x1000,None,None)
                    handle=C.c_void_p();ios=native.IOS()
                    opened=api.nt.NtOpenFile(C.byref(handle),0x100000|0x80|2,C.byref(attrs),C.byref(ios),3,
                                            0x20|0x200000|(1 if is_directory else 0x40))
                    event={'kind':kind,'open_status':f'0x{opened&0xffffffff:08x}',
                           'access':'SYNCHRONIZE|READ_ATTRIBUTES|WRITE_DATA_OR_ADD_FILE',
                           'open_options':'SYNCHRONOUS|OPEN_REPARSE_POINT|DIRECTORY_OR_NON_DIRECTORY'}
                    item['operations'].append(event)
                    if opened!=0:
                        require(not handle.value,'failed open returned handle')
                        raise native.NtFailure(opened,'flush probe NtOpenFile')
                    try:
                        info=api.info(handle.value);event['before']=info
                        require(not info['attributes']&0x400 and bool(info['attributes']&0x10)==is_directory,
                                'flush handle type/reparse mismatch')
                        require(info['file_id']==expected['directory_id' if is_directory else 'file_id'],
                                'flush handle identity mismatch')
                        require(info['volume_serial']==pinned_parent['volume_serial'],'flush handle volume mismatch')
                        result=native.IOS();started=time.monotonic_ns()
                        status=api.nt.NtFlushBuffersFileEx(handle.value,0,None,0,C.byref(result))
                        event.update(api='NtFlushBuffersFileEx',flags=0,parameters=None,parameters_size=0,
                                     status=f'0x{status&0xffffffff:08x}',io_status=f'0x{result.Result.Status&0xffffffff:08x}',
                                     started_ns=started,returned_ns=time.monotonic_ns())
                        event['after']=api.info(handle.value)
                        require(status==0 and result.Result.Status==0,'native flush request not accepted')
                        require(all(event['before'][key]==event['after'][key] for key in ('volume_serial','file_id')),
                                'flush object identity changed')
                        if is_directory:
                            directory_handle=handle.value;handle.value=None
                    except Exception as error:
                        event['primary_error']={'error':str(error),'traceback':traceback.format_exc()}
                        raise
                    finally:
                        if handle.value: api.close(handle.value)
                require(file.read_bytes()==payload and file.stat().st_ino==expected['file_id'],'flush fixture changed')
                require(sorted(p.name for p in directory.iterdir())==['member.bin'],'flush membership changed')
                item['readback_verified']=True
            except Exception as error:
                item['primary_error']={'error':str(error),'traceback':traceback.format_exc()}
                raise
            finally:
                errors=[]
                for value in (directory_handle,parent_handle):
                    if value is not None:
                        try: api.close(value)
                        except Exception as error: errors.append(str(error))
                item['close_errors']=errors
                require(not errors,'flush handle finalization failed')
            record['completed_repeats']=i+1
        record['request_acceptance_verdict']='SUPPORTED'
    except Exception as error:
        record.update(error=str(error),traceback=traceback.format_exc())
    name='g-native-flush-'+str(time.time_ns())
    binding=archival.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'native-flush-v1','lane':'MIX','result':{
        'request_acceptance_verdict':record['request_acceptance_verdict'],'g06_verdict':'NOT_VERIFIED',
        'phase_route_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'request_acceptance_verdict':record['request_acceptance_verdict'],
                             'completed':record['completed_repeats'],'error':record.get('error')},indent=2))

if __name__=='__main__': main()
