"""A05 second API: native SYMLINK tag via FSCTL, plus own-fixture inventory.

No privilege adjustment, registry setting, deletion, fallback writer or foreign
root. Reads only metadata of explicitly known owned synthetic campaign trees.
"""
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time
import traceback

CAMPAIGN='936b34d0-4f82-4558-b26e-9a206f20af88'
NATIVE='7bacdc37efd02e6ac42aa0d6d473413e2a14f9eaf556bd5d58cfa91716d23df5'
ARCHIVE='0b1461bcf4e91bcb026ab8ed8bef548891c63147afc9d663a582e607b8ea7984'
OWN_CAMPAIGNS=(CAMPAIGN,'08bed06b-3236-4a64-9972-ab92f0c51f81')

def require(value,message):
    if not value: raise RuntimeError(message)

def load(name,path,digest=None):
    if digest: require(hashlib.sha256(path.read_bytes()).hexdigest()==digest,'dependency hash mismatch')
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

class TAG(C.Structure):
    _fields_=[('attributes',C.c_uint32),('tag',C.c_uint32)]

def main():
    require(not sys.flags.optimize,'optimized probe forbidden')
    directory=Path(__file__).parent
    native=load('native',directory/'native_rename_probe_v3.py',NATIVE)
    native.ownership()
    controller=load('controller',Path.cwd()/'qualification/campaign.py')
    archival=load('archive_v2',directory/'ext4_archive_v2.py',ARCHIVE)
    provisional=Path.cwd().parent/'qualification-campaigns'/CAMPAIGN
    state=json.loads((provisional/'state.json').read_bytes())
    require(state['owner']==controller.OWNER and state['campaign']==CAMPAIGN,'wrong campaign')
    controller.verify_owned(state);controller.verify_owned(state,read_only=True)
    case=native.PROBE/'a05-native-tag-pilot-v1'
    native.checked(case,exists=False);case.mkdir(exist_ok=False)
    inside=case/'inside';inside.mkdir()
    outside=case/'outside-sentinel';outside.mkdir()
    sentinel=outside/'sentinel.bin'
    content=hashlib.sha256(b'phase-native-symlink-sentinel').digest()*2048
    with sentinel.open('xb') as stream: stream.write(content)
    record={'case':'A05_NATIVE_SYMLINK_FSCTL','campaign':CAMPAIGN,
            'harness_digest':controller.sha(Path(__file__).read_bytes()),
            'archival_digest':'sha256:'+ARCHIVE,'native_digest':'sha256:'+NATIVE,
            'a05_conformance_verdict':'NOT_VERIFIED','phase_route_verdict':'NOT_VERIFIED',
            'sentinel_before':{'file_id':sentinel.stat().st_ino,'digest':controller.sha(content)},
            'fixtures':[],'owned_reparse_inventory':[]}
    api=native.Native();k=api.k
    k.DeviceIoControl.argtypes=[C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,
                               C.POINTER(C.c_uint32),C.c_void_p]
    k.DeviceIoControl.restype=C.c_int32
    k.GetFileInformationByHandleEx.argtypes=[C.c_void_p,C.c_int,C.c_void_p,C.c_uint32]
    k.GetFileInformationByHandleEx.restype=C.c_int32
    def metadata(path):
        handle=k.CreateFileW(str(path),0x80,7,None,3,0x02000000|0x00200000,None)
        if handle in (None,C.c_void_p(-1).value): raise C.WinError(C.get_last_error())
        try:
            info=TAG()
            if not k.GetFileInformationByHandleEx(handle,9,C.byref(info),C.sizeof(info)):
                raise C.WinError(C.get_last_error())
            return {'attributes':info.attributes,'tag':f'0x{info.tag:08x}',**api.info(handle)}
        finally: api.close(handle)
    try:
        for is_directory in (False,True):
            item={'directory':is_directory,'api':'FSCTL_SET_REPARSE_POINT','requested_tag':'0xa000000c'}
            record['fixtures'].append(item)
            try:
                path=inside/('symlink-dir' if is_directory else 'symlink-file')
                if is_directory: path.mkdir(exist_ok=False)
                else: path.open('xb').close()
                expected=path.stat().st_ino
                handle=k.CreateFileW(str(path),0x40000000|0x80,7,None,3,0x02000000|0x00200000,None)
                if handle in (None,C.c_void_p(-1).value): raise C.WinError(C.get_last_error())
                try:
                    require(api.info(handle)['file_id']==expected,'new symlink object changed')
                    target='../outside-sentinel' if is_directory else '../outside-sentinel/sentinel.bin'
                    # SYMLINK_FLAG_RELATIVE=1; documented relative target only.
                    name=target.replace('/','\\').encode('utf-16-le')
                    names=name+b'\0\0'+name+b'\0\0'
                    data=struct.pack('<IHHHHHHI',0xa000000c,12+len(names),0,0,len(name),len(name)+2,len(name),1)+names
                    buffer=C.create_string_buffer(data);returned=C.c_uint32();C.set_last_error(0)
                    result=k.DeviceIoControl(handle,0x900a4,buffer,len(data),None,0,C.byref(returned),None)
                    item.update(success=bool(result),winerror=C.get_last_error() if not result else None,
                                relative_path=path.relative_to(case).as_posix(),target=target)
                finally: api.close(handle)
                item['metadata']=metadata(path)
            except Exception as error:
                item.update(error=str(error),traceback=traceback.format_exc())
        count=0
        for campaign in OWN_CAMPAIGNS:
            root=Path('S:/Phase-NTFS-Qualification')/campaign
            native.checked(root)
            marker=json.loads((root/'ownership.json').read_bytes())
            require(marker['owner']==controller.OWNER and marker['campaign']==campaign,'inventory root not owned')
            pending=[root]
            while pending:
                parent=pending.pop()
                with os.scandir(parent) as entries:
                    for entry in entries:
                        count+=1;require(count<=10000,'bounded own inventory exceeded')
                        info=entry.stat(follow_symlinks=False)
                        if getattr(info,'st_file_attributes',0)&0x400:
                            record['owned_reparse_inventory'].append({'campaign':campaign,
                                'relative_path':Path(entry.path).relative_to(root).as_posix(),
                                'native_metadata':metadata(Path(entry.path))})
                        elif stat.S_ISDIR(info.st_mode): pending.append(Path(entry.path))
            record['inventory_entries']=count
        require(sentinel.stat().st_ino==record['sentinel_before']['file_id'] and sentinel.read_bytes()==content,
                'sentinel changed')
        record['sentinel_after_unchanged']=True
    except Exception as error:
        record.update(error=str(error),traceback=traceback.format_exc())
    name='g-a05-native-tag-'+str(time.time_ns())
    binding=archival.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'a05-native-symlink-fsctl','lane':'MIX','result':{
        'a05_conformance_verdict':'NOT_VERIFIED','phase_route_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'fixtures':record['fixtures'],'existing_reparse':record['owned_reparse_inventory'],
        'error':record.get('error'),'sentinel_unchanged':record.get('sentinel_after_unchanged')},indent=2))

if __name__=='__main__': main()
