"""A05 environment pilot: actual tags of owned Windows/Linux link fixtures.

Not full A05 conformance. No traversal mutation, delete, privilege/policy change
or production resource. Fixtures and sentinels remain for further reviewed tests.
"""
import ctypes as C
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time
import traceback

CAMPAIGN='936b34d0-4f82-4558-b26e-9a206f20af88'
NATIVE='7bacdc37efd02e6ac42aa0d6d473413e2a14f9eaf556bd5d58cfa91716d23df5'
ARCHIVE='0b1461bcf4e91bcb026ab8ed8bef548891c63147afc9d663a582e607b8ea7984'

def require(value,message):
    if not value: raise RuntimeError(message)

def load(name,path,digest=None):
    if digest: require(hashlib.sha256(path.read_bytes()).hexdigest()==digest,'reviewed dependency changed')
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

class TAG(C.Structure):
    _fields_=[('attributes',C.c_uint32),('tag',C.c_uint32)]

def main():
    require(not sys.flags.optimize,'optimized fixture probe forbidden')
    base=Path(__file__).parent
    native=load('native_probe',base/'native_rename_probe_v3.py',NATIVE)
    native.ownership()
    repo=Path.cwd()
    controller=load('owned_controller',repo/'qualification/campaign.py')
    archival=load('ext4_archival',base/'ext4_archive_v2.py',ARCHIVE)
    provisional=repo.parent/'qualification-campaigns'/CAMPAIGN
    state=json.loads((provisional/'state.json').read_bytes())
    require(state['campaign']==CAMPAIGN and state['owner']==controller.OWNER,'campaign mismatch')
    worker=controller.verify_owned(state)
    controller.verify_owned(state,read_only=True)
    case=native.PROBE/'a05-fixture-pilot-v1'
    native.checked(case,exists=False)
    case.mkdir(exist_ok=False)
    inside=case/'inside';inside.mkdir()
    outside=case/'outside-sentinel';outside.mkdir()
    sentinel=outside/'sentinel.bin'
    content=hashlib.sha256(b'phase-a05-sentinel').digest()*2048
    sentinel.open('xb').write(content)
    record={'case':'A05_FIXTURE_PILOT','campaign':CAMPAIGN,'phase_route_verdict':'NOT_VERIFIED',
            'a05_conformance_verdict':'NOT_VERIFIED','harness_digest':controller.sha(Path(__file__).read_bytes()),
            'archival_digest':'sha256:'+ARCHIVE,'native_digest':'sha256:'+NATIVE,
            'sentinel_before':{'file_id':sentinel.stat().st_ino,'digest':controller.sha(content),'length':len(content)},
            'fixtures':[]}
    api=native.Native()
    k=api.k
    k.CreateSymbolicLinkW.argtypes=[C.c_wchar_p,C.c_wchar_p,C.c_uint32]
    k.CreateSymbolicLinkW.restype=C.c_uint8
    k.GetFileInformationByHandleEx.argtypes=[C.c_void_p,C.c_int,C.c_void_p,C.c_uint32]
    k.GetFileInformationByHandleEx.restype=C.c_int32
    k.DeviceIoControl.argtypes=[C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,
                               C.POINTER(C.c_uint32),C.c_void_p]
    k.DeviceIoControl.restype=C.c_int32
    def tag(path):
        handle=k.CreateFileW(str(path),0x80,7,None,3,0x02000000|0x00200000,None)
        if handle in (None,C.c_void_p(-1).value): raise C.WinError(C.get_last_error())
        try:
            data=TAG()
            if not k.GetFileInformationByHandleEx(handle,9,C.byref(data),C.sizeof(data)):
                raise C.WinError(C.get_last_error())
            return {'attributes':data.attributes,'tag':f'0x{data.tag:08x}',**api.info(handle)}
        finally: api.close(handle)
    def capture(name,operation):
        item={'name':name};record['fixtures'].append(item)
        try: operation(item)
        except Exception as error: item.update(error=str(error),traceback=traceback.format_exc())
    def windows_link(item,directory):
        name='windows-dir-link' if directory else 'windows-file-link'
        path=inside/name
        target=outside if directory else sentinel
        C.set_last_error(0)
        result=k.CreateSymbolicLinkW(str(path),str(target),2|int(directory))
        item.update(api='CreateSymbolicLinkW',flags=2|int(directory),success=bool(result),
                    winerror=C.get_last_error() if not result else None,relative_path='inside/'+name,
                    target='outside-sentinel' if directory else 'outside-sentinel/sentinel.bin')
        if result: item['native_metadata']=tag(path)
    def junction(item):
        path=inside/'windows-junction'
        path.mkdir(exist_ok=False)
        expected=path.stat().st_ino
        handle=k.CreateFileW(str(path),0x40000000|0x80,7,None,3,0x02000000|0x00200000,None)
        if handle in (None,C.c_void_p(-1).value): raise C.WinError(C.get_last_error())
        try:
            require(api.info(handle)['file_id']==expected,'new junction object changed')
            substitute=('\\??\\'+str(outside)).encode('utf-16-le')
            printed=str(outside).encode('utf-16-le')
            paths=substitute+b'\0\0'+printed+b'\0\0'
            data=struct.pack('<IHHHHHH',0xa0000003,8+len(paths),0,0,len(substitute),len(substitute)+2,len(printed))+paths
            buffer=C.create_string_buffer(data)
            returned=C.c_uint32()
            C.set_last_error(0)
            result=k.DeviceIoControl(handle,0x900a4,buffer,len(data),None,0,C.byref(returned),None)
            item.update(api='FSCTL_SET_REPARSE_POINT',success=bool(result),
                        winerror=C.get_last_error() if not result else None,
                        relative_path='inside/windows-junction',target='outside-sentinel',
                        expected_file_id=expected)
        finally: api.close(handle)
        item['native_metadata']=tag(path)
    def linux_link(item,directory):
        name='linux-dir-link' if directory else 'linux-file-link'
        target='../outside-sentinel' if directory else '../outside-sentinel/sentinel.bin'
        script="import os,json;from pathlib import Path;p=Path('/ntfs/transport-cases/nt-native-v3/a05-fixture-pilot-v1/inside');os.symlink(__import__('sys').argv[2],p/__import__('sys').argv[1]);s=(p/__import__('sys').argv[1]).lstat();print(json.dumps({'mode':s.st_mode,'device':s.st_dev,'inode':s.st_ino,'link':os.readlink(p/__import__('sys').argv[1])}))"
        output=controller.docker('exec',worker,'/opt/phase/bin/python','-B','-c',script,name,target,timeout=30)
        item.update(api='Linux os.symlink',success=True,relative_path='inside/'+name,
                    target=target,linux_metadata=json.loads(output))
        item['native_metadata']=tag(inside/name)
    try:
        capture('windows-file-symlink',lambda item:windows_link(item,False))
        capture('windows-directory-symlink',lambda item:windows_link(item,True))
        capture('windows-directory-junction',junction)
        capture('linux-file-symlink',lambda item:linux_link(item,False))
        capture('linux-directory-symlink',lambda item:linux_link(item,True))
        require(sentinel.stat().st_ino==record['sentinel_before']['file_id'],'sentinel identity changed')
        require(sentinel.read_bytes()==content,'sentinel bytes changed')
        record['sentinel_after_unchanged']=True
    except Exception as error:
        record.update(error=str(error),traceback=traceback.format_exc())
    name='g-a05-fixture-pilot-'+str(time.time_ns())
    binding=archival.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'a05-fixture-pilot','lane':'MIX','result':{
        'a05_conformance_verdict':'NOT_VERIFIED','phase_route_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'fixtures':record['fixtures'],'sentinel_unchanged':record.get('sentinel_after_unchanged')},indent=2))

if __name__=='__main__': main()
