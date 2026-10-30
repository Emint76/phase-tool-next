"""Synthetic H01/H02 Windows directory-publication probe, not a Phase backend.

No delete, no network, no shell, no arbitrary path/operation dispatch. The sole
native mutation is handle-relative FileRenameInformation, ReplaceIfExists=0.
Reports are provisional until stored through existing Phase on own ext4.
"""
from __future__ import annotations
import argparse
import ctypes as C
import hashlib
import json
import multiprocessing as MP
import os
from pathlib import Path
import queue
import re
import stat
import sys
import time
import traceback
import uuid

CAMPAIGN = '936b34d0-4f82-4558-b26e-9a206f20af88'
BASE = Path('S:/Phase-NTFS-Qualification') / CAMPAIGN
OWNER = 'phase-ntfs-qualification'
PROBE = BASE / 'transport-cases/nt-native-v1'
MAX_BYTES = 256 * 1024**2
NATIVE_EVENTS = []


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def checked(path, *, exists=True):
    path = Path(path)
    require(path.is_absolute() and os.path.normcase(str(path)) == os.path.normcase(str(path.resolve(strict=exists))), 'noncanonical path')
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not (getattr(info,'st_file_attributes',0) & 0x400), 'reparse ancestor')
    return path


def ownership():
    require(os.name == 'nt' and C.sizeof(C.c_void_p)==8 and C.sizeof(C.c_wchar)==2, 'Windows amd64 ABI required')
    shell = C.WinDLL('shell32')
    shell.IsUserAnAdmin.restype = C.c_int
    require(not shell.IsUserAnAdmin(), 'elevated process forbidden')
    require(str(uuid.UUID(CAMPAIGN,version=4))==CAMPAIGN, 'invalid UUID')
    checked(BASE)
    manifest = json.loads((BASE/'ownership.json').read_bytes())
    require(manifest['owner']==OWNER and manifest['campaign']==CAMPAIGN, 'campaign owner mismatch')
    token=json.loads((BASE/'transport-cases/.campaign-owner.json').read_bytes())
    require(token=={'owner':OWNER,'campaign':CAMPAIGN},'root owner mismatch')
    for root in (Path('C:/'),Path('S:/')):
        import shutil
        require(shutil.disk_usage(root).free>=4*1024**3,'small-probe reserve')
    return manifest


class USTR(C.Structure):
    _fields_=[('Length',C.c_uint16),('MaximumLength',C.c_uint16),('Buffer',C.c_void_p)]


class ATTR(C.Structure):
    _fields_=[('Length',C.c_uint32),('RootDirectory',C.c_void_p),('ObjectName',C.POINTER(USTR)),
              ('Attributes',C.c_uint32),('SecurityDescriptor',C.c_void_p),('SecurityQoS',C.c_void_p)]


class IOSUNION(C.Union):
    _fields_=[('Status',C.c_int32),('Pointer',C.c_void_p)]


class IOS(C.Structure):
    _fields_=[('Result',IOSUNION),('Information',C.c_size_t)]


class RENAME(C.Structure):
    _fields_=[('ReplaceIfExists',C.c_uint8),('RootDirectory',C.c_void_p),
              ('FileNameLength',C.c_uint32),('FileName',C.c_wchar*1)]


class FILEINFO(C.Structure):
    _fields_=[(name,C.c_uint32) for name in ('Attributes','CreationLow','CreationHigh','AccessLow','AccessHigh',
        'WriteLow','WriteHigh','VolumeSerial','SizeHigh','SizeLow','Links','IndexHigh','IndexLow')]


class NtFailure(OSError):
    def __init__(self,status,operation):
        self.status=status & 0xffffffff
        super().__init__(f'{operation}: NTSTATUS 0x{self.status:08x}')


class Native:
    def __init__(self):
        self.nt=C.WinDLL('ntdll')
        self.k=C.WinDLL('kernel32',use_last_error=True)
        self.nt.NtOpenFile.argtypes=[C.POINTER(C.c_void_p),C.c_uint32,C.POINTER(ATTR),C.POINTER(IOS),C.c_uint32,C.c_uint32]
        self.nt.NtOpenFile.restype=C.c_int32
        self.nt.NtSetInformationFile.argtypes=[C.c_void_p,C.POINTER(IOS),C.c_void_p,C.c_uint32,C.c_int32]
        self.nt.NtSetInformationFile.restype=C.c_int32
        self.k.GetFileInformationByHandle.argtypes=[C.c_void_p,C.POINTER(FILEINFO)]
        self.k.GetFileInformationByHandle.restype=C.c_int32
        self.k.CloseHandle.argtypes=[C.c_void_p]
        self.k.CloseHandle.restype=C.c_int32
        require(C.sizeof(ATTR)==48 and C.sizeof(IOS)==16 and RENAME.RootDirectory.offset==8 and RENAME.FileName.offset==20,'ABI layout mismatch')

    def open(self,name,*,root=None,source=False):
        if root is not None:
            require(re.fullmatch('[a-z][a-z0-9-]{0,63}',name) is not None,'invalid native leaf')
        encoded=name.encode('utf-16-le')
        buffer=C.create_unicode_buffer(name)
        text=USTR(len(encoded),len(encoded)+2,C.cast(buffer,C.c_void_p))
        attr=ATTR(C.sizeof(ATTR),root,C.pointer(text),0x40|0x1000,None,None)
        handle=C.c_void_p()
        ios=IOS()
        # Directory + synchronous I/O + open reparse itself. OBJ_DONT_REPARSE
        # blocks reparses during name parsing; handle attributes are also checked.
        access=0x100000|0x80|(0x10000 if source else 0x20)
        share=7 if source else 3  # Pinned parent cannot be renamed/deleted.
        status=self.nt.NtOpenFile(C.byref(handle),access,C.byref(attr),C.byref(ios),share,1|0x20|0x200000)
        if status!=0:
            if handle.value:
                self.close(handle.value)
            raise NtFailure(status,'NtOpenFile')
        try:
            info=self.info(handle.value)
            require(info['attributes'] & 0x10 and not info['attributes'] & 0x400,'non-directory/reparse handle')
        except Exception:
            self.close(handle.value)
            raise
        return handle.value

    def info(self,handle):
        data=FILEINFO()
        if not self.k.GetFileInformationByHandle(handle,C.byref(data)):
            raise C.WinError(C.get_last_error())
        return {'volume_serial':data.VolumeSerial,'file_id':(data.IndexHigh<<32)|data.IndexLow,'attributes':data.Attributes}

    def close(self,handle):
        if not self.k.CloseHandle(handle):
            raise C.WinError(C.get_last_error())

    def rename(self,source_handle,parent_handle,destination):
        require(re.fullmatch('[a-z][a-z0-9-]{0,63}',destination) is not None,'invalid destination')
        encoded=destination.encode('utf-16-le')
        # Allocate at least sizeof(FILE_RENAME_INFORMATION)+name bytes, per WDK.
        storage=C.create_string_buffer(C.sizeof(RENAME)+len(encoded))
        header=RENAME.from_buffer(storage)
        header.ReplaceIfExists=0
        header.RootDirectory=parent_handle
        header.FileNameLength=len(encoded)
        C.memmove(C.addressof(storage)+RENAME.FileName.offset,encoded,len(encoded))
        ios=IOS()
        before=time.monotonic_ns()
        status=self.nt.NtSetInformationFile(source_handle,C.byref(ios),storage,len(storage),10)
        event={'api':'NtSetInformationFile','information_class':10,'replace_if_exists':False,
                'status':f'0x{status&0xffffffff:08x}','success':status==0,
                'io_status':f'0x{ios.Result.Status&0xffffffff:08x}',
                'started_ns':before,'returned_ns':time.monotonic_ns(),'pid':os.getpid()}
        NATIVE_EVENTS.append(event)
        require(status != 0 or ios.Result.Status == 0,'successful return/IO_STATUS_BLOCK disagree')
        return event


def case_path(path):
    path=checked(path)
    require(path.is_relative_to(PROBE) and path!=PROBE,'case outside probe root')
    return path


def do_rename(parent,source,destination,ready=None):
    parent=case_path(parent)
    api=Native()
    root_handle=source_handle=None
    try:
        root_handle=api.open('\\??\\'+str(parent))
        root_identity=api.info(root_handle)
        source_handle=api.open(source,root=root_handle,source=True)
        before=api.info(source_handle)
        if ready:
            ready.wait(timeout=30)
        event=api.rename(source_handle,root_handle,destination)
        event.update(parent_before=root_identity,parent_after=api.info(root_handle),
                     source_before=before,source_after=api.info(source_handle))
        event.update(parent_path=str(parent),source_leaf=source,destination_leaf=destination)
        require(all(event['parent_before'][k]==event['parent_after'][k] and event['source_before'][k]==event['source_after'][k]
                    for k in ('volume_serial','file_id')),'native identity changed')
        return event
    finally:
        if source_handle is not None:
            api.close(source_handle)
        if root_handle is not None:
            api.close(root_handle)


def member_bytes(name):
    return hashlib.sha256(name.encode('ascii')).digest()*2048


def fixture(parent,name):
    target=parent/name
    target.mkdir(exist_ok=False)
    data=member_bytes(name)
    with (target/'member.bin').open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    return {'digest':sha(data),'length':len(data),'file_id':target.stat().st_ino}


def h01(report):
    records=[]
    report.update(id='H01',subcase='native no-replace prepared directory',requested_repeats=10,completed_repeats=0,records=records)
    for i in range(10):
        for kind in ('absent','empty','nonempty'):
            parent=PROBE/f'h01-r{i:02}-{kind}'
            parent.mkdir(exist_ok=False)
            expected=fixture(parent,'source')
            if kind!='absent':
                (parent/'target').mkdir()
            if kind=='nonempty':
                (parent/'target'/'sentinel').write_bytes(b'preserved')
            existing=(parent/'target').stat().st_ino if kind!='absent' else None
            event=do_rename(parent,'source','target')
            records.append({'repeat':i,'kind':kind,'expected_source':expected,'event':event})
            if kind=='absent':
                require(event['success'],'native absent-target rename failed')
                require(not (parent/'source').exists(),'source still named after commit')
                require((parent/'target').stat().st_ino==expected['file_id'],'target identity not preserved')
                require((parent/'target'/'member.bin').read_bytes()==member_bytes('source'),'published bytes mismatch')
                require(sorted(p.name for p in (parent/'target').iterdir())==['member.bin'],'partial/misbound publication')
            else:
                require(not event['success'],'existing directory replaced')
                require(event['status'] in {'0xc0000035','0xc0000022'},'unexpected refusal status; investigate')
                require((parent/'source').stat().st_ino==expected['file_id'],'source changed on refusal')
                require((parent/'source'/'member.bin').read_bytes()==member_bytes('source'),'source bytes changed')
                require((parent/'target').stat().st_ino==existing,'existing target identity changed')
                require(sorted(p.name for p in (parent/'source').iterdir())==['member.bin'],'source membership changed')
                require(sorted(p.name for p in (parent/'target').iterdir())==(['sentinel'] if kind=='nonempty' else []),'target membership changed')
                if kind=='nonempty':
                    require((parent/'target'/'sentinel').read_bytes()==b'preserved','target bytes changed')
        report['completed_repeats']=i+1
    report.update(primitive_verdict='SUPPORTED',phase_route_verdict='NOT_VERIFIED')


def race_worker(commands,results,barrier):
    ownership()
    while True:
        item=commands.get()
        if item is None:
            return
        round_id,parent,source=item
        event_start=len(NATIVE_EVENTS)
        try:
            event=do_rename(Path(parent),source,'target',ready=barrier)
            results.put({'round':round_id,'source':source,'event':event})
        except Exception as exc:
            results.put({'round':round_id,'source':source,'error':str(exc),'traceback':traceback.format_exc(),'pid':os.getpid(),
                         'native_events':NATIVE_EVENTS[event_start:]})


def h02(report):
    ctx=MP.get_context('spawn')
    barrier=ctx.Barrier(9)
    commands=[ctx.Queue(maxsize=1) for _ in range(8)]
    output=ctx.Queue(maxsize=16)
    children=[ctx.Process(target=race_worker,args=(q,output,barrier)) for q in commands]
    records=[]
    report.update(id='H02',requested_rounds=100,completed_rounds=0,writers=8,records=records)
    try:
        for child in children:
            child.start()
        for i in range(100):
            parent=PROBE/f'h02-r{i:03}'
            parent.mkdir(exist_ok=False)
            expected={f'source-{n}':fixture(parent,f'source-{n}') for n in range(8)}
            events=[]
            round_record={'round':i,'events':events,'expected_sources':expected,
                          'parent':str(parent),'dispatch_started_ns':time.monotonic_ns(),
                          'unknown_outcomes':8,'barrier_reached':False}
            records.append(round_record)
            for n,q in enumerate(commands):
                q.put((i,str(parent),f'source-{n}'),timeout=10)
            barrier.wait(timeout=30)
            round_record['barrier_reached']=True
            for _ in range(8):
                events.append(output.get(timeout=30))
                round_record['unknown_outcomes']=8-len(events)
            require(all('event' in e for e in events),'race window/worker error')
            require(all(e['round']==i for e in events) and {e['source'] for e in events}==set(expected),
                    'stale/duplicate/missing source events')
            require(len({e['event']['pid'] for e in events})==8,'not eight independent processes')
            for e in events:
                native=e['event']
                require(native['source_leaf']==e['source'] and native['parent_path']==str(parent)
                        and native['destination_leaf']=='target','misbound native event')
                require(native['source_before']['file_id']==expected[e['source']]['file_id'],
                        'native source/fixture identity mismatch')
                require(native['source_before']['volume_serial']==native['parent_before']['volume_serial'],
                        'native source/parent volume mismatch')
            winners=[e for e in events if e['event']['success']]
            require(len(winners)==1,'NOREPLACE race did not have exactly one winner')
            winner=winners[0]['source']
            require((parent/'target').stat().st_ino==expected[winner]['file_id'],'winner identity mismatch')
            require((parent/'target'/'member.bin').read_bytes()==member_bytes(winner),'winner bytes mismatch')
            require(sorted(p.name for p in (parent/'target').iterdir())==['member.bin'],'target membership mismatch')
            for e in events:
                name=e['source']
                if name==winner:
                    require(not (parent/name).exists(),'winner source not removed')
                else:
                    require(e['event']['status'] in {'0xc0000035','0xc0000022'},'unexpected race refusal')
                    require((parent/name).stat().st_ino==expected[name]['file_id'],'loser identity changed')
                    require((parent/name/'member.bin').read_bytes()==member_bytes(name),'loser bytes changed')
            round_record['winner']=winner
            report['completed_rounds']=i+1
            if i%10==9:
                print(f'H02 completed {i+1}/100',file=sys.stderr,flush=True)
    finally:
        # A failed barrier or partial receive must retain every available event.
        # Stop the current barrier so waiting workers can return a bounded error.
        if report['completed_rounds'] < 100:
            barrier.abort()
        for q in commands:
            try:
                q.put_nowait(None)
            except queue.Full:
                pass
        for child in children:
            if child.pid:
                child.join(timeout=10)
                if child.is_alive():
                    child.terminate()  # Only exact own probe children, never OS/runtime.
                    child.join(timeout=10)
        leftovers=[]
        while True:
            try:
                leftovers.append(output.get_nowait())
            except queue.Empty:
                break
        for item in leftovers:
            matches=[r for r in records if r['round']==item.get('round')]
            if len(matches)==1:
                matches[0]['events'].append(item)
                matches[0]['unknown_outcomes']=max(0,8-len(matches[0]['events']))
            else:
                report.setdefault('unbound_events',[]).append(item)
        report['workers']=[{'pid':child.pid,'exitcode':child.exitcode} for child in children]
        require(all(child.exitcode==0 for child in children),'worker termination/error; no positive verdict')
    report.update(primitive_verdict='SUPPORTED',phase_route_verdict='NOT_VERIFIED')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('case',choices=['h01','h02'])
    args=parser.parse_args()
    ownership()
    checked(PROBE,exists=False)
    if not PROBE.exists():
        PROBE.mkdir(exist_ok=False)
    stage=PROBE/(args.case+'-started')
    stage.mkdir(exist_ok=False)  # Never silently replay an interrupted probe.
    record={'campaign':CAMPAIGN,'case':args.case,'harness_digest':sha(Path(__file__).read_bytes()),
            'python':sys.version,'utc_ns':time.time_ns(),'elevated':False,'root':str(PROBE),'category':'Evidence/Raw','result':{}}
    try:
        if args.case=='h01':
            h01(record['result'])
        else:
            h02(record['result'])
    except Exception as exc:
        record['result'].update(primitive_verdict='NOT_VERIFIED',phase_route_verdict='NOT_VERIFIED',
                          error=str(exc),traceback=traceback.format_exc())
    record['native_events']=NATIVE_EVENTS
    try:
        total=0
        def scan_error(error):
            raise error
        for directory,dirs,files in os.walk(PROBE,followlinks=False,onerror=scan_error):
            for name in (*dirs,*files):
                info=(Path(directory)/name).lstat()
                require(not getattr(info,'st_file_attributes',0)&0x400,'unexpected reparse fixture')
                if stat.S_ISREG(info.st_mode):
                    total+=info.st_size
        record['fixture_bytes']=total
        require(total<MAX_BYTES,'small-stage budget exceeded')
    except Exception as exc:
        record['scan_error']={'error':str(exc),'traceback':traceback.format_exc()}
        record['result'].update(primitive_verdict='NOT_VERIFIED',phase_route_verdict='NOT_VERIFIED')
    print(json.dumps(record,sort_keys=True),flush=True)


if __name__=='__main__':
    main()
