"""L1 actual-syscall metadata-conversion window, fixed owned campaign only.

Injection wraps a real native function without replacing its return value or
arguments. The source module is unchanged. No route, A05 or G06 acceptance.
No cleanup, arbitrary path service, production resource, privilege or policy.
"""
from contextlib import ExitStack
import ctypes as C
import hashlib
import json
import multiprocessing as MP
import os
from pathlib import Path
import struct
import sys
import time
import traceback

import native_io_probe as common

CAMPAIGN = common.CAMPAIGN
CASE = 'native-kernel-window-v1'
MUTATING = '3530e17ff7721d257ce5b1e6279cbbf3a4628213f26529008f6baddfa851c764'
COMMON = 'b829c6d0b0126fd166303d0df6d9b2a2c368d32c9715168b1650450d99c6a78f'
KINDS = ('open','create','rename-dir','rename-file','link-file')
require = common.require

def positive_control(io, root, sources_root, case, sources, kind, ordinal, payload, old, controller, item):
    leaf='control-'+kind+f'-{ordinal:02}'
    path=case/leaf; path.mkdir()
    source_path=sources/leaf
    before=len(io.events)
    with ExitStack() as stack:
        parent=stack.enter_context(io.child(root,leaf,directory=True,namespace_flush=True))
        expected_parent=io.identity(parent)
        if kind=='open':
            (path/'target.bin').open('xb').write(payload)
            with io.child(parent,'target.bin',directory=False) as opened:
                require(io.hash_file(opened,len(payload))==(controller.sha(payload),len(payload)),'open control failed')
        elif kind=='create':
            with io.create_exclusive(parent,'target.bin',directory=False,expected_parent=expected_parent) as created:
                identity=io.identity(created)
                require(io.write_chunk(created,payload,offset=0,expected=identity)==len(payload),'write control short')
                io.flush_file(created,identity)
                require(io.hash_file(created,len(payload))==(controller.sha(payload),len(payload)),'create control hash')
                io.truncate(created,length=128,expected=identity); io.flush_file(created,identity)
                require(io.hash_file(created,128)==(controller.sha(payload[:128]),128),'truncate control hash')
                require(io.write_chunk(created,payload,offset=0,expected=identity)==len(payload),'restore control short')
                io.flush_file(created,identity)
        else:
            directory=kind=='rename-dir'
            if directory:
                source_path.mkdir(); (source_path/'member.bin').open('xb').write(payload)
            else: source_path.open('xb').write(payload)
            with io.child(sources_root,leaf,directory=directory,rename_source=True) as source:
                expected_source=io.identity(source)
                if kind=='link-file':
                    io.hardlink_noreplace(source,parent,'target.bin',expected_source=expected_source,expected_parent=expected_parent)
                else:
                    io.rename_noreplace(source,parent,'target.bin',expected_source=expected_source,expected_parent=expected_parent)
                item['source_identity']=expected_source.as_dict()
                item['target_metadata']=common.raw_metadata(old,path/'target.bin')
                require(item['target_metadata']['native_identity']==expected_source.as_dict(),'name control identity mismatch')
            require(source_path.exists()==(kind=='link-file'),'name control source membership mismatch')
        io.flush_namespace(parent,expected_parent)
    target=path/'target.bin'
    require((target/'member.bin' if kind=='rename-dir' else target).read_bytes()==payload,'independent control bytes')
    item['native_events']=io.events[before:]
    item['completed']=True
    return item

def reject_counterexample(item, property_name, message):
    item[property_name]='UNSUPPORTED'
    raise RuntimeError('COUNTEREXAMPLE: '+message)

def worker(pipe, kind, ordinal):
    try:
        require(kind in KINDS and type(ordinal) is int and 0 <= ordinal < 10,'invalid case')
        native = common.load('owned_helper',Path(__file__).with_name('native_rename_probe_v3.py'),common.NATIVE)
        native.ownership()
        path = native.PROBE/CASE/f'{kind}-{ordinal:02}'
        target = native.PROBE/CASE/'outside-sentinel'
        native.checked(path); native.checked(target)
        api = native.Native(); k = api.k
        k.DeviceIoControl.argtypes = [C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,
                                     C.POINTER(C.c_uint32),C.c_void_p]
        k.DeviceIoControl.restype = C.c_int32
        handle = k.CreateFileW(str(path),0x40000000|0x80,7,None,3,0x02000000|0x00200000,None)
        require(handle not in (None,C.c_void_p(-1).value),'worker open failed')
        try:
            pipe.send({'ready':True,'pid':os.getpid(),'metadata':common.raw_metadata(api,path)})
            require(pipe.poll(20) and pipe.recv()=={'convert':ordinal},'conversion barrier timeout')
            substitute, printed = ('\\??\\'+str(target)).encode('utf-16-le'),str(target).encode('utf-16-le')
            paths = substitute+b'\0\0'+printed+b'\0\0'
            raw = struct.pack('<IHHHHHH',0xa0000003,8+len(paths),0,0,len(substitute),
                              len(substitute)+2,len(printed))+paths
            buffer, returned = C.create_string_buffer(raw), C.c_uint32()
            C.set_last_error(0)
            result = k.DeviceIoControl(handle,0x900a4,buffer,len(raw),None,0,C.byref(returned),None)
            code = C.get_last_error() if not result else None
            pipe.send({'converted':bool(result),'winerror':code,'metadata':common.raw_metadata(api,path)})
            require(pipe.poll(20) and pipe.recv()=={'finish':ordinal},'finish barrier timeout')
        finally: api.close(handle)
    except BaseException as error:
        try: pipe.send({'error':str(error),'traceback':traceback.format_exc()})
        except BaseException: pass
        raise
    finally: pipe.close()

def raw_names(io,handle):
    """Research observer only: no-follow directory-handle enumeration of RP object."""
    names = {}
    buffer = C.create_string_buffer(64*1024)
    first = True
    while True:
        C.set_last_error(0)
        result = io.kernel.GetFileInformationByHandleEx(handle.value,20 if first else 19,buffer,len(buffer))
        code = C.get_last_error() if not result else None
        first = False
        if not result:
            require(code==18,'raw directory observation failed')
            return names
        data, offset = buffer.raw, 0
        while True:
            following = struct.unpack_from('<I',data,offset)[0]
            attrs,length = struct.unpack_from('<II',data,offset+56)
            require(length%2==0 and offset+88+length<=len(data),'bad raw directory record')
            name = data[offset+88:offset+88+length].decode('utf-16-le')
            if name not in ('.','..'):
                require(name not in names and len(names)<8,'unexpected raw membership')
                names[name]={'attributes':attrs,'file_id':data[offset+72:offset+88].hex()}
            if not following: break
            require(following>=88+length and following%8==0 and offset+following<len(data),'invalid raw offset')
            offset += following

def main():
    require(not sys.flags.optimize,'optimized harness forbidden')
    folder = Path(__file__).parent
    require(hashlib.sha256((folder/'native_io_probe.py').read_bytes()).hexdigest()==COMMON,'common source drift')
    native = common.load('native',folder/'native_rename_probe_v3.py',common.NATIVE)
    native.ownership()
    controller = common.load('controller',Path.cwd()/'qualification/campaign.py')
    archive = common.load('archive',folder/'ext4_archive_v2.py',common.ARCHIVE)
    provisional = Path.cwd().parent/'qualification-campaigns'/CAMPAIGN
    state = json.loads((provisional/'state.json').read_bytes())
    require(state['owner']==controller.OWNER and state['campaign']==CAMPAIGN,'wrong campaign')
    controller.verify_owned(state); controller.verify_owned(state,read_only=True)
    module = common.product_module(folder)
    mutation = common.load('phase_tool.mutation.ntfs.mutating',folder/'product/mutating.py',MUTATING)
    io, old = mutation.NativeMutationIO(), native.Native()
    case = native.PROBE/CASE
    native.checked(case,exists=False); case.mkdir(exist_ok=False)
    outside = case/'outside-sentinel'; outside.mkdir()
    payload = hashlib.sha256(b'native-kernel-sentinel').digest()*2048
    sentinel = outside/'sentinel.bin'; sentinel.open('xb').write(payload)
    sentinel_id = common.raw_metadata(old,sentinel)
    sources = case/'sources'; sources.mkdir()
    record={'case':'NATIVE_KERNEL_WINDOW_V1','campaign':CAMPAIGN,'harness_digest':controller.sha(Path(__file__).read_bytes()),
        'native_digest':'sha256:'+common.PRODUCT,'mutation_digest':'sha256:'+MUTATING,
        'phase_route_verdict':'NOT_VERIFIED','a05_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED',
        'confinement_verdict':'NOT_VERIFIED','post_binding_verdict':'NOT_VERIFIED',
        'identity_integrity_verdict':'NOT_VERIFIED','requested_per_kind':10,
        'controls':[],'records':[],'sentinel_before':sentinel_id}
    context = MP.get_context('spawn')
    try:
        with ExitStack() as stack:
            root = stack.enter_context(io.open_device_root(io.volume()))
            for part in ('Phase-NTFS-Qualification',CAMPAIGN,'transport-cases','nt-native-v3',CASE):
                root = stack.enter_context(io.child(root,part,directory=True))
            sources_root = stack.enter_context(io.child(root,'sources',directory=True))
            for kind in KINDS:
                for ordinal in range(10):
                    control={'kind':kind,'ordinal':ordinal,'completed':False}
                    record['controls'].append(control)
                    positive_control(io,root,sources_root,case,sources,kind,ordinal,payload,old,controller,control)
                    leaf = f'{kind}-{ordinal:02}'
                    path = case/leaf; path.mkdir()
                    source_path = sources/leaf
                    directory = kind=='rename-dir'
                    if directory:
                        source_path.mkdir(); (source_path/'member.bin').open('xb').write(payload)
                    elif kind in ('rename-file','link-file'):
                        source_path.open('xb').write(payload)
                    destination = 'sentinel.bin' if kind=='open' else 'new-'+leaf+('.bundle' if directory else '.bin')
                    item={'kind':kind,'ordinal':ordinal,'injection_count':0,'destination':destination}
                    record['records'].append(item)
                    pipe, child_pipe = context.Pipe()
                    process = context.Process(target=worker,args=(child_pipe,kind,ordinal))
                    try:
                        with ExitStack() as local:
                            parent = local.enter_context(io.child(root,leaf,directory=True,namespace_flush=True))
                            expected = io.identity(parent); item['expected_parent']=expected.as_dict()
                            source = None
                            if kind in ('rename-dir','rename-file','link-file'):
                                source = local.enter_context(io.child(sources_root,leaf,directory=directory,rename_source=True))
                                item['expected_source']=io.identity(source).as_dict()
                            process.start(); child_pipe.close()
                            require(pipe.poll(20),'worker ready timeout')
                            item['ready']=pipe.recv()
                            require(item['ready'].get('ready') and
                                item['ready']['metadata']['native_identity']==expected.as_dict(),'worker binding mismatch')
                            function_name = 'NtOpenFile' if kind=='open' else 'NtCreateFile' if kind=='create' else 'NtSetInformationFile'
                            original = getattr(io.nt,function_name)
                            def injected(*args):
                                item['injection_count']+=1
                                require(item['injection_count']==1,'duplicate syscall attempt')
                                if kind in ('open','create'):
                                    attrs=C.cast(args[2],C.POINTER(module._ObjectAttributes)).contents
                                    require(attrs.RootDirectory==parent.value and attrs.Attributes==0x1040,'altered native open args')
                                    require((args[4] if kind=='open' else args[6])==(1 if kind=='create' else 3),
                                            'altered sharing')
                                    options=args[5] if kind=='open' else args[8]
                                    require(options==0x20|0x200000|0x40,'altered native open options')
                                    if kind=='create': require(args[7]==2,'not actual exclusive create')
                                    name=C.wstring_at(attrs.ObjectName.contents.Buffer,attrs.ObjectName.contents.Length//2)
                                    require(name==destination,'wrong native leaf')
                                else:
                                    info=module._RenameInfo.from_buffer(args[2])
                                    require(info.RootDirectory==parent.value and info.ReplaceIfExists==0
                                            and args[4]==(11 if kind=='link-file' else 10)
                                            and args[0]==source.value,'wrong name syscall args')
                                    name=C.wstring_at(C.addressof(args[2])+module._RenameInfo.FileName.offset,info.FileNameLength//2)
                                    require(name==destination,'wrong name syscall leaf')
                                pipe.send({'convert':ordinal}); require(pipe.poll(20),'conversion ACK timeout')
                                item['conversion']=pipe.recv()
                                require(item['conversion'].get('converted') and
                                    item['conversion']['metadata']['tag']=='0xa0000003' and
                                    item['conversion']['metadata']['attributes']&0x400 and
                                    item['conversion']['metadata']['native_identity']==expected.as_dict(),'window not reached')
                                item['pre_syscall_observation']=common.raw_metadata(old,path)
                                require(item['pre_syscall_observation']==item['conversion']['metadata'],'conversion binding changed')
                                item['real_call_started_ns']=time.monotonic_ns()
                                status=original(*args)  # Exactly the original native call and arguments.
                                ios=C.cast(args[3] if kind in ('open','create') else args[1],C.POINTER(module._IoStatus)).contents
                                item.update(real_return_status=f'0x{status & 0xffffffff:08x}',
                                            real_io_status=f'0x{ios.Result.Status & 0xffffffff:08x}',
                                            real_information=ios.Information,real_returned_ns=time.monotonic_ns())
                                return status
                            setattr(io.nt,function_name,injected)
                            before_events=len(io.events)
                            try:
                                if kind=='open':
                                    opened=io.child(parent,destination,directory=False)
                                    try: item['opened_identity']=io.identity(opened).as_dict()
                                    finally: opened.close()
                                elif kind=='create':
                                    created=io.create_exclusive(parent,destination,directory=False,expected_parent=expected)
                                    try: item['created_identity']=io.identity(created).as_dict()
                                    finally: created.close()
                                elif kind=='link-file':
                                    io.hardlink_noreplace(source,parent,destination,expected_source=io.identity(source),expected_parent=expected)
                                else:
                                    io.rename_noreplace(source,parent,destination,expected_source=io.identity(source),expected_parent=expected)
                                item['returned_without_error']=True
                            except module.PhaseError as error:
                                item['product_error']={'code':error.code,'details':error.details}
                            finally:
                                setattr(io.nt,function_name,original)
                            item['native_events']=io.events[before_events:]
                            require(item['injection_count']==1 and 'real_return_status' in item,'real syscall window absent')
                            item['pinned_membership']=raw_names(io,parent)
                            item['outside_membership']=sorted(p.name for p in outside.iterdir())
                            if item['outside_membership']!=['sentinel.bin']:
                                reject_counterexample(item,'confinement_verdict','outside creation/rename/link')
                            if sentinel.read_bytes()!=payload or common.raw_metadata(old,sentinel)!=sentinel_id:
                                reject_counterexample(item,'confinement_verdict','outside sentinel changed')
                            # Either no-reparse/error or the old pinned object;
                            # no result may be represented as verified after rebinding.
                            if item.get('opened_identity')==sentinel_id['native_identity']:
                                reject_counterexample(item,'confinement_verdict','outside sentinel opened')
                            if item.get('returned_without_error'):
                                reject_counterexample(item,'post_binding_verdict','return after reached parent rebinding')
                            status=item['real_return_status']
                            native_success=status==item['real_io_status']=='0x00000000'
                            denied=status=='0xc000050b' or (kind=='open' and status in ('0xc0000034','0xc000000f'))
                            require(native_success or denied,'unexpected kernel error; not a positive result')
                            error=item.get('product_error',{})
                            if kind=='open':
                                require(denied and not item.get('opened_identity') and not item['pinned_membership'],
                                        'unexpected read outcome')
                                require(error.get('code')=='ntfs.open_failed' and error.get('details',{}).get('ntstatus')==status,
                                        'open denial not propagated faithfully')
                                item['outcome']='kernel_denial_without_traversal'
                            elif native_success:
                                if set(item['pinned_membership'])!={destination}:
                                    reject_counterexample(item,'identity_integrity_verdict','successful syscall has wrong membership')
                                require(error.get('code')=='ntfs.post_observation_failed','missing exact post-detection error')
                                require(any(e.get('code')=='ntfs.reparse_forbidden' for e in
                                    error.get('details',{}).get('event',{}).get('post_observation_errors',[])),
                                    'missing reparse post-detection')
                                expected_child=item['expected_source'] if source is not None else item['native_events'][0].get('object_identity')
                                require(expected_child is not None,'missing expected created identity')
                                if item['pinned_membership'][destination]['file_id']!=expected_child['file_id']:
                                    reject_counterexample(item,'identity_integrity_verdict','destination is not committed source/object')
                                item['outcome']='safe_old_object_effect_and_post_detection'
                            else:
                                require(not item['pinned_membership'],'effect after kernel denial')
                                require(error.get('code') in ('ntfs.create_failed','ntfs.post_observation_failed'),
                                        'unexpected product denial error')
                                item['outcome']='kernel_no_reparse_denial'
                            if source is not None:
                                require(source_path.exists()==(kind=='link-file' or not native_success),
                                        'source link/rename membership mismatch')
                            item['confinement_verdict']='SUPPORTED'
                            item['post_binding_verdict']='SUPPORTED' if native_success else 'NOT_VERIFIED'
                            item['post_binding_observation']='detection' if native_success else 'kernel_prevention'
                            pipe.send({'finish':ordinal})
                    except BaseException as error:
                        item['primary_error']={'error':str(error),'traceback':traceback.format_exc()}
                        raise
                    finally:
                        pipe.close(); child_pipe.close()
                        if process.pid:
                            process.join(10); item.update(pid=process.pid,exitcode=process.exitcode)
                            if process.is_alive(): process.terminate(); process.join(10); item['terminated']=True
                            require(not process.is_alive(),'own worker still alive')
                            require(process.exitcode==0 and not item.get('terminated'),'own worker failed')
                            process.close()
                    item['completed']=True
            record['sentinel_unchanged']=True
        require(not io._handles,'module handles leaked')
        record['confinement_verdict']='SUPPORTED'
        record['identity_integrity_verdict']='SUPPORTED'
        record['post_binding_verdict']='SUPPORTED' if any(v.get('outcome')=='safe_old_object_effect_and_post_detection'
            for v in record['records']) else 'NOT_VERIFIED'
    except BaseException as error:
        record.update(error=str(error),error_details=getattr(error,'details',{}),traceback=traceback.format_exc())
        for prop in ('confinement_verdict','post_binding_verdict','identity_integrity_verdict'):
            if any(v.get(prop)=='UNSUPPORTED' for v in record['records']): record[prop]='UNSUPPORTED'
    record['module_open_handle_count']=len(io._handles)
    record['all_native_events']=io.events
    name='g-native-kernel-window-'+str(time.time_ns())
    binding=archive.retain(controller,state,provisional,record,name)
    counts={kind:sum(v.get('completed',False) for v in record['records'] if v['kind']==kind) for kind in KINDS}
    state['records'].append(binding|{'action':'native-kernel-window-v1','lane':'MIX','result':{
        'confinement_verdict':record['confinement_verdict'],'phase_route_verdict':'NOT_VERIFIED','completed':counts}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'confinement_verdict':record['confinement_verdict'],'completed':counts,'error':record.get('error')},indent=2))

if __name__=='__main__': main()
