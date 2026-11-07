"""L1 class65 real-syscall reparse window, fixed synthetic campaign only.

Ten controls replace an existing ordinary file; ten windows convert an empty
pinned parent to a junction immediately before the unchanged class65 syscall.
No claim that a nonempty directory can be converted, and no A05 substitution.
"""
from contextlib import ExitStack
import base64
import ctypes as C
import hashlib
import json
import multiprocessing as MP
from pathlib import Path
import struct
import subprocess
import time

import native_root_mutex_probe_v2 as gates

CASE = 'native-replace-window-v1'
GATES = '50ad82cc474b527f1260180e142a5c920d78a13c070c2e7a11fa2a611408ec8c'
WINDOW = '48acdd5e062597f38b9799ad449b9eabc6011e454a8eb40f05e01b1e2b5c88ef'
require = gates.require


def environment():
    folder = Path(__file__).parent
    require(hashlib.sha256((folder/'native_root_mutex_probe_v2.py').read_bytes()).hexdigest()==GATES,'gate helper drift')
    native,module,scoped,_ = gates.modules()
    from phase_tool.mutation.ntfs import mutating
    observer = gates.common.load('frozen_kernel_observer',folder/'native_kernel_window_probe.py',WINDOW)
    return native,module,scoped,mutating,observer


def actor(pipe, ordinal):
    result = {}
    try:
        require(type(ordinal) is int and 0 <= ordinal < 10,'invalid worker ordinal')
        native,_,_,_,_ = environment()
        path,target = native.PROBE/CASE/f'window-{ordinal:02}',native.PROBE/CASE/'outside'
        native.checked(path);native.checked(target)
        api = native.Native();kernel = api.k
        kernel.DeviceIoControl.argtypes = [C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,
            C.c_uint32,C.POINTER(C.c_uint32),C.c_void_p]
        kernel.DeviceIoControl.restype = C.c_int32
        handle = kernel.CreateFileW(str(path),0x40000000|0x80,7,None,3,0x02000000|0x00200000,None)
        require(handle not in (None,C.c_void_p(-1).value),'conversion metadata open failed')
        try:
            result['before'] = gates.common.raw_metadata(api,path)
            pipe.send({'ready':True,'metadata':result['before']})
            require(pipe.poll(20) and pipe.recv()=={'convert':ordinal},'conversion barrier timeout')
            substitute,printed = ('\\??\\'+str(target)).encode('utf-16-le'),str(target).encode('utf-16-le')
            paths = substitute+b'\0\0'+printed+b'\0\0'
            raw = struct.pack('<IHHHHHH',0xa0000003,8+len(paths),0,0,len(substitute),len(substitute)+2,len(printed))+paths
            buffer,returned = C.create_string_buffer(raw),C.c_uint32()
            succeeded = kernel.DeviceIoControl(handle,0x900a4,buffer,len(raw),None,0,C.byref(returned),None)
            code = C.get_last_error() if not succeeded else None
            result.update(converted=bool(succeeded),winerror=code,after=gates.common.raw_metadata(api,path))
            pipe.send({'conversion':result.copy()})
            # Parent sends finish after every attempted conversion, also if the
            # conversion failed. EOF must not disguise the original failure.
            require(pipe.poll(20) and pipe.recv()=={'finish':ordinal},'finish barrier timeout')
        finally:
            api.close(handle)
    except BaseException as error:
        result['error'] = gates.error_value(error)
    finally:
        try:
            pipe.send({'result':result})
        finally:
            pipe.close()
    if result.get('error'):
        raise RuntimeError('own conversion worker failed; structured result retained')


def main():
    native,module,scoped,mutation,observer = environment()
    folder,repo = Path(__file__).parent,Path.cwd()
    controller = gates.common.load('controller',repo/'qualification/campaign.py',
        '245caaf82aef4e8f0e5584405e6530ec9ef8e35aba5c2180bf92d4ce1b216eab')
    archive = gates.common.load('archive',folder/'ext4_archive_v2.py',gates.common.ARCHIVE)
    provisional = repo.parent/'qualification-campaigns'/gates.common.CAMPAIGN
    state = json.loads((provisional/'state.json').read_bytes())
    controller.verify_owned(state);controller.verify_owned(state,read_only=True)
    case = native.PROBE/CASE
    native.checked(case,exists=False);case.mkdir(exist_ok=False)
    outside,sources = case/'outside',case/'sources'
    outside.mkdir();sources.mkdir()
    first = hashlib.sha256(b'replace-window-old').digest()*2048
    second = hashlib.sha256(b'replace-window-new').digest()*2048
    sentinel = outside/'current.bin';sentinel.open('xb').write(first)
    old,io = native.Native(),mutation.NativeMutationIO()
    sentinel_before = gates.common.raw_metadata(old,sentinel)
    facts = io.volume()
    root_identity = module.NativeIdentity.parse(gates.common.raw_metadata(old,case)['native_identity'])
    grant = scoped.NativeRootGrant('phase_result_root',facts['device'],facts['volume_guid'],facts['volume_serial32'],
        ('Phase-NTFS-Qualification',gates.common.CAMPAIGN,'transport-cases','nt-native-v3',CASE),root_identity)
    record = {'case':'NATIVE_REPLACE_WINDOW_V1','campaign':gates.common.CAMPAIGN,
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'grant':grant.as_dict(),'controls':[],'windows':[],'requested_each':10,
        'confinement_verdict':'NOT_VERIFIED','post_binding_verdict':'NOT_VERIFIED',
        'a05_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED','phase_route_verdict':'NOT_VERIFIED',
        'window_scope':'empty physical parent conversion; controls separately replace an existing ordinary file',
        'sentinel_before':sentinel_before,'first_digest':controller.sha(first),'second_digest':controller.sha(second)}
    paths = [(name,repo/name) for name in gates.SOURCES] + [(name,folder/name) for name in
        ('native_replace_window_probe.py','native_root_mutex_probe_v2.py','native_kernel_window_probe.py',
         'native_io_probe.py','native_rename_probe_v3.py','ext4_archive_v2.py')]
    record['source_snapshot'] = [{'name':name,'sha256':hashlib.sha256(data).hexdigest(),
        'bytes_base64':base64.b64encode(data).decode('ascii')} for name,path in paths for data in [path.read_bytes()]]
    context = MP.get_context('spawn')
    try:
        for ordinal in range(10):
            for kind in ('control','window'):
                path = case/f'{kind}-{ordinal:02}';path.mkdir()
                source_path = sources/f'{kind}-{ordinal:02}.bin'
                source_path.open('xb').write(second)
                row = {'ordinal':ordinal,'completed':False,'kind':kind,'injection_count':0}
                record['controls' if kind=='control' else 'windows'].append(row)
                if kind=='control':
                    (path/'current.bin').open('xb').write(first)
                    row['old_metadata'] = gates.common.raw_metadata(old,path/'current.bin')
                pipe,child = context.Pipe()
                process = context.Process(target=actor,args=(child,ordinal))
                try:
                    with ExitStack() as stack:
                        target_scope = stack.enter_context(scoped.NativeScopedTarget(io,grant,path.name+'/current.bin',namespace_flush=True))
                        source_scope = stack.enter_context(scoped.NativeScopedTarget(io,grant,'sources/'+source_path.name))
                        parent,expected_parent = target_scope.parent,target_scope.parent_identity
                        source = stack.enter_context(io.child(source_scope.parent,source_path.name,directory=False,rename_source=True))
                        expected_source = io.identity(source)
                        row.update(expected_parent=expected_parent.as_dict(),expected_source=expected_source.as_dict())
                        row['source_readback_before'] = io.hash_file(source,len(second))
                        require(row['source_readback_before']==(controller.sha(second),len(second)),'source bytes mismatch')
                        original = io.nt.NtSetInformationFile
                        before = len(io.events)
                        if kind=='control':
                            previous = stack.enter_context(io._open('current.bin',parent=parent,directory=False,sharing=7))
                            previous_id = io.identity(previous)
                            row['old_readback_before'] = io.hash_file(previous,len(first))
                            require(previous_id.as_dict()==row['old_metadata']['native_identity'] and
                                row['old_readback_before']==(controller.sha(first),len(first)),'old binding mismatch')
                        else:
                            process.start();child.close()
                            row['ready_packet'] = gates.receive(pipe,20)
                            require(row['ready_packet'].get('ready') and
                                row['ready_packet']['metadata']['native_identity']==expected_parent.as_dict(),'actor parent mismatch')
                            def injected(*arguments):
                                row['injection_count'] += 1
                                require(row['injection_count']==1,'duplicate actual syscall attempt')
                                info = mutation._RenameInfoEx.from_buffer(arguments[2])
                                require(arguments[0]==source.value and arguments[4]==65 and info.Flags==3
                                    and info.RootDirectory==parent.value,'class65 syscall arguments drift')
                                leaf = C.wstring_at(C.addressof(arguments[2])+mutation._RenameInfoEx.FileName.offset,info.FileNameLength//2)
                                require(leaf=='current.bin','actual destination drift')
                                row['convert_sent'] = True
                                pipe.send({'convert':ordinal})
                                row['conversion_packet'] = gates.receive(pipe,20)
                                conversion = row['conversion_packet'].get('conversion',{})
                                require(conversion.get('converted') and conversion['after']['tag']=='0xa0000003'
                                    and conversion['after']['native_identity']==expected_parent.as_dict(),'required window not reached')
                                row['pre_syscall_metadata'] = gates.common.raw_metadata(old,path)
                                require(row['pre_syscall_metadata']==conversion['after'],'conversion identity drift')
                                # Invoke the original function pointer with exactly
                                # the original buffers, source and parent handles.
                                status = original(*arguments)
                                ios = C.cast(arguments[1],C.POINTER(module._IoStatus)).contents
                                row.update(real_return_status=f'0x{status & 0xffffffff:08x}',
                                    real_io_status=f'0x{ios.Result.Status & 0xffffffff:08x}',real_information=ios.Information)
                                return status
                            io.nt.NtSetInformationFile = injected
                        try:
                            try:
                                row['effect'] = io.rename(source,parent,'current.bin',expected_source=expected_source,
                                    expected_parent=expected_parent,replace=True)
                                row['returned_without_error'] = True
                            except module.PhaseError as error:
                                row['product_error'] = {'code':error.code,'details':error.details}
                        finally:
                            io.nt.NtSetInformationFile = original
                        row['native_events'] = io.events[before:]
                        if kind=='control':
                            require(row.get('returned_without_error') and row['effect']['class']==65 and
                                    row['effect']['rename_flags']==3 and row['effect']['effect_state']=='committed','control did not replace')
                            row['old_readback_after'] = io.hash_file(previous,len(first))
                            row['old_identity_after'] = io.identity(previous).as_dict()
                            require(row['old_readback_after']==(controller.sha(first),len(first)) and
                                row['old_identity_after']==previous_id.as_dict(),'old observer changed')
                            target_scope.assert_file_name(source,expected_source)
                            row['namespace_flush'] = io.flush_namespace(parent,expected_parent)
                        else:
                            require(row['injection_count']==1 and 'real_return_status' in row,'actual syscall not observed')
                            row['physical_parent_membership'] = observer.raw_names(io,parent)
                            row['outside_membership'] = sorted(item.name for item in outside.iterdir())
                            if (row['outside_membership']!=['current.bin'] or sentinel.read_bytes()!=first or
                                    gates.common.raw_metadata(old,sentinel)!=sentinel_before):
                                record.update(safety_stop=True,confinement_verdict='UNSUPPORTED')
                                raise RuntimeError('COUNTEREXAMPLE: outside state changed')
                            if row.get('returned_without_error'):
                                record.update(safety_stop=True,post_binding_verdict='UNSUPPORTED')
                                raise RuntimeError('COUNTEREXAMPLE: return after actual parent reparse conversion')
                            status = row['real_return_status']
                            events = [event for event in row['native_events'] if event.get('api')=='NtSetInformationFile']
                            require(len(events)==1 and events[0].get('class')==65 and events[0].get('rename_flags')==3
                                and events[0]['return_status']==status and events[0]['io_status']==row['real_io_status']
                                and events[0]['source_identity']==expected_source.as_dict()
                                and events[0]['parent_identity']==expected_parent.as_dict(),'raw event differs from actual syscall')
                            require(row['product_error']['details']['event']==events[0],'post error lost exact raw event')
                            require(any(error.get('code')=='ntfs.reparse_forbidden' for error in
                                events[0].get('post_observation_errors',[])),'missing exact reparse post-observation error')
                            if status==row['real_io_status']=='0x00000000':
                                require(row['product_error']['code']=='ntfs.post_observation_failed','missing post-binding failure')
                                require(row['physical_parent_membership'].get('current.bin',{}).get('file_id')==expected_source.file_id,
                                    'successful effect identity mismatch')
                                require(set(row['physical_parent_membership'])=={'current.bin'},'successful effect membership mismatch')
                                row['outcome'] = 'old_pinned_object_effect_and_post_detection'
                            else:
                                require(status in ('0xc0000280','0xc0000281','0xc000050b'),'unexpected kernel error is not prevention')
                                require(not row['physical_parent_membership'],'effect after kernel denial')
                                require(row['product_error']['code']=='ntfs.post_observation_failed','raw denial not preserved in post error')
                                require(source_path.exists(),'source disappeared after denied call')
                                row['outcome'] = 'kernel_no_reparse_prevention'
                        row['source_readback_after'] = io.hash_file(source,len(second))
                        row['source_identity_after'] = io.identity(source).as_dict()
                        require(row['source_readback_after']==(controller.sha(second),len(second)) and
                                row['source_identity_after']==expected_source.as_dict(),'pinned source bytes/identity changed')
                    if kind=='control':
                        row['fresh_metadata'] = gates.common.raw_metadata(old,path/'current.bin')
                        row['fresh_digest'] = controller.sha((path/'current.bin').read_bytes())
                        require(row['fresh_metadata']['native_identity']==expected_source.as_dict()
                            and row['fresh_digest']==controller.sha(second) and not source_path.exists(),'fresh control readback mismatch')
                    row['completed'] = True
                except BaseException as error:
                    row['primary_error'] = gates.error_value(error)
                    raise
                finally:
                    if process.pid and row.get('convert_sent'):
                        try:
                            pipe.send({'finish':ordinal})
                            row['finish_sent'] = True
                            row['final_packet'] = gates.receive(pipe,20)
                            require('result' in row['final_packet'] and not row['final_packet']['result'].get('error'),'actor error')
                        except BaseException as error:
                            row['finish_error'] = gates.error_value(error)
                            record['safety_stop'] = True
                    gates.finish(process,pipe,child,row,record)
                require(not io._handles,'case native handles remain')
                require(not record.get('safety_stop'),'structured worker safety stop')
        require(len(record['controls'])==len(record['windows'])==10 and
            all(row['completed'] for row in (*record['controls'],*record['windows'])),'incomplete repetition count')
        record['confinement_verdict'] = 'SUPPORTED'
        if any(row.get('outcome')=='old_pinned_object_effect_and_post_detection' for row in record['windows']):
            record['post_binding_verdict'] = 'SUPPORTED'
    except BaseException as error:
        record['error'] = gates.error_value(error)
    record['native_file_handles'] = len(io._handles)
    try:
        record['sentinel_after'] = gates.common.raw_metadata(old,sentinel)
        record['sentinel_digest'] = controller.sha(sentinel.read_bytes())
        record['sentinel_unchanged'] = record['sentinel_after']==sentinel_before and sentinel.read_bytes()==first
    except BaseException as error:
        record['sentinel_error'] = gates.error_value(error)
        record['sentinel_unchanged'] = False
    if not record['sentinel_unchanged'] or io._handles:
        record.update(safety_stop=True,confinement_verdict='UNSUPPORTED')
    require(len(json.dumps(record,sort_keys=True).encode('utf-8'))<=1024**2,'raw exceeds identified 1MiB bound')
    name = 'g-native-replace-window-'+str(time.time_ns())
    binding = archive.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'native-replace-window-v1','lane':'MIX','result':{
        'confinement_verdict':record['confinement_verdict'],'phase_route_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'confinement_verdict':record['confinement_verdict'],
        'controls':sum(row['completed'] for row in record['controls']),
        'windows':sum(row['completed'] for row in record['windows']),'error':record.get('error')},indent=2))
    require(not record.get('safety_stop'),'SAFETY STOP: own worker/sentinel; raw retained')


if __name__ == '__main__':
    main()
