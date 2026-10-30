"""Thirty bounded L1 namespace-scope cases; not installed Phase qualification."""
from contextlib import ExitStack
from dataclasses import replace
import base64
import ctypes as C
import hashlib
import json
import multiprocessing as MP
from pathlib import Path
import struct
import subprocess
import sys
import time
import traceback

import native_io_probe as common

CASE = 'native-scope-v1'
COMMON = 'b829c6d0b0126fd166303d0df6d9b2a2c368d32c9715168b1650450d99c6a78f'
MUTATING = 'b1b19f763de31fb3b8077b595207d37ef4c921397266cba5edb53594996c379a'
SCOPED = '20180e628f17d01b81f15292c7c35313a754e64951680d645592db8f93e1e6b9'
require = common.require


def modules():
    folder = Path(__file__).parent
    require(hashlib.sha256((folder/'native_io_probe.py').read_bytes()).hexdigest()==COMMON,'common drift')
    native = common.load('owned_helper',folder/'native_rename_probe_v3.py',common.NATIVE)
    native.ownership()
    module = common.product_module(folder)
    mutation = common.load('phase_tool.mutation.ntfs.mutating',folder/'product/mutating_v2.py',MUTATING)
    scoped = common.load('phase_tool.mutation.ntfs.scoped',folder/'product/scoped.py',SCOPED)
    return native,module,mutation,scoped


def actor(pipe,kind,ordinal):
    io = None
    result = {}
    try:
        require(not sys.flags.optimize and kind in ('reparse','leaf') and type(ordinal) is int
                and 0 <= ordinal < 10,'invalid actor arguments')
        native,module,mutation,_ = modules()
        path = native.PROBE/CASE/f'{kind}-{ordinal:02}'
        native.checked(path)
        if kind=='reparse':
            target = native.PROBE/CASE/'outside'
            native.checked(target)
            api = native.Native();k = api.k
            k.DeviceIoControl.argtypes = [C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,
                C.c_uint32,C.POINTER(C.c_uint32),C.c_void_p]
            k.DeviceIoControl.restype = C.c_int32
            handle = k.CreateFileW(str(path),0x40000000|0x80,7,None,3,0x02000000|0x00200000,None)
            require(handle not in (None,C.c_void_p(-1).value),'actor metadata open failed')
            try:
                result['before'] = common.raw_metadata(api,path)
                pipe.send({'ready':True,'metadata':result['before']})
                require(pipe.poll(20) and pipe.recv()=={'go':ordinal},'actor barrier timeout')
                substitute,printed = ('\\??\\'+str(target)).encode('utf-16-le'),str(target).encode('utf-16-le')
                paths = substitute+b'\0\0'+printed+b'\0\0'
                raw = struct.pack('<IHHHHHH',0xa0000003,8+len(paths),0,0,len(substitute),len(substitute)+2,len(printed))+paths
                buffer,returned = C.create_string_buffer(raw),C.c_uint32()
                succeeded = k.DeviceIoControl(handle,0x900a4,buffer,len(raw),None,0,C.byref(returned),None)
                error = C.get_last_error() if not succeeded else None
                result.update(converted=bool(succeeded),winerror=error,metadata=common.raw_metadata(api,path))
                pipe.send({'converted_result':result.copy()})
                require(pipe.poll(20) and pipe.recv()=={'finish':ordinal},'actor finish timeout')
            finally:
                api.close(handle)
        else:
            io = mutation.NativeMutationIO()
            with ExitStack() as stack:
                parent = stack.enter_context(io.open_device_root(io.volume()))
                for name in ('Phase-NTFS-Qualification',common.CAMPAIGN,'transport-cases','nt-native-v3',CASE,path.name):
                    parent = stack.enter_context(io.child(parent,name,directory=True))
                source = stack.enter_context(io.child(parent,'source.bin',directory=False,rename_source=True))
                source_id,parent_id = io.identity(source),io.identity(parent)
                pipe.send({'ready':True,'source_identity':source_id.as_dict(),'parent_identity':parent_id.as_dict()})
                require(pipe.poll(20) and pipe.recv()=={'go':ordinal},'actor barrier timeout')
                result['effect'] = io.rename(source,parent,'current.bin',expected_source=source_id,
                                            expected_parent=parent_id,replace=True)
    except BaseException as error:
        result['error'] = {'error':str(error),'details':getattr(error,'details',{}),'traceback':traceback.format_exc()}
    finally:
        result.update(open_handles=len(io._handles) if io else 0,native_events=io.events if io else [])
        try:
            pipe.send({'result':result})
        finally:
            pipe.close()
    if result.get('error'):
        raise RuntimeError('own scope actor failed; structured error retained')


def finalize(process,pipe,child,row,record,ordinal):
    if process.pid and row['kind']=='reparse' and row.get('go_sent') and not row.get('finish_sent'):
        try:
            pipe.send({'finish':ordinal});row['finish_sent'] = True
        except BaseException as error:
            row['finish_error'] = str(error)
    pipe.close();child.close()
    if not process.pid:
        return
    try:
        process.join(10)
        if process.is_alive():
            row['termination_requested'] = True
            process.terminate();process.join(10);row['terminated'] = True
        row.update(worker_exitcode=process.exitcode,worker_alive=process.is_alive())
        require(not row['worker_alive'],'own actor still alive')
        process.close()
        require(row['worker_exitcode']==0 and not row.get('terminated'),'own actor finalization failed')
    except BaseException as error:
        record['safety_stop'] = True
        row['finalization_error'] = {'error':str(error),'traceback':traceback.format_exc()}
        raise


def main():
    require(not sys.flags.optimize,'optimized harness forbidden')
    native,module,mutation,scoped = modules()
    io,old = mutation.NativeMutationIO(),native.Native()
    controller = common.load('controller',Path.cwd()/'qualification/campaign.py')
    archive = common.load('archive',Path(__file__).with_name('ext4_archive_v2.py'),common.ARCHIVE)
    provisional = Path.cwd().parent/'qualification-campaigns'/common.CAMPAIGN
    state = json.loads((provisional/'state.json').read_bytes())
    controller.verify_owned(state);controller.verify_owned(state,read_only=True)
    case = native.PROBE/CASE
    native.checked(case,exists=False);case.mkdir(exist_ok=False)
    outside = case/'outside';outside.mkdir()
    sentinel_data = hashlib.sha256(b'scope-sentinel').digest()*2048
    sentinel = outside/'sentinel.bin';sentinel.open('xb').write(sentinel_data)
    sentinel_before = common.raw_metadata(old,sentinel)
    root_before = common.raw_metadata(old,case)
    facts = io.volume()
    grant = scoped.NativeRootGrant('phase_result_root',facts['device'],facts['volume_guid'],facts['volume_serial32'],
        ('Phase-NTFS-Qualification',common.CAMPAIGN,'transport-cases','nt-native-v3',CASE),
        module.NativeIdentity.parse(root_before['native_identity']))
    record = {'case':'NATIVE_SCOPE_V1','campaign':common.CAMPAIGN,'primitive_verdict':'NOT_VERIFIED',
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'grant':grant.as_dict(),'sentinel_before':sentinel_before,'records':[],
        'a05_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED','phase_route_verdict':'NOT_VERIFIED'}
    folder = Path(__file__).parent
    record['source_snapshot'] = [{'name':name,'sha256':hashlib.sha256(data).hexdigest(),
        'bytes_base64':base64.b64encode(data).decode('ascii')}
        for name in ('native_scope_probe.py','native_io_probe.py','product/native.py','product/mutating_v2.py',
                     'product/scoped.py','native_rename_probe_v3.py','ext4_archive_v2.py')
        for data in [(folder/name).read_bytes()]]
    def rejects(action,code):
        before = len(io._handles)
        try:
            result = action()
        except module.PhaseError as error:
            require(error.code==code,'wrong error '+error.code)
            require(len(io._handles)==before,'rejected operation leaked handles')
            return {'code':error.code,'details':error.details}
        if hasattr(result,'close'):
            result.close()
        raise RuntimeError('unexpected scoped acceptance')
    context = MP.get_context('spawn')
    try:
        for ordinal in range(10):
            path = case/f'normal-{ordinal:02}';path.mkdir()
            data = hashlib.sha256(f'normal|{ordinal}'.encode()).digest()*2048
            (path/'current.bin').open('xb').write(data)
            identity = module.NativeIdentity.parse(common.raw_metadata(old,path/'current.bin')['native_identity'])
            row = {'kind':'normal','ordinal':ordinal,'completed':False};record['records'].append(row)
            scope = scoped.NativeScopedTarget(io,grant,path.name+'/current.bin',namespace_flush=True)
            with scope:
                with scope.open_file(expected=identity) as opened:
                    require(io.hash_file(opened,len(data))==(controller.sha(data),len(data)),'normal read mismatch')
                    scope.assert_file_name(opened,identity)
                wrong_id = module.NativeIdentity(identity.volume_serial,('ff' if identity.file_id[:2]!='ff' else '00')+identity.file_id[2:])
                row['wrong_leaf'] = rejects(lambda:scope.open_file(expected=wrong_id),'ntfs.object_identity_mismatch')
            row['closed_scope'] = rejects(scope.assert_bound,'ntfs.scope_closed_or_unknown')
            wrong_root = module.NativeIdentity(grant.root_identity.volume_serial,
                ('ff' if grant.root_identity.file_id[:2]!='ff' else '00')+grant.root_identity.file_id[2:])
            row['wrong_root'] = rejects(lambda:scoped.NativeScopedTarget(io,replace(grant,root_identity=wrong_root),
                path.name+'/current.bin'),'ntfs.granted_root_identity_mismatch')
            wrong_guid = '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\'
            require(wrong_guid!=grant.volume_guid,'wrong GUID control equals actual')
            row['wrong_volume'] = rejects(lambda:scoped.NativeScopedTarget(io,replace(grant,volume_guid=wrong_guid),
                path.name+'/current.bin'),'ntfs.granted_volume_mapping_changed')
            row['missing_parent'] = rejects(lambda:scoped.NativeScopedTarget(io,grant,
                path.name+'/absent/current.bin'),'ntfs.open_failed')
            require((path/'current.bin').read_bytes()==data and not (path/'absent').exists(),'normal named state changed')
            require(not io._handles,'normal handles remain')
            row['completed'] = True
        for kind in ('reparse','leaf'):
            for ordinal in range(10):
                path = case/f'{kind}-{ordinal:02}';path.mkdir()
                leaf = 'sentinel.bin' if kind=='reparse' else 'current.bin'
                first = hashlib.sha256(f'first|{ordinal}'.encode()).digest()*2048
                second = hashlib.sha256(f'second|{ordinal}'.encode()).digest()*2048
                if kind=='leaf':
                    (path/'current.bin').open('xb').write(first)
                    (path/'source.bin').open('xb').write(second)
                row = {'kind':kind,'ordinal':ordinal,'completed':False};record['records'].append(row)
                pipe,child = context.Pipe();process = context.Process(target=actor,args=(child,kind,ordinal))
                try:
                    with scoped.NativeScopedTarget(io,grant,path.name+'/'+leaf) as scope:
                        with ExitStack() as stack:
                            if kind=='leaf':
                                observer = stack.enter_context(io._open(leaf,parent=scope.parent,directory=False,sharing=7))
                                old_id = io.identity(observer)
                                row['old_identity'] = old_id.as_dict()
                                require(io.hash_file(observer,len(first))==(controller.sha(first),len(first)),'old initial read')
                                new_id = common.raw_metadata(old,path/'source.bin')['native_identity']
                            process.start();child.close()
                            require(pipe.poll(20),'actor ready timeout')
                            ready = pipe.recv();row['ready'] = ready
                            require(ready.get('ready'),'actor not ready')
                            expected_parent = scope.parent_identity.as_dict()
                            require((ready['metadata']['native_identity'] if kind=='reparse' else ready['parent_identity'])==expected_parent,
                                    'actor parent mismatch')
                            if kind=='leaf':
                                require(ready['source_identity']==new_id,'actor source mismatch')
                            pipe.send({'go':ordinal});row['go_sent'] = True
                            require(pipe.poll(20),'actor effect timeout')
                            message = pipe.recv()
                            if kind=='reparse':
                                conversion = message.get('converted_result',{});row['conversion'] = conversion
                                row['converted'] = conversion.get('converted',False)
                                require(row['converted'] and conversion['metadata']['tag']=='0xa0000003'
                                        and conversion['metadata']['native_identity']==expected_parent,'conversion not reached')
                                require(common.raw_metadata(old,path)==conversion['metadata'],'fresh conversion mismatch')
                                row['bound_rejection'] = rejects(scope.assert_bound,'ntfs.reparse_forbidden')
                                row['open_rejection'] = rejects(scope.open_file,'ntfs.reparse_forbidden')
                                pipe.send({'finish':ordinal});row['finish_sent'] = True
                                require(pipe.poll(20),'actor final response timeout')
                                message = pipe.recv()
                            row['actor'] = message.get('result',{})
                            require('result' in message and not row['actor'].get('error') and row['actor']['open_handles']==0,'actor failed')
                            if kind=='leaf':
                                event = row['actor'].get('effect',{})
                                require(event.get('class')==65 and event.get('rename_flags')==3 and event.get('effect_state')=='committed',
                                        'actual replacement absent')
                                row['name_rejection'] = rejects(lambda:scope.assert_file_name(observer,old_id),'ntfs.object_identity_mismatch')
                                require(io.identity(observer)==old_id and io.hash_file(observer,len(first))==(controller.sha(first),len(first)),
                                        'old handle changed')
                                require((path/'current.bin').read_bytes()==second and
                                        common.raw_metadata(old,path/'current.bin')['native_identity']==new_id,'fresh leaf binding mismatch')
                                require(not (path/'source.bin').exists(),'replacement source name remains')
                                scope.assert_bound()
                except BaseException as error:
                    row['primary_error'] = {'error':str(error),'details':getattr(error,'details',{}),'traceback':traceback.format_exc()}
                    raise
                finally:
                    finalize(process,pipe,child,row,record,ordinal)
                require(not io._handles,'case handles remain')
                row['completed'] = True
        record['primitive_verdict'] = 'SUPPORTED'
    except BaseException as error:
        record.update(error=str(error),details=getattr(error,'details',{}),traceback=traceback.format_exc())
    record['module_open_handle_count'] = len(io._handles)
    try:
        record['sentinel_unchanged'] = sentinel.read_bytes()==sentinel_data and common.raw_metadata(old,sentinel)==sentinel_before
    except BaseException as error:
        record['sentinel_unchanged'] = False;record['sentinel_error'] = str(error)
    if not record['sentinel_unchanged']:
        record['safety_stop'] = True;record['primitive_verdict'] = 'UNSUPPORTED'
    counts = {kind:sum(row['completed'] for row in record['records'] if row['kind']==kind)
              for kind in ('normal','reparse','leaf')}
    record['completed_by_kind'] = counts
    name = 'g-native-scope-'+str(time.time_ns())
    binding = archive.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'native-scope-v1','lane':'MIX','result':{
        'primitive_verdict':record['primitive_verdict'],'completed':counts,'phase_route_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'primitive_verdict':record['primitive_verdict'],'completed':counts,'error':record.get('error')},indent=2))
    require(not record.get('safety_stop'),'SAFETY STOP: actor finalization or sentinel; evidence retained')


if __name__ == '__main__':
    main()
