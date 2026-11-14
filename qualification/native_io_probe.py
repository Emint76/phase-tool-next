"""Reviewed before execution: bounded NativeIO read/list/reparse/flush pilot.

Only the fixed owned campaign. No cleanup/delete, production access, privilege
change, general path dispatcher or full-route/G06 acceptance. Synthetic fixture
initialization uses the L1 harness allowance; tested operations use NativeIO.
"""
from contextlib import ExitStack
import ctypes as C
import hashlib
import importlib.util
import json
import multiprocessing as MP
import os
from pathlib import Path
import sys
import subprocess
import time
import traceback
import types

CAMPAIGN = '936b34d0-4f82-4558-b26e-9a206f20af88'
NATIVE = '7bacdc37efd02e6ac42aa0d6d473413e2a14f9eaf556bd5d58cfa91716d23df5'
ARCHIVE = '0b1461bcf4e91bcb026ab8ed8bef548891c63147afc9d663a582e607b8ea7984'
PRODUCT = '41654049dc10f1c2db0f74c847f0a36038b49295c4f02582b959b9c7a0dd0a22'
CASE = 'native-io-v1'

def require(condition, message):
    if not condition: raise RuntimeError(message)

def load(name, path, digest=None):
    if digest: require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'dependency drift')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def product_module(folder):
    # Only supplies the eventual package namespace; does not replace imports,
    # native calls, error handling, guard implementation or filesystem behavior.
    sys.path.insert(0, str(Path.cwd()/'src'))
    import phase_tool.mutation
    name = 'phase_tool.mutation.ntfs'
    package = types.ModuleType(name)
    package.__path__ = [str(folder/'product')]
    sys.modules[name] = package
    return load(name+'.native', folder/'product/native.py', PRODUCT)

class Tag(C.Structure):
    _fields_ = [('attributes', C.c_uint32), ('tag', C.c_uint32)]

class RawIdentity(C.Structure):
    _fields_ = [('volume', C.c_uint64), ('file_id', C.c_ubyte*16)]

def raw_metadata(api, path):
    k = api.k
    k.GetFileInformationByHandleEx.argtypes = [C.c_void_p, C.c_int, C.c_void_p, C.c_uint32]
    k.GetFileInformationByHandleEx.restype = C.c_int32
    handle = k.CreateFileW(str(path), 0x80, 7, None, 3, 0x02000000|0x00200000, None)
    require(handle not in (None, C.c_void_p(-1).value), 'independent no-follow metadata open failed')
    try:
        tag = Tag()
        if not k.GetFileInformationByHandleEx(handle, 9, C.byref(tag), C.sizeof(tag)):
            raise C.WinError(C.get_last_error())
        identity = RawIdentity()
        if not k.GetFileInformationByHandleEx(handle,18,C.byref(identity),C.sizeof(identity)):
            raise C.WinError(C.get_last_error())
        return {**api.info(handle), 'tag': f'0x{tag.tag:08x}', 'attributes': tag.attributes,
                'native_identity': {'volume_serial':identity.volume,'file_id':bytes(identity.file_id).hex()}}
    finally:
        api.close(handle)

def conversion_worker(pipe, ordinal):
    """Exactly one metadata conversion of a fresh own directory, no traversal."""
    try:
        require(type(ordinal) is int and 0 <= ordinal < 10, 'invalid ordinal')
        native = load('owned_native', Path(__file__).with_name('native_rename_probe_v3.py'), NATIVE)
        native.ownership()
        api = native.Native()
        path = native.PROBE/CASE/f'race-{ordinal:02}'
        native.checked(path)
        target = native.PROBE/CASE/'outside-sentinel'
        native.checked(target)
        k = api.k
        k.DeviceIoControl.argtypes = [C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32,
            C.c_void_p, C.c_uint32, C.POINTER(C.c_uint32), C.c_void_p]
        k.DeviceIoControl.restype = C.c_int32
        handle = k.CreateFileW(str(path), 0x40000000|0x80, 7, None, 3, 0x02000000|0x00200000, None)
        require(handle not in (None, C.c_void_p(-1).value), 'conversion open failed')
        try:
            before = api.info(handle)
            pipe.send({'ready': True, 'pid': os.getpid(), 'before': before})
            require(pipe.poll(15) and pipe.recv() == {'convert': ordinal}, 'conversion barrier timeout')
            import struct
            substitute = ('\\??\\'+str(target)).encode('utf-16-le')
            printed = str(target).encode('utf-16-le')
            paths = substitute+b'\0\0'+printed+b'\0\0'
            data = struct.pack('<IHHHHHH',0xa0000003,8+len(paths),0,0,len(substitute),
                               len(substitute)+2,len(printed))+paths
            buffer, returned = C.create_string_buffer(data), C.c_uint32()
            C.set_last_error(0)
            status = k.DeviceIoControl(handle, 0x900a4, buffer, len(data), None, 0, C.byref(returned), None)
            code = C.get_last_error() if not status else None
            pipe.send({'converted': bool(status), 'winerror': code, 'after': raw_metadata(api,path),
                       'pid': os.getpid()})
            require(pipe.poll(15) and pipe.recv() == {'finish': ordinal}, 'finish barrier timeout')
        finally:
            api.close(handle)
    except BaseException as error:
        try: pipe.send({'error': str(error), 'traceback': traceback.format_exc()})
        except BaseException: pass
        raise
    finally:
        pipe.close()

def main():
    require(not sys.flags.optimize, 'optimized probe forbidden')
    folder = Path(__file__).parent
    native = load('native_probe', folder/'native_rename_probe_v3.py', NATIVE)
    native.ownership()
    controller = load('controller', Path.cwd()/'qualification/campaign.py')
    archival = load('archive_v2', folder/'ext4_archive_v2.py', ARCHIVE)
    provisional = Path.cwd().parent/'qualification-campaigns'/CAMPAIGN
    state = json.loads((provisional/'state.json').read_bytes())
    require(state['campaign'] == CAMPAIGN and state['owner'] == controller.OWNER, 'wrong campaign')
    controller.verify_owned(state); controller.verify_owned(state, read_only=True)
    module = product_module(folder)
    io, old = module.NativeIO(), native.Native()
    case = native.PROBE/CASE
    native.checked(case, exists=False); case.mkdir(exist_ok=False)
    outside = case/'outside-sentinel'; outside.mkdir()
    sentinel = outside/'sentinel.bin'
    sentinel_bytes = hashlib.sha256(b'native-io-outside').digest()*2048
    sentinel.open('xb').write(sentinel_bytes)
    sentinel_id = raw_metadata(old, sentinel)
    record = {'case': 'NATIVE_IO_V1', 'campaign': CAMPAIGN, 'product_digest': 'sha256:'+PRODUCT,
        'harness_digest': controller.sha(Path(__file__).read_bytes()),
        'source_commit': subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'phase_route_verdict': 'NOT_VERIFIED', 'a05_verdict': 'NOT_VERIFIED', 'g06_verdict': 'NOT_VERIFIED',
        'primitive_verdict': 'NOT_VERIFIED', 'normal_repeats': 10, 'conversion_repeats': 10,
        'normal': [], 'fixtures': [], 'conversion': [], 'sentinel_before': sentinel_id}
    def denied(operation, allowed):
        try:
            with operation(): pass
        except module.PhaseError as error:
            require(error.code in allowed, 'unexpected negative error: '+error.code)
            return {'rejected': True, 'code': error.code, 'details': error.details}
        raise RuntimeError('operation unexpectedly accepted')
    try:
        with ExitStack() as stack:
            volume = io.volume()
            root = stack.enter_context(io.open_device_root(volume))
            for part in ('Phase-NTFS-Qualification', CAMPAIGN, 'transport-cases', 'nt-native-v3'):
                root = stack.enter_context(io.child(root, part, directory=True))
            probe_root = root
            parent = stack.enter_context(io.child(root, CASE, directory=True, namespace_flush=True))
            for i in range(10):
                directory = case/f'normal-{i:02}'; directory.mkdir()
                payload = hashlib.sha256(f'native-io|{i}'.encode()).digest()*2048
                path = directory/'member.bin'
                with path.open('xb') as stream:
                    stream.write(payload); stream.flush(); os.fsync(stream.fileno())
                expected = raw_metadata(old, path)
                item = {'repeat': i, 'expected': expected}; record['normal'].append(item)
                with io.child(parent,directory.name,directory=True,namespace_flush=True) as pinned:
                    entries = io.entries(pinned,2)
                    require(set(entries) == {'member.bin'} and not entries['member.bin']['directory'], 'listing mismatch')
                    item['entries'] = entries
                    with io.child(pinned,'member.bin',directory=False) as file:
                        identity = io.identity(file)
                        require(identity.as_dict() == expected['native_identity'],
                                'independent identity mismatch')
                        require(identity.file_id == entries['member.bin']['file_id'], 'listing observation mismatch')
                        a, b = io.hash_file(file,len(payload)), io.hash_file(file,len(payload))
                        require(a == b == (controller.sha(payload),len(payload)), 'hash/rewind mismatch')
                        item.update(identity=identity.as_dict(), first_read=a, second_read=b)
                    event = io.flush_namespace(pinned, io.identity(pinned)); item['flush'] = event
                    require(event['accepted'] and 'post_observation_error' not in event, 'flush not fully observed')
                require(path.read_bytes() == payload, 'independent bytes changed')
                item['independent_readback'] = True
                item['completed'] = True
            # Actual existing tag observations precede each expected rejection;
            # arbitrary missing-path/access failure is never counted as a guard.
            with io.child(probe_root,'a05-fixture-pilot-v1',directory=True) as fixture_root:
                with io.child(fixture_root,'inside',directory=True) as inside:
                    for name,directory,tag in [('windows-junction',True,'0xa0000003'),
                            ('linux-dir-link',True,'0xa000001d'),('linux-file-link',False,'0xa000001d')]:
                        path = native.PROBE/'a05-fixture-pilot-v1/inside'/name
                        metadata = raw_metadata(old,path)
                        require(metadata['attributes'] & 0x400 and metadata['tag'] == tag,'fixture tag mismatch')
                        outcome = denied(lambda:io.child(inside,name,directory=directory),
                                         {'ntfs.open_failed','ntfs.reparse_forbidden'})
                        require(outcome['code'] != 'ntfs.open_failed' or
                                outcome['details'].get('ntstatus') == '0xc000050b','non-reparse open failure')
                        record['fixtures'].append({'name':name,'metadata':metadata,**outcome})
            # Pin first; a distinct process converts the same pinned directory
            # metadata. Reached conversion must be proven, never inferred.
            context = MP.get_context('spawn')
            for i in range(10):
                path = case/f'race-{i:02}'; path.mkdir()
                pipe, child_pipe = context.Pipe()
                process = context.Process(target=conversion_worker,args=(child_pipe,i))
                item = {'repeat':i}; record['conversion'].append(item)
                try:
                    with io.child(parent,path.name,directory=True,namespace_flush=True) as pinned:
                        identity = io.identity(pinned); item['identity_before'] = identity.as_dict()
                        process.start(); child_pipe.close()
                        require(pipe.poll(20),'worker ready timeout')
                        item['ready'] = pipe.recv(); require(item['ready'].get('ready'), 'worker not ready')
                        require(item['ready']['before']['file_id'] == int.from_bytes(bytes.fromhex(identity.file_id),'little'),
                                'worker opened another object')
                        pipe.send({'convert':i}); require(pipe.poll(20),'conversion timeout')
                        item['converted'] = pipe.recv()
                        require(item['converted'].get('converted') and
                                item['converted']['after']['tag'] == '0xa0000003','conversion not reached')
                        require(item['converted']['after']['attributes'] & 0x400 and
                                item['converted']['after']['native_identity'] == identity.as_dict(),
                                'converted tag belongs to another object')
                        require(io.identity(pinned) == identity, 'pinned identity changed during conversion')
                        outcomes=[]
                        for action in (lambda:io.entries(pinned,2),
                                       lambda:io.flush_namespace(pinned,identity),
                                       lambda:io.child(pinned,'sentinel.bin',directory=False)):
                            try:
                                result=action()
                                if isinstance(result,module.NativeHandle): result.close()
                            except module.PhaseError as error:
                                require(error.code == 'ntfs.reparse_forbidden','wrong conversion rejection')
                                outcomes.append({'rejected':True,'code':error.code})
                            else: raise RuntimeError('converted handle accepted')
                        item['outcomes'] = outcomes
                        pipe.send({'finish':i})
                except BaseException as error:
                    item['primary_error'] = {'error':str(error),'traceback':traceback.format_exc()}
                    raise
                finally:
                    pipe.close(); child_pipe.close()
                    if process.pid:
                        process.join(10)
                        item.update(pid=process.pid,exitcode=process.exitcode)
                        if process.is_alive():
                            process.terminate(); process.join(10)
                            item['terminated'] = True
                        require(not process.is_alive(), 'own worker still alive')
                        require(process.exitcode == 0 and not item.get('terminated'), 'conversion worker failed')
                        process.close()
                item['completed'] = True
            require(sentinel.read_bytes()==sentinel_bytes and raw_metadata(old,sentinel)==sentinel_id,
                    'outside sentinel changed')
            record['sentinel_unchanged'] = True
        require(not io._handles, 'native handles leaked')
        record['primitive_verdict'] = 'SUPPORTED'
    except BaseException as error:
        record.update(error=str(error),traceback=traceback.format_exc())
    record['module_open_handle_count'] = len(io._handles)
    name = 'g-native-io-'+str(time.time_ns())
    binding = archival.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'native-io-v1','lane':'MIX','result':{
        'primitive_verdict':record['primitive_verdict'],'phase_route_verdict':'NOT_VERIFIED',
        'a05_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'primitive_verdict':record['primitive_verdict'],'error':record.get('error'),
        'normal_attempted':len(record['normal']),
        'normal_completed':sum(bool(v.get('completed')) for v in record['normal']),
        'conversions_attempted':len(record['conversion']),
        'conversions_completed':sum(bool(v.get('completed')) for v in record['conversion']),
        'fixtures_completed':len(record['fixtures']),
        'module_open_handles':record['module_open_handle_count']},indent=2))

if __name__=='__main__': main()
