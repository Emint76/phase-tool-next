"""L1 measurement of external native replacement against share=3/7 readers.

Twenty fresh owned synthetic cases, one bounded child at a time. No property
acceptance is inferred from either success or denial. No production or policy
change, no arbitrary paths/commands and no cleanup of retained fixtures.
"""
from contextlib import ExitStack
import base64
import hashlib
import json
import multiprocessing as MP
from pathlib import Path
import subprocess
import sys
import time
import traceback

import native_io_probe as common

CASE = 'native-destination-sharing-v1'
MUTATING = 'b1b19f763de31fb3b8077b595207d37ef4c921397266cba5edb53594996c379a'
COMMON = 'b829c6d0b0126fd166303d0df6d9b2a2c368d32c9715168b1650450d99c6a78f'
require = common.require


def root_chain(io, stack, *parts):
    root = stack.enter_context(io.open_device_root(io.volume()))
    for name in ('Phase-NTFS-Qualification',common.CAMPAIGN,'transport-cases','nt-native-v3',CASE,*parts):
        root = stack.enter_context(io.child(root,name,directory=True))
    return root


def worker(pipe, sharing, ordinal):
    io = None
    result = {}
    try:
        require(not sys.flags.optimize and sharing in (3,7) and type(ordinal) is int
                and 0 <= ordinal < 10,'bad worker arguments')
        folder = Path(__file__).parent
        require(hashlib.sha256((folder/'native_io_probe.py').read_bytes()).hexdigest()==COMMON,'common drift')
        native = common.load('owned_helper',folder/'native_rename_probe_v3.py',common.NATIVE)
        native.ownership()
        common.product_module(folder)
        mutation = common.load('phase_tool.mutation.ntfs.mutating',folder/'product/mutating_v2.py',MUTATING)
        io = mutation.NativeMutationIO()
        with ExitStack() as stack:
            parent = root_chain(io,stack,f's{sharing}-r{ordinal:02}')
            source = stack.enter_context(io.child(parent,'source.bin',directory=False,rename_source=True))
            source_id,parent_id = io.identity(source),io.identity(parent)
            pipe.send({'ready':True,'parent_identity':parent_id.as_dict(),'source_identity':source_id.as_dict()})
            require(pipe.poll(15) and pipe.recv()=={'commit':ordinal},'commit barrier timeout')
            try:
                result['effect'] = io.rename(source,parent,'current.bin',expected_source=source_id,
                                             expected_parent=parent_id,replace=True)
            except mutation.PhaseError as error:
                result['effect_error'] = {'code':error.code,'details':error.details}
    except BaseException as error:
        result['worker_error'] = {'error':str(error),'details':getattr(error,'details',{}),
                                  'traceback':traceback.format_exc()}
    finally:
        result.update(native_events=io.events if io else [],open_handles=len(io._handles) if io else None)
        try:
            pipe.send({'result':result})
        finally:
            pipe.close()
    if result.get('worker_error'):
        raise RuntimeError('owned sharing worker failed; structured error retained')


def main():
    require(not sys.flags.optimize,'optimized harness forbidden')
    folder = Path(__file__).parent
    require(hashlib.sha256((folder/'native_io_probe.py').read_bytes()).hexdigest()==COMMON,'common drift')
    native = common.load('owned_helper',folder/'native_rename_probe_v3.py',common.NATIVE)
    native.ownership()
    module = common.product_module(folder)
    io,old = module.NativeIO(),native.Native()
    controller = common.load('controller',Path.cwd()/'qualification/campaign.py')
    archive = common.load('archive',folder/'ext4_archive_v2.py',common.ARCHIVE)
    provisional = Path.cwd().parent/'qualification-campaigns'/common.CAMPAIGN
    state = json.loads((provisional/'state.json').read_bytes())
    controller.verify_owned(state);controller.verify_owned(state,read_only=True)
    case = native.PROBE/CASE
    native.checked(case,exists=False);case.mkdir(exist_ok=False)
    sentinel = case/'sentinel.bin'
    sentinel_data = hashlib.sha256(b'destination-sharing-sentinel').digest()*2048
    sentinel.open('xb').write(sentinel_data)
    sentinel_before = common.raw_metadata(old,sentinel)
    record = {'case':'NATIVE_DESTINATION_SHARING_V1','campaign':common.CAMPAIGN,
              'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
              'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'measurement_complete':False,'a05_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED',
              'phase_route_verdict':'NOT_VERIFIED','sentinel_before':sentinel_before,'records':[]}
    record['source_snapshot'] = [{'name':name,'sha256':hashlib.sha256(data).hexdigest(),
                                 'bytes_base64':base64.b64encode(data).decode('ascii')}
        for name in ('native_destination_sharing_probe.py','native_io_probe.py','product/native.py',
                     'product/mutating_v2.py','native_rename_probe_v3.py','ext4_archive_v2.py')
        for data in [(folder/name).read_bytes()]]
    context = MP.get_context('spawn')
    try:
        with ExitStack() as stack:
            root = root_chain(io,stack)
            for sharing in (3,7):
                for ordinal in range(10):
                    path = case/f's{sharing}-r{ordinal:02}';path.mkdir()
                    first = hashlib.sha256(f'old|{sharing}|{ordinal}'.encode()).digest()*2048
                    second = hashlib.sha256(f'new|{sharing}|{ordinal}'.encode()).digest()*2048
                    (path/'current.bin').open('xb').write(first)
                    (path/'source.bin').open('xb').write(second)
                    before_current = common.raw_metadata(old,path/'current.bin')
                    before_source = common.raw_metadata(old,path/'source.bin')
                    row = {'sharing':sharing,'ordinal':ordinal,'completed':False,
                           'current_before':before_current,'source_before':before_source}
                    record['records'].append(row)
                    pipe,child = context.Pipe()
                    process = context.Process(target=worker,args=(child,sharing,ordinal))
                    try:
                        with io.child(root,path.name,directory=True) as parent:
                            with io._open('current.bin',parent=parent,directory=False,sharing=sharing) as observer:
                                require(io.identity(observer).as_dict()==before_current['native_identity'],'initial reader binding')
                                require(io.hash_file(observer,len(first))==(controller.sha(first),len(first)),'initial bytes')
                                process.start();child.close()
                                require(pipe.poll(20),'worker ready timeout')
                                ready = pipe.recv();row['ready'] = ready
                                require(ready.get('ready') and ready['parent_identity']==io.identity(parent).as_dict()
                                        and ready['source_identity']==before_source['native_identity'],'worker binding')
                                pipe.send({'commit':ordinal})
                                require(pipe.poll(20),'worker result timeout')
                                result = pipe.recv();row['worker'] = result.get('result',{})
                                require('result' in result and not row['worker'].get('worker_error'),'worker failure')
                                require(row['worker']['open_handles']==0,'worker handles leaked')
                                row['reader_after'] = io.identity(observer).as_dict()
                                require(row['reader_after']==before_current['native_identity'],'old reader identity changed')
                                require(io.hash_file(observer,len(first))==(controller.sha(first),len(first)),'old reader bytes changed')
                                events = row['worker']['native_events']
                                require(len(events)==1 and events[0]['class']==65 and events[0]['rename_flags']==3,
                                        'wrong actual external replacement')
                                event = events[0]
                                committed = event['return_status']==event['io_status']=='0x00000000'
                                if committed:
                                    require(row['worker'].get('effect')==event and not row['worker'].get('effect_error'),
                                            'successful syscall with unresolved post-observation')
                                else:
                                    require(event['return_status'] in ('0xc0000022','0xc0000043') and
                                            row['worker'].get('effect_error',{}).get('code')=='ntfs.name_effect_failed',
                                            'unknown denial, not a valid diagnostic')
                                row['replacement_committed'] = committed
                                expected_bytes = second if committed else first
                                expected_id = before_source if committed else before_current
                                require((path/'current.bin').read_bytes()==expected_bytes,'fresh current bytes mismatch')
                                row['current_after'] = common.raw_metadata(old,path/'current.bin')
                                require(row['current_after']['native_identity']==expected_id['native_identity'],'fresh current identity')
                                require((path/'source.bin').exists()!=committed,'source membership mismatch')
                    except BaseException as error:
                        row['primary_error'] = {'error':str(error),'traceback':traceback.format_exc()}
                        raise
                    finally:
                        pipe.close();child.close()
                        if process.pid:
                            try:
                                process.join(10)
                                if process.is_alive():
                                    row['termination_requested'] = True
                                    process.terminate();process.join(10);row['terminated'] = True
                                row['worker_exitcode'] = process.exitcode
                                row['worker_alive_after_finalization'] = process.is_alive()
                                require(not row['worker_alive_after_finalization'],'own worker still alive')
                                failed = process.exitcode!=0 or row.get('terminated')
                                process.close()
                            except BaseException as error:
                                record['safety_stop'] = True
                                row['worker_finalization_error'] = {'error':str(error),'traceback':traceback.format_exc()}
                                raise
                            if failed and not row.get('primary_error'):
                                raise RuntimeError('own worker finalization failed')
                    row['completed'] = True
        require(not io._handles,'observer handles leaked')
        record['measurement_complete'] = True
    except BaseException as error:
        record.update(error=str(error),details=getattr(error,'details',{}),traceback=traceback.format_exc())
    record['module_open_handle_count'] = len(io._handles)
    try:
        record['sentinel_unchanged'] = sentinel.read_bytes()==sentinel_data and common.raw_metadata(old,sentinel)==sentinel_before
    except BaseException as error:
        record['sentinel_unchanged'] = False
        record['sentinel_error'] = {'error':str(error),'traceback':traceback.format_exc()}
    if not record['sentinel_unchanged']:
        record['measurement_complete'] = False
        record['safety_stop'] = True
    record['by_sharing'] = {str(s):{'completed':sum(v['completed'] for v in record['records'] if v['sharing']==s),
        'committed':sum(v.get('replacement_committed',False) for v in record['records'] if v['sharing']==s)} for s in (3,7)}
    name = 'g-native-destination-share-'+str(time.time_ns())
    binding = archive.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'native-destination-sharing-v1','lane':'MIX',
        'result':{'measurement_complete':record['measurement_complete'],'by_sharing':record['by_sharing']}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'measurement_complete':record['measurement_complete'],
                            'by_sharing':record['by_sharing'],'error':record.get('error')},indent=2))
    require(not record.get('safety_stop'),'SAFETY STOP: sentinel observation failed; evidence retained')


if __name__ == '__main__':
    main()
