"""Bounded native root-mutex L1 probe; no target publication or qualification.

Only own synthetic campaign paths, ephemeral own mutex objects and own workers.
Fault injection terminates only the explicitly identified crash holder. There is
no general dispatcher, deletion, privilege change or production configuration.
"""
from contextlib import ExitStack
import base64
import hashlib
import json
import multiprocessing as MP
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import traceback

import native_io_probe as common

CASE = 'native-root-mutex-v1'
COMMON = 'b829c6d0b0126fd166303d0df6d9b2a2c368d32c9715168b1650450d99c6a78f'
LOCK_SOURCE = '5c18957ec54b555a38fb081557e7aa1c6ac25434728f5858ffd3f62503369178'
SOURCES = {
    'src/phase_tool/mutation/ntfs/native.py': common.PRODUCT,
    'src/phase_tool/mutation/ntfs/mutating.py': 'b1b19f763de31fb3b8077b595207d37ef4c921397266cba5edb53594996c379a',
    'src/phase_tool/mutation/ntfs/scoped.py': '20180e628f17d01b81f15292c7c35313a754e64951680d645592db8f93e1e6b9',
    'src/phase_tool/mutation/ntfs/root_lock.py': LOCK_SOURCE,
}
require = common.require


def modules():
    require(not sys.flags.optimize, 'optimized worker forbidden')
    folder = Path(__file__).parent
    require(hashlib.sha256((folder/'native_io_probe.py').read_bytes()).hexdigest()==COMMON, 'common drift')
    native = common.load('owned_helper', folder/'native_rename_probe_v3.py', common.NATIVE)
    native.ownership()
    for name, digest in SOURCES.items():
        native.checked(Path.cwd()/name)
        require(hashlib.sha256((Path.cwd()/name).read_bytes()).hexdigest()==digest, 'product source drift')
    sys.path.insert(0, str(Path.cwd()/'src'))
    from phase_tool.mutation.ntfs import native as io_module, scoped, root_lock
    return native, io_module, scoped, root_lock


def grant_from(value, io, native, module, scoped):
    require(set(value)=={'root_binding','device','volume_guid','volume_serial32','components','native_identity'},
            'invalid grant fields')
    require(value['components']==['Phase-NTFS-Qualification',common.CAMPAIGN,'transport-cases','nt-native-v3',CASE],
            'grant outside fixed own case')
    path = native.PROBE/CASE
    native.checked(path)
    fresh = common.raw_metadata(native.Native(), path)['native_identity']
    require(fresh==value['native_identity'], 'fresh grant identity drift')
    grant = scoped.NativeRootGrant(value['root_binding'],value['device'],value['volume_guid'],value['volume_serial32'],
        tuple(value['components']),module.NativeIdentity.parse(value['native_identity']))
    facts = io.volume()
    require((facts['device'],facts['volume_guid'],facts['volume_serial32'])==
            (grant.device,grant.volume_guid,grant.volume_serial32), 'volume drift')
    return grant


def error_value(error):
    return {'type':type(error).__name__,'code':getattr(error,'code',None),'message':str(error),
            'details':getattr(error,'details',{}),'traceback':traceback.format_exc()}


def expect_error(action, code):
    try:
        result = action()
    except BaseException as error:
        require(getattr(error,'code',None)==code, 'unexpected error '+str(error))
        return {'code':error.code,'details':error.details}
    if hasattr(result, 'close'):
        result.close()
    raise RuntimeError('expected rejection absent')


def contender(pipe, value, ordinal, barrier, owner, counter):
    result = {'ordinal':ordinal,'pid':os.getpid(),'records':[]}
    io = None
    try:
        require(type(ordinal) is int and 0 <= ordinal < 8,'invalid contender')
        native,module,scoped,locks = modules()
        io = module.NativeIO()
        grant = grant_from(value,io,native,module,scoped)
        pipe.send({'ready':True,'pid':os.getpid()})
        for number in range(100):
            barrier.wait(15)
            lock = locks.NativeRootMutex(io,grant,timeout_ms=5000)
            row = {'round':number,'completed':False}
            result['records'].append(row)
            try:
                with lock:
                    row['entered_ns'] = time.monotonic_ns()
                    require(owner.value==0, 'overlapping critical ownership')
                    owner.value = os.getpid()
                    row['counter_before'] = counter.value
                    time.sleep(0.001)
                    require(owner.value==os.getpid(), 'critical owner changed')
                    counter.value += 1
                    row['counter_after'] = counter.value
                    owner.value = 0
                    row['left_ns'] = time.monotonic_ns()
                require(lock.state=='closed' and not io._handles,'contender finalization failed')
                row['completed'] = True
            finally:
                row.update(events=lock.events,state=lock.state)
        require(len(result['records'])==100,'missing contention rounds')
    except BaseException as error:
        result['error'] = error_value(error)
        try:
            barrier.abort()
        except BaseException as failure:
            result['barrier_abort_error'] = str(failure)
    finally:
        result['native_file_handles'] = len(io._handles) if io else 0
        pipe.send({'result':result})
        pipe.close()
    if result.get('error'):
        raise RuntimeError('own contender failed; structured result retained')


def holder(pipe, value, mode):
    io = None
    result = {'mode':mode,'pid':os.getpid(),'records':[]}
    try:
        require(mode in ('handoff','crash'),'invalid holder mode')
        native,module,scoped,locks = modules()
        io = module.NativeIO()
        grant = grant_from(value,io,native,module,scoped)
        for ordinal in range(100 if mode=='handoff' else 1):
            lock = locks.NativeRootMutex(io,grant)
            row = {'ordinal':ordinal}
            result['records'].append(row)
            try:
                with lock:
                    pipe.send({'held':ordinal,'pid':os.getpid(),'name':lock.name,'events':lock.events})
                    require(pipe.poll(15), 'holder release command timeout')
                    require(pipe.recv()=={'release':ordinal}, 'unexpected holder command')
                require(lock.state=='closed' and not io._handles,'holder finalization failed')
                pipe.send({'released':ordinal})
                if mode=='handoff':
                    require(pipe.poll(15) and pipe.recv()=={'next':ordinal},'holder next barrier timeout')
            finally:
                row.update(events=lock.events,state=lock.state)
    except BaseException as error:
        result['error'] = error_value(error)
    finally:
        result['native_file_handles'] = len(io._handles) if io else 0
        try:
            pipe.send({'result':result})
        finally:
            pipe.close()
    if result.get('error'):
        raise RuntimeError('own holder failed; structured result retained')


def crash_checker(pipe, value, keep_reference):
    io, observer = None, None
    result = {'keep_reference':keep_reference,'pid':os.getpid(),'events':[]}
    try:
        require(type(keep_reference) is bool,'invalid checker mode')
        native,module,scoped,locks = modules()
        io = module.NativeIO()
        grant = grant_from(value,io,native,module,scoped)
        lock = locks.NativeRootMutex(io,grant)
        if keep_reference:
            # An independent pre-existing reference keeps the same OS object
            # alive across holder death. It never waits or claims ownership.
            observer, code, event = lock._call('CreateMutexExW',(None,lock.name,0,0x00100001),
                role='independent_reference_only',name=lock.name)
            require(observer and code==183, 'pre-existing holder mutex not observed')
            result['observer_open'] = event.copy()
        pipe.send({'ready':True,'pid':os.getpid(),'reference_open':bool(observer)})
        require(pipe.poll(15) and pipe.recv()=={'holder_dead':True}, 'checker death barrier timeout')
        if keep_reference:
            result['abandoned_rejection'] = expect_error(lock.acquire,'ntfs.abandoned_root_lock_recovery_required')
            require(lock.state=='closed','abandoned lease not finalized')
            following = locks.NativeRootMutex(io,grant)
            result['quarantine_rejection'] = expect_error(following.acquire,'ntfs.root_lock_worker_quarantined')
            require(not following.events,'quarantined attempt made OS calls')
        else:
            with lock:
                lock.assert_held()
            require([event['result'] for event in lock.events if event['api']=='WaitForSingleObject']==[0],
                    'last-handle disappearance control did not return WAIT_OBJECT_0')
            result['durable_recovery_authorization'] = False
        result['events'] = lock.events
        result['state'] = lock.state
    except BaseException as error:
        result['error'] = error_value(error)
    finally:
        if observer is not None:
            try:
                closed, code, event = lock._call('CloseHandle',(observer,),role='independent_reference_only')
                result['observer_close'] = event.copy()
                require(closed,'observer close failed '+str(code))
            except BaseException as error:
                result['finalization_error'] = error_value(error)
        result['native_file_handles'] = len(io._handles) if io else 0
        pipe.send({'result':result})
        pipe.close()
    if result.get('error') or result.get('finalization_error'):
        raise RuntimeError('own crash checker failed; structured result retained')


def receive(pipe, timeout=15):
    require(pipe.poll(timeout),'own actor response timeout')
    return pipe.recv()


def finish(process, pipe, child, row, record, *, injected=False):
    errors = []
    for connection in (pipe,child):
        try:
            connection.close()
        except BaseException as error:
            errors.append({'stage':'pipe_close','error':error_value(error)})
    if process.pid:
        try:
            process.join(10)
            if process.is_alive():
                row['unexpected_termination_requested'] = True
                process.terminate()
                process.join(10)
            row.update(worker_exitcode=process.exitcode,worker_alive=process.is_alive())
            if not row['worker_alive']:
                process.close()
            require(not row['worker_alive'],'own worker remains alive')
            require(not row.get('unexpected_termination_requested'),'own worker forced to finalize')
            require((injected and row['worker_exitcode']!=0) or (not injected and row['worker_exitcode']==0),
                    'own worker exit status mismatch')
        except BaseException as error:
            errors.append({'stage':'process_finalize','error':error_value(error)})
    if errors:
        row['finalization_errors'] = errors
        record['safety_stop'] = True
        raise RuntimeError('structured worker finalization failure')


def main():
    native,module,scoped,locks = modules()
    folder,repo = Path(__file__).parent,Path.cwd()
    controller = common.load('controller',repo/'qualification/campaign.py',
        '245caaf82aef4e8f0e5584405e6530ec9ef8e35aba5c2180bf92d4ce1b216eab')
    archive = common.load('archive',folder/'ext4_archive_v2.py',common.ARCHIVE)
    provisional = repo.parent/'qualification-campaigns'/common.CAMPAIGN
    state = json.loads((provisional/'state.json').read_bytes())
    controller.verify_owned(state)
    controller.verify_owned(state,read_only=True)
    native.ownership()
    case = native.PROBE/CASE
    native.checked(case,exists=False)
    case.mkdir(exist_ok=False)
    sentinel_data = hashlib.sha256(b'root-mutex-sentinel-v1').digest()*2048
    sentinel = case/'sentinel.bin'
    sentinel.open('xb').write(sentinel_data)
    old,io = native.Native(),module.NativeIO()
    sentinel_before = common.raw_metadata(old,sentinel)
    root_before = common.raw_metadata(old,case)
    facts = io.volume()
    grant = scoped.NativeRootGrant('phase_result_root',facts['device'],facts['volume_guid'],facts['volume_serial32'],
        ('Phase-NTFS-Qualification',common.CAMPAIGN,'transport-cases','nt-native-v3',CASE),
        module.NativeIdentity.parse(root_before['native_identity']))
    record = {'case':'NATIVE_ROOT_MUTEX_V1','campaign':common.CAMPAIGN,'primitive_verdict':'NOT_VERIFIED',
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'grant':grant.as_dict(),'sentinel_before':sentinel_before,'contention':[],'handoff':[],
        'crash_cases':[],'a05_verdict':'NOT_VERIFIED','g06_verdict':'NOT_VERIFIED',
        'phase_route_verdict':'NOT_VERIFIED','two_container_coordinator_verdict':'NOT_VERIFIED',
        'pending_index_implemented':False,'overlapping_grants_admission_implemented':False}
    source_paths = [(name,repo/name) for name in SOURCES] + [(name,folder/name) for name in
        ('native_root_mutex_probe.py','native_io_probe.py','native_rename_probe_v3.py','ext4_archive_v2.py')]
    record['source_snapshot'] = [{'name':name,'sha256':hashlib.sha256(data).hexdigest(),
        'bytes_base64':base64.b64encode(data).decode('ascii')} for name,path in source_paths for data in [path.read_bytes()]]
    context = MP.get_context('spawn')
    try:
        # Same-process recursion and wrong-thread attempts must make no calls.
        lock = locks.NativeRootMutex(io,grant)
        with lock:
            alias = locks.NativeRootMutex(io,grant)
            record['recursion_rejection'] = expect_error(alias.acquire,'ntfs.recursive_root_lock_forbidden')
            require(not alias.events,'recursive attempt made calls')
            errors = []
            before_events = len(lock.events)
            def wrong_thread():
                for operation in (lock.assert_held,lock.acquire,lock.close):
                    errors.append(expect_error(operation,'ntfs.root_lock_wrong_thread_or_process'))
            thread = threading.Thread(target=wrong_thread)
            thread.start();thread.join(3)
            require(not thread.is_alive() and len(errors)==3,'thread-affinity check absent')
            require(len(lock.events)==before_events,'wrong thread made calls')
            lock.assert_held()
            record['wrong_thread_rejections'] = errors
        record['initial_lock_events'] = lock.events
        barrier,owner,counter = context.Barrier(8),context.Value('i',0,lock=False),context.Value('i',0,lock=False)
        workers = []
        try:
            for ordinal in range(8):
                pipe,child = context.Pipe()
                process = context.Process(target=contender,args=(child,grant.as_dict(),ordinal,barrier,owner,counter))
                row = {'ordinal':ordinal}
                workers.append((process,pipe,child,row))
                record['contention'].append(row)
                process.start();child.close()
            for process,pipe,child,row in workers:
                row['ready_packet'] = receive(pipe)
                require(row['ready_packet'].get('ready'),'contender not ready')
            for process,pipe,child,row in workers:
                message = receive(pipe,300)
                row['final_packet'] = message
                require('result' in message,'contender result absent')
                require(not message['result'].get('error') and message['result']['native_file_handles']==0,'contender failed')
        except BaseException as error:
            record['contention_primary_error'] = error_value(error)
            raise
        finally:
            failures = []
            for process,pipe,child,row in workers:
                try:
                    finish(process,pipe,child,row,record)
                except BaseException as error:
                    row['finalization_error'] = error_value(error);failures.append(str(error))
            require(not failures,'contention finalization '+str(failures))
        require(counter.value==800 and owner.value==0,'counter/owner mismatch')
        intervals = sorted((entry['entered_ns'],entry['left_ns']) for row in record['contention']
                           for entry in row['final_packet']['result']['records'])
        require(len(intervals)==800 and all(a<=b for a,b in intervals),'missing critical intervals')
        require(all(intervals[i][1]<=intervals[i+1][0] for i in range(799)),'observed ownership overlap')
        record['contention_counter'] = counter.value
        # 100 actual timeouts, followed by 100 handoffs to a separate process.
        pipe,child = context.Pipe()
        process = context.Process(target=holder,args=(child,grant.as_dict(),'handoff'))
        holder_row = {}
        try:
            process.start();child.close()
            for ordinal in range(100):
                row = {'ordinal':ordinal}
                record['handoff'].append(row)
                ready = receive(pipe)
                row['holder'] = ready
                require(ready.get('held')==ordinal,'holder barrier absent')
                denied = locks.NativeRootMutex(io,grant,timeout_ms=10)
                row['timeout'] = expect_error(denied.acquire,'ntfs.root_lock_timeout')
                row['timeout_events'] = denied.events
                require(denied.state=='closed' and not io._handles,'timeout finalization')
                pipe.send({'release':ordinal})
                row['holder_released_packet'] = receive(pipe)
                require(row['holder_released_packet']=={'released':ordinal},'holder release absent')
                acquired = locks.NativeRootMutex(io,grant)
                with acquired:
                    acquired.assert_held()
                row['handoff_events'] = acquired.events
                row['completed'] = True
                pipe.send({'next':ordinal})
            holder_row['final_packet'] = receive(pipe)
            require(not holder_row['final_packet']['result'].get('error'),'handoff holder failed')
        except BaseException as error:
            holder_row['primary_error'] = error_value(error)
            raise
        finally:
            record['handoff_holder'] = holder_row
            finish(process,pipe,child,holder_row,record)
        # With a pre-existing reference WAIT_ABANDONED must fail closed; with
        # no surviving handle a fresh mutex forgets the crash. Neither case may
        # authorize persistent recovery or any target mutation.
        for keep_reference in (True,False):
            for ordinal in range(10):
                row = {'keep_reference':keep_reference,'ordinal':ordinal,'completed':False}
                record['crash_cases'].append(row)
                hp,hc = context.Pipe();cp,cc = context.Pipe()
                hp_process = context.Process(target=holder,args=(hc,grant.as_dict(),'crash'))
                cp_process = context.Process(target=crash_checker,args=(cc,grant.as_dict(),keep_reference))
                injected = False
                try:
                    hp_process.start();hc.close()
                    row['holder_ready'] = receive(hp)
                    require(row['holder_ready'].get('held')==0,'crash holder not held')
                    cp_process.start();cc.close()
                    row['checker_ready'] = receive(cp)
                    require(row['checker_ready'].get('ready') and
                            row['checker_ready']['reference_open']==keep_reference,'checker not ready')
                    require(hp_process.is_alive(),'holder died before intended fault window')
                    row['termination_requested_ns'] = time.monotonic_ns()
                    hp_process.terminate();injected = True
                    hp_process.join(10)
                    require(not hp_process.is_alive() and hp_process.exitcode!=0,'holder crash not reached')
                    row['holder_dead_ns'] = time.monotonic_ns()
                    cp.send({'holder_dead':True})
                    row['checker_final_packet'] = receive(cp)
                    checker = row['checker_final_packet']['result']
                    require(not checker.get('error') and not checker.get('finalization_error')
                            and checker['native_file_handles']==0,'crash checker failed')
                    row['completed'] = True
                except BaseException as error:
                    row['primary_error'] = error_value(error)
                    raise
                finally:
                    failures = []
                    for process,pipe,child,key in ((hp_process,hp,hc,'holder_final'),(cp_process,cp,cc,'checker_final')):
                        row[key] = {}
                        try:
                            finish(process,pipe,child,row[key],record,injected=injected and key=='holder_final')
                        except BaseException as error:
                            row[key]['error'] = error_value(error);failures.append(str(error))
                    require(not failures,'crash worker finalization '+str(failures))
        record['primitive_verdict'] = 'SUPPORTED'
    except BaseException as error:
        record['error'] = error_value(error)
    record['native_file_handles'] = len(io._handles)
    try:
        record['sentinel_after'] = common.raw_metadata(old,sentinel)
        record['sentinel_digest'] = controller.sha(sentinel.read_bytes())
        record['sentinel_unchanged'] = (record['sentinel_after']==sentinel_before and sentinel.read_bytes()==sentinel_data)
    except BaseException as error:
        record['sentinel_error'] = error_value(error)
        record['sentinel_unchanged'] = False
    if not record['sentinel_unchanged'] or io._handles:
        record.update(safety_stop=True,primitive_verdict='UNSUPPORTED')
    require(len(json.dumps(record,sort_keys=True).encode('utf-8'))<=4*1024**2,'bounded raw exceeded 4MiB')
    name = 'g-native-root-mutex-'+str(time.time_ns())
    binding = archive.retain(controller,state,provisional,record,name)
    state['records'].append(binding|{'action':'native-root-mutex-v1','lane':'MIX','result':{
        'primitive_verdict':record['primitive_verdict'],'phase_route_verdict':'NOT_VERIFIED'}})
    controller.update_state(provisional/'state.json',state)
    print(json.dumps(binding|{'primitive_verdict':record['primitive_verdict'],'error':record.get('error'),
        'contention_counter':record.get('contention_counter'),'handoffs':len(record['handoff']),
        'crash_completed':sum(row['completed'] for row in record['crash_cases'])},indent=2))
    require(not record.get('safety_stop'),'SAFETY STOP: finalization or sentinel; raw preserved')


if __name__ == '__main__':
    main()
