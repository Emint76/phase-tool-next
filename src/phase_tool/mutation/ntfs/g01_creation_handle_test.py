"""Unselected qualification-only passive transfer of actual worker creation HANDLE.

No process spawn/termination, PID lookup of worker, job transfer, authority,
receipt, retry or effect protocol. Ordinary launchers never construct this token.
Only a fixed source-pinned external CLI qualification launcher may select it.
ACK-loss never authorizes sender to close a remote numeric handle. The exact
finite receiver must independently query/wait/close, or establish its own exit
while retaining unknown worker outcome. No Native qualification is implied.
"""
from __future__ import annotations
import ctypes as C
import os
from pathlib import Path
import re
import threading
import time
import uuid
from ...canonical import canonical_bytes,canonical_digest,digest_bytes,parse_json_bytes
from ...evidence import _read_dynamic_a05_fixed as _fixed_read
from ...evidence import _read_qualification_catalog_chunk as _artifact_read
from ...evidence import _write_dynamic_a05_telemetry as _write_raw
from ...errors import PhaseError
from .native import _require
from .process_witness import WindowsProcessWitness,_FileTime

_CAMPAIGN='c41b087a-7bed-4bca-8621-dd83effc8abf'
_CUT='worker-job-bound-before-original'
_LAUNCHER_DIGEST='sha256:34fd9c519b3f544e84fbfdea6ab14fbae97fc9fb661285a40751eb4247536b61'
_ROLES=('File1','File2','Version1','Version2','Bundle1','Bundle2')
DIGEST=re.compile(r'sha256:[0-9a-f]{64}')

def need(value,message):
    _require(value,'ntfs.g01_test_'+message.replace(' ','_'))

class _SenderOwnership:
    """Exactly one creation-HANDLE duplicate; sender never reclaims remotely."""
    def __init__(self):
        self.owner = os.getpid(),threading.get_ident()
        self.state = 'NEW'
        self.remote_handle = None
        self.offer_digest = None
        self.receiver_ownership_confirmed = False
        self.failed = False

    def _owned(self):
        need(self.owner == (os.getpid(),threading.get_ident()), 'sender owner changed')
        need(not self.failed, 'sender transfer failed and sticky')

    def duplicated(self, remote_handle):
        self._owned()
        need(self.state == 'NEW' and type(remote_handle)is int and remote_handle>0,
             'sole actual duplicate required')
        self.remote_handle=remote_handle
        self.state='CREATED'

    def before_offer(self, offer_digest):
        self._owned()
        need(self.state=='CREATED' and type(offer_digest)is str
             and DIGEST.fullmatch(offer_digest)is not None,'one exact offer required')
        self.offer_digest=offer_digest
        self.state='OFFER_POSSIBLE'  # BEFORE any raw write or signal attempt.

    def acknowledged(self, offer_digest):
        self._owned()
        need(self.state=='OFFER_POSSIBLE' and offer_digest==self.offer_digest,
             'exact receiver ACK required')
        self.receiver_ownership_confirmed=True
        self.state='RECEIVER_OWNS'

    def before_arm(self):
        self._owned()
        need(self.state=='RECEIVER_OWNS','cannot arm before ACK')
        self.state='ARM_POSSIBLE'  # BEFORE late telemetry/signalling IO.

    def armed(self):
        self._owned()
        need(self.state=='ARM_POSSIBLE','arm transition required')
        self.state='ARMED'

    def released(self):
        self._owned()
        need(self.state=='ARMED','one controlled no-kill release required')
        self.state='RELEASED'

    def fail(self):
        need(self.owner == (os.getpid(),threading.get_ident()),'sender owner changed')
        self.failed=True
        self.state='UNKNOWN'

    @property
    def may_close_remote(self):
        # Even an ACK can be lost after receiver accepted/closed/reused the
        # numeric handle. No DUPLICATE_CLOSE_SOURCE or sender remote close.
        return False

    @property
    def may_send_GO(self):
        return self.state=='RELEASED' and not self.failed



class _G01Kernel:
    def __init__(self):
        _require(os.name=='nt','ntfs.g01_test_windows_required')
        self.owner=os.getpid(),threading.get_ident()
        self.k=C.WinDLL('kernel32',use_last_error=True)
        self.handles=[];self.events=[];self.close_attempted=set()
        specs={
            'GetCurrentProcess':([],C.c_void_p),
            'OpenProcess':([C.c_uint32,C.c_int32,C.c_uint32],C.c_void_p),
            'GetProcessId':([C.c_void_p],C.c_uint32),
            'GetProcessTimes':([C.c_void_p]+[C.POINTER(_FileTime)]*4,C.c_int32),
            'QueryFullProcessImageNameW':([C.c_void_p,C.c_uint32,C.c_wchar_p,C.POINTER(C.c_uint32)],C.c_int32),
            'DuplicateHandle':([C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p),C.c_uint32,C.c_int32,C.c_uint32],C.c_int32),
            'OpenEventW':([C.c_uint32,C.c_int32,C.c_wchar_p],C.c_void_p),
            'SetEvent':([C.c_void_p],C.c_int32),
            'WaitForMultipleObjects':([C.c_uint32,C.POINTER(C.c_void_p),C.c_int32,C.c_uint32],C.c_uint32),
            'WaitForSingleObject':([C.c_void_p,C.c_uint32],C.c_uint32),
            'CloseHandle':([C.c_void_p],C.c_int32)}
        for name,(args,result)in specs.items():
            getattr(self.k,name).argtypes=args;getattr(self.k,name).restype=result

    def call(self,name,*args,boolean=True):
        _require(self.owner==(os.getpid(),threading.get_ident()),'ntfs.g01_test_owner_changed')
        C.set_last_error(0);before=time.perf_counter_ns()
        value=getattr(self.k,name)(*args);code=C.get_last_error()
        self.events.append({'api':name,'result':value,'winerror':code,'started_ns':before,'returned_ns':time.perf_counter_ns()})
        if boolean and not value:raise C.WinError(code)
        return value

    def retain(self,handle):
        _require(type(handle)is int and handle>0 and handle not in self.handles,'ntfs.g01_test_handle_owner')
        self.handles.append(handle);return handle

    def identity(self,handle):
        pid=self.call('GetProcessId',handle);times=[_FileTime()for _ in range(4)]
        self.call('GetProcessTimes',handle,*(C.byref(value)for value in times))
        return {'pid':pid,'creation_filetime':times[0].integer()}

    def image(self,handle):
        buffer=C.create_unicode_buffer(32768);size=C.c_uint32(len(buffer))
        self.call('QueryFullProcessImageNameW',handle,0,buffer,C.byref(size))
        _require(0<size.value<len(buffer)and buffer[size.value]=='\0','ntfs.g01_test_harness_image')
        return Path(buffer.value)

    def close_local(self):
        errors=[]
        for handle in reversed(self.handles):
            if handle in self.close_attempted:continue
            self.close_attempted.add(handle)  # Sticky before API, never numeric close retry.
            try:self.call('CloseHandle',handle)
            except BaseException as error:errors.append(error)
        if errors:raise BaseExceptionGroup('G01 local control handle closure incomplete',errors)


class _G01CreationHandleTest:
    __slots__=('_launch','_owner','_deadline','_binding_bytes','_binding','_consumed','_initialized','_transfer')

    def __init__(self,launch,*,_initial_deadline_ns):
        from .bootstrap import _NativeAcceptedLaunch
        _require(type(self)is _G01CreationHandleTest and type(launch)is _NativeAcceptedLaunch,
            'ntfs.g01_test_role_required')
        _require(not getattr(self,'_initialized',False),'ntfs.g01_test_initialization_consumed')
        self._initialized=True;self._launch=launch;self._owner=os.getpid(),threading.get_ident()
        self._deadline=_initial_deadline_ns;self._consumed=False;self._transfer=None
        _require(type(self._deadline)is int and 0<self._deadline-time.perf_counter_ns()<=30_000_000_000,
            'ntfs.g01_test_deadline_required')
        self.check_launch(launch)
        config=launch._config;path=Path(config['windows_launcher']).parent/'g01-creation-handle-test.json'
        raw=_fixed_read(path);pin=config['dependency_file_digests'].get(str(path))
        _require(DIGEST.fullmatch(pin or '')is not None and digest_bytes(raw)==pin
            and config['artifact_graph']['windows']['dependency_file_digests'].get(str(path))==pin,
            'ntfs.g01_test_source_graph')
        self._binding_bytes=raw;self._binding=self._parse_binding(raw)
        started,deadline=(self._binding[key] for key in ('case_started_ns','case_deadline_ns'))
        _require(type(started)is int and type(deadline)is int
            and 0<started<=time.perf_counter_ns()<deadline<=self._deadline
            and deadline-started==30_000_000_000,'ntfs.g01_test_owner_clock_mismatch')
        self._deadline=deadline

    @property
    def deadline_ns(self):
        return self._deadline

    def check_launch(self,launch):
        from .bootstrap import _NativeAcceptedLaunch
        from .owner_directory_fixture import fixture_role,_kinds
        _require(type(self)is _G01CreationHandleTest and type(launch)is _NativeAcceptedLaunch
            and launch is self._launch and self._owner==(os.getpid(),threading.get_ident())
            and not self._consumed,'ntfs.g01_test_owner_required')
        launch.check_runtime()
        ctx=launch._experimental_admission_context
        doc,role=fixture_role(type(ctx),ctx.raw)
        _require(type(ctx)is _kinds()[role['role']] and doc['experimental_admission_version']=='2.0'
            and launch._inspection_only is False and launch.invocation['request'].get('operation')=='execute',
            'ntfs.g01_test_closed_owner2_required')
        config=launch._config;graph=config['artifact_graph']
        _require(graph['launcher_digest']==_LAUNCHER_DIGEST
            and digest_bytes(_fixed_read(Path(config['windows_launcher'])))==_LAUNCHER_DIGEST
            and canonical_digest(graph)==launch.manifest['composition']['artifact_graph_digest'],
            'ntfs.g01_test_fixed_launcher_required')

    def _parse_binding(self,raw):
        from .owner_directory_fixture import fixture_role
        value=parse_json_bytes(raw,maximum_bytes=65536)
        fields={'g01_creation_handle_test_version','campaign','fixture_uuid','role','repeat','cut','run_id',
            'installation_id','contract','root_grants_digest','evidence_identity_digest',
            'preparation_identity_digest','harness','nonce','case_started_ns','case_deadline_ns'}
        _require(type(value)is dict and set(value)==fields and canonical_bytes(value)==raw
            and value['g01_creation_handle_test_version']=='1.0'and value['campaign']==_CAMPAIGN
            and value['role']in _ROLES and type(value['repeat'])is int and 0<=value['repeat']<10
            and value['cut']==_CUT and re.fullmatch('[0-9a-f]{64}',value['nonce'])is not None,
            'ntfs.g01_test_binding_shape')
        case=str(uuid.uuid5(uuid.UUID(_CAMPAIGN),value['role']+':'+str(value['repeat'])))
        doc,role=fixture_role(type(self._launch._experimental_admission_context),self._launch._experimental_admission_context.raw)
        _require(value['fixture_uuid']==case==doc['fixture_uuid']and role['role']==value['role']
            and value['run_id']==self._launch.run_id==f'od2-{case}-g01-{value["role"].lower()}-{value["repeat"]:02d}'
            and value['installation_id']==self._launch.manifest['installation_id']
            and value['contract']==self._launch.manifest['contract']
            and value['root_grants_digest']==canonical_digest(self._launch.root_grants)
            and value['evidence_identity_digest']==canonical_digest(self._launch.manifest['evidence_identity'])
            and value['preparation_identity_digest']==canonical_digest(self._launch.manifest['preparation_identity']),
            'ntfs.g01_test_binding_mismatch')
        harness=value['harness']
        _require(type(harness)is dict and set(harness)=={'pid','creation_filetime','image_path','image_sha256'}
            and type(harness['pid'])is int and harness['pid']>0 and harness['pid']!=os.getpid()
            and type(harness['creation_filetime'])is int and harness['creation_filetime']>0
            and type(harness['image_path'])is str and Path(harness['image_path']).is_absolute()
            and DIGEST.fullmatch(harness['image_sha256'])is not None,'ntfs.g01_test_harness_shape')
        return value

    def worker_job_bound(self,launch,process,parsed,*,_exchange_deadline_ns=None):
        self.check_launch(launch);self._consumed=True  # BEFORE native/offer/wait errors.
        deadline=self._deadline
        if _exchange_deadline_ns is not None:
            _require(type(_exchange_deadline_ns)is int,'ntfs.g01_test_deadline_required')
            deadline=min(deadline,_exchange_deadline_ns)
        deadline=min(deadline,time.perf_counter_ns()+5_000_000_000)
        def remaining():
            left=deadline-time.perf_counter_ns();_require(left>0,'ntfs.g01_test_deadline')
            return left//1000000
        remaining()
        from .worker_job import WindowsWorkerJob
        _require(process is launch._worker and type(launch._worker_job)is WindowsWorkerJob,
            'ntfs.g01_test_genuine_worker_job_required')
        launch._worker_job.check_bound(process)
        witness=WindowsProcessWitness(process);fact=witness.wait_for_exit(0)
        _require(fact['wait_result']==0x102 and fact['worker_exit_established']is False,
            'ntfs.g01_test_live_worker_required')
        context=parse_json_bytes(parsed.context_bytes,maximum_bytes=4096)
        _require(context['run_id']==launch.run_id and context['operation_nonce']==launch.operation_nonce
            and context['installation_digest']==launch.installation_digest and DIGEST.fullmatch(context['intent_digest'])is not None,
            'ntfs.g01_test_original_binding')
        control=_G01Kernel();transfer=_SenderOwnership();self._transfer=transfer
        primary=None
        try:
            expected=self._binding['harness'];remaining()
            _require(expected['pid']!=witness.pid,'ntfs.g01_test_worker_pid_lookup_forbidden')
            # This PID is the exact source-pinned, known LIVE own finite harness.
            # Never OpenProcess(workerPID), never search any process.
            harness=control.retain(control.call('OpenProcess',0x101040,False,expected['pid']))
            _require(control.identity(harness)=={k:expected[k]for k in('pid','creation_filetime')}
                and control.call('WaitForSingleObject',harness,0,boolean=False)==0x102,
                'ntfs.g01_test_harness_identity')
            image=control.image(harness)
            _require(image.samefile(Path(expected['image_path']))
                and digest_bytes(_artifact_read(image,32*1024**2))==expected['image_sha256'],
                'ntfs.g01_test_harness_image')
            names={kind:'Local\\Phase-G01-'+self._binding['fixture_uuid']+'-'+self._binding['nonce']+'-'+kind
                for kind in('offer','ack','armed','abort','release')}
            events={kind:control.retain(control.call('OpenEventW',0x100002,False,name))for kind,name in names.items()}
            # All control handles are local and non-inherited; none is a job HANDLE.
            for kind in events:
                _require(control.call('WaitForSingleObject',events[kind],0,boolean=False)==0x102,
                    'ntfs.g01_test_event_already_signalled')
            copied=C.c_void_p();remaining();witness._owned()
            control.call('DuplicateHandle',control.call('GetCurrentProcess',boolean=False),
                witness.handle,harness,C.byref(copied),0x00101000,False,0)
            transfer.duplicated(copied.value)
            offer={'g01_offer_version':'1.0','campaign':_CAMPAIGN,'cut':_CUT,'nonce':self._binding['nonce'],
                'run_id':launch.run_id,'role':self._binding['role'],'fixture_uuid':self._binding['fixture_uuid'],
                'parent_pid':os.getpid(),'cut_wait_deadline_ns':deadline,'original_deadline_ns':self._deadline,
                'captured_ns':time.perf_counter_ns(),'clock':'same-host-Windows-perf-counter-ns','harness_identity':{k:expected[k]for k in('pid','creation_filetime')},
                'worker':{'handle':copied.value,'pid':fact['pid'],'creation_filetime':fact['creation_filetime']},
                'context':context,'intent_digest':context['intent_digest'],'go_sent':False,
                'job_handle_duplicated':False,'observation_authoritative':False,'final_acceptance':None}
            raw=canonical_bytes(offer);offer_digest=digest_bytes(raw)
            transfer.before_offer(offer_digest)  # BEFORE first potentially visible byte.
            parent=Path(launch._config['windows_launcher']).parent
            remaining();_write_raw(parent/'g01-worker-offer.json',offer);remaining()
            control.call('SetEvent',events['offer']);remaining()
            pair=(C.c_void_p*2)(events['abort'],events['ack'])
            result=control.call('WaitForMultipleObjects',2,pair,False,remaining(),boolean=False)
            _require(result==1,'ntfs.g01_test_ack_unconfirmed')
            remaining()
            ack_raw=_fixed_read(parent/'g01-receiver-ack.json')
            ack=parse_json_bytes(ack_raw,maximum_bytes=65536)
            _require(canonical_bytes(ack)==ack_raw and ack=={
                'g01_ack_version':'1.0','offer_digest':offer_digest,'nonce':self._binding['nonce'],
                'run_id':launch.run_id,'harness_identity':offer['harness_identity'],
                'worker':offer['worker'],'actual_receiver_live_handle_checked':True,
                'observation_authoritative':False,'final_acceptance':None},
                'ntfs.g01_test_exact_receiver_ack_required')
            remaining();transfer.acknowledged(ack['offer_digest'])
            transfer.before_arm()
            _write_raw(parent/'g01-parent-armed.json',{'g01_arm_version':'1.0','offer_digest':offer_digest,
                'nonce':self._binding['nonce'],'run_id':launch.run_id,'receiver_ownership_acknowledged':True,
                'cut_wait_deadline_ns':deadline,'original_deadline_ns':self._deadline,
                'armed_observed_ns':time.perf_counter_ns(),'go_sent':False,'final_acceptance':None})
            remaining();control.call('SetEvent',events['armed']);remaining();transfer.armed()
            # This interrupted fixture cannot grant release or send Original.
            pair=(C.c_void_p*2)(events['abort'],events['release'])
            control.call('WaitForMultipleObjects',2,pair,False,remaining(),boolean=False)
            raise PhaseError('ntfs.g01_test_interruption_not_observed')
        except BaseException as error:
            transfer.fail();primary=error
        finally:
            try:control.close_local()
            except BaseException as error:
                transfer.fail()
                if primary is None:primary=error
                else:primary=BaseExceptionGroup('G01 operation and local closure failed',[primary,error])
        # Local fstat/close or reporting cannot renew the original deadline.
        try:remaining()
        except BaseException as error:
            transfer.fail()
            if primary is None:primary=error
            else:primary=BaseExceptionGroup('G01 primary and final clock failed',[primary,error])
        if primary is not None:raise primary
        _require(transfer.may_send_GO,'ntfs.g01_test_transfer_unresolved')
