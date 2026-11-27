"""Portable component models only. No Windows/NTFS, admission or qualification.

These exercise real capture/framing/lineage/remaining-effect decision code with
explicit modeled OS boundaries. Source212 must precede their first execution.
"""
import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import threading
import time
import unittest
from unittest.mock import Mock,patch

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bundle_recovery_terminal as terminal
from phase_tool.mutation.ntfs.bundle_recovery_capture import completion_wait_deadline,wire_record
from phase_tool.mutation.ntfs.bundle_recovery_original import verify_quiescence,verify_trace,_record,_wire
from phase_tool.mutation.ntfs.bundle_recovery_worker import validate_recovery_ready,execute_remaining
from phase_tool.mutation.ntfs.bundle_execution import _bundle_projection_value,_BUNDLE2_CONTRACT_V2
from phase_tool.mutation.ntfs.native import NativeIdentity
from .test_native_bundle2_prepared import b2_projection,native_stage


def recovery_fixture():
    project=replace(b2_projection(),contract_bytes=canonical_bytes(_BUNDLE2_CONTRACT_V2))
    from phase_tool.mutation.ntfs.bundle_prepared import prepared_locator
    prepared={'stage_locator':prepared_locator(project),'device':native_stage(project)['stat_identity']['device'],
        'inode':native_stage(project)['stat_identity']['inode']}
    old=parse_json_bytes(project.context_bytes)
    context={'native_recovery_context_version':'1.0','run_id':old['run_id'],
        'intent_digest':old['intent_digest'],'effect_plan_digest':old['effect_plan_digest'],
        'installation_digest':old['installation_digest'],'operation_nonce':'8'*32,'channel_id':'9'*32,
        'original_operation_nonce':old['operation_nonce'],'preparation_digest':digest_bytes(canonical_bytes(prepared)),
        'mode':'commit_prepared'}
    return project,prepared,context


def witness_parent():
    apis=['GetProcessId','GetProcessTimes','GetProcessId','GetProcessTimes',
        'WaitForSingleObject','GetExitCodeProcess','GetProcessId','GetProcessTimes']
    events=[{'api':api,'outcome':'returned','started_ns':i*10+1,'returned_ns':i*10+2,
        'result':123 if api=='GetProcessId' else 0 if api=='WaitForSingleObject' else 1,
        'winerror':0}for i,api in enumerate(apis)]
    return {'process_witness':{'process_witness_version':'1.0','pid':123,
        'creation_filetime':134377902787700038,'wait_result':0,'worker_exit_established':True,
        'exit_code':0,'events':events},'owner_finalization':{
        'worker_stdin':'closed','worker_stdout':'closed','worker_stderr':'closed',
        'creation_handle':'closed','errors':[]}}


class RecoveryProofComponentTests(unittest.TestCase):
    def test_retained_handle_calls_required_in_addition_to_exit_flags(self):
        parent=witness_parent();verify_quiescence(parent,{'pid':123})
        for change in ('events','pid','creation_filetime','wait_result','exit_code'):
            bad=deepcopy(parent)
            bad['process_witness'][change]=[] if change=='events' else False
            with self.subTest(field=change),self.assertRaises(PhaseError):
                verify_quiescence(bad,{'pid':123})

    def test_eof_self_report_or_close_error_never_supplies_quiescence(self):
        for replacement in ({'creation_handle':'unknown'},{'errors':[{'code':'close.failed'}]}):
            parent=witness_parent();parent['owner_finalization'].update(replacement)
            with self.assertRaises(PhaseError):verify_quiescence(parent,{'pid':123})
        parent=witness_parent();parent['process_witness']['events'][4]['result']=0x102
        with self.assertRaises(PhaseError):verify_quiescence(parent,{'pid':123})

    def test_trace_requires_exact_full_records_and_actual_lf_digest(self):
        rows=[{'api':'NtSetInformationFile','class':10}]
        trace={'capture_complete':True,'capture_errors':[],'unacknowledged_records_upper_bound':0,
            'raw_records_complete':True,'omitted_middle_records':0,'records':rows,
            'acknowledged_recorded_event_count':1,
            'canonical_jsonl_digest':digest_bytes(canonical_bytes(rows[0])+b'\n')}
        self.assertEqual(verify_trace({'mutation_trace':trace}),rows)
        for key,value in [('omitted_middle_records',1),('raw_records_complete',False),
                ('acknowledged_recorded_event_count',2),
                ('canonical_jsonl_digest',digest_bytes(canonical_bytes(rows[0])+b'\\n'))]:
            bad=deepcopy(trace);bad[key]=value
            with self.subTest(key=key),self.assertRaises(PhaseError):verify_trace({'mutation_trace':bad})

    def test_full_raw_completion_bytes_correlated_not_only_nested_claim(self):
        raw=canonical_bytes({'context':{'run_id':'modeled'},'body':'x'*20000})
        self.assertEqual(_wire(wire_record(raw)),raw)
        bad=wire_record(raw);bad['bytes_base64']=base64.b64encode(raw+b' ').decode()
        with self.assertRaises(PhaseError):_wire(bad)

    def test_native_control_reader_retains_over_host_1mib_but_refuses_over_2mib(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temp:
            path=Path(temp)/'native-parent-failure.json'
            value={'diagnostic':'x'*(1024**2+1)};path.write_bytes(canonical_bytes(value))
            self.assertEqual(_record(path),value)
            path.write_bytes(canonical_bytes({'diagnostic':'x'*(2*1024**2)}))
            with self.assertRaises(PhaseError):_record(path)

    def test_ready_rejects_foreign_original_nonce_intent_install_and_full_inode(self):
        project,prepared,context=recovery_fixture()
        ready={'native_recovery_ready_version':'1.0','context':context,'pid':123,'selected':'stage',
            'native':native_stage(project),'mutex_state':'held','stage_lease':'retained'}
        validate_recovery_ready(ready,context=context,projection=project,prepared=prepared,expected_pid=123)
        for field in ('intent_digest','installation_digest','original_operation_nonce'):
            other=deepcopy(context);other[field]=('a'*32 if field.endswith('nonce') else 'sha256:'+'a'*64)
            changed=deepcopy(ready);changed['context']=other
            with self.subTest(field=field),self.assertRaises(PhaseError):
                validate_recovery_ready(changed,context=other,projection=project,prepared=prepared,expected_pid=123)
        bad=deepcopy(ready);bad['native']['stat_identity']['inode']&=(1<<64)-1
        with self.assertRaises(PhaseError):
            validate_recovery_ready(bad,context=context,projection=project,prepared=prepared,expected_pid=123)


class TerminalCaptureComponentTests(unittest.TestCase):
    def owner(self,*,failed=True,direction='send',count=0):
        return SimpleNamespace(_owner=(os.getpid(),threading.get_ident()),_sealed=False,_failed=failed,
            _last_frame_failure={'direction':direction,'progress':{'wire_bytes':count,'expected_wire_bytes':40}},
            _pipe=lambda side:(side,1,2),_identities=[(0,1,2),(1,1,2)])

    def test_partial_poisoned_writer_never_emits_second_frame(self):
        owner=self.owner(count=12)
        with patch.object(terminal.os,'write')as write,self.assertRaises(PhaseError)as caught:
            terminal._frame_io(owner,sending=True,raw=b'{}',deadline_ns=time.perf_counter_ns()+1_000_000_000,
                maximum_bytes=100,windows=True)
        self.assertEqual(caught.exception.code,'ntfs.terminal_boundary_unknown');write.assert_not_called()

    def test_opposite_direction_can_report_but_never_clears_poison(self):
        owner=self.owner(direction='receive',count=4)
        with patch.object(terminal.os,'write',side_effect=lambda fd,data:len(data)):
            terminal._frame_io(owner,sending=True,raw=b'{}',deadline_ns=time.perf_counter_ns()+1_000_000_000,
                maximum_bytes=100,windows=True)
        self.assertTrue(owner._failed)
        with patch.object(terminal.os,'write',side_effect=AssertionError('second write'))as write, self.assertRaises(PhaseError):
            terminal._frame_io(owner,sending=True,raw=b'{}',deadline_ns=time.perf_counter_ns()+1_000_000_000,
                maximum_bytes=100,windows=True)
        write.assert_not_called()

    def test_partial_frame_larger_than_human_diagnostic_keeps_exact_machine_prefix(self):
        prefix=b'00004e20\n'+b'x'*18000
        chunks=[prefix[:9],prefix[9:],b'']
        owner=self.owner(failed=False)
        with patch.object(terminal.os,'read',side_effect=chunks),self.assertRaises(PhaseError)as caught:
            terminal._frame_io(owner,sending=False,raw=None,deadline_ns=time.perf_counter_ns()+1_000_000_000,
                maximum_bytes=30000,windows=True)
        record=caught.exception.details
        self.assertEqual(base64.b64decode(record['wire_prefix_base64']),prefix)
        self.assertFalse(record['progress']['complete']);self.assertTrue(owner._failed)

    def test_completion_wait_helper_keeps_original_remaining_effect_budget(self):
        now=time.perf_counter_ns();original=now+20_000_000_000
        with patch('phase_tool.mutation.ntfs.bundle_recovery_capture.time.perf_counter_ns',return_value=now):
            bound=completion_wait_deadline(original)
        self.assertEqual(bound,original+5_000_000_000)
        self.assertGreater(bound,now+5_000_000_000)

    def test_first_partial_failure_not_overwritten_by_cleanup_call(self):
        from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames
        pipe=object.__new__(WindowsPipeFrames)
        pipe._gate=threading.Lock();pipe._failed=True
        origin={'direction':'send','progress':{'wire_bytes':12,'expected_wire_bytes':40}}
        pipe._last_frame_failure=deepcopy(origin)
        # An ordinary call on poison fails during its initial ownership check.
        # Its zero-byte receive failure must not erase the earlier partial send.
        pipe._time=Mock(return_value=1);pipe._identity=Mock(side_effect=PhaseError('ntfs.pipe_unavailable'))
        with self.assertRaises(PhaseError):pipe.receive_frame(1,maximum_bytes=100)
        self.assertEqual(pipe._last_frame_failure,origin)


    def _original_capture_model(self,*,ack_fault,partial=False,worker_exit=0):
        """Real parent/framer/validator; modeled OS/launch/witness, no native proof.

        The complete error frame has physical_evidence=None. It models terminal
        delivery only, and deliberately promises no valid recoverable original.
        """
        from phase_tool.mutation.ntfs import bundle_recovery_capture as capture
        from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames
        project,_,_=recovery_fixture();context=parse_json_bytes(project.context_bytes)
        grant=parse_json_bytes(project.grant_bytes);effect=parse_json_bytes(project.effect_bytes)
        raw=canonical_bytes({'worker_completion_version':'1.5','context':context,'pid':123,
            'effect_receipt':None,'physical_evidence':None,'worker_exit_established':False,
            'error':{'type':'PhaseError','code':'model.worker','message':'modeled negative completion',
                'details':{'model_terminal_padding':'x'*20000}}})
        framed=f'{len(raw):08x}\n'.encode()+raw+b'\n'
        # Parent effect clock started earlier. Worker finishes after its local
        # ACK wait at36s, beyond old parent30s+5s but inside existing70s report.
        now=[10_000_000_000];arrival=36_000_000_000 if ack_fault else 20_000_000_000
        cursor=[0];events=[];prefix=framed[:26]
        pipe=object.__new__(WindowsPipeFrames)
        pipe._owner=(os.getpid(),threading.get_ident());pipe._sealed=False;pipe._failed=False
        pipe._gate=threading.Lock();pipe._identities=[(0,1,2),(1,1,2)]
        pipe._pipe=lambda side:pipe._identities[side]  # Modeled descriptor identity boundary.
        def read(fd,count):
            self.assertEqual(fd,0)
            if now[0]<arrival:
                now[0]=arrival
                raise BlockingIOError(11,'modeled would-block')
            if partial and cursor[0]>=len(prefix):
                events.append('read_failure');raise OSError(5,'modeled terminal read failure')
            limit=len(prefix)if partial else len(framed)
            chunk=framed[cursor[0]:min(cursor[0]+count,cursor[0]+4096,limit)]
            self.assertTrue(chunk);cursor[0]+=len(chunk)
            if cursor[0]==len(framed):events.append('frame_complete')
            return chunk
        def sleep(seconds):now[0]+=int(seconds*1_000_000_000)
        process=SimpleNamespace(pid=123);fact=deepcopy(witness_parent()['process_witness'])
        fact['exit_code']=worker_exit
        def wait(milliseconds):
            events.append('wait');self.assertGreaterEqual(milliseconds,0);return deepcopy(fact)
        witness=SimpleNamespace(wait_for_exit=Mock(side_effect=wait))
        launch=SimpleNamespace(manifest={'native_read_installation_version':'1.9'},
            run_id=context['run_id'],operation_nonce=context['operation_nonce'],
            installation_digest=context['installation_digest'],root_grant=grant,
            read_original=Mock(return_value=project),spawn_worker=Mock(return_value=process),
            worker_pipe=Mock(return_value=pipe),send_worker_original=Mock(),
            finalize_worker=Mock(side_effect=lambda *args:events.append('finalize')),
            check_runtime=Mock())
        parent=SimpleNamespace(_launch=launch,_bundle=True,_inspection_only=False,_consumed=True,
            _spawn_attempted=False,_file2_exchange_deadline=30_000_000_000,
            _completion_wire=None,_ready_wire=None,_go_attempted=False,_worker_finalized=False)
        def transfer(worker_pipe,parsed,deadline,common):
            self.assertIs(worker_pipe,pipe);self.assertIs(parsed,project)
            self.assertEqual(deadline,30_000_000_000);parent._go_attempted=True
            if ack_fault:
                parent._bundle_ack_relay_entered=True
                raise PhaseError('ntfs.test_prepared_ack_delivery_failed')
            return None
        parent._transfer_bundle=Mock(side_effect=transfer)
        observation={'bundle_observation_version':'1.0','state':{'known':True,'exists':False,
            'digest':None,'length':None,'head_token':None},'native':{'exists':False,'native_identity':None},
            'grant':grant,'locator':effect['target']['relative_locator'],'handles_finalized':True}
        value=error=None
        with patch.object(terminal.time,'perf_counter_ns',side_effect=lambda:now[0]), \
                patch.object(terminal.time,'sleep',side_effect=sleep), \
                patch.object(terminal.os,'read',side_effect=read), \
                patch.object(terminal,'_frame_io',wraps=terminal._frame_io)as frame, \
                patch('phase_tool.mutation.ntfs.process_witness.WindowsProcessWitness',return_value=witness), \
                patch('phase_tool.mutation.ntfs.bundle_observation.observe_bundle',return_value=observation)as observe:
            try:value=capture.execute_original_with_capture(parent,context['intent_digest'],common={})
            except PhaseError as caught:error=caught
        launch.spawn_worker.assert_called_once();parent._transfer_bundle.assert_called_once()
        launch.send_worker_original.assert_called_once_with(pipe,project,_handshake_deadline_ns=30_000_000_000)
        witness.wait_for_exit.assert_called_once();launch.finalize_worker.assert_called_once_with(process,pipe)
        self.assertEqual(frame.call_count,1);self.assertTrue(pipe._terminal_read_attempted)
        self.assertEqual(parent._file2_exchange_deadline,30_000_000_000)
        return SimpleNamespace(value=value,error=error,parent=parent,raw=raw,prefix=prefix,
            events=events,pipe=pipe,observe=observe,deadline=frame.call_args.kwargs['deadline_ns'])

    def test_ack_fault_drains_late_full_completion_before_wait_with_existing_report_budget(self):
        model=self._original_capture_model(ack_fault=True)
        self.assertEqual(model.deadline,80_000_000_000)
        self.assertEqual(model.error.code,'ntfs.parent_execution_unresolved')
        details=model.error.details
        self.assertEqual(details['operation_primary']['code'],'ntfs.test_prepared_ack_delivery_failed')
        self.assertTrue(details['terminal_drain_attempted']);self.assertIsNone(details['terminal_failure'])
        self.assertEqual(details['resource_closure_errors'],[])
        self.assertEqual(_wire(details['worker_completion_wire']),model.raw)
        partial=details['parent_partial'];self.assertEqual(canonical_bytes(partial['completion']),model.raw)
        verify_quiescence(partial,partial['completion'])
        self.assertLess(model.events.index('frame_complete'),model.events.index('wait'))
        self.assertLess(model.events.index('wait'),model.events.index('finalize'))
        model.observe.assert_not_called()  # Reporting never resumes an effect/observation path.

    def test_terminal_partial_or_nonzero_exit_cannot_be_healed_by_wait_and_close(self):
        for partial,exit_code in ((True,0),(False,50)):
            with self.subTest(partial=partial,exit_code=exit_code):
                model=self._original_capture_model(ack_fault=True,partial=partial,worker_exit=exit_code)
                self.assertEqual(model.error.code,'ntfs.parent_execution_unresolved');details=model.error.details
                self.assertTrue(details['terminal_drain_attempted']);model.observe.assert_not_called()
                if partial:
                    failure=details['terminal_failure'];self.assertFalse(failure['progress']['complete'])
                    self.assertEqual(failure['progress']['wire_bytes'],len(model.prefix))
                    self.assertEqual(base64.b64decode(failure['wire_prefix_base64']),model.prefix)
                    self.assertIsNone(details['parent_partial']['completion']);self.assertTrue(model.pipe._failed)
                    with self.assertRaises(PhaseError):_wire(details['worker_completion_wire'])
                    self.assertLess(model.events.index('read_failure'),model.events.index('wait'))
                else:
                    self.assertEqual(_wire(details['worker_completion_wire']),model.raw)
                    self.assertEqual(details['parent_partial']['process_witness']['exit_code'],50)
                    self.assertEqual([e['code']for e in details['resource_closure_errors']],['ntfs.worker_exit_not_established'])
                    with self.assertRaises(PhaseError):
                        verify_quiescence(details['parent_partial'],details['parent_partial']['completion'])

    def test_healthy_original_transport_keeps_original_completion_deadline(self):
        model=self._original_capture_model(ack_fault=False)
        self.assertIsNone(model.error);self.assertEqual(model.deadline,35_000_000_000)
        self.assertEqual(canonical_bytes(model.value['completion']),model.raw)
        verify_quiescence(model.value,model.value['completion'])
        self.assertTrue(model.value['post_observation']['handles_finalized']);model.observe.assert_called_once()
        self.assertLess(model.events.index('frame_complete'),model.events.index('wait'))
        self.assertLess(model.events.index('wait'),model.events.index('finalize'))


class RemainingEffectComponentTests(unittest.TestCase):
    def model(self,*,existing=False,wrong_identity=False,flush_error=False,rename_post_error=False):
        project,prepared,context=recovery_fixture();native=native_stage(project)
        identity=NativeIdentity.parse(native['native_identity']);parent_id=NativeIdentity(identity.volume_serial,'3'*32)
        events=[];calls=[]
        class Handle:
            def __init__(self,io):self.io=io;self.closed=False;io._handles[id(self)]=self
            def __enter__(self):return self
            def __exit__(self,*a):self.close()
            def close(self):
                if self.closed:raise AssertionError('double close')
                self.closed=True;self.io._handles.pop(id(self))
        class IO:
            def __init__(self):self._handles={};self.events=events;self.mutation_state='active'
            def child(self,parent,name,**kwargs):
                calls.append(('open',name,kwargs))
                if name=='bundle' and not existing and not kwargs.get('rename_source'):
                    raise PhaseError('ntfs.open_failed',details={'ntstatus':'0xc0000034'})
                return Handle(self)
            def identity(self,handle):return identity
            def directory_stat_identity(self,*a):
                return dict(native['stat_identity'],inode=1) if wrong_identity else native['stat_identity']
            def observe_committed_name(self,*a,**kw):return Handle(self)
            def rename(self,*a,**kw):
                calls.append(('rename',kw));event={'api':'NtSetInformationFile','class':10,
                    'return_status':'0x00000000','io_status':'0x00000000','effect_state':'committed',
                    'replace_if_exists':kw['replace'],'rename_flags':0,'leaf':'bundle',
                    'source_identity':kw['expected_source'].as_dict(),'parent_identity':kw['expected_parent'].as_dict()}
                self.events.append(event)
                if rename_post_error:raise PhaseError('injected.postguard')
                return event
            def flush_namespace(self,*a):
                calls.append(('flush',))
                if flush_error:raise PhaseError('injected.flush')
                event={'api':'NtFlushBuffersFileEx','kind':'directory','accepted':True,'flags':0,
                    'return_status':'0x00000000','io_status':'0x00000000','object_identity':parent_id.as_dict()}
                self.events.append(event)
                return event
            def seal_mutations(self):self.mutation_state='sealed'
        io=IO()
        class Lock:
            def __init__(self,*a):self.state='held';self.events=[]
            def __enter__(self):return self
            def __exit__(self,*a):self.state='closed'
            def assert_held(self):pass
        class Scope:
            def __init__(self,*a,**kw):self.parent=object();self.parent_identity=parent_id;self.name='bundle'
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def assert_bound(self):pass
            def assert_directory_name(self,*a):pass
        def go(ready):
            calls.append(('authorize',deepcopy(ready)))
            return time.perf_counter_ns()+20_000_000_000
        authorize=Mock(side_effect=go)
        with patch('phase_tool.mutation.ntfs.mutating.NativeMutationIO',return_value=io), \
                patch('phase_tool.mutation.ntfs.root_lock.NativeRootMutex',Lock), \
                patch('phase_tool.mutation.ntfs.scoped.NativeScopedTarget',Scope), \
                patch('phase_tool.mutation.ntfs.bundle_recovery_worker.verify_bundle_handle',return_value=native):
            result=execute_remaining(project,prepared,context,authorize=authorize)
        return result,calls,authorize,io

    def test_remaining_stage_has_one_rename_one_flush_after_ready_and_closes_all_handles(self):
        result,calls,authorize,io=self.model()
        authorize.assert_called_once();self.assertEqual(sum(c[0]=='rename'for c in calls),1)
        self.assertEqual(sum(c[0]=='flush'for c in calls),1)
        self.assertFalse(calls[0][2].get('rename_source',False))
        order=[c[0]for c in calls]
        self.assertLess(order.index('authorize'),order.index('rename'))
        self.assertLess(order.index('rename'),order.index('flush'))
        rename=next(c for c in calls if c[0]=='rename')[1]
        self.assertIs(rename['replace'],False)
        self.assertEqual(rename['expected_source'].as_dict(),result['ready']['native']['native_identity'])
        self.assertEqual(rename['expected_parent'].as_dict(),result['parent_identity'])
        self.assertNotEqual(rename['expected_source'],rename['expected_parent'])
        self.assertTrue(result['mutation_attempted']);self.assertEqual(io._handles,{})
        self.assertEqual(result['handle_finalization'],'closed')

    def test_exact_existing_target_finalizes_namespace_without_second_rename(self):
        result,calls,authorize,io=self.model(existing=True)
        self.assertFalse(any(c[0]=='rename'for c in calls));self.assertEqual(sum(c[0]=='flush'for c in calls),1)
        self.assertTrue(result['mutation_attempted']);self.assertIsNone(result['primary_error'])

    def test_same_bytes_wrong_full_identity_refuses_before_go_or_effect(self):
        result,calls,authorize,io=self.model(wrong_identity=True)
        authorize.assert_not_called();self.assertFalse(any(c[0]in{'rename','flush'}for c in calls))
        self.assertFalse(result['mutation_attempted']);self.assertIsNone(result['after'])

    def test_returned_rename_then_postguard_fault_retains_attempt_and_committed_raw_event(self):
        result,calls,authorize,io=self.model(rename_post_error=True)
        self.assertTrue(result['mutation_attempted']);self.assertIsNone(result['rename'])
        self.assertIsNone(result['after']);self.assertEqual(result['primary_error']['code'],'injected.postguard')
        events=verify_trace(result)
        self.assertTrue(any(e.get('effect_state')=='committed'for e in events))
        self.assertFalse(any(c[0]=='flush'for c in calls))

    def test_flush_failure_never_becomes_verified_success_or_second_rename(self):
        result,calls,authorize,io=self.model(flush_error=True)
        self.assertTrue(result['mutation_attempted']);self.assertIsNone(result['after'])
        self.assertEqual(result['primary_error']['code'],'injected.flush')
        self.assertEqual(sum(c[0]=='rename'for c in calls),1)

    def test_completion_verifier_uses_real_native_event_names_and_both_identities(self):
        from phase_tool.mutation.ntfs.bundle_recovery import verify_completion
        completion,calls,authorize,io=self.model()
        project,prepared,context=recovery_fixture()
        completion['pid']=123;completion['ready']['pid']=123
        completion['mutex_events']=[{'api':name,'outcome':'returned','started_ns':i*10+1,
            'returned_ns':i*10+2,'result':0 if name=='WaitForSingleObject' else 1}
            for i,name in enumerate(['CreateMutexExW','WaitForSingleObject','ReleaseMutex','CloseHandle'])]
        parent=witness_parent()|{'native_recovery_parent_version':'1.0','context':context,
            'completion':completion,'completion_wire':wire_record(canonical_bytes(completion)),
            'operation_primary':None,'go_attempted':True}
        original={'projection':project,'prepared':prepared}
        self.assertEqual(verify_completion(parent,original,context),native_stage(project))
        for mutate in ('flush_api','flush_status','parent_fid','source_fid','replace'):
            changed=deepcopy(parent);body=changed['completion'];records=body['mutation_trace']['records']
            rename=next(e for e in records if e['api']=='NtSetInformationFile')
            flush=next(e for e in records if e['api']=='NtFlushBuffersFileEx')
            if mutate=='flush_api':flush['api']='FlushFileBuffers'
            elif mutate=='flush_status':flush['return_status']='0xc0000001'
            elif mutate=='parent_fid':rename['parent_identity']=rename['source_identity']
            elif mutate=='source_fid':rename['source_identity']=rename['parent_identity']
            else:rename['replace_if_exists']=True
            # Rehash altered modeled records so the test reaches semantic
            # event/identity checks rather than only its outer byte hash.
            body['rename']=deepcopy(rename)
            body['mutation_trace']['canonical_jsonl_digest']=digest_bytes(
                b''.join(canonical_bytes(e)+b'\n'for e in records))
            changed['completion_wire']=wire_record(canonical_bytes(body))
            with self.subTest(mutate=mutate),self.assertRaises(PhaseError):
                verify_completion(changed,original,context)

    def test_observe_cannot_reach_mutation_worker(self):
        project,prepared,context=recovery_fixture();context['mode']='observe'
        with patch('phase_tool.mutation.ntfs.mutating.NativeMutationIO',side_effect=AssertionError('native ctor forbidden'))as ctor, \
                self.assertRaises(PhaseError)as caught:
            execute_remaining(project,prepared,context,authorize=Mock())
        self.assertEqual(caught.exception.code,'recovery.closed_commit_role_required');ctor.assert_not_called()


class RecoveryGenerationBoundaryTests(unittest.TestCase):
    def test_old_host_recovery_still_uses_existing_context_before_any_native_channel(self):
        from phase_tool.recovery import recover_publication
        app=SimpleNamespace(installation=object())
        with patch('phase_tool.recovery.load_context',side_effect=PhaseError('model.host_context'))as load:
            response=recover_publication(app,evidence_root=Path('evidence'),target_root=Path('target'),
                run_id='model-host',request_id='request',expected_intent_digest='sha256:'+'1'*64)
        load.assert_called_once();self.assertEqual(response.payload['error'],'model.host_context')

    def test_new_registry_appends_without_changing_old_161_entries_or_trust_roots(self):
        from phase_tool.registry import BundledRegistry
        resources=BundledRegistry.resources()
        old=parse_json_bytes(resources['registries/native-bundle2-experiment-v2.json'])
        new=parse_json_bytes(resources['registries/native-bundle2-experiment-v3.json'])
        self.assertEqual(len(old['entries']),161);self.assertEqual(new['entries'][:161],old['entries'])
        self.assertEqual(new['trust_roots'],old['trust_roots'])
        profile=parse_json_bytes(resources['descriptors/guarantee/phase.native.ntfs.experiment.bundle2.authority.v1-1.0.2.json'])
        self.assertEqual(profile['provided_guarantees'],[]);self.assertEqual(profile['conformance'],[])
        self.assertEqual(profile['classification'],'qualification_candidate')


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux recovery authority imports required')
class CanonicalRecoveryTerminalGuardTests(unittest.TestCase):
    """Real selection, continuation and result serializers with recorded IO."""

    CHECKPOINT = 'commit-intent.json'
    PROOF = 'native-commit-proof.json'
    RECEIPT = 'commit-receipt.json'
    CHECKPOINT_IDENTITY = (tuple((71, inode) for inode in range(1, 7)), (71, 9, 0o100600, 1, 1, 1, 1, 1))

    @classmethod
    def setUpClass(cls):
        from phase_tool.installation import _native_experimental_bundle2_registry_v3
        cls.registry = _native_experimental_bundle2_registry_v3()

    def setUp(self):
        self.reset_model()

    def reset_model(self):
        from phase_tool.canonical import profile_digest
        from phase_tool.mutation.ntfs.bundle_recovery import _expected_continuation

        self.run_id = 'model-native-recovery'
        self.root = Path('modeled-evidence')
        self.run_root = self.root / '.phase/runs' / self.run_id
        self.target_root = 'modeled-target'
        self.request_id = 'modeled-request'
        self.target = native_stage(b2_projection())
        self.identity = self.CHECKPOINT_IDENTITY
        self.intent = {'run_id': self.run_id, 'effect_plan_digest': 'sha256:' + '1'*64,
                       'idempotency': {'key': self.request_id}, 'contract': _BUNDLE2_CONTRACT_V2}
        self.intent_digest = profile_digest('intent', self.intent)
        self.plan = {'effects': [{'target': {'relative_locator': 'bundle'}}]}
        self.original = {'intent': self.intent, 'plan': self.plan, 'contract': object(),
                         'run': self.run_root, 'projection': object(), 'original_receipt': None,
                         'prepared': self.target['stat_identity'], 'parent': {'completion': {
                             'physical_evidence': {'stage_identity': self.target['native_identity']}}}}
        self.expected_checkpoint = _expected_continuation(self.original)
        self.binding = SimpleNamespace(manifest_bytes=canonical_bytes({
            'evidence_root': str(self.root), 'root_projections': {'phase_result_root': self.target_root}}),
            manifest_digest='sha256:' + '2'*64, registry=self.registry)
        self.records = {}
        self.events = []
        self.stores = []
        self.guard = None
        self.guard_count = 0
        self.dispatches = 0
        self.parent = None
        self.failure = None
        self.original_bytes = canonical_bytes(self.intent)
        self.after_first_guard = lambda: None
        self.projected = {'grant': {}, 'context': {'operation_nonce': '3'*32},
                          'effect': self.plan['effects'][0]}

    def inventory(self):
        rows = {'intent.json': (digest_bytes(self.original_bytes), len(self.original_bytes))}
        rows.update({'recovery/' + leaf: (digest_bytes(raw), len(raw)) for leaf, raw in self.records.items()})
        return rows

    def verify_original(self, binding, run_id, request_id, intent_digest):
        self.assertIs(binding, self.binding)
        self.assertEqual((run_id, request_id, intent_digest), (self.run_id, self.request_id, self.intent_digest))
        return {**self.original, 'files': self.inventory()}

    def shared_guard(self, binding, *, history_bindings, _recovery_selection):
        from contextlib import contextmanager

        @contextmanager
        def owned():
            self.assertIs(binding, self.binding)
            self.assertIs(history_bindings, self)
            self.assertIsNone(self.guard)
            self.guard_count += 1
            generation = self.guard_count
            self.guard = generation
            self.events.append(('guard', generation))
            try:
                _recovery_selection.check(self.run_root)
                yield
                if self.failure == ('unlock', generation):
                    raise OSError('modeled common guard unlock uncertainty')
            finally:
                self.guard = None
                if generation == 1:
                    self.after_first_guard()
        return owned()

    def open_store(self, binding, run_id, *, _expected_commit_checkpoint=None):
        self.assertIs(binding, self.binding)
        self.assertEqual(run_id, self.run_id)
        self.assertIsNotNone(self.guard)
        if _expected_commit_checkpoint is not None:
            self.assertTrue(self.stores[0].closed)
            if self.identity != _expected_commit_checkpoint:
                raise PhaseError('recovery.commit_checkpoint_identity_changed')
        store = SimpleNamespace(owner=self.guard, closed=False)
        self.stores.append(store)
        return store

    def close_store(self, store):
        self.assertFalse(store.closed)
        store.closed = True
        self.events.append(('close', store.owner, self.guard))
        if self.failure == ('close', store.owner):
            raise OSError('modeled Evidence close uncertainty')

    def checkpoint_identity(self, store):
        self.assertEqual(self.guard, store.owner)
        self.assertFalse(store.closed)
        self.assertEqual(parse_json_bytes(self.records[self.CHECKPOINT]), self.expected_checkpoint)
        return self.identity

    def write_record(self, store, leaf, value):
        self.assertFalse(store.closed)
        self.events.append(('write', leaf, self.guard))
        if self.guard != store.owner:
            raise PhaseError('model.unguarded_recovery_write')
        if self.failure == ('write', leaf):
            raise OSError('modeled terminal receipt uncertainty')
        raw = canonical_bytes(value)
        self.assertEqual(self.records.setdefault(leaf, raw), raw)
        return self.run_root / 'recovery' / leaf, digest_bytes(raw)

    def read_record(self, path):
        try:
            return parse_json_bytes(self.records[path.name])
        except KeyError as error:
            raise PhaseError('model.terminal_record_absent') from error

    def resume(self, *_args, _native_checkpoint):
        _native_checkpoint.persist({'pid': 123})
        self.dispatches += 1
        context = _native_checkpoint.context
        rename = {'api': 'NtSetInformationFile', 'class': 10, 'return_status': '0x00000000',
                  'io_status': '0x00000000', 'effect_state': 'committed'}
        trace = {'capture_complete': True, 'capture_errors': [], 'unacknowledged_records_upper_bound': 0,
                 'raw_records_complete': True, 'omitted_middle_records': 0, 'records': [rename],
                 'acknowledged_recorded_event_count': 1,
                 'canonical_jsonl_digest': digest_bytes(canonical_bytes(rename) + b'\n')}
        completion = {'context': context, 'mutation_attempted': True, 'mutation_trace': trace}
        self.parent = {'context': context, 'completion': completion,
                       'completion_wire': wire_record(canonical_bytes(completion))}
        return self.parent

    def recover(self):
        from contextlib import ExitStack
        from phase_tool import continuation, core, evidence, recovery
        from phase_tool.installation import _NativeFileCreateInstallation
        from phase_tool.mutation import broker
        from phase_tool.mutation.ntfs import bundle_execution, bundle_recovery, bundle_recovery_original
        from phase_tool.mutation.ntfs.experimental_bundle2_authority_v3 import _ExperimentalBundle2AuthorityV3

        authority = object.__new__(_ExperimentalBundle2AuthorityV3)
        channel = SimpleNamespace(_sealed=False, channel_id='4'*32)
        channel.seal = lambda: setattr(channel, '_sealed', True)
        channel.captured_file2_completion = lambda: None if self.parent is None else canonical_bytes(self.parent)
        authority._inspection_only, authority._run_id = False, self.run_id
        authority._operation_nonce, authority._server_ingress_sealed = '5'*32, False
        authority.read_binding, authority.profile, authority.channel = self.binding, object(), channel
        authority.observe = Mock(return_value={'native': self.target})
        installation = object.__new__(_NativeFileCreateInstallation)
        installation.read_binding, installation.authority, installation.history_bindings = self.binding, authority, self
        with ExitStack() as boundaries:
            for module, name, implementation in (
                (core, '_guard_native_original_intents', self.shared_guard),
                (evidence, '_open_native_recovery_store', self.open_store),
                (evidence, '_close_native_recovery_store', self.close_store),
                (evidence, '_write_native_recovery_canonical', self.write_record),
                (evidence, '_native_recovery_checkpoint_identity', self.checkpoint_identity),
                (bundle_recovery_original, 'verify_original', self.verify_original),
                (bundle_recovery_original, '_record', self.read_record),
                (bundle_recovery, 'native_inventory', lambda *_: self.inventory()),
                (bundle_recovery, 'verify_completion', lambda *_: self.target),
                (bundle_recovery, 'validate_recovery_ready', Mock()),
                (bundle_execution, '_bundle_projection_value', lambda _: self.projected),
                (bundle_execution, 'validate_bundle_observation', lambda observed, *_a, **_k: observed),
                (continuation, 'validate_record_schema', Mock()),
                (recovery, 'read_record', self.read_record),
                (broker, 'EffectBroker', lambda *_a, **_k: SimpleNamespace(resume_prepared_bundle=self.resume)),
            ):
                boundaries.enter_context(patch.object(module, name, implementation,
                    create=name == '_native_recovery_checkpoint_identity'))
            # Only filesystem presence is modeled here. Selection and canonical
            # record verification use the retained byte map and real parsers.
            directory = self.run_root / 'recovery'
            exists, iterdir = Path.exists, Path.iterdir

            def model_exists(path, *args, **kwargs):
                if path == directory:
                    return bool(self.records)
                return path.name in self.records if path.parent == directory else exists(path, *args, **kwargs)

            def model_iterdir(path):
                return iter(directory / leaf for leaf in self.records) if path == directory else iterdir(path)

            boundaries.enter_context(patch.object(Path, 'exists', model_exists))
            boundaries.enter_context(patch.object(Path, 'iterdir', model_iterdir))
            self.parent = None
            return bundle_recovery.recover_native(SimpleNamespace(installation=installation), authority,
                evidence_root=self.root, run_id=self.run_id, target_root=self.target_root, request_id=self.request_id,
                expected_intent_digest=self.intent_digest, mode='commit_prepared')

    def test_terminal_pair_uses_second_guard_then_repeat_observes_without_effect(self):
        first = self.recover()
        self.assertEqual((first.exit_code, first.payload['success']), (0, True), self.events)
        self.assertEqual(parse_json_bytes(self.records[self.CHECKPOINT]), self.expected_checkpoint)
        self.assertLess(self.events.index(('close', 1, None)), self.events.index(('guard', 2)))
        self.assertEqual([row[1:] for row in self.events if row[0] == 'write'][:3],
                         [(self.CHECKPOINT, 1), (self.PROOF, 2), (self.RECEIPT, 2)])
        self.assertIn(('close', 2, 2), self.events)
        terminal = {leaf: self.records[leaf] for leaf in (self.CHECKPOINT, self.PROOF, self.RECEIPT)}
        repeated = self.recover()
        self.assertEqual((repeated.exit_code, repeated.payload['recovery_mutation_attempted']), (0, False))
        self.assertEqual(self.dispatches, 1)
        self.assertEqual({leaf: self.records[leaf] for leaf in terminal}, terminal)

    def test_reselect_refuses_original_checkpoint_or_competing_proof_drift(self):
        for scope, code in (
            ('original', 'recovery.commit_terminal_checkpoint_changed'),
            ('checkpoint', 'recovery.commit_checkpoint_identity_changed'),
            ('proof', 'recovery.commit_terminal_checkpoint_changed'),
        ):
            with self.subTest(scope=scope):
                self.reset_model()

                def drift():
                    if scope == 'original':
                        self.original_bytes += b' '
                    elif scope == 'checkpoint':
                        self.identity = (self.identity[0], (*self.identity[1][:-1], 2))
                    else:
                        self.records[self.PROOF] = canonical_bytes({'competing': True})

                self.after_first_guard = drift
                result = self.recover()
                self.assertEqual((result.exit_code, result.payload['error']), (40, code))
                self.assertEqual(self.dispatches, 1)
                self.assertNotIn(self.RECEIPT, self.records)
                self.assertFalse(any(row[:2] == ('write', self.PROOF) for row in self.events))

    def test_unlock_or_close_uncertainty_keeps_indeterminate_result(self):
        for fault in ('unlock', 'close'):
            for generation in (1, 2):
                with self.subTest(fault=fault, generation=generation):
                    self.reset_model()
                    self.failure = fault, generation
                    result = self.recover()
                    self.assertEqual((result.exit_code, result.payload['success']), (40, False))
                    self.assertTrue(result.payload['inspection_required'])
                    self.assertEqual(result.payload['native_parent_response'], self.parent)
                    self.assertEqual(self.dispatches, 1)
                    self.assertEqual(self.PROOF in self.records, generation == 2)
                    self.assertEqual(self.RECEIPT in self.records, generation == 2)

    def test_partial_pair_blocks_a_second_effect(self):
        self.failure = 'write', self.RECEIPT
        result = self.recover()
        self.assertEqual(result.exit_code, 40)
        self.assertIn(self.PROOF, self.records)
        self.assertNotIn(self.RECEIPT, self.records)
        self.failure = None
        result = self.recover()
        self.assertEqual((result.exit_code, result.payload['error']), (40, 'model.terminal_record_absent'))
        self.assertEqual(self.dispatches, 1)
        self.assertEqual(self.events.count(('write', self.RECEIPT, 2)), 1)


if __name__=='__main__':unittest.main()
