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


if __name__=='__main__':unittest.main()
