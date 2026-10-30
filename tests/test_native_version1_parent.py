"""Pure consistency and protocol regressions, not Windows qualification.

Every state, NativeID, process witness and pipe is synthetic. No native handle,
Core admission, qualification guard, real process, target or receipt publisher
is exercised. Real exit/flush/namespace/lifetime guarantees remain NOT_VERIFIED.
"""
from copy import deepcopy
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.contracts.publish_new_version_v1 import archive_locator
from phase_tool.errors import PhaseError
from phase_tool.mutation.archive_then_publish import _receipt
from phase_tool.mutation.ntfs import parent_result,worker,version1_effect
from .test_native_worker import context as file_context,grant


def state(content):
    return {'known':True,'exists':content is not None,
        'digest':None if content is None else digest_bytes(content),
        'length':None if content is None else len(content),'head_token':None}


def sample(content,identifier):
    if content is None:return {'exists':False,'native_identity':None}
    return {'exists':True,'native_identity':{'volume_serial':1,'file_id':identifier*32},
        'digest':digest_bytes(content),'length':len(content),'link_count':1}


def observed(content,identifier,locator):
    return {'observation_version':'1.1','state':state(content),'native':sample(content,identifier),
        'grant':grant(),'locator':locator,'handles_finalized':True,'ancestor_absence':None}


def fixture(*, old=b'old synthetic bytes',new=b'new synthetic bytes',archive_exists=False,complete=False):
    ctx=file_context()|{'worker_version':'1.1'}
    target='synthetic.txt';archive=archive_locator(digest_bytes(old))
    effect={'effect_id':'synthetic.version1','kind':'publish_new_version',
        'target':{'root_binding':'phase_result_root','relative_locator':target},
        'archive_target':{'root_binding':'phase_result_root','relative_locator':archive},
        'archive_digest':digest_bytes(old),'archive_length':len(old),
        'content_digest':digest_bytes(new),'content_length':len(new),
        'preconditions':{'existence':'present','expected_digest':digest_bytes(old),
            'expected_head':None,'concurrency_token':digest_bytes(old)},
        'lock_scope':'publish.'+digest_bytes(target.encode()).removeprefix('sha256:'),
        'durability_policy_id':'file_data_synced','on_failure':'stop_and_classify'}
    archive_before=old if archive_exists or complete else None
    physical={'native_version1_effect_version':'1.0','run_id':ctx['run_id'],'effect_id':effect['effect_id'],
        'grant':grant(),'locator':target,'archive_locator':archive,
        'before':sample(new if complete else old,'4'),'after':sample(new,'4'),
        'archive_before':sample(archive_before,'5'),'archive_after':sample(old,'5'),
        'current_data_flushed':not complete,'current_namespace_flushed':not complete,
        'archive_data_flushed':not complete and archive_before is None,
        'archive_namespace_flushed':not complete and archive_before is None,
        'mutation_trace':{'acknowledged_recorded_event_count':0 if complete else 5,
            'capture_complete':True,'unacknowledged_records_upper_bound':0,'capture_errors':[]},
        'mutex_state':'closed','mutation_session_state':'sealed','handle_finalization':'closed',
        'remaining_handle_count':0,'finalization_errors':[],'primary_error':None,
        'worker_exit_established':False}
    receipt=_receipt(effect,run_id=ctx['run_id'],timestamp='2026-01-01T00:00:00Z',
        status='applied_verified',attempted=True,before=state(old),after=state(new),
        archive_before=state(archive_before),archive_after=state(old),
        bytes_written=0 if complete else len(new)+(len(old) if archive_before is None else 0),
        verification_refs=['native.current.after','native.archive.after'],error_code=None)
    completion={'worker_completion_version':'1.1','context':ctx,'pid':123,'effect_receipt':receipt,
        'physical_evidence':physical,'error':None,'worker_exit_established':False}
    reply={'parent_execution_version':'1.1','context':ctx,'completion':completion,
        'process_witness':{'process_witness_version':'1.0','pid':123,'wait_result':0,
            'exit_code':0,'worker_exit_established':True},
        'owner_finalization':{'worker_stdin':'closed','worker_stdout':'closed','worker_stderr':'closed',
            'creation_handle':'closed','errors':[]},'ingress_state':'consumed',
        'post_observation':{'observation_pair_version':'1.0',
            'current':observed(new,'4',target),'archive':observed(old,'5',archive)}}
    return ctx,effect,new,reply


def check(ctx,effect,reply):
    checked=parent_result.validate_version1_parent_completion(reply,context=ctx,grant_data=grant(),effect=effect)
    return parent_result.validate_version1_parent_finalization(reply,checked,grant_data=grant(),effect=effect)


class Version1ParentConsistencyTests(unittest.TestCase):
    def test_first_archive_reuse_and_zero_length_updates_accept_exact_totals(self):
        for kwargs in ({},{'archive_exists':True},{'old':b'','new':b''}):
            with self.subTest(kwargs=kwargs):
                ctx,effect,_,reply=fixture(**kwargs)
                self.assertEqual(check(ctx,effect,reply),reply['post_observation'])

    def test_already_complete_and_same_content_continuations_need_no_flush_or_bytes(self):
        for kwargs in ({'complete':True},{'complete':True,'old':b'equal','new':b'equal'},
                       {'complete':True,'old':b'','new':b''}):
            with self.subTest(kwargs=kwargs):
                ctx,effect,_,reply=fixture(**kwargs)
                self.assertEqual(check(ctx,effect,reply),reply['post_observation'])
                self.assertEqual(reply['completion']['effect_receipt']['bytes_written'],0)

    def test_zero_events_cannot_claim_verified_modifying_publication(self):
        ctx,effect,_,reply=fixture()
        p=reply['completion']['physical_evidence']
        p['mutation_trace']['acknowledged_recorded_event_count']=0
        for key in ('current_data_flushed','current_namespace_flushed','archive_data_flushed','archive_namespace_flushed'):
            p[key]=False
        with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_physical_before_current_and_existing_archive_full_ids_cannot_change(self):
        for field in ('before','archive_before'):
            with self.subTest(field=field):
                ctx,effect,_,reply=fixture(archive_exists=True)
                reply['completion']['physical_evidence'][field]['native_identity']['file_id']='6'*32
                with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_matching_recomputed_after_samples_do_not_hide_current_object_replacement(self):
        ctx,effect,_,reply=fixture()
        reply['completion']['physical_evidence']['after']['native_identity']['file_id']='6'*32
        reply['post_observation']['current']['native']['native_identity']['file_id']='6'*32
        with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_independent_archive_sample_must_match_worker_full_id(self):
        ctx,effect,_,reply=fixture()
        reply['post_observation']['archive']['native']['native_identity']['file_id']='6'*32
        with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_counts_are_exact_nonnegative_integers(self):
        for field,bad in [('acknowledged_recorded_event_count',-1),('acknowledged_recorded_event_count',True),
                          ('unacknowledged_records_upper_bound',False),('unacknowledged_records_upper_bound','0')]:
            with self.subTest(field=field,bad=bad):
                ctx,effect,_,reply=fixture()
                reply['completion']['physical_evidence']['mutation_trace'][field]=bad
                with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_written_totals_are_exact_integers_bound_to_copy_and_publish(self):
        for complete in (False,True):
            for bad in (None,False,-1,999):
                with self.subTest(complete=complete,bad=bad):
                    ctx,effect,_,reply=fixture(complete=complete)
                    reply['completion']['effect_receipt']['bytes_written']=bad
                    with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_each_required_flush_capture_and_finalizer_fact_is_mandatory(self):
        for field in ('current_data_flushed','current_namespace_flushed','archive_data_flushed','archive_namespace_flushed'):
            with self.subTest(field=field):
                ctx,effect,_,reply=fixture();reply['completion']['physical_evidence'][field]=False
                with self.assertRaises(PhaseError):check(ctx,effect,reply)
        for field,bad in [('capture_complete',False),('capture_errors',[{'synthetic':True}])]:
            with self.subTest(field=field):
                ctx,effect,_,reply=fixture();reply['completion']['physical_evidence']['mutation_trace'][field]=bad
                with self.assertRaises(PhaseError):check(ctx,effect,reply)
        ctx,effect,_,reply=fixture();reply['owner_finalization']['creation_handle']='unknown'
        with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_completion_never_proves_exit_or_accepts_wrong_wire_generation(self):
        mutations=[('completion','worker_exit_established',True),('completion','worker_completion_version','1.0'),
                   ('process_witness','worker_exit_established',False),('process_witness','exit_code',True),
                   ('process_witness','wait_result',False)]
        for section,field,bad in mutations:
            with self.subTest(section=section,field=field):
                ctx,effect,_,reply=fixture();reply[section][field]=bad
                with self.assertRaises(PhaseError):check(ctx,effect,reply)

    def test_archive_and_current_full_identity_must_be_distinct(self):
        ctx,effect,_,reply=fixture()
        reply['post_observation']['archive']['native']['native_identity']=deepcopy(
            reply['post_observation']['current']['native']['native_identity'])
        with self.assertRaises(PhaseError):check(ctx,effect,reply)


@unittest.skipUnless(sys.platform.startswith('linux'),'Connected authority is a Linux role')
class Version1CausalAttemptTests(unittest.TestCase):
    def setUp(self):
        from phase_tool.mutation.ntfs.authority import _NativeFileCreateAuthority
        self.Authority=_NativeFileCreateAuthority

    def test_failed_expected_binding_or_either_read_consumes_one_causal_attempt(self):
        # Allocated, UNADMITTED shell exercises one method only. Its local
        # usability/execution prerequisites are explicitly stubbed below; no
        # real factory/profile/root qualification is run or claimed to pass.
        for fail_at in ('expected','first','second'):
            with self.subTest(fail_at=fail_at):
                ctx,effect,_,reply=fixture()
                owner=object.__new__(self.Authority)
                owner._version1=True;owner._version2=False;owner._run_id=ctx['run_id'];owner._dispatch_attempted=True
                owner._parent_safety_established=True;owner._version1_post_attempted=False;owner._observations={}
                owner._grant_bytes=canonical_bytes(grant())
                pair=reply['post_observation']
                identities={key:pair[key]['native']['native_identity'] for key in ('current','archive')}
                results=[PhaseError('synthetic.first')] if fail_at=='first' else [pair['current'],PhaseError('synthetic.second')]
                with patch.object(owner,'_execution_required'),patch.object(owner,'_usable'), \
                     patch.object(owner,'expected_after_identity',return_value=identities,
                        side_effect=PhaseError('synthetic.expected') if fail_at=='expected' else None) as expected, \
                     patch.object(owner,'observe_advisory',side_effect=results) as observe:
                    with self.assertRaises(PhaseError):owner.observe_version1_post_pair(run_id=ctx['run_id'],effect=effect)
                    counts=expected.call_count,observe.call_count
                    self.assertEqual(counts,(1,{'expected':0,'first':1,'second':2}[fail_at]))
                    self.assertTrue(owner._version1_post_attempted);self.assertEqual(owner._observations,{})
                    with self.assertRaises(PhaseError):owner.observe_version1_post_pair(run_id=ctx['run_id'],effect=effect)
                    self.assertEqual((expected.call_count,observe.call_count),counts)


    def test_successful_pair_is_canonical_run_bound_and_cannot_be_read_twice(self):
        ctx,effect,_,reply=fixture()
        owner=object.__new__(self.Authority)
        owner._version1=True;owner._version2=False;owner._run_id=ctx['run_id'];owner._dispatch_attempted=True
        owner._parent_safety_established=True;owner._version1_post_attempted=False;owner._observations={}
        owner._grant_bytes=canonical_bytes(grant());pair=reply['post_observation']
        identities={key:pair[key]['native']['native_identity'] for key in ('current','archive')}
        with patch.object(owner,'_execution_required'),patch.object(owner,'_usable'), \
             patch.object(owner,'expected_after_identity',return_value=identities), \
             patch.object(owner,'observe_advisory',side_effect=[pair['current'],pair['archive']]) as observe:
            self.assertEqual(owner.observe_version1_post_pair(run_id=ctx['run_id'],effect=effect),pair)
            self.assertEqual(owner._observations,{'post_operation':canonical_bytes({'run_id':ctx['run_id'],'observation':pair})})
            self.assertEqual(observe.call_count,2)
            with self.assertRaises(PhaseError):owner.observe_version1_post_pair(run_id=ctx['run_id'],effect=effect)
            self.assertEqual(observe.call_count,2)


class SyntheticFrames:
    """Pure peer model; no real WindowsPipeFrames or OS transport exercised."""
    def __init__(self,ctx,clock,*,expire_on_go=False,go_command='execute_version1'):
        self.ctx,self.clock=ctx,clock
        self.expire_on_go,self.go_command=expire_on_go,go_command
        self.sent=[];self.deadlines=[];self.seals=0

    def send_frame(self,raw,deadline):
        self.sent.append(parse_json_bytes(raw));self.deadlines.append(deadline)

    def receive_frame(self,deadline,*,maximum_bytes):
        self.deadlines.append(deadline)
        if self.expire_on_go:self.clock[0]=deadline
        return canonical_bytes({'command':self.go_command,'context':self.ctx}),{}

    def seal(self):self.seals+=1


class SyntheticConnection:
    def __init__(self):self.sent=[]


class Version1WorkerDeadlineTests(unittest.TestCase):
    def invoke(self,peer,ctx,effect,content,deadline,clock,*,effect_result=None):
        # Only in-memory protocol paths. The actual native executor is replaced
        # with a data result and never invoked. The Windows platform/framer
        # prerequisites are simulated, not passed on this Linux test host.
        # No native installation/OS transport/admission/conformance is claimed.
        with patch.object(worker,'os',SimpleNamespace(name='nt',getpid=os.getpid)), \
             patch.object(worker,'WindowsPipeFrames',SyntheticFrames), \
             patch.object(worker._connection,'PipeConnection',SyntheticConnection,create=True), \
             patch.object(worker,'time',SimpleNamespace(perf_counter_ns=lambda:clock[0])), \
             patch.object(version1_effect,'execute_version1',return_value=({}, {}) if effect_result is None else effect_result) as execute:
            try:worker.run_version1_worker(peer,ctx,grant(),effect,content,'synthetic',_handshake_deadline_ns=deadline)
            finally:self.executions=execute.call_count

    def test_none_bool_and_connection_refuse_before_ready_or_effect(self):
        ctx,effect,content,_=fixture();clock=[1000]
        for deadline,connection in ((None,False),(True,False),(1000000,True)):
            with self.subTest(deadline=deadline,connection=connection):
                peer=SyntheticConnection() if connection else SyntheticFrames(ctx,clock)
                with self.assertRaises(PhaseError) as caught:self.invoke(peer,ctx,effect,content,deadline,clock)
                self.assertEqual(caught.exception.code,'ntfs.version1_owned_deadline_required')
                self.assertEqual((peer.sent,self.executions),([],0))

    def test_transfer_deadline_already_expired_emits_no_ready_and_no_effect(self):
        ctx,effect,content,_=fixture();clock=[1000];peer=SyntheticFrames(ctx,clock)
        self.invoke(peer,ctx,effect,content,999,clock)
        self.assertEqual(self.executions,0);self.assertEqual(peer.seals,1)
        self.assertEqual(len(peer.sent),1);self.assertNotIn('worker_ready_version',peer.sent[0])
        self.assertEqual(peer.sent[0]['error']['code'],'ntfs.worker_go_deadline')
        self.assertIs(peer.sent[0]['worker_exit_established'],False)

    def test_expiry_between_ready_and_go_does_not_reset_the_original_window(self):
        ctx,effect,content,_=fixture();clock=[1000];deadline=1000000
        peer=SyntheticFrames(ctx,clock,expire_on_go=True)
        self.invoke(peer,ctx,effect,content,deadline,clock)
        self.assertEqual(self.executions,0);self.assertEqual(peer.deadlines[:2],[deadline,deadline])
        self.assertEqual(peer.sent[0]['worker_ready_version'],'1.1')
        self.assertEqual(peer.sent[1]['error']['code'],'ntfs.worker_go_deadline')

    def test_file1_go_cannot_dispatch_version1_worker(self):
        ctx,effect,content,_=fixture();clock=[1000]
        peer=SyntheticFrames(ctx,clock,go_command='execute_file_create')
        self.invoke(peer,ctx,effect,content,1000000,clock)
        self.assertEqual(self.executions,0)
        self.assertEqual(peer.sent[-1]['error']['code'],'ntfs.worker_go_binding_mismatch')

    def test_exact_ready_go_dispatches_once_and_keeps_receipt_evidence_without_exit_claim(self):
        ctx,effect,content,reply=fixture();clock=[1000];deadline=1000000
        peer=SyntheticFrames(ctx,clock);completion=reply['completion']
        result=(completion['effect_receipt'],completion['physical_evidence'])
        self.invoke(peer,ctx,effect,content,deadline,clock,effect_result=result)
        self.assertEqual(self.executions,1);self.assertEqual(peer.seals,1);self.assertEqual(len(peer.sent),2)
        worker.validate_version1_worker_ready(canonical_bytes(peer.sent[0]),context=ctx,grant_data=grant(),
            effect=effect,content=content,expected_pid=os.getpid(),timestamp='synthetic')
        checked=worker.validate_version1_worker_completion(canonical_bytes(peer.sent[1]),context=ctx,
            grant_data=grant(),effect=effect,expected_pid=os.getpid())
        self.assertIsNone(checked['error']);self.assertEqual(checked['effect_receipt'],result[0])
        self.assertEqual(checked['physical_evidence'],result[1]);self.assertIs(checked['worker_exit_established'],False)
        self.assertEqual(peer.deadlines[:2],[deadline,deadline])
