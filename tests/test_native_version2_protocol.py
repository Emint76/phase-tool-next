"""Pure data/protocol checks. Every identity, receipt and exit witness is synthetic.

These do not execute Windows APIs, qualify NTFS or replace real Core trials.
"""
from copy import deepcopy
import base64
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.contracts.publish_new_version_v2 import object_locator
from phase_tool.errors import PhaseError
from phase_tool.mutation.object_store_publish import _receipt
from phase_tool.mutation.ntfs.handoff import ParsedNativeVersion2
from phase_tool.mutation.ntfs import parent_result,worker
from phase_tool.mutation.ntfs.original_transfer import original_version2_frames,_Version2OriginalDecoder
from phase_tool.mutation.ntfs.root_lock import root_mutex_name
from phase_tool.mutation.ntfs.version2_observation import _version2_grants
from .test_native_worker import context,grant
from .test_native_version1_parent import state,sample,SyntheticFrames,SyntheticConnection


def fixture(*,old=b'old synthetic',new=b'new synthetic',complete=False,existing=False):
    ctx=context()|{'worker_version':'1.3'}
    roots=[grant()|{'root_binding':role,'components':['synthetic',leaf],
        'native_identity':{'volume_serial':1,'file_id':identifier*32}}
        for role,leaf,identifier in [('current_root','results','1'),('objects_root','objects','2')]]
    target='document.txt';same=old==new
    effect={'effect_id':'synthetic.v2','kind':'publish_new_version','input_binding':None,
        'target':{'root_binding':'current_root','relative_locator':target},
        'archive_target':{'root_binding':'objects_root','relative_locator':object_locator(digest_bytes(old))},
        'content_object_target':{'root_binding':'objects_root','relative_locator':object_locator(digest_bytes(new))},
        'archive_digest':digest_bytes(old),'archive_length':len(old),
        'content_digest':digest_bytes(new),'content_blob_digest':digest_bytes(new),
        'content_length':len(new),'content_base64':base64.b64encode(new).decode(),
        'preconditions':{'existence':'present','expected_digest':digest_bytes(old),'expected_head':None,
            'concurrency_token':digest_bytes(old)},'lock_scope':'publish.'+digest_bytes(target.encode())[7:],
        'durability_policy_id':'file_and_directory_synced','on_failure':'stop_and_classify'}
    before={'current':sample(new if complete else old,'4' if complete else '3'),
        'old_object':sample(old if complete or existing else None,'5'),
        'new_object':sample(new if complete or existing else None,'5' if same else '6')}
    after={'current':sample(new,'4'),'old_object':sample(old,'5'),'new_object':sample(new,'5' if same else '6')}
    written=0 if complete else len(new)+(0 if existing else len(old)+(0 if same else len(new)))
    receipt=_receipt(effect,run_id=ctx['run_id'],timestamp='2026-01-01T00:00:00Z',
        status='applied_verified',before=state(new if complete else old),after=state(new),
        old_before=state(old if complete or existing else None),old_after=state(old),
        new_before=state(new if complete or existing else None),new_after=state(new),
        bytes_written=written,refs=['native.current.after','native.old_object.after','native.new_object.after'],
        error_code=None)
    targets={'current':effect['target'],'old_object':effect['archive_target'],'new_object':effect['content_object_target']}
    observed={}
    for name,value in after.items():
        observed[name]={'observation_version':'1.1','state':state(old if name=='old_object' else new),
            'native':deepcopy(value),'grant':roots[0 if name=='current' else 1],
            'locator':targets[name]['relative_locator'],'handles_finalized':True,'ancestor_absence':None}
    physical={'native_version2_effect_version':'1.0','run_id':ctx['run_id'],'effect_id':effect['effect_id'],
        'grants':roots,'targets':targets,'before':before,'after':after,
        'temporary_locators':{} if complete else {'current':'synthetic-stage'},
        'namespace_flushed':[] if complete else ['old_object','new_object','current'],
        'replace_completed':not complete,'mutation_trace':{'acknowledged_recorded_event_count':0 if complete else 12,
            'capture_complete':True,'unacknowledged_records_upper_bound':0,'capture_errors':[]},
        'mutexes':[{'name':name,'state':'closed','events':[]} for name in
            sorted(root_mutex_name(g) for g in _version2_grants(roots).values())],
        'mutation_session_state':'sealed','handle_finalization':'closed','remaining_handle_count':0,
        'primary_error':None,'finalization_errors':[],'worker_exit_established':False}
    completion={'worker_completion_version':'1.3','context':ctx,'pid':123,'effect_receipt':receipt,
        'physical_evidence':physical,'error':None,'worker_exit_established':False}
    reply={'parent_execution_version':'1.3','context':ctx,'completion':completion,
        'process_witness':{'process_witness_version':'1.0','pid':123,'wait_result':0,
            'worker_exit_established':True,'exit_code':0},'owner_finalization':{
                'worker_stdin':'closed','worker_stdout':'closed','worker_stderr':'closed',
                'creation_handle':'closed','errors':[]},'post_observation':observed,'ingress_state':'consumed'}
    return ctx,roots,effect,new,reply


def check(ctx,roots,effect,reply):
    completion=parent_result.validate_version2_parent_completion(reply,context=ctx,grant_data=roots,effect=effect)
    return parent_result.validate_version2_parent_finalization(reply,completion,grant_data=roots,effect=effect)


class Version2ProtocolTests(unittest.TestCase):
    def test_distinct_same_content_empty_existing_and_complete_triples(self):
        for options in ({},{'existing':True},{'old':b'equal','new':b'equal'},
                {'old':b'','new':b''},{'complete':True},{'complete':True,'old':b'equal','new':b'equal'}):
            with self.subTest(options=options):
                ctx,roots,effect,_,reply=fixture(**options)
                self.assertEqual(check(ctx,roots,effect,reply),reply['post_observation'])

    def test_missing_object_swapped_id_incomplete_exit_and_wrong_write_total_refuse(self):
        changes=[lambda r:r['post_observation'].pop('old_object'),
            lambda r:r['post_observation']['current']['native']['native_identity'].update(file_id='9'*32),
            lambda r:r['process_witness'].update(worker_exit_established=False),
            lambda r:r['owner_finalization'].update(creation_handle='unknown'),
            lambda r:r['completion']['physical_evidence']['mutexes'][1].update(state='unknown'),
            lambda r:r['completion']['effect_receipt'].update(bytes_written=1),
            lambda r:r['completion']['physical_evidence'].update(replace_completed=False)]
        for index,change in enumerate(changes):
            with self.subTest(index=index):
                ctx,roots,effect,_,reply=fixture();change(reply)
                with self.assertRaises(PhaseError):check(ctx,roots,effect,reply)

    def test_same_content_does_not_allow_current_object_alias_or_distinct_object_ids(self):
        for name in ('current','new_object'):
            ctx,roots,effect,_,reply=fixture(old=b'equal',new=b'equal')
            reply['post_observation'][name]['native']['native_identity']['file_id']='5'*32 if name=='current' else '6'*32
            with self.subTest(name=name),self.assertRaises(PhaseError):check(ctx,roots,effect,reply)

    def test_ready_binds_both_ordered_grants_and_timestamp(self):
        ctx,roots,effect,content,_=fixture();timestamp='2026-01-01T00:00:00Z'
        value={'worker_ready_version':'1.3','context':ctx,'pid':123,
            'grants_digest':digest_bytes(canonical_bytes(roots)),'effect_digest':digest_bytes(canonical_bytes(effect)),
            'content_digest':digest_bytes(content),'content_length':len(content),'timestamp':timestamp}
        args=dict(context=ctx,grant_data=roots,effect=effect,content=content,expected_pid=123,timestamp=timestamp)
        self.assertEqual(worker.validate_version2_worker_ready(canonical_bytes(value),**args),value)
        for changed in (value|{'timestamp':'different'},value|{'grants_digest':digest_bytes(canonical_bytes(roots[::-1]))}):
            with self.assertRaises(PhaseError):worker.validate_version2_worker_ready(canonical_bytes(changed),**args)
        with self.assertRaises(PhaseError):worker.validate_version2_worker_ready(canonical_bytes(value),**(args|{'grant_data':roots[::-1]}))

    def test_completion_grant_boolean_cannot_alias_integer_one(self):
        for field in ('volume_serial32','volume_serial'):
            ctx,roots,effect,_,reply=fixture()
            # Corrupt only the worker's copy, keeping installed expectations intact.
            physical=reply['completion']['physical_evidence']
            physical['grants']=deepcopy(physical['grants'])
            target=physical['grants'][0] if field=='volume_serial32' else physical['grants'][0]['native_identity']
            target[field]=True
            with self.subTest(field=field),self.assertRaises(PhaseError):
                worker.validate_version2_worker_completion(canonical_bytes(reply['completion']),
                    context=ctx,grant_data=roots,effect=effect,expected_pid=123)

    def test_bounded_transfer_tail_binding_and_mixed_generation_rejection(self):
        ctx,roots,effect,content,_=fixture(new=b'x'*(512*1024-1)+b'z')
        parsed=ParsedNativeVersion2(canonical_bytes(ctx),canonical_bytes(roots),canonical_bytes(effect),content,'2026-01-01T00:00:00Z')
        frames=list(original_version2_frames(parsed,channel_id='a'*32,leg='worker',query_digest=None))
        def decoder():
            return _Version2OriginalDecoder(channel_id='a'*32,leg='worker',query_digest=None,
                expected_context={k:ctx[k] for k in ('run_id','operation_nonce','installation_digest')},
                expected_grants=canonical_bytes(roots))
        accepted=decoder()
        for raw in frames:accepted.feed(raw)
        self.assertEqual(accepted.finish(),parsed)
        bad=decoder();bad.feed(frames[0]);changed=parse_json_bytes(frames[1]);changed['native_original_transfer_version']='1.1'
        with self.assertRaises(PhaseError):bad.feed(canonical_bytes(changed))
        changed=deepcopy(frames);chunk=parse_json_bytes(changed[-2]);data=base64.b64decode(chunk['content_base64']);chunk['content_base64']=base64.b64encode(data[:-1]+b'y').decode();changed[-2]=canonical_bytes(chunk)
        bad=decoder()
        with self.assertRaises(PhaseError):
            for raw in changed:bad.feed(raw)


class Version2ModeledWorkerTests(unittest.TestCase):
    def invoke(self,*,go_command='execute_version2',expire=False):
        # Only the worker protocol body runs: IO executor/platform/pipe/clock
        # are explicitly modeled, never a fake qualification/Core factory.
        from phase_tool.mutation.ntfs import version2_effect
        ctx,roots,effect,content,reply=fixture();clock=[1000];deadline=1000000
        peer=SyntheticFrames(ctx,clock,go_command=go_command,expire_on_go=expire)
        complete=reply['completion']
        with (patch.object(worker,'os',SimpleNamespace(name='nt',getpid=os.getpid)),
              patch.object(worker,'WindowsPipeFrames',SyntheticFrames),
              patch.object(worker._connection,'PipeConnection',SyntheticConnection,create=True),
              patch.object(worker,'time',SimpleNamespace(perf_counter_ns=lambda:clock[0])),
              patch.object(version2_effect,'execute_version2',return_value=(
                  complete['effect_receipt'],complete['physical_evidence'])) as execute):
            worker.run_version2_worker(peer,ctx,roots,effect,content,'2026-01-01T00:00:00Z',
                _handshake_deadline_ns=deadline)
            count=execute.call_count
        return ctx,roots,effect,content,peer,count,deadline

    def test_wrong_role_go_never_executes(self):
        *_,peer,count,deadline=self.invoke(go_command='execute_version1')
        self.assertEqual(count,0);self.assertEqual(peer.seals,1)
        self.assertEqual(peer.sent[-1]['error']['code'],'ntfs.worker_go_binding_mismatch')
        self.assertEqual(peer.deadlines[:2],[deadline,deadline])

    def test_one_exact_go_completes_once_without_worker_exit_claim(self):
        ctx,roots,effect,content,peer,count,deadline=self.invoke()
        self.assertEqual(count,1);self.assertEqual(peer.seals,1);self.assertEqual(len(peer.sent),2)
        worker.validate_version2_worker_ready(canonical_bytes(peer.sent[0]),context=ctx,grant_data=roots,
            effect=effect,content=content,expected_pid=os.getpid(),timestamp='2026-01-01T00:00:00Z')
        checked=worker.validate_version2_worker_completion(canonical_bytes(peer.sent[1]),context=ctx,
            grant_data=roots,effect=effect,expected_pid=os.getpid())
        self.assertIsNone(checked['error']);self.assertIs(checked['worker_exit_established'],False)
        self.assertEqual(peer.deadlines[:2],[deadline,deadline])

    def test_ready_go_expiry_does_not_reset_owned_deadline(self):
        *_,peer,count,deadline=self.invoke(expire=True)
        self.assertEqual(count,0);self.assertEqual(peer.seals,1)
        self.assertEqual(peer.sent[-1]['error']['code'],'ntfs.worker_go_deadline')
        self.assertEqual(peer.deadlines[:2],[deadline,deadline])


if __name__=='__main__':unittest.main()
