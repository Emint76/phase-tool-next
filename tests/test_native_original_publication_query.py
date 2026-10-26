"""Source-only software regressions; no native authority or qualification.

Real original-buffer parser and literal correlation use synthetic claim data.
Owned-reader mocks exercise only protocol/finalizer semantics, never Windows
API, a process, filesystem mutation, qualified transport or physical GO.
"""
import base64
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap,original_endpoint,parent,process_witness
from phase_tool.mutation.ntfs.handoff import ParsedNativeFileCreate
from phase_tool.mutation.ntfs.intent import parse_original_file_create
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers


class NativeOriginalPublicationQueryTests(unittest.TestCase):
    def setUp(self):
        self.registry=BundledRegistry.load()
        self.intent,self.plan,self.pre,self.content,self.contract=buffers(self.registry)
        candidate=self.intent['candidate']['storage']['value']
        candidate['operation_id']=candidate['idempotency_key']='synthetic-create-only'
        self.request={'operation':'execute','native_file_publication_request_version':'1.0',
            'source_locator':'input/payload.bin','target_locator':'synthetic.txt',
            'request_id':'synthetic-create-only','expected_digest':None}

    def arguments(self):
        candidate=self.intent['candidate']['storage']['value']
        self.intent['candidate']['digest']=profile_digest('candidate',candidate)
        self.intent['candidate']['length']=len(canonical_bytes(candidate))
        scope={'contract':self.intent['contract'],'result_locator':candidate['target_locator'],
            'root_identity_digest':self.intent['idempotency']['root_identity_digest'],'operation_intent':'create'}
        self.intent['idempotency'].update(key=candidate['idempotency_key'],
            scope_digest=profile_digest('idempotency-scope',scope),request_digest=profile_digest('request',{
                'scope':scope,'candidate_digest':self.intent['candidate']['digest'],'inputs':self.intent['inputs']}))
        self.intent['effect_plan_digest']=profile_digest('effect-plan',self.plan)
        self.intent['implementation_binding']['effect_plan_digest']=self.intent['effect_plan_digest']
        self.intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(self.plan))
        self.intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(self.pre))
        return dict(intent_bytes=canonical_bytes(self.intent),plan_bytes=canonical_bytes(self.plan),
            pre_validator_bytes=canonical_bytes(self.pre),blob_bytes=self.content,registry=self.registry,
            expected_run_id=self.intent['run_id'],expected_intent_digest=profile_digest('intent',self.intent),
            installed_core_binding=canonical_bytes(self.intent['core']),
            installed_native_binding=canonical_bytes(self.intent['native_binding']),
            installed_root_grants=canonical_bytes(self.intent['idempotency']['root_identities']),
            installed_implementation_binding=canonical_bytes(self.intent['implementation_binding']))

    def launch(self,request=None,version1=False):
        return SimpleNamespace(run_id=self.intent['run_id'],operation_nonce=self.intent['native_binding']['operation_nonce'],
            installation_digest=self.intent['native_binding']['installation']['descriptor_digest'],channel_id='b'*32,
            _version1=version1,_file2=False,invocation={'request':deepcopy(self.request if request is None else request)})

    def query(self,digest):
        # Independently specified wire oracle; do not derive from tested builder.
        return {'native_original_query_version':'1.1','action':'read_executing',
            'run_id':self.intent['run_id'],'intent_digest':digest,
            'operation_nonce':self.intent['native_binding']['operation_nonce'],
            'installation_digest':self.intent['native_binding']['installation']['descriptor_digest'],
            'channel_id':'b'*32,'publication_request':{k:self.request[k] for k in
                ('request_id','target_locator','expected_digest')}}

    def require_literal(self,parsed,query):
        return original_endpoint._require_publication_original(intent=self.intent,plan=self.plan,
            parsed=parsed,query=query,binding=self.intent['contract'])

    def test_same_real_parser_tuple_and_full_original_literal_check_none_or_matching_digest(self):
        for expected in (None,digest_bytes(self.content)):
            with self.subTest(expected=expected):
                self.request['expected_digest']=expected
                args=self.arguments();parsed=parse_original_file_create(**args)
                query=self.query(args['expected_intent_digest'])
                self.assertEqual(bootstrap._original_query_request(self.launch(),'read_executing',
                    args['expected_intent_digest']),query)
                self.assertIsNone(self.require_literal(parsed,query))
                self.assertIs(type(parsed),ParsedNativeFileCreate)
                self.assertEqual(parsed.content_bytes,self.content)
                self.assertEqual(set(vars(parsed)),{'context_bytes','grant_bytes','effect_bytes','content_bytes','timestamp'})

    def test_independently_rehashed_valid_operation_key_and_target_drift_reject_literal(self):
        initial_intent,initial_plan=deepcopy(self.intent),deepcopy(self.plan)
        for field in ('operation_id','idempotency_key','target_locator'):
            with self.subTest(field=field):
                self.intent,self.plan=deepcopy(initial_intent),deepcopy(initial_plan)
                candidate=self.intent['candidate']['storage']['value']
                candidate[field]='other-target.txt' if field=='target_locator' else 'synthetic-other'
                if field=='target_locator':self.plan['effects'][0]['target']['relative_locator']=candidate[field]
                args=self.arguments()
                parsed=parse_original_file_create(**args)  # Must genuinely accept before literal check.
                with self.assertRaisesRegex(PhaseError,'publish_file.evidence_mismatch'):
                    self.require_literal(parsed,self.query(args['expected_intent_digest']))

    def test_wrong_expected_content_digest_and_cross_original_context_reject(self):
        args=self.arguments();parsed=parse_original_file_create(**args)
        query=self.query(args['expected_intent_digest']);query['publication_request']['expected_digest']='sha256:'+'f'*64
        with self.assertRaisesRegex(PhaseError,'publish_file.source_digest_mismatch'):self.require_literal(parsed,query)
        for field,value in (('run_id','synthetic-other'),('intent_digest','sha256:'+'e'*64)):
            query=self.query(args['expected_intent_digest']);query[field]=value
            with self.subTest(field=field):
                with self.assertRaisesRegex(PhaseError,'ntfs.original_query_binding_mismatch'):
                    self.require_literal(parsed,query)

    def test_generations_mixed_keys_role_action_and_no_digest_fail_closed(self):
        args=self.arguments();query=self.query(args['expected_intent_digest'])
        invalid=[]
        for field,value in (('native_original_query_version','1.0'),('native_original_query_version','1.2'),
                ('action','verify_no_dispatch'),('intent_digest',None)):
            invalid.append(query|{field:value})
        invalid.extend((dict(query,extra=True),{k:v for k,v in query.items() if k!='publication_request'}))
        for field,value in (('request_id',True),('request_id','bad request'),('request_id','a'*129),
                ('target_locator',3),('expected_digest',True),('expected_digest','sha256:BAD')):
            item=deepcopy(query);item['publication_request'][field]=value;invalid.append(item)
        item=deepcopy(query);item['publication_request']['root']='untrusted';invalid.append(item)
        for item in invalid:
            with self.subTest(item=item):
                with self.assertRaises(PhaseError):original_endpoint._original_query_publication(item)
        for target in ('../escape','x//y','x\\y','/absolute','con','bad:stream'):
            item=deepcopy(query);item['publication_request']['target_locator']=target
            with self.subTest(target=target):
                with self.assertRaises(PhaseError):original_endpoint._original_query_publication(item)

    def test_legacy_prepared_version1_and_no_dispatch_query_shapes_are_unchanged(self):
        digest='sha256:'+'d'*64
        for request,version1,action,value in (
                ({'operation':'execute','candidate_path':'/unused'},False,'read_executing',digest),
                ({'operation':'execute','candidate_path':'/unused'},True,'read_executing',digest),
                (self.request,False,'verify_no_dispatch',None),
                (self.request,False,'verify_no_dispatch',digest)):
            with self.subTest(version1=version1,action=action,value=value):
                launch=self.launch(request=request,version1=version1)
                query=bootstrap._original_query_request(launch,action,value)
                self.assertEqual(query,{'native_original_query_version':'1.0','action':action,
                    'run_id':launch.run_id,'intent_digest':value,'operation_nonce':launch.operation_nonce,
                    'channel_id':launch.channel_id,'installation_digest':launch.installation_digest})
                self.assertIsNone(original_endpoint._original_query_publication(query))
        for change in ({'native_file_publication_request_version':'9.9'},{'extra':True}):
            launch=self.launch(request=self.request|change)
            with self.assertRaises(PhaseError):bootstrap._original_query_request(launch,'read_executing',digest)

    def reader_shell(self,parsed):
        launch=object.__new__(bootstrap._NativeAcceptedLaunch)
        launch._inspection_only=False;launch._original_query_attempted=False
        launch._manifest_bytes=canonical_bytes({'native_read_installation_version':'1.1'})
        launch._manifest_digest=self.intent['native_binding']['installation']['descriptor_digest']
        launch._invocation_bytes=canonical_bytes({'run_id':self.intent['run_id'],'channel_id':'b'*32,
            'operation_nonce':self.intent['native_binding']['operation_nonce'],'request':self.request})
        value={'context':parse_json_bytes(parsed.context_bytes),'grant':parse_json_bytes(parsed.grant_bytes),
            'effect':parse_json_bytes(parsed.effect_bytes),'content_base64':base64.b64encode(parsed.content_bytes).decode(),
            'timestamp':parsed.timestamp}
        return launch,value

    def read_with_shell(self,*,fault=None):
        args=self.arguments();parsed=parse_original_file_create(**args);launch,value=self.reader_shell(parsed)
        query=self.query(args['expected_intent_digest'])
        reply={'query':deepcopy(query),'value':value,'required_evidence_reads_finalized':True}
        if fault=='downgrade':
            reply['query'].pop('publication_request');reply['query']['native_original_query_version']='1.0'
        if fault=='unfinalized_evidence':reply['required_evidence_reads_finalized']=False
        pipe=Mock();pipe.receive_frame.return_value=(canonical_bytes(reply),None)
        witness=Mock();witness.wait_for_exit.return_value={'worker_exit_established':True,'exit_code':0}
        with (patch.object(bootstrap._NativeAcceptedLaunch,'_windows_required'),
                patch.object(bootstrap._NativeAcceptedLaunch,'check_runtime',
                    side_effect=PhaseError('synthetic.late_runtime') if fault=='runtime' else None),
                patch.object(bootstrap._NativeAcceptedLaunch,'_linux_command',return_value=['UNEXECUTED']),
                patch.object(bootstrap._NativeAcceptedLaunch,'_spawn',return_value=object()) as spawn,
                patch.object(bootstrap._NativeAcceptedLaunch,'_pipe',return_value=pipe),
                patch.object(bootstrap._NativeAcceptedLaunch,'_finalize_exited',
                    side_effect=PhaseError('synthetic.finalizer') if fault=='finalizer' else None) as finalizer,
                patch.object(process_witness,'WindowsProcessWitness',return_value=witness),
                patch.object(bootstrap._NativeAcceptedLaunch,'spawn_worker',
                    side_effect=AssertionError('worker reached')) as worker):
            if fault is None:
                self.assertEqual(launch.read_original(args['expected_intent_digest']),parsed)
            else:
                owner=object.__new__(parent._NativeWindowsParent)
                owner._inspection_only=False;owner._consumed=True;owner._spawn_attempted=False;owner._launch=launch
                with self.assertRaises(PhaseError):owner._execute(args['expected_intent_digest'])
            self.assertTrue(launch._original_query_attempted)
            spawn.assert_called_once();finalizer.assert_called_once();witness.wait_for_exit.assert_called_once_with(60000)
            worker.assert_not_called()
            pipe.send_frame.assert_called_once()
            self.assertEqual(pipe.send_frame.call_args.args[0],canonical_bytes(query))

    def test_owned_reader_echo_finalization_and_unchanged_five_field_tuple(self):
        self.read_with_shell()

    def test_downgrade_unfinalized_finalizer_and_late_runtime_fail_before_worker(self):
        for fault in ('downgrade','unfinalized_evidence','finalizer','runtime'):
            with self.subTest(fault=fault):self.read_with_shell(fault=fault)
