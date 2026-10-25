"""Host saved plans plus explicit synthetic native claims, never qualification.

No Windows API, native process or guard is patched to obtain a positive claim.
The real full version1 parser accepts before caller-literal comparison. This
closed seam is not yet wired to publication preparation or a positive MCP route.
"""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock,patch
import sys
import unittest

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap,original_endpoint
from phase_tool.mutation.ntfs.intent import parse_original_version1
from .test_native_version1_original import original_fixture,arguments


@unittest.skipUnless(sys.platform.startswith('linux'),'Real Host fixture requires Linux')
class NativeVersion1PublicationQueryTests(unittest.TestCase):
    def request(self,intent,content):
        return {'operation':'execute','native_version1_publication_request_version':'1.0',
            'source_locator':'incoming/synthetic.bin','target_locator':intent['candidate']['storage']['value']['target_locator'],
            'request_id':'synthetic-version1','expected_current_digest':intent['candidate']['storage']['value']['expected_current_digest'],
            'expected_digest':digest_bytes(content)}

    def fixture_values(self,values):
        registry,intent,plan,pre,content=values
        intent,plan=deepcopy(intent),deepcopy(plan)
        candidate=intent['candidate']['storage']['value']
        candidate['operation_id']=candidate['idempotency_key']='synthetic-version1'
        plan['effects'][0]['operation_identity']='synthetic-version1'
        intent['candidate'].update(digest=profile_digest('candidate',candidate),length=len(canonical_bytes(candidate)))
        scope={'contract':intent['contract'],'result_locator':candidate['target_locator'],
            'root_identity_digest':intent['idempotency']['root_identity_digest'],'operation_intent':'publish_new_version'}
        intent['idempotency'].update(key=candidate['idempotency_key'],scope_digest=profile_digest('idempotency-scope',scope),
            request_digest=profile_digest('request',{'scope':scope,'candidate_digest':intent['candidate']['digest'],'inputs':intent['inputs']}))
        args=arguments(registry,intent,plan,pre,content)
        intent=parse_json_bytes(args['intent_bytes'])
        parsed=parse_original_version1(**args)  # Real parser MUST accept first.
        return intent,plan,content,args,parsed

    def launch(self,intent,request,version1=True):
        return SimpleNamespace(run_id=intent['run_id'],operation_nonce=intent['native_binding']['operation_nonce'],
            channel_id='b'*32,installation_digest=intent['native_binding']['installation']['descriptor_digest'],
            _version1=version1,invocation={'request':deepcopy(request)})

    def query(self,intent,request,digest):
        return {'native_original_query_version':'1.2','action':'read_executing','run_id':intent['run_id'],
            'intent_digest':digest,'operation_nonce':intent['native_binding']['operation_nonce'],'channel_id':'b'*32,
            'installation_digest':intent['native_binding']['installation']['descriptor_digest'],
            'version1_publication_request':{k:request[k] for k in (
                'request_id','target_locator','expected_current_digest','expected_digest')}}

    def require_literals(self,intent,plan,parsed,query):
        return original_endpoint._require_version1_publication_original(
            intent=intent,plan=plan,parsed=parsed,query=query,binding=intent['contract'])

    def test_real_full_parser_then_exact_caller_literals_zero_and_large_payload(self):
        for content in (b'',b'synthetic-new',b'x'*(1024**2)+b'tail',b'x'*(16*1024**2)):
            with self.subTest(length=len(content)),original_fixture(content) as values:
                intent,plan,content,args,parsed=self.fixture_values(values)
                request=self.request(intent,content)
                for expected in (None,digest_bytes(content)):
                    request['expected_digest']=expected
                    query=self.query(intent,request,args['expected_intent_digest'])
                    self.assertEqual(bootstrap._original_query_request(self.launch(intent,request),
                        'read_executing',args['expected_intent_digest']),query)
                    self.assertIsNone(self.require_literals(intent,plan,parsed,query))
                    self.assertEqual(parsed.content_bytes,content)
                    self.assertEqual(set(vars(parsed)),{'context_bytes','grant_bytes','effect_bytes','content_bytes','timestamp'})

    def test_valid_original_cannot_substitute_key_target_or_old_digest_literals(self):
        with original_fixture() as values:
            intent,plan,content,args,parsed=self.fixture_values(values)
            query=self.query(intent,self.request(intent,content),args['expected_intent_digest'])
            for key,bad in (('request_id','other-version'),('target_locator','documents/other.bin'),
                    ('expected_current_digest','sha256:'+'f'*64)):
                changed=deepcopy(query);changed['version1_publication_request'][key]=bad
                with self.subTest(key=key),self.assertRaisesRegex(PhaseError,'ntfs.original_version1_publication_mismatch'):
                    self.require_literals(intent,plan,parsed,changed)

    def test_optional_payload_digest_and_original_context_are_independent_assertions(self):
        with original_fixture() as values:
            intent,plan,content,args,parsed=self.fixture_values(values)
            query=self.query(intent,self.request(intent,content),args['expected_intent_digest'])
            changed=deepcopy(query);changed['version1_publication_request']['expected_digest']='sha256:'+'e'*64
            with self.assertRaisesRegex(PhaseError,'ntfs.original_version1_payload_mismatch'):
                self.require_literals(intent,plan,parsed,changed)
            for key,bad in (('run_id','synthetic-other'),('intent_digest','sha256:'+'d'*64)):
                with self.subTest(key=key),self.assertRaisesRegex(PhaseError,'ntfs.original_version1_publication_mismatch'):
                    self.require_literals(intent,plan,parsed,query|{key:bad})

    def test_exact_candidate_value_cannot_hide_extra_field_or_different_idempotency(self):
        with original_fixture() as values:
            intent,plan,content,args,parsed=self.fixture_values(values)
            query=self.query(intent,self.request(intent,content),args['expected_intent_digest'])
            # Helper-level corrupt inputs after valid parsed tuple; not new
            # authenticated originals or accepted Core output.
            changed=deepcopy(intent);changed['candidate']['storage']['value']['extra']=True
            with self.assertRaisesRegex(PhaseError,'ntfs.original_version1_publication_mismatch'):
                self.require_literals(changed,plan,parsed,query)
            changed=deepcopy(intent);changed['idempotency']['key']='other'
            with self.assertRaisesRegex(PhaseError,'ntfs.original_version1_publication_mismatch'):
                self.require_literals(changed,plan,parsed,query)

    def test_closed_query_generation_keys_locators_and_digest_types(self):
        with original_fixture() as values:
            intent,plan,content,args,parsed=self.fixture_values(values)
            query=self.query(intent,self.request(intent,content),args['expected_intent_digest'])
            bad=[dict(query,action='verify_no_dispatch'),dict(query,intent_digest=None),
                dict(query,publication_request={}),dict(query,extra=True)]
            for key,value in (('request_id',True),('request_id','bad id'),('request_id','a'*129),
                    ('target_locator','../escape'),('target_locator','con'),('target_locator','x//y'),
                    ('expected_current_digest',None),('expected_current_digest',True),
                    ('expected_current_digest','sha256:BAD'),('expected_digest',True)):
                item=deepcopy(query);item['version1_publication_request'][key]=value;bad.append(item)
            for item in bad:
                with self.subTest(item=item),self.assertRaises(PhaseError):
                    original_endpoint._original_query_version1_publication(item)
            # New literals must not be accepted as the historical file1 grammar.
            for generation in ('1.0','1.1'):
                with self.subTest(generation=generation),self.assertRaises(PhaseError):
                    original_endpoint._original_query_publication(query|{'native_original_query_version':generation})
            with self.assertRaises(PhaseError):original_endpoint._original_query_publication(query)

    def test_builder_mixed_request_wrong_role_and_no_dispatch_shapes(self):
        with original_fixture() as values:
            intent,plan,content,args,parsed=self.fixture_values(values)
            request=self.request(intent,content)
            for changed,role in ((request,False),(request|{'extra':True},True),
                    (request|{'native_version1_publication_request_version':'9.9'},True),
                    (request|{'native_file_publication_request_version':'1.0'},True)):
                with self.subTest(request=changed,role=role),self.assertRaises(PhaseError):
                    bootstrap._original_query_request(self.launch(intent,changed,role),
                        'read_executing',args['expected_intent_digest'])
            for action,digest in (('verify_no_dispatch',None),('verify_no_dispatch',args['expected_intent_digest'])):
                q=bootstrap._original_query_request(self.launch(intent,request),action,digest)
                self.assertEqual(q['native_original_query_version'],'1.0')
                self.assertEqual(set(q),original_endpoint._QUERY_FIELDS)
                self.assertIsNone(original_endpoint._original_query_publication(q))
            q=bootstrap._original_query_request(self.launch(intent,{'operation':'execute','candidate_path':'/unused'}),
                'read_executing',args['expected_intent_digest'])
            self.assertEqual(q['native_original_query_version'],'1.0')

    def test_new_query_does_not_bypass_real_native_guard_before_reader_or_binding(self):
        from phase_tool import installation
        from phase_tool.mutation.ntfs import reader
        registry=installation._native_lifecycle_registry()
        raw=canonical_bytes({'native_read_installation_version':'1.2','registry_snapshot_digest':registry.digest,
            'contract':{'id':'publish_new_version.v1'}})
        launch=object.__new__(bootstrap._NativeAcceptedLaunch)
        launch._manifest_bytes=raw;launch._manifest_digest=digest_bytes(raw)
        launch._invocation_bytes=canonical_bytes({'run_id':'synthetic-version1','channel_id':'b'*32,
            'operation_nonce':'a'*32,'request':{'operation':'execute'}})
        query={'native_original_query_version':'1.2','action':'read_executing','run_id':'synthetic-version1',
            'intent_digest':'sha256:'+'c'*64,'operation_nonce':'a'*32,'channel_id':'b'*32,
            'installation_digest':digest_bytes(raw),'version1_publication_request':{
                'request_id':'synthetic-version1','target_locator':'documents/item.bin',
                'expected_current_digest':'sha256:'+'d'*64,'expected_digest':None}}
        with (patch.object(bootstrap._NativeAcceptedLaunch,'check_runtime'),
                patch.object(original_endpoint,'_resolve_native_file_create_read_binding',
                    side_effect=AssertionError('binding reached')) as binding,
                patch.object(reader,'read_original_version1_buffers',
                    side_effect=AssertionError('reader reached')) as original):
            with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                original_endpoint.native_original_query(launch,query)
            binding.assert_not_called();original.assert_not_called()
