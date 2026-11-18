"""Real Linux/ext4 binding.read BEFORE staged assertions, all six contracts.

Synthetic claimed Originals are written directly into disposable test roots.
The installed reader/parsers, attachment checks, scopes/markers and hash checks
are genuine. Runtime acceptance alone is modelled; NativeIO/process/GO are
forbidden. No qualified profile, operation or physical NTFS result is claimed.
"""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import base64,sys,unittest
from unittest.mock import patch
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.errors import PhaseError
from phase_tool.installation import _linux_filesystem_type,qualify_host_authority_roots,_NativeFileCreateReadBinding
from phase_tool.mutation.ntfs import input_stage
from .native_staged_original14_storage import Original14Storage
from .native_staged_original14_records import rehash

ROLES=('File1','File2','Version1','Version2','Bundle1','Bundle2')

@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: genuine Linux/ext4 reader component required')
class GenuineOriginal14Ext4(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=TemporaryDirectory(prefix='phase-original14-')
        root=Path(cls.temporary.name)
        try:
            qualify_host_authority_roots({'phase_evidence_root':root})
            fs=_linux_filesystem_type(root)
        except PhaseError as error:
            cls.temporary.cleanup();raise unittest.SkipTest('NOT_VERIFIED: '+error.code)
        if fs!='ext4':
            cls.temporary.cleanup();raise unittest.SkipTest('NOT_VERIFIED: actual evidence filesystem '+fs)
        cls.group=Original14Storage(root/'owner3','3.0')
        cls.legacy=Original14Storage(root/'owner2','2.0')
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def setUp(self):
        for group in(self.group,self.legacy):
            for role in ROLES:group.restore(role)
    def snapshot(self,group):return{p.relative_to(group.root).as_posix():digest_bytes(p.read_bytes())for p in group.root.rglob('*')if p.is_file()}
    def positive(self,role):
        group=self.group;before=self.snapshot(group);trace=[]
        real_read=_NativeFileCreateReadBinding.read;real_late=input_stage._require_staged_original
        def read(binding,**kwargs):
            parsed=real_read(binding,**kwargs);trace.append(('read',type(parsed).__name__));return parsed
        def late(**kwargs):trace.append(('late',type(kwargs['parsed']).__name__));return real_late(**kwargs)
        with patch.object(_NativeFileCreateReadBinding,'read',read),patch.object(input_stage,'_require_staged_original',late):
            result,query=group.query(role)
        self.assertEqual(query['native_original_query_version'],'1.4')
        self.assertEqual([row[0]for row in trace],['read','late'])
        self.assertEqual(trace[0][1],trace[1][1])
        if role.startswith('Version'):self.assertEqual(type(result).__name__,'ParsedNative'+role)
        else:self.assertTrue(result['required_evidence_reads_finalized'])
        self.assertEqual(before,self.snapshot(group));self.assertEqual(group.native_calls,0);self.assertEqual(group.process_calls,0)
    def payload_tamper(self,role):
        group=self.group;record=group.records[role]
        if role.startswith('Bundle'):
            member=next(r for r in parse_json_bytes(record['content'])['members']if r['length'])
            digest=member['digest']
        else:digest=digest_bytes(record['content'])
        path=group.evidence/'.phase'/'runs'/record['intent']['run_id']/'blobs'/digest[7:]
        raw=path.read_bytes();self.assertGreater(len(raw),0)
        group.write(path,bytes([raw[0]^1])+raw[1:])
        expected='bundle.frozen_member_mismatch'if role.startswith('Bundle')else'ntfs.original_evidence_bytes_mismatch'
        with patch.object(input_stage,'_require_staged_original',wraps=input_stage._require_staged_original)as late:
            with self.assertRaisesRegex(PhaseError,expected):group.query(role)
            self.assertEqual(late.call_count,0)
    def candidate_tamper(self,role):
        group=self.group;before=group.records[role]
        changed=dict(before,intent=deepcopy(before['intent']),plan=deepcopy(before['plan']),pre=deepcopy(before['pre']))
        value=changed['intent']['candidate']['storage']['value'];value['operation_id']='different-valid-operation'
        changed['intent']['candidate']['digest']=profile_digest('candidate',value)
        changed['intent']['candidate']['length']=len(canonical_bytes(value))
        if role.startswith('Version'):changed['plan']['effects'][0]['operation_identity']=value['operation_id']
        rehash(changed);group.records[role]=changed
        for path,raw in group.original_files(changed).items():group.write(path,raw)
        try:
            with patch.object(input_stage,'_require_staged_original',wraps=input_stage._require_staged_original)as late:
                with self.assertRaisesRegex(PhaseError,'input_stage.original_candidate_mismatch'):group.query(role)
                self.assertEqual(late.call_count,1) # mandatory real binding.read succeeded first
        finally:group.records[role]=before
    def test_legacy_generic_Original10_all_six_genuine_reads(self):
        group=self.legacy
        for role in ROLES:
            with self.subTest(role=role):
                before=self.snapshot(group);result,query=group.query(role,request={'operation':'execute'})
                self.assertEqual(query['native_original_query_version'],'1.0')
                self.assertEqual(before,self.snapshot(group))
    def traced_rejection(self,group,role,request,expected):
        trace=[];real_read=_NativeFileCreateReadBinding.read;real_late=input_stage._require_staged_original
        def read(binding,**kwargs):
            parsed=real_read(binding,**kwargs);trace.append(('read',type(parsed).__name__));return parsed
        def late(**kwargs):trace.append(('late',type(kwargs['parsed']).__name__));return real_late(**kwargs)
        before=self.snapshot(group)
        with patch.object(_NativeFileCreateReadBinding,'read',read),patch.object(input_stage,'_require_staged_original',late):
            with self.assertRaisesRegex(PhaseError,expected):group.query(role,request=request)
        self.assertEqual([x[0]for x in trace],['read','late'])
        self.assertEqual(trace[0][1],trace[1][1]);self.assertEqual(before,self.snapshot(group))
        self.assertEqual(group.native_calls,0);self.assertEqual(group.process_calls,0)
    def test_scope_mismatch_all_six_rejected_after_genuine_original_read(self):
        for role in ROLES:
            request=dict(self.group.records[role]['staged_request'],input_scope='foreign-scope')
            with self.subTest(role=role):self.traced_rejection(self.group,role,request,'input_stage.foreign_scope')
    def test_hash_mismatch_all_six_rejects_exact_intent_digest_before_staged_assertion(self):
        for role in ROLES:
            record=self.group.records[role];before=record['intent_digest'];record['intent_digest']='sha256:'+'f'*64
            count=self.group.runtime_model_calls
            try:
                with self.subTest(role=role),patch.object(input_stage,'_require_staged_original')as late:
                    with self.assertRaisesRegex(PhaseError,'ntfs.original_intent_mismatch'):self.group.query(role)
                    self.assertEqual(late.call_count,0);self.assertGreater(self.group.runtime_model_calls,count)
            finally:record['intent_digest']=before
    def test_foreign_role_rehashed_header_all_six_rejected_after_genuine_original_read(self):
        for role in ROLES:
            record=self.group.records[role];marker=deepcopy(record['marker'])
            marker['source_header']['role']='File2'if role=='File1'else'File1'
            digest=digest_bytes(canonical_bytes(marker['source_header']));marker['header_digest']=digest
            source='phase-native-input-'+digest[7:39]+'/payload'+('/payload'if not role.startswith('Bundle')else'')
            marker['source_locator']=source
            request=dict(record['staged_request'],stage_header_digest=digest,source_locator=source)
            path=self.group.preparation/('phase-native-input-'+digest[7:39])/'input-stage.json';self.group.write(path,canonical_bytes(marker))
            with self.subTest(role=role):self.traced_rejection(self.group,role,request,'input_stage.source_header_binding')
    def bundle_append_bound(self,role):
        group=self.group;record=group.records[role]
        member=next(r for r in parse_json_bytes(record['content'])['members']if r['length'])
        path=group.evidence/'.phase'/'runs'/record['intent']['run_id']/'blobs'/member['digest'][7:]
        group.write(path,path.read_bytes()+b'X')
        with patch.object(input_stage,'_require_staged_original',wraps=input_stage._require_staged_original)as late:
            with self.assertRaisesRegex(PhaseError,'stream.limit_exceeded'):group.query(role)
            self.assertEqual(late.call_count,0)
    def test_Bundle1_appended_member_rejected_at_declared_length(self):self.bundle_append_bound('Bundle1')
    def test_Bundle2_appended_member_rejected_at_declared_length(self):self.bundle_append_bound('Bundle2')
    def test_unselected_companion_history_blocks_all_six_before_runtime(self):
        for role in ROLES:
            config=deepcopy(self.group.configs[role]);history=deepcopy(self.group.history)
            row=next(r for r in history['manifests']if r['role']!=role)
            manifest=parse_json_bytes(base64.b64decode(row['manifest_base64']));manifest['contract']['package_digest']='sha256:'+'f'*64
            raw=canonical_bytes(manifest);row['manifest_base64']=base64.b64encode(raw).decode();row['manifest_digest']=digest_bytes(raw)
            hraw=canonical_bytes(history);config['history_manifest_set_base64']=base64.b64encode(hraw).decode();config['history_manifest_set_digest']=digest_bytes(hraw)
            before=self.group.runtime_boundaries
            with self.subTest(role=role),self.assertRaises(PhaseError):self.group.launch(role,config=config)
            self.assertEqual(self.group.runtime_boundaries,before)

for _role in ROLES:
    for _kind,_method in(('genuine_binding_read_then_staged_assertion','positive'),('actual_blob_tamper_rejected','payload_tamper'),
        ('valid_rehashed_candidate_mismatch_rejected_after_read','candidate_tamper')):
        def _make(role,method):
            def test(self):getattr(self,method)(role)
            return test
        setattr(GenuineOriginal14Ext4,'test_'+_role+'_'+_kind,_make(_role,_method))

if __name__=='__main__':unittest.main(verbosity=2)
