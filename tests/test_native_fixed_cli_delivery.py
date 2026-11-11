"""Real stdio models; no Phase/Core/native/admission proof.

Windows uses the real Popen process HANDLE; POSIX models only its Close field.
"""
import base64
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

RESOURCE=Path(__file__).absolute().parents[1]/'src/phase_tool/data/native/native_phase_cli_v1.py.in'
LAUNCHER=RESOURCE.with_name('native_phase_candidate_launcher_v1.py.in')
TOY=r"""
import json,pathlib,sys
mode=json.loads((pathlib.Path(__file__).parent/'mode.json').read_text())
head=sys.stdin.buffer.read(9);n=int(head[:8],16)
request=json.loads(sys.stdin.buffer.read(n));assert sys.stdin.buffer.read(1)==b'\n'
assert sys.stdin.buffer.read()==b''
code=10 if mode=='negative'else 0
result={'command':request['request']['operation'],'run_id':request['run_id'],'exit_code':code,
 'success':code==0,'target_verified':False if code else None,
 'modeled_only':True,'error':'modeled.conflict'if code else None}
reply={'protocol':'phase.native.command','version':'1.0','channel_id':'a'*32,
 'run_id':'different-run'if mode=='wrong-run'else request['run_id'],'result':result,'exit_code':code}
b=json.dumps(reply,sort_keys=True,separators=(',',':')).encode()
if request['request']['operation']=='publish_input':
    action=request['request']
    if mode=='pending':
        raise SystemExit(50)
    if mode.startswith('diagnostic-'):
        reason=mode.removeprefix('diagnostic-')
        diagnostic={'phase':'execute','error_class':'timeout' if reason in ('deadline','rx_empty','rx_bytes','rx_first','rx_fdata','rx_next','rx_ndata','tx','tx_obs') else 'error'}
        if reason!='other':diagnostic['reason']=reason
        sys.stderr.buffer.write(json.dumps(diagnostic,sort_keys=True,separators=(',',':')).encode()+b'\n')
        raise SystemExit(50)
    role=action['input_scope'].split('.')[-1]
    bundle=role.startswith('Bundle')
    bound={'File1':1024**2,'File2':2*1024**3,'Bundle1':2*1024**3,'Bundle2':2*1024**3}[role]
    pure=bundle and mode in {'bundle-count','wrong-count'}
    code=10
    error='bundle.member_count_limit'if pure else'input_stage.member_bound'
    refusal={'stage3_command_result_version':'1.0','command':'execute','success':False,
        'run_id':None,'terminal_status':'rejected','execution_disposition':'not_executed',
        'mutation_attempted':False,'effect_plan_digest':None,'intent_digest':None,'receipt_digest':None,
        'target_verified':None,'blockers':[error],'error':error,'exit_code':code}
    result={'native_input_publication_refusal_version':'1.0','run_id':request['run_id'],
        'input_scope':action['input_scope'],'role':role,'source_locator':action['source_locator'],
        'source_length':bound+1,'maximum_source_length':bound,'request_id':action['request_id'],
        'target_locator':action['target_locator'],'source_handles_closed':True,'preparation_started':False,
        'refusal':refusal,'exit_code':code,'retry_authorized':False}
    if bundle:
        for field in ('source_length','maximum_source_length','source_handles_closed'):del result[field]
        result['native_input_publication_refusal_version']='1.1'
        result['source_finalization']='not_opened'if pure else'closed'
        result['bound']={'kind':'member_count'if pure else'member_bytes',
            'observed':(1026 if mode=='wrong-count'else 1025)if pure else bound+1,
            'maximum':1024 if pure else bound}
        if mode=='wrong-bound':result['bound']['maximum']-=1
        if mode=='pending-handle':result['source_finalization']='pending'
    if mode=='wrong-role':result['role']='File9'
    if mode=='wrong-run':result['run_id']='another-run'
    if mode=='wrong-source':result['source_locator']='different.bin'
    if mode=='pending-handle'and not bundle:result['source_handles_closed']=False
    if mode=='fake-receipt':refusal['receipt_digest']='sha256:'+'1'*64
    reply={'protocol':'phase.native.input.publication','version':'1.0','run_id':request['run_id'],
        'installation_digest':'sha256:'+'b'*64,'result':result,'exit_code':code}
    b=json.dumps(reply,sort_keys=True,separators=(',',':')).encode()
    if mode=='wrong-exit':code=50
if mode=='oversized-diagnostic':
    b=b'{"broken":1.'+b'3'*70000+b'}'
if request['request']['operation']=='inspect':
    assert request['request']=={'operation':'inspect'} and sys.argv[1:]==['inspect-parent']
if request['request']['operation']=='publish_file':
    assert sys.argv[1:]==['publish-input']
    action=request['request'];v=action['publication_version'][0]
    proof='sha256:'+'b'*64
    result={'publish_file_result_version':'1.0','success':True,'status':'verified',
        'request_id':action['request_id'],'run_id':request['run_id'],'evidence_root':'/work/evidence',
        'target_locator':action['target_locator'],'contract_binding':'file_create.v'+v+'@1.0.1',
        'contract_digest':'sha256:'+'c'*64,'content_digest':action['expected_digest'],'content_length':65536,
        'receipt_digest':proof,'intent_digest':proof,'effect_plan_digest':proof,'execution_disposition':'executed',
        'mutation_attempted':True,'target_verified':True,'inspection_required':False,'error':None,'exit_code':0}
    if mode=='file-wrong-digest':
        code=10
        result.update(status='rejected_before_write',success=False,content_digest=proof,receipt_digest=None,
            intent_digest=None,effect_plan_digest=None,execution_disposition=None,mutation_attempted=False,
            target_verified=False,error='publish_file.source_digest_mismatch',exit_code=10)
    if mode=='file-foreign-contract':result['contract_binding']='file_create.v9@1.0.1'
    if mode=='file-missing-receipt':result['receipt_digest']=None
    reply={'protocol':'phase.native.input.publication','version':'1.0','run_id':request['run_id'],
        'installation_digest':'sha256:'+'b'*64,'result':result,'exit_code':code}
    b=json.dumps(reply,sort_keys=True,separators=(',',':')).encode()
frame=f'{len(b):08x}\n'.encode()+b+b'\n'
sys.stdout.buffer.write(frame[:-3]if mode=='truncated'else frame);sys.stdout.buffer.flush()
sys.stderr.buffer.write(b'modeled-child-diagnostic\n');sys.stderr.buffer.flush()
raise SystemExit(code)
"""

class NativeFixedCLIDeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        loader=importlib.machinery.SourceFileLoader('_phase_fixed_cli_delivery_under_test',str(RESOURCE))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        cls.cli=importlib.util.module_from_spec(spec);loader.exec_module(cls.cli)
        cls.resource_bytes=RESOURCE.read_bytes()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='phase-cli-delivery-model-')
        self.root=Path(self.temp.name).resolve();self.parent=Path(tempfile.gettempdir()).resolve()
        self.marker=os.urandom(16).hex();(self.root/'MODEL_OWNER').write_text(self.marker)
        self.binding=self.root/'I'/'binding';self.binding.mkdir(parents=True)
        self.output=self.root/'O';self.output.mkdir()
        self.launcher=self.binding/'launcher.py';self.launcher.write_text(TOY,encoding='utf-8')
        self.request=self.root/'request.json'
        self.request.write_text(json.dumps({'run_id':'model-cli-run','request':{
            'operation':'execute','candidate_path':'/prepared/model-candidate.json',
            'input_paths':{'payload':'/prepared/model-payload.bin'},'expected_inputs':None,
            'maximum_candidate_bytes':1048576}}),encoding='utf-8')
        self.children=[]

    def tearDown(self):
        # Only toy Python children created by this exact fixture. Never a native worker.
        for child in self.children:
            if child.poll()is None:child.terminate()
            child.wait(timeout=10)
            for stream in (child.stdin,child.stdout,child.stderr):
                if stream is not None and not stream.closed:stream.close()
        self.assertEqual(RESOURCE.read_bytes(),self.resource_bytes)
        self.assertEqual((self.root/'MODEL_OWNER').read_text(),self.marker)
        self.assertTrue(self.root.is_relative_to(self.parent))
        self.assertTrue(self.root.name.startswith('phase-cli-delivery-model-'))
        self.temp.cleanup()

    def call_model(self,mode,*,input_role=None,staged_file_role=None,inspect_binding=None):
        (self.binding/'mode.json').write_text(json.dumps(mode))
        capture=self.output/('fresh'if input_role is None else input_role+'-'+mode)
        outer={'manifest_digest':'sha256:'+'b'*64}
        action='execute'
        if input_role is not None:
            action='publish-input'
            contract={'File1':'file_create.v1','File2':'file_create.v2','Bundle1':'bundle_create.v1',
                'Bundle2':'bundle_create.v2'}[input_role]
            outer['manifest_base64']=base64.b64encode(json.dumps({'contract':{'id':contract}}).encode()).decode()
            members=None
            if input_role.startswith('Bundle'):
                count=1025 if mode in {'bundle-count','wrong-count'}else 1
                members=[f'member-{index}'for index in range(count)]
            self.request.write_text(json.dumps({'run_id':'model-cli-run','request':{
                'operation':'publish_input','input_scope':'inputs.'+input_role,'source_locator':'input.bin',
                'target_locator':'target.bin','request_id':'request-a','members':members,
                'expected_current_digest':None}}),encoding='utf-8')
        if staged_file_role is not None or inspect_binding is not None:
            version='1' if staged_file_role is None else staged_file_role[-1]
            contract={'id':'file_create.v'+version,'version':'1.0.1','package_digest':'sha256:'+'c'*64}
            manifest={'contract':contract,'evidence_root':'/work/evidence',
                'root_grants':[{'root_binding':'phase_result_root'}]}
            outer['manifest_base64']=base64.b64encode(json.dumps(manifest).encode()).decode()
            if inspect_binding is None:
                action='publish-file'
                request={'operation':'publish_file','input_scope':'owner.inputs','source_locator':'input.bin',
                    'target_locator':'target.bin','request_id':'request-a','publication_version':version+'.0',
                    'expected_digest':'sha256:'+'d'*64,'root_binding':'phase_result_root'}
            else:
                action='inspect'
                request={'operation':'inspect','root_binding':inspect_binding}
            self.request.write_text(json.dumps({'run_id':'model-cli-run','request':request}),encoding='utf-8')
            capture=self.output/(action+'-'+version+'-'+mode)
        real_popen=subprocess.Popen
        def popen(argv,**kwargs):
            # Dependency injection models the OUTER pipe only. Native bindings are never loaded.
            if os.name!='nt':kwargs.pop('creationflags',None)
            child=real_popen(argv,**kwargs)
            if os.name!='nt':
                class PosixModelHandle:
                    closed=False
                    def Close(self):self.closed=True
                child._handle=PosixModelHandle()  # Model only; real Windows HANDLE is not replaced.
            self.children.append(child);return child
        stdout=io.TextIOWrapper(io.BytesIO(),encoding='utf-8')
        stderr=io.TextIOWrapper(io.BytesIO(),encoding='utf-8')
        proxy=types.SimpleNamespace(Popen=popen,PIPE=subprocess.PIPE,
            CREATE_NO_WINDOW=getattr(subprocess,'CREATE_NO_WINDOW',0))
        with patch.object(self.cli,'HERE',self.binding),patch.object(self.cli,'bindings',return_value=(self.launcher,outer)),patch.object(self.cli,'subprocess',proxy),patch.object(sys,'argv',['cli.py',action,str(self.request),str(capture)]),patch.dict(os.environ,{'SYSTEMROOT':os.environ.get('SYSTEMROOT','/'),'WINDIR':os.environ.get('WINDIR','/')}),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            status=self.cli.main()
        stdout.flush();stderr.flush();out=stdout.buffer.getvalue();err=stderr.buffer.getvalue()
        stdout.close();stderr.close()
        return status,out,err,capture

    def assert_outer_closed_before_fixture_cleanup(self):
        child=self.children[-1]
        self.assertIsNotNone(child.poll())
        self.assertTrue(all(stream.closed for stream in (child.stdin,child.stdout,child.stderr)))
        self.assertTrue(child._handle.closed)

    def test_staged_file_both_versions_and_typed_mismatch_use_closed_pipe(self):
        for role in ('File1','File2'):
            for mode,exit_code in (('file-good',0),('file-wrong-digest',10)):
                with self.subTest(role=role,mode=mode):
                    code,out,err,capture=self.call_model(mode,staged_file_role=role)
                    self.assert_outer_closed_before_fixture_cleanup()
                    self.assertEqual((code,err),(exit_code,b''))
                    self.assertEqual(json.loads(out),json.loads((capture/'stdout.bin').read_bytes()[9:-1])['result'])
                    self.assertEqual(json.loads((capture/'delivery.json').read_bytes())['child_delivery'],
                        'COMPLETE_NATIVE_PUBLICATION_FRAME')

    def test_staged_file_uncorrelated_claims_retain_raw_with_unknown_delivery(self):
        for mode in ('file-foreign-contract','file-missing-receipt'):
            with self.subTest(mode=mode):
                code,out,_,capture=self.call_model(mode,staged_file_role='File2')
                self.assert_outer_closed_before_fixture_cleanup()
                self.assertEqual((code,out),(50,b''))
                self.assertTrue((capture/'stdout.bin').read_bytes())
                report=json.loads((capture/'delivery.json').read_bytes())
                self.assertEqual(report['child_delivery'],'UNKNOWN')
                self.assertIs(report['retry_authorized'],False)

    def test_explicit_file_inspect_retains_assertion_and_keeps_unary_child_wire(self):
        code,out,_,capture=self.call_model('inspect-good',inspect_binding='phase_result_root')
        self.assert_outer_closed_before_fixture_cleanup()
        self.assertEqual((code,json.loads(out)['command']),(0,'inspect'))
        recorded=json.loads((capture/'request.json').read_bytes())
        self.assertEqual(recorded['request'],{'operation':'inspect','root_binding':'phase_result_root'})
        with self.assertRaises(RuntimeError):
            self.call_model('inspect-foreign',inspect_binding='objects_root')
        self.assertEqual(len(self.children),1)

    def test_real_pipe_positive_preserves_nullable_actual_result(self):
        code,out,err,capture=self.call_model('positive')
        self.assert_outer_closed_before_fixture_cleanup()
        value=json.loads(out);self.assertEqual(value,json.loads((capture/'stdout.bin').read_bytes()[9:-1])['result'])
        self.assertEqual(code,0);self.assertIsNone(value['target_verified'])
        self.assertTrue(value['modeled_only']);self.assertIn(b'modeled-child-diagnostic',err)
        self.assertEqual({p.name for p in capture.iterdir()},{'request.json','stdout.bin','stderr.bin','delivery.json'})
        report=json.loads((capture/'delivery.json').read_bytes())
        self.assertEqual(report['child_delivery'],'COMPLETE_NATIVE_COMMAND_FRAME')
        self.assertEqual(report['outer_owner_finalization'],'closed')
        self.assertFalse(report['native_worker_quiescence_proven'])

    def test_real_pipe_negative_result_and_exit_are_unchanged(self):
        code,out,err,capture=self.call_model('negative')
        self.assert_outer_closed_before_fixture_cleanup()
        value=json.loads(out);self.assertEqual(value,json.loads((capture/'stdout.bin').read_bytes()[9:-1])['result'])
        self.assertEqual(code,10);self.assertFalse(value['success'])
        self.assertFalse(value['target_verified']);self.assertEqual(value['error'],'modeled.conflict')
        self.assertEqual(json.loads((capture/'delivery.json').read_bytes())['process_exit'],10)

    def test_wrong_run_is_unknown_without_synthetic_command_result(self):
        code,out,err,capture=self.call_model('wrong-run')
        self.assert_outer_closed_before_fixture_cleanup()
        self.assertEqual(code,50);self.assertEqual(out,b'')
        report=json.loads((capture/'delivery.json').read_bytes())
        self.assertEqual(report['child_delivery'],'UNKNOWN');self.assertIsNotNone(report['error'])
        self.assertFalse(report['retry_authorized']);self.assertTrue((capture/'stdout.bin').read_bytes())

    def test_truncated_frame_is_unknown_and_original_bytes_remain(self):
        code,out,err,capture=self.call_model('truncated')
        self.assert_outer_closed_before_fixture_cleanup()
        self.assertEqual(code,50);self.assertEqual(out,b'')
        saved=(capture/'stdout.bin').read_bytes();report=json.loads((capture/'delivery.json').read_bytes())
        self.assertEqual(report['stdout_sha256'],'sha256:'+hashlib.sha256(saved).hexdigest())
        self.assertEqual(report['child_delivery'],'UNKNOWN');self.assertFalse(report['retry_authorized'])

    def test_oversized_delivery_diagnostic_preserves_raw_and_remains_unknown(self):
        code,out,err,capture=self.call_model('oversized-diagnostic')
        self.assert_outer_closed_before_fixture_cleanup()
        self.assertEqual((code,out),(50,b''))
        payload=b'{"broken":1.'+b'3'*70000+b'}'
        raw=f'{len(payload):08x}\n'.encode()+payload+b'\n'
        self.assertEqual((capture/'stdout.bin').read_bytes(),raw)
        self.assertEqual((capture/'stderr.bin').read_bytes(),b'modeled-child-diagnostic\n')
        delivery=(capture/'delivery.json').read_bytes()
        self.assertLessEqual(len(delivery),64*1024)
        report=json.loads(delivery)
        self.assertEqual(report['process_exit'],0)
        self.assertEqual(report['child_delivery'],'UNKNOWN')
        self.assertEqual(report['outer_owner_finalization'],'closed')
        self.assertFalse(report['retry_authorized'])
        self.assertEqual(report['stdout_sha256'],'sha256:'+hashlib.sha256(raw).hexdigest())
        self.assertEqual(report['error']['type'],'DELIVERY_REPORT_TOO_LARGE')
        self.assertEqual(json.loads(err)['delivery_error'],'DELIVERY_REPORT_TOO_LARGE')

    def test_previous_capture_is_never_replaced_or_redispatched(self):
        _,_,_,capture=self.call_model('positive')
        saved={p.name:p.read_bytes()for p in capture.iterdir()};count=len(self.children)
        with self.assertRaises(FileExistsError):self.call_model('positive')
        self.assertEqual(len(self.children),count)
        self.assertEqual({p.name:p.read_bytes()for p in capture.iterdir()},saved)

    def test_input_size_refusal_frames_are_delivered_with_closed_outer_handle(self):
        for role in ('File1','File2'):
            with self.subTest(role=role):
                code,out,_,capture=self.call_model('input-refusal',input_role=role)
                self.assert_outer_closed_before_fixture_cleanup()
                self.assertEqual(code,10)
                value=json.loads(out);self.assertEqual(value['role'],role)
                self.assertEqual(value,json.loads((capture/'stdout.bin').read_bytes()[9:-1])['result'])
                report=json.loads((capture/'delivery.json').read_bytes())
                self.assertEqual(report['child_delivery'],'COMPLETE_NATIVE_INPUT_REFUSAL_FRAME')
                self.assertEqual(report['process_exit'],10)
                self.assertEqual(report['outer_owner_finalization'],'closed')
                self.assertIsNone(value['refusal']['receipt_digest'])
                self.assertFalse(value['retry_authorized'])

    def test_invalid_or_pending_input_refusals_preserve_raw_and_are_unknown(self):
        for mode in ('pending','wrong-role','wrong-run','wrong-source','pending-handle','fake-receipt','wrong-exit'):
            with self.subTest(mode=mode):
                code,out,_,capture=self.call_model(mode,input_role='File2')
                self.assert_outer_closed_before_fixture_cleanup()
                self.assertEqual((code,out),(50,b''))
                report=json.loads((capture/'delivery.json').read_bytes())
                self.assertEqual(report['child_delivery'],'UNKNOWN')
                self.assertEqual(report['stdout_sha256'],'sha256:'+hashlib.sha256((capture/'stdout.bin').read_bytes()).hexdigest())
                self.assertFalse(report['retry_authorized'])

    def test_bundle_refusals_require_correlated_frame_and_closed_actual_process(self):
        for role in ('Bundle1','Bundle2'):
            for mode in ('bundle-count','bundle-member'):
                with self.subTest(role=role,mode=mode):
                    code,out,_,capture=self.call_model(mode,input_role=role)
                    self.assert_outer_closed_before_fixture_cleanup()
                    self.assertEqual(code,10)
                    value=json.loads(out)
                    self.assertEqual(value,json.loads((capture/'stdout.bin').read_bytes()[9:-1])['result'])
                    self.assertEqual(value['role'],role)
                    self.assertIsNone(value['refusal']['receipt_digest'])
                    report=json.loads((capture/'delivery.json').read_bytes())
                    self.assertEqual(report['child_delivery'],'COMPLETE_NATIVE_INPUT_REFUSAL_FRAME')
                    self.assertEqual(report['process_exit'],10)
                    self.assertEqual(report['outer_owner_finalization'],'closed')

    def test_bundle_pending_or_invalid_proofs_preserve_raw_and_are_unknown(self):
        for mode in ('pending','wrong-role','wrong-run','wrong-source','wrong-count','wrong-bound',
                     'pending-handle','fake-receipt','wrong-exit','truncated'):
            with self.subTest(mode=mode):
                code,out,_,capture=self.call_model(mode,input_role='Bundle2')
                self.assert_outer_closed_before_fixture_cleanup()
                self.assertEqual((code,out),(50,b''))
                report=json.loads((capture/'delivery.json').read_bytes())
                self.assertEqual(report['child_delivery'],'UNKNOWN')
                self.assertEqual(report['stdout_sha256'],'sha256:'+hashlib.sha256((capture/'stdout.bin').read_bytes()).hexdigest())
                self.assertFalse(report['retry_authorized'])

    def test_execute_frame_diagnostics_stay_bounded_and_relay_only_fixed_reasons(self):
        from phase_tool.errors import PhaseError
        launcher={'__name__':'_phase_test_diagnostic_only'}
        exec(compile(LAUNCHER.read_bytes(),str(LAUNCHER),'exec'),launcher)
        emitted=[]
        with patch.dict(launcher,os=types.SimpleNamespace(write=lambda fd, raw: emitted.append((fd,raw)))):
            for reason,cause in (('deadline','ntfs.pipe_deadline_expired'),('eof','ntfs.pipe_eof'),
                                 ('other','ntfs.pipe_invalid_header')):
                with self.subTest(reason=reason):
                    error=PhaseError('ntfs.pipe_frame_unknown','private-model-wrapper')
                    error.__cause__=PhaseError(cause,'private-model-cause')
                    launcher['_input_failure_diagnostic']('execute',error)
                    fd,expected=emitted.pop()
                    self.assertEqual(fd,2)
                    self.assertLessEqual(len(expected),64)
                    self.assertNotIn(b'private-model',expected)
                    code,out,err,capture=self.call_model('diagnostic-'+reason,input_role='File1')
                    self.assert_outer_closed_before_fixture_cleanup()
                    self.assertEqual((code,out,err),(50,b'',expected))
                    self.assertEqual((capture/'stderr.bin').read_bytes(),expected)
                    report=json.loads((capture/'delivery.json').read_bytes())
                    self.assertEqual(report['child_delivery'],'UNKNOWN')
                    self.assertFalse(report['retry_authorized'])
            for reason in ('rx_empty','rx_bytes','rx_first','rx_fdata','rx_next','rx_ndata','tx','tx_obs'):
                with self.subTest(reason=reason):
                    code,out,err,capture=self.call_model('diagnostic-'+reason,input_role='File1')
                    self.assert_outer_closed_before_fixture_cleanup()
                    expected=json.dumps({'error_class':'timeout','phase':'execute','reason':reason},
                        sort_keys=True,separators=(',',':')).encode()+b'\n'
                    self.assertLessEqual(len(expected),64)
                    self.assertEqual((code,out,err),(50,b'',expected))
                    self.assertEqual((capture/'stderr.bin').read_bytes(),expected)
                    report=json.loads((capture/'delivery.json').read_bytes())
                    self.assertEqual(report['child_delivery'],'UNKNOWN')
                    self.assertFalse(report['retry_authorized'])
            code,out,err,capture=self.call_model('diagnostic-foreign',input_role='File1')
            self.assert_outer_closed_before_fixture_cleanup()
            self.assertEqual((code,out,err),(50,b'',b'{"error_class":"error","phase":"delivery"}\n'))
            self.assertIn(b'"reason":"foreign"',(capture/'stderr.bin').read_bytes())


if __name__=='__main__':unittest.main()
