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
import time
import types
import unittest
from unittest.mock import patch

RESOURCE=Path(__file__).absolute().parents[1]/'src/phase_tool/data/native/native_phase_cli_v1.py.in'
LAUNCHER=RESOURCE.with_name('native_phase_candidate_launcher_v1.py.in')
TOY=r"""
import json,pathlib,sys
mode=json.loads((pathlib.Path(__file__).parent/'mode.json').read_text())
if mode=='expired-ingress':
    assert sys.stdin.buffer.read()==b''
    sys.stderr.buffer.write(b'held diagnostic after request deadline\n')
    raise SystemExit(50)
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
    bound={'File1':1024**2,'File2':2*1024**3,'Bundle1':2*1024**3,'Bundle2':2*1024**3,
           'Version1':16*1024**2,'Version2':512*1024}[role]
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
    if mode.startswith('partial-'):
        proof='sha256:'+'d'*64
        code=30
        ack={'stage3_command_result_version':'1.0','command':'execute','success':True,
            'run_id':request['run_id'],'terminal_status':'succeeded_verified',
            'execution_disposition':'executed','mutation_attempted':True,'effect_plan_digest':proof,
            'intent_digest':proof,'receipt_digest':proof,'target_verified':None,'blockers':[],
            'error':None,'exit_code':0}
        result={'native_input_publication_result_version':'1.1','run_id':request['run_id'],
            'input_scope':action['input_scope'],'role':role,'source_digest':proof,'source_length':65536,
            'request_id':action['request_id'],'target_locator':action['target_locator'],'command_ack':ack,
            'independent_inspection':None,'exit_code':code,'retry_authorized':False,
            'status':'committed_unverified','inspection_required':True}
        if mode=='partial-wrong-digest':ack['receipt_digest']='not-a-digest'
        if mode=='partial-success-claim':result['independent_inspection']={'target_verified':True}
        if mode=='partial-retry':result['retry_authorized']=True
        if mode=='partial-downgrade':result['native_input_publication_result_version']='1.0'
        reply.update(result=result,exit_code=code)
    b=json.dumps(reply,sort_keys=True,separators=(',',':')).encode()
    if mode in {'wrong-exit','partial-wrong-exit'}:code=50
if mode=='oversized-diagnostic':
    b=b'{"broken":1.'+b'3'*70000+b'}'
if request['request']['operation']=='inspect':
    assert request['request']=={'operation':'inspect'} and sys.argv[1:]==['inspect-parent']
if request['request']['operation']=='publish_file':
    assert len(sys.argv)==3 and sys.argv[1]=='publish-input'
    assert sys.argv[2].startswith('--input-deadline-ns=') and int(sys.argv[2].split('=')[1])>0
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
    if mode in {'file-occupied','file-occupied-intent','file-occupied-foreign-error','file-occupied-bad-receipt'}:
        code=10
        result.update(status='rejected_before_write',success=False,intent_digest=None,effect_plan_digest=None,
            execution_disposition='not_executed',mutation_attempted=False,target_verified=False,
            error='target.destination_exists',exit_code=10)
        if mode=='file-occupied-intent':result['intent_digest']=proof
        if mode=='file-occupied-foreign-error':result['error']='ntfs.admission_required'
        if mode=='file-occupied-bad-receipt':result['receipt_digest']='not-a-digest'
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
        self.child_argv=[]

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

    def call_model(self,mode,*,input_role=None,staged_file_role=None,inspect_binding=None,qualification=None,
            prebound_deadline_ns=None):
        (self.binding/'mode.json').write_text(json.dumps(mode))
        capture=self.output/('fresh'if input_role is None else input_role+'-'+mode)
        outer={'manifest_digest':'sha256:'+'b'*64}
        action='execute'
        if input_role is not None:
            action='publish-input'
            contract={'File1':'file_create.v1','File2':'file_create.v2','Bundle1':'bundle_create.v1',
                'Bundle2':'bundle_create.v2','Version1':'publish_new_version.v1',
                'Version2':'publish_new_version.v2'}[input_role]
            if mode.startswith('partial-') or qualification is not None:
                version=qualification or '4.0'
                config={'native_launch_version':version}
                if qualification is not None:config['qualification_cold_publication_seconds']=900
                outer.update(native_fixed_startup_version=version,
                    config_base64=base64.b64encode(self.cli.canon(config)).decode())
            outer['manifest_base64']=base64.b64encode(json.dumps({'contract':{'id':contract}}).encode()).decode()
            members=None
            if input_role.startswith('Bundle'):
                count=1025 if mode in {'bundle-count','wrong-count'}else 1
                members=[f'member-{index}'for index in range(count)]
            self.request.write_text(json.dumps({'run_id':'model-cli-run','request':{
                'operation':'publish_input','input_scope':'inputs.'+input_role,'source_locator':'input.bin',
                'target_locator':'target.bin','request_id':'request-a','members':members,
                'expected_current_digest':'sha256:'+'e'*64 if input_role.startswith('Version') else None}}),encoding='utf-8')
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
        if qualification is not None and action in {'execute','inspect'}:
            config={'native_launch_version':qualification,'qualification_cold_publication_seconds':900}
            outer.update(native_fixed_startup_version=qualification,
                config_base64=base64.b64encode(self.cli.canon(config)).decode())
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
            self.child_argv.append(argv);self.children.append(child);return child
        stdout=io.TextIOWrapper(io.BytesIO(),encoding='utf-8')
        stderr=io.TextIOWrapper(io.BytesIO(),encoding='utf-8')
        proxy=types.SimpleNamespace(Popen=popen,PIPE=subprocess.PIPE,
            CREATE_NO_WINDOW=getattr(subprocess,'CREATE_NO_WINDOW',0))
        argv=['cli.py',action,str(self.request),str(capture)]
        if prebound_deadline_ns is not None:argv.append(f'--input-deadline-ns={prebound_deadline_ns}')
        with patch.object(self.cli,'HERE',self.binding),patch.object(self.cli,'bindings',return_value=(self.launcher,outer)),patch.object(self.cli,'subprocess',proxy),patch.object(sys,'argv',argv),patch.dict(os.environ,{'SYSTEMROOT':os.environ.get('SYSTEMROOT','/'),'WINDIR':os.environ.get('WINDIR','/')}),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            status=self.cli.main()
        stdout.flush();stderr.flush();out=stdout.buffer.getvalue();err=stderr.buffer.getvalue()
        stdout.close();stderr.close()
        return status,out,err,capture

    def test_qualified_ordinary_execute_and_inspect_share_entry_capture_clock(self):
        start=50_000_000_000
        cutoff=start+900_000_000_000
        clock=types.SimpleNamespace(now=start,monotonic=time.monotonic,sleep=time.sleep)
        clock.perf_counter_ns=lambda:clock.now
        ordinary,exchange=self.cli.ordinary,self.cli.exchange

        def later_read(path,maximum):
            raw=ordinary(path,maximum)
            clock.now=start+181_000_000_000
            return raw

        def checked_exchange(process,frame,*,deadline_ns,_qualification_cold_publication):
            self.assertTrue(_qualification_cold_publication)
            self.assertEqual((clock.now,deadline_ns),(start+181_000_000_000,cutoff))
            return exchange(process,frame,deadline_ns=deadline_ns,_qualification_cold_publication=True)

        with patch.object(self.cli,'time',clock),patch.object(self.cli,'ordinary',later_read), \
                patch.object(self.cli,'exchange',checked_exchange):
            for role,binding,qualification in [('parent',None,'3.0'),('inspect-parent','phase_result_root','4.0')]:
                with self.subTest(role=role):
                    clock.now=start
                    code,out,err,capture=self.call_model('negative',inspect_binding=binding,qualification=qualification)
                    self.assertEqual(code,10)
                    self.assertEqual(err,b'modeled-child-diagnostic\n')
                    self.assertEqual(json.loads(out)['command'],'execute' if binding is None else 'inspect')
                    self.assertEqual(self.child_argv[-1][-1],role)
                    self.assertTrue((capture/'delivery.json').is_file())
                    self.assert_outer_closed_before_fixture_cleanup()

    def test_qualified_execute_late_capture_preserves_raw_and_unknown(self):
        start=50_000_000_000
        cutoff=start+900_000_000_000
        clock=types.SimpleNamespace(now=start,monotonic=time.monotonic,sleep=time.sleep)
        clock.perf_counter_ns=lambda:clock.now
        exclusive=self.cli.exclusive

        def late_capture(path,raw):
            exclusive(path,raw)
            if path.name=='delivery.json':
                clock.now=cutoff

        with patch.object(self.cli,'time',clock),patch.object(self.cli,'exclusive',late_capture):
            code,out,err,capture=self.call_model('positive',qualification='3.0')
        self.assertEqual((code,out),(50,b''))
        refusal=json.loads(err.splitlines()[-1])
        self.assertEqual(refusal['child_delivery'],'UNKNOWN')
        self.assertFalse(refusal['retry_authorized'])
        self.assertEqual(json.loads((capture/'stdout.bin').read_bytes()[9:-1])['run_id'],'model-cli-run')
        self.assert_outer_closed_before_fixture_cleanup()

    def assert_outer_closed_before_fixture_cleanup(self):
        child=self.children[-1]
        self.assertIsNotNone(child.poll())
        self.assertTrue(all(stream.closed for stream in (child.stdin,child.stdout,child.stderr)))
        self.assertTrue(child._handle.closed)

    def test_staged_entry_clock_covers_request_and_both_fixed_input_routes(self):
        start=50_000_000_000
        deadline=start+30_000_000_000
        clock=types.SimpleNamespace(perf_counter_ns=lambda:start,monotonic=time.monotonic,sleep=time.sleep)
        with patch.object(self.cli,'time',clock):
            self.assertEqual(self.call_model('positive')[0],0)
            self.assertEqual(self.child_argv[-1][-1],'parent')
            self.assertEqual(self.call_model('file-occupied',staged_file_role='File1')[0],10)
            self.assertEqual(self.child_argv[-1][-2:],['publish-input',f'--input-deadline-ns={deadline}'])
            self.assertEqual(self.call_model('negative',input_role='File1')[0],10)
            self.assertEqual(self.child_argv[-1][-2:],['publish-input',f'--input-deadline-ns={deadline}'])
        self.assert_outer_closed_before_fixture_cleanup()

    def test_request_read_consumes_original_window_before_spawn(self):
        start=50_000_000_000
        clock=types.SimpleNamespace(perf_counter_ns=lambda:start,monotonic=time.monotonic,sleep=time.sleep)
        ordinary=self.cli.ordinary

        def late_read(path,maximum):
            raw=ordinary(path,maximum)
            clock.perf_counter_ns=lambda:start+30_000_000_000
            return raw

        with patch.object(self.cli,'time',clock),patch.object(self.cli,'ordinary',late_read):
            with self.assertRaisesRegex(TimeoutError,'native input request deadline'):
                self.call_model('negative',input_role='File1')
        self.assertFalse(self.children)

    def test_qualification_cli_caps_late_ingress_and_never_renews_at_spawn(self):
        start=50_000_000_000
        cutoff=start+900_000_000_000
        clock=types.SimpleNamespace(perf_counter_ns=lambda:start,monotonic=time.monotonic,sleep=time.sleep)
        ordinary,exchange=self.cli.ordinary,self.cli.exchange

        def later_read(path,maximum):
            raw=ordinary(path,maximum)
            clock.perf_counter_ns=lambda:start+181_000_000_000
            return raw

        def at_cutoff(process,frame,*,deadline_ns,_qualification_cold_publication):
            self.assertTrue(_qualification_cold_publication)
            self.assertEqual(deadline_ns,cutoff)
            received=exchange(process,frame,deadline_ns=deadline_ns,
                _qualification_cold_publication=True)
            clock.perf_counter_ns=lambda:cutoff
            return received

        with patch.object(self.cli,'time',clock),patch.object(self.cli,'ordinary',later_read), \
                patch.object(self.cli,'exchange',at_cutoff):
            code,out,err,capture=self.call_model('negative',input_role='File1',qualification='4.0')
        self.assertEqual((code,out,err),(50,b'',b'{"error_class":"timeout","phase":"delivery"}\n'))
        self.assertEqual(self.child_argv[-1][-2:],['publish-input',f'--input-deadline-ns={cutoff}'])
        self.assertEqual(json.loads((capture/'delivery.json').read_bytes())['child_delivery'],'UNKNOWN')
        self.assert_outer_closed_before_fixture_cleanup()

    def test_qualified_cli_preserves_exact_caller_absolute_deadline(self):
        start=50_000_000_000
        cutoff=start+18_000_000_000
        clock=types.SimpleNamespace(perf_counter_ns=lambda:start,monotonic=time.monotonic,sleep=time.sleep)
        ordinary=self.cli.ordinary

        def later_read(path,maximum):
            raw=ordinary(path,maximum)
            clock.perf_counter_ns=lambda:cutoff-1
            return raw

        with patch.object(self.cli,'time',clock),patch.object(self.cli,'ordinary',later_read):
            self.assertEqual(self.call_model('negative',input_role='File1',qualification='3.0',
                prebound_deadline_ns=cutoff)[0],10)
            with self.assertRaisesRegex(RuntimeError,'fixed qualification publication timeout'):
                self.call_model('negative',input_role='File1',prebound_deadline_ns=cutoff)
        self.assertEqual(len(self.children),1)
        self.assertEqual(self.child_argv[0][-2:],['publish-input',f'--input-deadline-ns={cutoff}'])
        self.assert_outer_closed_before_fixture_cleanup()

    def test_qualified_cli_expiry_in_fixed_binding_read_refuses_before_request(self):
        start=50_000_000_000
        cutoff=start+2_000_000_000
        clock=types.SimpleNamespace(now=start)
        clock.perf_counter_ns=lambda:clock.now
        config={'native_launch_version':'4.0','qualification_cold_publication_seconds':900}
        outer={'native_fixed_startup_version':'4.0',
            'config_base64':base64.b64encode(self.cli.canon(config)).decode()}
        def fixed_bindings():
            clock.now=cutoff
            return self.launcher,outer

        with patch.object(self.cli,'time',clock),patch.object(self.cli,'bindings',side_effect=fixed_bindings) as binding, \
                patch.object(self.cli,'stdin_request') as request:
            for action in ('inspect','execute'):
                argv=['cli.py',action,'-',str(self.output/'unused'),f'--input-deadline-ns={cutoff}']
                with patch.object(sys,'argv',argv),self.assertRaisesRegex(RuntimeError,'fixed qualification publication deadline argument'):
                    self.cli.main()
            binding.assert_not_called()
            argv=['cli.py','publish-input','-',str(self.output/'unused'),f'--input-deadline-ns={cutoff}']
            with patch.object(sys,'argv',argv),self.assertRaisesRegex(TimeoutError,'native input request deadline'):
                self.cli.main()
        binding.assert_called_once()
        request.assert_not_called()
        self.assertFalse((self.output/'unused').exists())

    def test_stdin_wait_uses_remaining_input_budget(self):
        deadline=80_000_000_000
        now=deadline-1

        def reach_deadline(_seconds):
            nonlocal now
            now=deadline

        clock=types.SimpleNamespace(perf_counter_ns=lambda:now,sleep=reach_deadline)
        reads=[]

        def unavailable(fd,maximum):
            reads.append((fd,maximum))
            raise BlockingIOError

        ops=types.SimpleNamespace(set_blocking=lambda fd,blocking:None,read=unavailable)
        with patch.object(self.cli,'time',clock),patch.object(self.cli,'os',ops):
            with self.assertRaisesRegex(TimeoutError,'request stdin deadline'):
                self.cli.stdin_request(deadline)
        self.assertEqual(reads,[(0,65536)])

    def test_late_child_frame_or_capture_completion_never_yields_public_result(self):
        start=50_000_000_000
        deadline=start+30_000_000_000
        clock=types.SimpleNamespace(perf_counter_ns=lambda:start,monotonic=time.monotonic,sleep=time.sleep)
        exchange,exclusive=self.cli.exchange,self.cli.exclusive

        def late_frame(process,frame,*,deadline_ns):
            self.assertEqual(deadline_ns,deadline)
            received=exchange(process,frame,deadline_ns=deadline_ns)
            clock.perf_counter_ns=lambda:deadline
            return received

        def late_capture(path,raw):
            exclusive(path,raw)
            if path.name=='delivery.json':
                clock.perf_counter_ns=lambda:deadline

        with patch.object(self.cli,'time',clock):
            with patch.object(self.cli,'exchange',late_frame):
                code,out,err,capture=self.call_model('negative',input_role='File1')
            self.assertEqual((code,out,err),(50,b'',b'{"error_class":"timeout","phase":"delivery"}\n'))
            report=json.loads((capture/'delivery.json').read_bytes())
            self.assertEqual(report['child_delivery'],'UNKNOWN')
            self.assertEqual(report['error']['type'],'TimeoutError')
            self.assertEqual(report['process_exit'],10)
            self.assertTrue((capture/'stdout.bin').read_bytes())
            self.assert_outer_closed_before_fixture_cleanup()
            clock.perf_counter_ns=lambda:start
            with patch.object(self.cli,'exclusive',late_capture):
                code,out,err,capture=self.call_model('positive',staged_file_role='File1')
            self.assertEqual((code,out,err),(50,b'',b'{"error_class":"timeout","phase":"delivery"}\n'))
            report=json.loads((capture/'delivery.json').read_bytes())
            self.assertEqual(report['child_delivery'],'COMPLETE_NATIVE_PUBLICATION_FRAME')
            self.assertEqual(report['process_exit'],0)
            self.assertTrue((capture/'stdout.bin').read_bytes())
            self.assert_outer_closed_before_fixture_cleanup()

    def test_expired_request_stops_ingress_but_drains_existing_child(self):
        start=50_000_000_000
        clock=types.SimpleNamespace(perf_counter_ns=lambda:start,monotonic=time.monotonic,sleep=time.sleep)
        exchange=self.cli.exchange

        def expired(process,frame,*,deadline_ns):
            self.assertEqual(deadline_ns,start+30_000_000_000)
            clock.perf_counter_ns=lambda:deadline_ns
            return exchange(process,frame,deadline_ns=deadline_ns)

        with patch.object(self.cli,'time',clock),patch.object(self.cli,'exchange',expired):
            code,out,err,capture=self.call_model('expired-ingress',input_role='File1')
        self.assertEqual((code,out,err),(50,b'',b'{"error_class":"timeout","phase":"delivery"}\n'))
        self.assertEqual((capture/'stderr.bin').read_bytes(),b'held diagnostic after request deadline\n')
        report=json.loads((capture/'delivery.json').read_bytes())
        self.assertEqual(report['capture']['bytes_sent'],0)
        self.assertEqual(report['capture']['primary']['type'],'TimeoutError')
        self.assertEqual(report['capture']['eof'],[True,True])
        self.assertEqual(report['outer_owner_finalization'],'closed')
        self.assertIs(report['retry_authorized'],False)
        self.assert_outer_closed_before_fixture_cleanup()

    def test_partial_input_requires_original_ack_and_real_cli_exit_correlation(self):
        for role in ('File1','File2','Version1','Version2','Bundle1','Bundle2'):
            with self.subTest(role=role):
                code,out,err,capture=self.call_model('partial-good',input_role=role)
                self.assert_outer_closed_before_fixture_cleanup()
                self.assertEqual((code,err),(30,b''))
                result=json.loads(out)
                self.assertEqual(result['role'],role)
                self.assertEqual(result['command_ack']['exit_code'],0)
                self.assertIsNone(result['independent_inspection'])
                self.assertFalse(result['retry_authorized'])
                report=json.loads((capture/'delivery.json').read_bytes())
                self.assertEqual(report['child_delivery'],'COMPLETE_NATIVE_INPUT_PARTIAL_FRAME')
        for mode in ('partial-wrong-digest','partial-success-claim','partial-retry','partial-downgrade','partial-wrong-exit'):
            with self.subTest(mode=mode):
                code,out,err,capture=self.call_model(mode,input_role='File2')
                self.assert_outer_closed_before_fixture_cleanup()
                self.assertEqual((code,out),(50,b''))
                self.assertTrue(err)
                self.assertTrue((capture/'stdout.bin').read_bytes())
                self.assertEqual(json.loads((capture/'delivery.json').read_bytes())['child_delivery'],'UNKNOWN')

    def test_staged_file1_occupancy_keeps_bound_no_intent_receipt_and_known_exit(self):
        code,out,err,capture=self.call_model('file-occupied',staged_file_role='File1')
        self.assert_outer_closed_before_fixture_cleanup()
        self.assertEqual((code,err),(10,b''))
        result=json.loads(out)
        self.assertEqual(result['error'],'target.destination_exists')
        self.assertEqual(result['receipt_digest'],'sha256:'+'b'*64)
        self.assertIsNone(result['intent_digest'])
        self.assertIsNone(result['effect_plan_digest'])
        inner=(capture/'stdout.bin').read_bytes()
        self.assertEqual(json.loads(inner[9:-1])['result'],result)
        delivery=json.loads((capture/'delivery.json').read_bytes())
        self.assertEqual(delivery['child_delivery'],'COMPLETE_NATIVE_PUBLICATION_FRAME')
        self.assertEqual(delivery['outer_owner_finalization'],'closed')
        self.assertIs(delivery['native_worker_quiescence_proven'],False)
        self.assertIs(delivery['retry_authorized'],False)

    def test_staged_file_receipt_exception_does_not_cover_other_refusals_or_file2(self):
        rows=[('File1',mode) for mode in ('file-occupied-intent','file-occupied-foreign-error',
            'file-occupied-bad-receipt')]+[('File2','file-occupied')]
        for role,mode in rows:
            with self.subTest(role=role,mode=mode):
                code,out,err,capture=self.call_model(mode,staged_file_role=role)
                self.assert_outer_closed_before_fixture_cleanup()
                self.assertEqual((code,out),(50,b''))
                self.assertTrue(err)
                self.assertTrue((capture/'stdout.bin').read_bytes())
                delivery=json.loads((capture/'delivery.json').read_bytes())
                self.assertEqual(delivery['child_delivery'],'UNKNOWN')
                self.assertIs(delivery['retry_authorized'],False)

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


class NativeInputLauncherDeadlineTests(unittest.TestCase):
    """Execute the shipped launcher dispatch and receive code with modeled boundaries."""

    def setUp(self):
        loader=importlib.machinery.SourceFileLoader('_phase_input_clock_launcher',str(LAUNCHER))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        self.launcher=importlib.util.module_from_spec(spec)
        loader.exec_module(self.launcher)
        self.start=50_000_000_000
        self.deadline=self.start+30_000_000_000
        self.now=self.start
        self.events=[]
        self.request={'run_id':'model','request':{'operation':'publish_input'}}
        self.canon=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        self.modules={name:types.ModuleType(name) for name in ('phase_tool','phase_tool.canonical',
            'phase_tool.mutation','phase_tool.mutation.ntfs','phase_tool.mutation.ntfs.entrypoint',
            'phase_tool.mutation.ntfs.owner_directory_launch','phase_tool.mutation.ntfs.inspection_mcp')}
        self.config={}
        self.ordinary=False
        self.sdk_elapsed=0
        launch_scope=self.modules['phase_tool.mutation.ntfs.owner_directory_launch']
        launch_scope._qualification_cold_publication_seconds=lambda config:config.get('qualification_cold_publication_seconds')
        canonical=self.modules['phase_tool.canonical']
        canonical.canonical_bytes=self.canon
        canonical.parse_json_bytes=lambda raw,maximum_bytes:json.loads(raw)
        ntfs=self.modules['phase_tool.mutation.ntfs']
        ntfs.entrypoint=self.modules['phase_tool.mutation.ntfs.entrypoint']
        ntfs.entrypoint._windows_stdio=lambda:self
        self.modules['phase_tool.mutation.ntfs.inspection_mcp'].run_native_input_mcp=self.run_mcp

    def fixed_startup(self):
        self.events.append('fixed-startup')
        self.now+=4_000_000_000
        outer={'native_fixed_startup_version':'4.0' if self.ordinary else '3.0',
            'config_digest':'config','manifest_digest':'manifest'}
        return outer,self.canon(self.config),b'manifest',None,None

    def receive_frame(self,deadline):
        self.events.append(('receive',deadline))
        return self.canon(self.request),None

    def publish(self,request,transport,deadline,*_):
        self.assertEqual(request,self.request)
        self.assertIs(transport,self)
        self.events.append(('publish',deadline))
        return 10

    def sdk_bootstrap(self,*_):
        self.events.append('sdk-bootstrap')
        self.now+=self.sdk_elapsed

    def run_mcp(self,**startup):
        self.events.append(('input-mcp',startup.get('_input_deadline_ns')))
        return 20

    def invoke(self,*args):
        with patch.dict(sys.modules,self.modules),patch.object(sys,'argv',['launcher.py',*args]), \
                patch.object(self.launcher,'os',types.SimpleNamespace(name='nt')), \
                patch.object(time,'perf_counter_ns',lambda:self.now), \
                patch.object(self.launcher,'fixed_startup',self.fixed_startup), \
                patch.object(self.launcher,'fixed_windows_mcp_sdk_bootstrap',self.sdk_bootstrap), \
                patch.object(self.launcher,'_publish_input_cli',self.publish):
            return self.launcher.main()

    def test_private_cli_deadline_preserves_exact_value_through_startup_and_receive(self):
        self.assertEqual(self.invoke('publish-input',f'--input-deadline-ns={self.deadline}'),10)
        self.assertEqual(self.events,['fixed-startup',('receive',self.deadline),('publish',self.deadline)])

    def test_legacy_direct_role_retains_existing_receive_clock(self):
        self.assertEqual(self.invoke('publish-input'),10)
        later=self.deadline+4_000_000_000
        self.assertEqual(self.events,['fixed-startup',('receive',later),('publish',later)])

    def test_expiry_during_startup_never_receives_or_calls_publish(self):
        with self.assertRaisesRegex(TimeoutError,'native input request deadline'):
            self.invoke('publish-input',f'--input-deadline-ns={self.now+3_000_000_000}')
        self.assertEqual(self.events,['fixed-startup'])

    def test_expiry_malformed_cap_and_other_roles_refuse_before_startup(self):
        with self.assertRaisesRegex(TimeoutError,'native input request deadline'):
            self.invoke('publish-input',f'--input-deadline-ns={self.now}')
        for route in (('publish-input','--input-deadline-ns=+50000000001'),
                      ('publish-input',f'--input-deadline-ns={self.now+900_000_000_001}'),
                      ('publish-input','--input-deadline-ns=0001'),
                      ('inspect-parent',f'--input-deadline-ns={self.deadline}'),
                      ('worker',f'--input-deadline-ns={self.deadline}')):
            with self.subTest(route=route),self.assertRaisesRegex(RuntimeError,'Native accepted startup unavailable'):
                self.invoke(*route)
        self.assertFalse(self.events)

    def test_legacy_valid_long_syntax_refuses_before_request(self):
        with self.assertRaisesRegex(RuntimeError,'Native accepted startup unavailable'):
            self.invoke('publish-input',f'--input-deadline-ns={self.deadline+1}')
        self.assertEqual(self.events,['fixed-startup'])

    def test_qualification_whole_cutoff_and_local_initial_frame_window_are_distinct(self):
        self.config={'qualification_cold_publication_seconds':900}
        self.ordinary=True
        cutoff=self.now+900_000_000_000
        self.assertEqual(self.invoke('publish-input',f'--input-deadline-ns={cutoff}'),10)
        self.assertEqual(self.events,['fixed-startup',('receive',self.deadline+4_000_000_000),
            ('publish',cutoff)])

    def test_qualified_semantic_launcher_requires_its_existing_admission(self):
        self.config={'qualification_cold_publication_seconds':900}
        cutoff=self.now+900_000_000_000
        with self.assertRaisesRegex(RuntimeError,'Native accepted startup unavailable'):
            self.invoke('publish-input',f'--input-deadline-ns={cutoff}')
        self.assertEqual(self.events,['fixed-startup'])

    def test_prebound_mcp_requires_qualified_startup_and_never_refreshes_after_sdk(self):
        cutoff=self.start+20_000_000_000
        arg=f'--input-deadline-ns={cutoff}'
        with self.assertRaisesRegex(RuntimeError,'Native accepted startup unavailable'):
            self.invoke('input-mcp',arg)
        self.assertEqual(self.events,['fixed-startup'])
        self.now=self.start;self.events.clear()
        self.ordinary=True;self.config={'qualification_cold_publication_seconds':900}
        self.sdk_elapsed=12_000_000_000
        self.assertEqual(self.invoke('input-mcp',arg),20)
        self.assertEqual(self.events,['fixed-startup','sdk-bootstrap',('input-mcp',cutoff)])
        self.now=self.start;self.events.clear()
        self.sdk_elapsed=16_000_000_000
        with self.assertRaisesRegex(TimeoutError,'native input request deadline'):
            self.invoke('input-mcp',arg)
        self.assertEqual(self.events,['fixed-startup','sdk-bootstrap'])


if __name__=='__main__':unittest.main()
