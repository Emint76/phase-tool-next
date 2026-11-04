"""Real stdio models; no Phase/Core/native/admission proof.

Windows uses the real Popen process HANDLE; POSIX models only its Close field.
"""
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
TOY=r"""
import json,pathlib,sys
mode=json.loads((pathlib.Path(__file__).parent/'mode.json').read_text())
head=sys.stdin.buffer.read(9);n=int(head[:8],16)
request=json.loads(sys.stdin.buffer.read(n));assert sys.stdin.buffer.read(1)==b'\n'
assert sys.stdin.buffer.read()==b''
code=10 if mode=='negative'else 0
result={'command':'execute','run_id':request['run_id'],'exit_code':code,
 'success':code==0,'target_verified':False if code else None,
 'modeled_only':True,'error':'modeled.conflict'if code else None}
reply={'protocol':'phase.native.command','version':'1.0','channel_id':'a'*32,
 'run_id':'different-run'if mode=='wrong-run'else request['run_id'],'result':result,'exit_code':code}
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

    def call_model(self,mode):
        (self.binding/'mode.json').write_text(json.dumps(mode))
        capture=self.output/'fresh'
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
        with patch.object(self.cli,'HERE',self.binding),patch.object(self.cli,'bindings',return_value=(self.launcher,{'manifest_digest':'sha256:'+'b'*64})),patch.object(self.cli,'subprocess',proxy),patch.object(sys,'argv',['cli.py','execute',str(self.request),str(capture)]),patch.dict(os.environ,{'SYSTEMROOT':os.environ.get('SYSTEMROOT','/'),'WINDIR':os.environ.get('WINDIR','/')}),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            status=self.cli.main()
        stdout.flush();stderr.flush();out=stdout.buffer.getvalue();err=stderr.buffer.getvalue()
        stdout.close();stderr.close()
        return status,out,err,capture

    def assert_outer_closed_before_fixture_cleanup(self):
        child=self.children[-1]
        self.assertIsNotNone(child.poll())
        self.assertTrue(all(stream.closed for stream in (child.stdin,child.stdout,child.stderr)))
        self.assertTrue(child._handle.closed)

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

    def test_previous_capture_is_never_replaced_or_redispatched(self):
        _,_,_,capture=self.call_model('positive')
        saved={p.name:p.read_bytes()for p in capture.iterdir()};count=len(self.children)
        with self.assertRaises(FileExistsError):self.call_model('positive')
        self.assertEqual(len(self.children),count)
        self.assertEqual({p.name:p.read_bytes()for p in capture.iterdir()},saved)

if __name__=='__main__':unittest.main()
