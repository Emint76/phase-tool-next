"""Linux control-protocol fault regressions over real subprocess pipes.

No native Windows worker, grant authority, Core admission or filesystem writes.
The test peer deliberately sends synthetic ACKs/errors; they are not receipts.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest

from phase_tool.canonical import canonical_bytes, parse_json_bytes
import phase_tool


CLIENT = r'''
import fcntl,hashlib,json,os,sys,threading
from pathlib import Path
if Path(sys.pycache_prefix).exists():raise RuntimeError('unexpected child bytecode prefix')
from phase_tool.errors import PhaseError
import phase_tool.mutation.ntfs.channel as channel_source
import phase_tool.mutation.ntfs.native as native_source
from phase_tool.mutation.ntfs.channel import LinuxNativeChannel,NativeChannelError
root=Path(os.environ['PHASE_NATIVE_CHANNEL_SOURCE_ROOT']).resolve(strict=True)
loaded={}
for name,module,sha in (
 ('channel',channel_source,'e2546d5767736eb98576765b6d71f483b282ae3c748968bc1152b999ad11d570'),
 ('native',native_source,'41654049dc10f1c2db0f74c847f0a36038b49295c4f02582b959b9c7a0dd0a22')):
 p=Path(module.__file__).resolve(strict=True)
 if p!=root/'phase_tool/mutation/ntfs'/(name+'.py') or hashlib.sha256(p.read_bytes()).hexdigest()!=sha:
  raise RuntimeError('wrong child module origin or bytes')
 loaded[name]={'path':str(p),'sha256':sha}
os.set_blocking(0,False);os.set_blocking(1,False)
c=LinuxNativeChannel('ab'*16)
mode=sys.argv[1];result={'mode':mode,'loaded_sources':loaded}
def execute():return c.execute_file_create(run_id='own-channel-test',intent_digest='sha256:'+'34'*32)
def observe():return c.observe_file(run_id='own-channel-test',root_binding='phase_result_root',locator='result.bin')
try:
 if mode=='normal':
  result['observed']=observe();result['executed']=execute()
  try:c.__init__('ab'*16)
  except PhaseError as e:result['reinit_error']=e.code
  execute()
 elif mode=='invalid_payload':
  c._exchange('observe_file','own-channel-test',None,{'protocol':'evil'})
 elif mode=='owner':
  def other():
   try:observe()
   except NativeChannelError as e:result['other_error']=e.details
  t=threading.Thread(target=other);t.start();t.join();execute()
 elif mode=='reentrant':
  original=c._write
  def nested(data,deadline):
   try:observe()
   except NativeChannelError as e:result['nested_error']=e.details
   return original(data,deadline)
  c._write=nested;execute()
 elif mode=='flags':
  os.set_blocking(1,True);execute()
 elif mode=='seal':
  before=[(os.fstat(fd).st_ino,fcntl.fcntl(fd,fcntl.F_GETFL)) for fd in (0,1)]
  c.seal()
  result['borrowed_pipes_unchanged']=before==[(os.fstat(fd).st_ino,fcntl.fcntl(fd,fcntl.F_GETFL)) for fd in (0,1)]
  execute()
 else:execute()
except NativeChannelError as e:
 result['error']={'code':e.code,'possible_dispatch':e.possible_dispatch,'details':e.details}
result['possible_dispatch']=c.possible_dispatch
sys.stderr.write(json.dumps(result,sort_keys=True))
'''


@unittest.skipUnless(sys.platform.startswith('linux'), 'real Linux borrowed-pipe protocol')
class NativeChannelTests(unittest.TestCase):
    def setUp(self):
        self.children = []
        self.source_root = Path(phase_tool.__file__).resolve(strict=True).parent.parent
        self.loaded = {name: {'path': str(self.source_root/'phase_tool/mutation/ntfs'/(name+'.py')), 'sha256': sha}
            for name, sha in (
                ('channel', 'e2546d5767736eb98576765b6d71f483b282ae3c748968bc1152b999ad11d570'),
                ('native', '41654049dc10f1c2db0f74c847f0a36038b49295c4f02582b959b9c7a0dd0a22'))}

    def tearDown(self):
        errors = []
        for child in self.children:
            try:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
            except BaseException as error:
                errors.append(error)
            finally:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None and not stream.closed:
                        try:
                            stream.close()
                        except BaseException as error:
                            errors.append(error)
        if errors:
            raise AssertionError('own protocol child finalization failed: '+str(errors))

    def start(self, mode):
        environment = os.environ.copy()
        environment.update(PYTHONPATH=str(self.source_root),
            PYTHONPYCACHEPREFIX=str(self.source_root/'bytecode-not-created'),
            PYTHONDONTWRITEBYTECODE='1', PHASE_NATIVE_CHANNEL_SOURCE_ROOT=str(self.source_root))
        self.assertFalse(Path(environment['PYTHONPYCACHEPREFIX']).exists())
        child = subprocess.Popen([sys.executable, '-B', '-c', CLIENT, mode],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, env=environment)
        self.children.append(child)
        return child

    def read_exact(self, child, count):
        value = bytearray()
        deadline = time.monotonic()+5
        while len(value) < count:
            self.assertGreater(deadline-time.monotonic(), 0, 'protocol peer deadline')
            readable, _, _ = select.select([child.stdout], [], [], max(0, deadline-time.monotonic()))
            self.assertTrue(readable, 'protocol peer did not write')
            data = os.read(child.stdout.fileno(), count-len(value))
            self.assertTrue(data, 'protocol peer EOF before complete frame')
            value.extend(data)
        return bytes(value)

    def request(self, child, kind):
        header = self.read_exact(child, 9)
        self.assertRegex(header, b'^[0-9a-f]{8}\n$')
        length = int(header[:8], 16)
        self.assertLessEqual(length, 4096)
        raw = self.read_exact(child, length)
        self.assertEqual(self.read_exact(child, 1), b'\n')
        value = parse_json_bytes(raw)
        self.assertEqual(canonical_bytes(value), raw)
        expected = {'protocol', 'version', 'channel_id', 'sequence', 'kind', 'run_id', 'intent_digest'}
        if kind == 'observe_file':
            expected |= {'root_binding', 'locator', 'expected_identity'}
            self.assertEqual(value['root_binding'], 'phase_result_root')
            self.assertEqual(value['locator'], 'result.bin')
            self.assertIsNone(value['intent_digest'])
        else:
            self.assertEqual(value['intent_digest'], 'sha256:'+'34'*32)
        self.assertEqual(set(value), expected)
        self.assertEqual(value['kind'], kind)
        self.assertEqual(value['channel_id'], 'ab'*16)
        self.assertEqual(value['run_id'], 'own-channel-test')
        self.assertIs(type(value['sequence']), int)
        return {key: value[key] for key in ('protocol', 'version', 'channel_id', 'sequence', 'kind', 'run_id', 'intent_digest')}

    def response(self, child, common, *, value=None, error=None, edit=None, raw_override=None):
        response = common | {'ok': error is None, 'value': {} if value is None else value, 'error': error}
        if error is not None:
            response['value'] = None
        if edit:
            response.update(edit)
        raw = canonical_bytes(response) if raw_override is None else raw_override(response)
        frame = f'{len(raw):08x}\n'.encode('ascii')+raw+b'\n'
        self.assertLessEqual(len(frame), 4096)
        # Multiple actual sender writes; scheduling may coalesce receiver reads.
        for offset in range(0, len(frame), 7):
            chunk = frame[offset:offset+7]
            while chunk:
                written = os.write(child.stdin.fileno(), chunk)
                self.assertGreater(written, 0)
                chunk = chunk[written:]

    def finish(self, child):
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stderr.decode('utf-8', 'replace'))
        self.assertEqual(stdout, b'', 'unexpected extra command or automatic resend')
        self.assertLessEqual(len(stderr), 16384)
        result = json.loads(stderr)
        self.assertEqual(result['loaded_sources'], self.loaded)
        return result

    def test_observe_execute_once_and_init_cannot_reset_dispatch(self):
        child = self.start('normal')
        first = self.request(child, 'observe_file')
        self.assertEqual(first['sequence'], 1)
        self.response(child, first, value={'synthetic_observation': True})
        second = self.request(child, 'execute_file_create')
        self.assertEqual(second['sequence'], 2)
        self.response(child, second, value={'synthetic_ack_only': True})
        result = self.finish(child)
        self.assertEqual(result['observed'], {'synthetic_observation': True})
        self.assertEqual(result['executed'], {'synthetic_ack_only': True})
        self.assertEqual(result['reinit_error'], 'ntfs.channel_initialization_consumed')
        self.assertTrue(result['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_execution_consumed')

    def test_eof_after_execution_frame_stays_unknown_without_resend(self):
        child = self.start('eof')
        self.request(child, 'execute_file_create')
        result = self.finish(child)  # communicate closes request source: actual EOF.
        self.assertTrue(result['error']['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_eof_unknown')

    def test_bool_sequence_is_not_integer_sequence(self):
        child = self.start('boolean')
        common = self.request(child, 'execute_file_create')
        self.response(child, common, edit={'sequence': True})
        result = self.finish(child)
        self.assertTrue(result['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_response_shape')

    def test_response_from_another_channel_is_rejected(self):
        child = self.start('foreign')
        common = self.request(child, 'execute_file_create')
        self.response(child, common, edit={'channel_id': 'cd'*16})
        result = self.finish(child)
        self.assertTrue(result['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_response_binding_mismatch')

    def test_structured_remote_primary_error_is_retained(self):
        child = self.start('remote')
        common = self.request(child, 'execute_file_create')
        error = {'code': 'ntfs.create_outcome_unknown', 'message': 'synthetic remote error',
                 'details': {'ntstatus': '0xc0000280', 'synthetic': True}}
        self.response(child, common, error=error)
        result = self.finish(child)
        self.assertTrue(result['error']['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['details']['remote_error'], error)

    def test_duplicate_json_member_is_rejected(self):
        child = self.start('duplicate')
        common = self.request(child, 'execute_file_create')
        self.response(child, common, raw_override=lambda value: canonical_bytes(value)[:-1]+b',"ok":true}')
        result = self.finish(child)
        self.assertTrue(result['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'candidate.duplicate_key')

    def test_closed_request_rejects_common_field_injection_before_write(self):
        result = self.finish(self.start('invalid_payload'))
        self.assertFalse(result['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_request_shape')

    def test_other_thread_poison_prevents_following_execution(self):
        result = self.finish(self.start('owner'))
        self.assertFalse(result['possible_dispatch'])
        self.assertEqual(result['other_error']['primary']['code'], 'ntfs.channel_owner_changed')
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_unavailable')

    def test_reentrant_exchange_poison_prevents_actual_frame_write(self):
        result = self.finish(self.start('reentrant'))
        self.assertTrue(result['possible_dispatch'])  # Conservative, even before bytes.
        self.assertEqual(result['nested_error']['primary']['code'], 'ntfs.channel_reentrant_call')
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_unavailable')

    def test_changed_blocking_flag_rejected_before_actual_frame_write(self):
        result = self.finish(self.start('flags'))
        self.assertTrue(result['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_pipe_blocking')

    def test_seal_revokes_calls_without_closing_borrowed_pipes(self):
        result = self.finish(self.start('seal'))
        self.assertTrue(result['borrowed_pipes_unchanged'])
        self.assertFalse(result['possible_dispatch'])
        self.assertEqual(result['error']['details']['primary']['code'], 'ntfs.channel_unavailable')
