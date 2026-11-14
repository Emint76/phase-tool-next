"""Real finite POSIX pipes plus default ext4 sink; no admitted Native launch.

Wire metadata is controlled unit-fixture data. No Windows source handle,
Core operation, worker, receipt or qualification success is modeled as real.
"""
import hashlib,json,os,subprocess,sys
from pathlib import Path
import pytest
import phase_tool
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes

pytestmark=pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Actual Linux pipe/ext4 component only')
CHUNK=256*1024
CHILD=r'''
import errno,json,os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from phase_tool.canonical import canonical_bytes
from phase_tool.evidence import _InputStageFrames,_OwnedInputStageSink
from phase_tool.mutation.ntfs.input_stage import _InputStageReceiver
from phase_tool.mutation.ntfs.entrypoint import _linux_stdio_identity
root=Path(sys.argv[2]);info=root.lstat();deadline=time.monotonic_ns()+10_000_000_000
_linux_stdio_identity();frames=_InputStageFrames(deadline);sink=None
try:
 header=frames.receive_frame(2*1024**2)
 sink=_OwnedInputStageSink(root,dict(device=info.st_dev,inode=info.st_ino),'phase-native-input-'+'1'*32,deadline)
 receiver=_InputStageReceiver(header,sink,deadline)
 while receiver.state!='complete':result=receiver.feed(frames.receive_frame(receiver.wanted()or 2*1024**2))
 frames.send_frame(canonical_bytes(result));frames.seal()
except BaseException as primary:
 error=primary
 if sink is not None and not sink.close_attempted:
  try:sink.abort(primary)
  except BaseException as final:error=final
 closed=[]
 if sink is not None:
  for row in sink.opened:
   try:os.fstat(row['fd']);known_closed=False
   except OSError as e:known_closed=e.errno==errno.EBADF
   closed.append(dict(actual_ebadf=known_closed,closed=row['closed'],close_attempted=row['close_attempted']))
 sys.stderr.buffer.write(canonical_bytes(dict(error_type=type(error).__name__,code=getattr(error,'code',None),descriptors=closed)))
 raise SystemExit(50)
'''

def frame(raw):return ('%08x\n'%len(raw)).encode()+raw+b'\n'

def fixture_wire(body,complete=True):
 header={'protocol':'phase.native.input.stage','version':'1.0','kind':'header','chunk_bytes':CHUNK,
  'members':[{'path':'payload','length':len(body)}],'total_length':len(body),'payload_kind':'file'}
 raw=canonical_bytes(header);h=digest_bytes(raw)
 row={'path':'payload','length':len(body),'digest':digest_bytes(body)}
 wire=frame(raw)+b''.join(frame(body[n:n+CHUNK])for n in range(0,len(body),CHUNK))
 if complete:
  wire+=frame(canonical_bytes({'protocol':'phase.native.input.stage','version':'1.0','kind':'member_end','header_digest':h,'index':0,'member':row}))
  wire+=frame(canonical_bytes({'protocol':'phase.native.input.stage','version':'1.0','kind':'end','header_digest':h,'members':[row],'total_length':len(body),'source_handles_closed':True}))
 return wire

def invoke(tmp_path,wire):
 from phase_tool.installation import _linux_filesystem_type
 assert os.geteuid()!=0 and os.getegid()!=0 and _linux_filesystem_type(tmp_path)=='ext4'
 root=tmp_path/'preparation';root.mkdir(mode=0o700)
 p=subprocess.Popen([sys.executable,'-I','-B','-c',CHILD,str(Path(phase_tool.__file__).parent.parent),str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:
  try:out,err=p.communicate(wire,timeout=12)
  except subprocess.TimeoutExpired:
   p.kill();p.wait(timeout=2);raise
  assert p.poll()is not None
  return root,p.returncode,out,err
 finally:
  for stream in(p.stdin,p.stdout,p.stderr):stream.close()

def test_real_raw_pipes_deliver_binary_chunks_into_checked_ext4_sink(tmp_path):
 body=bytes(range(256))*4096+b'end'
 root,code,out,err=invoke(tmp_path,fixture_wire(body))
 assert code==0 and err==b'' and len(out)>10
 length=int(out[:8],16);assert out[8:9]==b'\n'and len(out)==length+10 and out[-1:]==b'\n'
 result=parse_json_bytes(out[9:-1]);assert result['owned_preparation_descriptors_closed']is True
 assert result['expected_digest']==digest_bytes(body)and result['expected_length']==len(body)
 payload=root/result['source_locator'];assert payload.read_bytes()==body
 marker=json.loads((root/('phase-native-input-'+'1'*32)/'input-stage.json').read_bytes())
 assert marker['final_acceptance']is None and marker['telemetry_stage']=='PRE_RETURN_PREPARATION_DATA'

def test_real_truncated_stream_keeps_written_prefix_and_closes_owned_sink(tmp_path):
 body=b'x'*(CHUNK+37)
 root,code,out,err=invoke(tmp_path,fixture_wire(body,complete=False))
 assert code==50 and out==b''
 negative=parse_json_bytes(err);assert negative['code']=='input_stage.truncated_stream'
 assert negative['descriptors']and all(r['actual_ebadf']and r['closed']and r['close_attempted']for r in negative['descriptors'])
 assert(root/('phase-native-input-'+'1'*32)/'payload/payload').read_bytes()==body
 assert not(root/('phase-native-input-'+'1'*32)/'input-stage.json').exists()
