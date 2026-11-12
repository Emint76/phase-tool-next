"""Portable models of native input framing/ownership; no Native API or Phase run.

Actual Windows/NTFS and ext4 qualification remain separate required tests.
"""
import copy,ctypes,hashlib,os,re,stat,threading,time,types,unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.paths import safe_relative_locator
from phase_tool.bundle import validate_members,parse_manifest
from phase_tool.mutation.ntfs.native import NativeIdentity,_require
from phase_tool.mutation.ntfs import input_stage,native
from phase_tool import evidence
g=vars(input_stage);ng=vars(native);eg=vars(evidence)

def deadline():return time.perf_counter_ns()+20_000_000_000


IDENTITY={'volume_serial':99,'file_id':'0123456789abcdef0123456789abcdef'}


scope={'scope_id':'owner.inputs','root_identity':IDENTITY}


launch=types.SimpleNamespace(run_id='run-a',installation_digest='sha256:'+'3'*64,channel_id='a'*32,operation_nonce='b'*32)


def record(path,body):
    identity=dict(IDENTITY,file_id=hashlib.sha256(path.encode()).hexdigest()[:32])
    state=dict(native_identity=dict(identity),length=len(body),attributes=32,links=1,creation_time=10,write_time=20,change_time=30)
    return {'path':path,'length':len(body),'native_identity':dict(identity),'state':state}


class Source:
    def __init__(self,files,fail_close=False):
        self.files=files;self.records=[record(path,body)for path,body in files];self.close_count=0;self.checked=0;self.fail_close=fail_close
    def chunks(self,index):
        body=self.files[index][1]
        for start in range(0,len(body),256*1024):yield body[start:start+256*1024]
    def verify_complete(self):self.checked+=1
    def close(self):
        self.close_count+=1
        if self.fail_close:raise PhaseError('MODEL.source_close_unknown')


class Sink:
    def __init__(self):self.values=[];self.current=None;self.finish_count=0
    def begin_member(self,index,path,length):self.current=[index,path,length,bytearray()]
    def write(self,raw):self.current[3].extend(raw)
    def finish_member(self,row):
        assert len(self.current[3])==row['length']and digest_bytes(bytes(self.current[3]))==row['digest']
        self.values.append((row['path'],bytes(self.current[3])));self.current=None
    def finish(self,header_digest,rows,kind,preparation_binding=None):
        self.finish_count+=1
        return {'kind':kind,'rows':rows,'header':preparation_binding,'digest':header_digest}


def pair(files,role='File2'):
    source=Source(files);members=[path for path,_ in files]if role.startswith('Bundle')else None
    request=g['_stage_request']('owner.inputs','incoming',members)
    sender=g['_InputStageSender'](launch,scope,role,'sha256:'+'4'*64,request,source,deadline())
    sink=Sink();receiver=g['_InputStageReceiver'](sender.header,sink,deadline())
    return source,sender,sink,receiver


class StreamModels(unittest.TestCase):
    def test_file_binary_chunks_and_empty_file(self):
        for body in (b'',b'abc',b'\x00\xff'*(256*1024)+b'end'):
            source,sender,sink,receiver=pair([('payload',body)])
            for raw in sender.frames():result=receiver.feed(raw)
            self.assertEqual(sink.values,[('payload',body)]);self.assertEqual(receiver.state,'complete')
            self.assertEqual(source.close_count,1);self.assertEqual(source.checked,1);self.assertEqual(sink.finish_count,1)

    def test_bundle_canonical_manifest_zero_file_nested_members(self):
        files=[('a/empty.bin',b''),('b.bin',b'one'),('nested/c.bin',b'two')]
        source,sender,sink,receiver=pair(files,'Bundle1')
        for raw in sender.frames():result=receiver.feed(raw)
        self.assertEqual(sink.values,files);self.assertEqual(source.close_count,1)
        rows=result['rows'];manifest=canonical_bytes({'bundle_version':'1.0','members':rows,'total_length':6})
        self.assertEqual(parse_manifest(manifest)['total_length'],6)

    def test_legacy_empty_input_and_role_kind_and_high_volume_refused_before_bytes(self):
        for role in ('File1',):
            with self.assertRaises(PhaseError):pair([('payload',b'')],role)
        src=Source([('payload',b'a')]);src.records[0]['native_identity']['volume_serial']=100
        req=g['_stage_request']('owner.inputs','a',None)
        with self.assertRaises(PhaseError):g['_InputStageSender'](launch,scope,'File2','sha256:'+'4'*64,req,src,deadline())
        self.assertEqual(src.close_count,0) # enclosing concrete owner must close acquisition on construction refusal

    def test_malformed_member_control_bool_and_extra_are_sticky(self):
        for change in ('bool','extra','hash','index'):
            source,sender,sink,receiver=pair([('payload',b'x')]);frames=list(sender.frames());receiver.feed(frames[0])
            value=parse_json_bytes(frames[1])
            if change=='bool':value['member']['length']=True
            elif change=='extra':value['authority']={}
            elif change=='hash':value['member']['digest']='sha256:'+'0'*64
            else:value['index']=1
            with self.assertRaises(PhaseError):receiver.feed(canonical_bytes(value))
            self.assertEqual(receiver.state,'failed');self.assertEqual(sink.finish_count,0)
            with self.assertRaises(PhaseError):receiver.feed(frames[1])

    def test_source_close_failure_has_no_footer_and_no_repeat_close(self):
        source,sender,sink,receiver=pair([('payload',b'a')]);source.fail_close=True;frames=[]
        with self.assertRaises(PhaseError):
            for raw in sender.frames():frames.append(raw);receiver.feed(raw)
        self.assertEqual(source.close_count,1);self.assertEqual(receiver.state,'end');self.assertEqual(sink.finish_count,0)

    def test_cancelled_sender_closes_actual_source_once(self):
        source,sender,sink,receiver=pair([('payload',b'a'*(256*1024+1))]);frames=sender.frames();next(frames);frames.close()
        self.assertEqual(source.close_count,1)
        with self.assertRaises(PhaseError):next(sender.frames())

    def test_wrong_payload_length_footer_or_extra_rejected(self):
        for kind in ('short','footer-bool','footer-extra'):
            source,sender,sink,receiver=pair([('payload',b'x')]);frames=list(sender.frames())
            if kind=='short':bad=b'';prefix=[]
            else:
                prefix=frames[:-1];value=parse_json_bytes(frames[-1]);value['source_handles_closed']=1 if kind=='footer-bool'else True
                if kind=='footer-extra':value['retry']=True
                bad=canonical_bytes(value)
            for raw in prefix:receiver.feed(raw)
            with self.assertRaises(PhaseError):receiver.feed(bad)
            self.assertEqual(sink.finish_count,0)


class MemoryFS:
    def __init__(self):
        self.root=Path.cwd()/'MODEL_ONLY_PREPARATION_NOT_CREATED';self.nodes={};self.handles={};self.nextino=1;self.nextfd=100
        self.closed=[];self.calls=[];self.hook=None
        for path in (*reversed(self.root.parents),self.root):self.nodes[path]=self.node(True)
    def node(self,directory):
        value=dict(directory=directory,ino=self.nextino,data=bytearray(),links=1,mode=(stat.S_IFDIR|0o700)if directory else(stat.S_IFREG|0o600));self.nextino+=1;return value
    def event(self,name,*args):
        self.calls.append((name,*args))
        if self.hook:self.hook(self,name,*args)
    def info(self,node):return types.SimpleNamespace(st_dev=7,st_ino=node['ino'],st_mode=node['mode'],st_uid=42,st_nlink=node['links'],st_size=len(node['data']))
    def uid(self):return 42
    def lstat(self,path):self.event('lstat',path);return self.info(self.nodes[path])
    def fstat(self,fd):self.event('fstat',fd);return self.info(self.handles[fd]['node'])
    def open_handle(self,path):
        fd=self.nextfd;self.nextfd+=1;self.handles[fd]=dict(path=path,node=self.nodes[path],offset=0);return fd
    def open_root(self,path):self.event('open_root',path);return self.open_handle(path)
    def child_stat(self,parent,name):self.event('child_stat',parent,name);return self.info(self.nodes[self.handles[parent]['path']/name])
    def mkdir(self,parent,name):
        self.event('mkdir',parent,name);path=self.handles[parent]['path']/name
        if path in self.nodes:raise FileExistsError(str(path))
        self.nodes[path]=self.node(True)
    def directory(self,parent,name):self.event('directory',parent,name);return self.open_handle(self.handles[parent]['path']/name)
    def file(self,parent,name):
        self.event('file',parent,name);path=self.handles[parent]['path']/name
        if path in self.nodes:raise FileExistsError(str(path))
        self.nodes[path]=self.node(False);return self.open_handle(path)
    def write(self,fd,raw):
        self.event('write',fd,raw);entry=self.handles[fd];entry['node']['data'].extend(raw);entry['offset']+=len(raw);return len(raw)
    def rewind(self,fd):self.event('rewind',fd);self.handles[fd]['offset']=0;return 0
    def read(self,fd,count):
        self.event('read',fd,count);e=self.handles[fd];raw=bytes(e['node']['data'][e['offset']:e['offset']+count]);e['offset']+=len(raw);return raw
    def flush(self,fd):self.event('flush',fd)
    def close(self,fd):self.closed.append(fd);self.event('close',fd);del self.handles[fd]


class SinkModels(unittest.TestCase):
    def sink(self,fs):
        return eg['_OwnedInputStageSink'](fs.root,{'device':7,'inode':fs.nodes[fs.root]['ino']},'phase-native-input-'+'1'*32,deadline(),_io=fs)
    def test_real_sink_file_and_bundle_manifest_lengths_and_all_closes(self):
        for kind,files in (('file',[('payload',b'hello')]),('bundle',[('a/empty',b''),('b',b'world')])):
            fs=MemoryFS();sink=self.sink(fs);rows=[]
            for index,(path,raw)in enumerate(files):
                sink.begin_member(index,path,len(raw))
                if raw:sink.write(raw)
                row={'path':path,'length':len(raw),'digest':digest_bytes(raw)};rows.append(row);sink.finish_member(row)
            result=sink.finish('sha256:'+'2'*64,rows,kind,preparation_binding={'model':True})
            self.assertTrue(result['owned_preparation_descriptors_closed']);self.assertFalse(fs.handles)
            self.assertEqual(len(fs.closed),len(set(fs.closed)))
            if kind=='bundle':
                raw=canonical_bytes({'bundle_version':'1.0','members':rows,'total_length':5})
                self.assertEqual(result['expected_length'],len(raw));self.assertEqual(result['expected_digest'],digest_bytes(raw))
                self.assertNotEqual(result['expected_length'],result['total_length'])
            marker=next(node for path,node in fs.nodes.items()if path.name=='input-stage.json')
            stored=parse_json_bytes(bytes(marker['data']));self.assertIsNone(stored['final_acceptance'])
            self.assertNotIn('owned_preparation_descriptors_closed',stored)

    def test_corrupt_readback_never_ready_all_owned_fds_closed(self):
        fs=MemoryFS();sink=self.sink(fs);sink.begin_member(0,'payload',1);sink.write(b'a')
        def corrupt(io,name,*args):
            if name=='rewind':io.handles[args[0]]['node']['data'][:]=b'b'
        fs.hook=corrupt
        with self.assertRaises(PhaseError)as c:sink.finish_member({'path':'payload','length':1,'digest':digest_bytes(b'a')})
        with self.assertRaises(PhaseError):sink.abort(c.exception)
        self.assertFalse(fs.handles);self.assertEqual(len(fs.closed),len(set(fs.closed)))

    def test_close_failure_not_retried_and_original_preserved(self):
        fs=MemoryFS();sink=self.sink(fs);sink.begin_member(0,'payload',1);sink.write(b'a')
        original=PhaseError('MODEL.primary');failure=OSError('MODEL.close_unknown');chosen=sink.current['fd']
        def fail(io,name,*args):
            if name=='close'and args[0]==chosen:raise failure
        fs.hook=fail
        with self.assertRaises(BaseExceptionGroup)as c:sink.abort(original)
        self.assertIs(c.exception.exceptions[0],original);self.assertEqual(fs.closed.count(chosen),1)
        self.assertEqual(sum(fd==chosen for fd in fs.handles),1)

    def test_preparation_identity_substitution_before_write_refused(self):
        fs=MemoryFS();sink=self.sink(fs);sink.begin_member(0,'payload',1)
        stage=fs.root/sink.name;fs.nodes[stage]=fs.node(True)
        with self.assertRaises(PhaseError)as c:sink.write(b'a')
        with self.assertRaises(PhaseError):sink.abort(c.exception)
        self.assertFalse(any(name=='write'for name,*args in fs.calls))


class ContractCandidateModels(unittest.TestCase):
    def test_all_six_existing_candidate_formulas(self):
        for role in('File1','File2','Version1','Version2','Bundle1','Bundle2'):
            members=['a','nested/b']if role.startswith('Bundle')else None
            current='sha256:'+'e'*64 if role.startswith('Version')else None
            content='Hello \u03b1\n'if role=='Version2'else None
            value,raw=g['_publication_candidate'](role,'write-a','dest',members,current,content)
            self.assertEqual(canonical_bytes(value),raw)
            if role=='Version2':
                self.assertNotIn('input_binding',value);self.assertEqual(value['media_type'],'text/plain; charset=utf-8')
            else:self.assertEqual(value['input_binding'],'payload')
            if role.startswith('Version'):self.assertEqual(value['expected_current_digest'],current)
    def test_version1_zero_is_supported_and_v1_file_zero_is_not(self):
        source,sender,sink,receiver=pair([('payload',b'')],'Version1')
        for frame in sender.frames():receiver.feed(frame)
        self.assertEqual(receiver.state,'complete')
        with self.assertRaises(PhaseError):pair([('payload',b'')],'File1')
    def test_version2_utf8_bounded_inline_equals_independent_stage(self):
        for content in('', '\u03b1\n', 'x'*(512*1024)):
            body=content.encode();source,sender,sink,receiver=pair([('payload',body)],'Version2')
            for frame in sender.frames():receiver.feed(frame)
            self.assertEqual(bytes(sender.inline_bytes),body)
            prepared=dict(source_locator='phase-native-input-'+'1'*32+'/payload/payload',
                header_digest='sha256:'+'1'*64,expected_digest=digest_bytes(body),expected_length=len(body))
            req=g['_staged_publication_request'](role='Version2',prepared=prepared,input_scope='owner.inputs',
                request_id='v2-a',target_locator='dest',members=None,expected_current_digest='sha256:'+'e'*64,content_utf8=content)
            self.assertEqual(req['source_digest'],digest_bytes(body))
            bad=dict(req,source_digest='sha256:'+'f'*64)
            with self.assertRaises(PhaseError):g['_require_staged_publication_request'](bad,role='Version2')
        with self.assertRaises(PhaseError):pair([('payload',b'x'*(512*1024+1))],'Version2')
    def test_version2_binary_surrogates_or_oversize_never_candidate(self):
        with self.assertRaises(UnicodeDecodeError):b'\xff'.decode('utf-8',errors='strict')
        for body in('\ud800','x'*(512*1024+1)):
            with self.assertRaises(PhaseError):g['_publication_candidate']('Version2','a','dest',None,'sha256:'+'e'*64,body)
    def test_closed_relative_scope_and_target_grammar(self):
        for path in('../a','/absolute',r'C:\secret','a:ads',r'a\b','a/../b','con'):
            with self.assertRaises(PhaseError):g['_stage_request']('owner.inputs',path,None)
        for role in('File1','File2','Version1','Version2'):
            with self.assertRaises(PhaseError):g['_publication_candidate'](role,'write-a','dest',['member'],None)


class NativeHandle:
    def __init__(self,api,name,directory,ident):
        self.api=api;self.name=name;self.directory=directory;self.value=len(api.handles)+100
        self.ident=ident;self.close_count=0;api.handles.append(self)
    def close(self):
        self.close_count+=1
        if self.api.fail_close==self.name:raise OSError('MODEL.unknown_close')
        self.api.closed.append(self)


class NativeModel:
    def __init__(self,tree):
        self.tree=tree;self.handles=[];self.closed=[];self.fail_close=None;self.hook=None;self.entry_calls=[]
        self.volume=dict(device=r'\Device\HarddiskVolume7',volume_guid='model',volume_serial32=99,filesystem='NTFS',flags=0)
    def event(self,name,*args):
        if self.hook:self.hook(self,name,*args)
    def input_volume(self,drive):self.event('volume');return self.volume
    def _open(self,name,*,parent,directory,sharing=3,_input_name=False):
        self.event('open',name)
        path=name if parent is None else parent.name+'/'+name
        if path not in self.tree:raise PhaseError('MODEL.missing')
        row=self.tree[path]
        if row.get('reparse')or row['directory']!=directory:raise PhaseError('MODEL.reparse_or_type')
        return NativeHandle(self,path,directory,NativeIdentity(99,row['id']))
    def identity(self,h):return h.ident
    def assert_object(self,h,*,directory=None,expected=None):
        row=self.tree[h.name]
        if row.get('reparse')or(directory is not None and h.directory!=directory)or(expected is not None and h.ident!=expected):raise PhaseError('MODEL.identity')
    def entries(self,h,maximum):
        self.event('entries',h);self.entry_calls.append(h.name);prefix=h.name+'/'
        return{name[len(prefix):]:{'directory':row['directory'],'file_id':row['id']}
            for name,row in self.tree.items()if name.startswith(prefix)and'/'not in name[len(prefix):]}
    def input_state(self,h):
        self.event('state',h);row=self.tree[h.name];body=row.get('body',b'')
        return dict(native_identity=self.identity(h).as_dict(),length=len(body),attributes=32,
            links=row.get('links',1),creation_time=10,write_time=row.get('write',20),change_time=30)
    def read_chunks(self,h,length):
        self.event('read',h);yield self.tree[h.name]['body']


def native_fixture(bundle=False):
    prefix='\\Device\\HarddiskVolume7\\';tree={prefix:dict(directory=True,id='0'*31+'1')}
    tree[prefix+'/owned']=dict(directory=True,id='0'*31+'2')
    if bundle:
        tree[prefix+'/owned/incoming']=dict(directory=True,id='0'*31+'3')
        tree[prefix+'/owned/incoming/a']=dict(directory=False,id='0'*31+'4',body=b'a')
        source='incoming';members=['a']
    else:
        tree[prefix+'/owned/a']=dict(directory=False,id='0'*31+'4',body=b'a'*(512*1024+3))
        source='a';members=None
    api=NativeModel(tree);scope=dict(windows_root='C:\\owned',volume=api.volume,root_identity=NativeIdentity(99,'0'*31+'2').as_dict())
    return api,scope,source,members


class RetainedNativeSourceModels(unittest.TestCase):
    def test_actual_snapshot_retains_full_ids_chunks_and_closes_all(self):
        api,sc,source,members=native_fixture();snap=ng['_NativeInputSnapshot'](api,sc,source,members,deadline())
        chunks=list(snap.chunks(0));self.assertEqual([len(x)for x in chunks],[256*1024,256*1024,3])
        self.assertEqual(snap.records[0]['native_identity'],NativeIdentity(99,'0'*31+'4').as_dict())
        self.assertEqual(api.entry_calls,[]) # a large granted directory is not a bundle membership census
        snap.verify_complete();snap.close();self.assertEqual(len(api.closed),len(api.handles))
        with self.assertRaises(PhaseError):snap.close()
    def test_actual_snapshot_explicit_members_ignore_2048_unselected_siblings(self):
        api,sc,source,members=native_fixture(True)
        base=next(name for name in api.tree if name.endswith('/incoming'))
        for index in range(2048):api.tree[base+'/unselected'+str(index)]=dict(directory=False,id=format(index+100,'032x'),body=b'')
        snap=ng['_NativeInputSnapshot'](api,sc,source,members,deadline())
        self.assertEqual([r['path']for r in snap.records],['a']);self.assertEqual(api.entry_calls,[])
        self.assertEqual(b''.join(snap.chunks(0)),b'a');snap.verify_complete();snap.close()
        self.assertEqual(len(api.closed),len(api.handles))
    def test_actual_snapshot_declared_missing_rebound_alias_and_ancestor_drift(self):
        api,sc,source,members=native_fixture(True)
        with self.assertRaises(PhaseError):ng['_NativeInputSnapshot'](api,sc,source,['missing'],deadline())
        self.assertEqual(len(api.closed),len(api.handles))
        api,sc,source,members=native_fixture(True)
        base=next(name for name in api.tree if name.endswith('/incoming'))
        api.tree[base+'/alias']=dict(api.tree[base+'/a'])
        with self.assertRaises(PhaseError):ng['_NativeInputSnapshot'](api,sc,source,['a','alias'],deadline())
        self.assertEqual(len(api.closed),len(api.handles))
        for variant in('source','ancestor'):
            api,sc,source,members=native_fixture(True);snap=ng['_NativeInputSnapshot'](api,sc,source,members,deadline())
            selected=snap.files[0][0]if variant=='source'else snap.anchors[-1][0]
            selected.ident=NativeIdentity(99,'f'*32)
            with self.assertRaises(PhaseError):snap.verify_complete()
            snap.close()
        with self.assertRaises(PhaseError):g['_stage_request']('owner.inputs','incoming',['a','A'])
    def test_actual_snapshot_hardlinks_reparse_volume_drift(self):
        for variant in('hardlink','reparse','volume'):
            api,sc,source,members=native_fixture();leaf=next(name for name in api.tree if name.endswith('/a'))
            if variant=='hardlink':api.tree[leaf]['links']=2
            if variant=='reparse':api.tree[leaf]['reparse']=True
            if variant=='volume':sc['volume']=dict(api.volume,flags=2)
            with self.assertRaises(PhaseError):ng['_NativeInputSnapshot'](api,sc,source,members,deadline())
            self.assertEqual(len(api.closed),len(api.handles));self.assertTrue(all(h.close_count==1 for h in api.handles))
    def test_actual_snapshot_source_change_or_close_unknown_not_success(self):
        api,sc,source,members=native_fixture();snap=ng['_NativeInputSnapshot'](api,sc,source,members,deadline())
        leaf=next(name for name in api.tree if name.endswith('/a'));api.tree[leaf]['write']=21
        with self.assertRaises(PhaseError):list(snap.chunks(0))
        api.fail_close=leaf
        with self.assertRaises(BaseExceptionGroup):snap.close()
        with self.assertRaises(PhaseError):snap.close()
        self.assertTrue(all(h.close_count==1 for h in api.handles))


class WindowsStageRefusalModels(unittest.TestCase):
    def stage(self,role,length,*,fail_close=False,fail_recheck=False,receiver_started=False):
        from phase_tool.mutation.ntfs import bootstrap,process_witness
        model,sc,source,members=native_fixture()
        sc['scope_id']='owner.inputs'
        leaf=next(path for path in model.tree if path.endswith('/a'))
        opened=[]
        source_reads=[]

        class ModelIO(NativeModel):
            def __init__(self):
                super().__init__(model.tree)
                self.fail_close=leaf if fail_close else None
                self.states=0
                opened.append(self)
            @property
            def _handles(self):
                return [handle for handle in self.handles if handle not in self.closed]
            def input_snapshot(self,*args):
                return native._NativeInputSnapshot(self,*args)
            def input_state(self,handle):
                self.states+=1
                state=super().input_state(handle)
                state['length']=length
                if fail_recheck and self.states==3:state['write_time']+=1
                return state
            def read_chunks(self,*args):
                source_reads.append(args)
                raise AssertionError('no body read is permitted in this model')

        owner=types.SimpleNamespace(_startup={},_held_launch=None,_unavailable=False)
        probe=types.SimpleNamespace(**vars(launch),_invocation_bytes=b'model')
        bound=input_stage._role_bounds(role)[1]
        def fail_after_start(*args):
            raise input_stage._InputFileTooLarge(role,bound+1,bound)
        receiver=types.SimpleNamespace(send_frame=fail_after_start)
        witness=types.SimpleNamespace(wait_for_exit=lambda timeout:{'worker_exit_established':False})
        with patch.object(input_stage,'os',types.SimpleNamespace(name='nt',getpid=os.getpid)),\
                patch.object(native,'NativeIO',ModelIO),\
                patch.object(input_stage,'_scope_for_launch',return_value=(sc,role,'sha256:'+'4'*64)),\
                patch.object(bootstrap,'_NativeAcceptedLaunch',return_value=probe),\
                patch.object(process_witness,'WindowsProcessWitness',return_value=witness),\
                patch.object(probe,'spawn_input_stage',create=True)as spawn,\
                patch.object(probe,'_pipe',return_value=receiver,create=True):
            if not receiver_started:spawn.side_effect=AssertionError('receiver spawn attempted')
            try:
                result=input_stage.run_windows_input_stage(owner,'run-a','owner.inputs',source,members,deadline(),
                    request_id='request-a',target_locator='a.bin',expected_current_digest=None)
            except Exception as error:
                result=error
        self.assertEqual(source_reads,[])
        return owner,opened[0],spawn.call_count,result

    def test_file1_file2_plus_one_close_before_known_refusal_without_spawn(self):
        for role,maximum in (('File1',1024**2),('File2',2*1024**3)):
            with self.subTest(role=role):
                owner,api,starts,result=self.stage(role,maximum+1)
                self.assertEqual(result,input_stage._ClosedInputFileRefusal(role,maximum+1,maximum))
                self.assertEqual(starts,0);self.assertEqual(api._handles,[])
                self.assertTrue(all(handle.close_count==1 for handle in api.handles))
                self.assertIsNone(owner._held_input_source);self.assertIsNone(owner._held_input_io)
                self.assertFalse(owner._unavailable)

    def test_source_close_or_recheck_failure_has_no_closed_refusal(self):
        for fault in ('fail_close','fail_recheck'):
            with self.subTest(fault=fault):
                owner,api,starts,result=self.stage('File2',2*1024**3+1,**{fault:True})
                self.assertIsInstance(result,Exception);self.assertEqual(starts,0)
                self.assertEqual(bool(api._handles),fault=='fail_close')
                self.assertIs(owner._held_input_io,api)
                self.assertTrue(all(handle.close_count==1 for handle in api.handles))

    def test_exact_boundary_enters_receiver_and_same_late_error_is_unknown(self):
        for role,maximum in (('File1',1024**2),('File2',2*1024**3)):
            with self.subTest(role=role):
                owner,api,starts,result=self.stage(role,maximum,receiver_started=True)
                self.assertEqual(starts,1);self.assertIsInstance(result,BaseExceptionGroup)
                self.assertTrue(owner._unavailable);self.assertIsNotNone(owner._held_launch)
                self.assertEqual(api._handles,[])


class PrivatePipeSelectionModels(unittest.TestCase):
    execute_roles = ('core', 'original', 'worker')

    @staticmethod
    def requests(length):
        # Use the real header, source record and staged execute builders.
        body = b'x' * length
        _, sender, _, _ = pair([('payload', body)], 'File1')
        header = parse_json_bytes(sender.header)
        stage = {'operation':'stage_input', 'native_input_stage_request_version':'1.0', 'header':header}
        prepared = {'source_locator':'phase-native-input-' + sender.header_digest[7:39] + '/payload/payload',
                    'header_digest':sender.header_digest, 'expected_digest':digest_bytes(body),
                    'expected_length':length}
        execute = input_stage._staged_publication_request(role='File1', prepared=prepared,
            input_scope=scope['scope_id'], request_id='pipe-test', target_locator='out.bin', members=None,
            expected_current_digest=None)
        return stage, execute

    @staticmethod
    def launch_shell(request, *, version='1.1', contract='file_create.v1', inspection=False):
        from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch

        # Model only the transport selector's parsed launch fields.
        selected = object.__new__(_NativeAcceptedLaunch)
        selected._manifest_bytes = canonical_bytes({'native_read_installation_version':version,
            'contract':{'id':contract}})
        selected._invocation_bytes = canonical_bytes({'request':request})
        selected._inspection_only = inspection
        selected._file2 = contract == 'file_create.v2'
        return selected

    @staticmethod
    @contextmanager
    def active_clock():
        clock = types.SimpleNamespace(now=1_000_000_000)
        simulated_windows = types.SimpleNamespace(name='nt', getpid=os.getpid)
        with patch.object(input_stage, 'os', simulated_windows), patch.object(input_stage, 'time',
                types.SimpleNamespace(perf_counter_ns=lambda:clock.now)):
            token = input_stage._InputOperationDeadline(_initial_deadline_ns=clock.now + 10_000)
            with input_stage._input_operation_scope(token):
                yield clock, token

    def test_file1_private_pipe_threshold_uses_real_stage_and_execute_controls(self):
        for length in (64 * 1024, 256 * 1024 - 1, 256 * 1024, 1024**2):
            with self.subTest(length=length):
                stage, execute = self.requests(length)
                prepared = self.launch_shell(stage)
                publication = self.launch_shell(execute)
                self.assertFalse(prepared._file1_input_pipes('prepare-input'))
                self.assertFalse(publication._file1_input_pipes('core'))
                with self.active_clock():
                    self.assertEqual(prepared._file1_input_pipes('prepare-input'), length >= 256 * 1024)
                    self.assertFalse(publication._file1_input_pipes('prepare-input'))
                    for role in self.execute_roles:
                        self.assertFalse(prepared._file1_input_pipes(role))
                        self.assertEqual(publication._file1_input_pipes(role), length >= 256 * 1024)
                self.assertFalse(publication._file1_input_pipes('core'))

    def test_file1_private_pipe_does_not_follow_foreign_role_or_request(self):
        stage, execute = self.requests(256 * 1024)
        with self.active_clock():
            publication = self.launch_shell(execute)
            for role in ('inspect', 'observe-recovery', 'worker-unlisted'):
                self.assertFalse(publication._file1_input_pipes(role))
            for selected in (self.launch_shell(execute, inspection=True),
                             self.launch_shell(execute, version='1.2'),
                             self.launch_shell(execute, contract='bundle_create.v1'),
                             self.launch_shell({'operation':'execute', 'source_length':1024**2})):
                self.assertFalse(selected._file1_input_pipes('core'))
            for bad_length in (True, 1024**2 + 1):
                invalid = copy.deepcopy(stage)
                invalid['header']['members'][0]['length'] = bad_length
                self.assertFalse(self.launch_shell(invalid)._file1_input_pipes('prepare-input'))
            other = dict(stage, header=dict(stage['header'], role='File2'))
            self.assertFalse(self.launch_shell(other)._file1_input_pipes('prepare-input'))
            bad_path = dict(execute, source_locator='other/payload')
            with self.assertRaisesRegex(PhaseError, 'input_stage.staged_path_binding'):
                self.launch_shell(bad_path)._file1_input_pipes('original')

    def test_original_deadline_precedes_pipe_or_process_creation(self):
        from phase_tool.mutation.ntfs import bootstrap, private_stdio

        class StopBeforeAllocation(Exception):
            pass

        large = self.launch_shell(self.requests(1024**2)[1])
        small = self.launch_shell(self.requests(64 * 1024)[1])
        args = ['modeled-fixed-launcher', 'core']
        with (self.active_clock() as (clock, token),
              patch.object(bootstrap._NativeAcceptedLaunch, '_windows_required'),
              patch.object(bootstrap._NativeAcceptedLaunch, '_check_linux_contours'),
              patch.object(private_stdio, '_PrivateSizedStdio', side_effect=StopBeforeAllocation) as private,
              patch.object(bootstrap.subprocess, 'CREATE_NO_WINDOW', 0, create=True),
              patch.object(bootstrap.subprocess, 'Popen', side_effect=StopBeforeAllocation) as ordinary):
            with self.assertRaises(StopBeforeAllocation):
                large._spawn(args)
            private.assert_called_once_with()
            ordinary.assert_not_called()
            with self.assertRaises(StopBeforeAllocation):
                small._spawn(args)
            ordinary.assert_called_once()
            clock.now = token.deadline_ns
            for selected in (large, small):
                with self.assertRaisesRegex(PhaseError, 'input_stage.deadline'):
                    selected._spawn(args)
            private.assert_called_once_with()
            ordinary.assert_called_once()


class DeadlineModels(unittest.TestCase):
    def test_one_absolute_deadline_caps_all_clocks_no_reset_or_foreign_token(self):
        clock=types.SimpleNamespace(now=1_000_000_000)
        old_os,old_time=g['os'],g['time']
        g['os']=types.SimpleNamespace(name='nt',getpid=os.getpid)
        g['time']=types.SimpleNamespace(perf_counter_ns=lambda:clock.now,monotonic_ns=lambda:clock.now)
        try:
            token=g['_InputOperationDeadline'](_initial_deadline_ns=clock.now+10_000)
            with g['_input_operation_scope'](token):
                self.assertEqual(g['_cap_input_deadline'](clock.now+100_000),token.deadline_ns)
                clock.now+=4_000
                self.assertEqual(g['_cap_input_deadline'](clock.now+100_000),token.deadline_ns)
                self.assertEqual(g['_cap_input_deadline'](clock.now+1_000),clock.now+1_000)
                with self.assertRaises(PhaseError):
                    with g['_input_operation_scope'](token):pass
                clock.now=token.deadline_ns
                with self.assertRaises(PhaseError):g['_cap_input_deadline'](clock.now+30_000_000_000)
                self.assertEqual(g['_input_observation_timeout_ms'](60000),0)
            with self.assertRaises(PhaseError):
                with g['_input_operation_scope'](token):pass
            self.assertEqual(g['_cap_input_deadline'](123),123)
            self.assertEqual(g['_input_observation_timeout_ms'](60000),60000)
            for bad in(True,clock.now,clock.now+30_000_000_001):
                with self.assertRaises(PhaseError):g['_InputOperationDeadline'](_initial_deadline_ns=bad)
        finally:g['os'],g['time']=old_os,old_time
    def test_expired_or_final_close_never_claims_ready(self):
        fs=MemoryFS();sink=SinkModels().sink(fs);sink.begin_member(0,'payload',1);sink.write(b'a')
        row=dict(path='payload',length=1,digest=digest_bytes(b'a'));sink.finish_member(row)
        def late_close(io,name,*args):
            if name=='close'and args[0]==sink.rootfd:sink._clock=lambda:sink.deadline
        fs.hook=late_close
        with self.assertRaises(PhaseError):sink.finish('sha256:'+'1'*64,[row],'file',preparation_binding={})
        marker=next(node for path,node in fs.nodes.items()if path.name=='input-stage.json')
        stored=parse_json_bytes(bytes(marker['data']));self.assertIsNone(stored['final_acceptance'])
        self.assertEqual(stored['telemetry_stage'],'PRE_RETURN_PREPARATION_DATA')
        self.assertFalse(fs.handles)


class FrameOwnerModels(unittest.TestCase):
    def model(self,raw):
        import sys
        class IO:
            O_ACCMODE=3;O_RDONLY=0;O_WRONLY=1;O_NONBLOCK=2048
            def __init__(self):self.raw=bytearray(raw);self.output=bytearray();self.ids=[10,11];self.closed=[]
            def getpid(self):return os.getpid()
            def fstat(self,fd):return types.SimpleNamespace(st_dev=7,st_ino=self.ids[fd],st_mode=stat.S_IFIFO|0o600)
            def isatty(self,fd):return False
            def read(self,fd,count):value=bytes(self.raw[:min(count,3)]);del self.raw[:len(value)];return value
            def write(self,fd,value):value=value[:3];self.output.extend(value);return len(value)
        io_model=IO();old=eg['os'];eg['os']=io_model
        fcntl=types.SimpleNamespace(F_GETFL=3,fcntl=lambda fd,flag:2048|fd)
        poll=types.SimpleNamespace(register=lambda *a:None,poll=lambda *a:[(0,1)])
        selected=types.SimpleNamespace(POLLOUT=4,POLLIN=1,poll=lambda:poll)
        context=patch.dict(sys.modules,{'fcntl':fcntl,'select':selected});context.__enter__()
        try:owner=eg['_InputStageFrames'](deadline())
        except BaseException:context.__exit__(None,None,None);eg['os']=old;raise
        return owner,io_model,lambda:(context.__exit__(None,None,None),eg.__setitem__('os',old))
    def test_actual_byte_framer_partial_read_write_seals_no_close(self):
        raw=b'hello\x00\xff';frame=f'{len(raw):08x}\n'.encode()+raw+b'\n'
        owner,io_model,restore=self.model(frame)
        try:
            self.assertEqual(owner.receive_frame(99),raw);owner.send_frame(raw)
            self.assertEqual(bytes(io_model.output),frame);owner.seal()
            with self.assertRaises(PhaseError):owner.send_frame(raw)
            self.assertEqual(io_model.closed,[])
        finally:restore()
    def test_actual_byte_framer_truncation_bad_frame_or_fd_identity_sticky(self):
        for raw,substitute in((b'00000004\nx\n',False),(b'zzzzzzzz\n',False),(b'00000001\nx\n',True)):
            owner,io_model,restore=self.model(raw)
            try:
                if substitute:io_model.ids[0]+=1
                with self.assertRaises(PhaseError):owner.receive_frame(99)
                self.assertTrue(owner.failed)
                with self.assertRaises(PhaseError):owner.receive_frame(99)
            finally:restore()


class SinkOwnedClosureModels(unittest.TestCase):
    def test_parent_namespace_changed_still_closes_owned_fds_once_preserving_primary(self):
        fs=MemoryFS();sink=SinkModels().sink(fs);sink.begin_member(0,'payload',1)
        fs.nodes[fs.root/sink.name]=fs.node(True)
        with self.assertRaises(PhaseError)as failed:sink.write(b'x')
        with self.assertRaises(PhaseError)as closed:sink.abort(failed.exception)
        self.assertIs(closed.exception,failed.exception);self.assertFalse(fs.handles)
        self.assertEqual(len(fs.closed),len(set(fs.closed)))
    def test_ancestor_symlink_to_same_root_is_rejected_and_closes_owned_fds(self):
        fs=MemoryFS();sink=SinkModels().sink(fs);sink.begin_member(0,'payload',1)
        parent=fs.root.parent;replacement=fs.node(False);replacement['mode']=stat.S_IFLNK|0o777;fs.nodes[parent]=replacement
        with self.assertRaises(PhaseError)as failed:sink.write(b'x')
        with self.assertRaises(PhaseError):sink.abort(failed.exception)
        self.assertFalse(fs.handles);self.assertFalse(any(row[0]=='write'for row in fs.calls))
    def test_foreign_reused_fd_remains_open_while_other_owned_fds_close(self):
        fs=MemoryFS();sink=SinkModels().sink(fs);sink.begin_member(0,'payload',1)
        chosen=sink.current['fd'];fs.handles[chosen]['node']=fs.node(False)
        primary=PhaseError('MODEL.namespace_primary')
        with self.assertRaises(BaseExceptionGroup)as result:sink.abort(primary)
        self.assertIs(result.exception.exceptions[0],primary)
        self.assertIn(chosen,fs.handles);self.assertNotIn(chosen,fs.closed)
        self.assertEqual(set(fs.handles),{chosen})
    def test_namespace_primary_and_close_failure_both_retained_without_repeat(self):
        fs=MemoryFS();sink=SinkModels().sink(fs);sink.begin_member(0,'payload',1)
        fs.nodes[fs.root/sink.name]=fs.node(True);chosen=sink.current['fd']
        with self.assertRaises(PhaseError)as failed:sink.write(b'x')
        def bad(io,name,*args):
            if name=='close'and args[0]==chosen:raise OSError('MODEL.close_unknown')
        fs.hook=bad
        with self.assertRaises(BaseExceptionGroup)as result:sink.abort(failed.exception)
        self.assertIs(result.exception.exceptions[0],failed.exception);self.assertEqual(fs.closed.count(chosen),1)
        self.assertIn(chosen,fs.handles)
    def test_namespace_drift_during_last_close_rejects_prepared_return(self):
        fs=MemoryFS();sink=SinkModels().sink(fs);sink.begin_member(0,'payload',0)
        row=dict(path='payload',digest=digest_bytes(b''),length=0);sink.finish_member(row)
        def substitute(io,name,*args):
            if name=='close'and args[0]==sink.rootfd:io.nodes[fs.root/sink.name]=io.node(True)
        fs.hook=substitute
        with self.assertRaises(PhaseError):sink.finish('sha256:'+'1'*64,[row],'file',preparation_binding={})
        self.assertFalse(fs.handles)
