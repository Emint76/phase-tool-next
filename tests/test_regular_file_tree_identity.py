"""Portable full-file-tree identity/hash regressions; no real IO or SDK execution."""
import copy,hashlib,json,stat,time,unittest
from pathlib import Path
from types import SimpleNamespace
from phase_tool import evidence as reader

ROOT=Path.cwd()/'MODEL_ONLY_FILE_TREE_NO_DIRECTORY_CREATED'
root=ROOT
scope=vars(reader)
def verify(root,expected,_io=None,_windows=None):
    return reader._snapshot_regular_file_tree(root,expected_files=expected,maximum_files=8192,maximum_directories=8192,
        maximum_file_bytes=16*1024**2,maximum_total_bytes=64*1024**2,deadline_ns=time.monotonic_ns()+10_000_000_000,
        _io=_io,_windows=_windows)
m=SimpleNamespace(verify_sdk_tree=verify,_cross_file=reader._tree_cross,_named_state=reader._tree_state)

class MemoryIO:
    def __init__(self,windows=False):
        self.windows=windows;self.nodes={};self.handles={};self.next_inode=1;self.next_fd=100;self.closed=[];self.calls=[];self.hook=None
        for path in (*reversed(ROOT.parents),ROOT):self.directory(path)
    def directory(self,path):
        path=Path(path)
        if path not in self.nodes:self.nodes[path]={'kind':'directory','inode':self.next_inode,'bytes':b'','links':1,'mtime':10,'ctime':20,'birth':5,'attrs':0};self.next_inode+=1
    def file(self,name,body):
        path=ROOT/name
        for parent in reversed(path.parents):
            if parent==ROOT or ROOT in parent.parents:self.directory(parent)
        self.nodes[path]={'kind':'file','inode':self.next_inode,'bytes':body,'links':1,'mtime':10,'ctime':20,'birth':5,'attrs':0};self.next_inode+=1
        return path
    def event(self,name,*args):
        self.calls.append((name,*args))
        if self.hook is not None:self.hook(self,name,*args)
    def info(self,node,opened=False):
        mode=(stat.S_IFDIR|0o755) if node['kind']=='directory' else (stat.S_IFLNK|0o777 if node['kind']=='link' else stat.S_IFREG|0o644)
        mode=node.get('opened_mode' if opened else 'named_mode',mode)
        return SimpleNamespace(st_mode=mode,st_dev=7,st_ino=node['inode'],st_nlink=node['links'],st_size=0 if node['kind']=='directory' else len(node['bytes']),
            st_mtime_ns=node['mtime'],st_ctime_ns=node['ctime'] if opened or not self.windows else node['birth'],st_birthtime_ns=node['birth'],
            st_file_attributes=node['attrs'],st_reparse_tag=0xA000000C if node['attrs']&0x400 else 0)
    def lstat(self,path):self.event('lstat',path);return self.info(self.nodes[path])
    def names(self,path,maximum):
        self.event('names',path)
        return tuple(row.name for row in self.nodes if row.parent==path and row!=path)
    def open_read(self,path):
        self.event('open_read',path);fd=self.next_fd;self.next_fd+=1;self.handles[fd]={'node':self.nodes[path],'path':path,'offset':0};return fd
    def fstat(self,fd):self.event('fstat',fd);return self.info(self.handles[fd]['node'],True)
    def read(self,fd,count):
        self.event('read',fd,count);entry=self.handles[fd];offset=entry['offset'];part=entry['node']['bytes'][offset:offset+count];entry['offset']+=len(part);return part
    def close(self,fd):
        self.closed.append(fd);self.event('close',fd);del self.handles[fd]
    def expected(self):return {str(path.relative_to(ROOT)).replace('\\','/'):{'bytes':len(node['bytes']),'sha256':'sha256:'+hashlib.sha256(node['bytes']).hexdigest()}
        for path,node in self.nodes.items() if node['kind']=='file'}

def reject(io,expected=None,windows=None):
    try:m.verify_sdk_tree(ROOT,io.expected() if expected is None else expected,_io=io,_windows=io.windows if windows is None else windows)
    except BaseException as error:return error
    raise AssertionError('negative IO fixture accepted')

def basic(windows=False):
    io=MemoryIO(windows);io.file('a.bin',b'alpha');io.file('pkg/b.bin',b'beta');io.file('pkg/empty.bin',b'');return io

def assert_closed(io):assert not io.handles and len(io.closed)==len(set(io.closed))

old_scope={'basic':basic}

def test_positive_linear():
    io=basic();io.directory(ROOT/'allowed-empty-directory');expected=io.expected()
    result=m.verify_sdk_tree(ROOT,expected,_io=io,_windows=False)
    assert result['files']==expected and result['file_count']==3 and result['all_opened_file_descriptors_closed'] is True
    assert result['operation_counts']['open_read']==result['operation_counts']['close']==3
    # Ancestors are only pre/post, not repeated once per member.
    for ancestor in ROOT.parents:assert sum(name=='lstat' and args[0]==ancestor for name,*args in io.calls)==2
    assert_closed(io)

def test_windows_method_ctime():
    io=basic(True);result=m.verify_sdk_tree(ROOT,io.expected(),_io=io,_windows=True)
    assert result['file_count']==3;assert_closed(io)

def test_ancestor_reparse():
    io=basic();io.nodes[ROOT.parent]['attrs']=0x400;error=reject(io)
    assert not io.closed and not io.handles and 'reparse' in str(error)

def test_subtree_and_leaf_reparse():
    for path in (ROOT/'pkg',ROOT/'a.bin'):
        io=basic();expected=io.expected();io.nodes[path]['attrs']=0x400
        reject(io,expected);assert_closed(io)

def test_hardlink_and_open_substitution():
    io=basic();expected=io.expected();io.nodes[ROOT/'a.bin']['links']=2;reject(io,expected);assert_closed(io)
    io=basic();expected=io.expected()
    def mutate(fs,op,*args):
        if op=='open_read' and args[0]==ROOT/'a.bin':fs.nodes[args[0]]['links']=2
    io.hook=mutate;reject(io,expected);assert_closed(io)

def test_foreign_opened_identity():
    io=basic();expected=io.expected()
    def mutate(fs,op,*args):
        if op=='open_read' and args[0]==ROOT/'a.bin':fs.nodes[args[0]]['inode']+=1000
    io.hook=mutate;reject(io,expected);assert_closed(io)

def test_changed_byte():
    io=basic();expected=io.expected();io.nodes[ROOT/'a.bin']['bytes']=b'ALPHA';reject(io,expected);assert_closed(io)

def test_extra_and_missing_file():
    io=basic();expected=io.expected();io.file('added.bin',b'x');reject(io,expected);assert_closed(io)
    io=basic();expected=io.expected();del io.nodes[ROOT/'a.bin'];reject(io,expected);assert_closed(io)

def test_opened_read_mutation():
    io=basic(True);expected=io.expected();once=False
    def mutate(fs,op,*args):
        nonlocal once
        if op=='read' and not once:
            once=True;node=fs.handles[args[0]]['node'];node['mtime']+=1;node['ctime']+=1
    io.hook=mutate;reject(io,expected);assert_closed(io)

def test_named_replacement_after_close():
    io=basic();expected=io.expected();once=False
    def mutate(fs,op,*args):
        nonlocal once
        if op=='close' and not once:
            once=True;path=fs.handles[args[0]]['path'];fs.nodes[path]=dict(fs.nodes[path],inode=9999)
    io.hook=mutate;reject(io,expected);assert_closed(io)

def test_added_during_scan_and_dir_swap():
    for change in ('added','directory'):
        io=basic();expected=io.expected();once=False
        def mutate(fs,op,*args):
            nonlocal once
            if op=='close' and not once:
                once=True
                if change=='added':fs.file('late.bin',b'late');fs.nodes[ROOT]['mtime']+=1
                else:fs.nodes[ROOT/'pkg']['inode']+=1000
        io.hook=mutate;reject(io,expected);assert_closed(io)

def test_change_earlier_file_later():
    io=basic();expected=io.expected()
    def mutate(fs,op,*args):
        if op=='open_read' and args[0]==ROOT/'pkg/b.bin':fs.nodes[ROOT/'a.bin']['mtime']+=1
    io.hook=mutate;reject(io,expected);assert_closed(io)

def test_short_read():
    io=basic();expected=io.expected();actual=io.read
    io.read=lambda fd,count:b''
    reject(io,expected);assert_closed(io)

def test_close_failures():
    for corrupt in (False,True):
        io=basic();expected=io.expected()
        if corrupt:io.nodes[ROOT/'a.bin']['bytes']=b'ALPHA'
        def fail_close(fd):io.closed.append(fd);raise OSError('SYNTHETIC CLOSE FAILURE')
        io.close=fail_close;error=reject(io,expected)
        assert len(io.closed)==1
        if corrupt:assert isinstance(error,BaseExceptionGroup) and len(error.exceptions)==2
        else:assert isinstance(error,OSError)

def test_bad_manifest():
    for name in ('../escape','/absolute','a//b','a/../b','C:escape','a\\b'):
        io=basic();expected={name:{'bytes':0,'sha256':'sha256:'+hashlib.sha256(b'').hexdigest()}}
        reject(io,expected);assert not io.calls

def test_measured_executable_mode_variance():
    io=basic(True);path=ROOT/'a.bin';node=io.nodes[path]
    node.update(named_mode=33279,opened_mode=33206)
    result=m.verify_sdk_tree(ROOT,io.expected(),_io=io,_windows=True)
    assert result['file_count']==3;assert_closed(io)

def test_real_filetype_and_identity_variance():
    for mutation in ('type','inode','birth','mtime'):
        io=basic(True);expected=io.expected()
        def mutate(fs,op,*args):
            if op=='open_read' and args[0]==ROOT/'a.bin':
                node=fs.nodes[args[0]]
                if mutation=='type':node['opened_mode']=stat.S_IFDIR|0o666
                elif mutation=='inode':node['inode']+=100
                elif mutation=='birth':node['birth']+=100
                else:node['mtime']+=100
        io.hook=mutate;reject(io,expected);assert_closed(io)

def test_method_specific_mode_drift():
    for method in ('named','opened'):
        io=basic(True);expected=io.expected();once=False
        def mutate(fs,op,*args):
            nonlocal once
            if op=='read' and not once:
                once=True;node=fs.handles[args[0]]['node'];node[method+'_mode']=stat.S_IFREG|0o444
        io.hook=mutate;reject(io,expected);assert_closed(io)

def test_directory_and_ancestor_mode_drift():
    for path in (ROOT/'pkg',ROOT.parent):
        io=basic(True);expected=io.expected();once=False
        def mutate(fs,op,*args):
            nonlocal once
            if op=='close' and not once:
                once=True;fs.nodes[path]['named_mode']=stat.S_IFDIR|0o444
        io.hook=mutate;reject(io,expected);assert_closed(io)

def test_context_for_mismatch():
    io=basic(True);expected=io.expected()
    def mutate(fs,op,*args):
        if op=='open_read' and args[0]==ROOT/'a.bin':fs.nodes[args[0]]['inode']+=100
    io.hook=mutate;error=reject(io,expected);assert_closed(io)
    note=json.loads(error.__notes__[0].split('=',1)[1])
    assert note['relative_file']=='a.bin' and note['operation_counts']['open_read']==1
    assert note['operation_counts']['close']==1 and 'named_cross' in str(error) and 'opened_cross' in str(error)

def run_model(io,expected=None,deadline=None,**bounds):
    args=dict(expected_files=expected,maximum_files=8192,maximum_directories=8192,
        maximum_file_bytes=16*1024**2,maximum_total_bytes=64*1024**2,
        deadline_ns=time.monotonic_ns()+10_000_000_000 if deadline is None else deadline,_io=io,_windows=io.windows)
    args.update(bounds)
    return scope['_snapshot_regular_file_tree'](root,**args)

class TestGenericTreeBounds(unittest.TestCase):
    def test_snapshot_without_prior_manifest_and_empty_tree(self):
            io=old_scope['basic']();expected=io.expected()
            self.assertEqual(run_model(io)['files'],expected)
            empty=MemoryIO();result=run_model(empty)
            self.assertEqual(result['files'],{});self.assertEqual(result['file_count'],0)
            self.assertEqual(run_model(MemoryIO(),expected={})['files'],{})

    def test_bounds_enforced_before_or_during_initial_inventory_before_open(self):
            for kw in ({'maximum_files':0},{'maximum_directories':8193},{'maximum_file_bytes':16*1024**2+1},
                       {'maximum_total_bytes':256*1024**2+1},{'maximum_files':True}):
                io=old_scope['basic']()
                with self.assertRaises(scope['_RegularTreeReadError']):run_model(io,**kw)
                self.assertEqual(io.calls,[])
            for kw in ({'maximum_files':1},{'maximum_directories':1},{'maximum_file_bytes':1},{'maximum_total_bytes':1}):
                io=old_scope['basic']()
                with self.assertRaises(scope['_RegularTreeReadError']):run_model(io,**kw)
                self.assertFalse(io.handles);self.assertFalse(io.closed)

    def test_case_alias_and_bad_entry_components_rejected(self):
            io=old_scope['basic']();base_names=io.names
            io.names=lambda path,maximum:('a.bin','A.bin','pkg')if path==root else base_names(path,maximum)
            with self.assertRaises(scope['_RegularTreeReadError'])as c:run_model(io)
            self.assertEqual(c.exception.code,'file_tree.case_alias')
            for name in ('..','a/b','a\\b','a:b','a\x00b'):
                io=MemoryIO();io.names=lambda path,maximum:(name,)
                with self.assertRaises(scope['_RegularTreeReadError']):run_model(io)
                self.assertFalse(io.closed)

    def test_original_deadline_fixed_and_expiry_after_open_still_closes_once(self):
            original_time=scope['time'];clock=[100]
            scope['time']=SimpleNamespace(monotonic_ns=lambda:clock[0])
            try:
                io=old_scope['basic']()
                def hook(fs,op,*args):
                    if op=='open_read':clock[0]=200
                io.hook=hook
                with self.assertRaises(BaseException)as c:run_model(io,deadline=150)
                self.assertIn('file_tree.deadline',str(c.exception)+repr(c.exception))
                self.assertEqual(len(io.closed),1);self.assertFalse(io.handles)
                # Same expired absolute integer reused by a second call: no IO.
                fresh=old_scope['basic']()
                with self.assertRaises(scope['_RegularTreeReadError']):run_model(fresh,deadline=150)
                self.assertEqual(fresh.calls,[])
            finally:scope['time']=original_time

    def test_expiry_during_read_closes_and_does_not_report_success(self):
            original_time=scope['time'];clock=[100];scope['time']=SimpleNamespace(monotonic_ns=lambda:clock[0])
            try:
                io=old_scope['basic']();io.hook=lambda fs,op,*args:clock.__setitem__(0,200)if op=='read'else None
                with self.assertRaises(BaseException):run_model(io,deadline=150)
                self.assertEqual(len(io.closed),1);self.assertFalse(io.handles)
            finally:scope['time']=original_time

    def test_original_read_error_and_close_error_are_both_retained(self):
            io=old_scope['basic']();original=OSError('READ_PRIMARY_EXACT');secondary=OSError('CLOSE_SECONDARY_EXACT')
            io.read=lambda *args:(_ for _ in ()).throw(original)
            def fail(fd):io.closed.append(fd);raise secondary
            io.close=fail
            with self.assertRaises(BaseExceptionGroup)as c:run_model(io)
            self.assertIs(c.exception.exceptions[0],original);self.assertIs(c.exception.exceptions[1],secondary)
            self.assertEqual(len(io.closed),1)
