"""Exercise exact fixed launcher bootstrap up to the first SDK DLL load."""
import ast
import base64
import hashlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path, PureWindowsPath
import re
import stat
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = 'tests/fixtures/native/qualification_fixed_native_c05_first_lock_v1.py.in'
ORDINARY = 'src/phase_tool/data/native/native_phase_candidate_launcher_v1.py.in'
CASE = '51c05d17-7e2b-4c45-9273-15aa66bdab75'
LAUNCHER = PureWindowsPath(r'C:\Users\Gennady\CodexWorkspace\phase-tool-codex-app\work\native-owner3-c05-ci169-51c05d17\install\artifacts\file1\windows\launcher.py')
CONTRACT = {'id':'file_create.v1','version':'1.0.1',
            'package_digest':'sha256:1410ce0916fa9c63d101a0659e55a6ded257f9250b9cd0fb24d22365fea46573'}


def digest(raw):
    return 'sha256:'+hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


class Refused(ValueError):
    pass


class ReachedPinnedLoader(Exception):
    pass


def evaluate(launcher_raw,role,mode):
    sdk = PureWindowsPath(r'C:\c05-model\runtime\windows-sdk\site-packages')
    launcher = LAUNCHER if mode!='foreign_path' else LAUNCHER.with_name('different-launcher.py')
    scope = launcher.with_name('native-input-scope.json')
    policy = launcher.with_name('c05-windows-transport-capture.json')
    loader,dll = (sdk/'win32/_win32sysloader.pyd',sdk/'pywin32_system32/pywintypes312.dll')
    policy_raw = encoded({'schema':'phase.c05.windows-transport-capture/1','case':CASE})
    if mode=='too_large':
        policy_raw = b'x'*16385
    if mode=='bad_policy_case':
        policy_raw = encoded({'schema':'phase.c05.windows-transport-capture/1','case':'foreign'})
    docs = {str(launcher):launcher_raw,str(scope):b'{}',str(policy):policy_raw,
            str(loader):b'known model loader',str(dll):b'known model DLL'}
    sdk_manifest = sdk.parent/'WINDOWS_SDK_MANIFEST_v1.json'
    sdk_rows = {item.relative_to(sdk).as_posix():{'bytes':len(docs[str(item)]),'sha256':digest(docs[str(item)])}
                for item in (loader,dll)}
    docs[str(sdk_manifest)] = encoded({'root':str(sdk),'platform':'win_amd64','python_version':'3.12.10',
                                       'versions':{'pywin32':'312'},'files':sdk_rows})
    deps = {str(item):digest(docs[str(item)]) for item in (loader,dll,scope)}
    if mode!='no_policy':
        deps[str(policy)] = digest(policy_raw) if mode!='bad_policy_hash' else digest(b'not the installed sidecar')
    if mode=='unrelated_extra':
        deps[str(launcher.with_name('arbitrary.json'))] = digest(b'{}')
    graph = dict(deps)
    if mode=='divergent_graph':
        graph[str(policy)] = digest(b'other approved graph')
    if mode=='absent_graph_pin':
        del graph[str(policy)]
    if mode=='missing_file':
        del docs[str(policy)]
    version = '4.0' if mode=='ordinary_startup' else '3.0'
    config = encoded({'native_launch_version':version,'windows_launcher':str(launcher),'dependency_file_digests':deps,
        'artifact_graph':{'launcher_digest':digest(launcher_raw),'windows':{
            'runtime_manifest_digest':digest(docs[str(sdk_manifest)]),'dependency_file_digests':graph}}})
    roots = [str(item) for item in (sdk,sdk/'win32',sdk/'win32/lib')]
    contract = CONTRACT if mode!='foreign_contract' else {**CONTRACT,'version':'2.0'}
    manifest = encoded({'native_read_installation_version':'1.1','contract':contract})
    admission = {'experimental_admission_version':'3.0','fixture_uuid':CASE if mode!='foreign_fixture' else 'foreign'}
    if mode=='foreign_c02_marker':
        admission['c02_current_root_alias'] = True
    outer = {'config_base64':base64.b64encode(config).decode(),'config_digest':digest(config),
             'manifest_base64':base64.b64encode(manifest).decode(),'manifest_digest':digest(manifest),
             'dependency_roots':roots,'native_fixed_startup_version':version}
    if version=='3.0':
        outer['owner_directory_fixture_base64'] = base64.b64encode(encoded(admission)).decode()
    calls = []
    seen = {'named':0,'fd':0}
    directories = {str(path) for member in (loader,dll,sdk_manifest,launcher) for path in member.parents}

    def info(path,*,handle):
        if str(path) not in docs and str(path) not in directories:
            raise FileNotFoundError(str(path))
        inode,mtime,ctime,attrs,links = 7,123,222 if handle else 321,0,1
        if path==policy:
            lane = 'fd' if handle else 'named'
            seen[lane] += 1
            if mode=='reparse' and not handle:
                attrs = 0x400
            if mode=='hardlink' and not handle:
                links = 2
            if mode=='opened_swap' and handle:
                inode = 8
            if mode=='after_name_swap' and not handle and seen[lane]>1:
                inode = 8
            if mode=='after_handle_change' and handle and seen[lane]>1:
                ctime += 1
            if mode=='after_name_change' and not handle and seen[lane]>1:
                ctime += 1
        return SimpleNamespace(st_mode=stat.S_IFDIR if str(path) in directories else stat.S_IFREG,
            st_dev=91,st_ino=inode,st_size=len(docs.get(str(path),b'')),
            st_nlink=links,st_file_attributes=attrs,st_mtime_ns=mtime,st_birthtime_ns=20,st_ctime_ns=ctime)

    class ModelStream(io.BytesIO):
        def fileno(self):
            assert not self.closed
            return 117

        def read(self,size):
            assert size==16385
            calls.append(('bounded_read',size))
            return super().read(size)

        def close(self):
            if not self.closed:
                calls.append(('close',117))
                super().close()
                if mode=='close_failed':
                    raise Refused('same policy stream close failed')
            return None

    class ModelPath(PureWindowsPath):
        def absolute(self):
            return self

        def is_file(self):
            return str(self) in docs

        def is_symlink(self):
            return False

        def read_bytes(self):
            assert self!=policy
            return docs[str(self)]

        def lstat(self):
            return info(self,handle=False)

        def open(self,mode):
            assert self==policy and mode=='rb'
            calls.append(('open',self.name))
            return ModelStream(docs[str(self)])

        stat = lstat

    def fstat(fd):
        assert fd==117
        return info(policy,handle=True)

    def need(value):
        if not value:
            raise Refused('exact fixed bootstrap predicate refused')

    def stop_at_loader(name):
        assert name=='_win32sysloader'
        calls.append(('pinned_loader',name))
        raise ReachedPinnedLoader

    model_sys = SimpleNamespace(version_info=(3,12,10),path=roots,meta_path=[importlib.machinery.BuiltinImporter,
                                importlib.machinery.FrozenImporter,importlib.machinery.PathFinder],modules={})
    env = {'Path':ModelPath,'os':SimpleNamespace(name='nt',fstat=fstat),'sys':model_sys,'need':need,'hashlib':hashlib,
           'base64':base64,'re':re,'json':json,'__file__':str(launcher)}
    names = {'fixed_startup_version','fixed_windows_mcp_sdk_bootstrap','_fixed_c05_sdk_policy'}
    nodes = [node for node in ast.parse(launcher_raw).body if isinstance(node,ast.FunctionDef) and node.name in names]
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-fixed-bootstrap>','exec'),env)
    kwargs = {} if role is None else {'_c05_input_role':role}
    with patch.object(importlib.util,'find_spec',stop_at_loader):
        try:
            env['fixed_windows_mcp_sdk_bootstrap'](outer,config,**kwargs)
        except (Refused,FileNotFoundError):
            return {'result':'refused','calls':calls}
        except ReachedPinnedLoader:
            return {'result':'would_load_pinned_sdk','calls':calls}
    raise AssertionError('model must never load a DLL')


def expected_cases(fixture,ordinary):
    outcomes = {}
    for role in ('publish-input','input-mcp'):
        observed = evaluate(fixture,role,'exact')
        assert observed=={'result':'would_load_pinned_sdk','calls':[
            ('open','c05-windows-transport-capture.json'),('bounded_read',16385),('close',117),
            ('pinned_loader','_win32sysloader')]}
        outcomes[role] = observed
    for prefix,raw in [('ordinary_package',ordinary),('fixture_default',fixture)]:
        assert evaluate(raw,None,'no_policy')['result']=='would_load_pinned_sdk'
        assert evaluate(raw,None,'exact')=={'result':'refused','calls':[]}
        outcomes[prefix] = 'same exact scope-only behaviour'
    for mode in ('no_policy','foreign_path','foreign_fixture','foreign_contract','ordinary_startup','foreign_c02_marker',
                 'divergent_graph','absent_graph_pin','unrelated_extra','reparse','hardlink','too_large','missing_file',
                 'opened_swap','after_name_swap','after_handle_change','after_name_change','close_failed',
                 'bad_policy_hash','bad_policy_case'):
        observed = evaluate(fixture,'input-mcp',mode)
        assert observed['result']=='refused' and not any(row[0]=='pinned_loader' for row in observed['calls']),mode
        outcomes[mode] = observed
    assert evaluate(fixture,'execute-mcp','exact')=={'result':'refused','calls':[]}
    outcomes['foreign_role'] = 'refused'
    return outcomes


def test_c05_fixed_sdk_exact_extra_preserves_ordinary_dependency_guard():
    expected_cases((ROOT/FIXTURE).read_bytes(),(ROOT/ORDINARY).read_bytes())
