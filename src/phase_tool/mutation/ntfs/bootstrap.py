"""DRAFT fixed native composition, not a request-selected plugin/dispatcher.

The accepted launcher/CPython/image/deployment and immutable wheel NAMESPACE
for the entire import lifetime are trust prerequisites. Hashes and origins below
check consistency WITH that boundary, never authenticate or create it. An
unqualified deployment must not invoke this constructor. No acceptance flag,
environment override, journal, target retry, copy-out or receipt owner is added.
Not installed, imported, executed or qualified.
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import threading
import time
import zipfile
import zipimport

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import _require
from .handoff import ParsedNativeFileCreate,ParsedNativeVersion1,ParsedNativeVersion2


def _normalized_linux_contour(value,keys):
    # Docker serializes its mount map in varying list order. Compare
    # every field, keyed only by each unique Linux destination; never
    # reduce entries to an allowlisted subset of mount properties.
    _require(type(value) is dict and set(value)==keys
        and type(value['mounts']) is list, 'ntfs.accepted_linux_contour_required')
    mounts=value['mounts']
    _require(all(type(row) is dict and type(row.get('Destination')) is str
        and row['Destination'].startswith('/') and type(row.get('RW')) is bool
        for row in mounts), 'ntfs.accepted_linux_contour_required')
    _require(len({row['Destination'] for row in mounts})==len(mounts),
        'ntfs.accepted_linux_contour_required')
    return value|{'mounts':sorted(mounts,key=lambda row:row['Destination'])}

def _native_history_manifest_buffers(raw, expected_digest, *, active_bytes, active_digest):
    """Pure accepted-config correlation; no authentication, I/O or authority.

    Exact V5 pair1.2 or V7 triple1.4 in fixed order. Trust belongs to the
    externally accepted immutable config namespace, never to these hashes.
    """
    _require(type(raw) is bytes and len(raw)<=2*1024**2
        and type(expected_digest) is str and digest_bytes(raw)==expected_digest,
        'ntfs.accepted_history_binding_mismatch')
    value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
    _require(type(value) is dict and canonical_bytes(value)==raw
        and set(value)=={'history_manifest_set_version','manifests'}
        and type(value['history_manifest_set_version']) is str
        and value['history_manifest_set_version'] in {'1.0','1.1'}
        and type(value['manifests']) is list,
        'ntfs.accepted_history_shape')
    roles=('file_create.v1','publish_new_version.v1')
    generation='1.2'
    if value['history_manifest_set_version']=='1.1':
        roles+=('file_create.v2',)
        generation='1.4'
    _require(len(value['manifests'])==len(roles),
        'ntfs.accepted_history_shape')
    buffers=[]
    for role,row in zip(roles,value['manifests'],strict=True):
        _require(type(row) is dict and set(row)=={'manifest_base64','manifest_digest'}
            and type(row['manifest_base64']) is str and type(row['manifest_digest']) is str
            and re.fullmatch('sha256:[0-9a-f]{64}',row['manifest_digest']) is not None,
            'ntfs.accepted_history_shape')
        try:leaf=base64.b64decode(row['manifest_base64'],validate=True)
        except (ValueError,UnicodeError) as error:
            raise PhaseError('ntfs.accepted_history_shape') from error
        _require(base64.b64encode(leaf).decode('ascii')==row['manifest_base64']
            and digest_bytes(leaf)==row['manifest_digest'],
            'ntfs.accepted_history_binding_mismatch')
        manifest=parse_json_bytes(leaf,maximum_bytes=2*1024**2)
        _require(type(manifest) is dict and canonical_bytes(manifest)==leaf
            and manifest.get('native_read_installation_version')==generation
            and type(manifest.get('contract')) is dict and manifest['contract'].get('id')==role,
            'ntfs.accepted_history_shape')
        buffers.append((leaf,row['manifest_digest']))
    _require(type(active_bytes) is bytes and type(active_digest) is str
        and digest_bytes(active_bytes)==active_digest
        and sum(leaf==active_bytes and sha==active_digest for leaf,sha in buffers)==1,
        'ntfs.accepted_history_binding_mismatch')
    return tuple(buffers)


def _native_experimental_history_buffers(raw, expected_digest, *, active_bytes, active_digest):
    """Three accepted per-run read expectations, never an evidence-derived index.

    The fixed experiment is File1 -> Version1 -> Version1. Every invocation
    retains its single active admission; companion bytes grant no dispatch.
    Historical config1.0/1.1 and their manifest sets remain unchanged.
    """
    _require(type(raw) is bytes and len(raw)<=2*1024**2
        and type(expected_digest) is str and digest_bytes(raw)==expected_digest,
        'ntfs.accepted_history_binding_mismatch')
    value=parse_json_bytes(raw,maximum_bytes=2*1024**2)
    _require(type(value) is dict and canonical_bytes(value)==raw
        and set(value)=={'history_manifest_set_version','manifests'}
        and value['history_manifest_set_version']=='1.2'
        and type(value['manifests']) is list and len(value['manifests'])==3,
        'ntfs.accepted_history_shape')
    roles=(('file_create.v1','1.1'),('publish_new_version.v1','1.2'),
        ('publish_new_version.v1','1.2'))
    buffers=[];runs=set()
    for row,(role,generation) in zip(value['manifests'],roles,strict=True):
        _require(type(row) is dict and set(row)=={'manifest_base64','manifest_digest',
            'experimental_admission_base64','experimental_admission_digest'},
            'ntfs.accepted_history_shape')
        decoded=[]
        for stem,limit in (('manifest',2*1024**2),('experimental_admission',32768)):
            encoded,sha=row[stem+'_base64'],row[stem+'_digest']
            _require(type(encoded) is str and type(sha) is str
                and re.fullmatch('sha256:[0-9a-f]{64}',sha) is not None,
                'ntfs.accepted_history_shape')
            try:leaf=base64.b64decode(encoded,validate=True)
            except (ValueError,UnicodeError) as error:
                raise PhaseError('ntfs.accepted_history_shape') from error
            _require(len(leaf)<=limit and base64.b64encode(leaf).decode('ascii')==encoded
                and digest_bytes(leaf)==sha,'ntfs.accepted_history_binding_mismatch')
            doc=parse_json_bytes(leaf,maximum_bytes=limit)
            _require(type(doc) is dict and canonical_bytes(doc)==leaf,
                'ntfs.accepted_history_shape')
            decoded.append((leaf,sha,doc))
        manifest,admission=(part[2] for part in decoded)
        _require(manifest.get('native_read_installation_version')==generation
            and type(manifest.get('contract')) is dict
            and manifest['contract'].get('id')==role
            and admission.get('contract')==manifest['contract']
            and type(admission.get('run_id')) is str and admission['run_id'] not in runs,
            'ntfs.accepted_history_shape')
        runs.add(admission['run_id'])
        buffers.append((decoded[0][0],decoded[0][1],decoded[1][0],decoded[1][1]))
    _require(type(active_bytes) is bytes and type(active_digest) is str
        and digest_bytes(active_bytes)==active_digest
        and sum(leaf==active_bytes and sha==active_digest for leaf,sha,_,_ in buffers)==1,
        'ntfs.accepted_history_binding_mismatch')
    return tuple(buffers)


def _accepted_launch_history(config, manifest_bytes, manifest_digest):
    """Closed config1.0/1.1 preserved; config1.2 is a separate experiment."""
    fields={'native_launch_version','phase_wheel','phase_wheel_digest',
        'dependency_file_digests','windows_launcher','linux_launcher','docker_executable',
        'core_container_id','reader_container_id','image_digest','linux_python',
        'expected_linux_contours','artifact_graph'}
    _require(type(config) is dict and type(config.get('native_launch_version')) is str,
        'ntfs.accepted_launch_shape')
    version=config['native_launch_version']
    if version=='1.0':
        _require(set(config)==fields,'ntfs.accepted_launch_shape')
        return None,None
    _require(version in {'1.1','1.2'} and set(config)==fields|{
        'history_manifest_set_base64','history_manifest_set_digest'}
        and type(config['history_manifest_set_base64']) is str,
        'ntfs.accepted_launch_shape')
    try:raw=base64.b64decode(config['history_manifest_set_base64'],validate=True)
    except (ValueError,UnicodeError) as error:
        raise PhaseError('ntfs.accepted_history_shape') from error
    _require(base64.b64encode(raw).decode('ascii')==config['history_manifest_set_base64'],
        'ntfs.accepted_history_shape')
    digest=config['history_manifest_set_digest']
    parser=(_native_experimental_history_buffers if version=='1.2' else
        _native_history_manifest_buffers)
    parser(raw,digest,active_bytes=manifest_bytes,active_digest=manifest_digest)
    return raw,digest


def _original_query_request(launch,action,digest):
    """Pure request composition; the accepted launcher still owns all trust."""
    query={'native_original_query_version':'1.0','action':action,'run_id':launch.run_id,
        'intent_digest':digest,'operation_nonce':launch.operation_nonce,'channel_id':launch.channel_id,
        'installation_digest':launch.installation_digest}
    request=launch.invocation['request']
    if action=='read_executing' and type(request) is dict and (
            'native_version1_publication_request_version' in request):
        _require(launch._version1 and set(request)=={'operation',
            'native_version1_publication_request_version','source_locator','target_locator',
            'request_id','expected_current_digest','expected_digest'}
            and request['operation']=='execute' and request['native_version1_publication_request_version']=='1.0'
            and type(request['source_locator']) is str,'ntfs.fixed_native_request_required')
        query['native_original_query_version']='1.2'
        query['version1_publication_request']={key:request[key] for key in (
            'request_id','target_locator','expected_current_digest','expected_digest')}
    elif action=='read_executing' and not launch._version1 and not launch._file2 and not launch._version2 and not getattr(launch,'_bundle',False) and type(request) is dict and (
            'native_file_publication_request_version' in request):
        _require(set(request)=={'operation','native_file_publication_request_version','source_locator',
            'target_locator','request_id','expected_digest'}
            and request['operation']=='execute' and request['native_file_publication_request_version']=='1.0'
            and type(request['source_locator']) is str,'ntfs.fixed_native_request_required')
        query['native_original_query_version']='1.1'
        query['publication_request']={key:request[key] for key in ('request_id','target_locator','expected_digest')}
    from .original_endpoint import _original_query_publication,_original_query_version1_publication
    if _original_query_version1_publication(query) is None:
        _original_query_publication(query)  # Exact generation/shape; never downgrade.
    return query


class _NativeAcceptedLaunch:
    """One invocation from the fixed trusted launcher, never from operation JSON.

    Static config bytes/expected hashes come from the accepted installation
    OUTSIDE requests and original intents. The corresponding fixed Linux
    launcher has the SAME manifest/registry and accepted source wheel. Both RO
    and RW roles use that installed composition; this class never copies files
    into a running container or assumes docker CLI exit means Linux-exec exit.
    """
    def __init__(self, *, config_bytes, expected_config_digest, manifest_bytes,
                 expected_manifest_digest, invocation_bytes, _inspection_only: bool = False,
                 _experimental_admission_context=None):
        _require(not getattr(self,'_initialization_attempted',False),
            'ntfs.bootstrap_initialization_consumed')
        self._initialization_attempted=True
        _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
        self._inspection_only=_inspection_only
        self._experimental_admission_context=_experimental_admission_context
        _require(type(config_bytes) is bytes and type(manifest_bytes) is bytes
            and type(expected_config_digest) is str and type(expected_manifest_digest) is str
            and digest_bytes(config_bytes)==expected_config_digest
            and digest_bytes(manifest_bytes)==expected_manifest_digest,
            'ntfs.accepted_launch_binding_required')
        config=parse_json_bytes(config_bytes,maximum_bytes=2*1024**2)
        manifest=parse_json_bytes(manifest_bytes,maximum_bytes=2*1024**2)
        invocation=parse_json_bytes(invocation_bytes,maximum_bytes=2*1024**2)
        _require(type(config) is dict and canonical_bytes(config)==config_bytes and canonical_bytes(manifest)==manifest_bytes
            and canonical_bytes(invocation)==invocation_bytes,'ntfs.accepted_launch_shape')
        _require(config.get('native_launch_version')!='1.2'
            or _experimental_admission_context is not None,'ntfs.experimental_admission_required')
        if _experimental_admission_context is not None:
            from .experimental_history import (_ExperimentalHistoryFile1Admission,
                _ExperimentalHistoryVersion1Admission)
            shared=type(_experimental_admission_context) in (
                _ExperimentalHistoryFile1Admission,_ExperimentalHistoryVersion1Admission)
            _require(shared==(config.get('native_launch_version')=='1.2'),
                'ntfs.experimental_admission_scope')
        self._history_manifest_set=_accepted_launch_history(config,manifest_bytes,expected_manifest_digest)
        _require(type(invocation) is dict and set(invocation)=={'run_id','channel_id','operation_nonce','request'}
            and type(invocation['run_id']) is str
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',invocation['run_id']) is not None
            and invocation['run_id'] not in {'.','..'}
            and all(type(invocation[name]) is str and re.fullmatch('[0-9a-f]{32}',invocation[name])
                for name in ('channel_id','operation_nonce')),'ntfs.accepted_invocation_shape')
        _require(type(manifest) is dict and manifest.get('native_read_installation_version') in {'1.1','1.2','1.3','1.4','1.5','1.6','1.7'}
            and type(manifest.get('root_grants')) is list
            and len(manifest['root_grants'])==(2 if manifest['native_read_installation_version']=='1.5' else 1),
            'ntfs.accepted_launch_binding_required')
        if manifest['native_read_installation_version']=='1.6':
            from .experimental_bundle1 import _ExperimentalBundle1Admission
            from .bundle_execution import _BUNDLE1_CONTRACT
            _require(type(_experimental_admission_context) is _ExperimentalBundle1Admission
                and manifest.get('contract')==_BUNDLE1_CONTRACT,'ntfs.experimental_admission_required')
        if manifest['native_read_installation_version']=='1.7':
            from .experimental_bundle2 import _ExperimentalBundle2Admission
            from .bundle_execution import _BUNDLE2_CONTRACT
            _require(type(_experimental_admission_context) is _ExperimentalBundle2Admission
                and manifest.get('contract')==_BUNDLE2_CONTRACT,'ntfs.experimental_admission_required')
        if manifest['native_read_installation_version']=='1.5':
            from .experimental_version2 import _ExperimentalVersion2Admission,_VERSION2_CONTRACT
            from .version2_observation import _version2_grants
            _require(type(_experimental_admission_context) is _ExperimentalVersion2Admission
                and manifest.get('contract')==_VERSION2_CONTRACT,'ntfs.experimental_admission_required')
            _version2_grants(manifest['root_grants'])
        _require(manifest['native_read_installation_version']!='1.4'
            or (self._history_manifest_set[0] is not None
                and type(manifest.get('contract')) is dict
                and manifest['contract'].get('id') in {
                    'file_create.v1','publish_new_version.v1','file_create.v2'}),
            'ntfs.accepted_history_binding_mismatch')
        self._owner=os.getpid(),threading.get_ident()
        self._config_bytes,self._manifest_bytes,self._invocation_bytes=config_bytes,manifest_bytes,invocation_bytes
        self._manifest_digest=expected_manifest_digest
        self._spawn_attempted=False
        self._worker=None
        self._core_spawn_attempted=False
        self._original_query_attempted=False
        self._pipe_created=set()
        self._linux_contours_checked=False
        self._held=[]
        self._finalization_attempted=set()
        if _experimental_admission_context is not None:
            from ...installation import _native_read_binding_for_launch,_resolve_native_history_bindings
            binding=_native_read_binding_for_launch(self)
            if self._history_manifest_set[0] is not None:
                _resolve_native_history_bindings(binding,*self._history_manifest_set)
        self.check_runtime()

    @property
    def history_manifest_set(self):
        return self._history_manifest_set

    @property
    def _config(self):return parse_json_bytes(self._config_bytes,maximum_bytes=2*1024**2)
    @property
    def manifest(self):return parse_json_bytes(self._manifest_bytes,maximum_bytes=2*1024**2)
    @property
    def invocation(self):return parse_json_bytes(self._invocation_bytes,maximum_bytes=2*1024**2)
    @property
    def run_id(self):return self.invocation['run_id']
    @property
    def channel_id(self):return self.invocation['channel_id']
    @property
    def operation_nonce(self):return self.invocation['operation_nonce']
    @property
    def installation_digest(self):return self._manifest_digest
    @property
    def root_grant(self):
        grants=self.root_grants
        _require(len(grants)==1,'ntfs.original_single_root_required')
        return grants[0]

    @property
    def root_grants(self):return self.manifest['root_grants']

    @property
    def _version2(self):
        manifest=self.manifest
        return (manifest['native_read_installation_version']=='1.5'
            and manifest['contract']['id']=='publish_new_version.v2')

    @property
    def _version1(self):
        manifest = self.manifest
        return (manifest['native_read_installation_version'] in {'1.2','1.4'}
            and manifest['contract']['id'] == 'publish_new_version.v1')

    @property
    def _file2(self):
        manifest=self.manifest
        return (manifest['native_read_installation_version'] in {'1.3','1.4'}
            and manifest['contract']['id']=='file_create.v2')

    @property
    def _bundle(self):
        manifest=self.manifest
        from .bundle_execution import _BUNDLE1_CONTRACT,_BUNDLE2_CONTRACT
        return ((manifest['native_read_installation_version']=='1.6' and manifest['contract']==_BUNDLE1_CONTRACT)
            or (manifest['native_read_installation_version']=='1.7' and manifest['contract']==_BUNDLE2_CONTRACT))

    def check_runtime(self):
        _require(self._owner==(os.getpid(),threading.get_ident())
            and sys.flags.isolated and sys.flags.no_site and not sys.flags.optimize
            and sys.dont_write_bytecode and sys.implementation.name=='cpython',
            'ntfs.accepted_cold_runtime_required')
        if os.name=='nt':
            _require(sys.version_info[:3]==(3,12,10),'ntfs.windows_cpython31210_process_required')
        import importlib.machinery
        _require(sys.meta_path==[importlib.machinery.BuiltinImporter,
            importlib.machinery.FrozenImporter,importlib.machinery.PathFinder],
            'ntfs.accepted_standard_importers_required')
        config=self._config
        wheel=Path(config['phase_wheel'])
        _require(wheel.is_absolute() and type(config['phase_wheel_digest']) is str
            and re.fullmatch('sha256:[0-9a-f]{64}',config['phase_wheel_digest']) is not None,
            'ntfs.accepted_wheel_required')
        _require(wheel.stat().st_size<=16*1024**2,'ntfs.accepted_wheel_shape')
        raw=wheel.read_bytes()
        _require(digest_bytes(raw)==config['phase_wheel_digest'],'ntfs.accepted_wheel_mismatch')
        # The qualified immutable namespace is essential: this one rehash is
        # NOT a lifetime immutability check or executable authentication.
        with zipfile.ZipFile(io.BytesIO(raw)) as package:
            entries=package.infolist()
            names=[row.filename for row in entries]
            _require(len(names)==len(set(names)) and all(not name.startswith('/')
                and '\\' not in name and '..' not in name.split('/') for name in names),
                'ntfs.accepted_wheel_shape')
            source={}
            for row in entries:
                _require(not stat.S_ISLNK(row.external_attr>>16),'ntfs.accepted_wheel_shape')
                if not row.filename.startswith('phase_tool/'):continue
                _require(not row.is_dir() and not row.filename.endswith(('.pyc','.pyo','.pyd','.so'))
                    and row.file_size<=2*1024**2,'ntfs.accepted_wheel_shape')
                if row.filename.endswith('.py'):
                    source[row.filename]=package.read(row)
            _require('phase_tool/__init__.py' in source,'ntfs.accepted_wheel_shape')
            for name,module in tuple(sys.modules.items()):
                if name=='phase_tool' or name.startswith('phase_tool.'):
                    spec=getattr(module,'__spec__',None)
                    _require(spec is not None and type(spec.loader) is zipimport.zipimporter,
                        'ntfs.accepted_phase_origin_required')
                    relative=name.replace('.','/')
                    is_package=spec.submodule_search_locations is not None
                    member=relative+('/__init__.py' if is_package else '.py')
                    origin=os.path.normcase(os.path.normpath(str(wheel/member)))
                    _require(member in source and os.path.normcase(os.path.normpath(spec.origin))==origin
                        and spec.loader.get_data(spec.origin)==source[member],
                        'ntfs.accepted_phase_origin_mismatch')
                    if is_package:
                        _require([os.path.normcase(os.path.normpath(p)) for p in module.__path__]
                            ==[os.path.normcase(os.path.normpath(str(wheel/relative)))],
                            'ntfs.accepted_phase_namespace_mismatch')
        # Same complete code graph is bound by the original composition,
        # independent of OS-specific deployment paths/container identity. Config
        # and graph are installation data, never an acceptance/qualification flag.
        from ...canonical import canonical_digest
        graph=config['artifact_graph']
        platform='windows' if os.name=='nt' else 'linux'
        _require(type(graph) is dict and set(graph)=={'artifact_graph_version','phase_wheel_digest',
            'launcher_digest','windows','linux'} and graph['artifact_graph_version']=='1.0'
            and graph['phase_wheel_digest']==config['phase_wheel_digest']
            and canonical_digest(graph)==self.manifest['composition']['artifact_graph_digest'],
            'ntfs.accepted_artifact_graph_mismatch')
        runtime=graph[platform]
        runtime_fields={'python_version','python_executable_digest','runtime_manifest_digest','dependency_file_digests'}
        if platform=='windows':runtime_fields.add('docker_executable_digest')
        _require(type(runtime) is dict and set(runtime)==runtime_fields
            and runtime['python_version']=='.'.join(map(str,sys.version_info[:3]))
            and digest_bytes(Path(sys.executable).read_bytes())==runtime['python_executable_digest']
            and runtime['dependency_file_digests']==config['dependency_file_digests']
            and type(runtime['runtime_manifest_digest']) is str
            and re.fullmatch('sha256:[0-9a-f]{64}',runtime['runtime_manifest_digest']) is not None,
            'ntfs.accepted_artifact_graph_mismatch')
        if platform=='windows':
            _require(digest_bytes(Path(config['docker_executable']).read_bytes())==runtime['docker_executable_digest'],
                'ntfs.accepted_docker_client_mismatch')
        launcher=Path(config['windows_launcher'] if platform=='windows' else config['linux_launcher'])
        _require(digest_bytes(launcher.read_bytes())==graph['launcher_digest'],
            'ntfs.accepted_launcher_mismatch')
        # CPython is an explicit accepted immutable trust root. A stdlib NAME is
        # insufficient: dependency roots must not shadow it from another origin.
        import sysconfig
        stdroot=Path(sysconfig.get_path('stdlib')).resolve()
        sitelibs={Path(sysconfig.get_path(key)).resolve() for key in ('purelib','platlib')}
        dllroot=Path(sys.base_prefix,'DLLs').resolve()
        stdzip={Path(p).absolute() for p in sys.path if type(p) is str and p.endswith('.zip')
            and Path(p).absolute().parent==Path(sys.base_prefix).absolute()}
        _require(type(config['dependency_file_digests']) is dict,'ntfs.accepted_dependency_graph_required')
        for name,module in tuple(sys.modules.items()):
            if name=='__main__' or name=='phase_tool' or name.startswith('phase_tool.'):continue
            if name=='__mp_main__' and module is sys.modules.get('__main__'):continue
            spec=getattr(module,'__spec__',None)
            origin=None if spec is None else spec.origin
            if origin in ('built-in','frozen'):continue
            # CPython typing installs these two documented deprecated aliases.
            if origin is None and name in {'typing.io','typing.re'}:continue
            _require(type(origin) is str,'ntfs.accepted_dependency_origin_required')
            actual=Path(origin).resolve()
            if name.split('.')[0] in sys.stdlib_module_names:
                ordinary=(actual.is_relative_to(stdroot)
                    and not any(actual.is_relative_to(site) for site in sitelibs))
                extension=(platform=='windows' and actual.is_relative_to(dllroot))
                zipped=(type(spec.loader) is zipimport.zipimporter
                    and any(str(Path(origin).absolute()).startswith(str(p)+os.sep) for p in stdzip))
                _require(ordinary or extension or zipped,'ntfs.accepted_stdlib_origin_mismatch')
                continue
            expected=config['dependency_file_digests'].get(origin)
            _require(type(expected) is str and re.fullmatch('sha256:[0-9a-f]{64}',expected)
                and digest_bytes(Path(origin).read_bytes())==expected,
                'ntfs.accepted_dependency_graph_mismatch')

    def _windows_required(self):
        self.check_runtime()
        _require(os.name=='nt','ntfs.fixed_windows_parent_required')

    def _pipe(self,process):
        from .windows_pipe import WindowsPipeFrames
        _require(type(process) is subprocess.Popen and type(process.stdin) is io.FileIO
            and type(process.stdout) is io.FileIO and type(process.stderr) is io.FileIO,
            'ntfs.exact_open_fileio_required')
        _require(id(process) not in self._pipe_created,'ntfs.process_pipe_setup_consumed')
        self._pipe_created.add(id(process))
        # Own fresh streams before lending them. Never change borrowed flags.
        for stream in (process.stdin,process.stdout,process.stderr):os.set_blocking(stream.fileno(),False)
        return WindowsPipeFrames(process.stdout,process.stdin)

    def _spawn(self,args):
        self._windows_required()
        self._check_linux_contours()
        process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            bufsize=0,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
        self._held.append(process)  # Retain actual owner BEFORE later fallible setup.
        return process

    def _linux_command(self,role):
        _require(role in {'core','original','inspect'},'ntfs.fixed_linux_role_required')
        config=self._config
        container=config['core_container_id' if role=='core' else 'reader_container_id']
        _require(type(container) is str and re.fullmatch('[0-9a-f]{64}',container) is not None
            and type(config['image_digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}',config['image_digest'])
            and Path(config['docker_executable']).is_absolute()
            and str(config['linux_python']).startswith('/opt/')
            and str(config['linux_launcher']).startswith('/opt/'), 'ntfs.accepted_linux_contour_required')
        # Fixed accepted launcher verifies the actual same image/runtime/RO mounts
        # and installed artifact graph; inspect metadata alone is insufficient.
        return [config['docker_executable'],'exec','-i',container,config['linux_python'],
            '-I','-S','-B','-u',config['linux_launcher'],role]

    def spawn_core(self):
        _require(not self._inspection_only,'ntfs.inspection_only_operation_forbidden')
        _require(not self._core_spawn_attempted,'ntfs.core_spawn_consumed')
        self._core_spawn_attempted=True
        return self._spawn(self._linux_command('core'))

    def spawn_inspection(self):
        _require(self._inspection_only,'ntfs.fixed_inspection_role_required')
        _require(not self._core_spawn_attempted,'ntfs.core_spawn_consumed')
        self._core_spawn_attempted=True
        # Existing identified RO reader contour; no new container or mount.
        return self._spawn(self._linux_command('inspect'))

    def spawn_worker(self):
        _require(not self._inspection_only,'ntfs.inspection_only_operation_forbidden')
        _require(not self._spawn_attempted,'ntfs.parent_execution_consumed')
        self._spawn_attempted=True
        launcher=self._config['windows_launcher']
        _require(Path(launcher).is_absolute(),'ntfs.accepted_windows_launcher_required')
        self._worker=self._spawn([sys.executable,'-I','-S','-B','-u',launcher,'worker'])
        return self._worker

    def worker_pipe(self,process):
        _require(process is self._worker,'ntfs.owned_creation_process_required')
        return self._pipe(process)

    def send_worker_original(self,pipe,parsed,*,_handshake_deadline_ns=None):
        from .windows_pipe import WindowsPipeFrames
        _require(type(pipe) is WindowsPipeFrames,'ntfs.original_parsed_data_required')
        if self._bundle:
            from .bundle_execution import _bundle_projection_value
            _require(type(_handshake_deadline_ns) is int,'ntfs.bundle_owned_deadline_required')
            pipe.send_frame(canonical_bytes({'native_worker_original_version':'3.0',
                'channel_id':self.channel_id,'projection':_bundle_projection_value(parsed)}),_handshake_deadline_ns)
            return
        if self._file2:
            from .file2_execution import _file2_projection_value
            _require(type(_handshake_deadline_ns) is int,'ntfs.file2_owned_deadline_required')
            pipe.send_frame(canonical_bytes({'native_worker_original_version':'2.0',
                'channel_id':self.channel_id,'projection':_file2_projection_value(parsed)}),_handshake_deadline_ns)
            return
        if self._version1 or self._version2:
            from .original_transfer import original_version1_frames,original_version2_frames
            _require(type(parsed) is (ParsedNativeVersion2 if self._version2 else ParsedNativeVersion1)
                and type(_handshake_deadline_ns) is int,
                'ntfs.version1_owned_deadline_required')
            frames=original_version2_frames if self._version2 else original_version1_frames
            for raw in frames(parsed,channel_id=self.channel_id,leg='worker',query_digest=None):
                pipe.send_frame(raw,_handshake_deadline_ns)
            return
        _require(type(parsed) is ParsedNativeFileCreate,'ntfs.original_parsed_data_required')
        value={'native_worker_original_version':'1.0','channel_id':self.channel_id,'context':parse_json_bytes(parsed.context_bytes),
            'grant':parse_json_bytes(parsed.grant_bytes),'effect':parse_json_bytes(parsed.effect_bytes),
            'content_base64':base64.b64encode(parsed.content_bytes).decode('ascii'),'timestamp':parsed.timestamp}
        pipe.send_frame(canonical_bytes(value),time.perf_counter_ns()+30_000_000_000)

    def finalize_worker(self,process,pipe):
        _require(process is self._worker,'ntfs.owned_creation_process_required')
        self._finalize_exited(process,pipe)

    def _finalize_exited(self,process,pipe):
        from .process_witness import WindowsProcessWitness
        # Called ONLY after the retained witness reported actual exit. Recheck
        # with the same retained creation HANDLE before closing its owner once.
        _require(id(process) not in self._finalization_attempted,'ntfs.process_finalization_consumed')
        self._finalization_attempted.add(id(process))
        fact=WindowsProcessWitness(process).wait_for_exit(0)
        _require(fact['worker_exit_established'] is True,'ntfs.worker_exit_not_established')
        process.returncode=fact['exit_code']  # Actual retained-HANDLE result, not an exit inference.
        errors=[]
        try:
            _require(pipe is not None,'ntfs.process_pipe_finalization_unknown')
            pipe.seal()
        except BaseException as error:errors.append(error)
        for stream in (process.stdin,process.stdout,process.stderr):
            try:
                _require(type(stream) is io.FileIO and not stream.closed,'ntfs.process_stream_owner_changed')
                stream.close()
                _require(stream.closed,'ntfs.worker_finalization_unknown')
            except BaseException as error:errors.append(error)
        try:
            handle=process._handle
            _require(type(handle) is subprocess.Handle and not handle.closed,'ntfs.owned_popen_handle_required')
            handle.Close()
            _require(handle.closed,'ntfs.worker_finalization_unknown')
        except BaseException as error:errors.append(error)
        if errors:
            primary=errors[0]
            for error in errors[1:]:
                try:primary.add_note('Native owner secondary close: '+type(error).__name__)
                except BaseException:pass
            raise primary

    def _query_original(self,action,digest):
        _require(not self._inspection_only,'ntfs.inspection_only_operation_forbidden')
        from .process_witness import WindowsProcessWitness
        self._windows_required()
        _require(not self._original_query_attempted,'ntfs.original_query_consumed')
        self._original_query_attempted=True
        request=_original_query_request(self,action,digest)
        process=self._spawn(self._linux_command('original'))
        witness=pipe=None
        answer=None
        primary=None
        try:
            witness=WindowsProcessWitness(process)
            pipe=self._pipe(process)
            deadline = time.perf_counter_ns()+30_000_000_000
            pipe.send_frame(canonical_bytes(request),deadline)
            if (self._version1 or self._version2) and action == 'read_executing':
                answer = _receive_version1_original(self,pipe,request,deadline,_version2=self._version2)
            else:
                raw,_=pipe.receive_frame(time.perf_counter_ns()+30_000_000_000)
                answer=parse_json_bytes(raw,maximum_bytes=2*1024**2)
            if type(answer) not in (ParsedNativeVersion1,ParsedNativeVersion2):
                _require(type(answer) is dict and set(answer)=={'query','value','required_evidence_reads_finalized'}
                    and answer['query']==request and answer['required_evidence_reads_finalized'] is True
                    and canonical_bytes(answer)==raw,'ntfs.original_query_binding_mismatch')
        except BaseException as error:
            primary=error
        finally:
            try:
                _require(witness is not None,'ntfs.reader_creation_witness_unavailable')
                fact=witness.wait_for_exit(60000)
                _require(fact['worker_exit_established'] is True and fact['exit_code']==0,
                    'ntfs.reader_owner_exit_not_established')
                self._finalize_exited(process,pipe)
            except BaseException as error:
                if primary is None:primary=error
                else:
                    try:primary.add_note('Native reader finalization: '+type(error).__name__)
                    except BaseException:pass
        if primary is not None:raise primary
        self.check_runtime()
        return answer if type(answer) in (ParsedNativeVersion1,ParsedNativeVersion2) else answer['value']

    def read_original(self,intent_digest):
        value=self._query_original('read_executing',intent_digest)
        if self._bundle:
            from .bundle_execution import _bundle_projection_from_value
            return _bundle_projection_from_value(value)
        if self._file2:
            from .file2_execution import _file2_projection_from_value
            return _file2_projection_from_value(value)
        if self._version1 or self._version2:
            _require(type(value) is (ParsedNativeVersion2 if self._version2 else ParsedNativeVersion1),
                'ntfs.original_version_tuple_required')
            return value
        _require(type(value) is dict and set(value)=={'context','grant','effect','content_base64','timestamp'},
            'ntfs.original_query_shape')
        content=base64.b64decode(value['content_base64'],validate=True)
        _require(len(content)<=1024**2 and type(value['timestamp']) is str,
            'mechanism.content_too_large')
        return ParsedNativeFileCreate(canonical_bytes(value['context']),canonical_bytes(value['grant']),
            canonical_bytes(value['effect']),content,value['timestamp'])

    def verify_no_dispatch_original(self,intent_digest):
        value=self._query_original('verify_no_dispatch',intent_digest)
        _require(value=={'original_absent':intent_digest is None,'verified_intent_digest':intent_digest},
            'ntfs.original_query_binding_mismatch')


    def _check_linux_contours(self):
        """Actual identified own deployment; not loaded-code authentication.

        The accepted launcher additionally supplies immutable source/runtime
        qualification. Do not broaden it from this metadata match alone.
        """
        if self._linux_contours_checked:return
        config=self._config
        expected=config['expected_linux_contours']
        keys={'id','image','user','readonly_rootfs','cap_drop','security_options','network_mode',
            'mounts','pids_limit','memory','nano_cpus','running'}
        _require(type(expected) is dict and set(expected)=={'core','original'}
            and config['core_container_id']!=config['reader_container_id'],
            'ntfs.accepted_linux_contour_required')
        template='{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"readonly_rootfs":{{json .HostConfig.ReadonlyRootfs}},"cap_drop":{{json .HostConfig.CapDrop}},"security_options":{{json .HostConfig.SecurityOpt}},"network_mode":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},"pids_limit":{{json .HostConfig.PidsLimit}},"memory":{{json .HostConfig.Memory}},"nano_cpus":{{json .HostConfig.NanoCpus}},"running":{{json .State.Running}}}'
        for role,field in [('core','core_container_id'),('original','reader_container_id')]:
            declared=_normalized_linux_contour(expected[role],keys)
            _require(type(declared) is dict and set(declared)==keys
                and declared['id']==config[field] and declared['image']==config['image_digest']
                and declared['user']=='10001:10001' and declared['readonly_rootfs'] is True
                and declared['network_mode']=='none' and declared['cap_drop']==['ALL']
                and declared['security_options']==['no-new-privileges']
                and declared['pids_limit']==128 and declared['memory']==2*1024**3
                and declared['nano_cpus']==2*10**9 and declared['running'] is True,
                'ntfs.accepted_linux_contour_required')
            if role=='original':
                _require(type(declared['mounts']) is list
                    and all(row['RW'] is False for row in declared['mounts']),
                    'ntfs.original_readonly_contour_required')
            result=subprocess.run([config['docker_executable'],'inspect','--format',template,config[field]],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                timeout=30,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
            _require(len(result.stdout)<=1024**2,'ntfs.accepted_linux_contour_required')
            actual=parse_json_bytes(result.stdout,maximum_bytes=1024**2)
            _require(canonical_bytes(_normalized_linux_contour(actual,keys))==canonical_bytes(declared),'ntfs.accepted_linux_contour_mismatch')
        self._linux_contours_checked=True

def _receive_version1_original(launch,pipe,request,deadline,*,_version2=False):
    from .original_transfer import _Version1OriginalDecoder,_Version2OriginalDecoder
    _require(type(_version2) is bool,'ntfs.original_closed_role_required')
    decoder_type=_Version2OriginalDecoder if _version2 else _Version1OriginalDecoder
    decoder = decoder_type(channel_id=launch.channel_id,leg='reader',
        query_digest=digest_bytes(canonical_bytes(request)),
        expected_context={name:request[name] for name in
            ('run_id','intent_digest','operation_nonce','installation_digest')},
        **({'expected_grants':canonical_bytes(launch.root_grants)} if _version2 else
            {'expected_grant':canonical_bytes(launch.root_grant)}))
    while not decoder.ended:
        raw,_ = pipe.receive_frame(deadline)
        decoder.feed(raw)
    parsed = decoder.finish()
    # A valid end token alone is insufficient. The caller additionally waits
    # on the same retained actual process HANDLE and finalizes all owners.
    pipe._expect_eof(deadline)
    return parsed
