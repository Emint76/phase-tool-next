"""Actual local ZIP/zipimport byte checks with a synthetic accepted-launch view.

No cold process, Docker/Phase launch or native authority. Source-only here;
copy into tests/ of the exact composed Linux snapshot before running.
"""
import importlib.machinery
import os
from pathlib import Path
import sys
import threading
from types import MappingProxyType, SimpleNamespace
import zipfile
import zipimport

import pytest

from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap


pytestmark = pytest.mark.skipif(sys.platform!='linux', reason='Linux accepted-wheel component')


def case(tmp_path, monkeypatch):
    wheel, interpreter, launcher = (tmp_path/name for name in ('phase.whl','interpreter-model','launcher-model'))
    interpreter.write_bytes(b'test model only');launcher.write_bytes(b'model launcher')
    with zipfile.ZipFile(wheel,'x') as archive:
        archive.writestr('phase_tool/__init__.py',b'from . import future\n')
        archive.writestr('phase_tool/future.py',b'VALUE = 2\n')
    loader = zipimport.zipimporter(str(wheel))
    package = SimpleNamespace(__spec__=SimpleNamespace(loader=loader,submodule_search_locations=[str(wheel/'phase_tool')],
        origin=str(wheel/'phase_tool'/'__init__.py')),__path__=[str(wheel/'phase_tool')])
    sys_view = SimpleNamespace(flags=SimpleNamespace(isolated=True,no_site=True,optimize=0),
        dont_write_bytecode=True,implementation=sys.implementation,version_info=sys.version_info,
        executable=str(interpreter),base_prefix=sys.base_prefix,stdlib_module_names=sys.stdlib_module_names,path=[],
        meta_path=[importlib.machinery.BuiltinImporter,importlib.machinery.FrozenImporter,importlib.machinery.PathFinder],
        modules={'phase_tool':package})
    monkeypatch.setattr(bootstrap,'sys',sys_view)
    view=object.__new__(bootstrap._NativeAcceptedLaunch)
    view._owner=os.getpid(),threading.get_ident()
    def config():
        pin=digest_bytes(wheel.read_bytes())
        graph={'artifact_graph_version':'1.0','phase_wheel_digest':pin,'launcher_digest':digest_bytes(launcher.read_bytes()),
            'windows':{},'linux':{'python_version':'.'.join(map(str,sys.version_info[:3])),
            'python_executable_digest':digest_bytes(interpreter.read_bytes()),'runtime_manifest_digest':'sha256:'+'a'*64,
            'dependency_file_digests':{}}}
        view._config_bytes=canonical_bytes({'phase_wheel':str(wheel),'phase_wheel_digest':pin,'artifact_graph':graph,
            'linux_launcher':str(launcher),'dependency_file_digests':{}})
        view._manifest_bytes=canonical_bytes({'composition':{'artifact_graph_digest':canonical_digest(graph)}})
    config()
    return SimpleNamespace(view=view,package=package,sys=sys_view,config=config,wheel=wheel,loader=loader,launcher=launcher)


def test_snapshot_publishes_only_after_dependency_audit(tmp_path,monkeypatch):
    c=case(tmp_path,monkeypatch)
    c.sys.modules['types']=SimpleNamespace(__spec__=SimpleNamespace(origin=str(tmp_path/'foreign-types.py'),loader=None))
    with pytest.raises(PhaseError) as exc:
        c.view.check_runtime()
    assert exc.value.code=='ntfs.accepted_stdlib_origin_mismatch'
    assert not hasattr(c.view,'_verified_phase_source_snapshot')
    del c.sys.modules['types']
    c.view.check_runtime()
    raw,table=c.view._verified_phase_source_snapshot
    assert raw==c.wheel.read_bytes() and type(table) is MappingProxyType
    with pytest.raises(TypeError):
        table['phase_tool/future.py']=b'poisoned'


def test_warm_snapshot_still_checks_new_modules_namespace_and_launcher(tmp_path,monkeypatch):
    c=case(tmp_path,monkeypatch);c.view.check_runtime();saved=c.view._verified_phase_source_snapshot
    c.sys.modules['phase_tool.future']=SimpleNamespace(__spec__=SimpleNamespace(loader=c.loader,
        submodule_search_locations=None,origin=str(c.wheel/'phase_tool'/'future.py')))
    c.view.check_runtime()
    assert c.view._verified_phase_source_snapshot is saved
    c.sys.modules['phase_tool.future'].__spec__.origin=str(c.wheel/'phase_tool'/'__init__.py')
    with pytest.raises(PhaseError) as wrong_origin:
        c.view.check_runtime()
    assert wrong_origin.value.code=='ntfs.accepted_phase_origin_mismatch'
    del c.sys.modules['phase_tool.future']
    c.package.__path__.append(str(tmp_path))
    with pytest.raises(PhaseError) as wrong_path:
        c.view.check_runtime()
    assert wrong_path.value.code=='ntfs.accepted_phase_namespace_mismatch'
    c.package.__path__.pop()
    c.launcher.write_bytes(b'changed launcher')
    with pytest.raises(PhaseError) as changed:
        c.view.check_runtime()
    assert changed.value.code=='ntfs.accepted_launcher_mismatch'


def test_warm_raw_bytes_recheck_refuses_different_body_even_if_model_config_changes(tmp_path,monkeypatch):
    c=case(tmp_path,monkeypatch);c.view.check_runtime()
    saved=c.view._verified_phase_source_snapshot
    with c.wheel.open('ab') as stream:
        stream.write(b'changed trailer')
    with pytest.raises(PhaseError) as first:
        c.view.check_runtime()
    assert first.value.code=='ntfs.accepted_wheel_mismatch'
    c.config()  # Stronger synthetic rebind; normal config is immutable.
    with pytest.raises(PhaseError) as exact_bytes:
        c.view.check_runtime()
    assert exact_bytes.value.code=='ntfs.accepted_wheel_mismatch'
    assert c.view._verified_phase_source_snapshot is saved
