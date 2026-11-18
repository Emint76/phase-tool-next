"""Bounds of CI rollback controller; no installation, networking or CLI execution."""
import importlib.util
import io
import zipfile
from pathlib import Path
import tempfile
from unittest import mock
import pytest

_spec=importlib.util.spec_from_file_location("host_rollback_smoke_bounds",Path(__file__).parents[1]/"scripts/host_rollback_smoke.py")
rollback=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rollback)


def fixture_layout(tmp_path):
    evidence=tmp_path/"evidence";evidence.mkdir();(evidence/"dist").mkdir()
    wheel=evidence/"dist"/rollback.NEW_NAME;wheel.write_bytes(b"synthetic")
    return evidence,wheel


def test_accept_only_fresh_exact_owned_layout(tmp_path):
    evidence,wheel=fixture_layout(tmp_path)
    root,w,runtime=rollback.validate_layout(evidence/"installed-host-rollback",wheel,tmp_path,evidence)
    assert root.parent==evidence and w==wheel and runtime.parent==tmp_path
    assert not root.exists() and not runtime.exists()


def test_existing_runtime_refused_without_mutation(tmp_path):
    evidence,wheel=fixture_layout(tmp_path)
    runtime=tmp_path/"phase-host-rollback-runtime";runtime.mkdir();(runtime/"canary").write_bytes(b"preserved")
    with pytest.raises(RuntimeError):rollback.validate_layout(evidence/"installed-host-rollback",wheel,tmp_path,evidence)
    assert (runtime/"canary").read_bytes()==b"preserved"


def test_wrong_output_child_refused_without_creation(tmp_path):
    evidence,wheel=fixture_layout(tmp_path)
    with pytest.raises(RuntimeError):rollback.validate_layout(evidence/"other",wheel,tmp_path,evidence)
    assert not (evidence/"other").exists()


def test_linked_wheel_refused_without_following(tmp_path):
    evidence,wheel=fixture_layout(tmp_path);real=tmp_path/"reference";real.write_bytes(b"untouched")
    wheel.unlink();wheel.symlink_to(real)
    with pytest.raises(RuntimeError):rollback.validate_layout(evidence/"installed-host-rollback",wheel,tmp_path,evidence)
    assert real.read_bytes()==b"untouched"


def test_snapshot_does_not_suppress_walker_failure(tmp_path):
    def broken(*args,**kwargs):
        kwargs["onerror"](PermissionError("synthetic unavailable directory"))
        return iter(())
    with mock.patch.object(rollback.os,"walk",side_effect=broken):
        with pytest.raises(PermissionError):rollback.snapshot({"target":tmp_path})


def test_snapshot_rejects_missing_root_and_linked_member(tmp_path):
    with pytest.raises(RuntimeError):rollback.snapshot({"target":tmp_path/"missing"})
    outside=tmp_path/"outside";outside.write_bytes(b"untouched")
    target=tmp_path/"target";target.mkdir();(target/"linked").symlink_to(outside)
    with pytest.raises(RuntimeError):rollback.snapshot({"target":target})
    assert outside.read_bytes()==b"untouched"


def synthetic_inventory(members):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as wheel:
        for name,data in sorted(members.items()):wheel.writestr('phase_tool/'+name,data)
        wheel.writestr('synthetic.dist-info/METADATA',b'not package data')
    return stream.getvalue(),{name:rollback.digest(data) for name,data in members.items()}


def test_candidate_inventory_uses_exact_wheel_membership_as_package_grows():
    members={'__init__.py':b'synthetic module','data/synthetic.json':b'{}'}
    for additions in ({},{'new_module.py':b'added synthetic module'}):
        raw,actual=synthetic_inventory(dict(members,**additions))
        rollback.require_installed_inventory(raw,actual)


def test_candidate_inventory_refuses_extra_missing_or_changed_installed_bytes():
    raw,actual=synthetic_inventory({'__init__.py':b'current','data/synthetic.json':b'{}'})
    stale=dict(actual,**{'old_module.py':rollback.digest(b'stale')})
    missing=dict(actual);del missing['data/synthetic.json']
    changed=dict(actual,**{'__init__.py':rollback.digest(b'changed')})
    for observed in (stale,missing,changed):
        with pytest.raises(RuntimeError,match='installed source differs from exact wheel'):
            rollback.require_installed_inventory(raw,observed)


def test_reference_inventory_keeps_explicit_member_count_pin():
    raw,actual=synthetic_inventory({'__init__.py':b'current','data/synthetic.json':b'{}'})
    rollback.require_installed_inventory(raw,actual,expected_count=2)
    with pytest.raises(RuntimeError,match='reference wheel member count differs from pin'):
        rollback.require_installed_inventory(raw,actual,expected_count=3)
