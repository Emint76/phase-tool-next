from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from phase_tool.application import PhaseApplication
from tests.test_publish_file import arguments, roots, tree

pytestmark = pytest.mark.skipif(os.name != "posix", reason="F01 mutation evidence requires POSIX")


def test_f01_uses_existing_limits_and_has_no_external_generation_dependencies() -> None:
    import ast
    import inspect
    import phase_tool.publish_file as publication
    from phase_tool.freeze import copy_and_hash
    from phase_tool.inspection import _MATERIALIZED_TARGET_LIMITS
    from phase_tool.mutation.exclusive_create import _MAX_CONTENT_BYTES

    assert publication.MAX_BYTES == min(_MAX_CONTENT_BYTES, _MATERIALIZED_TARGET_LIMITS["mechanism.exclusive_create_v1"])
    assert publication.MAX_BYTES <= inspect.signature(copy_and_hash).parameters["maximum_bytes"].default
    parsed = ast.parse(Path(publication.__file__).read_text(encoding="utf-8"))
    external = set()
    for node in ast.walk(parsed):
        if isinstance(node, ast.Import):
            external.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            external.add(node.module)
    assert external == {"__future__", "datetime", "pathlib", "re", "tempfile", "typing", "pydantic"}


def test_all_preparation_stays_isolated_even_when_system_temp_is_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tempfile
    import phase_tool.application as application

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    original = application.TemporaryDirectory
    created = []
    def observe(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory
    monkeypatch.setattr(tempfile, "tempdir", str(paths["target"]))
    monkeypatch.setattr(application, "TemporaryDirectory", observe)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["status"] == "verified", result
    assert not any(path.is_relative_to(paths["target"]) for path in created), created


def test_source_mutation_during_stable_read_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.freeze as freeze

    paths = roots(tmp_path)
    source = paths["source"] / "ready.zip"
    source.write_bytes(b"ready")
    original = freeze.os.fstat
    changed = []
    def mutate(descriptor):
        info = original(descriptor)
        if not changed:
            changed.append(True)
            source.write_bytes(b"changed during capture")
        return info
    monkeypatch.setattr(freeze.os, "fstat", mutate)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["error"] == "freeze.source_changed_during_capture", result
    assert result["status"] == "rejected_before_write"
    assert tree(paths["target"]) == {"canary": b"preserve me"}


def test_expected_digest_success(tmp_path: Path) -> None:
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    digest = "sha256:" + hashlib.sha256(b"ready").hexdigest()
    result = PhaseApplication().publish_file(**(arguments(paths) | {"expected_digest": digest})).payload
    assert result["status"] == "verified", result
    assert result["content_digest"] == digest


def test_core_frozen_blob_tamper_still_prevents_target_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from phase_tool.evidence import EvidenceStore

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    original = EvidenceStore.write_canonical
    changed = []
    def corrupt(store, relative, value):
        returned = original(store, relative, value)
        if relative == "intent.json":
            for blob in store.blob_root.iterdir():
                blob.write_bytes(b"tampered")
                changed.append(blob)
        return returned
    monkeypatch.setattr(EvidenceStore, "write_canonical", corrupt)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert changed
    assert result["success"] is False, result
    assert result["target_verified"] is False
    assert tree(paths["target"]) == {"canary": b"preserve me"}


def test_commit_time_absence_rejects_racing_existing_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import phase_tool.mutation.broker as broker

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    original = broker.execute_exclusive_create
    calls = []
    def race(*args, **kwargs):
        calls.append(True)
        (paths["target"] / "result.bin").write_bytes(b"racer-owned")
        return original(*args, **kwargs)
    monkeypatch.setattr(broker, "execute_exclusive_create", race)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert calls == [True]
    assert result["success"] is False, result
    assert result["target_verified"] is False
    assert tree(paths["target"]) == {"canary": b"preserve me", "result.bin": b"racer-owned"}


@pytest.mark.parametrize("field", ["run_id", "receipt_digest", "intent_digest", "effect_plan_digest", "target_verified"])
def test_execute_inspect_mismatch_never_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    app = PhaseApplication()
    original = app.inspect
    def mismatch(**kwargs):
        response = original(**kwargs)
        response.payload[field] = False if field == "target_verified" else "wrong"
        return response
    monkeypatch.setattr(app, "inspect", mismatch)
    result = app.publish_file(**arguments(paths)).payload
    assert result["status"] == "committed_unverified", result
    assert result["target_verified"] is False
    assert result["receipt_digest"]
    assert result["mutation_attempted"] is True


def test_non_success_terminal_never_promoted_when_envelopes_agree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    app = PhaseApplication()
    execute, inspect = app.run, app.inspect
    def changed_execute(*args, **kwargs):
        response = execute(*args, **kwargs)
        response.payload["terminal_status"] = "committed_unverified"
        return response
    def changed_inspect(**kwargs):
        response = inspect(**kwargs)
        response.payload["terminal_status"] = "committed_unverified"
        return response
    monkeypatch.setattr(app, "run", changed_execute)
    monkeypatch.setattr(app, "inspect", changed_inspect)
    result = app.publish_file(**arguments(paths)).payload
    assert result["status"] == "committed_unverified", result
    assert result["target_verified"] is False


def test_receipt_write_failure_is_indeterminate_not_unexecuted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from phase_tool.core import CoreFaults, PhaseCore

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    original = PhaseCore.run
    def fail(core, request, **kwargs):
        return original(core, request, **(kwargs | {"faults": CoreFaults(fail_receipt_write=True)}))
    monkeypatch.setattr(PhaseCore, "run", fail)
    result = PhaseApplication().publish_file(**arguments(paths)).payload
    assert result["status"] == "indeterminate", result
    assert result["mutation_attempted"] is True
    assert result["target_verified"] is False
    assert result["receipt_digest"] is None
    assert result["intent_digest"]
    assert (paths["target"] / "result.bin").read_bytes() == b"ready"


@pytest.mark.parametrize("failure", ["raised", "unidentified_response_with_cleanup_failure"])
def test_unknown_handoff_does_not_claim_absence_of_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    import phase_tool.publish_file as publication

    paths = roots(tmp_path)
    (paths["source"] / "ready.zip").write_bytes(b"ready")
    app = PhaseApplication()
    def fail(*args, **kwargs):
        if failure == "unidentified_response_with_cleanup_failure":
            return app._failure("execute", OSError("lost handoff result"))
        raise OSError("lost handoff result")
    monkeypatch.setattr(app, "run", fail)
    if failure == "unidentified_response_with_cleanup_failure":
        class CleanupFailure(publication.TemporaryDirectory):
            def __exit__(self, *args):
                super().__exit__(*args)
                raise OSError("cleanup failed too")
        monkeypatch.setattr(publication, "TemporaryDirectory", CleanupFailure)
    result = app.publish_file(**arguments(paths)).payload
    assert result["status"] == "indeterminate", result
    assert result["mutation_attempted"] is None
    assert result["run_id"] == "f01-cli"
    assert result["inspection_required"] is True
