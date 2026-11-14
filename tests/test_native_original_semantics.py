"""Pure semantic parity and real ext4 reader controls; never native admission."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
import hashlib
import os
import sys

import pytest
from jsonschema.exceptions import ValidationError

from phase_tool.canonical import canonical_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.installation import qualify_host_authority_roots
from phase_tool.mutation.ntfs import intent as parser, native, reader
from phase_tool.mutation.ntfs.handoff import ParsedNativeFileCreate, ParsedNativeVersion1
from phase_tool.registry import BundledRegistry
from phase_tool import streaming
from .test_native_original_intent import buffers
from .test_native_version1_original import original_fixture, arguments


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
    reason="actual qualified Linux Host fixtures required")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@contextmanager
def _fixture(version1):
    if version1:
        # Real saved Host plan/preconditions, then EXPLICIT synthetic native claims.
        # This does not authenticate an installation or exercise a native worker.
        with original_fixture() as values:
            yield values
    else:
        registry = BundledRegistry.load()
        intent, plan, pre, content, _ = buffers(registry)
        yield registry, intent, plan, pre, content


@pytest.fixture(autouse=True)
def _qualified(tmp_path):
    qualify_host_authority_roots({"original_semantics": tmp_path})


def _controls(args, version1, *, executing=True):
    return parser._parse_original_controls(**{k: v for k, v in args.items() if k != "blob_bytes"},
        _execution_requested=executing, _version1=version1)


def _full(args, version1, *, executing=True):
    if executing:
        method = parser.parse_original_version1 if version1 else parser.parse_original_file_create
    else:
        method = parser.validate_planned_version1_original if version1 else parser.validate_planned_file_create_original
    return method(**args)


def _expected(values, args, version1):
    _, intent, plan, _, content = values
    native_binding = intent["native_binding"]
    context = {"worker_protocol": "phase.native.file-worker", "worker_version": "1.1" if version1 else "1.0",
        "run_id": intent["run_id"], "intent_digest": args["expected_intent_digest"],
        "effect_plan_digest": profile_digest("effect-plan", plan),
        "native_binding_digest": _digest(canonical_bytes(native_binding)),
        "installation_digest": native_binding["installation"]["descriptor_digest"],
        "implementation_artifact_digest": intent["implementation_binding"]["authority"]["provider"]["artifact_digest"],
        "operation_nonce": native_binding["operation_nonce"]}
    return {"context_bytes": canonical_bytes(context),
        "grant_bytes": canonical_bytes(intent["idempotency"]["root_identities"][0]),
        "effect_bytes": canonical_bytes(plan["effects"][0]), "timestamp": intent["created_at"],
        "input_binding": plan["effects"][0]["input_binding"],
        "content_digest": _digest(content), "content_length": len(content)}


@pytest.mark.parametrize("version1", [False, True])
@pytest.mark.parametrize("executing", [False, True])
def test_exact_control_projection_and_legacy_full_or_planned_result(version1, executing):
    with _fixture(version1) as values:
        registry, original, plan, pre, content = values
        original = deepcopy(original)
        original["execution_requested"] = executing
        values = registry, original, plan, pre, content
        args = arguments(*values)
        expected = _expected(values, args, version1)
        projection = _controls(args, version1, executing=executing)
        assert type(projection) is parser._OriginalControlProjection
        assert {field.name: getattr(projection, field.name) for field in fields(projection)} == expected
        assert not isinstance(projection, ParsedNativeFileCreate)
        assert not hasattr(projection, "content_bytes")
        result = _full(args, version1, executing=executing)
        if executing:
            assert type(result) is (ParsedNativeVersion1 if version1 else ParsedNativeFileCreate)
            assert result.content_bytes is content
            assert (result.context_bytes, result.grant_bytes, result.effect_bytes, result.timestamp) == (
                expected["context_bytes"], expected["grant_bytes"], expected["effect_bytes"], expected["timestamp"])
        else:
            assert result is None


@pytest.mark.parametrize("version1", [False, True])
def test_projection_is_frozen_detached_data_without_payload_authority(version1):
    with _fixture(version1) as values:
        args = arguments(*values)
        projection = _controls(args, version1)
        before = tuple(getattr(projection, field.name) for field in fields(projection))
        with pytest.raises(FrozenInstanceError):
            projection.timestamp = "changed"
        values[1]["candidate"]["storage"]["value"]["target_locator"] = "unrelated"
        values[2]["effects"][0]["content_length"] = 999
        assert tuple(getattr(projection, field.name) for field in fields(projection)) == before
        with pytest.raises(PhaseError, match="mechanism.content_too_large"):
            _full(args | {"blob_bytes": projection}, version1)


@pytest.mark.parametrize("version1", [False, True])
@pytest.mark.parametrize("payload", [None, "text", bytearray(b"mutable"), "same_length_corrupt"])
def test_valid_controls_never_substitute_for_actual_blob_bytes(version1, payload):
    with _fixture(version1) as values:
        args = arguments(*values)
        assert _controls(args, version1).content_digest == _digest(values[-1])
        if payload == "same_length_corrupt":
            content = values[-1]
            assert type(content) is bytes and content
            payload = bytes([content[0] ^ 1]) + content[1:]
            assert len(payload) == len(content) and payload != content
        expected = "ntfs.original_content_binding_mismatch" if type(payload) is bytes else "mechanism.content_too_large"
        with pytest.raises(PhaseError) as caught:
            _full(args | {"blob_bytes": payload}, version1)
        assert caught.value.code == expected


@pytest.mark.parametrize("version1", [False, True])
def test_actual_blob_limit_stays_historical_and_before_suffix(version1):
    with _fixture(version1) as values:
        args = arguments(*values)
        maximum = 16 * 1024**2 if version1 else 1024**2
        # Malformed suffix data cannot hide the fixed actual-byte rejection.
        args.update(blob_bytes=b"x" * (maximum + 1), installed_root_grants=b"{}")
        with pytest.raises(PhaseError) as caught:
            _full(args, version1)
        assert caught.value.code == "mechanism.content_too_large"


@pytest.mark.parametrize("version1", [False, True])
def test_prefix_then_actual_bytes_then_suffix_multifault_priority(version1):
    with _fixture(version1) as values:
        args = arguments(*values)
        suffix_bad = args | {"installed_root_grants": b"{}"}
        with pytest.raises(PhaseError) as suffix:
            _full(suffix_bad, version1)
        assert suffix.value.code == "ntfs.original_installed_roots_mismatch"
        with pytest.raises(PhaseError) as payload:
            _full(suffix_bad | {"blob_bytes": b"bad"}, version1)
        assert payload.value.code == "ntfs.original_content_binding_mismatch"
        with pytest.raises(PhaseError) as prefix:
            _full(suffix_bad | {"blob_bytes": b"bad", "expected_intent_digest": "sha256:" + "f" * 64}, version1)
        assert prefix.value.code == "ntfs.original_intent_mismatch"
        # Controls are a DIFFERENT API: they proceed to the suffix without a payload.
        with pytest.raises(PhaseError) as controls:
            _controls(suffix_bad, version1)
        assert controls.value.code == suffix.value.code


@pytest.mark.parametrize("version1", [False, True])
def test_full_and_controls_share_rehashed_idempotency_and_precondition_refusals(version1):
    with _fixture(version1) as values:
        registry, original, plan, pre, content = values
        changed = deepcopy(original)
        changed["idempotency"]["scope_digest"] = "sha256:" + "f" * 64
        args = arguments(registry, changed, plan, pre, content)
        for call in (_full, _controls):
            with pytest.raises(PhaseError) as caught:
                call(args, version1)
            assert caught.value.code == "ntfs.original_idempotency_binding_mismatch"
        changed_pre = deepcopy(pre)
        row = next(x for x in changed_pre if x["phase"] != "post_operation" and x["status"] == "pass")
        # The JSON/schema remains valid. Saved-result recomputation must reject
        # the altered actual value after all outer hashes have been rebound.
        row["actual"] = {"synthetic_corruption": "different saved result"}
        args = arguments(registry, original, plan, changed_pre, content)
        for call in (_full, _controls):
            with pytest.raises(ValueError, match="^result content$"):
                call(args, version1)


@pytest.mark.parametrize("version1", [False, True])
def test_complete_controls_reject_changed_installed_binding_before_any_payload(version1):
    with _fixture(version1) as values:
        args = arguments(*values)
        installed = parse_json_bytes(args["installed_native_binding"])
        installed["operation_nonce"] = "f" * 32
        args.update(installed_native_binding=canonical_bytes(installed), blob_bytes=b"bad")
        for call in (_full, _controls):
            with pytest.raises(PhaseError) as caught:
                call(args, version1)
            assert caught.value.code == "ntfs.original_installation_binding_mismatch"


@pytest.mark.parametrize("version1", [False, True])
def test_declared_content_length_has_no_actual_payload_proof(version1):
    with _fixture(version1) as values:
        registry, original, plan, pre, content = values
        changed = deepcopy(plan)
        changed["effects"][0]["content_length"] = len(content) + 1
        args = arguments(registry, original, changed, pre, content)
        projection = _controls(args, version1)
        assert projection.content_length == len(content) + 1
        assert projection.content_digest == _digest(content)
        with pytest.raises(PhaseError) as caught:
            _full(args, version1)
        assert caught.value.code == "ntfs.original_content_binding_mismatch"


@pytest.mark.parametrize("version1", [False, True])
def test_declared_over_cap_is_not_a_new_size_selector(version1):
    with _fixture(version1) as values:
        registry, original, plan, pre, content = values
        changed = deepcopy(plan)
        changed["effects"][0]["content_length"] = (16 * 1024**2 if version1 else 1024**2) + 1
        with pytest.raises((PhaseError, ValidationError)):
            _controls(arguments(registry, original, changed, pre, content), version1)


@pytest.mark.parametrize("version1", [False, True])
def test_pure_semantics_perform_no_source_snapshot_or_native_io(version1, monkeypatch):
    with _fixture(version1) as values:
        args = arguments(*values)
        def forbidden(*args, **kwargs):
            raise AssertionError("I/O reached from pure original semantics")
        with monkeypatch.context() as patcher:
            patcher.setattr(os, "open", forbidden)
            patcher.setattr(reader, "read_bounded_file", forbidden)
            patcher.setattr(streaming, "_verified_blob_snapshot", forbidden)
            patcher.setattr(native.NativeIO, "__init__", forbidden)
            projection = _controls(args, version1)
            result = _full(args, version1)
        assert result.content_bytes is values[-1]
        assert projection.content_digest == _digest(result.content_bytes)


@pytest.mark.parametrize("version1", [False, True])
@pytest.mark.parametrize("executing", [False, True])
def test_real_ext4_control_read_cannot_hide_missing_frozen_blob(tmp_path, version1, executing):
    with _fixture(version1) as values:
        registry, original, plan, pre, content = values
        root = tmp_path / "evidence"
        root.mkdir()
        qualify_host_authority_roots({"phase_evidence_root": root})
        info = root.stat()
        identity = {"stable_id": "synthetic.control.semantics", "device": info.st_dev, "inode": info.st_ino}
        original = deepcopy(original)
        original["execution_requested"] = executing
        original["native_binding"]["evidence_identity"] = identity
        args = arguments(registry, original, plan, pre, content)
        run = root / ".phase" / "runs" / original["run_id"]
        pre_name = "pre-validator-results.json" if executing else "validator-results.json"
        paths = (run / "intent.json", run / "attachments" / "effect-plan.json",
            run / "attachments" / pre_name, run / "blobs" / _digest(content).removeprefix("sha256:"))
        raw = (args["intent_bytes"], args["plan_bytes"], args["pre_validator_bytes"], content)
        for path, data in zip(paths, raw):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        expected = dict(evidence_root=root, installed_evidence_identity=canonical_bytes(identity),
            registry=registry, run_id=original["run_id"], expected_intent_digest=args["expected_intent_digest"])
        controls = reader._read_original_control_buffers(**expected)
        assert controls == raw[:3]
        projection = _controls(args, version1, executing=executing)
        assert projection.content_digest == _digest(content)
        full_read = reader.read_original_version1_buffers if version1 else reader.read_original_file_create_buffers
        assert full_read(**expected) == raw
        result = _full(args, version1, executing=executing)
        assert result is None if not executing else result.content_bytes == content
        paths[-1].unlink()  # Sole synthetic blob inside this test's disposable root.
        before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        assert reader._read_original_control_buffers(**expected) == controls
        assert _controls(args, version1, executing=executing) == projection
        with pytest.raises(FileNotFoundError):
            full_read(**expected)
        after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        assert after == before
