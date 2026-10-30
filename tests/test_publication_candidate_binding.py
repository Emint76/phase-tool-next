"""Literal publication binding regressions on real qualified Linux Host IO.

Unexecuted source at introduction. An injected schedule replaces only the
test's owned preparation candidate immediately before the real Core capture.
No qualifier, validator, broker, effect or capture implementation is replaced.
This is not a native/NTFS qualification or a general adversary timing test.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from phase_tool import core
from phase_tool.application import PhaseApplication
from phase_tool.candidate import encode_structured_input
from phase_tool.installation import _linux_filesystem_type
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes


PAYLOAD = b"Synthetic candidate-binding payload. No scientific data.\n"
CANARY = b"Synthetic unchanged target canary.\n"


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _write_new(path, data):
    with path.open("xb") as output:
        _require(output.write(data) == len(data), "short own observation write")


@contextmanager
def _owned_root(case):
    _require(getattr(shutil.rmtree, "avoids_symlink_attacks", False),
             "secure disposable-root cleanup unavailable")
    parent = Path(tempfile.gettempdir()).resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="phase-candidate-binding-", dir=parent))
    info = root.lstat()
    identity = info.st_dev, info.st_ino
    marker = canonical_bytes({"kind": "phase.candidate-binding.synthetic.1",
                              "case": case, "root_name": root.name,
                              "device": identity[0], "inode": identity[1]})
    _write_new(root / ".owned-case.json", marker)
    try:
        yield root
    finally:
        current = root.lstat()
        _require(root.is_absolute() and root.parent == parent
                 and root.resolve(strict=True) == root
                 and root.name.startswith("phase-candidate-binding-")
                 and stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid()
                 and (current.st_dev, current.st_ino) == identity
                 and (root / ".owned-case.json").read_bytes() == marker,
                 "disposable ownership changed; unsafe cleanup refused")
        shutil.rmtree(root)


def _snapshot(root):
    result = {}
    count = total = 0

    def fail(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        for name in (*dirs, *files):
            path = Path(directory) / name
            info = path.lstat()
            count += 1
            _require(count <= 256 and not stat.S_ISLNK(info.st_mode)
                     and info.st_uid == os.geteuid(), "unsafe own tree member")
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                result[relative] = {"kind": "directory"}
            else:
                _require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024**2,
                         "unexpected own tree object")
                total += info.st_size
                _require(total <= 4 * 1024**2, "own tree bound")
                data = path.read_bytes()
                after = path.lstat()
                _require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                         and len(data) == info.st_size, "observation source changed")
                result[relative] = {"kind": "file", "length": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest()}
    return result


def _copy_owned_tree(source, destination):
    """Export only bounded own synthetic bytes, never follow a link."""
    before = _snapshot(source)
    destination.mkdir(mode=0o700)
    for relative, row in sorted(before.items(), key=lambda item: (len(Path(item[0]).parts), item[0])):
        original = source / relative
        target = destination / relative
        _require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                 "unsafe own export locator")
        if row["kind"] == "directory":
            target.mkdir(mode=0o700)
        else:
            data = original.read_bytes()
            _require(len(data) == row["length"]
                     and hashlib.sha256(data).hexdigest() == row["sha256"],
                     "own export source drift")
            _write_new(target, data)
    _require(_snapshot(source) == before, "own export tree changed")


def _export(root, case, observation):
    value = os.environ.get("EVIDENCE")
    if value is None:
        # Ordinary local developers may run the unit suite in disposable roots.
        # The qualification invocation itself is remote CI and always exports.
        return
    _require("RUNNER_TEMP" in os.environ, "unexpected EVIDENCE authority")
    expected = Path(os.environ["RUNNER_TEMP"]) / "phase-next-evidence"
    base = Path(value)
    _require(base.is_absolute() and base == expected and base.resolve(strict=True) == base,
             "export root outside exact existing CI contour")
    info = base.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and not info.st_mode & 0o022, "unsafe CI observation root")
    family = base / "candidate-binding"
    family.mkdir(mode=0o700, exist_ok=True)
    info = family.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and not info.st_mode & 0o077, "unsafe own observation family")
    destination = family / case
    destination.mkdir(mode=0o700)  # Never overwrite another case or retry.
    raw = canonical_bytes(observation)
    _require(len(raw) <= 128 * 1024, "observation metadata bound")
    _write_new(destination / "observation.json", raw)
    for name in ("source", "target", "evidence"):
        _copy_owned_tree(root / name, destination / name)


def _replace_owned_candidate(path, preparation, replacement):
    path = Path(path)
    _require(path.is_absolute() and path.resolve(strict=True) == path
             and path.is_relative_to(preparation) and path.suffix == ".json",
             "capture did not name the owned generated candidate")
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid(), "unsafe own candidate")
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                 "own candidate changed before injected replacement")
        os.ftruncate(descriptor, 0)
        offset = 0
        while offset < len(replacement):
            count = os.write(descriptor, replacement[offset:])
            _require(count > 0, "injected write made no progress")
            offset += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@unittest.skipUnless(sys.platform.startswith("linux"), "qualified Linux Host component test")
class PublicationCandidateBindingTests(unittest.TestCase):
    def _case(self, kind, version, changed_field):
        case = kind + "-v" + version.replace(".", "-") + "-" + changed_field
        with _owned_root(case) as root:
            for name in ("source", "target", "preparation", "evidence"):
                (root / name).mkdir(mode=0o700)
            source, target, preparation, evidence = [root / name for name in
                ("source", "target", "preparation", "evidence")]
            filesystems = {name: _linux_filesystem_type(root if name == "root" else root / name)
                for name in ("root", "source", "target", "preparation", "evidence")}
            _require(set(filesystems.values()) == {"ext4"},
                     "exact Host/ext4 regression boundary unavailable")
            _write_new(source / "input.bin", PAYLOAD)
            _write_new(target / "canary.bin", CANARY)
            target_before = _snapshot(target)
            requested_target = "requested.bin" if kind == "file" else "requested-bundle"
            other_target = "changed.bin" if kind == "file" else "changed-bundle"
            request_id = "request." + case
            run_id = "binding-" + case
            captured = []
            real_capture = core.capture_structured

            def replace_then_capture(path, *, maximum_bytes):
                _require(not captured, "capture reached more than once")
                path = Path(path)
                _require(path.is_relative_to(preparation), "unexpected capture source")
                initial_bytes = path.read_bytes()
                initial = parse_json_bytes(initial_bytes)
                _require(initial["target_locator"] == requested_target
                         and initial["operation_id"] == request_id
                         and initial["idempotency_key"] == request_id
                         and initial["input_binding"] == "payload",
                         "initial generated candidate differs from literal API")
                replacement = dict(initial)
                if changed_field == "target":
                    replacement["target_locator"] = other_target
                else:
                    _require(changed_field == "request", "unknown injected field")
                    replacement["operation_id"] = "changed." + case
                    replacement["idempotency_key"] = "changed." + case
                replacement_bytes = encode_structured_input(replacement)
                _replace_owned_candidate(path, preparation, replacement_bytes)
                actual = real_capture(path, maximum_bytes=maximum_bytes)
                _require(actual.canonical_bytes == canonical_bytes(replacement)
                         and actual.canonical_bytes != canonical_bytes(initial),
                         "real capture did not consume the injected valid replacement")
                captured.append({"initial": initial, "substituted": replacement,
                    "actual_captured": parse_json_bytes(actual.canonical_bytes),
                    "captured_raw_sha256": hashlib.sha256(actual.captured_bytes).hexdigest(),
                    "captured_candidate_profile_digest": actual.digest,
                    "captured_canonical_length": actual.length})
                return actual

            response = None
            primary = None
            try:
                with patch.object(core, "capture_structured", side_effect=replace_then_capture):
                    arguments = dict(source_root=source, target_root=target,
                        target_locator=requested_target, preparation_root=preparation,
                        evidence_root=evidence, request_id=request_id, run_id=run_id,
                        publication_version=version)
                    application = PhaseApplication()
                    if kind == "file":
                        response = application.publish_file(source_locator="input.bin",
                            expected_digest=digest_bytes(PAYLOAD), **arguments)
                    else:
                        _require(kind == "bundle", "unknown publication kind")
                        response = application.publish_bundle(members=["input.bin"], **arguments)
            except BaseException as error:
                primary = error
            observation = {"observation_version": "1.0", "case": case,
                "kind": kind, "publication_version": version, "changed_field": changed_field,
                "scope": "injected schedule on real Host/ext4 components; not NTFS qualification",
                "filesystems": filesystems,
                "run_id": run_id, "capture_count": len(captured), "captures": captured,
                "target_before": target_before, "target_after": _snapshot(target),
                "canary_unchanged": (target / "canary.bin").read_bytes() == CANARY,
                "source_unchanged": (source / "input.bin").read_bytes() == PAYLOAD,
                "response": response.payload if response is not None else None,
                "response_exit_code": response.exit_code if response is not None else None,
                "raised_type": type(primary).__name__ if primary is not None else None}
            try:
                _export(root, case, observation)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note("Own observation export failed: " + type(error).__name__)
            if primary is not None:
                raise primary
            self.assertEqual(len(captured), 1, "missed candidate capture is not a PASS")
            self.assertTrue(observation["canary_unchanged"])
            self.assertTrue(observation["source_unchanged"])
            # Detect actual effects, including an altered key writing the originally
            # requested target. successFalse alone already occurs after a bad effect.
            self.assertEqual(observation["target_after"], target_before,
                             "literal API candidate changed the domain target tree")
            self.assertFalse(response.payload["success"])
            self.assertIs(response.payload["mutation_attempted"], False)
            self.assertEqual(response.payload["error"], "candidate.expected_content_mismatch")
            self.assertFalse((evidence / ".phase" / "runs" / run_id / "intent.json").exists())

    def test_file_v1_target_only(self):
        self._case("file", "1.0", "target")

    def test_file_v1_request_only(self):
        self._case("file", "1.0", "request")

    def test_file_v2_target_only(self):
        self._case("file", "2.0", "target")

    def test_file_v2_request_only(self):
        self._case("file", "2.0", "request")

    def test_bundle_v1_target_only(self):
        self._case("bundle", "1.0", "target")

    def test_bundle_v1_request_only(self):
        self._case("bundle", "1.0", "request")

    def test_bundle_v2_target_only(self):
        self._case("bundle", "2.0", "target")

    def test_bundle_v2_request_only(self):
        self._case("bundle", "2.0", "request")


@contextmanager
def _boundary_fixture(case):
    with _owned_root("boundary-" + case) as root:
        for name in ("source", "target", "preparation", "evidence"):
            (root / name).mkdir(mode=0o700)
        _require({_linux_filesystem_type(root / name) for name in
                 ("source", "target", "preparation", "evidence")} == {"ext4"},
                 "exact Host/ext4 boundary unavailable")
        _write_new(root / "source/input.bin", PAYLOAD)
        _write_new(root / "target/canary.bin", CANARY)
        candidate = {"operation_id": "boundary." + case,
                     "idempotency_key": "boundary." + case,
                     "input_binding": "payload", "target_locator": "requested.bin"}
        arguments = dict(contract_binding="file_create.v1@1.0.0",
            evidence_root=root / "evidence", run_id="boundary-" + case,
            input_paths={"payload": root / "source/input.bin"},
            root_bindings={"phase_result_root": root / "target"},
            maximum_candidate_bytes=1024)
        yield root, candidate, arguments


@unittest.skipUnless(sys.platform.startswith("linux"), "qualified Linux Host component test")
class CandidateExpectationBoundaryTests(unittest.TestCase):
    def _rejected(self, root, arguments, response, code, *, core_receipt=True):
        self.assertFalse(response.payload["success"])
        self.assertIs(response.payload["mutation_attempted"], False)
        self.assertEqual(response.payload["error"], code)
        self.assertEqual(_snapshot(root / "target"), {"canary.bin": {
            "kind": "file", "length": len(CANARY), "sha256": hashlib.sha256(CANARY).hexdigest()}})
        self.assertEqual((root / "source/input.bin").read_bytes(), PAYLOAD)
        run = root / "evidence/.phase/runs" / arguments["run_id"]
        self.assertFalse((run / "intent.json").exists())
        if core_receipt:
            receipt = parse_json_bytes((run / "receipt.json").read_bytes())
            self.assertEqual(receipt["terminal_status"], "rejected")
            self.assertEqual(receipt["execution_disposition"], "not_executed")
            self.assertIs(receipt["mutation_attempted"], False)
            self.assertEqual(receipt["effect_receipts"], [])
            self.assertIsNone(receipt["evidence"]["intent_digest"])
            self.assertEqual(receipt["blockers"], [code])
        else:
            self.assertFalse(run.exists())

    def test_expected_bytes_reject_mutable_subclass_and_over_bound(self):
        class BytesSubclass(bytes):
            pass
        for index, make in enumerate((lambda value: value.decode(), bytearray, memoryview,
                                      BytesSubclass, lambda value: False,
                                      lambda value: b"x" * 1025)):
            with self.subTest(index=index), _boundary_fixture("invalid-" + str(index)) as (root, candidate, arguments):
                encoded = encode_structured_input(candidate)
                path = root / "preparation/candidate.json"
                _write_new(path, encoded)
                response = PhaseApplication().run("execute", candidate_path=path,
                    _expected_candidate_bytes=make(encoded), **arguments)
                self._rejected(root, arguments, response, "candidate.invalid_expected_content")

    def test_path_without_expectation_preserves_capture_semantics(self):
        with _boundary_fixture("raw-path") as (root, candidate, arguments):
            candidate["target_locator"] = "direct.bin"
            path = root / "preparation/candidate.json"
            _write_new(path, encode_structured_input(candidate))
            response = PhaseApplication().run("execute", candidate_path=path, **arguments)
            self.assertTrue(response.payload["success"], response.payload)
            self.assertEqual((root / "target/direct.bin").read_bytes(), PAYLOAD)
            self.assertEqual((root / "target/canary.bin").read_bytes(), CANARY)

    def test_canonical_expectation_accepts_raw_formatting(self):
        with _boundary_fixture("formatting") as (root, candidate, arguments):
            path = root / "preparation/candidate.json"
            raw = (" \n" + json.dumps(candidate, indent=2) + "\n").encode()
            encoded = encode_structured_input(candidate)
            self.assertNotEqual(raw, encoded)
            _write_new(path, raw)
            response = PhaseApplication().run("execute", candidate_path=path,
                _expected_candidate_bytes=encoded, **arguments)
            self.assertTrue(response.payload["success"], response.payload)
            self.assertEqual((root / "target/requested.bin").read_bytes(), PAYLOAD)
            self.assertEqual((root / "target/canary.bin").read_bytes(), CANARY)

    def test_value_substitution_rejected_before_effect(self):
        from phase_tool import application as application_module
        with _boundary_fixture("value-target") as (root, candidate, arguments):
            real_capture = core.capture_structured
            real_directory = application_module.TemporaryDirectory
            captured = []
            def owned_directory(*, prefix):
                self.assertEqual(prefix, "phase-candidate-")
                return real_directory(prefix=prefix, dir=root / "preparation")
            def replace_then_capture(path, *, maximum_bytes):
                self.assertFalse(captured)
                self.assertEqual(parse_json_bytes(Path(path).read_bytes()), candidate)
                replacement = dict(candidate, target_locator="changed.bin")
                _replace_owned_candidate(path, root / "preparation", encode_structured_input(replacement))
                actual = real_capture(path, maximum_bytes=maximum_bytes)
                self.assertEqual(actual.canonical_bytes, canonical_bytes(replacement))
                captured.append(replacement)
                return actual
            with patch.object(application_module, "TemporaryDirectory", side_effect=owned_directory), \
                 patch.object(core, "capture_structured", side_effect=replace_then_capture):
                response = PhaseApplication().run("execute", candidate=candidate, **arguments)
            self.assertEqual(len(captured), 1)
            self._rejected(root, arguments, response, "candidate.expected_content_mismatch")

    def test_value_conflicting_expectation_rejected_before_materialization(self):
        from phase_tool import application as application_module
        with _boundary_fixture("value-conflict") as (root, candidate, arguments):
            different = encode_structured_input(dict(candidate, target_locator="changed.bin"))
            with patch.object(application_module, "TemporaryDirectory",
                    side_effect=AssertionError("conflicting value must not materialize")) as materialize:
                response = PhaseApplication().run("execute", candidate=candidate,
                    _expected_candidate_bytes=different, **arguments)
            materialize.assert_not_called()
            self._rejected(root, arguments, response, "candidate.expected_content_mismatch", core_receipt=False)
