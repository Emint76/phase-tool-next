import base64
import json
from pathlib import Path
import runpy
import unittest

from phase_tool.errors import PhaseError


SCRIPT = (Path(__file__).resolve().parents[1] / "integrations/hermes/skills"
          / "phase-mutation-preparation/scripts/prepare_native_phase_mutation.py")
prepare = runpy.run_path(str(SCRIPT))["prepare_native_mutations"]
DIGEST = "sha256:" + "a" * 64


def approved(role, number, contract):
    case = f"12345678-abcd-4def-8123-{number:012}"
    components = ["Phase-NTFS-Qualification", case, "results"]
    config = dict.fromkeys((
        "phase_wheel", "dependency_file_digests", "windows_launcher", "linux_launcher",
        "docker_executable", "core_container_id", "reader_container_id", "image_digest",
        "linux_python", "expected_linux_contours",
    ))
    config.update(native_launch_version="1.0", phase_wheel_digest=DIGEST,
                  windows_launcher=f"C:/fixed/{role}/launcher.py",
                  linux_launcher=f"/fixed/{role}/launcher.py",
                  artifact_graph={"phase_wheel_digest": DIGEST})
    return {
        "contract": contract, "windows_root": "S:\\" + "\\".join(components),
        "root_grant": {
            "root_binding": "phase_result_root", "device": "\\Device\\HarddiskVolume1",
            "volume_guid": "\\\\?\\volume{12345678-abcd-4def-8123-123456789abc}\\",
            "volume_serial32": 123, "components": components,
            "native_identity": {"volume_serial": 123, "file_id": f"{number:032x}"},
        },
        "evidence_root": f"/qualification/evidence/{role}",
        "evidence_identity": {"stable_id": role + "-evidence", "device": 5, "inode": number},
        "preparation_root": f"/qualification/preparation/{role}",
        "preparation_identity": {"stable_id": role + "-prep", "device": 7, "inode": number},
        "launch": {platform: {"config": config.copy(), "dependency_roots": []}
                   for platform in ("windows", "linux")},
    }


def intent(role, scope, members=None):
    return {
        "scope": role, "contract": scope["contract"], "run_id": "run-" + role,
        "target_locator": "result-" + role, "payload_digest": DIGEST,
        "payload_length": 3, "members": members,
    }


class NativePreparationTests(unittest.TestCase):
    def test_independent_grants_prepare_existing_file_and_bundle_bindings(self):
        file = approved("file2", 1, "file_create.v2@1.0.0")
        bundle = approved("bundle1", 2, "bundle_create.v1@1.1.0")
        scopes = {"file2": file, "bundle1": bundle}
        rows = prepare(scopes, [intent("file2", file), intent("bundle1", bundle, ["z", "a"])])
        self.assertEqual([row["scope"] for row in rows], list(scopes))
        self.assertEqual(rows[1]["candidate"]["members"], ["a", "z"])
        for row, version in zip(rows, ("1.3", "1.6"), strict=True):
            scope = scopes[row["scope"]]
            manifest = json.loads(base64.b64decode(row["startup"]["windows"]["manifest_base64"]))
            self.assertEqual(manifest["native_read_installation_version"], version)
            self.assertEqual(manifest["root_grants"], [scope["root_grant"]])
            self.assertEqual(manifest["evidence_root"], scope["evidence_root"])
            self.assertEqual(row["startup"]["linux"]["manifest_digest"], row["startup"]["windows"]["manifest_digest"])
            self.assertEqual(row["inspect"]["run_id"], row["execute"]["run_id"])
            self.assertTrue(row["execute"]["request"]["candidate_path"].startswith(scope["preparation_root"] + "/"))

    def test_request_cannot_admit_a_root_or_split_evidence(self):
        file = approved("file2", 1, "file_create.v2@1.0.0")
        bundle = approved("bundle1", 2, "bundle_create.v1@1.1.0")
        request = intent("file2", file)
        with self.assertRaisesRegex(ValueError, "no matching approved scope"):
            prepare({"file2": file}, [dict(request, scope="unapproved")])
        with self.assertRaisesRegex(ValueError, "exact native preparation intent"):
            prepare({"file2": file}, [dict(request, windows_root=bundle["windows_root"])])
        with self.assertRaisesRegex(ValueError, "overlapping native grants"):
            prepare({"file2": file, "bundle1": dict(bundle, root_grant=file["root_grant"])}, [request])
        same_inode = dict(file["evidence_identity"], stable_id="different-label")
        with self.assertRaisesRegex(ValueError, "disjoint evidence and preparation"):
            prepare({"file2": file, "bundle1": dict(bundle, evidence_identity=same_inode)}, [request])
        with self.assertRaisesRegex(PhaseError, "bundle.duplicate_path"):
            prepare({"bundle1": bundle}, [intent("bundle1", bundle, ["a", "A"])])


if __name__ == "__main__":
    unittest.main()
