"""Focused, stdlib-only distribution tests. Never import the Phase runtime."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("docker_stage", ROOT / "docker/stage.py")
staging = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(staging)


class DistributionRecipeTests(unittest.TestCase):
    def test_manifest_and_lock_are_exact(self):
        manifest = staging.load_manifest(ROOT / "docker/wheels.json")
        staging.verify_lock(ROOT / "docker/requirements.lock", manifest["wheels"])
        self.assertEqual(manifest["platform"], "linux/amd64")
        self.assertEqual(manifest["python"], "3.11")
        self.assertEqual(len(manifest["wheels"]), 30)
        release = [w for w in manifest["wheels"] if w["name"] == "phase-tool"]
        self.assertEqual(release, [{
            "filename": "phase_tool-1.1.0-py3-none-any.whl",
            "name": "phase-tool", "version": "1.1.0", "size": 317527,
            "sha256": "9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a",
        }])

    def test_dockerfile_boundary(self):
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        manifest = staging.load_manifest(ROOT / "docker/wheels.json")
        bases = re.findall(r"^FROM --platform=linux/amd64 (\S+) AS \w+$", text, re.M)
        self.assertEqual(bases, [manifest["base_image"]] * 2)
        for required in ("--require-hashes", "--no-index", "--no-compile",
                         "--without-pip", 'test "$TARGETPLATFORM" = "linux/amd64"',
                         "python docker/stage.py --verify /input", "USER 10001:10001",
                         'ENTRYPOINT ["phase"]', 'CMD ["mcp", "serve", "--stdio"]'):
            self.assertIn(required, text)
        for line in text.splitlines():
            if line.startswith("RUN "):
                self.assertTrue(line.startswith("RUN --network=none "))
        for prohibited in ("apt-get", "pip install .", "PYTHONPATH", "COPY . ", "ADD "):
            self.assertNotIn(prohibited, text)
        self.assertNotIn("ARG ", text.split("AS runtime", 1)[1])

    def test_context_positive_allowlist(self):
        lines = [line for line in (ROOT / ".dockerignore").read_text().splitlines()
                 if line and not line.startswith("#")]
        self.assertEqual(lines, ["**", "!Dockerfile", "!.dockerignore", "!docker/",
                                "!docker/requirements.lock", "!docker/wheels.json",
                                "!docker/stage.py", "!wheels/", "!wheels/*.whl"])


class InputRefusalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phase-docker-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.house = self.root / "wheelhouse"
        self.house.mkdir()
        self.payload = b"synthetic fixture; not a runtime wheel"
        self.filename = "synthetic-1.0-py3-none-any.whl"
        self.wheel = self.house / self.filename
        self.wheel.write_bytes(self.payload)
        self.rows = [{"filename": self.filename, "name": "synthetic", "version": "1.0",
                      "size": len(self.payload),
                      "sha256": hashlib.sha256(self.payload).hexdigest()}]
        self.recipe = self.root / "recipe"
        (self.recipe / "docker").mkdir(parents=True)
        for name in staging.RECIPE_FILES:
            (self.recipe / name).write_text("synthetic recipe\n", encoding="utf-8")
        self.manifest = self.recipe / "docker/wheels.json"
        self.manifest.write_text(json.dumps({"platform": "linux/amd64", "wheels": self.rows}))
        self.lock = self.recipe / "docker/requirements.lock"
        self.lock.write_text(f"synthetic==1.0 --hash=sha256:{self.rows[0]['sha256']}\n")

    def test_valid_bytes(self):
        staging.verify_wheels(self.house, self.rows)

    def test_same_length_corruption_refused(self):
        self.wheel.write_bytes(b"X" + self.payload[1:])
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            staging.verify_wheels(self.house, self.rows)

    def test_truncation_refused(self):
        self.wheel.write_bytes(self.payload[:-1])
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            staging.verify_wheels(self.house, self.rows)

    def test_missing_wheel_refused(self):
        self.wheel.unlink()
        with self.assertRaisesRegex(ValueError, "wheel set mismatch"):
            staging.verify_wheels(self.house, self.rows)

    def test_extra_input_refused(self):
        (self.house / "unexpected.txt").write_bytes(b"synthetic extra")
        with self.assertRaisesRegex(ValueError, "wheel set mismatch"):
            staging.verify_wheels(self.house, self.rows)

    def test_directory_as_wheel_refused(self):
        self.wheel.unlink()
        self.wheel.mkdir()
        with self.assertRaisesRegex(ValueError, "not a regular wheel"):
            staging.verify_wheels(self.house, self.rows)

    def test_symlink_refused(self):
        target = self.root / "synthetic-target"
        target.write_bytes(self.payload)
        self.wheel.unlink()
        try:
            self.wheel.symlink_to(target)
        except OSError as error:
            self.skipTest(f"host cannot create symlinks: {error}")
        with self.assertRaisesRegex(ValueError, "not a regular wheel"):
            staging.verify_wheels(self.house, self.rows)

    def test_unpinned_or_different_lock_refused(self):
        self.lock.write_text("synthetic>=1.0\n")
        with self.assertRaisesRegex(ValueError, "does not match"):
            staging.verify_lock(self.lock, self.rows)

    def test_duplicate_lock_refused(self):
        self.lock.write_text(self.lock.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "does not match"):
            staging.verify_lock(self.lock, self.rows)

    def test_manifest_path_traversal_refused(self):
        self.rows[0]["filename"] = "../synthetic.whl"
        self.manifest.write_text(json.dumps({"wheels": self.rows}))
        with self.assertRaisesRegex(ValueError, "unsafe wheel filename"):
            staging.load_manifest(self.manifest)

    def test_duplicate_manifest_identity_refused(self):
        self.manifest.write_text(json.dumps({"wheels": self.rows * 2}))
        with self.assertRaisesRegex(ValueError, "duplicate wheel identity"):
            staging.load_manifest(self.manifest)

    def test_staging_is_explicit_and_reverified(self):
        (self.recipe / "excluded-secret-fixture.txt").write_bytes(b"synthetic only")
        output = self.root / "staged"
        with patch.object(staging, "__file__", str(self.recipe / "docker/stage.py")):
            staging.stage(self.house, output)
        actual = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}
        self.assertEqual(actual, set(staging.RECIPE_FILES) | {f"wheels/{self.filename}"})
        staging.verify_context(output)

    def test_staging_refuses_existing_output_without_mutation(self):
        output = self.root / "existing"
        output.mkdir()
        marker = output / "marker"
        marker.write_bytes(b"preserve")
        with patch.object(staging, "__file__", str(self.recipe / "docker/stage.py")):
            with self.assertRaisesRegex(ValueError, "output already exists"):
                staging.stage(self.house, output)
        self.assertEqual(marker.read_bytes(), b"preserve")
        self.assertEqual(list(output.iterdir()), [marker])

    def test_bad_bytes_create_no_output(self):
        output = self.root / "not-created"
        self.wheel.write_bytes(b"bad")
        with patch.object(staging, "__file__", str(self.recipe / "docker/stage.py")):
            with self.assertRaises(ValueError):
                staging.stage(self.house, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
