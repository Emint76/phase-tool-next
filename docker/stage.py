"""Stage only verified distribution inputs; no downloads or Phase imports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

RECIPE_FILES = (
    "Dockerfile",
    ".dockerignore",
    "docker/requirements.lock",
    "docker/wheels.json",
    "docker/stage.py",
)


def load_manifest(path):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    wheels = manifest["wheels"]
    names = set()
    filenames = set()
    for wheel in wheels:
        filename = wheel["filename"]
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", filename):
            raise ValueError(f"unsafe wheel filename: {filename}")
        if filename in filenames or wheel["name"] in names:
            raise ValueError("duplicate wheel identity")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", wheel["name"]):
            raise ValueError("invalid package name")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", wheel["version"]):
            raise ValueError("invalid pinned version")
        if not re.fullmatch(r"[a-f0-9]{64}", wheel["sha256"]):
            raise ValueError("invalid SHA256")
        if type(wheel["size"]) is not int or wheel["size"] <= 0:
            raise ValueError("invalid wheel size")
        names.add(wheel["name"])
        filenames.add(filename)
    if not wheels:
        raise ValueError("empty wheel manifest")
    return manifest


def verify_wheels(wheelhouse, wheels):
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise ValueError("wheelhouse must be a real directory")
    expected = {wheel["filename"] for wheel in wheels}
    actual = {path.name for path in wheelhouse.iterdir()}
    if actual != expected:
        raise ValueError(f"wheel set mismatch: missing={sorted(expected - actual)}, "
                         f"extra={sorted(actual - expected)}")
    for wheel in wheels:
        path = wheelhouse / wheel["filename"]
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"not a regular wheel: {path.name}")
        if path.stat().st_size != wheel["size"]:
            raise ValueError(f"size mismatch: {path.name}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != wheel["sha256"]:
            raise ValueError(f"SHA256 mismatch: {path.name}")


def verify_lock(path, wheels):
    actual = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.startswith("#")]
    expected = [f"{w['name']}=={w['version']} --hash=sha256:{w['sha256']}"
                for w in wheels]
    if sorted(actual) != sorted(expected):
        raise ValueError("requirements.lock does not match wheels.json")


def verify_context(context):
    manifest = load_manifest(context / "docker/wheels.json")
    verify_lock(context / "docker/requirements.lock", manifest["wheels"])
    verify_wheels(context / "wheels", manifest["wheels"])
    return manifest


def stage(wheelhouse, output):
    recipe = Path(__file__).resolve().parent.parent
    manifest = load_manifest(recipe / "docker/wheels.json")
    verify_lock(recipe / "docker/requirements.lock", manifest["wheels"])
    verify_wheels(wheelhouse, manifest["wheels"])
    # Never merge with or overwrite an existing directory (including a symlink).
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists; choose a fresh build directory")
    for relative in RECIPE_FILES:
        source = recipe / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"not a regular recipe input: {relative}")
    output.mkdir(parents=True)
    for relative in RECIPE_FILES:
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(recipe / relative, destination)
    (output / "wheels").mkdir()
    for wheel in manifest["wheels"]:
        shutil.copyfile(wheelhouse / wheel["filename"], output / "wheels" / wheel["filename"])
    # Recheck copied bytes; this context is checked again inside the Docker build.
    verify_context(output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path, metavar="BUILD_CONTEXT")
    args = parser.parse_args()
    if args.verify is not None:
        if args.wheelhouse is not None or args.output is not None:
            parser.error("--verify cannot be combined with staging options")
        operation = lambda: verify_context(args.verify)
    else:
        if args.wheelhouse is None or args.output is None:
            parser.error("staging requires --wheelhouse and --output")
        operation = lambda: stage(args.wheelhouse, args.output)
    try:
        manifest = operation()
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"refused: {error}\n")
    print(f"verified {len(manifest['wheels'])} wheels ({manifest['platform']})")


if __name__ == "__main__":
    main()
