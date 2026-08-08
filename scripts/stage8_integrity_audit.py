from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from phase_tool.canonical import canonical_digest


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def generation_errors(entries: list[dict[str, Any]]) -> list[str]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in entries:
        if entry.get("kind") == "contract":
            key = ("contract", f"{entry.get('id')}@{entry.get('version')}")
        elif entry.get("kind") == "schema":
            key = ("schema", str(entry.get("schema_ref")))
        else:
            continue
        groups.setdefault(key, []).append(entry)
    errors: list[str] = []
    for key, group in sorted(groups.items()):
        current = [entry for entry in group if entry.get("current", True) is True]
        if len(current) != 1:
            errors.append(f"ambiguous current generation {key!r}: {len(current)}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    errors: list[str] = []

    registry_path = resources.files("phase_tool.data").joinpath("registry.json")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = registry["entries"]
    entry_keys: set[tuple[object, ...]] = set()
    for entry in entries:
        key = (
            entry.get("kind"),
            entry.get("id"),
            entry.get("version"),
            entry.get("artifact_digest"),
            entry.get("package_digest"),
        )
        if key in entry_keys:
            errors.append(f"duplicate registry entry {key!r}")
        entry_keys.add(key)
    errors.extend(generation_errors(entries))

    package_artifacts: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    for entry in entries:
        resource = entry.get("archive_resource", entry["artifact"])
        expected = entry["artifact_digest"]
        prior = artifacts.setdefault(resource, expected)
        if prior != expected:
            errors.append(f"conflicting artifact digest {resource}")
        for artifact in entry.get("package_artifacts", []):
            resource = artifact.get("archive_resource", artifact["resource"])
            expected = artifact["digest"]
            prior = package_artifacts.setdefault(resource, expected)
            if prior != expected:
                errors.append(f"conflicting package artifact digest {resource}")
            prior = artifacts.setdefault(resource, expected)
            if prior != expected:
                errors.append(f"conflicting artifact digest {resource}")
    schemas_checked = 0
    for resource, expected in sorted(artifacts.items()):
        item = resources.files("phase_tool.data").joinpath(resource)
        if not item.is_file():
            errors.append(f"missing package artifact {resource}")
            continue
        raw = item.read_bytes()
        if digest(raw) != expected:
            errors.append(f"package artifact digest mismatch {resource}")
        if resource.startswith("schemas/") and resource.endswith(".json"):
            try:
                Draft202012Validator.check_schema(json.loads(raw))
                schemas_checked += 1
            except Exception as exc:
                errors.append(f"invalid schema {resource}: {type(exc).__name__}: {exc}")

    for entry in entries:
        declared = entry.get("package_artifacts")
        if declared is None:
            continue
        actual = [
            {
                "resource": item["resource"],
                "digest": digest(
                    resources.files("phase_tool.data")
                    .joinpath(item.get("archive_resource", item["resource"]))
                    .read_bytes()
                ),
            }
            for item in declared
        ]
        if canonical_digest({"profile": "phase_contract_package_v1", "artifacts": actual}) != entry["package_digest"]:
            errors.append(f"package digest mismatch {entry['id']}")

    contract_bindings = {
        f"{entry['id']}@{entry['version']}"
        for entry in entries
        if entry.get("kind") == "contract"
    }

    manifest_entries = 0
    manifest_seen: set[str] = set()
    for line_number, line in enumerate((repository / "fixtures" / "manifest.sha256").read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            errors.append(f"malformed manifest line {line_number}")
            continue
        expected_hex, locator = parts
        if locator in manifest_seen:
            errors.append(f"duplicate manifest locator {locator}")
        manifest_seen.add(locator)
        path = repository / locator
        if not path.is_file():
            errors.append(f"missing manifest artifact {locator}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected_hex:
            errors.append(f"manifest digest mismatch {locator}")
        manifest_entries += 1

    with zipfile.ZipFile(args.wheel) as archive:
        wheel_names = set(archive.namelist())
        wheel_registry = "phase_tool/data/registry.json"
        if wheel_registry not in wheel_names:
            errors.append(f"wheel missing {wheel_registry}")
        elif archive.read(wheel_registry) != registry_path.read_bytes():
            errors.append(f"wheel registry mismatch {wheel_registry}")
        for resource, expected in artifacts.items():
            name = f"phase_tool/data/{resource}"
            if name not in wheel_names:
                errors.append(f"wheel missing {name}")
            elif digest(archive.read(name)) != expected:
                errors.append(f"wheel digest mismatch {name}")
        wheel_entries = len(wheel_names)

    summary = {
        "success": not errors,
        "registry_entries": len(entries),
        "registry_unique_entries": len(entry_keys),
        "contract_bindings": len(contract_bindings),
        "artifacts": len(artifacts),
        "package_artifacts": len(package_artifacts),
        "schemas_checked": schemas_checked,
        "manifest_entries": manifest_entries,
        "manifest_unique_entries": len(manifest_seen),
        "wheel_entries": wheel_entries,
        "errors": errors,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
