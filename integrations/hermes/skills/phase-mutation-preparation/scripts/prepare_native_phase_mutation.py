#!/usr/bin/env python
"""Compose existing fixed native Phase bindings from approved installation facts."""
from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

from phase_tool.bundle import validate_members
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.core import CORE_BINDING
from phase_tool.installation import (
    _native_experimental_bundle1_registry,
    _native_experimental_file2_registry,
    _native_experimental_read_binding,
)
from phase_tool.mutation.ntfs.bootstrap import _accepted_launch_history
from phase_tool.mutation.ntfs.experimental_bundle1 import _ExperimentalBundle1Admission
from phase_tool.mutation.ntfs.experimental_file1 import _AUTHORIZATION
from phase_tool.mutation.ntfs.experimental_file2 import _ExperimentalFile2Admission
from phase_tool.mutation.ntfs.reader import _evidence_identity
from phase_tool.mutation.ntfs.worker import _grant
from phase_tool.paths import safe_relative_locator


_FAMILIES = {
    "file_create.v2@1.0.0": (_ExperimentalFile2Admission, _native_experimental_file2_registry, "file2", "/ntfs-result"),
    "bundle_create.v1@1.1.0": (_ExperimentalBundle1Admission, _native_experimental_bundle1_registry, "bundle1", "/ntfs-results"),
}
_MAX_JSON = 2 * 1024**2


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _fields(value, names, message):
    _require(type(value) is dict and value.keys() == set(names.split()), message)


def _linux_path(value):
    _require(type(value) is str and value.startswith("/") and not value.startswith("//"), "absolute preparation path required")
    path = PurePosixPath(value)
    _require(path.as_posix() == value and len(path.parts) > 1 and ".." not in path.parts, "ordinary preparation path required")
    return path


def _overlap(left, right):
    return left.is_relative_to(right) or right.is_relative_to(left)


def _scope_check(scopes):
    grants = []
    linux_roots = []
    for scope in scopes.values():
        _fields(scope, "contract windows_root root_grant evidence_root evidence_identity preparation_root preparation_identity launch",
                "approved installation binding required")
        _require(type(scope["contract"]) is str and scope["contract"] in _FAMILIES,
                 "contract not admitted by this preparation adapter")
        grant = _grant(scope["root_grant"])
        components = tuple(part.casefold() for part in grant.components)
        for prior, prefix in grants:
            # The existing admissions use the same S: namespace.
            overlap = (components[:len(prefix)] == prefix or prefix[:len(components)] == components)
            _require(not overlap and grant.root_identity != prior.root_identity,
                     "overlapping native grants cannot be assigned separate evidence")
        grants.append((grant, components))
        for role in ("evidence", "preparation"):
            path = _linux_path(scope[f"{role}_root"])
            parsed = _evidence_identity(canonical_bytes(scope[f"{role}_identity"]))
            identity = (parsed["device"], parsed["inode"])
            _require(all(identity != existing_id and not _overlap(path, existing_path)
                         for existing_id, existing_path in linux_roots),
                     "installation scopes require disjoint evidence and preparation")
            linux_roots.append((identity, path))


def _base64(raw):
    return base64.b64encode(raw).decode("ascii")


def prepare_native_mutations(approved_scopes, intents):
    """Return in-order launch and execute bytes as JSON values. This performs no I/O.

    The caller supplies deployment-owned scopes resolved from an explicit task
    grant or approved rules. Intent data cannot supply a grant, root, executable
    or registry. Keep scopes fixed across calls and stage only in their own
    preparation/install locations. Existing Core admission remains authoritative.
    """
    _require(type(approved_scopes) is dict and approved_scopes and type(intents) is list and intents,
             "approved installation scopes and at least one intent required")
    _scope_check(approved_scopes)
    result = []
    used_scopes = set()
    used_runs = set()
    startup_locations = set()
    deployment = None
    for intent in intents:
        _fields(intent, "scope contract run_id target_locator payload_digest payload_length members",
                "exact native preparation intent required")
        name, run_id = intent["scope"], intent["run_id"]
        _require(type(name) is str and name in approved_scopes, "task has no matching approved scope")
        _require(type(run_id) is str, "stable native run id required")
        _require(name not in used_scopes and run_id not in used_runs, "fixed experimental scopes admit one original run")
        used_scopes.add(name)
        used_runs.add(run_id)
        scope = approved_scopes[name]
        _require(intent["contract"] == scope["contract"], "operation and approved contract differ")
        kind, factory, family, projection = _FAMILIES[scope["contract"]]
        target = safe_relative_locator(intent["target_locator"])
        _require(target == intent["target_locator"], "canonical relative target required")
        candidate = {
            "operation_id": run_id, "idempotency_key": run_id, "target_locator": target, "input_binding": "payload",
        }
        members = intent["members"]
        if family == "bundle1":
            candidate["members"] = validate_members(members)
        else:
            _require(members is None, "a file publication has no bundle members")
        candidate_raw = canonical_bytes(candidate)

        launch = scope["launch"]
        _fields(launch, "windows linux", "fixed Windows and Linux launch settings required")
        for row in launch.values():
            _fields(row, "config dependency_roots", "fixed runtime config and dependency roots required")
            _require(row["config"]["native_launch_version"] == "1.0", "standalone native launch required")
        windows, linux = (launch[role]["config"] for role in ("windows", "linux"))
        platform_fields = {"phase_wheel", "dependency_file_digests"}
        _require({k: v for k, v in windows.items() if k not in platform_fields}
                 == {k: v for k, v in linux.items() if k not in platform_fields},
                 "Windows and Linux must use the same fixed installation")
        pair = (windows["core_container_id"], windows["reader_container_id"])
        _require(deployment is None or pair == deployment, "prepare one fixed deployment per batch")
        deployment = pair
        locations = {
            PureWindowsPath(windows["windows_launcher"]).parent,
            _linux_path(linux["linux_launcher"]).parent,
        }
        _require(not startup_locations.intersection(locations), "native startup locations must be distinct")
        startup_locations.update(locations)
        graph = windows["artifact_graph"]
        wheel_digest = windows["phase_wheel_digest"]
        _require(graph["phase_wheel_digest"] == wheel_digest, "artifact graph wheel mismatch")

        admission = kind(canonical_bytes({
            "experimental_admission_version": "1.0", "authorization_digest": _AUTHORIZATION,
            "contract": kind._contract, "run_id": run_id, "request_id": run_id, "target_locator": target,
            "candidate_digest": digest_bytes(candidate_raw), "payload_digest": intent["payload_digest"],
            "payload_length": intent["payload_length"], "wheel_digest": wheel_digest,
            **{key: scope[key] for key in ("windows_root", "root_grant", "evidence_identity", "preparation_identity")},
            "qualification": {"A05": "NOT_VERIFIED", "G01": "NOT_VERIFIED"}, "release_eligible": False,
        }))
        admission.document()
        registry = factory()
        binding = kind._contract
        contract = registry.resolve_contract(binding["id"], binding["version"], binding["package_digest"],
                                             core_version=CORE_BINDING["version"])
        profile = registry.guarantee_profile_bindings()[kind._profile]
        implementation = registry.resolve_guarantee_profile(profile)["implementation"]
        manifest = {
            "native_read_installation_version": kind._manifest_version,
            "installation_id": kind._installation_prefix + admission.digest[7:],
            "core": CORE_BINDING, "contract": kind._contract, "registry_snapshot_digest": registry.digest,
            "authority": {"usage": "provider_backed", "profile": profile,
                          "provider": {key: implementation[key] for key in ("id", "version", "artifact_digest")}},
            "mechanism": {key: contract.document["operation"]["mechanism"][key] for key in ("id", "version", "package_digest")},
            "composition": {"id": "phase.native.ntfs.experiment." + family, "version": "1.0.0",
                            "artifact_graph_digest": digest_bytes(canonical_bytes(graph))},
            **{key: scope[key] for key in ("evidence_root", "evidence_identity", "preparation_root", "preparation_identity")},
            "root_grants": [scope["root_grant"]], "root_projections": {"phase_result_root": projection},
        }
        raw = canonical_bytes(manifest)
        _native_experimental_read_binding(manifest_bytes=raw, expected_manifest_digest=digest_bytes(raw), admission=admission)
        startup = {}
        for platform, row in launch.items():
            config_raw = canonical_bytes(row["config"])
            _accepted_launch_history(row["config"], raw, digest_bytes(raw))
            startup[platform] = {
                "native_fixed_startup_version": "1.1",
                "config_base64": _base64(config_raw), "config_digest": digest_bytes(config_raw),
                "manifest_base64": _base64(raw), "manifest_digest": digest_bytes(raw),
                "dependency_roots": row["dependency_roots"], "experimental_admission_base64": _base64(admission.raw),
            }

        prep = _linux_path(scope["preparation_root"])
        request = {
            "operation": "execute", "candidate_path": str(prep / (run_id + "-candidate.json")),
            "input_paths": {"payload": str(prep / (run_id + "-payload"))},
            "expected_inputs": {"payload": [intent["payload_digest"], intent["payload_length"]]},
            "maximum_candidate_bytes": 1024**2,
        }
        result.append({
            "scope": name, "candidate": candidate, "startup": startup,
            "execute": {"run_id": run_id, "request": request},
            "inspect": {"run_id": run_id, "request": {"operation": "inspect"}},
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("approved_scopes", type=Path, help="deployment-owned approved bindings")
    parser.add_argument("intents", type=Path, help="ordered preparation intents")
    args = parser.parse_args()

    def read(path):
        with path.open("rb") as stream:
            return parse_json_bytes(stream.read(_MAX_JSON + 1), maximum_bytes=_MAX_JSON)

    sys.stdout.buffer.write(canonical_bytes(prepare_native_mutations(read(args.approved_scopes), read(args.intents))) + b"\n")


if __name__ == "__main__":
    main()
