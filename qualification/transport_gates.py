"""Early mandatory-primitive gates; not a complete storage qualification.

Runs against explicitly owned synthetic roots only. No cleanup or admission
override exists. Stdout is provisional until archived through Phase on ext4.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
import traceback

ROOTS = {"REF": "/qualification/reference", "MIX": "/ntfs/transport-cases"}
MANIFEST = Path("/artifacts/ownership.json")
OWNER = "phase-ntfs-qualification"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def failure(error: Exception, phase: str) -> dict:
    unsupported = isinstance(error, OSError) and error.errno in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}
    violated = isinstance(error, AssertionError)
    return {"verdict": "UNSUPPORTED" if unsupported or violated else "NOT_VERIFIED",
            "reason": "TRANSPORT_INCOMPATIBILITY" if unsupported else "ORACLE_FAILURE" if violated else "ENVIRONMENT_OR_HARNESS_GAP",
            "phase": phase, "error_type": type(error).__name__, "error": str(error),
            "errno": getattr(error, "errno", None), "traceback": traceback.format_exc()}


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def identity(fd: int) -> dict:
    info = os.fstat(fd)
    return {"device": info.st_dev, "inode": info.st_ino,
            "mode": info.st_mode, "length": info.st_size,
            "descriptor": fd, "proc_fd": os.readlink(f"/proc/self/fd/{fd}")}


def checked_path(path: Path) -> Path:
    if not path.is_absolute() or str(path) != str(path.resolve(strict=True)):
        raise ValueError("non-canonical root")
    for component in (path, *path.parents):
        if stat.S_ISLNK(os.lstat(component).st_mode):
            raise ValueError("symlink root/ancestor")
    if not path.is_dir():
        raise ValueError("non-directory root")
    return path


def ownership(campaign: str) -> dict:
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", campaign) is None:
        raise ValueError("campaign UUID must be v4")
    manifest = json.loads(MANIFEST.read_bytes())
    if manifest["owner"] != OWNER or manifest["campaign"] != campaign:
        raise ValueError("ownership mismatch")
    if manifest["container_roots"] != ROOTS:
        raise ValueError("unexpected root map")
    for root in (*ROOTS.values(), "/qualification/records", "/qualification/preparation", "/qualification/evidence"):
        checked_path(Path(root))
        token = json.loads((Path(root) / ".campaign-owner.json").read_bytes())
        if token != {"campaign": campaign, "owner": OWNER}:
            raise ValueError("root ownership mismatch")
    return manifest


def freeze() -> dict:
    import phase_tool
    import phase_tool.mutation.posix.authority as authority
    from phase_tool.application import PhaseApplication
    from phase_tool.mutation.bundle_create import _rename_noreplace
    from phase_tool.mutation.guarantees import registered_profile_binding
    package = Path(phase_tool.__file__).parent
    artifact_paths = [Path(authority.__file__), Path(_rename_noreplace.__code__.co_filename),
                      package / "installation.py", package / "data/registry.json",
                      package / "data/descriptors/guarantee/phase.posix.authority.v1.json",
                      package / "data/descriptors/guarantee/phase.mutation-guarantees.v1.json"]
    return {
        "phase_version": importlib.metadata.version("phase-tool"),
        "python": sys.version, "optimize": sys.flags.optimize, "platform": platform.platform(), "uid": os.getuid(), "gid": os.getgid(),
        "dependencies": sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions()),
        "artifact_digests": {str(p.relative_to(package)): digest(p.read_bytes()) for p in artifact_paths},
        "harness_digest": digest(Path(__file__).read_bytes()),
        "registry": PhaseApplication().contracts_list().payload,
        "profile": repr(registered_profile_binding("phase.posix.authority.v1@1.0.0")),
        "mountinfo": Path("/proc/self/mountinfo").read_text(),
        "filesystems": {r: {"available": os.statvfs(r).f_bavail * os.statvfs(r).f_frsize,
                              "device": os.stat(r).st_dev, "inode": os.stat(r).st_ino}
                        for r in (*ROOTS.values(), "/qualification/records", "/qualification/preparation", "/qualification/evidence")},
    }


def fsync_gate(root: Path, count: int = 10) -> dict:
    from phase_tool.mutation.posix.authority import PosixTargetAuthority
    records = []
    for number in range(count):
        locator = f"e01/r{number:02d}/item.bin"
        events = []
        authority = None
        descriptor = None
        real_fsync = os.fsync

        def observed_fsync(fd: int) -> None:
            event = {"call": "fsync", "before": identity(fd), "monotonic_ns": time.monotonic_ns()}
            events.append(event)
            try:
                real_fsync(fd)
                event["return"] = 0
            except OSError as error:
                event.update(errno=error.errno, error=str(error))
                raise

        result = {"repeat": number, "events": events}
        phase = "setup"
        try:
            authority = PosixTargetAuthority(root, locator,
                expected_root_identity=(os.stat(root).st_dev, os.stat(root).st_ino))
            content = hashlib.sha256(f"e01|{number}".encode("ascii")).digest() * 2048
            descriptor = authority.open_exclusive()
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if not 0 < written <= len(view):
                    raise OSError("invalid write progress")
                view = view[written:]
            phase = "file_fsync"
            observed_fsync(descriptor)
            expected_parent = identity(authority.parent_fd)
            require(stat.S_ISDIR(expected_parent["mode"]), "parent descriptor is not directory")
            named = os.stat(root / locator).st_size
            require(named == len(content), "named size mismatch")
            # Observation delegates to the genuine syscall; no synthetic return.
            os.fsync = observed_fsync
            phase = "directory_fsync"
            authority.fsync_parent()
            os.fsync = real_fsync
            require(events[-1]["before"] == expected_parent, "wrong parent flushed")
            phase = "readback"
            authority.assert_namespace_binding()
            actual = authority.readback(None, descriptor=descriptor)
            require(actual["digest"] == digest(content) and actual["length"] == len(content), "readback mismatch")
            result.update(verdict="SUPPORTED", content_digest=digest(content), length=len(content), locator=locator)
        except Exception as error:
            result.update(failure(error, phase), locator=locator)
        finally:
            os.fsync = real_fsync
            try:
                if descriptor is not None:
                    os.close(descriptor)
                if authority is not None:
                    authority.close()
            except Exception as error:
                result["prior_verdict"] = result.get("verdict")
                result.update(failure(error, "finalization"))
        records.append(result)
        if result["verdict"] != "SUPPORTED":
            break  # Mandatory primitive counterexample stops dependent mutation.
    return {"case_id": "E01", "subcase": "real_directory_fsync_acceptance", "full_case_verdict": "NOT_VERIFIED",
            "scope": "early primitive gate only; error propagation and independent observers pending",
            "guarantees": ["G06"], "requested_repeats": count,
            "completed_repeats": len(records), "records": records,
            "verdict": next((r["verdict"] for r in records if r["verdict"] != "SUPPORTED"), "SUPPORTED")}


def rename_gate(root: Path, count: int = 10) -> dict:
    from phase_tool.mutation.bundle_create import _rename_noreplace
    records = []
    for number in range(count):
        case = root / "d02" / f"r{number:02d}"
        fd = None
        result = {"repeat": number, "observations": []}
        phase = "setup"
        try:
            case.mkdir(parents=True, exist_ok=False)
            fd = os.open(case, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            result["parent"] = identity(fd)
            for fixture in ("absent", "empty", "nonempty"):
                source = case / f"source-{fixture}"
                target = case / f"target-{fixture}"
                source.mkdir()
                payload = f"source|{number}|{fixture}".encode("ascii")
                (source / "member").write_bytes(payload)
                original_inode = source.stat().st_ino
                if fixture != "absent":
                    target.mkdir()
                if fixture == "nonempty":
                    (target / "sentinel").write_bytes(b"preserved")
                existing_inode = target.stat().st_ino if target.exists() else None
                observation = {"fixture": fixture, "monotonic_ns": time.monotonic_ns()}
                result["observations"].append(observation)
                phase = "rename_noreplace"
                try:
                    _rename_noreplace(fd, source.name, target.name)
                    observation["return"] = 0
                    require(fixture == "absent", "existing target replaced")
                    require(not source.exists(), "source retained after rename")
                    require(target.stat().st_ino == original_inode, "target identity mismatch")
                    require((target / "member").read_bytes() == payload, "target bytes mismatch")
                    require(sorted(p.name for p in target.iterdir()) == ["member"], "target membership mismatch")
                except FileExistsError as error:
                    observation["errno"] = error.errno
                    require(fixture != "absent", "unexpected EEXIST")
                    require(source.stat().st_ino == original_inode, "source changed on EEXIST")
                    require(target.stat().st_ino == existing_inode, "target changed on EEXIST")
                    require(sorted(p.name for p in source.iterdir()) == ["member"], "source membership changed")
                    require((source / "member").read_bytes() == payload, "source bytes changed")
                    require(sorted(p.name for p in target.iterdir()) == (["sentinel"] if fixture == "nonempty" else []), "target membership changed")
                    if fixture == "nonempty":
                        require((target / "sentinel").read_bytes() == b"preserved", "target sentinel changed")
            result["verdict"] = "SUPPORTED"
        except Exception as error:
            result.update(failure(error, phase))
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            except Exception as error:
                result["prior_verdict"] = result.get("verdict")
                result.update(failure(error, "finalization"))
        records.append(result)
        if result["verdict"] != "SUPPORTED":
            break
    return {"case_id": "D02", "subcase": "sequential_noreplace", "full_case_verdict": "NOT_VERIFIED",
            "requirements": ["R06"], "scope": "sequential gate; concurrent qualification pending",
            "requested_repeats": count, "completed_repeats": len(records), "records": records,
            "verdict": next((r["verdict"] for r in records if r["verdict"] != "SUPPORTED"), "SUPPORTED")}


def archive(payload: bytes, name: str) -> dict:
    """Archive provisional external reports via unchanged Phase, ext4 only."""
    from phase_tool.application import PhaseApplication
    from phase_tool.installation import _linux_filesystem_type
    if re.fullmatch(r"[a-z][a-z0-9-]{0,60}", name) is None:
        raise ValueError("invalid archive identity")
    for root in ("/qualification/records", "/qualification/preparation", "/qualification/evidence"):
        require(_linux_filesystem_type(Path(root)) == "ext4", "archive route must be ext4")
    source = Path("/qualification/preparation") / (name + "-capture")
    source.mkdir(exist_ok=False)
    (source / "record.json").write_bytes(payload)
    preparation = Path("/qualification/preparation") / (name + "-phase")
    preparation.mkdir(exist_ok=False)
    app = PhaseApplication()
    response = app.publish_file(source_root=source, source_locator="record.json",
        target_root=Path("/qualification/records"), target_locator=name + ".json",
        preparation_root=preparation, evidence_root=Path("/qualification/evidence"),
        run_id=name, request_id=name, expected_digest=digest(payload), publication_version="2.0")
    return {"publication": response.payload, "input_digest": digest(payload), "length": len(payload)}


def inspect_archive(name: str) -> dict:
    from phase_tool.application import PhaseApplication
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,60}", name) is not None, "invalid inspection name")
    app = PhaseApplication()
    result = app.inspect(evidence_root=Path("/qualification/evidence"), run_id=name,
        root_bindings={"phase_result_root": Path("/qualification/records")}).payload
    raw = (Path("/qualification/records") / (name + ".json")).read_bytes()
    return {"inspection": result, "readback_digest": digest(raw), "length": len(raw)}


def main() -> int:
    require(sys.flags.optimize == 0, "optimized Python is forbidden for qualification")
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["freeze", "e01", "d02", "archive", "inspect"])
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--lane", choices=ROOTS)
    parser.add_argument("--name")
    args = parser.parse_args()
    ownership(args.campaign)
    result = {"campaign": args.campaign, "action": args.action, "utc_ns": time.time_ns(),
              "monotonic_ns": time.monotonic_ns(), "harness_digest": digest(Path(__file__).read_bytes())}
    if args.action == "freeze":
        result["environment"] = freeze()
    elif args.action == "archive":
        payload = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
        require(len(payload) <= 16 * 1024 * 1024, "report input exceeds limit")
        json.loads(payload)  # Reject truncation/non-JSON before any archive attempt.
        result.update(archive(payload, args.name))
    elif args.action == "inspect":
        result.update(inspect_archive(args.name))
    else:
        if not args.lane:
            parser.error("--lane required")
        root = checked_path(Path(ROOTS[args.lane]))
        if os.statvfs(root).f_bavail * os.statvfs(root).f_frsize < 4 * 1024**3:
            raise RuntimeError("small-gate reserve exhausted")
        # A fresh action directory is owned exclusively by this one invocation.
        case_root = root / ("gate-" + args.action)
        case_root.mkdir(exist_ok=False)
        result.update(lane=args.lane, root=str(root),
            result=fsync_gate(case_root) if args.action == "e01" else rename_gate(case_root))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
