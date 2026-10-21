"""Windows host controller for a bounded, owned primitive-gate campaign.

No delete, production exec, arbitrary host-root, or qualification bypass action.
All host logs are provisional; each is independently archived by unchanged
Phase on dedicated ext4 volumes before it is accepted as durable evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parent.parent
OWNER = "phase-ntfs-qualification"
BASE = "sha256:5e6f98d684b7f65e6798f2fdc23edf05ed839ed96b611de29e4930c357ce0277"
ROOTS = {"REF": "/qualification/reference", "MIX": "/ntfs/transport-cases"}
VOLUME_DESTINATIONS = {k: "/qualification/" + k for k in ("reference", "records", "preparation", "evidence")}


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def execute(argv: list[str], payload: bytes | None = None, timeout: int = 60) -> bytes:
    result = subprocess.run(argv, input=payload, capture_output=True, timeout=timeout, shell=False)
    if result.returncode:
        raise RuntimeError(json.dumps({"argv": argv, "exit_code": result.returncode,
            "stdout": result.stdout.decode("utf-8", "replace"), "stderr": result.stderr.decode("utf-8", "replace")}))
    return result.stdout


def docker(*arguments: str, payload: bytes | None = None, timeout: int = 60) -> bytes:
    return execute(["docker", *arguments], payload, timeout)


def checked_host_path(path: Path, *, existing: bool) -> Path:
    require(path.is_absolute(), "host path must be absolute")
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode), "host symlink forbidden")
        require(not (getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT), "host reparse forbidden")
    resolved = path.resolve(strict=existing)
    require(os.path.normcase(str(path)) == os.path.normcase(str(resolved)), "resolved host path differs")
    return path


def save_exclusive(path: Path, value: dict | bytes) -> None:
    checked_host_path(path.parent, existing=True)
    with path.open("xb") as stream:
        stream.write(value if isinstance(value, bytes) else json.dumps(value, indent=2, sort_keys=True).encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def update_state(path: Path, state: dict) -> None:
    checked_host_path(path, existing=True)
    require(json.loads(path.read_bytes())["campaign"] == state["campaign"], "state ownership mismatch")
    temporary = path.with_name("state-update-" + str(uuid.uuid4()) + ".json")
    save_exclusive(temporary, state)
    os.replace(temporary, path)


def container_metadata(identifier: str) -> dict:
    raw = json.loads(docker("inspect", identifier))[0]
    return {"Id": raw["Id"], "Name": raw["Name"], "Image": raw["Image"], "State": raw["State"],
            "User": raw["Config"]["User"], "Labels": raw["Config"]["Labels"],
            "Mounts": raw["Mounts"], "ReadonlyRootfs": raw["HostConfig"]["ReadonlyRootfs"],
            "NetworkMode": raw["HostConfig"]["NetworkMode"], "CapDrop": raw["HostConfig"]["CapDrop"],
            "SecurityOpt": raw["HostConfig"]["SecurityOpt"], "Memory": raw["HostConfig"]["Memory"],
            "NanoCpus": raw["HostConfig"]["NanoCpus"], "PidsLimit": raw["HostConfig"]["PidsLimit"]}


def verify_owned(state: dict, *, read_only: bool = False) -> str:
    checked_host_path(Path(state["host_root"]), existing=True)
    marker = json.loads((Path(state["host_root"]) / "ownership.json").read_bytes())
    require(marker["campaign"] == state["campaign"] and marker["owner"] == OWNER, "host owner changed")
    name = "verifier" if read_only else "worker"
    expected = state["containers"][name]
    metadata = container_metadata(expected["Id"])
    require(metadata["Id"] == expected["Id"] and metadata["Image"] == state["test_image_id"], "container identity changed")
    require(metadata["User"] == "10001:10001", "wrong container user")
    require(metadata["Labels"].get("owner") == OWNER and metadata["Labels"].get("campaign") == state["campaign"], "container owner mismatch")
    require(metadata["ReadonlyRootfs"] and metadata["NetworkMode"] == "none", "container policy differs")
    require(set(metadata["CapDrop"] or []) == {"ALL"}, "capabilities differ")
    require("no-new-privileges" in (metadata["SecurityOpt"] or []), "no-new-privileges missing")
    require(metadata["Memory"] == 2 * 1024**3 and metadata["NanoCpus"] == 2 * 10**9 and metadata["PidsLimit"] == 128, "resource limits differ")
    require(metadata["Mounts"] == expected["Mounts"], "mount map changed")
    for volume in state["volumes"].values():
        current = json.loads(docker("volume", "inspect", volume["Name"]))[0]
        require(current["Name"] == volume["Name"] and current["CreatedAt"] == volume["CreatedAt"], "volume identity changed")
        require(current["Labels"] == volume["Labels"], "volume ownership changed")
    return metadata["Id"]


def invoke(state: dict, action: str, *, lane: str | None = None, name: str | None = None,
           payload: bytes | None = None, read_only: bool = False) -> dict:
    container = verify_owned(state, read_only=read_only)
    argv = ["exec", "-i", container, "/opt/phase/bin/python", "-B", "/artifacts/transport_gates.py",
            action, "--campaign", state["campaign"]]
    if lane:
        argv += ["--lane", lane]
    if name:
        argv += ["--name", name]
    return json.loads(docker(*argv, payload=payload, timeout=120))


def retain(state: dict, provisional: Path, record: dict, name: str) -> dict:
    raw = json.dumps(record, sort_keys=True).encode("utf-8")
    save_exclusive(provisional / (name + ".json"), raw)
    publication = invoke(state, "archive", name=name, payload=raw)
    save_exclusive(provisional / (name + "-publication.json"), publication)
    p = publication["publication"]
    require(p["success"] is True and p["target_verified"] is True and p["status"] == "verified" and p["exit_code"] == 0, "Phase archive not verified")
    require(p["run_id"] == name and p["contract_binding"] == "file_create.v2@1.0.0", "wrong archive binding")
    require(p["content_digest"] == sha(raw) and publication["input_digest"] == sha(raw), "archive input digest mismatch")
    require(p["content_length"] == len(raw) and p["receipt_digest"], "archive length/receipt missing")
    readback = invoke(state, "inspect", name=name, read_only=True)
    save_exclusive(provisional / (name + "-independent-inspection.json"), readback)
    i = readback["inspection"]
    require(i["success"] is True and i["target_verified"] is True and i["receipt_digest"] == p["receipt_digest"], "independent inspection failed")
    require(readback["readback_digest"] == sha(raw) and readback["length"] == len(raw), "independent bytes mismatch")
    return {"run_id": name, "receipt_digest": p["receipt_digest"], "input_digest": sha(raw), "independent_inspect": True}


def reserve() -> dict:
    free = {d: shutil.disk_usage(d).free for d in ("C:\\", "S:\\")}
    require(all(v >= 4 * 1024**3 for v in free.values()), "small-gate 4GiB host reserve unavailable")
    return free


def prepare(campaign: str, provisional: Path) -> dict:
    require(os.name == "nt", "Windows host controller required")
    root = checked_host_path(Path("S:/Phase-NTFS-Qualification") / campaign, existing=False)
    checked_host_path(provisional, existing=False)
    require(not root.exists(), "campaign root already exists")
    require(not provisional.exists(), "campaign state already exists")
    provisional.mkdir(parents=True, exist_ok=False)
    before = {"host_free": reserve(), "containers": []}
    volume_query = "Get-Volume -DriveLetter S,C | Select-Object DriveLetter,FileSystemType,DriveType,UniqueId,Size,SizeRemaining | ConvertTo-Json"
    before["host_volumes"] = json.loads(execute(["powershell", "-NoProfile", "-Command", volume_query]).decode("utf-8-sig"))
    require(next(v for v in before["host_volumes"] if v["DriveLetter"] == "S")["FileSystemType"] == "NTFS", "S is not NTFS")
    for identifier in docker("ps", "-aq", "--no-trunc").decode().split():
        # Metadata only; no Config.Env, command contents, scientific data or secrets.
        before["containers"].append(container_metadata(identifier))
    save_exclusive(provisional / "before.json", before)
    image = json.loads(docker("image", "inspect", BASE))[0]
    require(image["Id"] == BASE, "reference image mismatch")
    require("phase-tool@" + BASE in image["RepoDigests"], "exact local FROM digest not available")
    before["reference_image"] = {k: image[k] for k in ("Id", "RepoDigests", "RootFS", "Architecture", "Os")}
    root.parent.mkdir(exist_ok=True)
    checked_host_path(root.parent, existing=True)
    root.mkdir(exist_ok=False)
    artifacts = root / "artifacts"
    artifacts.mkdir()
    transport = root / "transport-cases"
    transport.mkdir()
    token = {"campaign": campaign, "owner": OWNER}
    save_exclusive(transport / ".campaign-owner.json", token)
    wheel = REPO.parent / "reference-assets/phase_tool-1.1.0-py3-none-any.whl"
    require(sha(wheel.read_bytes()) == "sha256:9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a", "reference wheel mismatch")
    script = Path(__file__).with_name("transport_gates.py")
    save_exclusive(artifacts / script.name, script.read_bytes())
    save_exclusive(artifacts / wheel.name, wheel.read_bytes())
    state = {"owner": OWNER, "campaign": campaign, "host_root": str(root), "container_roots": ROOTS,
             "created_utc_ns": time.time_ns(), "source_commit": execute(["git", "-C", str(REPO), "rev-parse", "HEAD"]).decode().strip(),
             "harness_digest": sha(script.read_bytes()), "reference_image": BASE,
             "containers": {}, "volumes": {}, "records": [], "small_gate_budget_bytes": 256 * 1024**2,
             "host_before": before["host_free"], "baseline_inventory": before}
    # Ownership marker freezes planned roots before any docker mount is created.
    save_exclusive(root / "ownership.json", state)
    save_exclusive(artifacts / "ownership.json", state)
    save_exclusive(provisional / "state.json", state)
    short = campaign[:8]
    tag = "phase-ntfs-gates:" + campaign
    base_tag = "phase-ntfs-gate-base:" + campaign
    found = subprocess.run(["docker", "image", "inspect", base_tag], capture_output=True)
    require(found.returncode != 0, "owned base tag already exists")
    docker("image", "tag", BASE, base_tag)
    require(json.loads(docker("image", "inspect", base_tag))[0]["Id"] == BASE, "owned base tag mismatch")
    state["owned_base_tag"] = base_tag
    update_state(provisional / "state.json", state)
    docker("build", "--pull=false", "--network", "none", "--label", "owner=" + OWNER,
           "--build-arg", "GATE_BASE=" + base_tag,
           "--label", "campaign=" + campaign, "-t", tag, "-f", str(REPO / "qualification/Dockerfile.gates"),
           str(REPO / "qualification"), timeout=120)
    built_image = json.loads(docker("image", "inspect", tag))[0]
    state["test_image_id"] = built_image["Id"]
    base_layers = image["RootFS"]["Layers"]
    require(built_image["RootFS"]["Layers"][:len(base_layers)] == base_layers, "test image ancestry mismatch")
    update_state(provisional / "state.json", state)
    for key in VOLUME_DESTINATIONS:
        name = f"phase-ntfs-q-{campaign}-{key}"
        # A fresh UUID plus refusal to claim any existing object, even by name.
        existing = subprocess.run(["docker", "volume", "inspect", name], capture_output=True)
        require(existing.returncode != 0, "volume already exists")
        docker("volume", "create", "--label", "owner=" + OWNER, "--label", "campaign=" + campaign, name)
        volume = json.loads(docker("volume", "inspect", name))[0]
        require(volume["Labels"] == {"owner": OWNER, "campaign": campaign}, "unexpected volume labels")
        state["volumes"][key] = volume
        update_state(provisional / "state.json", state)
    for role in ("worker", "verifier"):
        argv = ["run", "-d", "--name", f"phase-ntfs-q-{campaign}-{role}", "--label", "owner=" + OWNER,
                "--label", "campaign=" + campaign, "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", "10001:10001", "--cpus", "2",
                "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "128",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                "--tmpfs", "/work:rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700",
                "--mount", f"type=bind,source={artifacts},target=/artifacts,readonly",
                "--mount", f"type=bind,source={transport},target=/ntfs/transport-cases" + (",readonly" if role == "verifier" else "")]
        for key, destination in VOLUME_DESTINATIONS.items():
            argv += ["--mount", f"type=volume,source={state['volumes'][key]['Name']},target={destination}" + (",readonly" if role == "verifier" else "")]
        identifier = docker(*argv, state["test_image_id"]).decode().strip()
        metadata = container_metadata(identifier)
        require(len(metadata["Mounts"]) == 6, "unexpected mount count")
        expected_destinations = set(VOLUME_DESTINATIONS.values()) | {"/artifacts", "/ntfs/transport-cases"}
        require({m["Destination"] for m in metadata["Mounts"]} == expected_destinations, "unexpected mounts")
        for mount in metadata["Mounts"]:
            expected_write = role == "worker" and mount["Destination"] != "/artifacts"
            require(mount["RW"] == expected_write, "wrong mount access")
            if mount["Type"] == "volume":
                key = mount["Destination"].split("/")[-1]
                require(mount["Name"] == state["volumes"][key]["Name"], "wrong volume")
            else:
                source = artifacts if mount["Destination"] == "/artifacts" else transport
                actual = mount["Source"].replace("\\", "/")
                host_form = str(source).replace("\\", "/")
                engine_form = "/run/desktop/mnt/host/" + host_form[0].lower() + host_form[2:]
                require(actual.lower() in {host_form.lower(), engine_form.lower()}, "wrong host bind")
        state["containers"][role] = metadata
        update_state(provisional / "state.json", state)
    initializer = "import json,os; from pathlib import Path; token=json.loads(input()); roots=json.loads(input()); [(lambda p: p.write_text(json.dumps(token)) if not p.exists() else (_ for _ in ()).throw(RuntimeError('existing token')))(Path(r)/'.campaign-owner.json') for r in roots]"
    # Only newly created ext4 volume roots; no chown/ACL operation on the host.
    docker("exec", "-i", verify_owned(state), "/opt/phase/bin/python", "-B", "-c", initializer,
           payload=(json.dumps(token) + "\n" + json.dumps(list(VOLUME_DESTINATIONS.values())) + "\n").encode())
    return state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "freeze", "e01", "d02", "status"])
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--lane", choices=ROOTS)
    args = parser.parse_args()
    require(str(uuid.UUID(args.campaign, version=4)) == args.campaign, "invalid campaign UUID")
    provisional = REPO.parent / "qualification-campaigns" / args.campaign
    if args.action == "prepare":
        state = prepare(args.campaign, provisional)
    else:
        checked_host_path(provisional, existing=True)
        state = json.loads((provisional / "state.json").read_bytes())
        require(state["owner"] == OWNER and state["campaign"] == args.campaign, "wrong state owner")
    if args.action in {"prepare", "freeze", "e01", "d02"}:
        reserve()
        action = "freeze" if args.action == "prepare" else args.action
        name = f"g-{action}-{(args.lane or 'env').lower()}-{uuid.uuid4().hex[:8]}"
        try:
            result = invoke(state, action, lane=args.lane)
        except Exception as error:
            result = {"result": {"verdict": "NOT_VERIFIED", "reason": "EXECUTION_OR_OBSERVATION_GAP",
                       "error": str(error), "traceback": traceback.format_exc()}}
        record = {"controller_digest": sha(Path(__file__).read_bytes()), "source_commit": state["source_commit"],
                  "host_free_after": reserve(), "test_image_id": state["test_image_id"], "result": result,
                  "baseline_inventory": state["baseline_inventory"], "ownership": state}
        binding = retain(state, provisional, record, name)
        state["records"].append(binding | {"action": action, "lane": args.lane, "result": result.get("result")})
        update_state(provisional / "state.json", state)
        print(json.dumps(binding | {"result": result.get("result"), "provisional_dir": str(provisional)}, indent=2))
    else:
        verify_owned(state)
        verify_owned(state, read_only=True)
        print(json.dumps(state, indent=2))


if __name__ == "__main__":
    main()
