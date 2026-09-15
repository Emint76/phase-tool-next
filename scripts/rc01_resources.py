"""Mandatory F02 resource gate: real data, isolated Linux workers, no sparse I/O."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
from tempfile import TemporaryDirectory
import time


def io_counts():
    return {k:int(v) for k,v in (line.split(":") for line in Path("/proc/self/io").read_text().splitlines())}


def worker(root: Path):
    from phase_tool.application import PhaseApplication
    from phase_tool.streaming import limits
    before = io_counts()
    started = time.perf_counter()
    application = PhaseApplication()
    response = application.publish_file(source_root=root/"source", source_locator="input.bin",
        target_root=root/"target", target_locator="output.bin", preparation_root=root/"prep",
        evidence_root=root/"evidence", request_id="resource-test", run_id="resource-test", publication_version="2.0")
    verified = application.inspect(evidence_root=root/"evidence", run_id="resource-test",
        root_bindings={"phase_result_root": root/"target"})
    elapsed = time.perf_counter()-started
    after = io_counts()
    files = [p for p in root.rglob("*") if p.is_file()]
    record = {"result":response.payload, "cross_inspect":verified.payload, "seconds":elapsed,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        "io_delta":{k:after[k]-before[k] for k in before},
        "retained_logical_bytes":sum(p.stat().st_size for p in files),
        "retained_allocated_bytes":sum(p.stat().st_blocks*512 for p in files),
        "limits":limits(), "technical_calls":{"publish_file":1, "independent_inspect_inside_publish":1, "cross_inspect":1}}
    print(json.dumps(record))
    return 0 if response.exit_code == 0 and verified.payload["target_verified"] else 1


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--output", type=Path)
    args=parser.parse_args()
    if args.worker:
        return worker(args.worker)
    if args.output is None:
        parser.error("--output required")
    records=[]
    for size in (64*1024*1024, 1024*1024*1024, 2*1024*1024*1024):
        with TemporaryDirectory(prefix="phase-resource-") as tmp:
            root=Path(tmp)
            for name in ("source","target","prep","evidence"):
                (root/name).mkdir()
            # A nonzero deterministic block written through normal filesystem I/O.
            block=bytes(range(256))*4096
            expected=hashlib.sha256()
            with (root/"source/input.bin").open("wb") as out:
                for _ in range(size//len(block)):
                    out.write(block)
                    expected.update(block)
                out.flush()
                os.fsync(out.fileno())
            info=(root/"source/input.bin").stat()
            assert info.st_size == size and info.st_blocks*512 >= size
            call=subprocess.run([sys.executable,__file__,"--worker",str(root)], text=True,
                                capture_output=True,timeout=600)
            if call.returncode:
                raise RuntimeError(call.stdout+call.stderr)
            item=json.loads(call.stdout)
            assert item["result"]["content_digest"] == "sha256:"+expected.hexdigest()
            assert item["result"]["content_length"] == size
            item.update(input_bytes=size, source_allocated_bytes=info.st_blocks*512,
                        source_digest="sha256:"+expected.hexdigest())
            records.append(item)
    delta=records[1]["peak_rss_bytes"]-records[0]["peak_rss_bytes"]
    result={"method":"Linux ru_maxrss in separate child processes; input generation outside measured processes; real non-sparse I/O",
            "runs":records,"peak_rss_growth_bytes":delta,"maximum_growth_bytes":128*1024*1024,
            "pass":delta<=128*1024*1024,"python":sys.version,
            "retention":"generated input/target/payloads are disposable; exact runtime results, digests, logical/physical I/O counters retained"}
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2))
    return 0 if result["pass"] else 1

if __name__=="__main__":
    raise SystemExit(main())
