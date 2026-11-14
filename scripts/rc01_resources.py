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


def checked_work_root(path: Path) -> Path:
    """Explicit existing fixture parent; never fall back to the system temp root."""
    lexical=Path(os.path.abspath(path))
    if lexical.resolve(strict=True)!=lexical or not lexical.is_dir():
        raise ValueError("--work-root must name an existing directory without aliases")
    return lexical


def resource_preflight(root: Path, output: Path):
    """Retain actual fixture scope checks BEFORE generating any large payload."""
    from phase_tool.installation import (qualify_host_authority_roots,
        _linux_filesystem_type, _linux_kernel_release)
    report={"resource_preflight_version":"1.0","qualified":False,"roots":{},"error":None,
        "scope":"Existing Host qualification only; no NTFS admission or resource PASS claim"}
    primary=None
    try:
        report["kernel"]=_linux_kernel_release().strip()
        roots={name:root/name for name in ("source","target","prep","evidence")}
        for name,path in roots.items():
            report["roots"][name]={"lexical":str(path),"resolved":str(path.resolve(strict=True)),
                "filesystem":_linux_filesystem_type(path)}
        qualify_host_authority_roots(roots)
        report["qualified"]=True
    except BaseException as error:
        primary=error
        report["error"]={"type":type(error).__name__,"code":getattr(error,"code",None),
            "details":getattr(error,"details",{})}
    try:
        encoded=(json.dumps(report,indent=2)+"\n").encode("utf-8")
        if len(encoded)>16384:raise ValueError("resource preflight report exceeds16KiB")
        output.write_bytes(encoded)
    except BaseException as error:
        if primary is None:raise
        try:primary.add_note("Resource preflight evidence unavailable: "+type(error).__name__)
        except BaseException:pass
    if primary is not None:raise primary
    return report


def worker(root: Path):
    from phase_tool.application import PhaseApplication
    from phase_tool.streaming import limits
    before = io_counts()
    started = time.perf_counter()
    class ObservedApplication(PhaseApplication):
        def __init__(self):
            super().__init__()
            self.observed_inspect_calls=0
        def inspect(self,**kwargs):
            self.observed_inspect_calls+=1
            return super().inspect(**kwargs)
    application = ObservedApplication()
    response = application.publish_file(source_root=root/"source", source_locator="input.bin",
        target_root=root/"target", target_locator="output.bin", preparation_root=root/"prep",
        evidence_root=root/"evidence", request_id="resource-test", run_id="resource-test", publication_version="2.0")
    inside_inspect_calls=application.observed_inspect_calls
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
        "limits":limits(), "technical_calls":{"publish_file":1, "independent_inspect_inside_publish":inside_inspect_calls, "cross_inspect":application.observed_inspect_calls-inside_inspect_calls}}
    print(json.dumps(record))
    return 0 if response.exit_code == 0 and verified.payload["target_verified"] else 1


def maximum_peak_rss_growth(records):
    """Compare every larger workload with the first (64 MiB) baseline."""
    return max(row["peak_rss_bytes"] for row in records[1:])-records[0]["peak_rss_bytes"]


def fail_worker(output: Path, report: dict, diagnostic: str):
    """The worker failure stays primary when retaining its report also fails."""
    primary=RuntimeError(diagnostic)
    try:
        output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    except BaseException as error:
        try:primary.add_note("Failed worker report unavailable: "+type(error).__name__)
        except BaseException:pass
    raise primary


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--work-root", type=Path, help="Explicit existing parent on a supported Host filesystem; no fallback")
    args=parser.parse_args()
    if args.worker:
        return worker(args.worker)
    if args.output is None or args.work_root is None:
        parser.error("--output and --work-root required")
    work_root=checked_work_root(args.work_root)
    records=[]
    for size in (64*1024*1024, 1024*1024*1024, 2*1024*1024*1024):
        with TemporaryDirectory(prefix="phase-resource-",dir=work_root) as tmp:
            root=Path(tmp)
            for name in ("source","target","prep","evidence"):
                (root/name).mkdir()
            resource_preflight(root,args.output.with_name(args.output.stem+"-preflight-"+str(size)+".json"))
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
                failed={"pass":False,"failed_input_bytes":size,"runs":records,"peak_rss_growth_bytes":None,
                    "maximum_growth_bytes":128*1024*1024,"work_root":str(work_root),
                    "failure":{"returncode":call.returncode,"stdout_tail":call.stdout[-65536:],
                        "stderr_tail":call.stderr[-65536:],"diagnostic_tail_limit":65536},
                    "retention":"Failed worker diagnostics; no missing workload or RSS acceptance is inferred"}
                fail_worker(args.output,failed,call.stdout+call.stderr)
            item=json.loads(call.stdout)
            assert item["result"]["content_digest"] == "sha256:"+expected.hexdigest()
            assert item["result"]["content_length"] == size
            item.update(input_bytes=size, source_allocated_bytes=info.st_blocks*512,
                        source_digest="sha256:"+expected.hexdigest())
            records.append(item)
    delta=maximum_peak_rss_growth(records)
    result={"method":"Linux ru_maxrss in separate child processes; input generation outside measured processes; real non-sparse I/O; growth=max(1GiB,2GiB peaks)-64MiB baseline",
            "runs":records,"peak_rss_growth_bytes":delta,"maximum_growth_bytes":128*1024*1024,
            "pass":delta<=128*1024*1024,"python":sys.version,"work_root":str(work_root),
            "retention":"generated input/target/payloads are disposable; exact runtime results, digests, logical/physical I/O counters retained"}
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2))
    return 0 if result["pass"] else 1

if __name__=="__main__":
    raise SystemExit(main())
