"""Real F03 gate: 256 distinct 1 MiB files, complete byte verification."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
from tempfile import TemporaryDirectory
import time

from phase_tool.application import PhaseApplication


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    with TemporaryDirectory(prefix="phase-bundle-resource-") as temporary:
        root=Path(temporary)
        for name in ("source","target","prep","evidence"):
            (root/name).mkdir()
        expected={}
        for index in range(256):
            name=f"member-{index:04d}.bin"
            block=(index.to_bytes(4,"big")+bytes(range(252)))*4096
            assert len(block)==1048576
            with (root/"source"/name).open("wb") as output:
                output.write(block)
                output.flush()
                os.fsync(output.fileno())
            info=(root/"source"/name).stat()
            assert info.st_size==1048576 and info.st_blocks*512>=info.st_size
            expected[name]="sha256:"+hashlib.sha256(block).hexdigest()
        def counters():
            return {k:int(v) for k,v in (line.split(":") for line in Path("/proc/self/io").read_text().splitlines())}
        before=counters()
        started=time.perf_counter()
        app=PhaseApplication()
        result=app.publish_bundle(source_root=root/"source",members=list(expected),
            target_root=root/"target",target_locator="dataset",preparation_root=root/"prep",
            evidence_root=root/"evidence",request_id="bundle-resource",run_id="bundle-resource",publication_version="2.0").payload
        assert result["success"],result
        inspected=app.inspect(evidence_root=root/"evidence",run_id="bundle-resource",
            root_bindings={"phase_result_root":root/"target"}).payload
        assert inspected["success"] and inspected["target_verified"],inspected
        for name,digest in expected.items():
            assert "sha256:"+hashlib.sha256((root/"target/dataset"/name).read_bytes()).hexdigest()==digest
        elapsed=time.perf_counter()-started
        after=counters()
        files=[path for path in root.rglob("*") if path.is_file()]
        summary={"pass":True,"member_count":len(expected),"total_bytes":256*1048576,
            "seconds":elapsed,"peak_rss_bytes":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            "io_delta":{k:after[k]-before[k] for k in before},
            "retained_logical_bytes":sum(p.stat().st_size for p in files),
            "result":result,"cross_inspect":inspected,"source_member_digests":expected,
            "method":"real full allocated writes and fsync; Phase verify plus independent hashlib over each target member; no sparse main inputs",
            "retention":"generated payloads disposable; exact hashes, results and measured counters retained"}
        args.output.write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({k:v for k,v in summary.items() if k!="source_member_digests"},indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
