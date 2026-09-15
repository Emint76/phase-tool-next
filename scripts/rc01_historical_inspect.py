"""Read-only byte-preserving inspection of explicitly supplied old run bundles."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.canonical import parse_json_bytes,profile_digest


def hashes(root: Path):
    records={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink(): raise RuntimeError('historical symlink forbidden')
        if p.is_file(): records[str(p.relative_to(root))]=hashlib.sha256(p.read_bytes()).hexdigest()
    return records


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',action='append',type=Path,required=True,
        help='Explicit historical directory containing evidence/ and target/')
    parser.add_argument('--expected-runs',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); rows=[]; manifests={}
    for source in args.source:
        before=hashes(source); app=PhaseApplication()
        for path in sorted((source/'evidence/.phase/runs').glob('*/receipt.json')):
            receipt=parse_json_bytes(path.read_bytes())
            assert receipt['core']['version']=='1.0.0',receipt['core']
            expected=profile_digest('receipt',receipt)
            result=app.inspect(evidence_root=source/'evidence',run_id=path.parent.name,
                root_bindings={'phase_result_root':source/'target'}).payload
            assert result['success'] and result['target_verified'] and result['receipt_digest']==expected,result
            rows.append({'source':str(source),'run_id':path.parent.name,'old_core':receipt['core'],
                'contract':receipt['contract'],'receipt_digest':expected,'result':result})
        after=hashes(source); assert before==after,'historical bytes changed'
        manifests[str(source)]=before
    assert len(rows)==args.expected_runs,(len(rows),args.expected_runs)
    output={'success':True,'count':len(rows),'original_bytes_unchanged':True,
        'method':'current installed inspector, explicit relocated read-only evidence and targets; no old execution rerun',
        'runs':rows,'source_sha256':manifests}
    args.output.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'success':True,'count':len(rows),'original_bytes_unchanged':True}))
    return 0
if __name__=='__main__': raise SystemExit(main())
