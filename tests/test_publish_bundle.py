from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from phase_tool.application import PhaseApplication

pytestmark = pytest.mark.skipif(os.name != "posix", reason="qualified Linux bundle commit required")


def test_bundle_has_one_visible_commit_and_verifies_member_bytes(tmp_path: Path) -> None:
    roots = {name:tmp_path/name for name in ("source", "target", "prep", "evidence")}
    for root in roots.values():
        root.mkdir()
    (roots["source"]/"nested").mkdir()
    contents = {"a.bin": b"\x00\xffone", "nested/b.bin": b"two"}
    for name, data in contents.items():
        (roots["source"]/name).write_bytes(data)
    app = PhaseApplication()
    response = app.publish_bundle(
        source_root=roots["source"], members=list(contents),
        target_root=roots["target"], target_locator="dataset",
        preparation_root=roots["prep"], evidence_root=roots["evidence"],
        request_id="bundle-one", run_id="bundle-one",
    )
    result = response.payload
    assert response.exit_code == 0, result
    assert result["status"] == "verified" and result["target_verified"]
    assert result["member_count"] == 2
    assert result["total_length"] == sum(map(len, contents.values()))
    target = roots["target"]/"dataset"
    manifest_bytes = (target/"phase-bundle.json").read_bytes()
    assert result["bundle_digest"] == "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    manifest = json.loads(manifest_bytes)
    assert {item["path"] for item in manifest["members"]} == set(contents)
    for name, data in contents.items():
        assert (target/name).read_bytes() == data
    inspected = app.inspect(evidence_root=roots["evidence"], run_id="bundle-one",
        root_bindings={"phase_result_root":roots["target"]}).payload
    assert inspected["success"] and inspected["target_verified"], inspected
    assert inspected["receipt_digest"] == result["receipt_digest"]


def bundle_arguments(tmp_path: Path) -> dict:
    for name in ("source", "target", "prep", "evidence"):
        (tmp_path/name).mkdir()
    (tmp_path/"source/a.bin").write_bytes(b"a")
    (tmp_path/"source/b.bin").write_bytes(b"b")
    return {"source_root":tmp_path/"source", "members":["a.bin","b.bin"],
        "target_root":tmp_path/"target", "target_locator":"dataset",
        "preparation_root":tmp_path/"prep", "evidence_root":tmp_path/"evidence",
        "request_id":"bundle-test", "run_id":"bundle-test"}


def test_bundle_cli_real_stdio_and_cross_inspect(tmp_path: Path) -> None:
    import asyncio
    import subprocess
    import sys
    args = bundle_arguments(tmp_path)
    argv=[sys.executable,"-m","phase_tool","publish-bundle"]
    for key,value in args.items():
        if key == "members":
            for member in value:
                argv.extend(["--member",member])
        else:
            argv.extend(["--"+key.replace("_","-"),str(value)])
    completed=subprocess.run(argv,text=True,capture_output=True,timeout=30)
    assert completed.returncode == 0, completed.stderr + completed.stdout
    cli=json.loads(completed.stdout)
    async def exchange():
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        parameters=StdioServerParameters(command=sys.executable,args=["-m","phase_tool","mcp","serve","--stdio"])
        async with stdio_client(parameters) as (reader,writer):
            async with ClientSession(reader,writer) as session:
                await session.initialize()
                other={k:str(v) if isinstance(v,Path) else v for k,v in args.items()}
                other.update(target_locator="dataset-mcp",run_id="bundle-mcp",request_id="bundle-mcp")
                response=await session.call_tool("phase_publish_bundle",other)
                assert not response.isError, response
                verified=await session.call_tool("phase_inspect",{"evidence_root":str(args["evidence_root"]),"run_id":args["run_id"],"root_bindings":{"phase_result_root":str(args["target_root"])}})
                assert verified.structuredContent["target_verified"] is True
                return response.structuredContent
    mcp=asyncio.run(exchange())
    assert mcp["status"] == "verified", mcp
    assert mcp["bundle_digest"] == cli["bundle_digest"]


@pytest.mark.parametrize("members", [["a.bin","a.bin"],["a.bin","A.bin"],["../a.bin"],["/a.bin"],["a.bin","a.bin/child"],["phase-bundle.json"],["phase-owner.json"],["NUL.txt"],[]])
def test_unsafe_membership_never_creates_target(tmp_path: Path, members: list[str]) -> None:
    args=bundle_arguments(tmp_path)
    args["members"]=members
    result=PhaseApplication().publish_bundle(**args).payload
    assert result["status"] == "rejected_before_write", result
    assert result["mutation_attempted"] is False
    assert list(args["target_root"].iterdir()) == []


@pytest.mark.parametrize("damage",["missing","corrupt","extra","owner"])
def test_bundle_inspect_checks_contents_not_only_manifest(tmp_path: Path,damage: str) -> None:
    args=bundle_arguments(tmp_path)
    app=PhaseApplication()
    result=app.publish_bundle(**args).payload
    assert result["success"],result
    target=args["target_root"]/"dataset"
    if damage=="missing":
        (target/"b.bin").unlink()
    elif damage=="corrupt":
        (target/"b.bin").write_bytes(b"x")
    elif damage=="extra":
        (target/"extra.bin").write_bytes(b"x")
    else:
        (target/"phase-owner.json").write_bytes(b"{}")
    inspected=app.inspect(evidence_root=args["evidence_root"],run_id=args["run_id"],root_bindings={"phase_result_root":args["target_root"]}).payload
    assert not inspected["success"], inspected


def test_interrupt_before_commit_cannot_publish_incomplete_bundle(tmp_path: Path,monkeypatch) -> None:
    from phase_tool.mutation import bundle_create
    args=bundle_arguments(tmp_path)
    called=False
    def interrupt(parent_fd,source,destination):
        nonlocal called
        called=True
        assert not (args["target_root"]/"dataset").exists()
        assert (args["target_root"]/source/"a.bin").read_bytes()==b"a"
        raise OSError("injected interruption before final commit")
    monkeypatch.setattr(bundle_create,"_rename_noreplace",interrupt)
    result=PhaseApplication().publish_bundle(**args).payload
    assert called and not result["success"],result
    assert result["mutation_attempted"] is True
    assert not (args["target_root"]/"dataset").exists()
    assert list(args["target_root"].glob("phase-stage-*"))


def test_stage_creation_error_after_effect_is_not_no_mutation(tmp_path: Path,monkeypatch) -> None:
    from phase_tool.mutation import bundle_create
    args=bundle_arguments(tmp_path)
    mkdir=os.mkdir
    def fail_after_mkdir(path,*a,**kw):
        result=mkdir(path,*a,**kw)
        if str(path).startswith("phase-stage-"):
            raise OSError("injected error after stage creation")
        return result
    monkeypatch.setattr(bundle_create.os,"mkdir",fail_after_mkdir)
    result=PhaseApplication().publish_bundle(**args).payload
    assert list(args["target_root"].glob("phase-stage-*"))
    assert result["mutation_attempted"] is True,result
    assert result["status"] == "indeterminate",result


def test_bundle_commit_never_replaces_racing_destination(tmp_path: Path,monkeypatch) -> None:
    from phase_tool.mutation import bundle_create
    args=bundle_arguments(tmp_path)
    rename=bundle_create._rename_noreplace
    def race(parent_fd,source,destination):
        target=args["target_root"]/destination
        target.mkdir()
        (target/"foreign.txt").write_bytes(b"preserve")
        return rename(parent_fd,source,destination)
    monkeypatch.setattr(bundle_create,"_rename_noreplace",race)
    result=PhaseApplication().publish_bundle(**args).payload
    assert not result["success"] and not result["target_verified"],result
    assert (args["target_root"]/"dataset/foreign.txt").read_bytes()==b"preserve"
    assert not (args["target_root"]/"dataset/a.bin").exists()


def test_partial_member_write_has_exact_count_and_no_publication(tmp_path: Path,monkeypatch) -> None:
    from phase_tool.mutation import bundle_create
    args=bundle_arguments(tmp_path)
    (args["source_root"]/"a.bin").write_bytes(b"abcdef")
    write=os.write
    wrote=False
    def enospc(fd,data):
        nonlocal wrote
        for stage in args["target_root"].glob("phase-stage-*"):
            member=stage/"a.bin"
            if member.exists():
                a,b=os.fstat(fd),member.stat()
                if (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino):
                    if wrote:
                        raise OSError(28,"injected ENOSPC")
                    wrote=True
                    return write(fd,data[:1])
        return write(fd,data)
    monkeypatch.setattr(bundle_create.os,"write",enospc)
    result=PhaseApplication().publish_bundle(**args).payload
    assert wrote and not result["success"],result
    assert result["mutation_attempted"] is True
    stage=next(args["target_root"].glob("phase-stage-*"))
    assert (stage/"a.bin").read_bytes()==b"a"
    receipt=json.loads((args["evidence_root"]/".phase/runs/bundle-test/receipt.json").read_bytes())
    assert receipt["effect_receipts"][0]["bytes_written"] == sum(p.stat().st_size for p in stage.rglob("*") if p.is_file())
    assert not (args["target_root"]/"dataset").exists()


def test_inspect_rejects_fifo_metadata_without_blocking(tmp_path: Path) -> None:
    import subprocess
    import sys
    args=bundle_arguments(tmp_path)
    result=PhaseApplication().publish_bundle(**args).payload
    assert result["success"],result
    metadata=args["target_root"]/"dataset/phase-bundle.json"
    metadata.unlink()
    os.mkfifo(metadata)
    process=subprocess.run([sys.executable,"-m","phase_tool","inspect",
        "--evidence-root",str(args["evidence_root"]),"--run-id",args["run_id"],
        "--root","phase_result_root="+str(args["target_root"])],text=True,capture_output=True,timeout=5)
    assert process.returncode==10,process.stdout+process.stderr
    assert json.loads(process.stdout)["success"] is False


def test_bundle_metadata_hashing_obeys_metadata_limit(tmp_path: Path,monkeypatch) -> None:
    from phase_tool import streaming
    args=bundle_arguments(tmp_path)
    app=PhaseApplication()
    result=app.publish_bundle(**args).payload
    assert result["success"],result
    name=result["bundle_digest"].removeprefix("sha256:")
    original=streaming.hash_file
    def checked(path,maximum_bytes):
        if path.name==name:
            assert maximum_bytes<=streaming.REQUEST_LIMIT
        return original(path,maximum_bytes)
    monkeypatch.setattr(streaming,"hash_file",checked)
    inspected=app.inspect(evidence_root=args["evidence_root"],run_id=args["run_id"],root_bindings={"phase_result_root":args["target_root"]}).payload
    assert inspected["success"],inspected


def test_bundle_member_count_and_depth_limits() -> None:
    from phase_tool.bundle import MAX_MEMBERS, MAX_DEPTH, validate_members
    from phase_tool.errors import PhaseError
    assert len(validate_members([f"item-{i}" for i in range(MAX_MEMBERS)])) == MAX_MEMBERS
    with pytest.raises(PhaseError,match="bundle.member_count_limit"):
        validate_members([f"item-{i}" for i in range(MAX_MEMBERS+1)])
    with pytest.raises(PhaseError,match="bundle.reserved_or_deep_path"):
        validate_members(["/".join(["a"]*(MAX_DEPTH+1))])


@pytest.mark.parametrize("case",["file_limit","total_limit","wrong_total","unknown_field","wrong_version"])
def test_manifest_limits_are_strict_before_payload_access(case: str) -> None:
    from phase_tool.bundle import parse_manifest
    from phase_tool.canonical import canonical_bytes
    from phase_tool.errors import PhaseError
    manifest={"bundle_version":"1.0","members":[{"path":"a","length":0,"digest":"sha256:"+"0"*64}],"total_length":0}
    if case=="file_limit":
        manifest["members"][0]["length"]=2147483649
        manifest["total_length"]=2147483649
    elif case=="total_limit":
        manifest["members"]=[{"path":p,"length":2147483648,"digest":"sha256:"+"0"*64} for p in ("a","b","c")]
        manifest["total_length"]=6442450944
    elif case=="wrong_total":
        manifest["total_length"]=1
    elif case=="unknown_field":
        manifest["extra"]=True
    else:
        manifest["bundle_version"]="2.0"
    with pytest.raises(PhaseError):
        parse_manifest(canonical_bytes(manifest))
