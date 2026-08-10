from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import phase_tool.evidence as evidence_module
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.evidence import EvidenceStore, iter_run_artifacts
from phase_tool.freeze import copy_and_hash
from phase_tool.inspection import inspect_run
from phase_tool.installation import Installation
from phase_tool.mutation.guarantees import registered_profile_binding
from phase_tool.mutation.platform import HostAuthorityProvider
from phase_tool.registry import BundledRegistry


class _TestInstallation(Installation):
    def qualify_authority_roots(self, root_bindings: dict[str, Path]) -> None:
        del root_bindings


def _test_installation() -> Installation:
    return _TestInstallation(
        authority_provider=HostAuthorityProvider(),
        authority_profile_binding=registered_profile_binding("phase.posix.authority.v1@1.0.0"),
    )


def _partial_then_fail_writer(original_write, injected: list[bool]):
    def write(descriptor: int, data: memoryview) -> int:
        injected.append(True)
        original_write(descriptor, data[: min(5, len(data))])
        raise OSError("controlled partial evidence write")

    return write


def test_initialization_failure_before_run_reservation_allows_same_run_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    run_root = evidence_root / ".phase" / "runs" / "retryable-init"
    original_makedirs = evidence_module.os.makedirs

    def fail_lock_initialization(path: object, *args: object, **kwargs: object) -> None:
        if Path(str(path)).name == "locks":
            raise OSError("controlled lock-root initialization failure")
        original_makedirs(path, *args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(evidence_module.os, "makedirs", fail_lock_initialization)
        with pytest.raises(PhaseError) as error:
            EvidenceStore(evidence_root, "retryable-init")

    assert error.value.code == "evidence.initialization_failed"
    assert not run_root.exists()

    store = EvidenceStore(evidence_root, "retryable-init")
    assert store.run_root.samefile(run_root)
    assert run_root.is_dir()


def test_preexisting_run_is_never_reclaimed_as_initialization_debris(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    existing = EvidenceStore(evidence_root, "durable-run")
    receipt = existing.run_root / "receipt.json"
    receipt.write_bytes(b"truthful-existing-evidence")

    with pytest.raises(PhaseError) as error:
        EvidenceStore(evidence_root, "durable-run")

    assert error.value.code == "evidence.run_exists"
    assert receipt.read_bytes() == b"truthful-existing-evidence"


def test_post_reservation_identity_uncertainty_fails_closed_without_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    run_root = evidence_root / ".phase" / "runs" / "post-reservation-failure"
    original_stat = evidence_module.os.stat

    def fail_run_identity(path: object, *args: object, **kwargs: object):
        candidate = Path(str(path))
        if candidate.name == run_root.name and candidate.parent.name == "runs":
            raise OSError("controlled run identity failure")
        return original_stat(path, *args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(evidence_module.os, "stat", fail_run_identity)
        with pytest.raises(PhaseError) as error:
            EvidenceStore(evidence_root, run_root.name)

    assert error.value.code == "evidence.initialization_failed"
    assert run_root.is_dir()
    with pytest.raises(PhaseError) as retry_error:
        EvidenceStore(evidence_root, run_root.name)
    assert retry_error.value.code == "evidence.run_exists"


def test_cleanup_refuses_authoritative_or_identity_rebound_run(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    authoritative = EvidenceStore(evidence_root, "authoritative")
    authoritative.write_canonical("intent.json", {"state": "authoritative"})
    (authoritative.run_root / "intent.json").unlink()
    assert authoritative.release_unpublished_run() is False
    assert authoritative.run_root.is_dir()

    rebound = EvidenceStore(evidence_root, "identity-rebound")
    displaced = rebound.run_root.with_name("identity-rebound-displaced")
    rebound.run_root.rename(displaced)
    rebound.run_root.mkdir()
    (rebound.run_root / "foreign.json").write_bytes(b"foreign")

    assert rebound.release_unpublished_run() is False
    assert (rebound.run_root / "foreign.json").read_bytes() == b"foreign"
    assert displaced.is_dir()


def test_release_identity_race_preserves_both_owned_and_foreign_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", "release-race")
    store.write_canonical("attachments/effect-plan.json", {"owned": True})
    owned_survives = store.runs_root / ".owned-survives"
    moved_foreign: list[Path] = []
    original_rename = evidence_module.os.rename

    def replace_source_before_claim(source: object, target: object) -> None:
        original_rename(source, owned_survives)
        source_path = Path(str(source))
        source_path.mkdir()
        (source_path / "foreign.json").write_bytes(b"foreign")
        target_path = Path(str(target))
        original_rename(source, target)
        moved_foreign.append(target_path)

    with monkeypatch.context() as patcher:
        patcher.setattr(evidence_module.os, "rename", replace_source_before_claim)
        assert store.release_unpublished_run() is False

    assert (owned_survives / "attachments" / "effect-plan.json").is_file()
    assert len(moved_foreign) == 1
    assert (moved_foreign[0] / "foreign.json").read_bytes() == b"foreign"
    assert store.run_root.exists()


@pytest.mark.parametrize("artifact_kind", ["run", "attachment", "blob"])
def test_partial_evidence_write_never_publishes_canonical_artifact(
    artifact_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", f"partial-{artifact_kind}")
    value = {"artifact": artifact_kind, "state": "complete"}
    blob = canonical_bytes(value)
    if artifact_kind == "run":
        path = store.run_root / "receipt.json"
        write = lambda: store.write_canonical("receipt.json", value)
    elif artifact_kind == "attachment":
        path = store.attachment_root / "effect-plan.json"
        write = lambda: store.write_canonical("attachments/effect-plan.json", value)
    else:
        path = store.blob_root / digest_bytes(blob).removeprefix("sha256:")
        write = lambda: store.write_blob_exact(digest_bytes(blob), blob)

    injected: list[bool] = []
    original_write = evidence_module.os.write
    with monkeypatch.context() as patcher:
        patcher.setattr(
            evidence_module.os,
            "write",
            _partial_then_fail_writer(original_write, injected),
        )
        with pytest.raises(OSError, match="controlled partial evidence write"):
            write()

    assert injected
    assert not path.exists()

    write()
    assert path.read_bytes() == blob


def test_partial_frozen_blob_write_is_not_published_under_digest_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "payload.bin"
    payload = b"complete frozen payload"
    source.write_bytes(payload)
    blob_root = tmp_path / "evidence" / ".phase" / "runs" / "freeze" / "blobs"
    destination = blob_root / digest_bytes(payload).removeprefix("sha256:")

    injected: list[bool] = []
    original_write = evidence_module.os.write
    with monkeypatch.context() as patcher:
        patcher.setattr(
            evidence_module.os,
            "write",
            _partial_then_fail_writer(original_write, injected),
        )
        with pytest.raises(OSError, match="controlled partial evidence write"):
            copy_and_hash("payload", source_root, source.name, blob_root, frozen_at="2026-08-10T00:00:00Z")

    assert injected
    assert not destination.exists()

    frozen = copy_and_hash("payload", source_root, source.name, blob_root, frozen_at="2026-08-10T00:00:00Z")
    assert frozen.blob_path == destination
    assert destination.read_bytes() == payload


def test_failed_progress_replacement_preserves_last_complete_canonical_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", "progress-replacement")
    previous = {"completed": ["effect.0"]}
    replacement = {"completed": ["effect.0", "effect.1"]}
    path, _ = store.replace_attachment_canonical("ordered-effect-progress.json", previous)
    previous_bytes = path.read_bytes()

    injected: list[bool] = []
    original_write = evidence_module.os.write
    with monkeypatch.context() as patcher:
        patcher.setattr(
            evidence_module.os,
            "write",
            _partial_then_fail_writer(original_write, injected),
        )
        with pytest.raises(OSError, match="controlled partial evidence write"):
            store.replace_attachment_canonical("ordered-effect-progress.json", replacement)

    assert injected
    assert path.read_bytes() == previous_bytes


@pytest.mark.parametrize("failure_point", ["fsync", "link"])
def test_failure_before_exclusive_publication_leaves_canonical_name_absent(
    failure_point: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", f"publication-{failure_point}")
    path = store.run_root / "intent.json"
    value = {"state": "complete"}

    with monkeypatch.context() as patcher:
        if failure_point == "fsync":
            patcher.setattr(
                evidence_module.os,
                "fsync",
                lambda _descriptor: (_ for _ in ()).throw(OSError("controlled fsync failure")),
            )
        else:
            patcher.setattr(
                evidence_module.os,
                "link",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("controlled link failure")),
            )
            patcher.setattr(
                evidence_module,
                "_link_anonymous",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("controlled link failure")),
            )
        with pytest.raises(OSError, match=f"controlled {failure_point} failure"):
            store.write_canonical("intent.json", value)

    assert not path.exists()
    store.write_canonical("intent.json", value)
    assert path.read_bytes() == canonical_bytes(value)


def test_replace_failure_preserves_previous_progress_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", "replace-failure")
    path, _ = store.replace_attachment_canonical("ordered-effect-progress.json", {"completed": []})
    previous = path.read_bytes()

    with monkeypatch.context() as patcher:
        patcher.setattr(
            evidence_module.os,
            "replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("controlled replace failure")),
        )
        with pytest.raises(OSError, match="controlled replace failure"):
            store.replace_attachment_canonical("ordered-effect-progress.json", {"completed": ["effect.0"]})

    assert path.read_bytes() == previous


def test_directory_fsync_failure_leaves_only_complete_exclusive_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", "directory-fsync-create")
    path = store.run_root / "intent.json"

    with monkeypatch.context() as patcher:
        patcher.setattr(
            evidence_module,
            "_fsync_directory",
            lambda _path: (_ for _ in ()).throw(OSError("controlled directory fsync failure")),
        )
        patcher.setattr(
            evidence_module,
            "_fsync_pinned_directory",
            lambda *_args: (_ for _ in ()).throw(OSError("controlled directory fsync failure")),
        )
        with pytest.raises(OSError, match="controlled directory fsync failure"):
            store.write_canonical("intent.json", {"state": "complete"})

    assert path.read_bytes() == canonical_bytes({"state": "complete"})
    store.write_or_verify_canonical("intent.json", {"state": "complete"})


def test_directory_fsync_failure_leaves_only_complete_progress_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", "directory-fsync-replace")
    path, _ = store.replace_attachment_canonical("ordered-effect-progress.json", {"completed": []})
    replacement = {"completed": ["effect.0"]}
    original_fsync_directory = evidence_module._fsync_directory
    fallback_calls: list[Path] = []

    def fail_after_fallback_replace(directory: Path) -> None:
        fallback_calls.append(directory)
        if len(fallback_calls) == 2:
            raise OSError("controlled directory fsync failure")
        original_fsync_directory(directory)

    with monkeypatch.context() as patcher:
        patcher.setattr(evidence_module, "_fsync_directory", fail_after_fallback_replace)
        patcher.setattr(
            evidence_module,
            "_fsync_pinned_directory",
            lambda *_args: (_ for _ in ()).throw(OSError("controlled directory fsync failure")),
        )
        with pytest.raises(OSError, match="controlled directory fsync failure"):
            store.replace_attachment_canonical("ordered-effect-progress.json", replacement)

    assert path.read_bytes() == canonical_bytes(replacement)


def test_incomplete_temporary_artifact_is_not_inspectable_or_enumerated(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    store = EvidenceStore(evidence_root, "incomplete-run")
    temporary = store.run_root / ".intent.json.crashed.tmp"
    temporary.write_bytes(b'{"partial"')

    assert iter_run_artifacts(evidence_root / ".phase" / "runs", "intent.json") == []
    with pytest.raises(PhaseError) as error:
        inspect_run(evidence_root, "incomplete-run")
    assert error.value.code == "inspection.missing_artifact"


def test_concurrent_identical_create_publishes_one_complete_canonical_artifact(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence", "concurrent-identical")
    value = {"state": "complete", "writer": "identical"}

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(lambda _index: store.write_or_verify_canonical("intent.json", value), range(16)))

    path = store.run_root / "intent.json"
    assert all(result_path == path for result_path, _digest in results)
    assert {digest for _result_path, digest in results} == {digest_bytes(canonical_bytes(value))}
    assert path.read_bytes() == canonical_bytes(value)


@pytest.mark.parametrize("publication_kind", ["exclusive", "replace"])
def test_cleanup_never_unlinks_a_recreated_foreign_temporary(
    publication_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EvidenceStore(tmp_path / "evidence", f"temp-provenance-{publication_kind}")
    foreign_bytes = b"foreign temporary bytes"
    recreated: list[Path] = []

    with monkeypatch.context() as fallback:
        fallback.setattr(evidence_module, "_open_anonymous_staging", lambda _parent: None)
        if publication_kind == "exclusive":
            canonical = store.run_root / "intent.json"
            value = {"state": "complete"}
            original_link = evidence_module.os.link

            def publish_then_recreate(source: object, target: object, **kwargs: object) -> None:
                original_link(source, target, **kwargs)
                evidence_module.os.unlink(source)
                temporary = Path(str(source))
                temporary.write_bytes(foreign_bytes)
                recreated.append(temporary)

            fallback.setattr(evidence_module.os, "link", publish_then_recreate)
            store.write_canonical("intent.json", value)
            expected = canonical_bytes(value)
        else:
            canonical, _ = store.replace_attachment_canonical("ordered-effect-progress.json", {"completed": []})
            value = {"completed": ["effect.0"]}
            original_replace = evidence_module.os.replace

            def replace_then_recreate(source: object, target: object, **kwargs: object) -> None:
                original_replace(source, target, **kwargs)
                temporary = Path(str(source))
                temporary.write_bytes(foreign_bytes)
                recreated.append(temporary)

            fallback.setattr(evidence_module.os, "replace", replace_then_recreate)
            store.replace_attachment_canonical("ordered-effect-progress.json", value)
            expected = canonical_bytes(value)

    assert canonical.read_bytes() == expected
    assert len(recreated) == 1
    assert recreated[0].read_bytes() == foreign_bytes


def test_pre_intent_evidence_failure_releases_only_the_current_run_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        '{"expected_head":null,"idempotency_key":"atomic-retry","record":{"value":1},'
        '"record_id":"record-1","stream_id":"alpha","target_locator":"streams/alpha.jsonl"}',
        encoding="utf-8",
    )
    target = tmp_path / "target"
    target.mkdir()
    evidence_root = tmp_path / "evidence"
    binding = BundledRegistry.load().contract_bindings()["fixture_append.v1@1.0.0"]
    request = PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=evidence_root,
        run_id="pre-intent-retry",
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp="2026-08-10T00:00:00Z",
    )
    original = EvidenceStore.write_canonical

    def fail_plan_write(store: EvidenceStore, relative: str, value: object):
        if relative == "attachments/effect-plan.json":
            raise OSError("controlled pre-intent evidence failure")
        return original(store, relative, value)

    with monkeypatch.context() as patcher:
        patcher.setattr(EvidenceStore, "write_canonical", fail_plan_write)
        with pytest.raises(OSError, match="controlled pre-intent evidence failure"):
            PhaseCore(installation=_test_installation()).run(request)

    run_root = evidence_root / ".phase" / "runs" / request.run_id
    assert not run_root.exists()
    abandoned = list((evidence_root / ".phase" / "runs").glob(f".abandoned-{request.run_id}-*"))
    assert len(abandoned) == 1
    assert iter_run_artifacts(evidence_root / ".phase" / "runs", "intent.json") == []

    retry = PhaseCore(installation=_test_installation()).run(request)
    assert retry.exit_code == 0
    assert (run_root / "intent.json").is_file()
    assert (run_root / "receipt.json").is_file()
