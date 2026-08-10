from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import phase_tool.application as application_module
import phase_tool.core as core_module
from phase_tool.application import PhaseApplication
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.inspection import inspect_run as real_inspect_run
from phase_tool.installation import Installation
from phase_tool.registry import BundledRegistry, RegistrySnapshot

NOW = "2026-08-10T00:00:00Z"


class _RejectingAuthorityProvider:
    def open_authority(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("append must not open provider-backed authority")

    def lock_target_root(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("append must not acquire provider-backed root lock")


class _TestInstallation(Installation):
    def qualify_authority_roots(self, root_bindings: dict[str, Path]) -> None:
        pass


def _custom_registry() -> RegistrySnapshot:
    bundled = BundledRegistry.load()
    document = bundled.to_document()
    document["injected_snapshot_marker"] = "registry-lifecycle-regression"
    custom = RegistrySnapshot.from_document(document, BundledRegistry.resources())
    assert custom.digest != bundled.digest
    return custom


def _append_request(tmp_path: Path, registry: RegistrySnapshot, *, run_id: str) -> PhaseRequest:
    binding = registry.contract_bindings()["fixture_append.v1@1.0.0"]
    candidate = tmp_path / "append-candidate.json"
    candidate.write_text(
        json.dumps(
            {
                "stream_id": "alpha",
                "target_locator": "streams/alpha.jsonl",
                "record_id": "record-1",
                "expected_head": None,
                "record": {"value": 1},
                "idempotency_key": "registry-lifecycle-key",
            }
        ),
        encoding="utf-8",
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "streams").mkdir()
    return PhaseRequest(
        contract_id=binding["id"],
        contract_version=binding["version"],
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=tmp_path / "evidence",
        run_id=run_id,
        input_paths={},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )


def _recording_inspector(seen: list[RegistrySnapshot | None]):
    def inspect(
        evidence_root: Path,
        run_id: str,
        registry: RegistrySnapshot | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        seen.append(registry)
        return real_inspect_run(evidence_root, run_id, registry=registry, **kwargs)

    return inspect


def _forbid_bundled_fallback() -> RegistrySnapshot:
    raise AssertionError("BundledRegistry.load() must not run after registry injection")


def test_idempotency_inspection_preserves_injected_registry_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _custom_registry()
    installation = _TestInstallation(authority_provider=_RejectingAuthorityProvider())  # type: ignore[arg-type]
    request = _append_request(tmp_path, registry, run_id="registry-prior")
    first = PhaseCore(registry, installation).run(request, execute=True)
    assert first.receipt["terminal_status"] == "succeeded_verified", first.receipt
    assert first.receipt["evidence"]["finalization_status"] == "finalized"

    seen: list[RegistrySnapshot | None] = []
    monkeypatch.setattr(core_module, "inspect_run", _recording_inspector(seen))
    monkeypatch.setattr(BundledRegistry, "load", _forbid_bundled_fallback)

    repeated = PhaseCore(registry, installation).run(
        replace(request, run_id="registry-repeated"),
        execute=True,
    )

    assert repeated.receipt["execution_disposition"] == "reused_existing"
    assert seen == [registry]


def test_application_inspect_preserves_injected_registry_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _custom_registry()
    request = _append_request(tmp_path, registry, run_id="registry-application")
    installation = _TestInstallation(authority_provider=_RejectingAuthorityProvider())  # type: ignore[arg-type]
    outcome = PhaseCore(registry, installation).run(request)
    assert outcome.receipt["terminal_status"] == "validated_planned", outcome.receipt

    application = PhaseApplication(registry=registry, installation=installation)
    seen: list[RegistrySnapshot | None] = []
    monkeypatch.setattr(application_module, "inspect_run", _recording_inspector(seen))
    monkeypatch.setattr(BundledRegistry, "load", _forbid_bundled_fallback)

    response = application.inspect(
        evidence_root=request.evidence_root,
        run_id=request.run_id,
        root_bindings=request.root_bindings,
    )

    assert response.exit_code == 0
    assert response.payload["terminal_status"] == "validated_planned"
    assert seen == [registry]
