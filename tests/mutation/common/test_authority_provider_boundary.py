from __future__ import annotations

import json
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Callable

from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.installation import Installation, host_installation
from phase_tool.mutation.authority import AuthorityProvider, TargetAuthority

from phase_tool.registry import BundledRegistry

NOW = "2026-08-05T00:00:00Z"


class RecordingProvider:
    def __init__(self) -> None:
        self.delegate = host_installation().authority_provider
        self.authorities: list[tuple[Path, str]] = []
        self.locks: list[tuple[Path, str]] = []

    def open_authority(
        self,
        root: Path,
        locator: str,
        reparse_detector: Callable[[Path], bool] | None = None,
    ) -> TargetAuthority:
        self.authorities.append((Path(root), locator))
        return self.delegate.open_authority(root, locator, reparse_detector)

    def lock_target_root(self, root: Path, scope: str) -> AbstractContextManager[object]:
        self.locks.append((Path(root), scope))
        return self.delegate.lock_target_root(root, scope)


def _request(tmp_path: Path) -> tuple[PhaseRequest, Path, bytes]:
    registry = BundledRegistry.load()
    binding = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    target = tmp_path / "target"
    target.mkdir()
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        json.dumps(
            {
                "operation_id": "provider-boundary",
                "target_locator": "objects/item.bin",
                "input_binding": "payload",
                "idempotency_key": "provider-boundary",
            }
        ),
        encoding="utf-8",
    )
    content = b"provider-boundary-content"
    payload = tmp_path / "payload.bin"
    payload.write_bytes(content)
    return (
        PhaseRequest(
            contract_id=binding["id"],
            contract_version=binding["version"],
            contract_digest=binding["package_digest"],
            candidate_path=candidate,
            evidence_root=tmp_path / "evidence",
            run_id="provider-boundary",
            input_paths={"payload": payload},
            root_bindings={"fixture_result_root": target},
            timestamp=NOW,
        ),
        target,
        content,
    )


def test_host_installation_exposes_explicit_authority_provider() -> None:
    installation = host_installation()

    assert isinstance(installation.authority_provider, AuthorityProvider)


def test_core_rejects_unbound_installation_provider_before_mutation(tmp_path: Path) -> None:
    provider = RecordingProvider()
    assert isinstance(provider, AuthorityProvider)
    request, target, _content = _request(tmp_path)

    outcome = PhaseCore(installation=Installation(authority_provider=provider)).run(request, execute=True)

    assert outcome.exit_code != 0
    assert outcome.receipt["blockers"] == ["authority.guarantee_profile_unavailable"]
    assert not (target / "objects" / "item.bin").exists()
    assert provider.authorities == []
