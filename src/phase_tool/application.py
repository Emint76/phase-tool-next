from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as distribution_version
from pathlib import Path
import re
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any, Mapping

from . import __version__
from .canonical import canonical_bytes, profile_digest
from .core import PhaseCore, PhaseRequest
from .errors import PhaseError
from .inspection import inspect_run
from .installation import Installation, host_installation
from .registry import BundledRegistry, RegistrySnapshot


@dataclass(frozen=True)
class ApplicationResponse:
    """Transport-independent application response."""

    payload: dict[str, Any]
    exit_code: int = 0


class PhaseApplication:
    """Universal application boundary over the bundled registry and Phase Core."""

    def __init__(
        self,
        registry: RegistrySnapshot | None = None,
        installation: Installation | None = None,
    ) -> None:
        self.registry = registry or BundledRegistry.load()
        self.installation = installation or host_installation()

    def _binding(self, exact_binding: str) -> dict[str, str]:
        try:
            return self.registry.contract_bindings()[exact_binding]
        except KeyError as exc:
            raise PhaseError("application.contract_binding_not_found", exact_binding) from exc

    def contracts_list(self) -> ApplicationResponse:
        contracts = []
        for exact_binding, binding in sorted(self.registry.contract_bindings().items()):
            resolved = self.registry.resolve_contract(
                binding["id"],
                binding["version"],
                binding["package_digest"],
                core_version=__version__,
            )
            contracts.append(
                {
                    "contract_binding": exact_binding,
                    "id": binding["id"],
                    "version": binding["version"],
                    "package_digest": binding["package_digest"],
                    "operation_intent": resolved.document["operation"]["intent"],
                }
            )
        return ApplicationResponse({"contracts": contracts, "registry_snapshot_digest": self.registry.digest})

    def contract_describe(self, exact_binding: str) -> ApplicationResponse:
        try:
            binding = self._binding(exact_binding)
            resolved = self.registry.resolve_contract(
                binding["id"],
                binding["version"],
                binding["package_digest"],
                core_version=__version__,
            )
            return ApplicationResponse(
                {
                    "contract_binding": exact_binding,
                    "package_digest": resolved.package_digest,
                    "registry_snapshot_digest": resolved.registry_snapshot_digest,
                    "contract": resolved.document,
                    "package_artifacts": list(resolved.entry.get("package_artifacts", [])),
                }
            )
        except (PhaseError, OSError, ValueError) as exc:
            code = exc.code if isinstance(exc, PhaseError) else "application.failure"
            return ApplicationResponse(
                {"success": False, "error": code, "blockers": [code], "exit_code": 10},
                10,
            )

    def run(
        self,
        operation: str,
        *,
        contract_binding: str,
        candidate_path: Path | None = None,
        candidate: Mapping[str, Any] | None = None,
        evidence_root: Path,
        run_id: str,
        input_paths: Mapping[str, Path],
        root_bindings: Mapping[str, Path],
        timestamp: str | None = None,
        maximum_candidate_bytes: int = 1_048_576,
        contract_digest: str | None = None,
    ) -> ApplicationResponse:
        try:
            if (candidate_path is None) == (candidate is None):
                raise PhaseError("application.exactly_one_candidate_input_required")
            if candidate is not None:
                candidate_bytes = canonical_bytes(candidate)
                if len(candidate_bytes) > maximum_candidate_bytes:
                    raise PhaseError(
                        "candidate.too_large",
                        f"candidate exceeds {maximum_candidate_bytes} bytes",
                    )
                with TemporaryDirectory(prefix="phase-candidate-") as directory:
                    with NamedTemporaryFile(mode="wb", suffix=".json", dir=directory, delete=False) as temporary:
                        temporary.write(candidate_bytes)
                        materialized = Path(temporary.name)
                    return self.run(
                        operation,
                        contract_binding=contract_binding,
                        candidate_path=materialized,
                        evidence_root=evidence_root,
                        run_id=run_id,
                        input_paths=input_paths,
                        root_bindings=root_bindings,
                        timestamp=timestamp,
                        maximum_candidate_bytes=maximum_candidate_bytes,
                        contract_digest=contract_digest,
                    )
            assert candidate_path is not None
            binding = self._binding(contract_binding)
            if contract_digest is not None and contract_digest != binding["package_digest"]:
                raise PhaseError("registry.entry_not_found", contract_binding)
            request = PhaseRequest(
                contract_id=binding["id"],
                contract_version=binding["version"],
                contract_digest=binding["package_digest"],
                candidate_path=Path(candidate_path),
                evidence_root=Path(evidence_root),
                run_id=run_id,
                input_paths={name: Path(value) for name, value in input_paths.items()},
                root_bindings={name: Path(value) for name, value in root_bindings.items()},
                timestamp=timestamp,
                maximum_candidate_bytes=maximum_candidate_bytes,
            )
            outcome = PhaseCore(self.registry, self.installation).run(
                request,
                execute=operation == "execute",
            )
            blockers = outcome.receipt["blockers"]
            payload = self._command_payload(
                operation,
                success=outcome.exit_code == 0,
                run_id=outcome.run_id,
                terminal_status=outcome.receipt["terminal_status"],
                execution_disposition=outcome.receipt["execution_disposition"],
                mutation_attempted=outcome.receipt["mutation_attempted"],
                effect_plan_digest=outcome.effect_plan_digest,
                intent_digest=profile_digest("intent", outcome.intent) if outcome.intent is not None else None,
                receipt_digest=outcome.receipt_digest,
                target_verified=None,
                blockers=blockers,
                error=None if outcome.exit_code == 0 else blockers[0],
                exit_code=outcome.exit_code,
            )
            return ApplicationResponse(payload, outcome.exit_code)
        except (PhaseError, OSError, ValueError) as exc:
            return self._failure(operation, exc)

    def inspect(
        self,
        *,
        evidence_root: Path,
        run_id: str,
        root_bindings: Mapping[str, Path],
    ) -> ApplicationResponse:
        try:
            inspected = inspect_run(evidence_root, run_id, root_bindings=root_bindings)
            return ApplicationResponse(self._command_payload(
                "inspect",
                success=True,
                run_id=inspected["run_id"],
                terminal_status=inspected["terminal_status"],
                execution_disposition=inspected["execution_disposition"],
                mutation_attempted=inspected["mutation_attempted"],
                effect_plan_digest=inspected["effect_plan_digest"],
                intent_digest=inspected["intent_digest"],
                receipt_digest=inspected["receipt_digest"],
                target_verified=inspected["target_verified"],
                blockers=[],
                error=None,
                exit_code=0,
            ))
        except (PhaseError, OSError, ValueError) as exc:
            return self._failure("inspect", exc)

    @staticmethod
    def _command_payload(
        command: str,
        *,
        success: bool,
        run_id: str | None,
        terminal_status: str | None,
        execution_disposition: str | None,
        mutation_attempted: bool,
        effect_plan_digest: str | None,
        intent_digest: str | None,
        receipt_digest: str | None,
        target_verified: bool | None,
        blockers: list[str],
        error: str | None,
        exit_code: int,
    ) -> dict[str, Any]:
        return {
            "stage3_command_result_version": "1.0",
            "command": command,
            "success": success,
            "run_id": run_id,
            "terminal_status": terminal_status,
            "execution_disposition": execution_disposition,
            "mutation_attempted": mutation_attempted,
            "effect_plan_digest": effect_plan_digest,
            "intent_digest": intent_digest,
            "receipt_digest": receipt_digest,
            "target_verified": target_verified,
            "blockers": blockers,
            "error": error,
            "exit_code": exit_code,
        }

    def _failure(self, operation: str, exc: Exception) -> ApplicationResponse:
        code = exc.code if isinstance(exc, PhaseError) else "cli.failure"
        return ApplicationResponse(self._command_payload(
            operation,
            success=False,
            run_id=None,
            terminal_status="rejected",
            execution_disposition="not_executed",
            mutation_attempted=False,
            effect_plan_digest=None,
            intent_digest=None,
            receipt_digest=None,
            target_verified=None,
            blockers=[code],
            error=code,
            exit_code=10,
        ), 10)

    def doctor(self) -> ApplicationResponse:
        contracts = self.contracts_list().payload["contracts"]
        try:
            sdk_version = distribution_version("mcp")
            stable = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", sdk_version)
            compatible = bool(
                stable
                and int(stable.group(1)) == 1
                and int(stable.group(2)) >= 26
            )
        except (PackageNotFoundError, ValueError):
            sdk_version = None
            compatible = False
        success = bool(contracts) and compatible
        return ApplicationResponse(
            {
                "success": success,
                "version": __version__,
                "registry": {
                    "status": "ok" if contracts else "error",
                    "snapshot_digest": self.registry.digest,
                    "contract_count": len(contracts),
                },
                "mcp_sdk": {
                    "distribution": "mcp",
                    "version": sdk_version,
                    "required_range": ">=1.26,<2",
                    "compatible": compatible,
                },
            },
            0 if success else 10,
        )
