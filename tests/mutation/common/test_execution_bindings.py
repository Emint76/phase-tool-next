from __future__ import annotations

import json
import inspect
import os
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

import pytest
from jsonschema.exceptions import ValidationError

import phase_tool.installation as installation_module
from phase_tool.canonical import canonical_bytes, digest_bytes, profile_digest
from phase_tool.core import CoreFaults, PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.evidence import validate_receipt
from phase_tool.inspection import inspect_run
from phase_tool.installation import Installation, host_installation
from phase_tool.mutation import (
    AppendRecordFaults,
    BrokerFaults,
    ContentAddressedCopyFaults,
    EffectBroker,
    ExclusiveCreateFaults,
    ObjectStorePublishFaults,
)
from phase_tool.mutation.archive_then_publish import ArchiveThenPublishFaults
from phase_tool.mutation.platform import HostAuthorityProvider
from phase_tool.mutation.guarantees import GuaranteeProfileBinding
from phase_tool.registry import BundledRegistry, RegistrySnapshot

NOW = "2026-08-05T00:00:00Z"


def _create_request(tmp_path: Path, *, run_id: str) -> PhaseRequest:
    registry = BundledRegistry.load()
    contract = registry.contract_bindings()["fixture_create.v1@1.0.0"]
    target = tmp_path / "target"
    target.mkdir()
    (target / "objects").mkdir()
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        json.dumps(
            {
                "operation_id": "binding-operation",
                "target_locator": "objects/item.bin",
                "input_binding": "payload",
                "idempotency_key": "binding-key",
            }
        ),
        encoding="utf-8",
    )
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"bound implementation payload")
    return PhaseRequest(
        contract_id="fixture_create.v1",
        contract_version="1.0.0",
        contract_digest=contract["package_digest"],
        candidate_path=candidate,
        evidence_root=tmp_path / "evidence",
        run_id=run_id,
        input_paths={"payload": payload},
        root_bindings={"fixture_result_root": target},
        timestamp=NOW,
    )


def _expected_authority(binding: GuaranteeProfileBinding) -> dict[str, object]:
    return {
        "usage": "provider_backed",
        "profile": {
            "id": binding.id,
            "version": binding.version,
            "descriptor_digest": binding.descriptor_digest,
        },
        "provider": {
            "id": binding.implementation_id,
            "version": binding.implementation_version,
            "artifact_digest": binding.implementation_artifact_digest,
        },
    }


@pytest.mark.parametrize(
    ("switch_at", "expected_blocker", "intent_recorded"),
    [
        (2, "guarantee.profile_provider_disagreement", False),
        (3, "broker.intent_implementation_mismatch", True),
    ],
)
def test_provider_profile_change_after_admission_fails_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    switch_at: int,
    expected_blocker: str,
    intent_recorded: bool,
) -> None:
    installation = host_installation()
    selected = installation.authority_profile_binding
    assert selected is not None
    alternate = replace(selected, descriptor_digest="sha256:" + "0" * 64)
    call_count = 0

    def changing_report(_provider: HostAuthorityProvider) -> GuaranteeProfileBinding:
        nonlocal call_count
        call_count += 1
        return alternate if call_count >= switch_at else selected

    monkeypatch.setattr(HostAuthorityProvider, "guarantee_profile_binding", changing_report)
    request = _create_request(tmp_path, run_id=f"provider-change-{switch_at}")

    outcome = PhaseCore(installation=installation).run(request, execute=True)

    assert outcome.receipt["blockers"] == [expected_blocker]
    assert (outcome.intent is not None) is intent_recorded
    assert outcome.receipt["mutation_attempted"] is False
    assert not (request.root_bindings["fixture_result_root"] / "objects" / "item.bin").exists()


def _append_request(tmp_path: Path, *, run_id: str = "append-binding") -> PhaseRequest:
    registry = BundledRegistry.load()
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
                "idempotency_key": "append-binding-key",
            }
        ),
        encoding="utf-8",
    )
    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "streams").mkdir()
    return PhaseRequest(
        contract_id="fixture_append.v1",
        contract_version="1.0.0",
        contract_digest=binding["package_digest"],
        candidate_path=candidate,
        evidence_root=tmp_path / "evidence",
        run_id=run_id,
        input_paths={},
        root_bindings={"fixture_result_root": target_root},
        timestamp="2026-08-05T00:00:00Z",
    )


def test_provider_backed_intent_and_receipt_bind_exact_execution_facts(tmp_path: Path) -> None:
    installation = host_installation()
    outcome = PhaseCore(installation=installation).run(_create_request(tmp_path, run_id="bound-plan"))
    assert outcome.intent is not None
    assert outcome.effect_plan is not None
    profile = installation.authority_provider.guarantee_profile_binding()
    expected = {
        "authority": _expected_authority(profile),
        "mechanism": outcome.effect_plan["mechanism"],
        "effect_plan_digest": outcome.effect_plan_digest,
    }

    assert outcome.intent["implementation_binding"] == expected
    assert outcome.receipt["implementation_binding"] == expected


def test_broker_rejects_provider_binding_changed_after_intent_before_mutation(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="provider-rebound")
    target = request.root_bindings["fixture_result_root"] / "objects" / "item.bin"

    def rebind_provider(intent_path: Path) -> None:
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        intent["implementation_binding"]["authority"]["provider"]["artifact_digest"] = "sha256:" + "0" * 64
        intent_path.write_bytes(canonical_bytes(intent))

    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_mechanism=rebind_provider)),
    )

    assert outcome.exit_code != 0
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


@pytest.mark.parametrize("fault_name", ["before_mechanism", "before_effect_lock", "before_effect"])
def test_broker_rejects_root_identity_replacement_after_admission(
    tmp_path: Path,
    fault_name: str,
) -> None:
    request = _create_request(tmp_path, run_id=f"root-rebound-{fault_name}")
    target_root = request.root_bindings["fixture_result_root"]
    target = target_root / "objects" / "item.bin"

    def replace_root(*_args: object) -> None:
        displaced = tmp_path / "displaced-target"
        target_root.rename(displaced)
        target_root.mkdir()
        (target_root / "objects").mkdir()

    if fault_name == "before_mechanism":
        broker_faults = BrokerFaults(before_mechanism=lambda _intent_path: replace_root())
    elif fault_name == "before_effect_lock":
        broker_faults = BrokerFaults(before_effect_lock=lambda _ordinal, _intent_path: replace_root())
    else:
        broker_faults = BrokerFaults(before_effect={0: lambda _intent_path: replace_root()})
    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(broker=broker_faults),
    )

    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


@pytest.mark.skipif(os.name == "nt", reason="portable directory symlink setup is POSIX-only")
def test_broker_rejects_root_symlink_rebinding_after_admission(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="root-symlink-rebound")
    target_root = request.root_bindings["fixture_result_root"]
    target = target_root / "objects" / "item.bin"

    def replace_with_symlink(_ordinal: int, _intent_path: Path) -> None:
        target_root.rename(tmp_path / "displaced-target")
        alternate = tmp_path / "alternate-target"
        alternate.mkdir()
        (alternate / "objects").mkdir()
        target_root.symlink_to(alternate, target_is_directory=True)

    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(before_effect_lock=replace_with_symlink)),
    )

    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


def test_mechanism_callback_is_rejected_before_it_can_rebind_roots(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="mechanism-callback-root-rebound")
    original_root = request.root_bindings["fixture_result_root"]
    target = original_root / "objects" / "item.bin"
    alternate_root = tmp_path / "alternate-target"
    alternate_root.mkdir()
    (alternate_root / "objects").mkdir()

    def rebind_root(_target: Path) -> None:
        request.root_bindings["fixture_result_root"] = alternate_root

    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(
                exclusive_create=ExclusiveCreateFaults(before_exclusive_create=rebind_root)
            )
        ),
    )

    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()
    assert not (alternate_root / "objects" / "item.bin").exists()


@pytest.mark.parametrize(
    "mechanism_faults",
    [
        {"exclusive_create": ExclusiveCreateFaults(reparse_detector=lambda _path: False)},
        {"content_addressed_copy": ContentAddressedCopyFaults(reparse_detector=lambda _path: False)},
        {"archive_then_publish": ArchiveThenPublishFaults(reparse_detector=lambda _path: False)},
        {"object_store_publish": ObjectStorePublishFaults(reparse_detector=lambda _path: False)},
        {"append_record": AppendRecordFaults(write_primitive=lambda _descriptor, data: len(data))},
    ],
)
def test_broker_rejects_callbacks_that_can_mutate_inside_authority_boundary(
    tmp_path: Path,
    mechanism_faults: dict[str, object],
) -> None:
    request = _create_request(tmp_path, run_id="unsafe-authority-callback")
    target = request.root_bindings["fixture_result_root"] / "objects" / "item.bin"

    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(**mechanism_faults)),  # type: ignore[arg-type]
    )

    assert outcome.receipt["terminal_status"] == "rejected"
    assert outcome.receipt["mutation_attempted"] is False
    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert not target.exists()


@pytest.mark.parametrize(
    ("fault_key", "fault_type", "field_name"),
    [
        ("exclusive_create", ExclusiveCreateFaults, "before_exclusive_create"),
        ("exclusive_create", ExclusiveCreateFaults, "before_readback"),
        ("content_addressed_copy", ContentAddressedCopyFaults, "before_exclusive_create"),
        ("content_addressed_copy", ContentAddressedCopyFaults, "before_readback"),
        ("archive_then_publish", ArchiveThenPublishFaults, "before_archive_create"),
        ("archive_then_publish", ArchiveThenPublishFaults, "before_publish"),
        ("archive_then_publish", ArchiveThenPublishFaults, "before_current_write"),
        ("object_store_publish", ObjectStorePublishFaults, "before_final_revalidation"),
        ("object_store_publish", ObjectStorePublishFaults, "after_replace"),
    ],
)
def test_path_callbacks_are_rejected_before_target_write(
    tmp_path: Path,
    fault_key: str,
    fault_type: object,
    field_name: str,
) -> None:
    request = _create_request(tmp_path, run_id=f"unsafe-path-callback-{field_name}")
    target = request.root_bindings["fixture_result_root"] / "objects" / "item.bin"
    called = False

    def write_target(path: Path) -> None:
        nonlocal called
        called = True
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"callback mutation")

    mechanism_fault = fault_type(**{field_name: write_target})  # type: ignore[operator]
    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(broker=BrokerFaults(**{fault_key: mechanism_fault})),  # type: ignore[arg-type]
    )

    assert outcome.receipt["blockers"] == ["broker.unsafe_fault_callback"]
    assert outcome.receipt["mutation_attempted"] is False
    assert called is False
    assert not target.exists()


def test_duck_typed_mechanism_fault_is_rejected_before_callback(
    tmp_path: Path,
) -> None:
    request = _create_request(tmp_path, run_id="duck-typed-fault")
    target = request.root_bindings["fixture_result_root"] / "objects" / "item.bin"
    called = False

    def write_target(path: Path) -> None:
        nonlocal called
        called = True
        path.write_bytes(b"duck callback mutation")

    class DuckExclusiveCreateFaults:
        maximum_write_size = None
        fail_after_bytes = None
        readback_override = None
        readback_error = False
        reparse_detector = None
        write_primitive = None
        before_exclusive_create = write_target
        before_readback = None

    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(exclusive_create=DuckExclusiveCreateFaults())  # type: ignore[arg-type]
        ),
    )

    assert outcome.receipt["blockers"] == ["broker.invalid_fault_configuration"]
    assert outcome.receipt["mutation_attempted"] is False
    assert called is False
    assert not target.exists()


def test_mechanism_fault_subclass_is_rejected(tmp_path: Path) -> None:
    @dataclass(frozen=True)
    class ExtendedExclusiveCreateFaults(ExclusiveCreateFaults):
        extension: int = 1

    request = _create_request(tmp_path, run_id="subclassed-fault")
    target = request.root_bindings["fixture_result_root"] / "objects" / "item.bin"
    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(
            broker=BrokerFaults(exclusive_create=ExtendedExclusiveCreateFaults())
        ),
    )

    assert outcome.receipt["blockers"] == ["broker.invalid_fault_configuration"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


@pytest.mark.parametrize("subclassed", [False, True])
def test_core_fault_runtime_type_is_exact(tmp_path: Path, subclassed: bool) -> None:
    if subclassed:
        @dataclass(frozen=True)
        class InvalidCoreFaults(CoreFaults):
            extension: int = 1

        invalid_faults: object = InvalidCoreFaults()
    else:
        class InvalidCoreFaults:
            broker = None
            fail_receipt_write = False

        invalid_faults = InvalidCoreFaults()

    request = _create_request(tmp_path, run_id=f"invalid-core-fault-{subclassed}")
    target = request.root_bindings["fixture_result_root"] / "objects" / "item.bin"
    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=invalid_faults,  # type: ignore[arg-type]
    )

    assert outcome.receipt["blockers"] == ["broker.invalid_fault_configuration"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


@pytest.mark.parametrize("subclassed", [False, True])
def test_core_fault_type_check_never_calls_truthiness(tmp_path: Path, subclassed: bool) -> None:
    target = tmp_path / "truthiness-target.bin"

    if subclassed:
        class TruthyCoreFaults(CoreFaults):
            def __bool__(self) -> bool:
                target.write_bytes(b"unexpected")
                return False

        invalid_faults: object = TruthyCoreFaults()
    else:
        class TruthyCoreFaults:
            def __bool__(self) -> bool:
                target.write_bytes(b"unexpected")
                return False

        invalid_faults = TruthyCoreFaults()

    outcome = PhaseCore(installation=host_installation()).run(
        _create_request(tmp_path, run_id=f"core-truthiness-{subclassed}"),
        execute=False,
        faults=invalid_faults,  # type: ignore[arg-type]
    )

    assert outcome.receipt["blockers"] == ["broker.invalid_fault_configuration"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


@pytest.mark.parametrize("subclassed", [False, True])
def test_broker_fault_runtime_type_is_exact(tmp_path: Path, subclassed: bool) -> None:
    if subclassed:
        @dataclass(frozen=True)
        class InvalidBrokerFaults(BrokerFaults):
            extension: int = 1

        invalid_faults: object = InvalidBrokerFaults()
    else:
        class InvalidBrokerFaults:
            pass

        invalid_faults = InvalidBrokerFaults()

    request = _create_request(tmp_path, run_id=f"invalid-broker-fault-{subclassed}")
    target = request.root_bindings["fixture_result_root"] / "objects" / "item.bin"
    outcome = PhaseCore(installation=host_installation()).run(
        request,
        execute=True,
        faults=CoreFaults(broker=invalid_faults),  # type: ignore[arg-type]
    )

    assert outcome.receipt["blockers"] == ["broker.invalid_fault_configuration"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


def test_public_broker_execute_has_no_callback_or_external_sink_parameters() -> None:
    parameters = inspect.signature(EffectBroker.execute).parameters
    assert "progress_callback" not in parameters
    assert "receipt_sink" not in parameters


def test_broker_authority_qualification_ignores_non_contract_root_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _create_request(tmp_path, run_id="ignore-non-contract-root")
    unused_root = tmp_path / "unused-root"
    unused_root.mkdir()
    request = replace(request, root_bindings={**request.root_bindings, "unused_root": unused_root})
    original = installation_module.qualify_host_authority_roots
    observed: list[set[str]] = []

    def reject_unrelated_root(roots: Mapping[str, Path]) -> None:
        bindings = set(roots)
        observed.append(bindings)
        if "unused_root" in bindings:
            raise PhaseError("guarantee.profile_scope_unsupported")
        return original(roots)

    monkeypatch.setattr(installation_module, "qualify_host_authority_roots", reject_unrelated_root)
    outcome = PhaseCore(installation=host_installation()).run(request, execute=True)

    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert observed
    assert all("unused_root" not in bindings for bindings in observed)


@pytest.mark.parametrize("subclassed", [False, True])
def test_public_broker_fault_type_check_never_calls_truthiness(tmp_path: Path, subclassed: bool) -> None:
    target = tmp_path / "broker-truthiness-target.bin"

    if subclassed:
        class TruthyBrokerFaults(BrokerFaults):
            def __bool__(self) -> bool:
                target.write_bytes(b"unexpected")
                return False

        invalid_faults: object = TruthyBrokerFaults()
    else:
        class TruthyBrokerFaults:
            def __bool__(self) -> bool:
                target.write_bytes(b"unexpected")
                return False

        invalid_faults = TruthyBrokerFaults()

    installation = host_installation()
    broker = EffectBroker(
        BundledRegistry.load(),
        installation.authority_provider,
        installation.authority_profile_binding,
    )
    with pytest.raises(PhaseError) as error:
        broker.execute(
            {},
            None,  # type: ignore[arg-type]
            {},
            {},
            tmp_path / "missing-intent.json",
            tmp_path / "locks",
            timestamp="2026-08-05T00:00:00Z",
            faults=invalid_faults,  # type: ignore[arg-type]
        )

    assert error.value.code == "broker.invalid_fault_configuration"
    assert not target.exists()


def test_authority_rejects_rebound_root_handle_before_leaf_creation(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    root_info = root.stat()
    expected = (int(root_info.st_dev), int(root_info.st_ino))
    root.rename(tmp_path / "displaced")
    root.mkdir()

    with pytest.raises(PhaseError) as exc_info:
        HostAuthorityProvider().open_authority(
            root,
            "nested/item.bin",
            expected_root_identity=expected,
        )

    assert exc_info.value.code == "broker.root_identity_mismatch"
    assert not (root / "nested").exists()


def test_intent_stores_canonical_root_identity_records_used_by_broker(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="intent-root-identities")
    outcome = PhaseCore(installation=host_installation()).run(request)

    assert outcome.intent is not None
    records = outcome.intent["idempotency"]["root_identities"]
    root = request.root_bindings["fixture_result_root"].resolve(strict=True)
    info = root.stat()
    assert records == [
        {
            "binding_id": "fixture_result_root",
            "resolved_path": os.path.normcase(str(root)),
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
        }
    ]
    assert outcome.intent["idempotency"]["root_identity_digest"] == profile_digest(
        "resolved-root-identity",
        records,
    )


def test_broker_passes_intent_identity_across_race_before_authority_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installation = host_installation()
    request = _create_request(tmp_path, run_id="natural-root-race")
    root = request.root_bindings["fixture_result_root"]
    target = root / "objects" / "item.bin"
    original_open = HostAuthorityProvider.open_authority
    replaced = False

    def replace_before_open(
        provider: HostAuthorityProvider,
        selected_root: Path,
        locator: str,
        reparse_detector: object = None,
        **kwargs: object,
    ):
        nonlocal replaced
        if not replaced:
            replaced = True
            selected_root.rename(tmp_path / "displaced-target")
            selected_root.mkdir()
        return original_open(provider, selected_root, locator, reparse_detector, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(HostAuthorityProvider, "open_authority", replace_before_open)
    outcome = PhaseCore(installation=installation).run(request, execute=True)

    assert replaced is True
    assert outcome.receipt["blockers"] == ["broker.root_identity_mismatch"]
    assert outcome.receipt["mutation_attempted"] is False
    assert not target.exists()


def test_broker_rejects_self_reporting_provider_wrapper(tmp_path: Path) -> None:
    installation = host_installation()
    outcome = PhaseCore(installation=installation).run(_create_request(tmp_path, run_id="provider-wrapper"))
    assert outcome.intent is not None
    assert outcome.effect_plan is not None

    class SelfReportingProvider:
        def guarantee_profile_binding(self):
            return installation.authority_provider.guarantee_profile_binding()

        def open_authority(self, *args, **kwargs):
            return installation.authority_provider.open_authority(*args, **kwargs)

        def lock_target_root(self, *args, **kwargs):
            return installation.authority_provider.lock_target_root(*args, **kwargs)

    broker = EffectBroker(BundledRegistry.load(), SelfReportingProvider())
    with pytest.raises(PhaseError) as error:
        broker._validate_intent_implementation(outcome.intent, outcome.effect_plan)
    assert error.value.code == "broker.intent_implementation_mismatch"


def test_broker_rejects_effect_kind_bound_to_different_same_authority_mechanism(tmp_path: Path) -> None:
    installation = host_installation()
    outcome = PhaseCore(installation=installation).run(_create_request(tmp_path, run_id="effect-mechanism-swap"))
    assert outcome.intent is not None
    assert outcome.effect_plan is not None
    registry = BundledRegistry.load()
    entry = next(
        item
        for item in registry.to_document()["entries"]
        if item.get("kind") == "mechanism" and item.get("id") == "content_addressed_copy"
    )
    swapped_plan = deepcopy(outcome.effect_plan)
    swapped_plan["effects"][0]["mechanism"] = {
        "id": entry["id"],
        "version": entry["version"],
        "package_digest": entry["package_digest"],
    }
    swapped_intent = deepcopy(outcome.intent)
    swapped_digest = profile_digest("effect-plan", swapped_plan)
    swapped_intent["effect_plan_digest"] = swapped_digest
    swapped_intent["implementation_binding"]["effect_plan_digest"] = swapped_digest
    broker = EffectBroker(
        registry,
        installation.authority_provider,
        installation.authority_profile_binding,
    )

    with pytest.raises(PhaseError) as error:
        broker._validate_intent_implementation(swapped_intent, swapped_plan)
    assert error.value.code == "broker.intent_implementation_mismatch"


def test_inspection_rejects_receipt_binding_that_differs_from_intent(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="inspection-rebound")
    outcome = PhaseCore(installation=host_installation()).run(request)
    assert outcome.exit_code == 0
    receipt_path = request.evidence_root / ".phase" / "runs" / request.run_id / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["implementation_binding"]["authority"]["provider"]["artifact_digest"] = "sha256:" + "0" * 64
    receipt_path.write_bytes(canonical_bytes(receipt))

    with pytest.raises(PhaseError) as error:
        inspect_run(request.evidence_root, request.run_id)

    assert error.value.code == "inspection.implementation_binding_mismatch"


def test_executed_receipt_and_inspection_repeat_intent_binding(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="executed-binding")
    outcome = PhaseCore(installation=host_installation()).run(request, execute=True)

    assert outcome.exit_code == 0
    assert outcome.receipt["implementation_binding"] == outcome.intent["implementation_binding"]
    summary = inspect_run(request.evidence_root, request.run_id, root_bindings=request.root_bindings)
    assert summary["implementation_binding"] == outcome.intent["implementation_binding"]


def test_append_binding_is_mechanism_managed_not_provider_backed(tmp_path: Path) -> None:
    request = _append_request(tmp_path)
    outcome = PhaseCore(installation=host_installation()).run(request)

    assert outcome.exit_code == 0
    authority = outcome.intent["implementation_binding"]["authority"]
    assert authority == {"usage": "mechanism_managed", "profile": None, "provider": None}
    assert outcome.receipt["implementation_binding"] == outcome.intent["implementation_binding"]


def test_executed_append_does_not_invoke_authority_provider(tmp_path: Path) -> None:
    class RejectingAuthorityProvider:
        def open_authority(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("append must not open provider-backed authority")

        def lock_target_root(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("append must not acquire provider-backed root lock")

    request = _append_request(tmp_path, run_id="append-executed-binding")
    outcome = PhaseCore(installation=Installation(authority_provider=RejectingAuthorityProvider())).run(request, execute=True)

    assert outcome.exit_code == 0, outcome.receipt
    assert outcome.receipt["terminal_status"] == "succeeded_verified"
    assert outcome.receipt["implementation_binding"]["authority"] == {
        "usage": "mechanism_managed",
        "profile": None,
        "provider": None,
    }


@pytest.mark.parametrize("receipt_present", [True, False])
def test_inspection_accepts_historical_evidence_without_current_intent_fields(
    tmp_path: Path,
    receipt_present: bool,
) -> None:
    request = _create_request(tmp_path, run_id="historical-binding")
    outcome = PhaseCore(installation=host_installation()).run(request)
    assert outcome.exit_code == 0
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    intent_path = run_root / "intent.json"
    receipt_path = run_root / "receipt.json"
    plan_path = run_root / "attachments" / "effect-plan.json"
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    intent.pop("implementation_binding")
    intent["idempotency"].pop("root_identities")
    receipt.pop("implementation_binding")
    historical_package_digest = "sha256:3eeee20e539d5b49d08e0c4d93ff90218b797fbfe27b23035489cd6539059fa3"
    intent["contract"]["package_digest"] = historical_package_digest
    receipt["contract"]["package_digest"] = historical_package_digest
    plan["contract"]["package_digest"] = historical_package_digest
    old_plan_attachment_digest = intent["evidence"]["effect_plan_attachment_digest"]
    plan_bytes = canonical_bytes(plan)
    plan_attachment_digest = digest_bytes(plan_bytes)
    intent["effect_plan_digest"] = profile_digest("effect-plan", plan)
    intent["evidence"]["effect_plan_attachment_digest"] = plan_attachment_digest
    receipt["evidence"]["attachment_digests"] = [
        plan_attachment_digest if item == old_plan_attachment_digest else item
        for item in receipt["evidence"]["attachment_digests"]
    ]
    receipt["evidence"]["intent_digest"] = profile_digest("intent", intent)
    plan_path.write_bytes(plan_bytes)
    intent_path.write_bytes(canonical_bytes(intent))
    if receipt_present:
        receipt_path.write_bytes(canonical_bytes(receipt))
    else:
        receipt_path.unlink()

    summary = inspect_run(request.evidence_root, request.run_id)

    assert summary["implementation_binding"] is None
    if receipt_present:
        assert summary["terminal_status"] == "validated_planned"
    else:
        assert summary["terminal_status"] is None
        assert summary["state_classification"] is None


def test_inspection_rejects_current_evidence_without_implementation_binding(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="current-binding-missing")
    outcome = PhaseCore(installation=host_installation()).run(request)
    assert outcome.exit_code == 0
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    intent_path = run_root / "intent.json"
    receipt_path = run_root / "receipt.json"
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    intent.pop("implementation_binding")
    receipt.pop("implementation_binding")
    receipt["evidence"]["intent_digest"] = profile_digest("intent", intent)
    intent_path.write_bytes(canonical_bytes(intent))
    receipt_path.write_bytes(canonical_bytes(receipt))

    with pytest.raises(PhaseError) as error:
        inspect_run(request.evidence_root, request.run_id)
    assert error.value.code == "inspection.implementation_binding_missing"


def test_inspection_rejects_current_missing_receipt_intent_without_implementation_binding(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="current-intent-binding-missing")
    outcome = PhaseCore(installation=host_installation()).run(request)
    assert outcome.exit_code == 0
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    intent_path = run_root / "intent.json"
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    intent.pop("implementation_binding")
    intent_path.write_bytes(canonical_bytes(intent))
    (run_root / "receipt.json").unlink()

    with pytest.raises(PhaseError) as error:
        inspect_run(request.evidence_root, request.run_id)
    assert error.value.code == "inspection.implementation_binding_missing"


@pytest.mark.parametrize("receipt_present", [True, False])
def test_inspection_cannot_downgrade_current_evidence_with_zero_current_registry_snapshot(
    tmp_path: Path,
    receipt_present: bool,
) -> None:
    request = _create_request(tmp_path, run_id=f"registry-downgrade-{receipt_present}")
    outcome = PhaseCore(installation=host_installation()).run(request)
    assert outcome.exit_code == 0
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    intent_path = run_root / "intent.json"
    receipt_path = run_root / "receipt.json"
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    intent.pop("implementation_binding")
    intent_path.write_bytes(canonical_bytes(intent))
    if receipt_present:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt.pop("implementation_binding")
        receipt["evidence"]["intent_digest"] = profile_digest("intent", intent)
        receipt_path.write_bytes(canonical_bytes(receipt))
    else:
        receipt_path.unlink()

    bundled = BundledRegistry.load()
    document = bundled.to_document()
    for entry in document["entries"]:
        if entry.get("kind") == "contract" and entry.get("id") == "fixture_create.v1":
            entry["current"] = False
    downgraded = RegistrySnapshot.from_document(document, BundledRegistry.resources())

    with pytest.raises(PhaseError) as error:
        inspect_run(request.evidence_root, request.run_id, registry=downgraded)
    assert error.value.code == "inspection.implementation_binding_missing"


@pytest.mark.parametrize("receipt_present", [True, False])
def test_inspection_rejects_current_plan_relabelled_as_historical_contract(
    tmp_path: Path,
    receipt_present: bool,
) -> None:
    request = _create_request(tmp_path, run_id=f"historical-relabel-{receipt_present}")
    outcome = PhaseCore(installation=host_installation()).run(request)
    assert outcome.exit_code == 0
    run_root = request.evidence_root / ".phase" / "runs" / request.run_id
    intent_path = run_root / "intent.json"
    receipt_path = run_root / "receipt.json"
    historical_package_digest = "sha256:3eeee20e539d5b49d08e0c4d93ff90218b797fbfe27b23035489cd6539059fa3"
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    intent.pop("implementation_binding")
    intent["contract"]["package_digest"] = historical_package_digest
    intent_path.write_bytes(canonical_bytes(intent))
    if receipt_present:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt.pop("implementation_binding")
        receipt["contract"]["package_digest"] = historical_package_digest
        receipt["evidence"]["intent_digest"] = profile_digest("intent", intent)
        receipt_path.write_bytes(canonical_bytes(receipt))
    else:
        receipt_path.unlink()

    with pytest.raises(PhaseError) as error:
        inspect_run(request.evidence_root, request.run_id)
    assert error.value.code == "inspection.contract_mismatch"


def test_inspection_rejects_receipt_contract_different_from_intent_and_plan(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="receipt-contract-relabel")
    outcome = PhaseCore(installation=host_installation()).run(request)
    assert outcome.exit_code == 0
    receipt_path = request.evidence_root / ".phase" / "runs" / request.run_id / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["contract"]["package_digest"] = (
        "sha256:3eeee20e539d5b49d08e0c4d93ff90218b797fbfe27b23035489cd6539059fa3"
    )
    receipt_path.write_bytes(canonical_bytes(receipt))

    with pytest.raises(ValidationError):
        inspect_run(request.evidence_root, request.run_id)


def test_inspection_rejects_canonical_result_contract_different_from_receipt(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="canonical-result-contract-relabel")
    outcome = PhaseCore(installation=host_installation()).run(request, execute=True)
    assert outcome.exit_code == 0
    receipt_path = request.evidence_root / ".phase" / "runs" / request.run_id / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["canonical_result"]["contract"]["package_digest"] = (
        "sha256:3eeee20e539d5b49d08e0c4d93ff90218b797fbfe27b23035489cd6539059fa3"
    )
    receipt_path.write_bytes(canonical_bytes(receipt))

    with pytest.raises(PhaseError) as error:
        inspect_run(request.evidence_root, request.run_id, root_bindings=request.root_bindings)
    assert error.value.code == "inspection.contract_mismatch"


def test_broker_returns_the_validated_intent_snapshot_with_locked_plan(tmp_path: Path) -> None:
    request = _create_request(tmp_path, run_id="single-intent-snapshot")
    outcome = PhaseCore(installation=host_installation()).run(request, execute=True)
    assert outcome.exit_code == 0
    assert outcome.intent is not None
    assert outcome.effect_plan is not None
    intent_path = request.evidence_root / ".phase" / "runs" / request.run_id / "intent.json"
    registry = BundledRegistry.load()
    contract_binding = outcome.intent["contract"]
    contract = registry.resolve_contract(
        contract_binding["id"],
        contract_binding["version"],
        contract_binding["package_digest"],
        core_version=outcome.intent["core"]["version"],
    )
    installation = host_installation()
    broker = EffectBroker(
        registry,
        installation.authority_provider,
        installation.authority_profile_binding,
    )

    locked = broker._locked_plan_from_evidence(
        outcome.effect_plan,
        contract,
        request.root_bindings,
        intent_path,
    )

    assert isinstance(locked, tuple)
    locked_plan, validated_intent = locked
    assert locked_plan == outcome.effect_plan
    assert validated_intent == outcome.intent


def test_registry_retains_exact_pre_binding_contract_for_historical_evidence() -> None:
    registry = BundledRegistry.load()

    historical = registry.resolve_contract(
        "fixture_create.v1",
        "1.0.0",
        "sha256:3eeee20e539d5b49d08e0c4d93ff90218b797fbfe27b23035489cd6539059fa3",
        core_version="1.0.0",
    )

    assert historical.document["evidence"]["receipt_schema_digest"] == (
        "sha256:b68327ee676e8a51fabbd231e66ed5b3195171c9a169207a03782700892834bf"
    )


def test_core_rejects_historical_generation_with_receipt_conforming_to_exact_old_schema(tmp_path: Path) -> None:
    request = replace(
        _create_request(tmp_path, run_id="historical-generation-rejected"),
        contract_digest="sha256:3eeee20e539d5b49d08e0c4d93ff90218b797fbfe27b23035489cd6539059fa3",
    )
    registry = BundledRegistry.load()

    outcome = PhaseCore(registry=registry, installation=host_installation()).run(request)

    assert outcome.exit_code == 10
    assert outcome.intent is None
    assert outcome.receipt["blockers"] == ["registry.contract_generation_inactive"]
    assert "implementation_binding" not in outcome.receipt
    validate_receipt(outcome.receipt, registry)

    invalid = deepcopy(outcome.receipt)
    invalid["implementation_binding"] = None
    with pytest.raises(ValidationError):
        validate_receipt(invalid, registry)
