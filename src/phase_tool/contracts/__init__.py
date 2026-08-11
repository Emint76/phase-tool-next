from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ..errors import PhaseError
from ..paths import safe_relative_locator
from . import task_journal_v1


def _create_source_admission_hook() -> Any:
    from .source_admission_v1 import create_contract_hook

    return create_contract_hook()


def _create_knowledge_admission_hook() -> Any:
    from .knowledge_admission_v1 import create_contract_hook

    return create_contract_hook()


def _create_publish_new_version_hook() -> Any:
    from .publish_new_version_v1 import create_contract_hook

    return create_contract_hook()


def _create_publish_new_version_v2_hook() -> Any:
    from .publish_new_version_v2 import create_contract_hook

    return create_contract_hook()


_CONTRACT_HOOK_FACTORIES = {
    "builtin.knowledge_admission_v1": _create_knowledge_admission_hook,
    "builtin.publish_new_version_v1": _create_publish_new_version_hook,
    "builtin.publish_new_version_v2": _create_publish_new_version_v2_hook,
    "builtin.source_admission_v1": _create_source_admission_hook,
}


def load_contract_hook(contract: Any) -> Any | None:
    descriptor = getattr(contract, "contract_hook", None)
    if descriptor is None:
        return None
    if not isinstance(descriptor, dict):
        raise PhaseError("contract.hook_invalid")
    if descriptor.get("execution_allowed") is not True or descriptor.get("capability") != "contract_hook":
        raise PhaseError("contract.hook_unavailable")
    implementation_id = descriptor.get("implementation_id")
    if not isinstance(implementation_id, str):
        raise PhaseError("contract.hook_invalid")
    factory = _CONTRACT_HOOK_FACTORIES.get(implementation_id)
    if factory is None:
        raise PhaseError("contract.hook_unavailable", implementation_id)
    return factory()


def append_locator(contract_document: dict[str, Any], candidate: dict[str, Any]) -> str:
    if "record" in candidate:
        return safe_relative_locator(candidate["target_locator"])
    if "task_id" in candidate:
        return task_journal_v1.locator_for(candidate)
    raise PhaseError("contract.append_codec_unavailable")


def expected_append_locator(contract_document: dict[str, Any], candidate: dict[str, Any]) -> str:
    if "record" in candidate:
        return contract_document["canonical_result"]["locator_template"].replace("{stream_id}", candidate["stream_id"])
    if "task_id" in candidate:
        return task_journal_v1.locator_for(candidate)
    raise PhaseError("contract.append_codec_unavailable")


def append_record_bytes(
    candidate: dict[str, Any],
    *,
    existing_bytes: bytes | None = None,
    existing_path: Path | None = None,
    expected_head: str | None,
    request_digest: str | None = None,
) -> bytes:
    if "record" in candidate:
        return canonical_bytes(candidate["record"]) + b"\n"
    if "task_id" in candidate:
        if existing_path is not None:
            state = task_journal_v1.stream_state(existing_path)
            record = task_journal_v1.build_record_from_state(
                candidate,
                record_count=state.record_count,
                state=state.state,
                expected_head=expected_head,
                request_digest=request_digest,
            )
            previous_length = state.length
        else:
            materialized = b"" if existing_bytes is None else existing_bytes
            record = task_journal_v1.build_record(
                candidate,
                existing_bytes=materialized,
                expected_head=expected_head,
                request_digest=request_digest,
            )
            previous_length = len(materialized)
        return task_journal_v1.finalize_record(record, previous_head=expected_head, previous_length=previous_length)
    raise PhaseError("contract.append_codec_unavailable")


def append_record_identity(finalized_record_bytes: bytes) -> str:
    if not finalized_record_bytes.endswith(b"\n"):
        raise PhaseError("contract.append_identity_invalid_record")
    record = parse_json_bytes(finalized_record_bytes.rstrip(b"\n"))
    if all(key in record for key in ("task_id", "sequence", "event_hash")):
        return f"{record['task_id']}:{record['sequence']}:{record['event_hash']}"
    if "record_id" in record:
        return str(record["record_id"])
    return digest_bytes(finalized_record_bytes)


def append_lock_scope(candidate: dict[str, Any]) -> str:
    if "record" in candidate:
        return "stream." + candidate["stream_id"]
    if "task_id" in candidate:
        return "stream." + candidate["task_id"]
    raise PhaseError("contract.append_codec_unavailable")
