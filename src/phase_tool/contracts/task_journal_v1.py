from __future__ import annotations

import hashlib
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Iterable

from jsonschema import Draft202012Validator

from ..canonical import canonical_bytes, parse_json_bytes
from ..errors import PhaseError
from ..append_codec import append_head_token, iter_bounded_lines, stream_head_token_from_summary
from ..paths import safe_relative_locator

_WIRE_RECORD_TYPES = {
    "open": "task_open",
    "event": "task_event",
    "close": "task_close",
    "correction": "task_correction",
}

_DIGEST_SCHEMA = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_COMMON_RECORD_PROPERTIES: dict[str, Any] = {
    "task_record_version": {"const": "1.0"},
    "record_type": {"type": "string"},
    "task_id": {"type": "string", "pattern": "^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$"},
    "sequence": {"type": "integer", "minimum": 1},
    "action": {"type": "string"},
    "operation_id": {"type": "string", "minLength": 1},
    "request_digest": _DIGEST_SCHEMA,
    "previous_head": {"oneOf": [{"type": "null"}, _DIGEST_SCHEMA]},
    "event_hash": _DIGEST_SCHEMA,
}
_ACTION_RECORD_PROPERTIES: dict[str, dict[str, Any]] = {
    "open": {
        "original_instruction": {"type": "string"},
        "normalized_goal": {"type": "string"},
    },
    "event": {
        "event_kind": {"type": "string", "minLength": 1},
        "event_payload": {"type": "object"},
    },
    "close": {
        "outcome": {"enum": ["completed", "failed", "partial", "cancelled"]},
    },
    "correction": {
        "target_sequence": {"type": "integer", "minimum": 1},
        "target_event_hash": _DIGEST_SCHEMA,
        "reason": {"type": "string", "minLength": 1},
        "replacement": {"type": "object"},
    },
}
_ACTION_REQUIRED = {
    "open": ["original_instruction"],
    "event": ["event_kind", "event_payload"],
    "close": ["outcome"],
    "correction": ["target_sequence", "target_event_hash", "reason", "replacement"],
}
@dataclass(frozen=True)
class JournalStreamState:
    record_count: int
    state: str
    length: int
    head_token: str


def _validate_record_shape(record: dict[str, Any]) -> None:
    action = record.get("action")
    if action not in _WIRE_RECORD_TYPES:
        raise PhaseError("task_journal.action_unsupported")
    properties = dict(_COMMON_RECORD_PROPERTIES) | _ACTION_RECORD_PROPERTIES[action]
    properties["action"] = {"const": action}
    properties["record_type"] = {"const": _WIRE_RECORD_TYPES[action]}
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(_COMMON_RECORD_PROPERTIES) + _ACTION_REQUIRED[action],
    }
    if next(Draft202012Validator(schema).iter_errors(record), None) is not None:
        raise PhaseError("task_journal.record_schema_invalid")


def _load_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records, _summary, _matched = _scan_records(iter_bounded_lines(path), collect=True)
    return records


def _scan_records(
    lines: Iterable[bytes],
    *,
    collect: bool,
    target_identity: tuple[str, int, str] | None = None,
    visitor: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[dict[str, Any]], JournalStreamState, bool]:
    records: list[dict[str, Any]] = []
    offset = 0
    digest = hashlib.sha256()
    previous_head: str | None = None
    record_count = 0
    task_id = None
    state = "absent"
    matched_target = False
    for line in lines:
        value = parse_json_bytes(line.rstrip(b"\n"))
        _validate_record_replay(
            value,
            index=record_count + 1,
            previous_head=previous_head,
            task_id=task_id,
            state=state,
        )
        expected_hash = _event_hash(value, offset)
        if value.get("event_hash") != expected_hash:
            raise PhaseError("task_journal.hash_mismatch")
        task_id = value["task_id"]
        state = _next_state(state, value["action"])
        if target_identity == (value.get("task_id"), value.get("sequence"), value.get("event_hash")):
            matched_target = True
        if collect:
            records.append(value)
        if visitor is not None:
            visitor(value)
        digest.update(line)
        offset += len(line)
        record_count += 1
        previous_head = stream_head_token_from_summary(
            "sha256:" + digest.hexdigest(),
            offset,
            record_count,
        )
    stream_digest = "sha256:" + digest.hexdigest()
    return records, JournalStreamState(
        record_count=record_count,
        state=state,
        length=offset,
        head_token=stream_head_token_from_summary(stream_digest, offset, record_count),
    ), matched_target


def stream_state(path: Path) -> JournalStreamState:
    if not path.exists():
        empty_digest = "sha256:" + hashlib.sha256().hexdigest()
        return JournalStreamState(0, "absent", 0, stream_head_token_from_summary(empty_digest, 0, 0))
    _records, summary, _matched = _scan_records(iter_bounded_lines(path), collect=False)
    return summary


def _next_state(state: str, action: str) -> str:
    if action == "open":
        return "open"
    if action == "close":
        return "closed"
    return state


def _validate_record_replay(
    record: dict[str, Any],
    *,
    index: int,
    previous_head: str | None,
    task_id: str | None,
    state: str,
) -> None:
    _validate_record_shape(record)
    action = record.get("action")
    if action not in _WIRE_RECORD_TYPES:
        raise PhaseError("task_journal.action_unsupported")
    if record.get("record_type") != _WIRE_RECORD_TYPES[action]:
        raise PhaseError("task_journal.record_type_mismatch")
    if record.get("sequence") != index:
        raise PhaseError("task_journal.sequence_gap")
    if index == 1 and action != "open":
        raise PhaseError("task_journal.first_record_not_open")
    if index != 1 and action == "open":
        raise PhaseError("task_journal.duplicate_open")
    if task_id is not None and record.get("task_id") != task_id:
        raise PhaseError("task_journal.task_id_mismatch")
    if record.get("previous_head") != previous_head:
        raise PhaseError("task_journal.previous_head_mismatch")
    if action in {"event", "close"} and state != "open":
        raise PhaseError("task_journal.not_open")
    if action == "correction" and state == "absent":
        raise PhaseError("task_journal.not_open")


def _state(records: list[dict[str, Any]]) -> str:
    if not records:
        return "absent"
    status = "open"
    for record in records:
        if record["action"] == "close":
            status = "closed"
    return status


def locator_for(candidate: dict[str, Any]) -> str:
    return safe_relative_locator(f"tasks/{candidate['task_id']}.jsonl")


def build_record(candidate: dict[str, Any], *, existing_bytes: bytes, expected_head: str | None, request_digest: str | None = None) -> dict[str, Any]:
    records = _load_records_from_bytes(existing_bytes)
    return build_record_from_state(
        candidate,
        record_count=len(records),
        state=_state(records),
        expected_head=expected_head,
        request_digest=request_digest,
    )


def build_record_from_state(
    candidate: dict[str, Any],
    *,
    record_count: int,
    state: str,
    expected_head: str | None,
    request_digest: str | None = None,
) -> dict[str, Any]:
    action = candidate["action"]
    if candidate.get("operation_id") != candidate.get("idempotency_key"):
        raise PhaseError("task_journal.operation_id_mismatch")
    if expected_head is None and record_count:
        raise PhaseError("task_journal.already_open")
    if action == "open" and record_count:
        raise PhaseError("task_journal.already_open")
    if action in {"event", "close"} and state != "open":
        raise PhaseError("task_journal.not_open")
    if action == "correction" and state == "absent":
        raise PhaseError("task_journal.not_open")
    sequence = record_count + 1
    record: dict[str, Any] = {
        "task_record_version": "1.0",
        "record_type": _WIRE_RECORD_TYPES[action],
        "task_id": candidate["task_id"],
        "sequence": sequence,
        "action": action,
        "operation_id": candidate["operation_id"],
        "request_digest": request_digest or "",
        "previous_head": expected_head,
    }
    if action == "open":
        record["original_instruction"] = candidate["original_instruction"]
        if "normalized_goal" in candidate:
            record["normalized_goal"] = candidate["normalized_goal"]
    elif action == "event":
        record["event_kind"] = candidate["event_kind"]
        record["event_payload"] = candidate["event_payload"]
    elif action == "close":
        record["outcome"] = candidate["outcome"]
    elif action == "correction":
        record["target_sequence"] = candidate["target_sequence"]
        record["target_event_hash"] = candidate["target_event_hash"]
        record["reason"] = candidate["reason"]
        record["replacement"] = candidate["replacement"]
    else:
        raise PhaseError("task_journal.action_unsupported")
    return record


def finalize_record(record: dict[str, Any], *, previous_head: str | None, previous_length: int) -> bytes:
    staged = dict(record)
    staged.pop("event_hash", None)
    line_without_hash = canonical_bytes(staged | {"event_hash": ""}) + b"\n"
    event_hash = append_head_token(previous_head, line_without_hash, previous_length, "task_journal.v1")
    final = staged | {"event_hash": event_hash}
    return canonical_bytes(final) + b"\n"


def _event_hash(record: dict[str, Any], previous_length: int) -> str:
    staged = dict(record)
    staged["event_hash"] = ""
    previous = staged.get("previous_head")
    return append_head_token(previous, canonical_bytes(staged) + b"\n", previous_length, "task_journal.v1")


def _load_records_from_bytes(data: bytes) -> list[dict[str, Any]]:
    records, _summary, _matched = _scan_records(BytesIO(data), collect=True)
    return records


def validate_candidate(value: dict[str, Any], schema: dict[str, Any]) -> tuple[str, str, Any, Any, list[str]]:
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda error: list(error.path))
    if errors:
        return "fail", "candidate.schema_invalid", "schema_valid", errors[0].message, ["candidate.schema_invalid"]
    if value["operation_id"] != value["idempotency_key"]:
        return "fail", "task_journal.operation_id_mismatch", value["idempotency_key"], value["operation_id"], ["task_journal.operation_id_mismatch"]
    return "pass", "validation.pass", "schema_valid", "schema_valid", []


def validate_state(value: dict[str, Any], path: Path) -> tuple[str, str, Any, Any, list[str]]:
    expected = value["expected_head"]
    if not path.exists():
        if expected is None:
            return "pass", "validation.pass", "absent", "absent", []
        return "fail", "freeze.stale_snapshot", expected, None, ["freeze.stale_snapshot"]
    target_identity = None
    if value["action"] == "correction":
        target_identity = (value["task_id"], value["target_sequence"], value["target_event_hash"])
    try:
        _records, summary, matched_target = _scan_records(
            iter_bounded_lines(path),
            collect=False,
            target_identity=target_identity,
        )
    except PhaseError as exc:
        return "fail", exc.code, "valid_stream", "invalid_stream", [exc.code]
    if expected is None:
        if summary.record_count:
            return "fail", "target.same_key_conflict", "absent", "present", ["target.same_key_conflict"]
        return "pass", "validation.pass", "absent", "absent", []
    current = summary.head_token
    if current != expected:
        return "fail", "freeze.stale_snapshot", expected, current, ["freeze.stale_snapshot"]
    state = summary.state
    action = value["action"]
    if action in {"event", "close"} and state != "open":
        return "fail", "task_journal.not_open", "open", state, ["task_journal.not_open"]
    if action == "correction" and state == "absent":
        return "fail", "task_journal.not_open", "open_or_closed", state, ["task_journal.not_open"]
    if action == "correction" and not matched_target:
        return "fail", "task_journal.correction_target_mismatch", target_identity, "not_found", ["task_journal.correction_target_mismatch"]
    return "pass", "validation.pass", expected, current, []


def project_task(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "task_id": None,
            "status": "absent",
            "terminal_outcome": None,
            "sequence": 0,
            "event_count": 0,
            "corrections": [],
        }
    task_id = None
    terminal_outcome = None
    event_count = 0
    corrections: list[dict[str, Any]] = []

    def visit(record: dict[str, Any]) -> None:
        nonlocal task_id, terminal_outcome, event_count
        task_id = record["task_id"]
        if record["action"] == "close":
            terminal_outcome = record["outcome"]
        elif record["action"] == "event":
            event_count += 1
        elif record["action"] == "correction":
            corrections.append({
                "sequence": record["sequence"],
                "target_sequence": record["target_sequence"],
                "target_event_hash": record["target_event_hash"],
                "reason": record["reason"],
            })

    _records, summary, _matched = _scan_records(iter_bounded_lines(path), collect=False, visitor=visit)
    return {
        "task_id": task_id,
        "status": summary.state,
        "terminal_outcome": terminal_outcome,
        "sequence": summary.record_count,
        "event_count": event_count,
        "corrections": corrections,
    }
