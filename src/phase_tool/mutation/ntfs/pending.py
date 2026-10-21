"""Closed pure records for one native coordination lane; no storage authority.

These builders verify structure and hash linkage. They do not prove a receipt
durable, an inspection complete, a worker stopped, or a root authorized. A
trusted, pinned ext4 store/executor must establish those facts before installing
a proposed head. Neither commissioning nor finalization here performs I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from ...canonical import canonical_bytes, parse_json_bytes, profile_digest
from ...errors import PhaseError

_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_BINDING = re.compile(r'[a-z][a-z0-9_]{0,63}')
_RUN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise PhaseError('coordination.' + code)


def _digest(value: str) -> None:
    _need(type(value) is str and _DIGEST.fullmatch(value) is not None, 'invalid_digest')


def _closed(value: object, fields: set[str]) -> dict:
    _need(type(value) is dict and set(value)==fields, 'invalid_record_fields')
    return value


def _version(value: dict, field: str) -> None:
    _need(type(value[field]) is str and value[field]=='1.0', 'unsupported_version')


@dataclass(frozen=True)
class RootAccessV1:
    root_binding: str
    physical_root_key: str
    grant_digest: str

    def __post_init__(self):
        _need(type(self.root_binding) is str and _BINDING.fullmatch(self.root_binding) is not None,
              'invalid_root_binding')
        _digest(self.physical_root_key)
        _digest(self.grant_digest)

    def as_dict(self) -> dict:
        return {'root_binding':self.root_binding,'physical_root_key':self.physical_root_key,
                'grant_digest':self.grant_digest}

    @classmethod
    def parse(cls, value: object) -> 'RootAccessV1':
        return cls(**_closed(value, {'root_binding','physical_root_key','grant_digest'}))


def _roots(values: tuple[RootAccessV1, ...]) -> None:
    _need(type(values) is tuple and bool(values) and all(type(item) is RootAccessV1 for item in values),
          'invalid_root_footprint')
    _need(tuple(sorted(values,key=lambda item:item.root_binding))==values, 'unordered_root_footprint')
    _need(len({item.root_binding for item in values})==len(values) and
          len({item.physical_root_key for item in values})==len(values), 'duplicate_root_footprint')


def _parse_roots(value: object) -> tuple[RootAccessV1, ...]:
    _need(type(value) is list, 'invalid_root_footprint')
    return tuple(RootAccessV1.parse(item) for item in value)


@dataclass(frozen=True)
class LaneIdentityV1:
    lane_id: str
    admitted_roots: tuple[RootAccessV1, ...]

    def __post_init__(self):
        _digest(self.lane_id)
        _roots(self.admitted_roots)

    def as_dict(self) -> dict:
        return {'identity_version':'1.0','lane_id':self.lane_id,
                'admitted_roots':[item.as_dict() for item in self.admitted_roots]}

    @property
    def digest(self) -> str:
        return profile_digest('ntfs-lane-identity-v1',self.as_dict())

    @classmethod
    def parse(cls, value: object) -> 'LaneIdentityV1':
        data = _closed(value, {'identity_version','lane_id','admitted_roots'})
        _version(data,'identity_version')
        return cls(data['lane_id'],_parse_roots(data['admitted_roots']))


@dataclass(frozen=True)
class CoordinationIntentV1:
    lane_identity_digest: str
    run_id: str
    phase_intent_digest: str
    plan_digest: str
    frozen_inputs_manifest_digest: str
    composition_digest: str
    roots: tuple[RootAccessV1, ...]

    def __post_init__(self):
        for value in (self.lane_identity_digest,self.phase_intent_digest,self.plan_digest,
                      self.frozen_inputs_manifest_digest,self.composition_digest):
            _digest(value)
        _need(type(self.run_id) is str and _RUN.fullmatch(self.run_id) is not None, 'invalid_run_id')
        _roots(self.roots)

    def as_dict(self) -> dict:
        return {'coordination_intent_version':'1.0','lane_identity_digest':self.lane_identity_digest,
                'run_id':self.run_id,'phase_intent_digest':self.phase_intent_digest,'plan_digest':self.plan_digest,
                'frozen_inputs_manifest_digest':self.frozen_inputs_manifest_digest,
                'composition_digest':self.composition_digest,'roots':[item.as_dict() for item in self.roots]}

    @property
    def digest(self) -> str:
        return profile_digest('ntfs-coordination-intent-v1',self.as_dict())

    @classmethod
    def parse(cls, value: object) -> 'CoordinationIntentV1':
        data = _closed(value, {'coordination_intent_version','lane_identity_digest','run_id',
            'phase_intent_digest','plan_digest','frozen_inputs_manifest_digest','composition_digest','roots'})
        _version(data,'coordination_intent_version')
        return cls(data['lane_identity_digest'],data['run_id'],data['phase_intent_digest'],data['plan_digest'],
                   data['frozen_inputs_manifest_digest'],data['composition_digest'],_parse_roots(data['roots']))


@dataclass(frozen=True)
class DirectResolutionReferencesV1:
    """References to be verified externally, not caller assertions of truth.

    There is deliberately no generic recovery-digest escape hatch or boolean
    durable/verified/completed flag. Partial/unknown outcomes remain PENDING.
    """
    outcome: str
    run_id: str
    coordination_intent_digest: str
    pending_entry_digest: str
    receipt_digest: str
    observation_digest: str
    worker_completion_digest: str

    def __post_init__(self):
        _need(self.outcome in ('succeeded_verified','failed_no_effect') and type(self.outcome) is str,
              'resolution_not_direct')
        _need(type(self.run_id) is str and _RUN.fullmatch(self.run_id) is not None, 'invalid_run_id')
        for value in (self.coordination_intent_digest,self.pending_entry_digest,self.receipt_digest,
                      self.observation_digest,self.worker_completion_digest):
            _digest(value)

    def as_dict(self) -> dict:
        return {'resolution_version':'1.0','outcome':self.outcome,'run_id':self.run_id,
            'coordination_intent_digest':self.coordination_intent_digest,'pending_entry_digest':self.pending_entry_digest,
            'receipt_digest':self.receipt_digest,'observation_digest':self.observation_digest,
            'worker_completion_digest':self.worker_completion_digest}

    @classmethod
    def parse(cls, value: object) -> 'DirectResolutionReferencesV1':
        data = _closed(value, {'resolution_version','outcome','run_id','coordination_intent_digest',
            'pending_entry_digest','receipt_digest','observation_digest','worker_completion_digest'})
        _version(data,'resolution_version')
        return cls(**{key:value for key,value in data.items() if key!='resolution_version'})


@dataclass(frozen=True)
class LaneEntryV1:
    lane_identity_digest: str
    generation: int
    previous_entry_digest: str | None
    state: str
    intent: CoordinationIntentV1 | None
    resolution: DirectResolutionReferencesV1 | None

    def __post_init__(self):
        _digest(self.lane_identity_digest)
        _need(type(self.generation) is int and 0 <= self.generation < 2**63, 'invalid_generation')
        _need(type(self.state) is str and self.state in ('COMMISSIONED','PENDING','FINALIZED'), 'invalid_state')
        if self.state=='COMMISSIONED':
            _need(self.generation==0 and self.previous_entry_digest is None
                  and self.intent is None and self.resolution is None, 'invalid_commissioned_record')
        else:
            _digest(self.previous_entry_digest)
            _need(self.generation>0 and type(self.intent) is CoordinationIntentV1 and
                  self.intent.lane_identity_digest==self.lane_identity_digest, 'intent_binding_mismatch')
            if self.state=='PENDING':
                _need(self.resolution is None, 'pending_has_resolution')
            else:
                _need(self.generation>=2 and type(self.resolution) is DirectResolutionReferencesV1,
                      'missing_resolution')
                _need(self.resolution.pending_entry_digest==self.previous_entry_digest
                      and self.resolution.coordination_intent_digest==self.intent.digest
                      and self.resolution.run_id==self.intent.run_id, 'resolution_binding_mismatch')

    def as_dict(self) -> dict:
        return {'entry_version':'1.0','lane_identity_digest':self.lane_identity_digest,'generation':self.generation,
            'previous_entry_digest':self.previous_entry_digest,'state':self.state,
            'intent':None if self.intent is None else self.intent.as_dict(),
            'resolution':None if self.resolution is None else self.resolution.as_dict()}

    @property
    def digest(self) -> str:
        return profile_digest('ntfs-lane-entry-v1',self.as_dict())

    @classmethod
    def parse(cls, value: object) -> 'LaneEntryV1':
        data = _closed(value, {'entry_version','lane_identity_digest','generation','previous_entry_digest',
                              'state','intent','resolution'})
        _version(data,'entry_version')
        return cls(data['lane_identity_digest'],data['generation'],data['previous_entry_digest'],data['state'],
                   None if data['intent'] is None else CoordinationIntentV1.parse(data['intent']),
                   None if data['resolution'] is None else DirectResolutionReferencesV1.parse(data['resolution']))


@dataclass(frozen=True)
class LaneHeadV1:
    lane_identity_digest: str
    generation: int
    entry_digest: str

    def __post_init__(self):
        _digest(self.lane_identity_digest)
        _digest(self.entry_digest)
        _need(type(self.generation) is int and 0 <= self.generation < 2**63, 'invalid_generation')

    def as_dict(self) -> dict:
        return {'head_version':'1.0','lane_identity_digest':self.lane_identity_digest,
                'generation':self.generation,'entry_digest':self.entry_digest}

    @property
    def digest(self) -> str:
        return profile_digest('ntfs-lane-head-v1',self.as_dict())

    @classmethod
    def parse(cls, value: object) -> 'LaneHeadV1':
        data = _closed(value, {'head_version','lane_identity_digest','generation','entry_digest'})
        _version(data,'head_version')
        return cls(data['lane_identity_digest'],data['generation'],data['entry_digest'])


def head_for(entry: LaneEntryV1) -> LaneHeadV1:
    _need(type(entry) is LaneEntryV1, 'invalid_entry')
    return LaneHeadV1(entry.lane_identity_digest,entry.generation,entry.digest)


def commissioned_record(identity: LaneIdentityV1) -> LaneEntryV1:
    _need(type(identity) is LaneIdentityV1, 'invalid_identity')
    return LaneEntryV1(identity.digest,0,None,'COMMISSIONED',None,None)


def _previous(identity: LaneIdentityV1, head: LaneHeadV1, previous: LaneEntryV1,
              expected_head_digest: str) -> None:
    _need(type(identity) is LaneIdentityV1 and type(head) is LaneHeadV1 and type(previous) is LaneEntryV1,
          'invalid_transition_input')
    _digest(expected_head_digest)
    _need(head.digest==expected_head_digest and head==head_for(previous)
          and head.lane_identity_digest==identity.digest, 'head_precondition_failed')
    if previous.intent is not None:
        _need(all(item in identity.admitted_roots for item in previous.intent.roots), 'root_not_in_lane')


def pending_record(identity: LaneIdentityV1, head: LaneHeadV1, previous: LaneEntryV1,
                   intent: CoordinationIntentV1, *, expected_head_digest: str) -> LaneEntryV1:
    _previous(identity,head,previous,expected_head_digest)
    _need(previous.state in ('COMMISSIONED','FINALIZED'), 'pending_unresolved')
    _need(type(intent) is CoordinationIntentV1 and intent.lane_identity_digest==identity.digest,
          'intent_binding_mismatch')
    _need(all(item in identity.admitted_roots for item in intent.roots), 'root_not_in_lane')
    return LaneEntryV1(identity.digest,previous.generation+1,previous.digest,'PENDING',intent,None)


def finalized_record(identity: LaneIdentityV1, head: LaneHeadV1, previous: LaneEntryV1,
                     references: DirectResolutionReferencesV1, *, expected_head_digest: str) -> LaneEntryV1:
    """Build a linked proposal only; actual proof verification is external."""
    _previous(identity,head,previous,expected_head_digest)
    _need(previous.state=='PENDING', 'not_pending')
    _need(type(references) is DirectResolutionReferencesV1, 'invalid_resolution')
    return LaneEntryV1(identity.digest,previous.generation+1,previous.digest,'FINALIZED',previous.intent,references)


def decode_entry(data: bytes) -> LaneEntryV1:
    _need(type(data) is bytes, 'invalid_record_bytes')
    value = parse_json_bytes(data,maximum_bytes=64*1024,maximum_depth=16,maximum_nodes=4096)
    entry = LaneEntryV1.parse(value)
    _need(canonical_bytes(entry.as_dict())==data, 'noncanonical_record')
    return entry


def decode_head(data: bytes) -> LaneHeadV1:
    _need(type(data) is bytes, 'invalid_record_bytes')
    value = parse_json_bytes(data,maximum_bytes=64*1024,maximum_depth=8,maximum_nodes=128)
    head = LaneHeadV1.parse(value)
    _need(canonical_bytes(head.as_dict())==data, 'noncanonical_record')
    return head


def validate_link(identity: LaneIdentityV1, previous: LaneEntryV1 | None, entry: LaneEntryV1) -> None:
    """Check one structural chain edge; not evidence/authority verification."""
    _need(type(identity) is LaneIdentityV1 and type(entry) is LaneEntryV1, 'invalid_transition_input')
    if previous is None:
        expected = commissioned_record(identity)
    else:
        _need(type(previous) is LaneEntryV1, 'invalid_transition_input')
        head = head_for(previous)
        if entry.state=='PENDING':
            expected = pending_record(identity,head,previous,entry.intent,expected_head_digest=head.digest)
        elif entry.state=='FINALIZED':
            expected = finalized_record(identity,head,previous,entry.resolution,expected_head_digest=head.digest)
        else:
            raise PhaseError('coordination.recommissioning_forbidden')
    _need(entry==expected, 'invalid_entry_link')
