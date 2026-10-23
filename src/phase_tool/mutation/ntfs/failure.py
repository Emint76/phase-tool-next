"""DRAFT negative attachment in the existing Core EvidenceStore only.
No receipt, qualification, original discharge, target mutation or retry authority.
"""
from __future__ import annotations
from ...canonical import canonical_bytes,parse_json_bytes
from ...errors import PhaseError
from .native import _require

_RESOURCE='schemas/native-parent-failure-1.0.schema.json'


def validate_native_parent_failure(binding,value):
    from jsonschema import Draft202012Validator
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    exact=manifest['contract']
    contract=binding.registry.resolve_contract(exact['id'],exact['version'],exact['package_digest'],
        core_version=manifest['core']['version'])
    pins=[row['digest'] for row in contract.entry['package_artifacts'] if row['resource']==_RESOURCE]
    _require(len(pins)==1,'ntfs.native_failure_schema_unbound')
    schema=binding.registry.schema_document('https://phase-tool.local/'+_RESOURCE,pins[0])
    Draft202012Validator(schema,registry=binding.registry.schema_registry()).validate(value)
    _require(value['installation_digest']==binding.manifest_digest
        and value['registry_snapshot_digest']==binding.registry.digest,
        'ntfs.native_failure_binding_mismatch')
    _require(len(canonical_bytes(value))<=2*1024**2,'ntfs.native_failure_limit')


def make_native_parent_failure(binding,*,run_id,intent_digest,effect_plan_digest,operation_nonce,remote):
    value={'native_parent_failure_version':'1.0','run_id':run_id,'intent_digest':intent_digest,
        'effect_plan_digest':effect_plan_digest,'installation_digest':binding.manifest_digest,
        'registry_snapshot_digest':binding.registry.digest,'operation_nonce':operation_nonce,
        'outcome':'unresolved','retry_authorized':False,'parent_error':remote}
    validate_native_parent_failure(binding,value)
    return canonical_bytes(value)
