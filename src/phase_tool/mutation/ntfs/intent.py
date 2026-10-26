"""Unselected pure parser of the ORIGINAL Core intent; no execution authority.

Only a future fixed trusted parent may read the durable evidence and provide
installed expectations. Public parent input remains run_id + intent digest.
This function accepts immutable buffers internally, never paths, callbacks,
providers, commands, leases or a qualification flag. Matching data is NOT
proof of an actual installation, root, ext4 identity, loaded code or G01.
Root-wide unresolved scanning/locks, guarantee admission, fresh observations,
possible-dispatch/GO, worker exit and Core receipts remain mandatory outside.
"""
from __future__ import annotations
from dataclasses import dataclass
import re
from .handoff import ParsedNativeFileCreate, ParsedNativeVersion1
from jsonschema import Draft202012Validator, FormatChecker
from ...canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from ...evidence import validate_intent
from ...paths import safe_relative_locator
from ...planning import _validate_logical_plan
from ...preconditions import verify_saved_precondition_results
from ...registry import RegistrySnapshot
from .native import _require
from .worker import _grant, _context, _version1_context

_CONTROL_LIMIT=2*1024**2
_EFFECT_FIELDS={'effect_id','kind','target','input_binding','content_source','content_digest',
 'content_length','preconditions','lock_scope','durability_policy_id','on_failure'}



def _canonical(raw: bytes):
    _require(type(raw) is bytes,'ntfs.original_immutable_bytes_required')
    value=parse_json_bytes(raw,maximum_bytes=_CONTROL_LIMIT)
    _require(canonical_bytes(value)==raw,'ntfs.original_noncanonical_bytes')
    return value


@dataclass(frozen=True)
class _OriginalControlProjection:
    """Declared lineage only: no actual payload, FD, filesystem or GO authority."""
    context_bytes: bytes
    grant_bytes: bytes
    effect_bytes: bytes
    timestamp: str
    input_binding: str
    content_digest: str
    content_length: int


def _original_control_prefix(*, intent_bytes: bytes, plan_bytes: bytes,
    registry: RegistrySnapshot, expected_run_id: str, expected_intent_digest: str,
    installed_core_binding: bytes, installed_native_binding: bytes,
    installed_implementation_binding: bytes, _execution_requested: bool,
    _version1: bool):
    """Existing checks BEFORE payload verification; never a complete projection."""
    _require(type(_version1) is bool and type(_execution_requested) is bool,
        'ntfs.original_closed_role_required')
    _require(type(registry) is RegistrySnapshot,'ntfs.original_registry_required')
    intent=_canonical(intent_bytes)
    _require(type(intent) is dict and intent.get('phase_intent_version')=='1.2','ntfs.original_native_intent_required')
    validate_intent(intent,registry)
    _require(intent['run_id']==expected_run_id and profile_digest('intent',intent)==expected_intent_digest,
        'ntfs.original_intent_mismatch')
    _require(intent['registry_snapshot_digest']==registry.digest and intent['execution_requested'] is _execution_requested,
        'ntfs.original_execution_binding_mismatch')
    for key,expected in (('core',installed_core_binding),('native_binding',installed_native_binding),
                         ('implementation_binding',installed_implementation_binding)):
        _canonical(expected)
        _require(canonical_bytes(intent[key])==expected,'ntfs.original_installation_binding_mismatch')
    binding=intent['contract']
    contract=registry.resolve_contract(binding['id'],binding['version'],binding['package_digest'],core_version=intent['core']['version'])
    plan=_canonical(plan_bytes)
    _require(digest_bytes(plan_bytes)==intent['evidence']['effect_plan_attachment_digest']
        and profile_digest('effect-plan',plan)==intent['effect_plan_digest'],'ntfs.original_plan_digest_mismatch')
    _validate_logical_plan(plan,contract,registry)
    operation = 'publish_new_version' if _version1 else 'create'
    _require(plan['run_id']==intent['run_id'] and plan['operation_intent']==intent['operation']['intent']==operation
        and plan['mechanism']==intent['operation']['mechanism'],'ntfs.original_plan_binding_mismatch')
    scope=canonical_digest(contract.document['write_scope'])
    _require(intent['write_scope_digest']==plan['write_scope_digest']==scope,'ntfs.original_write_scope_mismatch')
    implementation=intent['implementation_binding']
    _require(implementation['effect_plan_digest']==intent['effect_plan_digest']
        and implementation['mechanism']==plan['mechanism'] and implementation['authority']['usage']=='provider_backed',
        'ntfs.original_implementation_mismatch')
    _require(len(plan['effects'])==1,'ntfs.original_single_effect_required')
    effect=plan['effects'][0]
    if _version1:
        _require(contract.document['identity']['id']=='publish_new_version.v1'
            and contract.document['identity']['version']=='1.0.0'
            and plan['mechanism']['id']=='mechanism.archive_then_publish_v1'
            and set(effect)==_EFFECT_FIELDS|{'ordinal','archive_target','archive_digest','archive_length',
                'operation_identity','request_digest'}
            and effect['kind']=='publish_new_version' and type(effect['ordinal']) is int
            and effect['ordinal']==0 and effect['request_digest'] is None,
            'ntfs.original_version1_effect_required')
    else:
        _require(set(effect)==_EFFECT_FIELDS and effect['kind']=='exclusive_create'
            and effect['preconditions']=={'existence':'absent','expected_digest':None,'expected_head':None,'concurrency_token':None}
            and effect['lock_scope'] is None and effect['durability_policy_id']=='file_data_synced'
            and effect['on_failure']=='stop_and_classify','ntfs.original_single_effect_required')
    candidate=intent['candidate']
    _require(candidate['input_mode']=='structured_json' and candidate['storage']['mode']=='inline'
        and candidate['storage']['attachment_digest'] is None,'ntfs.original_inline_candidate_required')
    value=candidate['storage']['value'];candidate_raw=canonical_bytes(value)
    Draft202012Validator(registry.schema_document(contract.document['candidate']['schema_ref'],contract.document['candidate']['schema_digest']),
        registry=registry.schema_registry(),format_checker=FormatChecker()).validate(value)
    _require(candidate['digest']==profile_digest('candidate',value) and candidate['length']==len(candidate_raw),
        'ntfs.original_candidate_digest_mismatch')
    _require(effect['target']['relative_locator']==safe_relative_locator(value['target_locator'])
        and effect['target']['root_binding']==contract.document['canonical_result']['root_binding']
        and effect['input_binding']==value['input_binding'] and intent['idempotency']['key']==value['idempotency_key'],
        'ntfs.original_candidate_effect_mismatch')
    if _version1:
        from ...contracts.publish_new_version_v1 import archive_locator
        archive = archive_locator(value['expected_current_digest'])
        _require(value['input_binding']=='payload' and effect['target']['relative_locator']!=archive
            and effect['archive_target']=={'root_binding':effect['target']['root_binding'],'relative_locator':archive}
            and effect['archive_digest']==value['expected_current_digest']
            and type(effect['archive_length']) is int and 0<=effect['archive_length']<=16*1024**2
            and effect['operation_identity']==value['operation_id']
            and effect['preconditions']=={'existence':'present','expected_digest':effect['archive_digest'],
                'expected_head':None,'concurrency_token':effect['archive_digest']}
            and effect['lock_scope']=='publish.'+digest_bytes(value['target_locator'].encode('utf-8')).removeprefix('sha256:')
            and effect['durability_policy_id']=='file_data_synced' and effect['on_failure']=='stop_and_classify',
            'ntfs.original_version1_effect_mismatch')
    inputs=intent['inputs']
    _require(len(inputs)==1 and inputs[0]['binding_id']==value['input_binding']
        and inputs[0]['freeze_strategy']=='copy_and_hash','ntfs.original_frozen_input_required')
    frozen=inputs[0]
    return intent,plan,contract


def _original_content_binding(intent: dict, plan: dict, digest: str, length: int) -> None:
    """Compare declarations with supplied data, without asserting its origin."""
    effect=plan['effects'][0];frozen=intent['inputs'][0]
    _require(type(effect['content_length']) is int and effect['content_length']==length
        and frozen['blob_digest']==frozen['digest']==effect['content_digest']==digest
        and effect['content_source']=={'kind':'frozen_input','binding_id':frozen['binding_id'],'source_digest':digest}
        and intent['evidence']['content_blob_digests']==[],'ntfs.original_content_binding_mismatch')


def _verify_original_blob_bytes(intent: dict, plan: dict, blob_bytes: bytes,
                                *, _version1: bool) -> None:
    maximum = 16*1024**2 if _version1 else 1024**2
    _require(type(blob_bytes) is bytes and len(blob_bytes)<=maximum,'mechanism.content_too_large')
    digest=digest_bytes(blob_bytes)
    _original_content_binding(intent,plan,digest,len(blob_bytes))


def _original_control_suffix(*, intent: dict, plan: dict, contract,
    registry: RegistrySnapshot, pre_validator_bytes: bytes,
    installed_root_grants: bytes, expected_intent_digest: str,
    _version1: bool) -> _OriginalControlProjection:
    """Existing checks AFTER the payload slot; no actual-content proof here."""
    effect=plan['effects'][0];candidate=intent['candidate'];value=candidate['storage']['value']
    inputs=intent['inputs'];binding=intent['contract']
    implementation=intent['implementation_binding']
    operation='publish_new_version' if _version1 else 'create'
    root_records=intent['idempotency']['root_identities']
    _canonical(installed_root_grants)
    _require(canonical_bytes(root_records)==installed_root_grants and len(root_records)==1,'ntfs.original_installed_roots_mismatch')
    grants=[_grant(row) for row in root_records]
    _require({grant.binding for grant in grants}=={root['binding_id'] for root in contract.document['write_scope']['roots']}
        and len({grant.binding for grant in grants})==len(grants)
        and not {grant.binding for grant in grants}.intersection(contract.document['write_scope']['forbidden_root_bindings'])
        and grants[0].binding==effect['target']['root_binding'],'ntfs.original_root_binding_mismatch')
    root_digest=profile_digest('native-root-identity-v1',root_records)
    id_scope={'contract':binding,'result_locator':value['target_locator'],'root_identity_digest':root_digest,'operation_intent':operation}
    _require(intent['idempotency']['root_identity_digest']==root_digest
        and intent['idempotency']['scope_digest']==profile_digest('idempotency-scope',id_scope)
        and intent['idempotency']['request_digest']==profile_digest('request',{'scope':id_scope,
            'candidate_digest':candidate['digest'],'inputs':inputs}),'ntfs.original_idempotency_binding_mismatch')
    _require(type(pre_validator_bytes) is bytes and len(pre_validator_bytes)<=_CONTROL_LIMIT,
        'ntfs.original_precondition_bytes_required')
    verify_saved_precondition_results(registry,contract,intent,plan,pre_validator_bytes)
    native=intent['native_binding']
    context={'worker_protocol':'phase.native.file-worker','worker_version':'1.1' if _version1 else '1.0','run_id':intent['run_id'],
        'intent_digest':expected_intent_digest,'effect_plan_digest':intent['effect_plan_digest'],
        'native_binding_digest':digest_bytes(canonical_bytes(native)),
        'installation_digest':native['installation']['descriptor_digest'],
        'implementation_artifact_digest':implementation['authority']['provider']['artifact_digest'],
        'operation_nonce':native['operation_nonce']}
    checked_context=_version1_context(context) if _version1 else _context(context)
    return _OriginalControlProjection(canonical_bytes(checked_context),canonical_bytes(grants[0].as_dict()),
        canonical_bytes(effect),intent['created_at'],effect['input_binding'],effect['content_digest'],
        effect['content_length'])


def _parse_original_controls(*, intent_bytes: bytes, plan_bytes: bytes,
    pre_validator_bytes: bytes, registry: RegistrySnapshot,
    expected_run_id: str, expected_intent_digest: str, installed_core_binding: bytes,
    installed_native_binding: bytes, installed_root_grants: bytes,
    installed_implementation_binding: bytes, _execution_requested: bool,
    _version1: bool = False) -> _OriginalControlProjection:
    """Same complete control semantics, DECLARED content only, never a handoff.

    This private seam adds no installed role or file2 selection. Historical full
    wrappers below MUST verify actual bytes before the shared suffix. A future
    closed composition must independently bind its own real verified snapshot.
    """
    intent,plan,contract=_original_control_prefix(
        intent_bytes=intent_bytes,plan_bytes=plan_bytes,registry=registry,
        expected_run_id=expected_run_id,expected_intent_digest=expected_intent_digest,
        installed_core_binding=installed_core_binding,installed_native_binding=installed_native_binding,
        installed_implementation_binding=installed_implementation_binding,
        _execution_requested=_execution_requested,_version1=_version1)
    effect=plan['effects'][0]
    length,digest=effect['content_length'],effect['content_digest']
    maximum=16*1024**2 if _version1 else 1024**2
    _require(type(length) is int and 0<=length<=maximum
        and type(digest) is str and re.fullmatch('sha256:[0-9a-f]{64}',digest) is not None,
        'ntfs.original_declared_content_bound')
    _original_content_binding(intent,plan,digest,length)
    return _original_control_suffix(
        intent=intent,plan=plan,contract=contract,registry=registry,
        pre_validator_bytes=pre_validator_bytes,installed_root_grants=installed_root_grants,
        expected_intent_digest=expected_intent_digest,_version1=_version1)


def _parse_original(*, intent_bytes: bytes, plan_bytes: bytes,
    pre_validator_bytes: bytes, blob_bytes: bytes, registry: RegistrySnapshot,
    expected_run_id: str, expected_intent_digest: str, installed_core_binding: bytes,
    installed_native_binding: bytes, installed_root_grants: bytes,
    installed_implementation_binding: bytes, _execution_requested: bool,
    _version1: bool = False) -> ParsedNativeFileCreate | ParsedNativeVersion1:
    """Validate exact buffers before a future installation-owned handoff.

    Installed buffers are supplied by the FUTURE closed selector, not a broker
    request or self-asserted credentials. Their authentication/actual graph and
    root/evidence observations are NOT performed here. This parser is unselected
    and cannot dispatch through normal Core while A05/G01 remains unverified.
    The first structural subset is existing single frozen-input file_create-v1,
    <=1MiB, existing parents. No new contract/limits or recovery permission.
    """
    intent,plan,contract=_original_control_prefix(
        intent_bytes=intent_bytes,plan_bytes=plan_bytes,registry=registry,
        expected_run_id=expected_run_id,expected_intent_digest=expected_intent_digest,
        installed_core_binding=installed_core_binding,installed_native_binding=installed_native_binding,
        installed_implementation_binding=installed_implementation_binding,
        _execution_requested=_execution_requested,_version1=_version1)
    _verify_original_blob_bytes(intent,plan,blob_bytes,_version1=_version1)
    projection=_original_control_suffix(
        intent=intent,plan=plan,contract=contract,registry=registry,
        pre_validator_bytes=pre_validator_bytes,installed_root_grants=installed_root_grants,
        expected_intent_digest=expected_intent_digest,_version1=_version1)
    result_type=ParsedNativeVersion1 if _version1 else ParsedNativeFileCreate
    return result_type(projection.context_bytes,projection.grant_bytes,projection.effect_bytes,
        blob_bytes,projection.timestamp)


def parse_original_file_create(*, intent_bytes: bytes, plan_bytes: bytes,
    pre_validator_bytes: bytes, blob_bytes: bytes, registry: RegistrySnapshot,
    expected_run_id: str, expected_intent_digest: str, installed_core_binding: bytes,
    installed_native_binding: bytes, installed_root_grants: bytes,
    installed_implementation_binding: bytes) -> ParsedNativeFileCreate:
    """Executing original only; never accept planned data for worker handoff."""
    return _parse_original(intent_bytes=intent_bytes,plan_bytes=plan_bytes,pre_validator_bytes=pre_validator_bytes,
        blob_bytes=blob_bytes,registry=registry,expected_run_id=expected_run_id,
        expected_intent_digest=expected_intent_digest,installed_core_binding=installed_core_binding,
        installed_native_binding=installed_native_binding,installed_root_grants=installed_root_grants,
        installed_implementation_binding=installed_implementation_binding,_execution_requested=True)


def validate_planned_file_create_original(*, intent_bytes: bytes, plan_bytes: bytes,
    pre_validator_bytes: bytes, blob_bytes: bytes, registry: RegistrySnapshot,
    expected_run_id: str, expected_intent_digest: str, installed_core_binding: bytes,
    installed_native_binding: bytes, installed_root_grants: bytes,
    installed_implementation_binding: bytes) -> None:
    """Same semantic parser for planned-only historical closure; returns no GO data."""
    _parse_original(intent_bytes=intent_bytes,plan_bytes=plan_bytes,pre_validator_bytes=pre_validator_bytes,
        blob_bytes=blob_bytes,registry=registry,expected_run_id=expected_run_id,
        expected_intent_digest=expected_intent_digest,installed_core_binding=installed_core_binding,
        installed_native_binding=installed_native_binding,installed_root_grants=installed_root_grants,
        installed_implementation_binding=installed_implementation_binding,_execution_requested=False)



def parse_original_version1(*, intent_bytes: bytes, plan_bytes: bytes,
    pre_validator_bytes: bytes, blob_bytes: bytes, registry: RegistrySnapshot,
    expected_run_id: str, expected_intent_digest: str, installed_core_binding: bytes,
    installed_native_binding: bytes, installed_root_grants: bytes,
    installed_implementation_binding: bytes) -> ParsedNativeVersion1:
    """Closed version1 executing tuple; no generic role or transport selector."""
    return _parse_original(intent_bytes=intent_bytes,plan_bytes=plan_bytes,pre_validator_bytes=pre_validator_bytes,
        blob_bytes=blob_bytes,registry=registry,expected_run_id=expected_run_id,
        expected_intent_digest=expected_intent_digest,installed_core_binding=installed_core_binding,
        installed_native_binding=installed_native_binding,installed_root_grants=installed_root_grants,
        installed_implementation_binding=installed_implementation_binding,_execution_requested=True,_version1=True)


def validate_planned_version1_original(*, intent_bytes: bytes, plan_bytes: bytes,
    pre_validator_bytes: bytes, blob_bytes: bytes, registry: RegistrySnapshot,
    expected_run_id: str, expected_intent_digest: str, installed_core_binding: bytes,
    installed_native_binding: bytes, installed_root_grants: bytes,
    installed_implementation_binding: bytes) -> None:
    """The same version1 semantics for nonexecuting closure; no GO tuple returned."""
    _parse_original(intent_bytes=intent_bytes,plan_bytes=plan_bytes,pre_validator_bytes=pre_validator_bytes,
        blob_bytes=blob_bytes,registry=registry,expected_run_id=expected_run_id,
        expected_intent_digest=expected_intent_digest,installed_core_binding=installed_core_binding,
        installed_native_binding=installed_native_binding,installed_root_grants=installed_root_grants,
        installed_implementation_binding=installed_implementation_binding,_execution_requested=False,_version1=True)
