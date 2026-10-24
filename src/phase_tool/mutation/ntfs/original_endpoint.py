"""DRAFT fixed Linux RO endpoint using the existing original reader/parser.
No EvidenceStore, target I/O, fsync, worker/GO, write, recovery or receipt owner.
Only accepted installed launch data select roots/registry. Query data cannot.
"""
from __future__ import annotations
import base64
from pathlib import Path
import re

from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from ...installation import (_NativeFileCreateReadBinding,_native_qualified_profile,
    _native_inspection_file_create_registry,_native_registry_for_manifest,_resolve_native_file_create_read_binding)
from .native import _require



def native_original_query(launch,query):
    from .bootstrap import _NativeAcceptedLaunch
    from ...evidence import _confirm_native_original_absent
    _require(type(launch) is _NativeAcceptedLaunch,'ntfs.accepted_launch_binding_required')
    launch.check_runtime()
    _require(type(query) is dict and set(query)=={'native_original_query_version','action','run_id',
        'intent_digest','operation_nonce','installation_digest','channel_id'}
        and query['native_original_query_version']=='1.0'
        and type(query['run_id']) is str
        and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',query['run_id']) is not None
        and query['run_id'] not in {'.','..'}
        and type(query['operation_nonce']) is str
        and re.fullmatch('[0-9a-f]{32}',query['operation_nonce']) is not None
        and query['channel_id']==launch.channel_id
        and query['installation_digest']==launch.installation_digest
        and query['action'] in {'read_executing','verify_no_dispatch'}
        and (query['intent_digest'] is None or (type(query['intent_digest']) is str
            and re.fullmatch('sha256:[0-9a-f]{64}',query['intent_digest']) is not None)),
        'ntfs.original_query_binding_mismatch')
    registry=_native_registry_for_manifest(launch._manifest_bytes,launch.installation_digest)  # Accepted static generation only.
    _native_qualified_profile(registry,registry.guarantee_profile_bindings().get(
        'phase.native.ntfs.authority.v1@1.0.0'))  # Candidate always refuses, even empty requirements.
    binding=_resolve_native_file_create_read_binding(manifest_bytes=launch._manifest_bytes,
        expected_manifest_digest=launch.installation_digest,registry=registry)
    binding.check_evidence_root()
    digest=query['intent_digest']
    if digest is None:
        _require(query['action']=='verify_no_dispatch','ntfs.original_intent_digest_required')
        _confirm_native_original_absent(binding,query['run_id'])
        value={'original_absent':True,'verified_intent_digest':None}
    else:
        from .reader import read_original_file_create_buffers,read_original_version1_buffers
        reader = read_original_version1_buffers if launch._version1 else read_original_file_create_buffers
        original,_,_,_=reader(
            evidence_root=Path(launch.manifest['evidence_root']),
            installed_evidence_identity=canonical_bytes(launch.manifest['evidence_identity']),
            registry=registry,run_id=query['run_id'],expected_intent_digest=digest)
        intent=parse_json_bytes(original,maximum_bytes=2*1024**2)
        _require(intent['native_binding']['operation_nonce']==query['operation_nonce'],
            'ntfs.original_current_invocation_mismatch')
        if query['action']=='read_executing':
            parsed=binding.read(run_id=query['run_id'],intent_digest=digest)
            if launch._version1:
                value=parsed
            else:
                value={'context':parse_json_bytes(parsed.context_bytes),'grant':parse_json_bytes(parsed.grant_bytes),
                    'effect':parse_json_bytes(parsed.effect_bytes),
                    'content_base64':base64.b64encode(parsed.content_bytes).decode('ascii'),'timestamp':parsed.timestamp}
        else:
            if intent['execution_requested'] is True:binding.read(run_id=query['run_id'],intent_digest=digest)
            else:binding.validate_planned(run_id=query['run_id'],intent_digest=digest)
            value={'original_absent':False,'verified_intent_digest':digest}
    binding.check_evidence_root()
    launch.check_runtime()
    from .handoff import ParsedNativeVersion1
    if type(value) is ParsedNativeVersion1:
        return value
    return {'query':query,'value':value,'required_evidence_reads_finalized':True}
