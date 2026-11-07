"""Literal isolated bundle1 admission; ordinary startup cannot select it."""
from dataclasses import dataclass
from typing import ClassVar
from ...canonical import canonical_bytes, digest_bytes
from .experimental_file1 import _ExperimentalFile1Admission
from .bundle_execution import _BUNDLE1_CONTRACT
from .native import _require


@dataclass(frozen=True)
class _ExperimentalBundle1Admission(_ExperimentalFile1Admission):
    _contract: ClassVar[dict]=_BUNDLE1_CONTRACT
    _profile: ClassVar[str]='phase.native.ntfs.experiment.bundle1.authority.v1@1.0.0'
    _manifest_version: ClassVar[str]='1.6'
    _installation_prefix: ClassVar[str]='phase.experiment.bundle1.'
    _authority_artifact: ClassVar[str]='phase_tool/mutation/ntfs/experimental_bundle1_authority.py'
    _required: ClassVar[frozenset[str]]=frozenset({'exclusive_create','readback_verification',
        'cross_process_serialization','namespace_bound_mutation','namespace_metadata_flush_attempted'})

    def check_original(self,intent,plan):
        doc=self.document();value=intent['candidate']['storage']['value'];inputs=intent['inputs']
        _require(intent['run_id']==plan['run_id']==doc['run_id']
            and intent['contract']==plan['contract']==doc['contract']
            and value['idempotency_key']==doc['request_id'] and value['target_locator']==doc['target_locator']
            and digest_bytes(canonical_bytes(value))==doc['candidate_digest']
            and len(inputs)==len(plan['effects'])==1 and inputs[0]['binding_id']==value['input_binding']=='payload'
            and inputs[0]['freeze_strategy']=='manifest_and_hash'
            and inputs[0]['digest']==inputs[0]['blob_digest']==inputs[0]['manifest_digest']==doc['payload_digest']
            and plan['effects'][0]['content_digest']==doc['payload_digest']
            and type(plan['effects'][0]['content_length']) is int
            and plan['effects'][0]['content_length']==doc['payload_length'],
            'ntfs.experimental_original_mismatch')
