"""Closed Version1 experiment data; the existing parser and worker own semantics.

No certificate, dynamic profile selection or independent history is introduced.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from ...canonical import canonical_bytes, digest_bytes
from ...contracts.publish_new_version_v1 import archive_locator
from .experimental_file1 import _ExperimentalFile1Admission
from .native import _require

_VERSION1_CONTRACT = {'id': 'publish_new_version.v1', 'version': '1.0.0',
    'package_digest': 'sha256:5f311c95f75a098e96bd8b69b0845ead41c005d94759d9b523c2a161bf1f8fa1'}


@dataclass(frozen=True)
class _ExperimentalVersion1Admission(_ExperimentalFile1Admission):
    _contract: ClassVar[dict] = _VERSION1_CONTRACT
    _profile: ClassVar[str] = 'phase.native.ntfs.experiment.version1.authority.v1@1.0.0'
    _manifest_version: ClassVar[str] = '1.2'
    _installation_prefix: ClassVar[str] = 'phase.experiment.version1.'
    _authority_artifact: ClassVar[str] = 'phase_tool/mutation/ntfs/experimental_version1_authority.py'
    _minimum_payload_length: ClassVar[int] = 0
    _maximum_payload_length: ClassVar[int] = 16*1024**2
    _required: ClassVar[frozenset[str]] = frozenset({
        'exclusive_create', 'readback_verification', 'cross_process_serialization',
        'namespace_bound_mutation', 'namespace_metadata_flush_attempted'})

    def check_original(self, intent, plan):
        # Called only AFTER the complete existing Version1 original parser,
        # including actual frozen bytes and saved precondition verification.
        # The full candidate digest binds expected_current_digest and hence the
        # deterministic archive. Real before/after identities are observed by
        # the existing hook and worker, never asserted by this capability.
        doc = self.document()
        value = intent['candidate']['storage']['value']
        inputs, effects = intent['inputs'], plan['effects']
        _require(intent['run_id'] == plan['run_id'] == doc['run_id']
            and intent['contract'] == plan['contract'] == doc['contract']
            and value['idempotency_key'] == doc['request_id']
            and value['target_locator'] == doc['target_locator']
            and digest_bytes(canonical_bytes(value)) == doc['candidate_digest']
            and len(inputs) == len(effects) == 1, 'ntfs.experimental_original_mismatch')
        effect, frozen = effects[0], inputs[0]
        archive = archive_locator(value['expected_current_digest'])
        root = doc['root_grant']['root_binding']
        _require(frozen['binding_id'] == value['input_binding'] == 'payload'
            and frozen['digest'] == frozen['blob_digest'] == doc['payload_digest']
            and frozen['freeze_strategy'] == 'copy_and_hash'
            and effect['kind'] == 'publish_new_version'
            and effect['input_binding'] == 'payload'
            and effect['target'] == {'root_binding': root, 'relative_locator': doc['target_locator']}
            and archive != doc['target_locator']
            and effect['archive_target'] == {'root_binding': root, 'relative_locator': archive}
            and effect['archive_digest'] == value['expected_current_digest']
            and type(effect['archive_length']) is int and 0 <= effect['archive_length'] <= 16*1024**2
            and effect['operation_identity'] == value['operation_id']
            and effect['preconditions'] == {'existence': 'present',
                'expected_digest': value['expected_current_digest'], 'expected_head': None,
                'concurrency_token': value['expected_current_digest']}
            and effect['content_digest'] == doc['payload_digest']
            and effect['content_length'] == doc['payload_length'],
            'ntfs.experimental_original_mismatch')
