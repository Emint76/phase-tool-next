"""Unselected Linux/ext4 original-buffer reader; no transport or authority.

Only a future trusted installed endpoint may supply the root, expected identity
and registry. Its external request stays run_id + original intent digest. This
helper does not establish that endpoint/bootstrap or grant GO/retry permission.
No EvidenceStore construction, target access, mutable state or publication.
"""
from __future__ import annotations

from pathlib import Path
import re
import stat
import sys

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ...evidence import validate_intent, validate_run_id
from ...installation import _linux_filesystem_type, qualify_host_authority_roots
from ...registry import RegistrySnapshot
from ...streaming import read_bounded_file
from .native import _require

_CONTROL_LIMIT=2*1024**2
_CONTENT_LIMIT=1024**2  # Existing single frozen-input file_create.v1 subset.
_DIGEST=re.compile(r'sha256:[0-9a-f]{64}')


def _evidence_identity(raw: bytes) -> dict:
    """Existing pure identity validation, shared by the unselected read binding."""
    _require(type(raw) is bytes and len(raw)<=4096,
        'ntfs.original_evidence_identity_required')
    expected=parse_json_bytes(raw,maximum_bytes=4096)
    _require(type(expected) is dict and set(expected)=={'stable_id','device','inode'}
        and canonical_bytes(expected)==raw
        and type(expected['stable_id']) is str and re.fullmatch(r'[a-z][a-z0-9._-]{0,127}',expected['stable_id']) is not None
        and type(expected['device']) is int and expected['device']>=0
        and type(expected['inode']) is int and expected['inode']>0,'ntfs.original_evidence_identity_required')
    return expected


def _read_original_buffers(*, evidence_root: Path,
    installed_evidence_identity: bytes, registry: RegistrySnapshot,
    run_id: str, expected_intent_digest: str, _maximum_bytes: int) -> tuple[bytes,bytes,bytes,bytes]:
    """Read only four existing Core objects, preserving their original bytes.

    Matching hashes establish data consistency, not the identity of a remote
    daemon/container/loaded program. That fixed trusted selector, full artifact
    graph/bootstrap, framing and current-invocation/root-lock/unresolved guard
    remain outside and unimplemented. This is not a callable native route.
    The existing original-buffer parser owns complete structural semantics.
    """
    _require(type(_maximum_bytes) is int and _maximum_bytes in (_CONTENT_LIMIT,16*1024**2),
        'ntfs.invalid_original_bound')
    _require(sys.platform.startswith('linux'),'ntfs.original_linux_reader_required')
    _require(type(registry) is RegistrySnapshot,'ntfs.original_registry_required')
    _require(type(run_id) is str,'evidence.invalid_run_id')
    validate_run_id(run_id)
    _require(type(expected_intent_digest) is str and _DIGEST.fullmatch(expected_intent_digest) is not None,
        'ntfs.original_intent_digest_required')
    expected=_evidence_identity(installed_evidence_identity)
    root=Path(evidence_root)
    _require(root.is_absolute(),'ntfs.original_evidence_root_required')
    qualify_host_authority_roots({'phase_evidence_root':root})
    _require(_linux_filesystem_type(root)=='ext4','ntfs.original_ext4_evidence_required')

    def check_root():
        info=root.stat(follow_symlinks=False)
        _require(stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(expected['device'],expected['inode']),
            'ntfs.original_evidence_identity_mismatch')

    check_root()
    run=root/'.phase'/'runs'/run_id
    intent_raw=read_bounded_file(run/'intent.json',_CONTROL_LIMIT)
    intent=parse_json_bytes(intent_raw,maximum_bytes=_CONTROL_LIMIT)
    _require(type(intent) is dict and canonical_bytes(intent)==intent_raw
        and intent.get('phase_intent_version')=='1.2','ntfs.original_native_intent_required')
    validate_intent(intent,registry)
    _require(intent['run_id']==run_id and profile_digest('intent',intent)==expected_intent_digest
        and intent['registry_snapshot_digest']==registry.digest,'ntfs.original_intent_mismatch')
    _require(canonical_bytes(intent['native_binding']['evidence_identity'])==installed_evidence_identity,
        'ntfs.original_evidence_identity_mismatch')
    _require(len(intent['inputs'])==1 and intent['inputs'][0]['freeze_strategy']=='copy_and_hash',
        'ntfs.original_frozen_input_required')
    blob_digest=intent['inputs'][0]['blob_digest']
    _require(type(blob_digest) is str and _DIGEST.fullmatch(blob_digest) is not None,
        'ntfs.original_frozen_input_required')
    plan=read_bounded_file(run/'attachments'/'effect-plan.json',_CONTROL_LIMIT)
    # Core already stores planned results under validator-results.json. Do not
    # manufacture an executing pre-validator attachment for a planned original.
    pre_name = ('pre-validator-results.json' if intent['execution_requested']
        else 'validator-results.json')
    pre=read_bounded_file(run/'attachments'/pre_name,_CONTROL_LIMIT)
    blob=read_bounded_file(run/'blobs'/blob_digest.removeprefix('sha256:'),_maximum_bytes)
    _require(digest_bytes(plan)==intent['evidence']['effect_plan_attachment_digest']
        and digest_bytes(pre)==intent['evidence']['pre_validator_results_digest']
        and digest_bytes(blob)==blob_digest,'ntfs.original_evidence_bytes_mismatch')
    check_root()
    return intent_raw,plan,pre,blob



def read_original_file_create_buffers(*, evidence_root: Path,
    installed_evidence_identity: bytes, registry: RegistrySnapshot,
    run_id: str, expected_intent_digest: str) -> tuple[bytes,bytes,bytes,bytes]:
    """Original1MiB bound and external signature; no request-selected size."""
    return _read_original_buffers(evidence_root=evidence_root,
        installed_evidence_identity=installed_evidence_identity,registry=registry,
        run_id=run_id,expected_intent_digest=expected_intent_digest,_maximum_bytes=_CONTENT_LIMIT)


def read_original_version1_buffers(*, evidence_root: Path,
    installed_evidence_identity: bytes, registry: RegistrySnapshot,
    run_id: str, expected_intent_digest: str) -> tuple[bytes,bytes,bytes,bytes]:
    """Same four Core-owned objects, with the existing version1 contract16MiB bound."""
    return _read_original_buffers(evidence_root=evidence_root,
        installed_evidence_identity=installed_evidence_identity,registry=registry,
        run_id=run_id,expected_intent_digest=expected_intent_digest,_maximum_bytes=16*1024**2)
