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


def _check_original_root_identity(root: Path, expected: dict) -> None:
    """Fresh actual root identity; no cached namespace acceptance."""
    info=root.stat(follow_symlinks=False)
    _require(stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==(expected['device'],expected['inode']),
        'ntfs.original_evidence_identity_mismatch')


def _read_original_control_buffers(*, evidence_root: Path,
    installed_evidence_identity: bytes, registry: RegistrySnapshot,
    run_id: str, expected_intent_digest: str, _version2: bool = False, _bundle: bool = False) -> tuple[bytes,bytes,bytes]:
    """Read three existing raw controls; never a parsed handoff or GO token.

    The full reader/parser still owns content and semantic verification.
    This private RO seam neither reads a payload nor creates a snapshot.
    Callers keep the SAME expected intent digest and installed binding.
    """
    _require(sys.platform.startswith('linux'),'ntfs.original_linux_reader_required')
    _require(type(_version2) is bool and type(_bundle) is bool and not (_version2 and _bundle),'ntfs.original_closed_role_required')
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

    _check_original_root_identity(root,expected)
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
    if _bundle:
        _frozen_bundle_digest(intent)
    elif _version2:
        _require(intent['contract']['id']=='publish_new_version.v2' and intent['inputs']==[],
            'ntfs.original_version2_content_binding')
    else:
        # Preserve the fixed frozen roles' early error ordering, before plan
        # or validator reads. This is a content role, never storage admission.
        _frozen_original_digest(intent)
    plan=read_bounded_file(run/'attachments'/'effect-plan.json',_CONTROL_LIMIT)
    # Core already stores planned results under validator-results.json. Do not
    # manufacture an executing pre-validator attachment for a planned original.
    pre_name = ('pre-validator-results.json' if intent['execution_requested']
        else 'validator-results.json')
    pre=read_bounded_file(run/'attachments'/pre_name,_CONTROL_LIMIT)
    _require(digest_bytes(plan)==intent['evidence']['effect_plan_attachment_digest']
        and digest_bytes(pre)==intent['evidence']['pre_validator_results_digest'],'ntfs.original_evidence_bytes_mismatch')
    _check_original_root_identity(root,expected)
    return intent_raw,plan,pre


def _frozen_original_digest(intent):
    """The existing fixed frozen-input roles retain their full requirement."""
    _require(len(intent['inputs'])==1 and intent['inputs'][0]['freeze_strategy']=='copy_and_hash',
        'ntfs.original_frozen_input_required')
    digest=intent['inputs'][0]['blob_digest']
    _require(type(digest) is str and _DIGEST.fullmatch(digest) is not None,
        'ntfs.original_frozen_input_required')
    return digest



def _read_original_buffers(*, evidence_root: Path,
    installed_evidence_identity: bytes, registry: RegistrySnapshot,
    run_id: str, expected_intent_digest: str, _maximum_bytes: int) -> tuple[bytes,bytes,bytes,bytes]:
    """Historical full byte tuples and fixed role bounds, never metadata-only."""
    _require(type(_maximum_bytes) is int and _maximum_bytes in (_CONTENT_LIMIT,16*1024**2),
        'ntfs.invalid_original_bound')
    intent_raw,plan,pre=_read_original_control_buffers(evidence_root=evidence_root,
        installed_evidence_identity=installed_evidence_identity,registry=registry,
        run_id=run_id,expected_intent_digest=expected_intent_digest)
    intent=parse_json_bytes(intent_raw,maximum_bytes=_CONTROL_LIMIT)
    root=Path(evidence_root)
    expected=_evidence_identity(installed_evidence_identity)
    blob_digest=_frozen_original_digest(intent)
    blob_path=root/'.phase'/'runs'/run_id/'blobs'/blob_digest.removeprefix('sha256:')
    _check_original_root_identity(root,expected)
    blob=read_bounded_file(blob_path,_maximum_bytes)
    _require(digest_bytes(blob)==blob_digest,'ntfs.original_evidence_bytes_mismatch')
    _check_original_root_identity(root,expected)
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


def read_original_version2_buffers(*, evidence_root: Path,
    installed_evidence_identity: bytes, registry: RegistrySnapshot,
    run_id: str, expected_intent_digest: str) -> tuple[bytes,bytes,bytes,bytes]:
    """Read the existing captured content blob, not a fabricated frozen input.

    This is still only a bounded reader. The fixed read binding MUST invoke
    parse_original_version2 with its installed expectations before handoff.
    """
    intent_raw,plan_raw,pre=_read_original_control_buffers(evidence_root=evidence_root,
        installed_evidence_identity=installed_evidence_identity,registry=registry,
        run_id=run_id,expected_intent_digest=expected_intent_digest,_version2=True)
    from .intent import _canonical, _version2_content_binding
    intent,plan=_canonical(intent_raw),_canonical(plan_raw)
    _require(intent['contract']['id']=='publish_new_version.v2','ntfs.original_version2_effect_required')
    content=_version2_content_binding(intent,plan)
    root=Path(evidence_root);expected=_evidence_identity(installed_evidence_identity)
    digest=digest_bytes(content)
    _check_original_root_identity(root,expected)
    blob=read_bounded_file(root/'.phase'/'runs'/run_id/'blobs'/digest[7:],512*1024)
    _require(blob==content,'ntfs.original_evidence_bytes_mismatch')
    _check_original_root_identity(root,expected)
    return intent_raw,plan_raw,pre,blob


def _verify_file2_original_blob(*, evidence_root: Path,
    installed_evidence_identity: bytes, intent: dict, projection) -> None:
    """Actual complete RO file2 hash, bounded memory, no snapshot/temp/target I/O.

    Only the installed read binding calls AFTER the fixed complete control parser.
    A declaration projection by itself never proves content or installation.
    """
    from .handoff import _OriginalControlProjection
    from ...streaming import FILE_LIMIT, hash_file
    _require(sys.platform.startswith('linux') and type(projection) is _OriginalControlProjection,
        'ntfs.original_file2_projection_required')
    _require(intent['contract']['id']=='file_create.v2' and len(intent['inputs'])==1,
        'ntfs.original_file2_effect_required')
    _frozen_original_digest(intent)
    frozen=intent['inputs'][0]
    _require(frozen['binding_id']==projection.input_binding=='payload'
        and frozen['freeze_strategy']=='copy_and_hash'
        and frozen['blob_digest']==frozen['digest']==projection.content_digest
        and type(projection.content_length) is int and 0<=projection.content_length<=FILE_LIMIT,
        'ntfs.original_content_binding_mismatch')
    expected=_evidence_identity(installed_evidence_identity);root=Path(evidence_root)
    _require(root.is_absolute(),'ntfs.original_evidence_root_required')
    qualify_host_authority_roots({'phase_evidence_root':root})
    _require(_linux_filesystem_type(root)=='ext4','ntfs.original_ext4_evidence_required')
    _check_original_root_identity(root,expected)
    validate_run_id(intent['run_id'])
    blob=root/'.phase'/'runs'/intent['run_id']/'blobs'/projection.content_digest.removeprefix('sha256:')
    actual=hash_file(blob,FILE_LIMIT)
    _require(actual==(projection.content_digest,projection.content_length),
        'ntfs.original_evidence_bytes_mismatch')
    _check_original_root_identity(root,expected)


def _frozen_bundle_digest(intent):
    _require(intent['contract']['id']=='bundle_create.v1' and len(intent['inputs'])==1,
        'ntfs.original_bundle_effect_required')
    frozen=intent['inputs'][0]
    _require(frozen['binding_id']=='payload' and frozen['freeze_strategy']=='manifest_and_hash'
        and type(frozen['blob_digest']) is str and _DIGEST.fullmatch(frozen['blob_digest']) is not None
        and frozen['blob_digest']==frozen['digest']==frozen['manifest_digest'],
        'ntfs.original_bundle_manifest_mismatch')
    return frozen['blob_digest']


def _verify_bundle_original_blobs(*,evidence_root,installed_evidence_identity,intent,projection):
    """Complete independent RO member-byte check, never declarations as bytes."""
    from ...bundle import parse_manifest, verify_frozen_members
    from .bundle_execution import _bundle_projection_value
    _require(sys.platform.startswith('linux'),'ntfs.original_linux_reader_required')
    _bundle_projection_value(projection)
    expected=_evidence_identity(installed_evidence_identity);root=Path(evidence_root)
    qualify_host_authority_roots({'phase_evidence_root':root})
    _require(_linux_filesystem_type(root)=='ext4','ntfs.original_ext4_evidence_required')
    _check_original_root_identity(root,expected);validate_run_id(intent['run_id'])
    digest=_frozen_bundle_digest(intent)
    _require(digest==projection.content_digest,'ntfs.original_bundle_manifest_mismatch')
    blobs=root/'.phase'/'runs'/intent['run_id']/'blobs'
    raw=read_bounded_file(blobs/digest.removeprefix('sha256:'),1024**2)
    _require(raw==projection.manifest_bytes,'ntfs.original_evidence_bytes_mismatch')
    verify_frozen_members(parse_manifest(raw),blobs)
    _check_original_root_identity(root,expected)
