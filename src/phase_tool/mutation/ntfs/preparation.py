"""Private file1 preparation inside the existing admitted MIX namespace.

This is not a publisher, admission replacement, outcome journal or cleanup owner.
Core must still capture the prepared bytes and recheck normal admission. Scratch
is retained like caller-prepared input; an uncertain outcome never deletes it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from tempfile import NamedTemporaryFile, mkdtemp

from ...canonical import canonical_bytes, parse_json_bytes
from ...errors import PhaseError
from ...evidence import validate_run_id
from ...freeze import copy_and_hash, revalidate_frozen
from ...paths import safe_relative_locator
from ...publish_file import CONTRACT_BINDING, MAX_BYTES, _file_publication_candidate


def _prepare_file_publication(application, *, source_locator, target_locator,
        request_id, expected_digest):
    """Return only existing Core prepared arguments, never a success claim.

    The fixed manifest's preparation root is the source namespace. No arbitrary
    host root is accepted. Target projections remain lexical and opaque here.
    This function must finish before Core starts; its caller must not catch a
    later Core failure as an ordinary preparation rejection.
    """
    from ...installation import _NativeFileCreateInstallation
    from .native import _require
    installation = application.installation
    _require(type(installation) is _NativeFileCreateInstallation
        and application.registry is installation.read_binding.registry,
        'ntfs.closed_native_installation_required')
    installation.authority._execution_required()
    manifest = parse_json_bytes(installation.read_binding.manifest_bytes,
        maximum_bytes=2*1024**2)
    roots = {k: Path(v) for k, v in manifest['root_projections'].items()}
    # Includes the authority's real profile check; no cached admission or flag.
    manifest = installation._check_preparation_namespace(root_bindings=roots,
        evidence_root=Path(manifest['evidence_root']), maximum_candidate_bytes=1024**2)
    binding = application._binding(CONTRACT_BINDING)
    _require(manifest['contract'] == binding, 'ntfs.original_single_effect_required')
    validate_run_id(installation.authority._run_id)
    if type(request_id) is not str or len(request_id) > 128 or not re.fullmatch(
            r'[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*', request_id):
        raise PhaseError('publish_file.invalid_request_id')
    if expected_digest is not None and (type(expected_digest) is not str or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest)):
        raise PhaseError('publish_file.invalid_expected_digest')
    source_locator = safe_relative_locator(source_locator)
    target_locator = safe_relative_locator(target_locator)
    _, candidate_bytes = _file_publication_candidate(request_id, target_locator)
    preparation = Path(manifest['preparation_root'])
    scratch = Path(mkdtemp(prefix='phase-native-publish-', dir=preparation))
    frozen = copy_and_hash('payload', preparation, source_locator, scratch,
        frozen_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        maximum_bytes=MAX_BYTES)
    if expected_digest is not None and frozen.digest != expected_digest:
        raise PhaseError('publish_file.source_digest_mismatch')
    revalidate_frozen(frozen)
    _require(frozen.blob_path is not None, 'freeze.blob_missing')
    with NamedTemporaryFile(mode='wb', suffix='.json', dir=scratch,
            delete=False) as temporary:
        temporary.write(candidate_bytes)
        candidate_path = Path(temporary.name)
    return (candidate_path, {'payload': frozen.blob_path},
        {'payload': (frozen.digest, frozen.length)}, candidate_bytes)


def _version1_publication_candidate(request_id, target_locator, expected_current_digest):
    """Pure fixed v1 candidate; existing contract owns all version semantics."""
    from ...contracts.publish_new_version_v1 import archive_locator
    if type(request_id) is not str or len(request_id) > 128 or not re.fullmatch(
            r'[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*', request_id):
        raise PhaseError('publish.invalid_request_id')
    if type(expected_current_digest) is not str or not re.fullmatch(
            r'sha256:[0-9a-f]{64}', expected_current_digest):
        raise PhaseError('publish.current_digest_invalid')
    if type(target_locator) is not str:
        raise PhaseError('ntfs.fixed_native_request_required')
    target_locator = safe_relative_locator(target_locator)
    if target_locator == archive_locator(expected_current_digest):
        raise PhaseError('publish.target_archive_collision')
    candidate = {'operation_id': request_id, 'idempotency_key': request_id,
        'target_locator': target_locator, 'input_binding': 'payload',
        'expected_current_digest': expected_current_digest}
    return candidate, canonical_bytes(candidate)


def _prepare_version1_publication(application, *, source_locator, target_locator,
        request_id, expected_current_digest, expected_digest):
    """Freeze only admitted ext4 input; Core owns archive/publish and evidence.

    No Linux projection of the Windows target is read or mutated here. Scratch
    remains after failure/uncertainty, exactly like the existing file1 path.
    """
    from ...installation import _NativeFileCreateInstallation
    from .native import _require
    installation = application.installation
    _require(type(installation) is _NativeFileCreateInstallation
        and application.registry is installation.read_binding.registry,
        'ntfs.closed_native_installation_required')
    installation.authority._execution_required()
    manifest = parse_json_bytes(installation.read_binding.manifest_bytes,
        maximum_bytes=2*1024**2)
    roots = {k: Path(v) for k, v in manifest['root_projections'].items()}
    manifest = installation._check_preparation_namespace(root_bindings=roots,
        evidence_root=Path(manifest['evidence_root']), maximum_candidate_bytes=1024**2)
    binding = application._binding('publish_new_version.v1@1.0.0')
    _require(manifest['native_read_installation_version'] in {'1.2','1.4'}
        and manifest['contract'] == binding, 'ntfs.original_single_effect_required')
    validate_run_id(installation.authority._run_id)
    _, candidate_bytes = _version1_publication_candidate(request_id,
        target_locator, expected_current_digest)
    if type(source_locator) is not str:
        raise PhaseError('ntfs.fixed_native_request_required')
    source_locator = safe_relative_locator(source_locator)
    if expected_digest is not None and (type(expected_digest) is not str or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest)):
        raise PhaseError('publish.invalid_expected_digest')
    preparation = Path(manifest['preparation_root'])
    scratch = Path(mkdtemp(prefix='phase-native-version-', dir=preparation))
    frozen = copy_and_hash('payload', preparation, source_locator, scratch,
        frozen_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        maximum_bytes=16*1024**2)
    if expected_digest is not None and frozen.digest != expected_digest:
        raise PhaseError('publish.source_digest_mismatch')
    revalidate_frozen(frozen)
    _require(frozen.blob_path is not None, 'freeze.blob_missing')
    with NamedTemporaryFile(mode='wb', suffix='.json', dir=scratch,
            delete=False) as temporary:
        temporary.write(candidate_bytes)
        candidate_path = Path(temporary.name)
    return (candidate_path, {'payload': frozen.blob_path},
        {'payload': (frozen.digest, frozen.length)}, candidate_bytes)


def _prepare_bundle_publication(application,*,source_locator,target_locator,request_id,members):
    """Prepare only a candidate under accepted ext4; Core captures bundle bytes."""
    from ...installation import _NativeFileCreateInstallation
    from ...paths import contained_read_path
    from ...publish_bundle import _bundle_publication_candidate
    from .parent_result import _native_bundle_result_binding
    from .native import _require
    installation=application.installation
    _require(type(installation) is _NativeFileCreateInstallation
        and application.registry is installation.read_binding.registry,'ntfs.closed_native_installation_required')
    installation.authority._execution_required()
    binding=installation.read_binding
    manifest,_=_native_bundle_result_binding(binding,binding.manifest_digest,application.registry)
    roots={key:Path(value)for key,value in manifest['root_projections'].items()}
    manifest=installation._check_preparation_namespace(root_bindings=roots,
        evidence_root=Path(manifest['evidence_root']),maximum_candidate_bytes=1024**2)
    validate_run_id(installation.authority._run_id)
    source_locator=safe_relative_locator(source_locator)
    _,candidate_bytes=_bundle_publication_candidate(request_id,target_locator,members)
    preparation=Path(manifest['preparation_root'])
    source=contained_read_path(preparation,source_locator)
    _require(source.is_dir()and not source.is_symlink(),'ntfs.bundle_preparation_directory_required')
    scratch=Path(mkdtemp(prefix='phase-native-bundle-',dir=preparation))
    with NamedTemporaryFile(mode='wb',suffix='.json',dir=scratch,delete=False)as temporary:
        temporary.write(candidate_bytes);candidate_path=Path(temporary.name)
    installation._check_preparation_namespace(root_bindings=roots,
        evidence_root=Path(manifest['evidence_root']),maximum_candidate_bytes=1024**2)
    return candidate_path,{'payload':source},None,candidate_bytes


def _prepare_staged_publication(application,launch,request):
    """Materialize only existing Core arguments inside admitted preparation.

    Prepared-input data is verified again; only Core captures/freeze/intents and
    existing native mechanisms may publish. No catch extends over Core.run.
    """
    from ...installation import _NativeFileCreateInstallation
    from .native import _require
    from .input_stage import _read_staged_input_marker,_publication_candidate
    from ...paths import contained_read_path
    from ...bundle import freeze_bundle
    installation=application.installation
    _require(type(installation)is _NativeFileCreateInstallation
        and application.registry is installation.read_binding.registry,
        'ntfs.closed_native_installation_required')
    installation.authority._execution_required()
    scope,role,marker=_read_staged_input_marker(launch,request)
    manifest=launch.manifest;roots={key:Path(value)for key,value in manifest['root_projections'].items()}
    checked=installation._check_preparation_namespace(root_bindings=roots,
        evidence_root=Path(manifest['evidence_root']),maximum_candidate_bytes=1024**2)
    _require(checked==manifest,'input_stage.preparation_manifest_mismatch')
    candidate,raw=_publication_candidate(role,request['request_id'],request['target_locator'],
        request['members'],request['expected_current_digest'],request['content_utf8'])
    preparation=Path(scope['preparation_root']);source=contained_read_path(preparation,request['source_locator'])
    scratch=Path(mkdtemp(prefix='phase-native-staged-',dir=preparation))
    if role in{'Bundle1','Bundle2'}:
        # Existing manifest capture owns member nofollow/hash/membership. Core
        # will independently capture again against this exact digest+length.
        frozen=freeze_bundle('payload',source,request['members'],scratch,
            frozen_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
        _require(frozen.digest==request['source_digest']and frozen.length==request['source_length'],
            'input_stage.preparation_digest_mismatch')
        inputs={'payload':source};expected={'payload':(frozen.digest,frozen.length)}
    elif role=='Version2':
        # Contract deliberately has no FrozenInput. Read independently staged
        # bytes with the normal bounded frozen reader, compare to candidate.
        frozen=copy_and_hash('payload',preparation,request['source_locator'],scratch,
            frozen_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),maximum_bytes=512*1024)
        _require(frozen.digest==request['source_digest']and frozen.length==request['source_length'],
            'input_stage.preparation_digest_mismatch')
        revalidate_frozen(frozen);inputs={};expected={}
    else:
        from .input_stage import _role_bounds
        from ...streaming import copy_and_hash_stream
        capture=copy_and_hash_stream if role=='File2'else copy_and_hash
        frozen=capture('payload',preparation,request['source_locator'],scratch,
            frozen_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),maximum_bytes=_role_bounds(role)[1])
        _require(frozen.digest==request['source_digest']and frozen.length==request['source_length'],
            'input_stage.preparation_digest_mismatch')
        revalidate_frozen(frozen);_require(frozen.blob_path is not None,'freeze.blob_missing')
        inputs={'payload':frozen.blob_path};expected={'payload':(frozen.digest,frozen.length)}
    with NamedTemporaryFile(mode='wb',suffix='.json',dir=scratch,delete=False)as temporary:
        temporary.write(raw);candidate_path=Path(temporary.name)
    installation._check_preparation_namespace(root_bindings=roots,
        evidence_root=Path(manifest['evidence_root']),maximum_candidate_bytes=1024**2)
    return candidate_path,inputs,expected,raw
