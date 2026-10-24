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

from ...canonical import parse_json_bytes
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
