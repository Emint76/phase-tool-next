from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .errors import PhaseError
from .mutation.authority import AuthorityProvider
from .mutation.guarantees import GuaranteeProfileBinding, registered_profile_binding
from .mutation.platform import HostAuthorityProvider


@dataclass(frozen=True)
class Installation:
    authority_provider: AuthorityProvider
    authority_profile_binding: GuaranteeProfileBinding | None = None

    def qualify_authority_roots(self, root_bindings: Mapping[str, Path]) -> None:
        qualify_host_authority_roots(root_bindings)


def _resolved_existing_root(path: Path) -> Path:
    lexical = Path(os.path.abspath(path))
    resolved = Path(path).resolve(strict=True)
    if os.path.normcase(str(lexical)) != os.path.normcase(str(resolved)):
        raise PhaseError("guarantee.profile_scope_unsupported", str(path))
    if not resolved.is_dir():
        raise PhaseError("guarantee.profile_scope_unsupported")
    return resolved


def _linux_filesystem_type(path: Path) -> str:
    resolved = str(_resolved_existing_root(path))
    selected: tuple[int, str] | None = None
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        if not separator or len(fields) < 5:
            continue
        mount = re.sub(r"\\([0-7]{3})", lambda item: chr(int(item.group(1), 8)), fields[4])
        if resolved == mount or resolved.startswith(mount.rstrip("/") + "/"):
            candidate = (len(mount), right.split()[0])
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    if selected is None:
        raise PhaseError("guarantee.profile_scope_unsupported", resolved)
    return selected[1]


def _linux_kernel_release() -> str:
    return Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8")


def _is_containerized_linux() -> bool:
    try:
        return _linux_filesystem_type(Path("/")) == "overlay"
    except (PhaseError, OSError):
        return False


def _is_wsl() -> bool:
    try:
        release = _linux_kernel_release().strip()
        if re.fullmatch(r"[0-9]+\.[0-9]+[A-Za-z0-9._+-]*", release) is None:
            return True
        return "microsoft" in release.lower() and not _is_containerized_linux()
    except OSError:
        return True


def qualify_host_authority_roots(root_bindings: Mapping[str, Path]) -> None:
    if not sys.platform.startswith("linux"):
        raise PhaseError(
            "platform.mutation_unsupported",
            details={"platform": sys.platform},
        )
    for binding_id, root in sorted(root_bindings.items()):
        try:
            filesystem = _linux_filesystem_type(Path(root))
            is_wsl = _is_wsl()
            qualified = not is_wsl and filesystem in {"ext4", "overlay"}
            if is_wsl:
                filesystem = f"wsl:{filesystem}"
        except (FileNotFoundError, OSError) as exc:
            raise PhaseError("guarantee.profile_scope_unsupported", binding_id) from exc
        if not qualified:
            raise PhaseError(
                "guarantee.profile_scope_unsupported",
                binding_id,
                details={"binding_id": binding_id, "filesystem": filesystem},
            )


def host_installation() -> Installation:
    """Build the explicit host installation configuration at one composition boundary."""

    provider = HostAuthorityProvider()
    profile = registered_profile_binding("phase.posix.authority.v1@1.0.0") if sys.platform.startswith("linux") else None
    return Installation(
        authority_provider=provider,
        authority_profile_binding=profile,
    )


@dataclass(frozen=True)
class _NativeFileCreateReadBinding:
    """Internal static correlation data, never an Installation or authority.

    Only a future authenticated startup may select this binding. An expected
    manifest digest supplied here does not authenticate that startup, loaded
    code, the declared artifact graph, a remote container or current invocation.
    No GO, write, worker, receipt, recovery or qualification method exists.
    """

    manifest_bytes: bytes
    manifest_digest: str
    registry: object

    def read(self, *, run_id: str, intent_digest: str):
        from .canonical import canonical_bytes, canonical_digest, parse_json_bytes
        from .mutation.ntfs.intent import parse_original_file_create
        from .mutation.ntfs.native import _require
        from .mutation.ntfs.reader import read_original_file_create_buffers

        manifest = parse_json_bytes(self.manifest_bytes, maximum_bytes=2*1024**2)
        _require(self.registry.digest == manifest['registry_snapshot_digest']
            == canonical_digest(self.registry.to_document()), 'ntfs.original_registry_mismatch')
        original, plan, pre, content = read_original_file_create_buffers(
            evidence_root=Path(manifest['evidence_root']),
            installed_evidence_identity=canonical_bytes(manifest['evidence_identity']),
            registry=self.registry, run_id=run_id, expected_intent_digest=intent_digest)
        intent = parse_json_bytes(original, maximum_bytes=2*1024**2)
        return parse_original_file_create(intent_bytes=original, plan_bytes=plan,
            pre_validator_bytes=pre, blob_bytes=content, registry=self.registry,
            expected_run_id=run_id, expected_intent_digest=intent_digest,
            **self._parser_bindings(intent))

    def _parser_bindings(self, intent: dict) -> dict[str, bytes]:
        """Same immutable expectations for reader/parser and original-intent gate.

        This performs static correlation only. It neither validates the complete
        original operation nor grants authority to dispatch a planned request.
        Callers still own schema/canonical/registry checks of original bytes.
        """
        from .canonical import canonical_bytes, parse_json_bytes
        from .mutation.ntfs.native import _require
        manifest = parse_json_bytes(self.manifest_bytes, maximum_bytes=2*1024**2)
        _require(intent['contract'] == manifest['contract'], 'ntfs.original_installation_binding_mismatch')
        # Per-operation claims remain in the original intent. The unchanged
        # parser separately verifies their plan/hash/semantic linkage. Matching
        # a nonce does not establish freshness or permit GO/retry.
        native = {'native_binding_version': '1.0',
            'installation': {'id': manifest['installation_id'], 'descriptor_digest': self.manifest_digest},
            'composition': manifest['composition'], 'evidence_identity': manifest['evidence_identity'],
            'operation_nonce': intent['native_binding']['operation_nonce']}
        implementation = {'authority': manifest['authority'], 'mechanism': manifest['mechanism'],
            'effect_plan_digest': intent['implementation_binding']['effect_plan_digest']}
        return {'installed_core_binding': canonical_bytes(manifest['core']),
            'installed_native_binding': canonical_bytes(native),
            'installed_root_grants': canonical_bytes(manifest['root_grants']),
            'installed_implementation_binding': canonical_bytes(implementation)}


def _resolve_native_file_create_read_binding(*, manifest_bytes: bytes,
    expected_manifest_digest: str, registry: object) -> _NativeFileCreateReadBinding:
    """Validate immutable static configuration without filesystem access.

    This unselected internal format has no nonce, plan digest or own descriptor
    digest. The expected raw SHA belongs to a future trusted startup, outside
    request/intent. Its provenance and checked executable graph are NOT supplied
    by this function. Normal host installation, defaults and guards are unchanged.
    """
    from pathlib import PurePosixPath
    from jsonschema import Draft202012Validator, FormatChecker
    from .canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
    from .mutation.ntfs.native import _require
    from .mutation.ntfs.reader import _evidence_identity
    from .mutation.ntfs.worker import _grant
    from .registry import RegistrySnapshot

    _require(type(registry) is RegistrySnapshot, 'ntfs.original_registry_required')
    _require(type(expected_manifest_digest) is str
        and re.fullmatch(r'sha256:[0-9a-f]{64}', expected_manifest_digest) is not None,
        'ntfs.original_installation_digest_required')
    _require(type(manifest_bytes) is bytes and len(manifest_bytes) <= 2*1024**2,
        'ntfs.original_installation_bytes_required')
    _require(digest_bytes(manifest_bytes) == expected_manifest_digest, 'ntfs.original_installation_digest_mismatch')
    manifest = parse_json_bytes(manifest_bytes, maximum_bytes=2*1024**2)
    _require(type(manifest) is dict and canonical_bytes(manifest) == manifest_bytes,
        'ntfs.original_installation_shape')
    # The exact package must be resolved before its immutable schema fragments
    # can validate the complete static projection. No replacement current schema.
    for key in ('core', 'contract'):
        binding = manifest.get(key)
        _require(type(binding) is dict and set(binding) == {'id', 'version', 'package_digest'}
            and all(type(value) is str for value in binding.values()), 'ntfs.original_installation_shape')
    _require(manifest.get('registry_snapshot_digest') == registry.digest
        == canonical_digest(registry.to_document()), 'ntfs.original_registry_mismatch')
    binding = manifest['contract']
    _require(binding['id'] == 'file_create.v1' and binding['version'] == '1.0.0',
        'ntfs.original_single_effect_required')
    contract = registry.resolve_contract(binding['id'], binding['version'], binding['package_digest'],
        core_version=manifest['core']['version'])
    resource = 'schemas/phase-intent-1.2.schema.json'
    matches = [item['digest'] for item in contract.entry.get('package_artifacts', ()) if item['resource'] == resource]
    _require(len(matches) == 1, 'intent.schema_unbound')
    schema = registry.schema_document('https://phase-tool.local/' + resource, matches[0])
    native = schema['$defs']['nativeBinding']['properties']
    implementation = schema['properties']['implementation_binding']['properties']
    properties = {
        'native_read_installation_version': {'const': '1.0'},
        'installation_id': native['installation']['properties']['id'],
        'core': schema['properties']['core'], 'contract': schema['properties']['contract'],
        'registry_snapshot_digest': {'$ref': '#/$defs/digest'},
        'authority': implementation['authority'], 'mechanism': implementation['mechanism'],
        'composition': native['composition'], 'evidence_identity': native['evidence_identity'],
        'root_grants': schema['properties']['idempotency']['properties']['root_identities'],
        'evidence_root': {'type': 'string', 'minLength': 1}}
    Draft202012Validator({'$schema': schema['$schema'], '$defs': schema['$defs'],
        'type': 'object', 'properties': properties, 'required': sorted(properties), 'additionalProperties': False},
        registry=registry.schema_registry(), format_checker=FormatChecker()).validate(manifest)
    _evidence_identity(canonical_bytes(manifest['evidence_identity']))
    root = PurePosixPath(manifest['evidence_root'])
    _require(root.is_absolute() and str(root) == manifest['evidence_root'] and str(root) != '/'
        and '..' not in root.parts, 'ntfs.original_evidence_root_required')
    mechanism = {key: contract.document['operation']['mechanism'][key] for key in ('id', 'version', 'package_digest')}
    _require(manifest['mechanism'] == mechanism and manifest['authority']['usage'] == 'provider_backed',
        'ntfs.original_implementation_mismatch')
    grants = [_grant(row) for row in manifest['root_grants']]
    scope = contract.document['write_scope']
    _require(len(grants) == 1 and {grants[0].binding} == {row['binding_id'] for row in scope['roots']}
        and grants[0].binding == contract.document['canonical_result']['root_binding']
        and grants[0].binding not in scope['forbidden_root_bindings'], 'ntfs.original_root_binding_mismatch')
    return _NativeFileCreateReadBinding(manifest_bytes, expected_manifest_digest, registry)


_NATIVE_FILE_CREATE_REGISTRY_RESOURCE = "registries/native-file-create-candidate-v1.json"
_NATIVE_FILE_CREATE_REGISTRY_DIGEST = "sha256:fa2a9aff5f576d15b5a71574a11bd3a7a994a38346540ff6d7e7a74335cfa2c7"


def _native_file_create_candidate_registry():
    """Load one code-selected structural snapshot, never native authority.

    A future authenticated composition may select this unadmitted candidate.
    Requests, intents, environment and external paths do not select the resource
    or its digest. The ordinary Host factory and default registry are unchanged.
    Loading it does not qualify roots, supply a profile or clear old evidence.
    """
    from . import __version__
    from .canonical import canonical_bytes, digest_bytes, parse_json_bytes
    from .registry import BundledRegistry, RegistrySnapshot

    resources = BundledRegistry.resources()
    try:
        raw = resources[_NATIVE_FILE_CREATE_REGISTRY_RESOURCE]
    except KeyError as exc:
        raise PhaseError("ntfs.native_registry_missing") from exc
    if digest_bytes(raw) != _NATIVE_FILE_CREATE_REGISTRY_DIGEST:
        raise PhaseError("ntfs.native_registry_digest_mismatch")
    document = parse_json_bytes(raw, maximum_bytes=256*1024)
    if canonical_bytes(document) != raw:
        raise PhaseError("ntfs.native_registry_noncanonical")
    registry = RegistrySnapshot.from_document(document, resources)
    expected = {"id": "file_create.v1", "version": "1.0.0",
        "package_digest": "sha256:734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09"}
    if registry.contract_bindings().get("file_create.v1@1.0.0") != expected:
        raise PhaseError("ntfs.native_registry_selection_mismatch")
    # The existing resolver checks trust, exact artifacts, dependencies, schemas
    # and Core compatibility; no inactive-generation exception is added to Core.
    registry.resolve_contract(expected["id"], expected["version"],
        expected["package_digest"], core_version=__version__)
    return registry
