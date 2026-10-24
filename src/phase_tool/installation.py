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

    def check_evidence_root(self):
        """Current qualified ext4 identity, shared by readonly native consumers."""
        import stat
        from .canonical import parse_json_bytes, canonical_bytes
        from .mutation.ntfs.native import _require
        from .mutation.ntfs.reader import _evidence_identity
        manifest = parse_json_bytes(self.manifest_bytes, maximum_bytes=2*1024**2)
        expected = _evidence_identity(canonical_bytes(manifest['evidence_identity']))
        root = Path(manifest['evidence_root'])
        qualify_host_authority_roots({'phase_evidence_root':root})
        _require(_linux_filesystem_type(root) == 'ext4', 'ntfs.original_ext4_evidence_required')
        info = root.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022
            and (info.st_dev, info.st_ino) == (expected['device'],expected['inode']),
            'ntfs.original_evidence_identity_mismatch')
        _require_native_no_descendant_mounts(root)
        return root

    def read(self, *, run_id: str, intent_digest: str):
        from .canonical import canonical_bytes, canonical_digest, parse_json_bytes
        from .mutation.ntfs.intent import parse_original_file_create,parse_original_version1
        from .mutation.ntfs.native import _require
        from .mutation.ntfs.reader import read_original_file_create_buffers,read_original_version1_buffers

        manifest = parse_json_bytes(self.manifest_bytes, maximum_bytes=2*1024**2)
        _require(self.registry.digest == manifest['registry_snapshot_digest']
            == canonical_digest(self.registry.to_document()), 'ntfs.original_registry_mismatch')
        version1 = manifest['native_read_installation_version'] == '1.2' and manifest['contract']['id'] == 'publish_new_version.v1'
        reader = read_original_version1_buffers if version1 else read_original_file_create_buffers
        parser = parse_original_version1 if version1 else parse_original_file_create
        original, plan, pre, content = reader(
            evidence_root=Path(manifest['evidence_root']),
            installed_evidence_identity=canonical_bytes(manifest['evidence_identity']),
            registry=self.registry, run_id=run_id, expected_intent_digest=intent_digest)
        intent = parse_json_bytes(original, maximum_bytes=2*1024**2)
        return parser(intent_bytes=original, plan_bytes=plan,
            pre_validator_bytes=pre, blob_bytes=content, registry=self.registry,
            expected_run_id=run_id, expected_intent_digest=intent_digest,
            **self._parser_bindings(intent))

    def validate_planned(self, *, run_id, intent_digest):
        from .canonical import parse_json_bytes, canonical_bytes
        from .mutation.ntfs.reader import read_original_file_create_buffers,read_original_version1_buffers
        from .mutation.ntfs.intent import validate_planned_file_create_original,validate_planned_version1_original
        manifest = parse_json_bytes(self.manifest_bytes, maximum_bytes=2*1024**2)
        version1 = manifest['native_read_installation_version'] == '1.2' and manifest['contract']['id'] == 'publish_new_version.v1'
        reader = read_original_version1_buffers if version1 else read_original_file_create_buffers
        parser = validate_planned_version1_original if version1 else validate_planned_file_create_original
        original,plan,pre,content = reader(
            evidence_root=Path(manifest['evidence_root']),
            installed_evidence_identity=canonical_bytes(manifest['evidence_identity']),
            registry=self.registry,run_id=run_id,expected_intent_digest=intent_digest)
        intent = parse_json_bytes(original, maximum_bytes=2*1024**2)
        parser(intent_bytes=original,plan_bytes=plan,
            pre_validator_bytes=pre,blob_bytes=content,registry=self.registry,
            expected_run_id=run_id,expected_intent_digest=intent_digest,
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
    version = manifest.get('native_read_installation_version')
    _require(binding['version'] == '1.0.0' and (binding['id'] == 'file_create.v1'
        or (version == '1.2' and binding['id'] == 'publish_new_version.v1')),
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
        'native_read_installation_version': {'const': manifest.get('native_read_installation_version')},
        'installation_id': native['installation']['properties']['id'],
        'core': schema['properties']['core'], 'contract': schema['properties']['contract'],
        'registry_snapshot_digest': {'$ref': '#/$defs/digest'},
        'authority': implementation['authority'], 'mechanism': implementation['mechanism'],
        'composition': native['composition'], 'evidence_identity': native['evidence_identity'],
        'root_grants': schema['properties']['idempotency']['properties']['root_identities'],
        'evidence_root': {'type': 'string', 'minLength': 1}}
    _require(type(version) is str and version in {'1.0', '1.1', '1.2'},
        'ntfs.original_installation_version_unsupported')
    if version in {'1.1','1.2'}:
        # New static generation binds MIX preparation and opaque projections.
        # Historical 1.0 keys/semantics and intent1.2 bytes remain unchanged.
        properties.update({
            'preparation_root': {'type': 'string', 'minLength': 1},
            'preparation_identity': native['evidence_identity'],
            'root_projections': {'type': 'object', 'minProperties': 1,
                'additionalProperties': {'type': 'string', 'minLength': 1}}})
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
    if version in {'1.1','1.2'}:
        preparation = PurePosixPath(manifest['preparation_root'])
        _require(preparation.is_absolute() and str(preparation) == manifest['preparation_root']
            and str(preparation) != '/' and '..' not in preparation.parts
            and not preparation.is_relative_to(root) and not root.is_relative_to(preparation),
            'ntfs.original_preparation_root_required')
        _evidence_identity(canonical_bytes(manifest['preparation_identity']))
        _require((manifest['preparation_identity']['device'],manifest['preparation_identity']['inode'])
            != (manifest['evidence_identity']['device'],manifest['evidence_identity']['inode']),
            'evidence.overlaps_preparation_root')
        projections = manifest['root_projections']
        _require(set(projections) == {grants[0].binding}, 'ntfs.installed_root_projections_required')
        for value in projections.values():
            projection = PurePosixPath(value)
            _require(projection.is_absolute() and str(projection) == value
                and str(projection) != '/' and '..' not in projection.parts
                and not projection.is_relative_to(root) and not root.is_relative_to(projection)
                and not projection.is_relative_to(preparation) and not preparation.is_relative_to(projection),
                'ntfs.installed_root_projections_required')
    return _NativeFileCreateReadBinding(manifest_bytes, expected_manifest_digest, registry)


_NATIVE_FILE_CREATE_REGISTRY_RESOURCE = "registries/native-file-create-candidate-v1.json"
_NATIVE_FILE_CREATE_REGISTRY_DIGEST = "sha256:fa2a9aff5f576d15b5a71574a11bd3a7a994a38346540ff6d7e7a74335cfa2c7"


def _native_file_create_candidate_registry():
    """Preserve the previous fixed unadmitted candidate generation."""
    return _load_native_file_create_registry(_NATIVE_FILE_CREATE_REGISTRY_RESOURCE,
        _NATIVE_FILE_CREATE_REGISTRY_DIGEST,
        'sha256:734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09')


def _native_connected_file_create_registry():
    """Connected generation, code-selected only; it grants NO native authority."""
    return _load_native_file_create_registry('registries/native-file-create-candidate-v3.json',
        'sha256:c5fe3be5e03d3be6b390135cb72e52559081c62feccb52e7db0788d8f705088b',
        'sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')


def _native_inspection_file_create_registry():
    """Current fixed create/read candidate; old snapshots and Host defaults unchanged."""
    return _load_native_file_create_registry('registries/native-file-create-candidate-v4.json',
        'sha256:2af8bac33feb42a583a14d6bff7b403de2ab0b63be3a962acc45807634a6ecca',
        'sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')


def _load_native_file_create_registry(resource, expected_digest, contract_digest):
    """Shared byte/trust resolver; only the two fixed factories select inputs.

    This helper is not an installation, qualifier, provider or request route.
    Environment, operation data and original intents cannot select a registry.
    """
    from . import __version__
    from .canonical import canonical_bytes, digest_bytes, parse_json_bytes
    from .registry import BundledRegistry, RegistrySnapshot

    resources = BundledRegistry.resources()
    try:
        raw = resources[resource]
    except KeyError as exc:
        raise PhaseError("ntfs.native_registry_missing") from exc
    if digest_bytes(raw) != expected_digest:
        raise PhaseError("ntfs.native_registry_digest_mismatch")
    document = parse_json_bytes(raw, maximum_bytes=256*1024)
    if canonical_bytes(document) != raw:
        raise PhaseError("ntfs.native_registry_noncanonical")
    registry = RegistrySnapshot.from_document(document, resources)
    expected = {"id": "file_create.v1", "version": "1.0.0",
        "package_digest": contract_digest}
    if registry.contract_bindings().get("file_create.v1@1.0.0") != expected:
        raise PhaseError("ntfs.native_registry_selection_mismatch")
    # The existing resolver checks trust, exact artifacts, dependencies, schemas
    # and Core compatibility; no inactive-generation exception is added to Core.
    registry.resolve_contract(expected["id"], expected["version"],
        expected["package_digest"], core_version=__version__)
    return registry


class _NativeFileCreateInstallation:
    """Closed one-operation MIX composition; no alternate lifecycle or store.

    The accepted fixed bootstrap owns construction, process/pipe provenance and
    the complete immutable executable graph. This data class cannot authenticate
    that bootstrap. Its factory refuses the unqualified candidate before channel
    construction, target I/O, operational lock or evidence reservation.
    """

    def __init__(self, read_binding, authority):
        from .mutation.ntfs.authority import _NativeFileCreateAuthority
        from .mutation.ntfs.native import _require
        from .canonical import parse_json_bytes
        _require(not getattr(self, '_initialization_attempted', False),
            'ntfs.native_installation_initialization_consumed')
        self._initialization_attempted = True
        _require(type(read_binding) is _NativeFileCreateReadBinding
            and type(authority) is _NativeFileCreateAuthority
            and authority.read_binding is read_binding, 'ntfs.closed_native_installation_required')
        manifest = parse_json_bytes(read_binding.manifest_bytes, maximum_bytes=2*1024**2)
        _require(manifest['native_read_installation_version'] in {'1.1','1.2'},
            'ntfs.original_preparation_root_required')
        self.read_binding, self.authority = read_binding, authority
        self.authority_profile_binding = authority.profile
        self._admission_attempted = False

    def admit(self, registry, request, *, execute, faults):
        from .mutation.ntfs.native import _require
        _require(not self._admission_attempted, 'ntfs.native_installation_consumed')
        self._admission_attempted = True
        self.authority._execution_required()
        _require(registry is self.read_binding.registry and type(execute) is bool
            and faults is None, 'ntfs.closed_native_installation_required')
        # No public caller-supplied registry/provider/profile override.
        self.authority._usable()
        _require(request.run_id == self.authority._run_id,
            'ntfs.original_current_invocation_mismatch')
        from . import __version__
        contract = registry.resolve_contract(request.contract_id, request.contract_version,
            request.contract_digest, core_version=__version__)
        self.authority.require_contract(contract)
        self.check_request(request)

    def check_request(self, request):
        from .canonical import parse_json_bytes
        from .mutation.ntfs.native import _require
        import stat
        manifest = parse_json_bytes(self.read_binding.manifest_bytes, maximum_bytes=2*1024**2)
        self.authority.require_request_roots(request.root_bindings, request.evidence_root)
        _require(type(request.maximum_candidate_bytes) is int
            and 0 < request.maximum_candidate_bytes <= 1024**2,
            'candidate.too_large')
        for name, identity in [('evidence_root', manifest['evidence_identity']),
                               ('preparation_root', manifest['preparation_identity'])]:
            root = Path(manifest[name])
            qualify_host_authority_roots({name: root})
            _require(_linux_filesystem_type(root) == 'ext4', 'ntfs.original_ext4_evidence_required')
            info = root.lstat()
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and not info.st_mode & 0o022
                and (info.st_dev, info.st_ino) == (identity['device'], identity['inode']),
                'ntfs.original_evidence_identity_mismatch')
        _require_native_no_descendant_mounts(Path(manifest['preparation_root']))
        _require_native_mixed_roots_disjoint(Path(manifest['evidence_root']),
            Path(manifest['preparation_root']))
        preparation = Path(manifest['preparation_root'])
        # Existing Core capture/freeze owns all bytes and their stable read checks.
        # This is admission of prepared paths, never a copy-out or target reader.
        version1 = manifest['native_read_installation_version'] == '1.2' and manifest['contract']['id'] == 'publish_new_version.v1'
        prepared = [(Path(request.candidate_path),1024**2),
            *((Path(p),16*1024**2 if version1 else 1024**2) for p in request.input_paths.values())]
        for path,maximum in prepared:
            _require(path.is_absolute() and path == Path(os.path.abspath(path)),
                'ntfs.prepared_input_outside_root')
            try:
                relative = path.relative_to(preparation)
            except ValueError as error:
                raise PhaseError('ntfs.prepared_input_outside_root') from error
            _require(bool(relative.parts), 'ntfs.prepared_input_outside_root')
            current = preparation
            for index, part in enumerate(relative.parts):
                current = current / part
                info = current.lstat()
                last = index == len(relative.parts)-1
                _require((stat.S_ISREG(info.st_mode) if last else stat.S_ISDIR(info.st_mode))
                    and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                    'ntfs.prepared_input_unsafe')
                if last:
                    _require(info.st_nlink == 1 and info.st_size <= maximum,
                        'ntfs.prepared_input_unsafe')
        return Path(manifest['evidence_root'])


def _native_file_create_installation(*, manifest_bytes, expected_manifest_digest,
    run_id, operation_nonce, channel_id, _inspection_only: bool = False):
    """Fixed trusted-startup seam, not a request-selected implementation.

    The packaged candidate snapshot deliberately has no qualified native profile:
    this factory fails closed before constructing a channel or authority. A later
    qualified immutable generation must be separately accepted and code-selected;
    neither environment nor request data can replace the bundled snapshot.
    Successful static checks do not authenticate a launcher or remote container.
    """
    from .canonical import canonical_bytes, parse_json_bytes
    from .mutation.ntfs.native import _require
    from .mutation.ntfs.authority import _NativeFileCreateAuthority
    from .mutation.ntfs.channel_v2 import LinuxNativeChannelV2
    _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
    # Capability mode cannot select a different historical registry generation.
    registry = _native_inspection_file_create_registry()
    exact = registry.guarantee_profile_bindings().get('phase.native.ntfs.authority.v1@1.0.0')
    _require(exact is not None, 'ntfs.native_profile_not_qualified')
    profile = _native_qualified_profile(registry,exact)
    binding = _resolve_native_file_create_read_binding(manifest_bytes=manifest_bytes,
        expected_manifest_digest=expected_manifest_digest, registry=registry)
    manifest = parse_json_bytes(binding.manifest_bytes, maximum_bytes=2*1024**2)
    _require(manifest['authority']['profile'] == profile.as_dict()
        and manifest['native_read_installation_version'] == '1.1',
        'ntfs.original_implementation_mismatch')
    channel = LinuxNativeChannelV2(channel_id=channel_id, _inspection_only=_inspection_only)
    authority = _NativeFileCreateAuthority(binding, profile,
        canonical_bytes(manifest['root_projections']), channel,
        run_id=run_id, operation_nonce=operation_nonce, _inspection_only=_inspection_only)
    return registry, _NativeFileCreateInstallation(binding, authority)


def _require_native_mixed_roots_disjoint(evidence, preparation):
    """Kernel mount roots expose physical overlap hidden by bind aliases.

    Both roots were already qualified as ext4. The accepted Docker daemon/mount
    namespace is trusted; mount topology cannot be changed during this call.
    No NTFS access, mount change, registry override or new storage adapter.
    """
    from pathlib import PurePosixPath
    from .mutation.ntfs.native import _require
    table = Path('/proc/self/mountinfo').read_bytes()
    def unescape(value):
        return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1),8)), value)
    def projection(path):
        selected = None
        resolved = str(_resolved_existing_root(path))
        for line in table.decode('utf-8').splitlines():
            left,separator,right = line.partition(' - ')
            fields = left.split()
            if not separator or len(fields) < 6:continue
            mount,source = unescape(fields[4]),unescape(fields[3])
            if resolved == mount or resolved.startswith(mount.rstrip('/')+'/'):
                value = (len(mount),fields[2],source,mount,right.split()[0])
                if selected is None or value[0] > selected[0]:selected = value
        _require(selected is not None and selected[4] == 'ext4', 'guarantee.profile_scope_unsupported')
        _,device,source,mount,_ = selected
        relative = PurePosixPath(resolved).relative_to(PurePosixPath(mount))
        return device,PurePosixPath(source)/relative
    left,right = projection(evidence),projection(preparation)
    _require(left[0] != right[0] or (not left[1].is_relative_to(right[1])
        and not right[1].is_relative_to(left[1])), 'evidence.overlaps_preparation_root')
    _require(table == Path('/proc/self/mountinfo').read_bytes(), 'ntfs.native_mount_topology_changed')


def _native_qualified_profile(registry, exact):
    """ONE pure native admission check shared by factory, role and inspector."""
    from .mutation.ntfs.native import _require
    current = registry.guarantee_profile_bindings().get('phase.native.ntfs.authority.v1@1.0.0')
    _require(exact is not None and exact == current, 'ntfs.native_profile_not_qualified')
    descriptor = registry.resolve_guarantee_profile(exact)
    # Mandatory even when contract requirements are empty.
    _require(descriptor['descriptor_version'] == '1.1'
        and descriptor['classification'] == 'production'
        and bool(descriptor['provided_guarantees']) and bool(descriptor['conformance']),
        'ntfs.native_profile_not_qualified')
    implementation = descriptor['implementation']
    _require(implementation['artifact'] == 'phase_tool/mutation/ntfs/authority.py',
        'guarantee.profile_implementation_mismatch')
    return GuaranteeProfileBinding(exact['id'],exact['version'],exact['descriptor_digest'],
        implementation['id'],implementation['version'],implementation['artifact_digest'])


def _require_native_no_descendant_mounts(root):
    """Fixed native evidence/preparation contour excludes nested mount aliases."""
    from .mutation.ntfs.native import _require
    resolved = str(_resolved_existing_root(root))
    for line in Path('/proc/self/mountinfo').read_text('utf-8').splitlines():
        left,separator,right = line.partition(' - ')
        fields = left.split()
        _require(bool(separator) and len(fields) >= 6, 'ntfs.native_mount_topology_unavailable')
        mount = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1),8)),fields[4])
        _require(not mount.startswith(resolved.rstrip('/')+'/'), 'ntfs.native_descendant_mount_forbidden')

def _native_lifecycle_registry():
    """Fixed unqualified V5; old V1-V4 loaders/bytes remain unchanged."""
    registry = _load_native_file_create_registry('registries/native-lifecycle-candidate-v5.json',
        'sha256:52e3835f506f6a806ac846312cce1758f54b61238d87f8aeffacb4a62f773186',
        'sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
    expected = {'id':'publish_new_version.v1','version':'1.0.0',
        'package_digest':'sha256:5f311c95f75a098e96bd8b69b0845ead41c005d94759d9b523c2a161bf1f8fa1'}
    if registry.contract_bindings().get('publish_new_version.v1@1.0.0') != expected:
        raise PhaseError('ntfs.native_registry_selection_mismatch')
    from . import __version__
    registry.resolve_contract(expected['id'],expected['version'],expected['package_digest'],core_version=__version__)
    return registry


def _native_registry_for_manifest(manifest_bytes, expected_manifest_digest):
    """Closed static-generation correlation, not launcher authentication.

    Only the accepted immutable bootstrap supplies these buffers. Neither a
    query, candidate, environment value nor arbitrary resource/digest selects a
    registry. The full installation resolver still verifies exact bindings and
    qualification before any channel/target/evidence reservation.
    """
    from .canonical import canonical_bytes,canonical_digest,digest_bytes,parse_json_bytes
    from .mutation.ntfs.native import _require
    _require(type(manifest_bytes) is bytes and len(manifest_bytes) <= 2*1024**2
        and type(expected_manifest_digest) is str
        and digest_bytes(manifest_bytes) == expected_manifest_digest,'ntfs.accepted_launch_binding_required')
    manifest = parse_json_bytes(manifest_bytes,maximum_bytes=2*1024**2)
    _require(type(manifest) is dict and canonical_bytes(manifest) == manifest_bytes,
        'ntfs.original_installation_shape')
    version = manifest.get('native_read_installation_version')
    _require(type(version) is str and version in {'1.1','1.2'},
        'ntfs.original_installation_version_unsupported')
    registry = _native_inspection_file_create_registry() if version == '1.1' else _native_lifecycle_registry()
    _require(manifest.get('registry_snapshot_digest') == registry.digest
        == canonical_digest(registry.to_document()),'ntfs.original_registry_mismatch')
    return registry


def _native_lifecycle_installation(*, manifest_bytes, expected_manifest_digest,
    run_id, operation_nonce, channel_id, _inspection_only: bool = False):
    """New fixed1.2 generation. A candidate never gains a native channel."""
    from .canonical import canonical_bytes,parse_json_bytes
    from .mutation.ntfs.native import _require
    from .mutation.ntfs.authority import _NativeFileCreateAuthority
    from .mutation.ntfs.channel_v3 import LinuxNativeChannelV3
    _require(type(_inspection_only) is bool,'ntfs.fixed_role_required')
    registry = _native_lifecycle_registry()
    # This check is deliberately before manifest roots/read binding/channel.
    # The V5 candidate has no production native-authority profile, even if a
    # contract has no explicit guarantee requirements.
    exact = registry.guarantee_profile_bindings().get('phase.native.ntfs.authority.v1@1.0.0')
    _require(exact is not None,'ntfs.native_profile_not_qualified')
    profile = _native_qualified_profile(registry,exact)
    binding = _resolve_native_file_create_read_binding(manifest_bytes=manifest_bytes,
        expected_manifest_digest=expected_manifest_digest,registry=registry)
    manifest = parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    _require(manifest['authority']['profile'] == profile.as_dict()
        and manifest['native_read_installation_version'] == '1.2','ntfs.original_implementation_mismatch')
    channel = LinuxNativeChannelV3(channel_id=channel_id,_inspection_only=_inspection_only,
        _version1=manifest['contract']['id'] == 'publish_new_version.v1')
    authority = _NativeFileCreateAuthority(binding,profile,canonical_bytes(manifest['root_projections']),channel,
        run_id=run_id,operation_nonce=operation_nonce,_inspection_only=_inspection_only)
    return registry,_NativeFileCreateInstallation(binding,authority)


def _native_installation_for_manifest(*, manifest_bytes, expected_manifest_digest,
    run_id, operation_nonce, channel_id, _inspection_only: bool = False):
    # No public/request selector: exactly TWO authenticated installation formats.
    _native_registry_for_manifest(manifest_bytes,expected_manifest_digest)
    from .canonical import parse_json_bytes
    version = parse_json_bytes(manifest_bytes,maximum_bytes=2*1024**2)['native_read_installation_version']
    factory = _native_file_create_installation if version == '1.1' else _native_lifecycle_installation
    return factory(manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest,
        run_id=run_id,operation_nonce=operation_nonce,channel_id=channel_id,_inspection_only=_inspection_only)

