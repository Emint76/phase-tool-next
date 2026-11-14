"""Bounded immutable configuration for a finite qualification campaign.

No writer, execution journal, evidence index or admission grant exists here.
The fixed bootstrap verifies its accepted runtime BEFORE loading these files.
Every operation still uses an existing exact per-run admission and registry.
The accepted config pins the catalog header; its rows pin the chunk bytes.
Chunks contain manifests that bind the artifact graph, so chunks/header MUST
NOT be dependency_file_digests entries in that graph (a digest cycle).
"""
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...streaming import fingerprint
from ...evidence import _read_qualification_catalog_chunk as _read_chunk
from .native import _require
from .experimental_history_set import mixed_history_buffers

MAX_CHUNK_BYTES = 2*1024**2
MAX_TOTAL_BYTES = 16*1024**2
MAX_CHUNKS = 32
MAX_ENTRIES = 4096
_DOMAIN = b'phase.native.qualification-history-catalog.v1\x00'


@dataclass(frozen=True)
class _QualificationHistoryCatalog:
    """Loaded data only; JSON cannot substitute this exact private type.

    Construction is not authentication. Every consumer revalidates its bytes;
    trust remains in the accepted immutable bootstrap/configuration namespace.
    """
    document_bytes: bytes
    chunks: tuple[bytes, ...]


def catalog_digest(chunks):
    value = hashlib.sha256(_DOMAIN)
    for raw in chunks:
        _require(type(raw) is bytes, 'ntfs.history_catalog_shape')
        value.update(len(raw).to_bytes(8, 'big'))
        value.update(raw)
    return 'sha256:'+value.hexdigest()


def _document(raw):
    _require(type(raw) is bytes and len(raw) <= MAX_CHUNK_BYTES, 'ntfs.history_catalog_limit')
    document = parse_json_bytes(raw, maximum_bytes=MAX_CHUNK_BYTES)
    _require(type(document) is dict and canonical_bytes(document) == raw
        and set(document) == {'history_catalog_version', 'chunks', 'entry_count', 'total_bytes', 'whole_set_digest'}
        and document['history_catalog_version'] == '1.0'
        and type(document['chunks']) is list and 1 <= len(document['chunks']) <= MAX_CHUNKS
        and type(document['entry_count']) is int and 2 <= document['entry_count'] <= MAX_ENTRIES
        and type(document['total_bytes']) is int and 0 < document['total_bytes'] <= MAX_TOTAL_BYTES
        and type(document['whole_set_digest']) is str
        and re.fullmatch('sha256:[0-9a-f]{64}', document['whole_set_digest']) is not None,
        'ntfs.history_catalog_shape')
    entries = 0
    length = 0
    for index, row in enumerate(document['chunks']):
        _require(type(row) is dict and set(row) == {'path', 'length', 'entry_count', 'digest'}
            and row['path'] == 'qualification-history/part-'+str(index).zfill(4)+'.json'
            and type(row['length']) is int and 0 < row['length'] <= MAX_CHUNK_BYTES
            and type(row['entry_count']) is int and 2 <= row['entry_count'] <= MAX_ENTRIES
            and type(row['digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}', row['digest']) is not None,
            'ntfs.history_catalog_shape')
        entries += row['entry_count']
        length += row['length']
    _require(entries == document['entry_count'] and length == document['total_bytes'],
        'ntfs.history_catalog_binding_mismatch')
    return document


def _catalog_buffers(catalog, expected_digest, *, active_bytes, active_digest):
    _require(type(catalog) is _QualificationHistoryCatalog
        and type(catalog.chunks) is tuple, 'ntfs.history_catalog_required')
    document = _document(catalog.document_bytes)
    _require(type(expected_digest) is str and expected_digest == document['whole_set_digest']
        and len(catalog.chunks) == len(document['chunks']), 'ntfs.history_catalog_binding_mismatch')
    buffers = []
    runs = set()
    installations = set()
    for raw, row in zip(catalog.chunks, document['chunks'], strict=True):
        _require(type(raw) is bytes and len(raw) == row['length'] <= MAX_CHUNK_BYTES
            and digest_bytes(raw) == row['digest'], 'ntfs.history_catalog_digest_mismatch')
        chunk = parse_json_bytes(raw, maximum_bytes=MAX_CHUNK_BYTES)
        _require(type(chunk) is dict and type(chunk.get('manifests')) is list
            and len(chunk['manifests']) == row['entry_count'], 'ntfs.history_catalog_binding_mismatch')
        # Reuse the exact existing row/parser checks. Its active check is local
        # to this chunk; the actual invocation is checked ONCE over the full set.
        import base64
        first = chunk['manifests'][0]
        _require(type(first) is dict and type(first.get('manifest_base64')) is str
            and type(first.get('manifest_digest')) is str, 'ntfs.history_catalog_shape')
        try:
            local_active = base64.b64decode(first['manifest_base64'], validate=True)
        except (ValueError, UnicodeError) as error:
            raise PhaseError('ntfs.history_catalog_shape') from error
        checked = mixed_history_buffers(raw, row['digest'], active_bytes=local_active,
            active_digest=first['manifest_digest'])
        for leaf, sha, cap, kind in checked:
            admission = kind(cap).document()
            manifest = parse_json_bytes(leaf, maximum_bytes=MAX_CHUNK_BYTES)
            _require(admission['run_id'] not in runs and manifest['installation_id'] not in installations,
                'ntfs.history_catalog_binding_mismatch')
            runs.add(admission['run_id'])
            installations.add(manifest['installation_id'])
            buffers.append((leaf, sha, cap, kind))
    _require(catalog_digest(catalog.chunks) == expected_digest
        and len(buffers) == document['entry_count']
        and sum(leaf == active_bytes and sha == active_digest for leaf, sha, _, _ in buffers) == 1
        and type(active_bytes) is bytes and type(active_digest) is str
        and digest_bytes(active_bytes) == active_digest, 'ntfs.history_catalog_binding_mismatch')
    return tuple(buffers)


def _ordinary(path, *, directory):
    try:
        info = path.lstat()
    except OSError as error:
        raise PhaseError('ntfs.history_catalog_unavailable') from error
    _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        and not getattr(info, 'st_file_attributes', 0)&0x400
        and (directory or info.st_nlink == 1), 'ntfs.history_catalog_file_unsafe')
    return info





def load_history_catalog(document, *, artifact_root, active_bytes, active_digest):
    """Only accepted startup calls this loader; it creates no files or authority."""
    raw = canonical_bytes(document)
    checked = _document(raw)
    root = Path(artifact_root)
    _require(root.is_absolute() and root == Path(os.path.abspath(root)), 'ntfs.history_catalog_file_unsafe')
    anchors = {}
    for path in (*reversed(root.parents), root):
        info = _ordinary(path, directory=True)
        anchors[path] = (info.st_dev, info.st_ino)
    chunks = []
    for row in checked['chunks']:
        path = root
        parts = row['path'].split('/')
        for part in parts[:-1]:
            path = path/part
            info = _ordinary(path, directory=True)
            identity = (info.st_dev, info.st_ino)
            _require(path not in anchors or anchors[path] == identity, 'ntfs.history_catalog_file_unsafe')
            anchors[path] = identity
        path = path/parts[-1]
        before = _ordinary(path, directory=False)
        _require(before.st_size == row['length'], 'ntfs.history_catalog_binding_mismatch')
        try:
            body = _read_chunk(path, MAX_CHUNK_BYTES)
        except OSError as error:
            raise PhaseError('ntfs.history_catalog_unavailable') from error
        after = _ordinary(path, directory=False)
        _require(fingerprint(before) == fingerprint(after) and len(body) == row['length']
            and digest_bytes(body) == row['digest'], 'ntfs.history_catalog_digest_mismatch')
        chunks.append(body)
    for path, identity in anchors.items():
        info = _ordinary(path, directory=True)
        _require((info.st_dev, info.st_ino) == identity, 'ntfs.history_catalog_file_unsafe')
    loaded = _QualificationHistoryCatalog(raw, tuple(chunks))
    _catalog_buffers(loaded, checked['whole_set_digest'], active_bytes=active_bytes, active_digest=active_digest)
    return loaded



class _CatalogRegistryContext:
    """One resolution's pure bundled data only; never execution/history state."""
    def __init__(self):
        self._owner = os.getpid(), threading.get_ident()
        self._validation_depth = 0
        from ... import installation
        from .experimental_history_set import _mixed_history_contexts
        self._factories = dict(zip(_mixed_history_contexts(), (
            installation._native_experimental_file1_registry,
            installation._native_experimental_file2_registry,
            installation._native_experimental_version1_registry,
            installation._native_experimental_version2_registry,
            installation._native_experimental_bundle1_registry,
            installation._native_experimental_bundle2_registry_v3), strict=True))
        self._registries = {}
        self._identities = {}
        self._schemas = {}
        self._well_formed = set()
        self._contracts = {}
        self._profiles = {}
        self._manifest_references = {}

    def registry(self, kind, factory):
        from ...registry import RegistrySnapshot
        _require(type(self) is _CatalogRegistryContext and self._owner == (os.getpid(), threading.get_ident())
            and kind in self._factories
            and factory is self._factories[kind], 'ntfs.history_catalog_context_mismatch')
        if kind not in self._registries:
            registry = factory()  # Actual fixed byte/trust/contract factory, once.
            _require(type(registry) is RegistrySnapshot
                and getattr(registry, '_qualification_context', None) is None,
                'ntfs.history_catalog_context_mismatch')
            self._registries[kind] = registry
            self._identities[id(registry)] = (registry, canonical_bytes(registry._document),
                registry.digest, registry._resources, parse_json_bytes(canonical_bytes(registry._document)))
            registry._qualification_context = self
        registry = self._registries[kind]
        self.check(registry)
        return registry

    def check(self, registry):
        from types import MappingProxyType
        from ...registry import RegistrySnapshot
        _require(type(self) is _CatalogRegistryContext and self._owner == (os.getpid(), threading.get_ident())
            and type(registry) is RegistrySnapshot,
            'ntfs.history_catalog_context_mismatch')
        expected = self._identities.get(id(registry))
        _require(expected is not None and expected[0] is registry
            and registry._qualification_context is self
            and registry.digest == expected[2]
            and type(registry._resources) is MappingProxyType and registry._resources is expected[3],
            'ntfs.history_catalog_snapshot_changed')
        if self._validation_depth == 0:
            _require(type(registry._document) is dict and registry._document == expected[4]
                and self._snapshot_bytes(registry._document) == expected[1]
                and digest_bytes(expected[1]) == registry.digest,
                'ntfs.history_catalog_snapshot_changed')
        # The actual mapping is a private copied MappingProxy of immutable bytes.
        # Ordinary resolution STILL hashes each bound resource on every call;
        # physical implementation bytes are read/hashed by resolve_profile too.

    @contextmanager
    def validation_pass(self):
        """Pure, same-thread pass; complete actual snapshots bracket ALL rows.

        Only immutable package/implementation bytes may be read in this scope.
        No evidence/target IO, channel construction or dispatch belongs here.
        Every varying manifest/admission/domain is still validated. Nested
        cache hits check exact member/proxy identities; physical implementation
        bytes are rehashed on every profile call. No token is returned or saved.
        """
        _require(type(self) is _CatalogRegistryContext
            and self._owner == (os.getpid(),threading.get_ident()), 'ntfs.history_catalog_context_mismatch')
        if self._validation_depth:
            self._validation_depth += 1
            try:
                yield
            finally:
                self._validation_depth -= 1
            return
        # Six literal fixed factories, independent of catalog row ordering.
        for kind,factory in self._factories.items():
            self.registry(kind,factory)
        self._validation_depth = 1
        primary = None
        try:
            yield
        except BaseException as error:
            primary = error
        finally:
            self._validation_depth = 0  # Always restore full outside-pass checks.
        failures = []
        for registry in self._registries.values():
            try:
                self.check(registry)  # ACTUAL complete mutable tree/bytes again.
            except BaseException as error:
                failures.append(error)
        if primary is not None:
            if failures:
                raise BaseExceptionGroup('catalog validation and final snapshot checks failed',[primary,*failures])
            raise primary
        if failures:
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup('catalog final snapshot checks failed',failures)

    @staticmethod
    def _snapshot_bytes(document):
        # The caller first compares the COMPLETE actual tree to a separate,
        # private parsed copy of the captured normalized bytes. No caller gets
        # that copy. This catches non-string keys/foreign structures as well as
        # Unicode drift; actual re-encoding then catches Python equality aliases
        # such as 1 == 1.0. It rehashes actual bytes, never only captured bytes.
        try:
            return json.dumps(document, ensure_ascii=False, sort_keys=True,
                separators=(',', ':'), allow_nan=False).encode('utf-8')
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            raise PhaseError('ntfs.history_catalog_snapshot_changed') from error

    def snapshot_digest(self, registry):
        self.check(registry)
        return registry.digest

    def document(self, registry):
        self.check(registry)
        return parse_json_bytes(self._identities[id(registry)][1])

    def resolve_contract(self, registry, identifier, version, package_digest, *, core_version):
        from types import MappingProxyType
        from ...registry import ResolvedContract
        self.check(registry)
        _require(all(type(value) is str for value in (identifier, version, package_digest, core_version)),
            'ntfs.history_catalog_context_mismatch')
        key = id(registry), identifier, version, package_digest, core_version
        cached = self._contracts.get(key)
        if cached is None:
            checked = registry._resolve_contract_uncached(identifier, version, package_digest, core_version=core_version)
            cached = (registry.resource_bytes(registry._entry_resource(checked.entry)),
                canonical_bytes(dict(checked.entry)))
            self._contracts[key] = cached
        matches = registry._exact_entries(kind='contract', identifier=identifier, version=version, package_digest=package_digest)
        _require(len(matches) == 1, 'ntfs.history_catalog_snapshot_changed')
        entry = matches[0]
        registry._verify_entry(entry)  # All exact package resources rehashed.
        raw = registry.resource_bytes(registry._entry_resource(entry))
        _require(type(cached) is tuple and len(cached) == 2 and cached[0] == raw
            and cached[1] == self._snapshot_bytes(entry), 'ntfs.history_catalog_snapshot_changed')
        contract = parse_json_bytes(raw)
        hook = registry.resolve_contract_hook(contract['contract_hook']) if 'contract_hook' in contract else None
        return ResolvedContract(document=contract, package_digest=package_digest,
            registry_snapshot_digest=registry.digest, entry=MappingProxyType(parse_json_bytes(cached[1])),
            contract_hook=hook)

    def resolve_guarantee_profile(self, registry, binding):
        self.check(registry)
        key = id(registry), canonical_bytes(dict(binding))
        cached = self._profiles.get(key)
        if cached is None:
            registry._resolve_guarantee_profile_uncached(binding)
            matches = [entry for entry in registry._document['entries'] if entry.get('kind') == 'guarantee_profile'
                and entry.get('id') == binding.get('id') and entry.get('version') == binding.get('version')
                and entry.get('artifact_digest') == binding.get('descriptor_digest')]
            _require(len(matches) == 1, 'ntfs.history_catalog_snapshot_changed')
            cached = registry.resource_bytes(registry._entry_resource(matches[0]))
            self._profiles[key] = cached
        matches = [entry for entry in registry._document['entries'] if entry.get('kind') == 'guarantee_profile'
            and entry.get('id') == binding.get('id') and entry.get('version') == binding.get('version')
            and entry.get('artifact_digest') == binding.get('descriptor_digest')]
        _require(len(matches) == 1, 'ntfs.history_catalog_snapshot_changed')
        registry._verify_entry(matches[0])  # Descriptor/schema/vocabulary package hashes every call.
        raw = registry.resource_bytes(registry._entry_resource(matches[0]))
        _require(type(cached) is bytes and cached == raw, 'ntfs.history_catalog_snapshot_changed')
        descriptor = parse_json_bytes(raw)  # Fresh mutable result, never shared.
        registry._check_profile_implementation(descriptor)  # Physical code is NEVER cached.
        return descriptor

    def check_schema(self, registry, schema):
        from jsonschema import Draft202012Validator
        self.check(registry)
        raw = canonical_bytes(schema)
        if raw not in self._well_formed:
            Draft202012Validator.check_schema(schema)
            self._well_formed.add(raw)

    def _schema_buffers(self, registry):
        self.check(registry)
        current = []
        for entry in registry._document['entries']:
            if entry.get('kind') == 'schema' and entry.get('current', True) is True:
                registry._verify_entry(entry)  # Never cache resource verification.
                current.append((entry['schema_ref'], registry.resource_bytes(registry._entry_resource(entry))))
        key = id(registry)
        immutable = tuple(current)
        if key not in self._schemas:
            self._schemas[key] = immutable
        _require(self._schemas[key] == immutable, 'ntfs.history_catalog_snapshot_changed')
        return self._schemas[key]

    @staticmethod
    def _reference_registry(buffers):
        from referencing import Registry, Resource
        resolved = Registry()
        for ref, raw in buffers:
            resolved = resolved.with_resource(ref, Resource.from_contents(parse_json_bytes(raw)))
        return resolved

    def schema_registry(self, registry):
        # Public callers always get fresh mutable Resource.contents objects.
        return self._reference_registry(self._schema_buffers(registry))

    @staticmethod
    def _immutable_schema(value):
        from types import MappingProxyType
        if type(value) is dict:
            # This optimization is scoped to the six EXACT fixed schema sets,
            # not generic jsonschema equivalence. Their data lacks these
            # keywords, whose implementation distinguishes dict from Mapping.
            _require(not set(value)&{'unevaluatedProperties','unevaluatedItems'},
                'ntfs.history_catalog_schema_unsupported')
            # The backing dict is created HERE and never returned separately.
            return MappingProxyType({key: _CatalogRegistryContext._immutable_schema(child)
                for key, child in value.items()})
        if type(value) is list:
            return tuple(_CatalogRegistryContext._immutable_schema(child) for child in value)
        _require(type(value) in (str, int, bool, type(None)), 'ntfs.history_catalog_snapshot_changed')
        return value

    def manifest_schema_registry(self, registry):
        # Only the fixed static manifest validator uses this private registry.
        # Every Resource.contents tree has an owned MappingProxy/tuple backing;
        # there is no mutable backing-dict alias. Recheck exact immutable tree
        # identities AND source resource hashes before every use. Public schema
        # registries continue returning fresh mutable data.
        from referencing import Registry, Resource
        buffers = self._schema_buffers(registry)
        key = id(registry)
        cached = self._manifest_references.get(key)
        if cached is None:
            resolved = Registry()
            controls = []
            for ref, raw in buffers:
                contents = self._immutable_schema(parse_json_bytes(raw))
                resolved = resolved.with_resource(ref, Resource.from_contents(contents))
                controls.append((ref, contents))
            cached = resolved, buffers, tuple(controls)
            self._manifest_references[key] = cached
        _require(type(cached) is tuple and len(cached) == 3
            and type(cached[0]) is Registry and cached[1] == buffers
            and type(cached[2]) is tuple
            and tuple(row[0] for row in cached[2]) == tuple(ref for ref, _ in buffers)
            and set(cached[0]) == {ref for ref, _ in buffers}, 'ntfs.history_catalog_snapshot_changed')
        try:
            for ref, expected_contents in cached[2]:
                _require(cached[0].contents(ref) is expected_contents,
                    'ntfs.history_catalog_snapshot_changed')
        except (KeyError, TypeError, ValueError) as error:
            raise PhaseError('ntfs.history_catalog_snapshot_changed') from error
        return cached[0]


def resolve_history_catalog(active, catalog, expected_digest):
    """Complete resolver/domain checks with one scoped pure-data context."""
    from ...installation import (_NativeFileCreateReadBinding, _native_experimental_read_binding,
        _validate_native_history_bindings)
    _require(type(active) is _NativeFileCreateReadBinding, 'ntfs.original_read_binding_required')
    buffers = _catalog_buffers(catalog, expected_digest, active_bytes=active.manifest_bytes,
        active_digest=active.manifest_digest)
    context = _CatalogRegistryContext()
    with context.validation_pass():
        bindings = tuple(_native_experimental_read_binding(manifest_bytes=leaf,
            expected_manifest_digest=sha, admission=kind(cap), _catalog_context=context)
            for leaf, sha, cap, kind in buffers)
        return _validate_native_history_bindings(active, bindings)
