"""Finite immutable catalog components; no native operation/qualification.

Real existing admission/registry/domain checks run on synthetic identities.
Filesystem cases mutate only pytest-owned disposable artifact directories.
"""
import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import os
from pathlib import Path
import sys
import threading
from unittest.mock import patch

import pytest

from phase_tool import installation
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import qualification_catalog as catalog
from phase_tool.mutation.ntfs.bootstrap import _accepted_launch_history, _NativeAcceptedLaunch
from .test_native_mixed_experimental_history import bindings_fixture, altered


@lru_cache(maxsize=1)
def fixture():
    rows = bindings_fixture(repeated=True)
    all_rows = list(rows)
    for index, row in enumerate(rows):
        doc = row.experimental_admission.document()
        doc.update(run_id='catalog-'+str(index), request_id='catalog-'+str(index))
        all_rows.append(altered(row, admission=doc))
    chunks = tuple(canonical_bytes({'history_manifest_set_version': '1.3', 'manifests': [
        {'manifest_base64': base64.b64encode(row.manifest_bytes).decode(), 'manifest_digest': row.manifest_digest,
            'experimental_admission_base64': base64.b64encode(row.experimental_admission.raw).decode(),
            'experimental_admission_digest': digest_bytes(row.experimental_admission.raw)} for row in all_rows[start:start+2]]})
        for start in (0, 2))
    header = {'history_catalog_version': '1.0', 'chunks': [
        {'path': 'qualification-history/part-'+str(index).zfill(4)+'.json', 'length': len(raw),
            'entry_count': 2, 'digest': digest_bytes(raw)} for index, raw in enumerate(chunks)],
        'entry_count': 4, 'total_bytes': sum(map(len, chunks)), 'whole_set_digest': catalog.catalog_digest(chunks)}
    return tuple(all_rows), chunks, header


def materialized(tmp_path, *, chunks=None, header=None):
    rows, original_chunks, original_header = fixture()
    chunks = original_chunks if chunks is None else chunks
    header = original_header if header is None else header
    root = tmp_path/'a'
    (root/'qualification-history').mkdir(parents=True)
    for index, raw in enumerate(chunks):
        (root/'qualification-history'/('part-'+str(index).zfill(4)+'.json')).write_bytes(raw)
    return root, rows, header


def load(root, rows, header, index=0):
    return catalog.load_history_catalog(header, artifact_root=root,
        active_bytes=rows[index].manifest_bytes, active_digest=rows[index].manifest_digest)


@pytest.mark.parametrize('index', range(4))
def test_complete_catalog_exact_active_and_existing_domain_checks(index, tmp_path):
    root, rows, header = materialized(tmp_path)
    loaded = load(root, rows, header, index)
    assert type(loaded) is catalog._QualificationHistoryCatalog
    assert loaded.chunks == fixture()[1]
    with pytest.raises(FrozenInstanceError): loaded.chunks = ()
    checked = installation._resolve_native_history_bindings(rows[index], loaded, header['whole_set_digest'])
    assert [row.manifest_digest for row in checked] == [row.manifest_digest for row in rows]
    for row in checked:
        with pytest.raises(PhaseError, match='ntfs.native_profile_not_qualified'):
            installation._native_qualified_profile(row.registry, row.experimental_admission.profile(row).as_dict())


@pytest.mark.parametrize('part', ['extra', 'unknown-version', 'path-traversal', 'absolute-path', 'reordered',
    'chunk-count', 'entry-count', 'total-bytes', 'chunk-size', 'bool-size', 'bool-count', 'digest'])
def test_closed_header_caps_and_paths_refuse_before_file_reads(part, tmp_path):
    rows, chunks, header = fixture()
    value = deepcopy(header)
    if part == 'extra': value['provider'] = 'untrusted'
    elif part == 'unknown-version': value['history_catalog_version'] = '2.0'
    elif part == 'path-traversal': value['chunks'][0]['path'] = '../outside.json'
    elif part == 'absolute-path': value['chunks'][0]['path'] = '/outside.json'
    elif part == 'reordered': value['chunks'].reverse()
    elif part == 'chunk-count': value['chunks'] = value['chunks']*17
    elif part == 'entry-count': value['entry_count'] = catalog.MAX_ENTRIES+1
    elif part == 'total-bytes': value['total_bytes'] = catalog.MAX_TOTAL_BYTES+1
    elif part == 'chunk-size': value['chunks'][0]['length'] = catalog.MAX_CHUNK_BYTES+1
    elif part == 'bool-size': value['chunks'][0]['length'] = True
    elif part == 'bool-count': value['entry_count'] = True
    else: value['whole_set_digest'] = 'unknown'
    with patch.object(catalog, '_read_chunk', side_effect=AssertionError('file read reached')) as read:
        with pytest.raises(PhaseError): load(tmp_path, rows, value)
        read.assert_not_called()


@pytest.mark.parametrize('damage', ['missing', 'changed', 'hardlink', 'directory'])
def test_missing_modified_or_linked_chunk_is_not_a_partial_catalog(damage, tmp_path):
    root, rows, header = materialized(tmp_path)
    target = root/header['chunks'][1]['path']
    if damage == 'missing': target.unlink()
    elif damage == 'changed': target.write_bytes(target.read_bytes()[:-1]+b' ')
    elif damage == 'hardlink': os.link(target, root/'alias.json')
    else: target.unlink(); target.mkdir()
    with pytest.raises(PhaseError): load(root, rows, header)


@pytest.mark.skipif(sys.platform == 'win32', reason='actual symlink fixture requires separate capability on Windows')
def test_symlink_chunk_refuses_without_following(tmp_path):
    root, rows, header = materialized(tmp_path)
    target = root/header['chunks'][0]['path']
    outside = tmp_path/'outside.json'
    outside.write_bytes(target.read_bytes())
    target.unlink(); target.symlink_to(outside)
    with pytest.raises(PhaseError, match='ntfs.history_catalog_file_unsafe'): load(root, rows, header)


def test_duplicate_runs_across_chunks_cannot_pass_with_recomputed_hashes(tmp_path):
    rows, chunks, header = fixture()
    chunks = (chunks[0], chunks[0])
    value = deepcopy(header)
    value['chunks'][1].update(length=len(chunks[0]), digest=digest_bytes(chunks[0]))
    value.update(total_bytes=sum(map(len, chunks)), whole_set_digest=catalog.catalog_digest(chunks))
    root, rows, value = materialized(tmp_path, chunks=chunks, header=value)
    with pytest.raises(PhaseError, match='ntfs.history_catalog_binding_mismatch'): load(root, rows, value)


def test_wrong_whole_digest_or_missing_actual_active_never_resolves(tmp_path):
    root, rows, header = materialized(tmp_path)
    bad = deepcopy(header); bad['whole_set_digest'] = 'sha256:'+'e'*64
    with pytest.raises(PhaseError, match='ntfs.history_catalog_binding_mismatch'): load(root, rows, bad)
    doc = rows[0].experimental_admission.document(); doc.update(run_id='absent-catalog', request_id='absent-catalog')
    absent = altered(rows[0], admission=doc)
    with pytest.raises(PhaseError, match='ntfs.history_catalog_binding_mismatch'):
        catalog.load_history_catalog(header, artifact_root=root, active_bytes=absent.manifest_bytes, active_digest=absent.manifest_digest)


def test_forged_private_object_fields_and_json_do_not_substitute_validated_catalog(tmp_path):
    root, rows, header = materialized(tmp_path)
    loaded = load(root, rows, header)
    for bad in (replace(loaded, chunks=loaded.chunks[:-1]), replace(loaded, document_bytes=loaded.document_bytes+b'\n')):
        with pytest.raises(PhaseError): installation._resolve_native_history_bindings(rows[0], bad, header['whole_set_digest'])
    with pytest.raises(PhaseError):
        installation._resolve_native_history_bindings(rows[0], {'document_bytes': loaded.document_bytes, 'chunks': loaded.chunks}, header['whole_set_digest'])


def test_parent_replacement_between_chunks_is_detected(tmp_path):
    root, rows, header = materialized(tmp_path)
    real = catalog._read_chunk
    changed = False
    def change(path, maximum):
        nonlocal changed
        raw = real(path, maximum)
        if not changed:
            changed = True
            parent = root/'qualification-history'; retained = root/'old-history'
            assert parent.absolute().is_relative_to(tmp_path.absolute()) and retained.absolute().is_relative_to(tmp_path.absolute())
            parent.rename(retained); parent.mkdir()
            for original in retained.iterdir(): (parent/original.name).write_bytes(original.read_bytes())
        return raw
    with patch.object(catalog, '_read_chunk', side_effect=change):
        with pytest.raises(PhaseError): load(root, rows, header)


def config(header):
    value = {name: None for name in ('phase_wheel', 'phase_wheel_digest', 'dependency_file_digests', 'windows_launcher',
        'linux_launcher', 'docker_executable', 'core_container_id', 'reader_container_id', 'image_digest',
        'linux_python', 'expected_linux_contours', 'artifact_graph')}
    value.update(native_launch_version='1.4', history_catalog=header)
    return value


def test_catalog_config_requires_actual_fixed_runtime_before_loading_files():
    rows, _, header = fixture()
    value = config(header)
    with patch.object(catalog, 'load_history_catalog', side_effect=AssertionError('catalog loader reached')) as loader:
        with pytest.raises(PhaseError, match='ntfs.history_catalog_runtime_required'):
            _accepted_launch_history(value, rows[0].manifest_bytes, rows[0].manifest_digest)
        launch = object.__new__(_NativeAcceptedLaunch)
        launch._owner = os.getpid(), threading.get_ident()
        launch._config_bytes = canonical_bytes(value)
        launch._manifest_bytes = rows[0].manifest_bytes
        launch._manifest_digest = rows[0].manifest_digest
        launch._invocation_bytes = b'{}'
        # The actual gate runs in this unaccepted pytest process and must fail.
        # It is never replaced by a successful mock or acceptance boolean.
        with pytest.raises(PhaseError):
            _accepted_launch_history(value, rows[0].manifest_bytes, rows[0].manifest_digest, _launch=launch)
        loader.assert_not_called()


def test_foreign_self_consistent_companion_still_fails_existing_domain_validation(tmp_path):
    rows, chunks, header = fixture()
    changed = list(rows)
    doc = changed[-1].experimental_admission.document(); doc['wheel_digest'] = 'sha256:'+'e'*64
    changed[-1] = altered(changed[-1], admission=doc)
    chunk = parse_json_bytes(chunks[-1]); row = changed[-1]
    chunk['manifests'][-1] = {'manifest_base64': base64.b64encode(row.manifest_bytes).decode(), 'manifest_digest': row.manifest_digest,
        'experimental_admission_base64': base64.b64encode(row.experimental_admission.raw).decode(),
        'experimental_admission_digest': digest_bytes(row.experimental_admission.raw)}
    chunks = (chunks[0], canonical_bytes(chunk)); header = deepcopy(header)
    header['chunks'][1].update(length=len(chunks[1]), digest=digest_bytes(chunks[1]))
    header.update(total_bytes=sum(map(len, chunks)), whole_set_digest=catalog.catalog_digest(chunks))
    root, _, header = materialized(tmp_path, chunks=chunks, header=header)
    loaded = load(root, rows, header)
    with pytest.raises(PhaseError, match='ntfs.original_history_domain_mismatch'):
        installation._resolve_native_history_bindings(rows[0], loaded, header['whole_set_digest'])


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='actual ext4 and Linux authority components required')
def test_catalog_foreign_orphan_still_blocks_existing_complete_core_scan(tmp_path):
    from phase_tool import core
    if installation._linux_filesystem_type(tmp_path) != 'ext4':
        pytest.skip('native MIX history requires actual ext4')
    root, rows, header = materialized(tmp_path)
    evidence = tmp_path/'evidence'; preparation = tmp_path/'preparation'
    evidence.mkdir(mode=0o700); preparation.mkdir(mode=0o700)
    updated = []
    for row in rows:
        doc = row.experimental_admission.document()
        doc['evidence_identity'] = {'stable_id': 'catalog.evidence', 'device': evidence.stat().st_dev, 'inode': evidence.stat().st_ino}
        doc['preparation_identity'] = {'stable_id': 'catalog.preparation', 'device': preparation.stat().st_dev, 'inode': preparation.stat().st_ino}
        leaf = parse_json_bytes(row.manifest_bytes)
        leaf.update(evidence_root=str(evidence), preparation_root=str(preparation))
        updated.append(altered(row, manifest=leaf, admission=doc))
    chunks = tuple(canonical_bytes({'history_manifest_set_version': '1.3', 'manifests': [
        {'manifest_base64': base64.b64encode(row.manifest_bytes).decode(), 'manifest_digest': row.manifest_digest,
            'experimental_admission_base64': base64.b64encode(row.experimental_admission.raw).decode(),
            'experimental_admission_digest': digest_bytes(row.experimental_admission.raw)} for row in updated[start:start+2]]}) for start in (0,2))
    header = deepcopy(header)
    for index, raw in enumerate(chunks):
        (root/header['chunks'][index]['path']).write_bytes(raw)
        header['chunks'][index].update(length=len(raw), digest=digest_bytes(raw))
    header.update(total_bytes=sum(map(len,chunks)), whole_set_digest=catalog.catalog_digest(chunks))
    runs = evidence/'.phase/runs'; runs.mkdir(parents=True, mode=0o700)
    (evidence/'.phase/locks').mkdir(mode=0o700)
    orphan = runs/'unknown-original'; orphan.mkdir(mode=0o700)
    for index in (0,3):
        loaded = load(root, updated, header, index)
        history = installation._resolve_native_history_bindings(updated[index], loaded, header['whole_set_digest'])
        with pytest.raises(PhaseError, match='ntfs.original_history_unresolved'):
            with core._guard_native_original_intents(updated[index], history_bindings=history):
                pytest.fail('unknown original was filtered')
    assert list(orphan.iterdir()) == []


@pytest.mark.skipif(os.name != 'nt', reason='Windows path/fstat ctime API distinction')
@pytest.mark.parametrize('damage', ['opened-ctime', 'named-ctime', 'cross-identity'])
def test_windows_reader_keeps_independent_drift_and_cross_identity_checks(damage, tmp_path):
    from types import SimpleNamespace
    target = tmp_path/'ordinary.json'; target.write_bytes(b'catalog reader control')
    from phase_tool import evidence
    real_fstat = os.fstat; real_ordinary = evidence._qualification_catalog_ordinary
    fd_count = 0; named_count = 0
    def values(info):
        return {name: getattr(info,name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_birthtime_ns','st_nlink','st_mode')}
    def changed_fstat(fd):
        nonlocal fd_count
        info = real_fstat(fd); fd_count += 1
        if (damage == 'opened-ctime' and fd_count == 2) or (damage == 'cross-identity' and fd_count == 1):
            data = values(info); key = 'st_ctime_ns' if damage == 'opened-ctime' else 'st_ino'; data[key] += 100
            return SimpleNamespace(**data)
        return info
    def changed_named(path, *, directory):
        nonlocal named_count
        info = real_ordinary(path,directory=directory); named_count += 1
        if damage == 'named-ctime' and named_count == 2:
            data = values(info); data['st_ctime_ns'] += 100
            return SimpleNamespace(**data)
        return info
    with patch.object(os,'fstat',side_effect=changed_fstat), patch.object(evidence,'_qualification_catalog_ordinary',side_effect=changed_named):
        with pytest.raises(PhaseError): catalog._read_chunk(target, 1024)



def resolved_fixture():
    rows, chunks, header = fixture()
    loaded = catalog._QualificationHistoryCatalog(canonical_bytes(header), chunks)
    return installation._resolve_native_history_bindings(rows[0], loaded, header['whole_set_digest'])


def test_context_scoped_sharing_preserves_full_resolution():
    rows = resolved_fixture()
    context = rows[0]._qualification_context
    assert type(context) is catalog._CatalogRegistryContext
    assert all(row._qualification_context is context and row.registry is rows[0].registry for row in rows)
    # A new invocation has a new exact context and re-runs the real factory.
    fresh = resolved_fixture()
    assert fresh[0]._qualification_context is not context and fresh[0].registry is not rows[0].registry
    # Complete domain revalidation carries the SAME scoped data context.
    again = installation._validate_native_history_bindings(rows[0], rows)
    assert all(row.registry is rows[0].registry for row in again)
    original = fixture()[0][0]
    normal = installation._native_experimental_read_binding(manifest_bytes=original.manifest_bytes,
        expected_manifest_digest=original.manifest_digest, admission=original.experimental_admission)
    assert normal._qualification_context is None and normal.registry._qualification_context is None


@pytest.mark.parametrize('damage', ['foreign-type', 'foreign-owner', 'different-row-context'])
def test_foreign_context_cannot_supply_registry_or_history(damage):
    rows = resolved_fixture()
    context = rows[0]._qualification_context
    if damage == 'foreign-type':
        with pytest.raises(PhaseError, match='ntfs.history_catalog_context_mismatch'):
            installation._native_experimental_read_binding(manifest_bytes=rows[0].manifest_bytes,
                expected_manifest_digest=rows[0].manifest_digest, admission=rows[0].experimental_admission,
                _catalog_context=object())
    elif damage == 'foreign-owner':
        foreign = catalog._CatalogRegistryContext()
        with pytest.raises(PhaseError, match='ntfs.history_catalog_snapshot_changed'):
            foreign.check(rows[0].registry)
    else:
        changed = (replace(rows[0], _qualification_context=catalog._CatalogRegistryContext()), *rows[1:])
        with pytest.raises(PhaseError, match='ntfs.history_catalog_context_mismatch'):
            installation._validate_native_history_bindings(rows[0], changed)


@pytest.mark.parametrize('damage', ['document', 'resources', 'digest', 'cache-bytes'])
def test_context_rejects_snapshot_or_cached_schema_mutation(damage):
    from types import MappingProxyType
    row = resolved_fixture()[0]
    registry = row.registry; context = row._qualification_context
    registry.schema_registry()
    if damage == 'document': registry._document['registry_snapshot_version'] = 'changed'
    elif damage == 'resources': registry._resources = MappingProxyType(dict(registry._resources))
    elif damage == 'digest': registry.digest = 'sha256:'+'0'*64
    else: context._schemas[id(registry)] = (("https://invalid.local/poison", b'{}'),)
    with pytest.raises(PhaseError, match='ntfs.history_catalog_snapshot_changed'):
        registry.schema_registry()


def test_returned_schema_and_descriptor_mutation_cannot_poison_later_validation():
    row = resolved_fixture()[0]; registry = row.registry
    entry = next(item for item in registry.to_document()['entries']
        if item['kind'] == 'schema' and item.get('current', True) is True)
    first = registry.schema_registry()
    before = canonical_bytes(first.contents(entry['schema_ref']))
    first.contents(entry['schema_ref']).clear()
    assert canonical_bytes(registry.schema_registry().contents(entry['schema_ref'])) == before
    binding = registry.guarantee_profile_bindings()[row.experimental_admission._profile]
    descriptor = registry.resolve_guarantee_profile(binding)
    descriptor['classification'] = 'qualified'; descriptor['provided_guarantees'].append('forged')
    later = registry.resolve_guarantee_profile(binding)
    assert later['classification'] == 'qualification_candidate' and later['provided_guarantees'] == []


def test_exact_schema_bytes_revalidated_and_invalid_schema_not_cached():
    from jsonschema.exceptions import SchemaError
    from jsonschema import Draft202012Validator
    row = resolved_fixture()[0]; context = row._qualification_context
    actual = Draft202012Validator.check_schema
    with patch.object(Draft202012Validator, 'check_schema', side_effect=actual) as observed:
        row.registry._check_schema({'type': 'string', 'maxLength': 3})
        row.registry._check_schema({'type': 'string', 'maxLength': 3})
        row.registry._check_schema({'type': 'string', 'maxLength': 4})
        with pytest.raises(SchemaError): row.registry._check_schema({'type': 'definitely-invalid'})
        with pytest.raises(SchemaError): row.registry._check_schema({'type': 'definitely-invalid'})
        assert observed.call_count == 4
    assert canonical_bytes({'type': 'definitely-invalid'}) not in context._well_formed


def test_physical_implementation_rehashed_after_scoped_cache_warmup():
    import phase_tool.registry as registry_module
    row = resolved_fixture()[0]; registry = row.registry
    binding = registry.guarantee_profile_bindings()[row.experimental_admission._profile]
    descriptor = registry.resolve_guarantee_profile(binding)
    relative = descriptor['implementation']['artifact'].removeprefix('phase_tool/')
    original_root = registry_module.package_resources.files('phase_tool')
    class ChangedRoot:
        def joinpath(self, name):
            assert name == relative
            class ChangedArtifact:
                def read_bytes(self): return original_root.joinpath(name).read_bytes()+b'changed-after-warmup'
            return ChangedArtifact()
    with patch.object(registry_module.package_resources, 'files', return_value=ChangedRoot()):
        with pytest.raises(PhaseError, match='guarantee_profile.implementation_digest_mismatch'):
            registry.resolve_guarantee_profile(binding)



def test_catalog_all_six_exact_contexts_and_version2_objects_use_existing_readers():
    from .test_native_mixed_experimental_history import set_bytes
    original = bindings_fixture()
    chunks = tuple(set_bytes(original[start:start+2]) for start in (0,2,4))
    header = {'history_catalog_version': '1.0', 'chunks': [
        {'path': 'qualification-history/part-'+str(index).zfill(4)+'.json', 'length': len(raw),
            'entry_count': 2, 'digest': digest_bytes(raw)} for index, raw in enumerate(chunks)],
        'entry_count': 6, 'total_bytes': sum(map(len,chunks)), 'whole_set_digest': catalog.catalog_digest(chunks)}
    loaded = catalog._QualificationHistoryCatalog(canonical_bytes(header),chunks)
    rows = installation._resolve_native_history_bindings(original[3],loaded,header['whole_set_digest'])
    context = rows[0]._qualification_context
    assert len({id(row.registry) for row in rows}) == len(context._registries) == 6
    assert [row.registry.digest for row in rows] == [row.registry.digest for row in original]
    assert all(row._qualification_context is context for row in rows)
    assert len(parse_json_bytes(rows[3].manifest_bytes)['root_grants']) == 2
    for row in rows:
        with pytest.raises(PhaseError,match='ntfs.native_profile_not_qualified'):
            installation._native_qualified_profile(row.registry,row.experimental_admission.profile(row).as_dict())



@pytest.mark.parametrize('damage', ['float', 'unicode', 'non-string-key'])
def test_actual_current_snapshot_tree_is_checked_before_cache_reuse(damage):
    row = resolved_fixture()[0]
    if damage == 'float': row.registry._document['registry_snapshot_version'] = 1.0
    elif damage == 'unicode': row.registry._document['registry_snapshot_version'] = 'é'
    else: row.registry._document[1] = 'non-string key'
    with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):
        row.experimental_admission.profile(row)


@pytest.mark.parametrize('damage', ['contract-cache', 'profile-cache'])
def test_cached_immutable_validation_bytes_are_bound_to_actual_resources(damage):
    row = resolved_fixture()[0]; context = row._qualification_context
    if damage == 'contract-cache':
        key = next(iter(context._contracts))
        context._contracts[key] = (b'{}', context._contracts[key][1])
        manifest = parse_json_bytes(row.manifest_bytes)
        with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):
            row.registry.resolve_contract(**{
                'identifier':manifest['contract']['id'], 'version':manifest['contract']['version'],
                'package_digest':manifest['contract']['package_digest'], 'core_version':manifest['core']['version']})
    else:
        key = next(iter(context._profiles)); context._profiles[key] = b'{}'
        with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):
            row.experimental_admission.profile(row)


def test_cached_contract_returns_fresh_documents_and_still_checks_core_version():
    row = resolved_fixture()[0]; manifest = parse_json_bytes(row.manifest_bytes)
    args = dict(identifier=manifest['contract']['id'],version=manifest['contract']['version'],
        package_digest=manifest['contract']['package_digest'],core_version=manifest['core']['version'])
    first = row.registry.resolve_contract(**args)
    expected = canonical_bytes(first.document)
    first.document.clear()
    first.entry['package_artifacts'].clear()
    later = row.registry.resolve_contract(**args)
    assert canonical_bytes(later.document) == expected and len(later.entry['package_artifacts']) > 0
    with pytest.raises(PhaseError,match='contract.core_incompatible'):
        row.registry.resolve_contract(**dict(args,core_version='99.0.0'))


def test_every_varying_manifest_is_validated_with_warmed_context():
    row = resolved_fixture()[0]
    manifest = parse_json_bytes(row.manifest_bytes); manifest['evidence_root'] = 'relative-root'
    raw = canonical_bytes(manifest)
    with pytest.raises(PhaseError,match='ntfs.original_evidence_root_required'):
        installation._native_experimental_read_binding(manifest_bytes=raw,
            expected_manifest_digest=digest_bytes(raw), admission=row.experimental_admission,
            _catalog_context=row._qualification_context)



def test_internal_manifest_reference_schema_poisoning_is_checked_before_every_reuse():
    row=resolved_fixture()[0]; context=row._qualification_context
    reference=context._manifest_references[id(row.registry)][0]
    from referencing import Resource
    ref=next(ref for ref in reference if hasattr(reference.contents(ref),'items'))
    contents=reference.contents(ref)
    with pytest.raises(TypeError): contents['type']='null'
    replacement=Resource.from_contents({'$schema':'https://json-schema.org/draft/2020-12/schema','type':'null'})
    cached=context._manifest_references[id(row.registry)]
    context._manifest_references[id(row.registry)]=(reference.with_resource(ref,replacement),cached[1],cached[2])
    with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):
        installation._native_experimental_read_binding(manifest_bytes=row.manifest_bytes,
            expected_manifest_digest=row.manifest_digest,admission=row.experimental_admission,_catalog_context=context)


def test_private_expected_snapshot_tree_does_not_alias_actual_or_returned_documents():
    row=resolved_fixture()[0]; context=row._qualification_context
    expected=context._identities[id(row.registry)][4]
    returned=row.registry.to_document()
    assert expected is not row.registry._document and expected is not returned
    returned['entries'].clear()
    row.experimental_admission.profile(row)
    expected['entries'].clear()
    with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):
        row.experimental_admission.profile(row)



def test_private_schema_trees_are_recursively_immutable_without_public_aliases():
    from types import MappingProxyType
    row=resolved_fixture()[0]; context=row._qualification_context
    private=context._manifest_references[id(row.registry)][0]
    found_list=False
    pending=[private.contents(ref) for ref in private]
    while pending:
        value=pending.pop()
        if type(value) is MappingProxyType:
            assert all(type(key) is str for key in value)
            with pytest.raises(TypeError): value['forged']=True
            pending.extend(value.values())
        elif type(value) is tuple:
            found_list=True
            with pytest.raises(TypeError): value[0:0]=()
            pending.extend(value)
        else: assert type(value) in (str,int,bool,type(None))
    assert found_list
    public=row.registry.schema_registry()
    ref=next(ref for ref in public if type(public.contents(ref)) is dict)
    assert type(public.contents(ref)) is dict and public.contents(ref) is not private.contents(ref)
    public.contents(ref).clear()
    installation._native_experimental_read_binding(manifest_bytes=row.manifest_bytes,
        expected_manifest_digest=row.manifest_digest,admission=row.experimental_admission,_catalog_context=context)



@pytest.mark.parametrize('keyword',['unevaluatedProperties','unevaluatedItems'])
def test_freezer_fails_closed_for_unsupported_schema_semantics(keyword):
    with pytest.raises(PhaseError,match='ntfs.history_catalog_schema_unsupported'):
        catalog._CatalogRegistryContext._immutable_schema({'properties':{'nested':{keyword:False}}})


def test_original_and_private_fixed_schema_readers_agree_for_all_six_manifests_and_invalids():
    from jsonschema.exceptions import ValidationError
    rows=bindings_fixture()
    context=catalog._CatalogRegistryContext()
    def verdict(row,registry,manifest):
        raw=canonical_bytes(manifest)
        try:
            installation._resolve_native_file_create_read_binding(manifest_bytes=raw,
                expected_manifest_digest=digest_bytes(raw),registry=registry)
            return ('accepted',)
        except PhaseError as error:return ('phase',error.code)
        except ValidationError as error:return ('schema',error.validator,tuple(error.absolute_path),tuple(error.absolute_schema_path))
    for row in rows:
        kind=type(row.experimental_admission)
        registry=context.registry(kind,context._factories[kind])
        original=parse_json_bytes(row.manifest_bytes)
        cases=[deepcopy(original) for _ in range(5)]
        cases[1]['unexpected_field']=True
        cases[2]['root_grants'][0]['native_identity']['file_id']='wrong'
        cases[3]['core']['version']='99.0.0'
        cases[4]['evidence_root']='relative-root'
        for manifest in cases:
            assert verdict(row,row.registry,manifest) == verdict(row,registry,manifest)


def test_supported_reference_const_enum_array_and_condition_semantics_differential():
    from jsonschema import Draft202012Validator
    from referencing import Registry,Resource
    document={'$schema':'https://json-schema.org/draft/2020-12/schema',
        '$id':'https://phase-test.local/fixed-data',
        '$defs':{'payload':{'enum':[[1,{'a':2}],[3]]}},
        'type':'object','properties':{'mode':{'enum':['strict','other']},'payload':{'$ref':'#/$defs/payload'}},
        'required':['mode','payload'],'if':{'properties':{'mode':{'const':'strict'}}},
        'then':{'properties':{'payload':{'const':[1,{'a':2}]}}},
        'else':{'properties':{'payload':{'const':[3]}}},'additionalProperties':False}
    source=canonical_bytes(document)
    frozen=catalog._CatalogRegistryContext._immutable_schema(parse_json_bytes(source))
    regular=Registry().with_resource(document['$id'],Resource.from_contents(parse_json_bytes(source)))
    private=Registry().with_resource(document['$id'],Resource.from_contents(frozen))
    outer={'$ref':document['$id']}
    original=Draft202012Validator(outer,registry=regular); immutable=Draft202012Validator(outer,registry=private)
    for instance in ({'mode':'strict','payload':[1,{'a':2}]},{'mode':'strict','payload':[3]},
            {'mode':'other','payload':[3]},{'mode':'other','payload':[1,{'a':2}]},
            {'mode':'strict','payload':[1,{'a':True}]},{'mode':'strict'},
            {'mode':'strict','payload':[1,{'a':2}],'extra':1}):
        left=sorted((error.validator,tuple(error.absolute_path)) for error in original.iter_errors(instance))
        right=sorted((error.validator,tuple(error.absolute_path)) for error in immutable.iter_errors(instance))
        assert left == right



def test_validation_pass_nested_scopes_and_exception_restore_actual_checks():
    context=catalog._CatalogRegistryContext()
    primary=PhaseError('test.original_validation_failure')
    cause=ValueError('original cause')
    with pytest.raises(PhaseError) as caught:
        with context.validation_pass():
            assert len(context._registries) == 6 and context._validation_depth == 1
            with context.validation_pass():
                assert context._validation_depth == 2
            assert context._validation_depth == 1
            raise primary from cause
    assert caught.value is primary and caught.value.__cause__ is cause and context._validation_depth == 0
    registry=next(iter(context._registries.values()))
    registry._document['registry_snapshot_version']='changed-after-exception'
    with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):context.check(registry)


def test_catalog_snapshot_mutation_during_rows_blocks_return_after_full_pass():
    rows,chunks,header=fixture(); loaded=catalog._QualificationHistoryCatalog(canonical_bytes(header),chunks)
    original=installation._native_experimental_read_binding
    observed=[]; context=None
    def mutate(*args,**kwargs):
        nonlocal context
        checked=original(*args,**kwargs); observed.append(checked)
        context=checked._qualification_context
        if len(observed) == 1:checked.registry._document['registry_snapshot_version']='during-loop'
        return checked
    with patch.object(installation,'_native_experimental_read_binding',side_effect=mutate):
        with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):
            installation._resolve_native_history_bindings(rows[0],loaded,header['whole_set_digest'])
    assert len(observed) == len(rows)*2 and context._validation_depth == 0


def test_validation_pass_preserves_original_failure_and_final_drift_together():
    context=catalog._CatalogRegistryContext(); primary=PhaseError('test.original_validation_failure')
    with pytest.raises(BaseExceptionGroup) as caught:
        with context.validation_pass():
            next(iter(context._registries.values()))._document['registry_snapshot_version']='during-failure'
            raise primary
    assert caught.value.exceptions[0] is primary
    assert any(isinstance(error,PhaseError) and error.code == 'ntfs.history_catalog_snapshot_changed'
        for error in caught.value.exceptions[1:])
    assert context._validation_depth == 0


def test_validation_pass_rejects_foreign_thread_and_foreign_snapshot_context():
    context=catalog._CatalogRegistryContext(); failures=[]
    def foreign():
        try:
            with context.validation_pass():pytest.fail('foreign thread entered')
        except PhaseError as error:failures.append(error)
    thread=threading.Thread(target=foreign); thread.start(); thread.join(timeout=10)
    assert not thread.is_alive() and len(failures) == 1
    assert failures[0].code == 'ntfs.history_catalog_context_mismatch' and context._validation_depth == 0
    other=catalog._CatalogRegistryContext()
    with context.validation_pass():
        registry=next(iter(context._registries.values()))
        with pytest.raises(PhaseError,match='ntfs.history_catalog_snapshot_changed'):other.check(registry)
    assert context._validation_depth == other._validation_depth == 0


def test_catalog_artifact_reader_is_owned_by_evidence_boundary():
    assert catalog._read_chunk.__module__ == 'phase_tool.evidence'
