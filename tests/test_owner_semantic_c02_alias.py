"""Data-only reciprocal Owner3 histories with genuine contract registries."""
import base64
from copy import deepcopy
from dataclasses import replace
from pathlib import Path, PureWindowsPath
import zipimport

import pytest

import phase_tool
from phase_tool import installation
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import owner_directory_fixture as owner
from phase_tool.mutation.ntfs.owner_semantic_history import owner3_history_buffers
from tests.test_owner_semantic_source_closure_v2 import ROLES, current_readers, history


ALIAS = 'c02_current_root_alias'
LEAVES = ('results', 'RESULTS')


def _loaded_wheel_digest():
    spec = phase_tool.__spec__
    loader = spec.loader
    if type(loader) is not zipimport.zipimporter:
        return None
    archive = Path(loader.archive)
    assert archive.is_absolute() and Path(spec.origin) == archive / 'phase_tool/__init__.py'
    limit = 16 * 1024**2
    with archive.open('rb') as stream:
        raw = stream.read(limit + 1)
    assert 0 < len(raw) <= limit
    return digest_bytes(raw)


def alias_readers(base, *, wheel_digest=None):
    rows, raw = base
    primary = parse_json_bytes(raw)
    if wheel_digest is None:
        wheel_digest = _loaded_wheel_digest()
    if wheel_digest is not None:
        primary['wheel_digest'] = wheel_digest
    current = primary['root_grants'][0]
    directory = PureWindowsPath(primary['windows_roots']['current_root']).parent
    observations = {}
    for leaf in LEAVES:
        observations[leaf] = {key: deepcopy(current[key]) for key in (
            'device', 'volume_guid', 'volume_serial32', 'native_identity')}
        observations[leaf].update(components=[*current['components'][:-1], leaf], reparse_tag=0,
            all_handles_closed=True, raw_digest=digest_bytes(('synthetic-c02-' + leaf).encode()))
    marker = {'version': '1.0', 'no_follow_observations': observations,
              'domain_digest': digest_bytes(canonical_bytes({'version': '1.0', 'owner_fixture': primary,
                                                            'no_follow_observations': observations}))}
    variants = []
    for leaf in LEAVES:
        doc = deepcopy(primary)
        doc['windows_roots']['current_root'] = str(directory / leaf)
        doc['root_grants'][0]['components'][-1] = leaf
        doc[ALIAS] = deepcopy(marker)
        cap = canonical_bytes(doc)
        bound = []
        for row in rows:
            kind = type(row.experimental_admission)
            manifest = parse_json_bytes(row.manifest_bytes)
            manifest['installation_id'] = owner.installation_id(kind, cap)
            manifest['root_grants'][0]['components'][-1] = leaf
            body = canonical_bytes(manifest)
            bound.append(replace(row, manifest_bytes=body, manifest_digest=digest_bytes(body),
                                 experimental_admission=kind(cap)))
        variants.append((tuple(bound), cap))
    return tuple(variants)


def reciprocal_history(active, peer):
    rows, raw = active
    past, past_raw = peer
    predecessors = [{'family': 'owner3', 'role': role,
        'manifest_base64': base64.b64encode(row.manifest_bytes).decode('ascii'),
        'manifest_digest': row.manifest_digest, 'admission_base64': base64.b64encode(past_raw).decode('ascii'),
        'admission_digest': digest_bytes(past_raw)} for role, row in zip(ROLES, past, strict=True)]
    return canonical_bytes(history(rows, raw, predecessors))


@pytest.fixture(scope='module')
def plain():
    return current_readers()


@pytest.fixture(scope='module')
def aliases(plain):
    return alias_readers(plain)


@pytest.mark.parametrize('index', (0, 1), ids=LEAVES)
def test_c02_reciprocal_history_resolves_and_rechecks_all_registries(aliases, index):
    local, other = aliases[index], aliases[1 - index]
    active = local[0][0]
    raw = reciprocal_history(local, other)
    readers = installation._resolve_native_history_bindings(active, raw, digest_bytes(raw))
    assert len(readers) == 12
    assert installation._validate_native_history_bindings(active, readers) is readers
    for reader, expected in zip(readers, local[0] + other[0], strict=True):
        doc = parse_json_bytes(reader.manifest_bytes)
        assert reader.manifest_bytes == expected.manifest_bytes
        assert reader.experimental_admission.raw == expected.experimental_admission.raw
        assert reader.registry.to_document() == expected.registry.to_document()
        chosen = installation._native_history_binding_for_original(readers, run_id='test-c02-full-tuple',
            contract=doc['contract'], core=doc['core'], installation={'id': doc['installation_id'],
            'descriptor_digest': reader.manifest_digest}, registry_snapshot_digest=reader.registry.digest)
        assert chosen is reader
    doc = parse_json_bytes(active.manifest_bytes)
    with pytest.raises(PhaseError, match='original_history_binding_mismatch'):
        installation._native_history_binding_for_original(readers, run_id='test-c02-proofless',
            contract=doc['contract'], core=doc['core'], installation=None, registry_snapshot_digest=None,
            _pre_intent_rejection=True)


@pytest.mark.parametrize('plain_active', (True, False), ids=('plain-active', 'marked-active'))
def test_c02_mixed_fixture_markers_refused_at_both_history_entries(plain, aliases, plain_active):
    active, peer = (plain, aliases[0]) if plain_active else (aliases[1], plain)
    current = active[0][0]
    raw = reciprocal_history(active, peer)
    with pytest.raises(PhaseError, match='c02_history_alias_peer'):
        owner3_history_buffers(raw, digest_bytes(raw), active_bytes=current.manifest_bytes,
                               active_digest=current.manifest_digest)
    with pytest.raises(PhaseError, match='c02_history_alias_peer'):
        installation._validate_native_history_bindings(current, active[0] + peer[0])


def test_c02_active_history_cannot_omit_its_peer(aliases):
    current, raw = aliases[0]
    data = canonical_bytes(history(current, raw, []))
    with pytest.raises(PhaseError, match='c02_history_alias_peer'):
        owner3_history_buffers(data, digest_bytes(data), active_bytes=current[0].manifest_bytes,
                               active_digest=current[0].manifest_digest)


def test_c02_reparse_observation_refused_before_manifest_selection(aliases):
    doc = parse_json_bytes(aliases[0][1])
    marker = doc.pop(ALIAS)
    marker['no_follow_observations']['RESULTS']['reparse_tag'] = 0xA000000C
    marker['domain_digest'] = digest_bytes(canonical_bytes({'version': '1.0', 'owner_fixture': doc,
        'no_follow_observations': marker['no_follow_observations']}))
    doc[ALIAS] = marker
    with pytest.raises(PhaseError, match='c02_alias_observation'):
        owner.fixture_document(canonical_bytes(doc))


def test_c02_loaded_wheel_mismatch_refused_at_both_history_entries(plain):
    if _loaded_wheel_digest() is None:
        pytest.skip('Requires a wheel imported directly as a ZIP archive')
    active, peer = alias_readers(plain, wheel_digest=digest_bytes(b'wrong-c02-wheel'))
    current = active[0][0]
    raw = reciprocal_history(active, peer)
    with pytest.raises(PhaseError, match='owner3_registry_corpus_changed'):
        installation._resolve_native_history_bindings(current, raw, digest_bytes(raw))
    with pytest.raises(PhaseError, match='owner3_registry_corpus_changed'):
        installation._validate_native_history_bindings(current, active[0] + peer[0])
