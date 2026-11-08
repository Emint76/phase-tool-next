"""Installed mixed-reader correlation and real ext4 history refusal.

These are not Windows execution, composed-lock or qualification evidence.
All production profile checks remain active; no successful native proof is mocked.
"""
import base64
from copy import deepcopy
from dataclasses import replace
import sys
from unittest.mock import patch

import pytest

from phase_tool import installation
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.experimental_history_set import (
    _mixed_history_contexts, mixed_history_buffers, validate_mixed_history_bindings)
from phase_tool.mutation.ntfs.bootstrap import _accepted_launch_history
from .test_native_experiment_file1 import experiment_fixture


def bindings_fixture(directory=None, *, repeated=False):
    cap, _, shell, _ = experiment_fixture()
    factories = (installation._native_experimental_file1_registry,
        installation._native_experimental_file2_registry,
        installation._native_experimental_version1_registry,
        installation._native_experimental_version2_registry,
        installation._native_experimental_bundle1_registry,
        installation._native_experimental_bundle2_registry_v3)
    contexts = _mixed_history_contexts()
    if repeated:
        contexts = (contexts[1], contexts[1])
        factories = (factories[1], factories[1])
    rows = []
    for index, (kind, factory) in enumerate(zip(contexts, factories, strict=True)):
        registry = factory()
        doc = cap.document()
        doc.update(contract=deepcopy(kind._contract), run_id='mixed-'+str(index), request_id='mixed-'+str(index))
        manifest = deepcopy(shell)
        contract = registry.resolve_contract(kind._contract['id'], kind._contract['version'],
            kind._contract['package_digest'], core_version=manifest['core']['version'])
        binding = contract.document['canonical_result']['root_binding']
        doc['root_grant']['root_binding'] = binding
        projections = {binding: '/ntfs-result'}
        if kind._manifest_version == '1.5':
            current = doc.pop('root_grant')
            objects = deepcopy(current)
            objects['root_binding'] = 'objects_root'
            objects['components'][-1] = 'objects'
            objects['native_identity']['file_id'] = 'f'*32
            windows = doc.pop('windows_root')
            doc.update(experimental_admission_version='1.1',
                content_digest=doc.pop('payload_digest'), content_length=doc.pop('payload_length'),
                root_grants=[current, objects], windows_roots={'current_root': windows,
                    'objects_root': windows[:-7]+'objects'})
            projections['objects_root'] = '/ntfs-objects'
        if directory is not None:
            evidence = directory/'evidence'
            preparation = directory/'preparation'
            for path in (evidence, preparation): path.mkdir(mode=0o700, exist_ok=True)
            doc['evidence_identity'] = {'stable_id': 'mixed.evidence', 'device': evidence.stat().st_dev, 'inode': evidence.stat().st_ino}
            doc['preparation_identity'] = {'stable_id': 'mixed.preparation', 'device': preparation.stat().st_dev, 'inode': preparation.stat().st_ino}
            manifest.update(evidence_root=str(evidence), preparation_root=str(preparation))
        admission = kind(canonical_bytes(doc))
        profile = registry.guarantee_profile_bindings()[kind._profile]
        implementation = registry.resolve_guarantee_profile(profile)['implementation']
        manifest.update(native_read_installation_version=kind._manifest_version,
            installation_id=kind._installation_prefix+admission.digest[7:],
            contract=deepcopy(kind._contract), registry_snapshot_digest=registry.digest,
            evidence_identity=doc['evidence_identity'], preparation_identity=doc['preparation_identity'],
            root_grants=doc['root_grants'] if kind._manifest_version == '1.5' else [doc['root_grant']],
            root_projections=projections,
            mechanism={k: contract.document['operation']['mechanism'][k] for k in ('id', 'version', 'package_digest')},
            authority={'usage': 'provider_backed', 'profile': profile,
                'provider': {k: implementation[k] for k in ('id', 'version', 'artifact_digest')}})
        raw = canonical_bytes(manifest)
        rows.append(installation._native_experimental_read_binding(manifest_bytes=raw,
            expected_manifest_digest=digest_bytes(raw), admission=admission))
    return tuple(rows)


def set_bytes(bindings):
    return canonical_bytes({'history_manifest_set_version': '1.3', 'manifests': [
        {'manifest_base64': base64.b64encode(row.manifest_bytes).decode('ascii'),
            'manifest_digest': row.manifest_digest,
            'experimental_admission_base64': base64.b64encode(row.experimental_admission.raw).decode('ascii'),
            'experimental_admission_digest': digest_bytes(row.experimental_admission.raw)}
        for row in bindings]})


def altered(row, *, manifest=None, admission=None):
    leaf = parse_json_bytes(row.manifest_bytes) if manifest is None else manifest
    cap = row.experimental_admission
    if admission is not None:
        cap = type(cap)(canonical_bytes(admission))
        leaf['installation_id'] = type(cap)._installation_prefix+cap.digest[7:]
        leaf['evidence_identity'] = admission['evidence_identity']
        leaf['preparation_identity'] = admission['preparation_identity']
        leaf['root_grants'] = admission['root_grants'] if type(cap)._manifest_version == '1.5' else [admission['root_grant']]
    raw = canonical_bytes(leaf)
    return replace(row, manifest_bytes=raw, manifest_digest=digest_bytes(raw), experimental_admission=cap)


@pytest.mark.parametrize('index', range(6))
def test_six_existing_exact_readers_resolve_each_active_without_qualifying_profile(index):
    rows = bindings_fixture()
    raw = set_bytes(rows)
    history = installation._resolve_native_history_bindings(rows[index], raw, digest_bytes(raw))
    assert [row.registry.digest for row in history] == [row.registry.digest for row in rows]
    assert validate_mixed_history_bindings(rows[index], history) is history
    for row in history:
        run = row.experimental_admission.document()['run_id']
        assert installation._native_experimental_history_binding_for_run(history, run).manifest_digest == row.manifest_digest
        with pytest.raises(PhaseError, match='ntfs.native_profile_not_qualified'):
            installation._native_qualified_profile(row.registry, row.experimental_admission.profile(row).as_dict())


def test_explicit_repeated_contract_runs_are_read_expectations_with_distinct_identities():
    rows = bindings_fixture(repeated=True)
    raw = set_bytes(rows)
    history = installation._resolve_native_history_bindings(rows[0], raw, digest_bytes(raw))
    assert len(history) == 2
    assert history[0].registry.digest == history[1].registry.digest
    assert history[0].manifest_digest != history[1].manifest_digest
    with pytest.raises(PhaseError, match='ntfs.original_history_binding_mismatch'):
        installation._native_experimental_history_binding_for_run(history, 'foreign-run')


@pytest.mark.parametrize('damage', ['extra-field', 'wrong-version', 'bad-digest', 'bad-base64',
    'noncanonical', 'duplicate', 'missing-active', 'oversize'])
def test_set_shape_digest_canonical_identity_and_active_member_are_closed(damage):
    rows = bindings_fixture()
    value = parse_json_bytes(set_bytes(rows))
    if damage == 'extra-field': value['route'] = 'arbitrary'
    elif damage == 'wrong-version': value['history_manifest_set_version'] = '1.2'
    elif damage == 'bad-digest': value['manifests'][1]['manifest_digest'] = 'sha256:'+'0'*64
    elif damage == 'bad-base64': value['manifests'][1]['manifest_base64'] = '!!'
    elif damage == 'duplicate': value['manifests'].append(deepcopy(value['manifests'][0]))
    elif damage == 'missing-active': value['manifests'].pop(0)
    raw = canonical_bytes(value)
    if damage == 'noncanonical': raw += b'\n'
    if damage == 'oversize': raw = b' '*(2*1024**2+1)
    with pytest.raises((PhaseError, ValueError)):
        mixed_history_buffers(raw, digest_bytes(raw), active_bytes=rows[0].manifest_bytes, active_digest=rows[0].manifest_digest)


@pytest.mark.parametrize('damage', ['wheel', 'composition', 'preparation', 'evidence', 'grant-identity',
    'grant-path', 'projection', 'objects-identity', 'objects-overlap'])
def test_common_domain_rejects_self_consistent_foreign_leaf(damage):
    rows = list(bindings_fixture())
    index = 3 if damage.startswith('objects') else 1
    row = rows[index]
    doc = row.experimental_admission.document()
    leaf = parse_json_bytes(row.manifest_bytes)
    if damage == 'wheel': doc['wheel_digest'] = 'sha256:'+'e'*64
    elif damage == 'composition': leaf['composition']['artifact_graph_digest'] = 'sha256:'+'e'*64
    elif damage == 'preparation': doc['preparation_identity']['inode'] += 1
    elif damage == 'evidence': doc['evidence_identity']['inode'] += 100
    elif damage == 'grant-identity': doc['root_grant']['native_identity']['file_id'] = 'e'*32
    elif damage == 'grant-path':
        doc['root_grant']['components'][1] = '22222222-2222-4222-8222-222222222222'
        doc['windows_root'] = doc['windows_root'].replace('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')
    elif damage == 'projection': leaf['root_projections']['phase_result_root'] = '/other-result'
    elif damage == 'objects-overlap': leaf['root_projections']['objects_root'] = '/ntfs-result/objects'
    else:
        # A second Version2 expectation must retain exactly the same objects domain.
        other_doc = deepcopy(doc)
        other_doc.update(run_id='mixed-other-version2', request_id='mixed-other-version2')
        other_doc['root_grants'][1]['native_identity']['file_id'] = 'e'*32
        rows.append(altered(row, admission=other_doc))
    rows[index] = altered(row, manifest=leaf, admission=doc)
    with pytest.raises(PhaseError, match='ntfs.original_history_domain_mismatch'):
        validate_mixed_history_bindings(rows[0], tuple(rows))


def test_config13_carries_only_explicit_installed_companions_and_keeps_legacy_parser_closed():
    rows = bindings_fixture()
    raw = set_bytes(rows)
    config = {key: None for key in ('phase_wheel', 'phase_wheel_digest', 'dependency_file_digests',
        'windows_launcher', 'linux_launcher', 'docker_executable', 'core_container_id',
        'reader_container_id', 'image_digest', 'linux_python', 'expected_linux_contours', 'artifact_graph')}
    config.update(native_launch_version='1.3', history_manifest_set_base64=base64.b64encode(raw).decode('ascii'),
        history_manifest_set_digest=digest_bytes(raw))
    assert _accepted_launch_history(config, rows[0].manifest_bytes, rows[0].manifest_digest) == (raw, digest_bytes(raw))
    for version in ('1.1', '1.2'):
        with pytest.raises(PhaseError):
            _accepted_launch_history(config | {'native_launch_version': version}, rows[0].manifest_bytes, rows[0].manifest_digest)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='actual ext4/Linux history lock required')
def test_foreign_unresolved_run_blocks_every_role_under_one_existing_lock(tmp_path):
    from phase_tool import core
    if installation._linux_filesystem_type(tmp_path) != 'ext4':
        pytest.skip('native MIX history must be tested on actual ext4')
    rows = bindings_fixture(tmp_path)
    evidence = tmp_path/'evidence'
    runs = evidence/'.phase'/'runs'
    locks = evidence/'.phase'/'locks'
    runs.mkdir(parents=True, mode=0o700)
    locks.mkdir(mode=0o700)
    (runs/'foreign-unresolved').mkdir(mode=0o700)
    raw = set_bytes(rows)
    lock_identity = None
    for row in rows:
        history = installation._resolve_native_history_bindings(row, raw, digest_bytes(raw))
        with pytest.raises(PhaseError, match='ntfs.original_history_unresolved'):
            with core._guard_native_original_intents(row, history_bindings=history):
                pytest.fail('foreign original was filtered')
        lock = next(locks.iterdir()).stat()
        actual = lock.st_dev, lock.st_ino
        if lock_identity is None: lock_identity = actual
        assert actual == lock_identity
    assert list((runs/'foreign-unresolved').iterdir()) == []


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='closed authority factories require Linux')
def test_factory_checks_every_companion_before_channel_creation():
    from phase_tool.mutation.ntfs.channel_v2 import LinuxNativeChannelV2
    rows = list(bindings_fixture())
    doc = rows[1].experimental_admission.document()
    doc['wheel_digest'] = 'sha256:'+'e'*64
    rows[1] = altered(rows[1], admission=doc)
    raw = set_bytes(rows)
    active = rows[0]
    with patch.object(LinuxNativeChannelV2, '__init__', side_effect=AssertionError('channel reached')) as channel:
        with pytest.raises(PhaseError, match='ntfs.original_history_domain_mismatch'):
            installation._native_installation_for_manifest(manifest_bytes=active.manifest_bytes,
                expected_manifest_digest=active.manifest_digest,
                run_id=active.experimental_admission.document()['run_id'],
                operation_nonce='a'*32, channel_id='b'*32,
                history_manifest_set_bytes=raw, history_manifest_set_digest=digest_bytes(raw),
                _experimental_admission_context=active.experimental_admission)
        channel.assert_not_called()


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='closed recovery authority requires Linux')
def test_standard_recovery_core_keeps_exact_installed_companions_before_any_channel_or_dispatch():
    from unittest.mock import Mock
    from phase_tool.application import PhaseApplication
    from phase_tool.mutation.ntfs import bundle_recovery_entrypoint, entrypoint
    from phase_tool.mutation.ntfs.bundle_recovery_channel import LinuxNativeBundleRecoveryChannel
    rows = list(bindings_fixture())
    doc = rows[1].experimental_admission.document()
    doc['wheel_digest'] = 'sha256:'+'e'*64
    rows[1] = altered(rows[1], admission=doc)
    active = rows[5]
    raw = set_bytes(rows)
    request = {'operation': 'recover_publication', 'native_bundle_recovery_request_version': '1.0',
        'request_id': active.experimental_admission.document()['request_id'],
        'expected_intent_digest': 'sha256:'+'a'*64, 'mode': 'observe'}
    # Exact-class metadata fixture; runtime/stdio are explicitly modeled.
    # No accepted installation is claimed. The ordinary helper's exact-type
    # guard must pass before the original complete-history refusal is reached.
    from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
    launch = object.__new__(_NativeAcceptedLaunch)
    launch._config_bytes = canonical_bytes({'native_launch_version': '1.3'})
    launch._manifest_bytes, launch._manifest_digest = active.manifest_bytes, active.manifest_digest
    launch._invocation_bytes = canonical_bytes({'request': request,
        'run_id': active.experimental_admission.document()['run_id'],
        'operation_nonce': 'b'*32, 'channel_id': 'c'*32})
    launch._history_manifest_set = (raw, digest_bytes(raw))
    launch._experimental_admission_context = active.experimental_admission
    launch._owner_directory_context = None
    launch._inspection_only = False
    launch.check_runtime = Mock()
    with (patch.object(entrypoint, '_linux_stdio_identity', return_value='framing-only-model'),
            patch.object(entrypoint, '_deliver_linux_frame') as delivery,
            patch.object(installation, '_native_installation_for_manifest', wraps=installation._native_installation_for_manifest) as factory,
            patch.object(LinuxNativeBundleRecoveryChannel, '__init__', side_effect=AssertionError('channel reached')) as channel,
            patch.object(PhaseApplication, 'recover_publication', side_effect=AssertionError('recovery dispatched')) as recovery):
        with pytest.raises(PhaseError, match='ntfs.original_history_domain_mismatch'):
            bundle_recovery_entrypoint.run_recovery_core(launch)
        assert factory.call_args.kwargs['history_manifest_set_bytes'] is raw
        assert factory.call_args.kwargs['history_manifest_set_digest'] == digest_bytes(raw)
        channel.assert_not_called()
        recovery.assert_not_called()
        delivery.assert_not_called()
