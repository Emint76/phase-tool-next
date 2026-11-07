"""C03 identity through real Core capture; exact synthetic test packages only.

Windows coverage preserves the genuine Core unsupported-platform boundary.
Linux-only tests perform real Host effects/replay/inspect. Neither is native
NTFS qualification or ordinary directory admission; no clock is patched.
"""
from copy import deepcopy
from dataclasses import replace
import sys

import pytest

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, parse_json_bytes, profile_digest
from phase_tool.core import PhaseCore
from phase_tool.errors import PhaseError
from phase_tool.freeze import FrozenInput
from phase_tool.inspection import inspect_run
from phase_tool.planning.request_identity import (
    LEGACY_REQUEST_POLICIES, SEMANTIC_REQUEST_POLICY, request_identity_digest,
)
from phase_tool.registry import BundledRegistry
from .c03_policy_fixtures import bundle_case, component_installation, file_case, policy_registry


def input_record():
    return FrozenInput('payload', 'copy_and_hash', 'sha256:'+'a'*64, 7,
                       '2026-11-07T00:00:00Z', blob_digest='sha256:'+'a'*64).intent_record()


def formula(policy, records):
    return request_identity_digest(policy=policy, scope={'contract': 'test-exact-package'},
                                   candidate_digest='sha256:'+'b'*64, input_records=records)


@pytest.mark.parametrize('policy', sorted(LEGACY_REQUEST_POLICIES))
def test_legacy_policy_retains_full_record_and_historical_request_domain(policy):
    records = [input_record()]
    original = deepcopy(records)
    expected = profile_digest('request', {
        'scope': {'contract': 'test-exact-package'},
        'candidate_digest': 'sha256:'+'b'*64, 'inputs': records,
    })
    assert formula(policy, records) == expected
    later = deepcopy(records); later[0]['frozen_at'] = '2026-11-07T00:00:01Z'
    assert formula(policy, later) != expected
    extended = deepcopy(records); extended[0]['extra_observation'] = 'retained'
    assert formula(policy, extended) != expected
    assert records == original


def test_all_bundled_contract_resources_keep_exact_legacy_policy_ids():
    policies = set()
    for name, raw in BundledRegistry.resources().items():
        if name.startswith(('contracts/', 'history/contracts/')) and name.endswith('.json'):
            value = parse_json_bytes(raw)
            if type(value) is dict and 'phase_contract_version' in value:
                policies.add(value['idempotency']['request_digest_policy_id'])
    assert policies == LEGACY_REQUEST_POLICIES == {
        'digest.canonical_request_v1', 'digest.admission_canonical_request_v1'}


def test_semantic_policy_omits_only_frozen_at_without_mutating_original_record():
    original = [input_record()]
    later = deepcopy(original); later[0]['frozen_at'] = '2026-11-07T00:00:01Z'
    assert formula(SEMANTIC_REQUEST_POLICY, original) == formula(SEMANTIC_REQUEST_POLICY, later)
    assert original == [input_record()]
    assert formula(SEMANTIC_REQUEST_POLICY, original) != formula('digest.canonical_request_v1', original)
    assert formula(SEMANTIC_REQUEST_POLICY, []) != formula('digest.canonical_request_v1', [])


@pytest.mark.parametrize('field', [
    'binding_id', 'freeze_strategy', 'digest', 'manifest_digest',
    'blob_digest', 'provenance_ref', 'revalidation_token',
])
def test_every_non_time_input_field_remains_in_semantic_identity(field):
    original = [input_record()]
    changed = deepcopy(original); changed[0][field] = 'different-observation'
    assert formula(SEMANTIC_REQUEST_POLICY, original) != formula(SEMANTIC_REQUEST_POLICY, changed)


@pytest.mark.parametrize('policy', [None, 0, '', 'digest.semantic_request_v3',
                                    'digest.canonical_request_v1 ', 'digest.admission_unknown_v1'])
def test_unknown_policy_never_falls_back_to_legacy(policy):
    with pytest.raises(PhaseError, match='plan.request_digest_policy_unsupported'):
        formula(policy, [input_record()])


@pytest.mark.parametrize('damage', ['missing', 'extra', 'tuple'])
def test_semantic_projection_requires_exact_known_input_shape(damage):
    records = [input_record()]
    if damage == 'missing':
        del records[0]['provenance_ref']
    elif damage == 'extra':
        records[0]['future_field'] = None
    else:
        records = tuple(records)
    with pytest.raises(PhaseError, match='plan.request_input_fields_unsupported'):
        formula(SEMANTIC_REQUEST_POLICY, records)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Real Host/Core preparation boundary requires Linux')
def test_real_core_natural_recapture_keeps_semantic_request_but_full_intents_differ(tmp_path):
    registry, _ = policy_registry(SEMANTIC_REQUEST_POLICY)
    request, source, target, evidence = bundle_case(tmp_path, registry)
    first = PhaseCore(registry, component_installation()).run(request('semantic-one'))
    second = PhaseCore(registry, component_installation()).run(request('semantic-two'))
    assert first.exit_code == second.exit_code == 0
    assert first.receipt['terminal_status'] == second.receipt['terminal_status'] == 'validated_planned'
    assert first.intent['created_at'] != second.intent['created_at']
    assert first.intent['inputs'][0]['frozen_at'] != second.intent['inputs'][0]['frozen_at']
    assert first.intent['idempotency']['request_digest'] == second.intent['idempotency']['request_digest']
    assert profile_digest('intent', first.intent) != profile_digest('intent', second.intent)
    for outcome in (first, second):
        saved = parse_json_bytes((evidence/'.phase/runs'/outcome.run_id/'intent.json').read_bytes())
        assert saved['inputs'] == outcome.intent['inputs']
        assert set(saved['inputs'][0]) == set(input_record())
        assert outcome.receipt['mutation_attempted'] is False
    assert not list(target.iterdir())


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Real Host/Core preparation boundary requires Linux')
def test_real_core_legacy_natural_recapture_preserves_original_conflict(tmp_path):
    registry = BundledRegistry.load()
    request, _, target, _ = bundle_case(tmp_path, registry)
    first = PhaseCore(registry, component_installation()).run(request('legacy-one'))
    second = PhaseCore(registry, component_installation()).run(request('legacy-two'))
    assert first.exit_code == 0
    assert second.exit_code == 10
    assert 'idempotency.same_key_conflict' in second.receipt['blockers']
    assert second.receipt['mutation_attempted'] is False
    assert not list(target.iterdir())


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Real Host/Core preparation boundary requires Linux')
def test_real_core_semantic_changed_bytes_conflict_before_target_mutation(tmp_path):
    registry, _ = policy_registry(SEMANTIC_REQUEST_POLICY)
    request, source, target, _ = bundle_case(tmp_path, registry)
    first = PhaseCore(registry, component_installation()).run(request('changed-one'))
    assert first.exit_code == 0
    (source/'member.bin').write_bytes(b'changed captured bytes under SAME key\n')
    second = PhaseCore(registry, component_installation()).run(request('changed-two'))
    assert second.exit_code == 10
    assert 'idempotency.same_key_conflict' in second.receipt['blockers']
    assert second.receipt['mutation_attempted'] is False
    assert not list(target.iterdir())


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Real Host/Core preparation boundary requires Linux')
def test_schema_valid_but_unknown_exact_policy_resolves_then_core_refuses(tmp_path):
    registry, binding = policy_registry('digest.unreviewed_request_v9')
    assert registry.resolve_contract(binding['id'], binding['version'], binding['package_digest'],
                                    core_version=__import__('phase_tool').__version__).document[
                                        'idempotency']['request_digest_policy_id'] == 'digest.unreviewed_request_v9'
    request, _, target, evidence = bundle_case(tmp_path, registry)
    outcome = PhaseCore(registry, component_installation()).run(request('unknown-policy'))
    assert outcome.exit_code == 10
    assert 'plan.request_digest_policy_unsupported' in outcome.receipt['blockers']
    assert outcome.intent is None and outcome.effect_plan is None
    assert outcome.receipt['mutation_attempted'] is False and not list(target.iterdir())
    assert not (evidence/'.phase/runs/unknown-policy/intent.json').exists()


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Real Host target mutation and fresh inspect require Linux')
def test_real_host_effect_then_cold_core_semantic_replay_and_changed_input_conflict(tmp_path):
    base = BundledRegistry.load()
    registry, _ = policy_registry(SEMANTIC_REQUEST_POLICY, original=base,
                                  binding=base.contract_bindings()['file_create.v1@1.0.0'])
    request, payload, target, evidence = file_case(tmp_path, registry)
    first = PhaseCore(registry, component_installation()).run(request('host-one'), execute=True)
    assert first.exit_code == 0, first.receipt
    saved_first = parse_json_bytes((evidence/'.phase/runs/host-one/receipt.json').read_bytes())
    original_id = (target/'published.bin').stat().st_ino
    second = PhaseCore(registry, component_installation()).run(request('host-two'), execute=True)
    assert second.exit_code == 0, second.receipt
    assert second.receipt['execution_disposition'] == 'reused_existing'
    assert second.receipt['mutation_attempted'] is False
    assert second.receipt['prior_verified_receipt_digest'] == profile_digest('receipt', saved_first)
    assert (target/'published.bin').stat().st_ino == original_id
    assert (target/'published.bin').read_bytes() == payload.read_bytes()
    inspected = inspect_run(evidence, 'host-two', registry, root_bindings={'phase_result_root': target})
    assert inspected['target_verified'] is True
    payload.write_bytes(b'different under the same key')
    third = PhaseCore(registry, component_installation()).run(request('host-three'), execute=True)
    assert third.exit_code == 10 and 'idempotency.same_key_conflict' in third.receipt['blockers']
    assert third.receipt['mutation_attempted'] is False
    assert (target/'published.bin').stat().st_ino == original_id


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Real existing publication and Host/Core replay require Linux')
def test_file_facade_and_core_reconcile_fresh_run_but_known_run_requires_inspection(tmp_path):
    base = BundledRegistry.load()
    registry, _ = policy_registry(SEMANTIC_REQUEST_POLICY, original=base,
                                  binding=base.contract_bindings()['file_create.v1@1.0.0'])
    request, payload, target, evidence = file_case(tmp_path, registry)
    preparation = tmp_path/'preparation'; preparation.mkdir()
    application = PhaseApplication(registry, component_installation())
    args = dict(source_root=payload.parent, source_locator=payload.name, target_root=target,
        target_locator='published.bin', preparation_root=preparation, evidence_root=evidence,
        request_id='c03-same-key', run_id='facade-one')
    first = application.publish_file(**args).payload
    assert first['status'] == 'verified', first
    same_run = application.publish_file(**args).payload
    assert same_run['error'] == 'evidence.run_exists' and same_run['status'] == 'indeterminate'
    another_run = application.publish_file(**dict(args, run_id='facade-two')).payload
    assert another_run['status'] == 'verified', another_run
    assert another_run['execution_disposition'] == 'reused_existing'
    assert another_run['mutation_attempted'] is False
    assert another_run['intent_digest'] is None and another_run['effect_plan_digest'] is None
    assert another_run['target_verified'] is True
    # The normal generic Core owns the same semantic comparison; construct
    # its candidate exactly as the high-level facade does.
    from phase_tool.publish_file import _file_publication_candidate
    _, candidate = _file_publication_candidate('c03-same-key', 'published.bin')
    path = tmp_path/'facade-exact-candidate.json'; path.write_bytes(candidate)
    generic = replace(request('core-after-facade'), candidate_path=path)
    reused = PhaseCore(registry, component_installation()).run(generic, execute=True)
    assert reused.exit_code == 0, reused.receipt
    assert reused.receipt['execution_disposition'] == 'reused_existing'
    assert reused.receipt['mutation_attempted'] is False
    assert reused.receipt['prior_verified_receipt_digest'] == first['receipt_digest']
    assert inspect_run(evidence, 'core-after-facade', registry,
                       root_bindings={'phase_result_root': target})['target_verified'] is True


@pytest.mark.skipif(sys.platform.startswith('linux'), reason='Windows Host preparation refusal boundary')
def test_windows_real_core_retains_unsupported_platform_before_policy_or_effect(tmp_path):
    registry, _ = policy_registry(SEMANTIC_REQUEST_POLICY)
    request, _, target, evidence = bundle_case(tmp_path, registry)
    outcome = PhaseCore(registry, component_installation()).run(request('windows-boundary'))
    assert outcome.exit_code == 10
    assert outcome.receipt['blockers'] == ['platform.mutation_unsupported']
    assert outcome.receipt['mutation_attempted'] is False
    assert outcome.intent is None and outcome.effect_plan is None
    assert not list(target.iterdir())
