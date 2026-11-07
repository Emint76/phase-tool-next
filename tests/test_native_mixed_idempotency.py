"""Generic Core history handoff with real static registry/intent checks.

Portable metadata components only: synthetic intents have no native proofs,
accepted launcher, authority lifecycle, worker, target observation or dispatch.
Only the already-entered Core-stage surrounding native boundaries are modeled;
the scanner, every historical registry/schema/static binding check remain real.
"""
from copy import deepcopy
from functools import lru_cache
from types import SimpleNamespace
import sys
from unittest.mock import patch

import pytest

from phase_tool import core, installation
from phase_tool.canonical import canonical_bytes, profile_digest, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.evidence import validate_intent
from phase_tool.registry import BundledRegistry
from .test_native_mixed_experimental_history import bindings_fixture
from .test_native_intent_v12 import fixture as schema_claims


@lru_cache(maxsize=1)
def history_fixture():
    return bindings_fixture()


def synthetic_static_intent(row):
    manifest=parse_json_bytes(row.manifest_bytes); admission=row.experimental_admission.document()
    intent=schema_claims(BundledRegistry.load())
    contract=row.registry.resolve_contract(manifest['contract']['id'],manifest['contract']['version'],
        manifest['contract']['package_digest'],core_version=manifest['core']['version'])
    intent.update(run_id=admission['run_id'],core=deepcopy(manifest['core']),
        contract=deepcopy(manifest['contract']),registry_snapshot_digest=row.registry.digest,
        operation={'intent':contract.document['operation']['intent'],'mechanism':deepcopy(manifest['mechanism'])})
    intent['idempotency'].update(key=admission['request_id'],root_identities=deepcopy(manifest['root_grants']),
        scope_digest=profile_digest('static-test-scope',manifest['contract']),
        request_digest=profile_digest('static-test-request',admission['request_id']))
    intent['native_binding'].update(installation={'id':manifest['installation_id'],'descriptor_digest':row.manifest_digest},
        composition=deepcopy(manifest['composition']),evidence_identity=deepcopy(manifest['evidence_identity']))
    intent['implementation_binding'].update(authority=deepcopy(manifest['authority']),mechanism=deepcopy(manifest['mechanism']))
    validate_intent(intent,row.registry)
    return intent


def materialized(tmp_path):
    rows=history_fixture(); active=rows[1]
    runs=tmp_path/'.phase/runs'; runs.mkdir(parents=True)
    intents=[]
    for row in (rows[0],rows[2],rows[3]):
        intent=synthetic_static_intent(row); intents.append(intent)
        run=runs/intent['run_id']; run.mkdir(); (run/'intent.json').write_bytes(canonical_bytes(intent))
    store=SimpleNamespace(evidence_root=tmp_path,run_root=runs/active.experimental_admission.document()['run_id'])
    # An inert exact-type object models the already-entered stage, not authority.
    authority=SimpleNamespace(read_binding=active)
    return rows,active,store,authority,intents


def check(store,active,authority,*,history,key='distinct-new-file2',scope='sha256:'+'e'*64,request='sha256:'+'f'*64):
    return core.PhaseCore._check_idempotency(store,None,active.registry,key,scope,request,{},
        execute=True,_native_authority=authority,_native_history_bindings=history)


def test_without_forwarded_history_old_path_rejects_foreign_contract_registry(tmp_path):
    rows,active,store,authority,_=materialized(tmp_path)
    with pytest.raises(PhaseError,match='idempotency.prior_inspection_required') as caught:
        check(store,active,authority,history=None)
    assert isinstance(caught.value.__cause__,PhaseError)
    assert caught.value.__cause__.code == 'registry.entry_not_found'


@pytest.mark.skipif(not sys.platform.startswith('linux'),reason='exact native authority classes import the Linux fcntl channel')
def test_generic_file2_core_stage_forwards_complete_installed_history(tmp_path):
    from phase_tool.mutation.ntfs.experimental_file2_authority import _ExperimentalFile2Authority
    rows,active,store,authority,_=materialized(tmp_path)
    authority=object.__new__(_ExperimentalFile2Authority); authority.read_binding=active
    installed=object.__new__(installation._NativeFileCreateInstallation)
    installed.read_binding=active; installed.authority=authority; installed.history_bindings=rows
    subject=core.PhaseCore(active.registry,installation=installed)
    class ReachedValidation(BaseException): pass
    class RejectedHistory(BaseException): pass
    def next_stage(*args,**kwargs): raise ReachedValidation()
    original=core.PhaseCore._check_idempotency
    seen=[]
    def observed(*args,**kwargs):
        seen.append(kwargs.get('_native_history_bindings'))
        try: return original(*args,**kwargs)
        except PhaseError as error: raise RejectedHistory(error.code) from error
    manifest=parse_json_bytes(active.manifest_bytes)
    contract=active.registry.resolve_contract(manifest['contract']['id'],manifest['contract']['version'],
        manifest['contract']['package_digest'],core_version=manifest['core']['version'])
    request=SimpleNamespace(run_id=active.experimental_admission.document()['run_id'],root_bindings={})
    with (patch.object(type(active.experimental_admission),'verify_attachment'),
            patch.object(core,'ValidatorRunner',return_value=SimpleNamespace(run=next_stage)),
            patch.object(core.PhaseCore,'_check_idempotency',side_effect=observed),
            patch.object(core,'inspect_run',side_effect=AssertionError('distinct-key history inspected as current'))):
        with pytest.raises(ReachedValidation):
            subject._run_after_idempotency_binding(request,store,contract,{},None,{},[],[],'2026-11-07T00:00:00Z',
                'sha256:'+'e'*64,'sha256:'+'f'*64,'distinct-new-file2','sha256:'+'d'*64,[],tmp_path,
                True,core.CoreFaults(),SimpleNamespace(native_authority=authority))
    assert seen == [rows]


def test_complete_history_distinct_key_does_not_require_historical_current_target(tmp_path):
    rows,active,store,authority,_=materialized(tmp_path)
    with patch.object(core,'inspect_run',side_effect=AssertionError('superseded current was inspected')):
        assert check(store,active,authority,history=rows) is None


def test_unknown_prior_run_is_not_filtered_with_complete_history(tmp_path):
    rows,active,store,authority,intents=materialized(tmp_path)
    unknown=store.evidence_root/'.phase/runs/unknown-original'; unknown.mkdir()
    intent=deepcopy(intents[0]); intent['run_id']='unknown-original'
    (unknown/'intent.json').write_bytes(canonical_bytes(intent))
    with pytest.raises(PhaseError,match='idempotency.prior_inspection_required'):
        check(store,active,authority,history=rows)


def test_same_key_foreign_historical_reader_still_requires_fresh_inspection(tmp_path):
    rows,active,store,authority,intents=materialized(tmp_path)
    prior=intents[0]['idempotency']
    with patch.object(core,'inspect_run',side_effect=AssertionError('foreign cap used for current inspection')):
        with pytest.raises(PhaseError,match='idempotency.prior_inspection_required'):
            check(store,active,authority,history=rows,key=prior['key'],scope=prior['scope_digest'],request=prior['request_digest'])
