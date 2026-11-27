"""C03 facade integration: real Linux Core; synthetic exact policy packages only."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys

import pytest

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run
from phase_tool.planning.request_identity import SEMANTIC_REQUEST_POLICY
from phase_tool.publish_file import (_require_reused_file_reference, _semantic_replay_enabled,
                                     PublishFileResult)
from phase_tool.registry import BundledRegistry
from tests.c03_policy_fixtures import component_installation, policy_registry

LINUX=pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Actual Linux/ext4 Host/Core publication boundary')


def case(tmp_path, version='1.0', policy=SEMANTIC_REQUEST_POLICY):
    base=BundledRegistry.load()
    name='file_create.v2@1.0.0' if version=='2.0' else 'file_create.v1@1.0.0'
    if policy=='digest.canonical_request_v1':
        registry=base
    else:
        registry,_=policy_registry(policy,original=base,binding=base.contract_bindings()[name])
    app=PhaseApplication(registry,component_installation())
    roots={name:tmp_path/name for name in ('source','target','preparation','evidence')}
    for root in roots.values():root.mkdir()
    (roots['source']/'ready.bin').write_bytes(bytes(range(256))+b'\x00semantic replay\n')
    (roots['target']/'canary.bin').write_bytes(b'unchanged')
    args=dict(source_root=roots['source'],source_locator='ready.bin',target_root=roots['target'],
        target_locator='published.bin',preparation_root=roots['preparation'],evidence_root=roots['evidence'],
        request_id='stable-business-request',run_id='first',publication_version=version)
    return app,args,roots


def test_semantic_gate_uses_the_exact_package_not_current_registry_default():
    base=BundledRegistry.load();legacy=base.contract_bindings()['file_create.v1@1.0.0']
    registry,semantic=policy_registry(SEMANTIC_REQUEST_POLICY,original=base,binding=legacy)
    app=PhaseApplication(registry,component_installation())
    assert _semantic_replay_enabled(app,semantic) is True
    assert _semantic_replay_enabled(app,legacy) is False
    unknown,exact=policy_registry('digest.unknown_future_v8',original=base,binding=legacy)
    assert _semantic_replay_enabled(PhaseApplication(unknown,component_installation()),exact) is False


@pytest.mark.parametrize('damage',['contract','root','locator','digest','length','extra-state'])
def test_reused_projection_cannot_adopt_a_different_result(damage):
    binding={'id':'file_create.v1','version':'1.0.0','package_digest':'sha256:'+'a'*64}
    digest='sha256:'+'b'*64
    reference={'contract':binding,'root_binding':'phase_result_root','locator':'published.bin',
        'state':{'exists':True,'digest':digest,'length':4,'head_token':None}}
    _require_reused_file_reference(reference,binding=binding,target_locator='published.bin',content_digest=digest,content_length=4)
    bad=deepcopy(reference)
    if damage=='contract':bad['contract']['package_digest']='sha256:'+'c'*64
    elif damage=='root':bad['root_binding']='foreign_root'
    elif damage=='locator':bad['locator']='other.bin'
    elif damage=='digest':bad['state']['digest']='sha256:'+'c'*64
    elif damage=='length':bad['state']['length']=5
    else:bad['state']['unreviewed']=True
    with pytest.raises(PhaseError,match='publish_file.evidence_mismatch'):
        _require_reused_file_reference(bad,binding=binding,target_locator='published.bin',content_digest=digest,content_length=4)


@LINUX
@pytest.mark.parametrize('version',['1.0','2.0'])
def test_fresh_run_reuses_real_core_receipt_and_freshly_inspects_without_new_intent(tmp_path,version):
    app,args,roots=case(tmp_path,version)
    first=app.publish_file(**args).payload
    assert first['status']=='verified',first
    target=roots['target']/'published.bin';identity=target.stat().st_ino;body=target.read_bytes()
    # New application/Core instance; no in-memory response cache or fixed clocks.
    cold=PhaseApplication(app.registry,component_installation())
    second=cold.publish_file(**dict(args,run_id='second')).payload
    PublishFileResult.model_validate(second)
    assert second['status']=='verified' and second['execution_disposition']=='reused_existing',second
    assert second['mutation_attempted']is False and second['target_verified']is True
    assert second['intent_digest']is None and second['effect_plan_digest']is None
    assert second['content_digest']==first['content_digest'] and second['content_length']==len(body)
    run=roots['evidence']/'.phase/runs/second'
    assert not(run/'intent.json').exists() and not(run/'attachments/effect-plan.json').exists()
    receipt=parse_json_bytes((run/'receipt.json').read_bytes())
    assert receipt['prior_verified_receipt_digest']==first['receipt_digest']
    observed=inspect_run(roots['evidence'],'second',app.registry,root_bindings={'phase_result_root':roots['target']})
    assert observed['target_verified']is True and observed['receipt_digest']==second['receipt_digest']
    assert target.stat().st_ino==identity and target.read_bytes()==body
    assert (roots['target']/'canary.bin').read_bytes()==b'unchanged'
    assert list(roots['preparation'].iterdir())==[]


@LINUX
def test_known_run_remains_truthful_inspection_required_without_a_second_attempt(tmp_path):
    app,args,roots=case(tmp_path)
    first=app.publish_file(**args).payload;assert first['success'],first
    receipt=roots['evidence']/'.phase/runs/first/receipt.json';before=receipt.read_bytes()
    target=roots['target']/'published.bin';identity=target.stat().st_ino
    repeated=app.publish_file(**args).payload
    assert repeated['error']=='evidence.run_exists' and repeated['status']=='indeterminate'
    assert repeated['mutation_attempted']is None and repeated['inspection_required']is True
    assert receipt.read_bytes()==before and target.stat().st_ino==identity
    assert app.inspect(evidence_root=roots['evidence'],run_id='first',
        root_bindings={'phase_result_root':roots['target']}).payload['target_verified']is True


@LINUX
@pytest.mark.parametrize('change',['source-bytes','candidate-operation-id','expected-digest'])
def test_changed_business_request_never_adopts_existing_target(tmp_path,monkeypatch,change):
    app,args,roots=case(tmp_path)
    first=app.publish_file(**args).payload;assert first['success'],first
    target=roots['target']/'published.bin';before=(target.stat().st_ino,target.read_bytes())
    new=dict(args,run_id='changed')
    if change=='source-bytes':(roots['source']/'ready.bin').write_bytes(b'changed')
    elif change=='candidate-operation-id':
        import phase_tool.publish_file as publication
        real=publication._file_publication_candidate
        def changed_candidate(request_id,target_locator):
            candidate,_=real(request_id,target_locator)
            candidate['operation_id']='changed-operation-with-same-key'
            return candidate,canonical_bytes(candidate)
        monkeypatch.setattr(publication,'_file_publication_candidate',changed_candidate)
    else:new['expected_digest']=digest_bytes(b'not the captured input')
    response=app.publish_file(**new).payload
    assert not response['success'] and response['mutation_attempted']is False,response
    expected='publish_file.source_digest_mismatch' if change=='expected-digest' else 'idempotency.same_key_conflict'
    assert response['error']==expected,response
    assert (target.stat().st_ino,target.read_bytes())==before and not(roots['target']/'other.bin').exists()


@LINUX
def test_caller_requested_different_locator_is_truthful_new_scope_publication(tmp_path):
    app,args,roots=case(tmp_path)
    first=app.publish_file(**args).payload;assert first['success'],first
    original=roots['target']/'published.bin';before=(original.stat().st_ino,original.read_bytes())
    # The existing contract scope explicitly contains result_locator. The same
    # business key at another requested locator is a distinct, legitimate scope.
    second=app.publish_file(**dict(args,run_id='other-scope',target_locator='other.bin')).payload
    assert second['status']=='verified' and second['execution_disposition']=='executed',second
    assert second['mutation_attempted']is True and second['intent_digest'] and second['effect_plan_digest']
    other=roots['target']/'other.bin'
    assert other.read_bytes()==before[1] and other.stat().st_ino!=before[0]
    assert (original.stat().st_ino,original.read_bytes())==before
    runs=roots['evidence']/'.phase/runs'
    first_intent=parse_json_bytes((runs/'first/intent.json').read_bytes())
    second_intent=parse_json_bytes((runs/'other-scope/intent.json').read_bytes())
    assert first_intent['idempotency']['key']==second_intent['idempotency']['key']==args['request_id']
    assert first_intent['idempotency']['scope_digest']!=second_intent['idempotency']['scope_digest']
    receipt=parse_json_bytes((runs/'other-scope/receipt.json').read_bytes())
    assert receipt['prior_verified_receipt_digest']is None
    for run in ('first','other-scope'):
        assert inspect_run(roots['evidence'],run,app.registry,
            root_bindings={'phase_result_root':roots['target']})['target_verified']is True


@LINUX
@pytest.mark.parametrize('field,value',[('revalidation_token','sha256:'+'d'*64),
                                      ('manifest_digest','sha256:'+'e'*64),
                                      ('strategy','value_snapshot')])
def test_actual_core_compares_non_time_semantic_input_fields_not_only_bytes(tmp_path,monkeypatch,field,value):
    import phase_tool.core as core
    app,args,roots=case(tmp_path)
    first=app.publish_file(**args).payload;assert first['success'],first
    real=core.freeze_declared_inputs;calls=[]
    def changed(*a,**kw):
        frozen=real(*a,**kw);calls.append(True)
        return {key:replace(item,**{field:value})for key,item in frozen.items()}
    monkeypatch.setattr(core,'freeze_declared_inputs',changed)
    target=roots['target']/'published.bin';before=(target.stat().st_ino,target.read_bytes())
    response=app.publish_file(**dict(args,run_id='changed-field')).payload
    assert calls and response['error']=='idempotency.same_key_conflict',response
    assert response['mutation_attempted']is False and not response['success']
    assert (target.stat().st_ino,target.read_bytes())==before


@LINUX
@pytest.mark.parametrize('mode',['unmanaged','other-root','tampered','missing-receipt'])
def test_existing_target_or_unverified_history_is_never_adopted(tmp_path,mode):
    app,args,roots=case(tmp_path)
    target=roots['target']/'published.bin'
    if mode=='unmanaged':target.write_bytes((roots['source']/'ready.bin').read_bytes())
    else:
        first=app.publish_file(**args).payload;assert first['success'],first
        if mode=='tampered':target.write_bytes(b'foreign result')
        elif mode=='missing-receipt':(roots['evidence']/'.phase/runs/first/receipt.json').unlink()
        else:
            other=tmp_path/'other-target';other.mkdir();target=other/'published.bin'
            target.write_bytes((roots['source']/'ready.bin').read_bytes());args=dict(args,target_root=other)
    before=(target.stat().st_ino,target.read_bytes())
    result=app.publish_file(**dict(args,run_id='blocked')).payload
    assert not result['success'] and result['mutation_attempted']is False,result
    assert (target.stat().st_ino,target.read_bytes())==before


@LINUX
def test_unknown_original_dispatch_is_not_a_new_key_or_target_adoption_path(tmp_path,monkeypatch):
    from phase_tool.mutation.broker import BrokerExecutionInterrupted,EffectBroker
    app,args,roots=case(tmp_path);real=EffectBroker.execute
    def lost_response(broker,*a,**kw):
        real(broker,*a,**kw)
        raise BrokerExecutionInterrupted(PhaseError('transport.component_response_lost'),[],None,possible_dispatch=True)
    with monkeypatch.context()as patch:
        patch.setattr(EffectBroker,'execute',lost_response)
        first=app.publish_file(**args).payload
    assert first['status']=='indeterminate' and first['mutation_attempted']is True,first
    target=roots['target']/'published.bin';before=(target.stat().st_ino,target.read_bytes())
    second=app.publish_file(**dict(args,run_id='after-unknown')).payload
    assert second['error']=='idempotency.prior_inspection_required' and second['mutation_attempted']is False,second
    assert not second['success'] and (target.stat().st_ino,target.read_bytes())==before


@LINUX
def test_legacy_exact_policy_keeps_fast_existing_target_refusal(tmp_path):
    app,args,roots=case(tmp_path,policy='digest.canonical_request_v1')
    first=app.publish_file(**args).payload;assert first['success'],first
    result=app.publish_file(**dict(args,run_id='legacy-second')).payload
    assert result['error']=='publish_file.target_exists_inspection_required'
    assert result['mutation_attempted']is False and not(roots['evidence']/'.phase/runs/legacy-second').exists()


@LINUX
def test_bundle_core_receipt_only_reuse_verifies_original_owner_after_fix(tmp_path):
    from phase_tool.core import PhaseCore
    from tests.c03_policy_fixtures import bundle_case
    registry,_=policy_registry(SEMANTIC_REQUEST_POLICY)
    request,source,target,evidence=bundle_case(tmp_path,registry)
    first=PhaseCore(registry,component_installation()).run(request('bundle-first'),execute=True)
    assert first.exit_code==0,first.receipt
    second=PhaseCore(registry,component_installation()).run(request('bundle-second'),execute=True)
    assert second.exit_code==0 and second.receipt['execution_disposition']=='reused_existing',second.receipt
    assert second.intent is None and second.effect_plan is None
    # The inspector verifies the original executed owner/plan first, while
    # preserving the CURRENT receipt-only run and its exact canonical reference.
    inspected=inspect_run(evidence,'bundle-second',registry,root_bindings={'phase_result_root':target})
    assert inspected['target_verified']is True
    assert inspected['receipt_digest']==second.receipt_digest
    assert inspected['intent_present']is False
