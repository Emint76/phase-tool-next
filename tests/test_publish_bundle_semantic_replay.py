"""Bundle semantic replay through the existing Core/inspector, Linux Host only."""
from copy import deepcopy
from dataclasses import replace
import sys

import pytest
from pydantic import TypeAdapter,ValidationError

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.errors import PhaseError
from phase_tool.inspection import inspect_run
from phase_tool.planning.request_identity import SEMANTIC_REQUEST_POLICY
from phase_tool.publish_bundle import PublishBundleResult,_require_bundle_projection
from phase_tool.registry import BundledRegistry
from tests.c03_policy_fixtures import component_installation,policy_registry

LINUX=pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Actual Linux/ext4 Host/Core Bundle mutation and inspection')


def case(tmp_path,version='1.0',semantic=True):
    base=BundledRegistry.load()
    key='bundle_create.v2@1.1.0'if version=='2.0'else'bundle_create.v1@1.0.0'
    registry=policy_registry(SEMANTIC_REQUEST_POLICY,original=base,binding=base.contract_bindings()[key])[0]if semantic else base
    app=PhaseApplication(registry,component_installation())
    roots={name:tmp_path/name for name in('source','target','preparation','evidence')}
    for path in roots.values():path.mkdir()
    members=['a.bin','b/empty.bin','c/d/e.bin']
    for name,body in zip(members,(b'bundle\x00\xff',b'',b'deep bytes\n'),strict=True):
        path=roots['source']/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
    args=dict(source_root=roots['source'],members=members,target_root=roots['target'],target_locator='dataset',
        preparation_root=roots['preparation'],evidence_root=roots['evidence'],request_id='bundle-business-request',
        run_id='first',publication_version=version)
    return app,args,roots


def projection():
    binding={'id':'bundle_create.v1','version':'1.0.0','package_digest':'sha256:'+'a'*64}
    manifest={'bundle_version':'1.0','members':[{'path':'a.bin','digest':digest_bytes(b'a'),'length':1}],
              'total_length':1}
    raw=canonical_bytes(manifest);digest=digest_bytes(raw)
    reference={'contract':binding,'root_binding':'phase_result_root','locator':'dataset',
        'state':{'exists':True,'digest':digest,'length':len(raw),'head_token':None}}
    summary={'manifest':manifest,'manifest_digest':digest,'member_count':1,'total_length':1}
    return binding,reference,summary


def test_bundle_result_keeps_legacy_shape_and_versions_semantic_disposition():
    result=PublishBundleResult(request_id='request',run_id='run',evidence_root='evidence',target_locator='dataset')
    payload=result.model_dump()
    assert payload['publish_bundle_result_version']=='1.0'and'execution_disposition'not in payload
    assert 'execution_disposition'not in TypeAdapter(PublishBundleResult).dump_python(result,mode='json')
    assert 'execution_disposition'not in parse_json_bytes(result.model_dump_json().encode())
    semantic=PublishBundleResult.model_validate({**payload,'publish_bundle_result_version':'1.1',
        'execution_disposition':'reused_existing'})
    assert semantic.model_dump()['execution_disposition']=='reused_existing'
    assert semantic.model_dump()['publish_bundle_result_version']=='1.1'
    with pytest.raises(ValidationError):PublishBundleResult.model_validate({**payload,'execution_disposition':'executed'})
    with pytest.raises(ValidationError):PublishBundleResult.model_validate({**payload,'publish_bundle_result_version':'2.0'})
    assert PublishBundleResult.model_json_schema()['additionalProperties']is False


@pytest.mark.parametrize('damage',['contract','root','locator','manifest','digest','count','count-bool','total','total-bool','members','extra'])
def test_verified_projection_must_match_reference_and_exact_members(damage):
    binding,reference,summary=projection()
    manifest,digest=_require_bundle_projection(reference,summary,binding=binding,target_locator='dataset',members=['a.bin'])
    assert manifest==summary['manifest']and digest==summary['manifest_digest']
    reference=deepcopy(reference);summary=deepcopy(summary);members=['a.bin']
    if damage=='contract':reference['contract']['package_digest']='sha256:'+'c'*64
    elif damage=='root':reference['root_binding']='foreign'
    elif damage=='locator':reference['locator']='foreign'
    elif damage=='manifest':summary['manifest']['members'][0]['digest']=digest_bytes(b'changed')
    elif damage=='digest':summary['manifest_digest']=digest_bytes(b'foreign')
    elif damage=='count':summary['member_count']=2
    elif damage=='count-bool':summary['member_count']=True
    elif damage=='total':summary['total_length']=2
    elif damage=='total-bool':summary['total_length']=True
    elif damage=='members':members=['other.bin']
    else:summary['unverified_claim']=True
    with pytest.raises(PhaseError,match='bundle.evidence_mismatch'):
        _require_bundle_projection(reference,summary,binding=binding,target_locator='dataset',members=members)


@pytest.mark.parametrize('flag',[None,0,1,'true',[]])
def test_manifest_projection_rejects_non_boolean_before_evidence_io(tmp_path,flag):
    with pytest.raises(PhaseError,match='inspection.invalid_result_projection'):
        inspect_run(tmp_path/'missing','run',_include_bundle_manifest=flag)


def test_host_manifest_projection_is_not_a_native_capability(tmp_path):
    with pytest.raises(PhaseError,match='inspection.bundle_projection_unsupported'):
        inspect_run(tmp_path/'missing','run',_native_authority=object(),_include_bundle_manifest=True)


def test_application_file_pair_and_private_bundle_triple_fail_closed(tmp_path):
    app=PhaseApplication(installation=component_installation())
    pair=app._inspect_with_result(evidence_root=tmp_path/'missing',run_id='run',root_bindings={})
    assert len(pair)==2 and pair[1]is None and not pair[0].payload['success']
    triple=app._inspect_bundle_with_result(evidence_root=tmp_path/'missing',run_id='run',root_bindings={},
        _expected_candidate_digest=None)
    assert len(triple)==3 and triple[1:] == (None,None)
    assert triple[0].payload['error']=='inspection.invalid_capture_expectation'


def tree(path):
    return {p.relative_to(path).as_posix():(p.stat().st_ino,p.read_bytes())for p in path.rglob('*')if p.is_file()}


@LINUX
@pytest.mark.parametrize('version',['1.0','2.0'])
def test_bundle_publish_cold_reuse_and_verified_projection_preserve_original_owner(tmp_path,version):
    app,args,roots=case(tmp_path,version)
    first=app.publish_bundle(**args).payload
    assert first['status']=='verified'and first['execution_disposition']=='executed',first
    assert first['publish_bundle_result_version']=='1.1'and first['mutation_attempted']is True
    target=roots['target']/'dataset';before=(target.stat().st_ino,tree(target))
    cold=PhaseApplication(app.registry,component_installation())
    second=cold.publish_bundle(**dict(args,run_id='second')).payload
    assert second['status']=='verified'and second['execution_disposition']=='reused_existing',second
    assert second['mutation_attempted']is False and second['intent_digest']is second['effect_plan_digest']is None
    assert second['bundle_digest']==first['bundle_digest'] and second['member_count']==3
    assert second['total_length']==len(b'bundle\x00\xff')+len(b'deep bytes\n')
    run=roots['evidence']/'.phase/runs/second'
    assert not(run/'intent.json').exists()and not(run/'attachments/effect-plan.json').exists()
    receipt=parse_json_bytes((run/'receipt.json').read_bytes())
    assert receipt['prior_verified_receipt_digest']==first['receipt_digest']
    assert (target.stat().st_ino,tree(target))==before
    owner=parse_json_bytes((target/'phase-owner.json').read_bytes());assert owner['run_id']=='first'
    plain=inspect_run(roots['evidence'],'second',app.registry,root_bindings={'phase_result_root':roots['target']})
    assert plain['target_verified']is True and plain['receipt_digest']==second['receipt_digest']
    assert 'bundle_manifest'not in plain and'canonical_result'not in plain
    candidate={'operation_id':args['request_id'],'idempotency_key':args['request_id'],'input_binding':'payload',
        'target_locator':'dataset','members':args['members']}
    response,reference,observed=cold._inspect_bundle_with_result(evidence_root=roots['evidence'],run_id='second',
        root_bindings={'phase_result_root':roots['target']},_expected_candidate_digest=profile_digest('candidate',candidate))
    assert response.payload['target_verified']is True
    assert observed['manifest_digest']==second['bundle_digest']and observed['member_count']==3
    assert observed['total_length']==second['total_length']
    assert [r['path']for r in observed['manifest']['members']]==args['members']
    assert reference['state']['length']==len(canonical_bytes(observed['manifest']))
    assert reference==receipt['canonical_result']
    observed['manifest']['members'][0]['digest']='corrupt returned copy'
    assert inspect_run(roots['evidence'],'second',app.registry,root_bindings={'phase_result_root':roots['target']})['target_verified']is True


@LINUX
def test_bundle_known_run_and_legacy_existing_target_behaviors_are_preserved(tmp_path):
    app,args,roots=case(tmp_path,semantic=False)
    first=app.publish_bundle(**args).payload;assert first['success'],first
    assert first['publish_bundle_result_version']=='1.0'and'execution_disposition'not in first
    prior=(roots['evidence']/'.phase/runs/first/receipt.json').read_bytes()
    known=app.publish_bundle(**args).payload
    assert known['error']=='evidence.run_exists'and known['mutation_attempted']is None
    blocked=app.publish_bundle(**dict(args,run_id='legacy-second')).payload
    assert blocked['error']=='bundle.target_exists_inspection_required'and blocked['mutation_attempted']is False
    assert not(roots['evidence']/'.phase/runs/legacy-second').exists()
    assert (roots['evidence']/'.phase/runs/first/receipt.json').read_bytes()==prior


@LINUX
@pytest.mark.parametrize('change',['bytes','members','operation-id','revalidation-token','manifest-digest'])
def test_bundle_same_scope_changed_candidate_and_full_input_records_conflict(tmp_path,monkeypatch,change):
    import phase_tool.core as core
    import phase_tool.publish_bundle as publication
    app,args,roots=case(tmp_path);first=app.publish_bundle(**args).payload;assert first['success'],first
    before=tree(roots['target']);new=dict(args,run_id='changed')
    if change=='bytes':(roots['source']/'a.bin').write_bytes(b'changed source')
    elif change=='members':new['members']=['a.bin']
    elif change=='operation-id':
        real=publication.encode_structured_input
        def alter(value):
            if 'operation_id'in value:value={**value,'operation_id':'changed-same-key-target'}
            return real(value)
        monkeypatch.setattr(publication,'encode_structured_input',alter)
    else:
        real=core.freeze_declared_inputs
        def alter(*a,**kw):
            frozen=real(*a,**kw);field='revalidation_token'if change=='revalidation-token'else'manifest_digest'
            return {key:replace(value,**{field:digest_bytes(b'changed non-time field')})for key,value in frozen.items()}
        monkeypatch.setattr(core,'freeze_declared_inputs',alter)
    result=app.publish_bundle(**new).payload
    assert not result['success']and result['error']=='idempotency.same_key_conflict',result
    assert result['mutation_attempted']is False and tree(roots['target'])==before


@LINUX
@pytest.mark.parametrize('damage',['unmanaged','owner','member-missing','member-corrupt','member-extra','receipt-missing'])
def test_bundle_target_or_unresolved_original_is_not_adopted(tmp_path,damage):
    app,args,roots=case(tmp_path)
    target=roots['target']/'dataset'
    if damage=='unmanaged':target.mkdir();(target/'unmanaged.bin').write_bytes(b'foreign')
    else:
        first=app.publish_bundle(**args).payload;assert first['success'],first
        if damage=='owner':(target/'phase-owner.json').write_bytes(b'{}')
        elif damage=='member-missing':(target/'a.bin').unlink()
        elif damage=='member-corrupt':(target/'a.bin').write_bytes(b'foreign bytes')
        elif damage=='member-extra':(target/'extra.bin').write_bytes(b'foreign extra')
        else:(roots['evidence']/'.phase/runs/first/receipt.json').unlink()
    before=tree(roots['target']);response=app.publish_bundle(**dict(args,run_id='blocked')).payload
    assert not response['success']and response['mutation_attempted']is False,response
    assert tree(roots['target'])==before


@LINUX
@pytest.mark.parametrize('damage',['locator','timestamp','contract'])
def test_reused_bundle_current_reference_must_equal_verified_original(tmp_path,damage):
    app,args,roots=case(tmp_path);assert app.publish_bundle(**args).payload['success']
    second=app.publish_bundle(**dict(args,run_id='second')).payload;assert second['success'],second
    path=roots['evidence']/'.phase/runs/second/receipt.json';receipt=parse_json_bytes(path.read_bytes())
    if damage=='locator':receipt['canonical_result']['locator']='different-dataset'
    elif damage=='timestamp':receipt['canonical_result']['observed_at']='2026-11-08T00:00:00Z'
    else:receipt['canonical_result']['contract']['package_digest']=digest_bytes(b'foreign package')
    path.write_bytes(canonical_bytes(receipt))
    with pytest.raises(PhaseError,match='inspection.(prior_receipt_mismatch|contract_mismatch)'):
        inspect_run(roots['evidence'],'second',app.registry,root_bindings={'phase_result_root':roots['target']})


@LINUX
def test_bundle_original_reader_cycle_and_wrong_capture_expectation_stay_closed(tmp_path):
    app,args,roots=case(tmp_path);assert app.publish_bundle(**args).payload['success']
    second=app.publish_bundle(**dict(args,run_id='second')).payload;assert second['success'],second
    with pytest.raises(PhaseError,match='inspection.prior_receipt_cycle'):
        inspect_run(roots['evidence'],'second',app.registry,root_bindings={'phase_result_root':roots['target']},
            _visited_receipts=frozenset({second['receipt_digest']}))
    response,reference,manifest=app._inspect_bundle_with_result(evidence_root=roots['evidence'],run_id='second',
        root_bindings={'phase_result_root':roots['target']},_expected_candidate_digest=digest_bytes(b'wrong candidate'))
    assert not response.payload['success']and reference is manifest is None


@LINUX
def test_bundle_unknown_actual_dispatch_is_not_normal_replay_or_recovery(tmp_path,monkeypatch):
    from phase_tool.mutation.broker import BrokerExecutionInterrupted,EffectBroker
    app,args,roots=case(tmp_path);real=EffectBroker.execute
    def lost(broker,*a,**kw):
        real(broker,*a,**kw)
        raise BrokerExecutionInterrupted(PhaseError('transport.component_bundle_lost'),[],None,possible_dispatch=True)
    with monkeypatch.context()as patch:
        patch.setattr(EffectBroker,'execute',lost);first=app.publish_bundle(**args).payload
    assert first['status']=='indeterminate'and first['mutation_attempted']is True,first
    before=tree(roots['target']);second=app.publish_bundle(**dict(args,run_id='after-unknown')).payload
    assert not second['success']and second['error']=='idempotency.prior_inspection_required',second
    assert second['mutation_attempted']is False and tree(roots['target'])==before
