"""Own disposable Host/ext4 artifacts plus explicit synthetic native claims.

No native authority, admission, Windows effect or proof is produced. Current
contract packages are reused. Candidate profile consistency is not G01 trust.
"""
import base64
from copy import deepcopy
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.core import PhaseCore,PhaseRequest
from phase_tool import installation
from ._native_history_fixture import manifests as legacy_manifests
from .test_native_version1_original import arguments
from .test_native_original_intent import buffers
from phase_tool.registry import BundledRegistry

ROLES=('file_create.v1','publish_new_version.v1','file_create.v2')


def manifests(evidence='/synthetic/shared/evidence',identity=None,
        preparation='/synthetic/shared/preparation',preparation_identity=None,
        projection='/synthetic/shared/opaque-target'):
    registry=installation._native_shared_history_registry()
    _,old=legacy_manifests(evidence,identity)
    first=deepcopy(old[0])
    first.update(native_read_installation_version='1.4',registry_snapshot_digest=registry.digest,
        preparation_root=str(preparation),root_projections={'phase_result_root':str(projection)})
    if preparation_identity is not None:first['preparation_identity']=deepcopy(preparation_identity)
    exact=registry.guarantee_profile_bindings()['phase.native.ntfs.candidate.authority.v5@1.0.0']
    descriptor=registry.resolve_guarantee_profile(exact)
    first['authority']={'usage':'provider_backed','profile':exact,
        'provider':{key:descriptor['implementation'][key] for key in ('id','version','artifact_digest')}}
    leaves=[]
    for index,role in enumerate(ROLES):
        leaf=deepcopy(first);leaf['installation_id']='synthetic.shared.role'+str(index)
        leaf['contract']=registry.contract_bindings()[role+'@1.0.0']
        contract=registry.resolve_contract(role,'1.0.0',leaf['contract']['package_digest'],
            core_version=leaf['core']['version'])
        leaf['mechanism']={key:contract.document['operation']['mechanism'][key]
            for key in ('id','version','package_digest')}
        alias=contract.document['canonical_result']['root_binding']
        leaf['root_grants'][0]['root_binding']=alias
        leaf['root_projections']={alias:str(projection)}
        leaves.append(leaf)
    return registry,tuple(leaves)


def set_bytes(leaves):
    return canonical_bytes({'history_manifest_set_version':'1.1','manifests':[
        {'manifest_base64':base64.b64encode(canonical_bytes(leaf)).decode('ascii'),
         'manifest_digest':digest_bytes(canonical_bytes(leaf))} for leaf in leaves]})


def binding(registry,leaf):
    raw=canonical_bytes(leaf)
    return installation._resolve_native_file_create_read_binding(manifest_bytes=raw,
        expected_manifest_digest=digest_bytes(raw),registry=registry)


def domain(tmp_path):
    roots={name:tmp_path/name for name in ('host-evidence','native-claims','preparation','target')}
    for root in roots.values():root.mkdir(mode=0o700)
    installation.qualify_host_authority_roots(roots)
    for root in roots.values():
        assert installation._linux_filesystem_type(root)=='ext4','actual ext4 component required'
    def identity(name):
        info=roots[name].stat()
        return {'stable_id':'synthetic.shared.'+name,'device':info.st_dev,'inode':info.st_ino}
    registry,leaves=manifests(str(roots['native-claims']),identity('native-claims'),
        str(roots['preparation']),identity('preparation'),str(roots['target']))
    bindings=tuple(binding(registry,leaf) for leaf in leaves)
    raw=set_bytes(leaves)
    history=installation._resolve_native_history_bindings(bindings[0],raw,digest_bytes(raw))
    for name in ('runs','locks'):(roots['native-claims']/'.phase'/name).mkdir(parents=True,mode=0o700)
    return registry,leaves,bindings,history,roots


def rejection(registry,leaves,roots,index,name):
    exact=leaves[index]['contract'];root=roots['native-claims']
    request=PhaseRequest(exact['id'],exact['version'],exact['package_digest'],
        root/'unused.json',root,name,{}, {},timestamp='2026-10-26T00:00:00Z')
    receipt=PhaseCore(registry)._rejection_receipt(request,[],request.timestamp,'synthetic.rejected')
    run=root/'.phase'/'runs'/name;run.mkdir(mode=0o700)
    (run/'receipt.json').write_bytes(canonical_bytes(receipt))
    return run,receipt


def planned(tmp_path,index,content=b'synthetic shared payload'):
    registry,leaves,bindings,history,roots=domain(tmp_path)
    leaf=leaves[index];exact=leaf['contract'];alias=leaf['root_grants'][0]['root_binding']
    candidate={'operation_id':'shared.component','target_locator':'synthetic.bin',
        'input_binding':'payload','idempotency_key':'shared-component'}
    if index==1:
        before=b'synthetic previous version';(roots['target']/'synthetic.bin').write_bytes(before)
        candidate['expected_current_digest']=digest_bytes(before)
    source=roots['preparation']/'payload';source.write_bytes(content)
    candidate_path=roots['preparation']/'candidate.json';candidate_path.write_bytes(canonical_bytes(candidate))
    request=PhaseRequest(exact['id'],exact['version'],exact['package_digest'],candidate_path,
        roots['host-evidence'],'shared-component',{'payload':source},{alias:roots['target']},
        timestamp='2026-10-26T00:00:00Z')
    outcome=PhaseCore(registry).run(request,execute=False)
    assert outcome.exit_code==0 and outcome.receipt['terminal_status']=='validated_planned'
    host_run=roots['host-evidence']/'.phase'/'runs'/request.run_id
    pre=parse_json_bytes((host_run/'attachments'/'validator-results.json').read_bytes())
    shell=buffers(BundledRegistry.load())[0]
    intent=deepcopy(outcome.intent);plan=deepcopy(outcome.effect_plan)
    intent.update(phase_intent_version='1.2',execution_requested=False,
        native_binding=deepcopy(shell['native_binding']))
    intent['native_binding'].update(installation={'id':leaf['installation_id'],
        'descriptor_digest':bindings[index].manifest_digest},composition=deepcopy(leaf['composition']),
        evidence_identity=deepcopy(leaf['evidence_identity']))
    intent['implementation_binding']={'authority':deepcopy(leaf['authority']),
        'mechanism':deepcopy(leaf['mechanism']),'effect_plan_digest':intent['effect_plan_digest']}
    grants=deepcopy(leaf['root_grants'])
    root_digest=profile_digest('native-root-identity-v1',grants)
    scope={'contract':intent['contract'],'result_locator':candidate['target_locator'],
        'root_identity_digest':root_digest,'operation_intent':'publish_new_version' if index==1 else 'create'}
    intent['idempotency'].update(root_identities=grants,root_identity_digest=root_digest,
        scope_digest=profile_digest('idempotency-scope',scope),
        request_digest=profile_digest('request',{'scope':scope,'candidate_digest':intent['candidate']['digest'],
            'inputs':intent['inputs']}))
    args=arguments(registry,intent,plan,pre,content)
    run=roots['native-claims']/'.phase'/'runs'/request.run_id;run.mkdir(mode=0o700)
    records={'intent.json':args['intent_bytes'],'attachments/effect-plan.json':args['plan_bytes'],
        'attachments/validator-results.json':args['pre_validator_bytes'],
        'blobs/'+digest_bytes(content).removeprefix('sha256:'):content}
    for name,data in records.items():
        path=run/name;path.parent.mkdir(mode=0o700,exist_ok=True);path.write_bytes(data)
    receipt=deepcopy(outcome.receipt)
    receipt['evidence']['intent_digest']=args['expected_intent_digest']
    receipt['implementation_binding']=deepcopy(parse_json_bytes(args['intent_bytes'])['implementation_binding'])
    (run/'receipt.json').write_bytes(canonical_bytes(receipt))
    return registry,leaves,bindings,history,roots,run,args,receipt
