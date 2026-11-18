"""Closed owner3 metadata/reader/startup components, not Native qualification.

Real fixed registries, profiles, admission classes and Original reader metadata
resolve. Retained CI148 predecessor controls stay exact. No accepted process,
Core.run, NativeIO, worker, Docker or Phase operation is started.
"""
import ast
import base64
from copy import deepcopy
from dataclasses import replace
from importlib import resources
import json
import sys
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from phase_tool import installation
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.core import CORE_BINDING
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import owner_directory_fixture as owner
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract,require_semantic_owner_admission
from phase_tool.mutation.ntfs.owner_semantic_fixture import semantic_owner_registry,semantic_owner_authority
from phase_tool.mutation.ntfs.owner_semantic_history import owner3_history_buffers,owner3_binding_for_original
from phase_tool.planning.request_identity import request_identity_digest
from tests.test_native_owner_directory_fixture import core_capture

ROLES=owner._ROLES
VECTORS=json.loads((Path(__file__).parent/'fixtures/native_ci148_closed_reader_manifests_v1.json').read_bytes())
ACTUAL={row['role']:row for row in VECTORS['rows']}


def fixture(version='3.0'):
    original=ACTUAL['Version2']['manifest'];case=original['root_grants'][0]['components'][1]
    value={'experimental_admission_version':version,'authorization_digest':owner._AUTHORIZATION,
        'fixture_uuid':case,'owner_scope_id':'phase.qualification.owner.'+case,
        'wheel_digest':'sha256:'+'3'*64,'core':deepcopy(CORE_BINDING),
        'windows_roots':deepcopy(ACTUAL['Version2']['admission']['windows_roots']),
        'root_grants':deepcopy(original['root_grants']),
        'root_projections':{'current_root':'/ntfs-result','objects_root':'/ntfs-objects'},
        'roles':[],'request_limits':{'run_prefix':('od3-'if version=='3.0'else'od2-')+case+'-',
            'maximum_attempts':65536,'maximum_retained_bytes':32*1024**3},
        'qualification':{'A05':'NOT_VERIFIED','G01':'NOT_VERIFIED'},'release_eligible':False}
    for key in('evidence_root','evidence_identity','preparation_root','preparation_identity'):value[key]=deepcopy(original[key])
    for role,kind in owner._kinds().items():
        if version=='3.0':
            registry=semantic_owner_registry(kind);binding=semantic_owner_contract(role)
            profile=registry.guarantee_profile_bindings()['phase.native.ntfs.experiment.owner3.'+role.lower()+'.authority.v1@1.0.0']
            implementation=registry.resolve_guarantee_profile(profile)['implementation']
            authority={'usage':'provider_backed','profile':profile,'provider':{key:implementation[key]for key in('id','version','artifact_digest')}}
            digest=registry.digest
        else:
            binding=deepcopy(kind._contract);authority=deepcopy(ACTUAL[role]['manifest']['authority']);digest=ACTUAL[role]['manifest']['registry_snapshot_digest']
        value['roles'].append({'role':role,'contract':binding,'native_read_installation_version':kind._manifest_version,
            'registry_snapshot_digest':digest,'authority':authority,
            'root_binding':ACTUAL[role]['manifest']['root_grants'][0]['root_binding']})
    return value


def current_readers(version='3.0'):
    document=fixture(version);raw=canonical_bytes(document);result=[]
    for role,kind in owner._kinds().items():
        row=next(row for row in document['roles']if row['role']==role)
        manifest=deepcopy(ACTUAL[role]['manifest'])
        manifest.update(core=deepcopy(document['core']),contract=deepcopy(row['contract']),
            registry_snapshot_digest=row['registry_snapshot_digest'],authority=deepcopy(row['authority']),
            installation_id=owner.installation_id(kind,raw))
        body=canonical_bytes(manifest)
        result.append(installation._native_experimental_read_binding(manifest_bytes=body,
            expected_manifest_digest=digest_bytes(body),admission=kind(raw)))
    return tuple(result),raw


def predecessor(role,family='per-run'):
    value=ACTUAL[role]
    body=canonical_bytes(value['manifest']);cap=canonical_bytes(value['admission'])
    return {'family':family,'role':role,'manifest_base64':base64.b64encode(body).decode(),
        'manifest_digest':digest_bytes(body),'admission_base64':base64.b64encode(cap).decode(),
        'admission_digest':digest_bytes(cap)}


def history(bindings,raw,predecessors=None):
    value={'history_manifest_set_version':'3.0','fixture_base64':base64.b64encode(raw).decode(),
        'fixture_digest':digest_bytes(raw),'manifests':[{'role':role,
            'manifest_base64':base64.b64encode(row.manifest_bytes).decode(),'manifest_digest':row.manifest_digest}
            for role,row in zip(ROLES,bindings,strict=True)],
        'predecessors':predecessors if predecessors is not None else[predecessor(role)for role in ROLES]}
    return value


@pytest.fixture(scope='module')
def six():return current_readers()


@pytest.mark.parametrize('role',ROLES)
def test_closed_real_registry_profile_and_reader_binding_all_six(six,role):
    bindings,raw=six;row=bindings[ROLES.index(role)];manifest=parse_json_bytes(row.manifest_bytes)
    assert manifest['contract']==semantic_owner_contract(role)
    assert row.experimental_admission.document()['experimental_admission_version']=='3.0'
    assert manifest['installation_id']==owner.installation_id(type(row.experimental_admission),raw)
    assert '.owner3.'in manifest['installation_id']
    profile=row.experimental_admission.profile(row);descriptor=row.registry.resolve_guarantee_profile(profile.as_dict())
    assert descriptor['classification']=='qualification_candidate'and descriptor['provided_guarantees']==descriptor['conformance']==[]
    with pytest.raises(PhaseError,match='native_profile_not_qualified'):
        installation._native_qualified_profile(row.registry,profile.as_dict())


@pytest.mark.parametrize('role',ROLES)
@pytest.mark.parametrize('field',['contract','profile','extra-policy','prefix','attempts-bool','root-extra'])
def test_fixture3_unknown_or_widened_role_data_refuses(six,role,field):
    _rows,raw=six;doc=parse_json_bytes(raw);row=doc['roles'][ROLES.index(role)]
    if field=='contract':row['contract']=deepcopy(owner._kinds()[role]._contract)
    elif field=='profile':row['authority']['profile']['id']='phase.native.ntfs.experiment.file1.authority.v1'
    elif field=='extra-policy':doc['request_digest_policy_id']='digest.canonical_request_v1'
    elif field=='prefix':doc['request_limits']['run_prefix']='od2-'+doc['fixture_uuid']+'-'
    elif field=='attempts-bool':doc['request_limits']['maximum_attempts']=True
    else:doc['windows_roots']['extra_root']='S:\\outside'
    with pytest.raises(PhaseError):owner.fixture_document(canonical_bytes(doc))


@pytest.mark.parametrize('role',ROLES)
def test_semantic_capture_and_exact_require_contract_have_no_legacy_fallback(six,role):
    rows,raw=six;row=rows[ROLES.index(role)];kind=type(row.experimental_admission)
    # Fresh admission owns one capture; only resource IO is scoped out of this
    # metadata case. Actual ext4 tests cover that default mechanism separately.
    current=replace(row,experimental_admission=kind(raw));run,candidate,frozen=core_capture(current)
    with patch.object(owner,'enforce_owner_evidence_budget',return_value=None):
        owner.bind_captured_owner_attempt(current,run_id=run,candidate=candidate,frozen=frozen)
    view=current.experimental_admission.check_binding(current)
    assert view['candidate_digest']==digest_bytes(candidate.canonical_bytes)
    assert view['captured_inputs']==[item.intent_record()for _,item in sorted(frozen.items())]
    # Execute the exact pure require_contract method AST on Windows, without
    # importing Linux fcntl/channel code or pretending an accepted constructor.
    method=authority_contract_method(role)
    authority=SimpleNamespace(read_binding=current,_manifest=parse_json_bytes(current.manifest_bytes),_usable=lambda:None)
    binding=semantic_owner_contract(role);contract=current.registry.resolve_contract(**dict(
        identifier=binding['id'],version=binding['version'],package_digest=binding['package_digest']),core_version=CORE_BINDING['version'])
    result=method(authority,contract);assert result['mechanisms']
    old=current.registry.resolve_contract(kind._contract['id'],kind._contract['version'],kind._contract['package_digest'],core_version=CORE_BINDING['version'])
    with pytest.raises(PhaseError):method(authority,old)


@pytest.mark.parametrize('role',ROLES)
def test_natural_records_recap_only_time_and_preserve_legacy_formula(six,role):
    rows,_=six;row=rows[ROLES.index(role)];run,candidate,frozen=core_capture(row)
    inputs=[item.intent_record()for _,item in sorted(frozen.items())];later=deepcopy(inputs)
    for item in later:item['frozen_at']='2026-11-08T00:00:00Z'
    kw={'scope':semantic_owner_contract(role),'candidate_digest':candidate.digest,'input_records':inputs}
    old=request_identity_digest(policy='digest.canonical_request_v1',**kw)
    assert old==profile_digest('request',{'scope':kw['scope'],'candidate_digest':kw['candidate_digest'],'inputs':inputs})
    new=request_identity_digest(policy='digest.semantic_request_v2',**kw)
    assert new==request_identity_digest(policy='digest.semantic_request_v2',**dict(kw,input_records=later))
    if inputs:
        changed=deepcopy(inputs);changed[0]['revalidation_token']=digest_bytes(b'changed')
        assert new!=request_identity_digest(policy='digest.semantic_request_v2',**dict(kw,input_records=changed))


def test_trusted_actual_old_six_and_new_six_resolve_same_physical_domain(six):
    current,raw=six;document=history(current,raw);body=canonical_bytes(document)
    for active in current:
        buffers=owner3_history_buffers(body,digest_bytes(body),active_bytes=active.manifest_bytes,active_digest=active.manifest_digest)
        assert len(buffers)==12
        readers=installation._resolve_native_history_bindings(active,body,digest_bytes(body))
        assert len(readers)==12
        for reader in readers:
            manifest=parse_json_bytes(reader.manifest_bytes)
            selected=installation._native_history_binding_for_original(readers,run_id=reader.experimental_admission.document().get('run_id','new-run'),
                contract=manifest['contract'],core=manifest['core'],installation={'id':manifest['installation_id'],'descriptor_digest':reader.manifest_digest},
                registry_snapshot_digest=manifest['registry_snapshot_digest'])
            assert selected is reader
        # Every actual predecessor keeps its old bytes, family, graph and root.
        for old,role in zip(readers[6:],ROLES,strict=True):
            assert old.manifest_bytes==canonical_bytes(ACTUAL[role]['manifest'])
            assert old.experimental_admission.raw==canonical_bytes(ACTUAL[role]['admission'])


@pytest.mark.parametrize('damage',['missing-old','foreign-tuple','wrong-core','wrong-registry','duplicate','foreign-root','foreign-evidence','bad-family','too-many'])
def test_history_unknown_predecessor_and_domains_never_filter_or_rekey(six,damage):
    current,raw=six;document=history(current,raw)
    if damage in{'foreign-tuple','wrong-core','wrong-registry'}:
        body=canonical_bytes(document);readers=installation._resolve_native_history_bindings(current[0],body,digest_bytes(body))
        manifest=ACTUAL['File1']['manifest'];installed={'id':manifest['installation_id'],'descriptor_digest':digest_bytes(canonical_bytes(manifest))}
        core=deepcopy(manifest['core']);registry=manifest['registry_snapshot_digest']
        if damage=='foreign-tuple':installed['descriptor_digest']=digest_bytes(b'foreign')
        elif damage=='wrong-core':core['package_digest']=digest_bytes(b'foreign')
        else:registry=digest_bytes(b'foreign')
        with pytest.raises(PhaseError):owner3_binding_for_original(readers,run_id=ACTUAL['File1']['admission']['run_id'],contract=manifest['contract'],core=core,installation=installed,registry_snapshot_digest=registry)
        return
    if damage=='missing-old':
        document['predecessors'].pop(0);body=canonical_bytes(document);readers=installation._resolve_native_history_bindings(current[0],body,digest_bytes(body))
        manifest=ACTUAL['File1']['manifest']
        with pytest.raises(PhaseError):owner3_binding_for_original(readers,run_id=ACTUAL['File1']['admission']['run_id'],contract=manifest['contract'],core=manifest['core'],installation={'id':manifest['installation_id'],'descriptor_digest':digest_bytes(canonical_bytes(manifest))},registry_snapshot_digest=manifest['registry_snapshot_digest'])
        return
    if damage=='duplicate':document['predecessors'].append(deepcopy(document['predecessors'][0]))
    elif damage=='bad-family':document['predecessors'][0]['family']='arbitrary-registry-provider'
    elif damage=='too-many':document['predecessors']*=6
    else:
        item=document['predecessors'][0];manifest=parse_json_bytes(base64.b64decode(item['manifest_base64']))
        if damage=='foreign-root':manifest['root_grants'][0]['native_identity']['file_id']='f'*32
        else:manifest['evidence_identity']['inode']+=1
        changed=canonical_bytes(manifest);item.update(manifest_base64=base64.b64encode(changed).decode(),manifest_digest=digest_bytes(changed))
    body=canonical_bytes(document)
    with pytest.raises(PhaseError):installation._resolve_native_history_bindings(current[0],body,digest_bytes(body))


@pytest.mark.parametrize('role',ROLES)
def test_fixed_legacy_per_run_pre_intent_selection_stays_narrow(six,role):
    current,raw=six;body=canonical_bytes(history(current,raw));readers=installation._resolve_native_history_bindings(current[0],body,digest_bytes(body))
    row=ACTUAL[role];selected=installation._native_history_binding_for_original(readers,
        run_id=row['admission']['run_id'],contract=row['manifest']['contract'],core=row['manifest']['core'],_pre_intent_rejection=True)
    assert selected.manifest_bytes==canonical_bytes(row['manifest'])
    with pytest.raises(PhaseError):installation._native_history_binding_for_original(readers,run_id='foreign-run',contract=row['manifest']['contract'],core=row['manifest']['core'],_pre_intent_rejection=True)


def test_owner2_stable_predecessors_keep_exact_old_factories_and_fixture(six):
    current,raw=six;old,old_raw=current_readers('2.0');past=[predecessor(role)for role in ROLES]
    for role,row in zip(ROLES,old,strict=True):
        past.append({'family':'owner2','role':role,'manifest_base64':base64.b64encode(row.manifest_bytes).decode(),
            'manifest_digest':row.manifest_digest,'admission_base64':base64.b64encode(old_raw).decode(),'admission_digest':digest_bytes(old_raw)})
    body=canonical_bytes(history(current,raw,past));readers=installation._resolve_native_history_bindings(current[0],body,digest_bytes(body))
    assert len(readers)==18
    for role,row in zip(ROLES,readers[12:],strict=True):assert row.registry.digest==ACTUAL[role]['manifest']['registry_snapshot_digest']


def authority_contract_method(role):
    from phase_tool.mutation.ntfs.native import _require
    source=resources.files('phase_tool').joinpath('mutation/ntfs/owner_semantic_authorities.py').read_text()
    cls=next(node for node in ast.parse(source).body if isinstance(node,ast.ClassDef)and node.name=='_OwnerSemantic'+role+'Authority')
    method=next(node for node in cls.body if isinstance(node,ast.FunctionDef)and node.name=='require_contract')
    env={'_require':_require,'semantic_owner_contract':semantic_owner_contract,
        'require_semantic_owner_admission':require_semantic_owner_admission}
    for kind in owner._kinds().values():env[kind.__name__]=kind
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[])),'<exact-pure-authority-method>','exec'),env)
    return env['require_contract']


@pytest.mark.skipif(sys.platform=='win32',reason='Actual authority classes import Linux-only fcntl; exact method models run on both hosts.')
@pytest.mark.parametrize('role',ROLES)
def test_linux_actual_authority_class_method_matches_portable_exact_ast(role):
    cls=semantic_owner_authority(owner._kinds()[role])
    source=resources.files('phase_tool').joinpath('mutation/ntfs/owner_semantic_authorities.py').read_text()
    method=next(node for node in next(node for node in ast.parse(source).body if isinstance(node,ast.ClassDef)and node.name==cls.__name__).body if isinstance(node,ast.FunctionDef)and node.name=='require_contract')
    import inspect
    assert ast.dump(ast.parse(inspect.getsource(cls.require_contract).lstrip()).body[0],include_attributes=False)==ast.dump(method,include_attributes=False)


def launcher_functions():
    source=resources.files('phase_tool').joinpath('data/native/native_phase_candidate_launcher_v1.py.in').read_text()
    names={'need','fixed_startup_version','fixed_admission'}
    nodes=[node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef)and node.name in names]
    env={'json':json,'hashlib':hashlib}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'<exact-fixed-admission-functions>','exec'),env)
    return env


@pytest.mark.parametrize('role',ROLES)
def test_fixed_launcher3_dispatch_selects_only_exact_role_and_factory(six,role):
    rows,raw=six;row=rows[ROLES.index(role)];manifest=parse_json_bytes(row.manifest_bytes)
    functions=launcher_functions()
    selected=functions['fixed_admission']({'native_launch_version':'3.0'},manifest,raw)
    assert type(selected)is owner._kinds()[role]and selected.raw==raw
    for damage in('launch2','launch1','old-contract','wrong-reader','wrong-registry'):
        altered=deepcopy(manifest);config={'native_launch_version':'3.0'}
        if damage=='launch2':config['native_launch_version']='2.0'
        elif damage=='launch1':config['native_launch_version']='1.3'
        elif damage=='old-contract':altered['contract']=deepcopy(type(selected)._contract)
        elif damage=='wrong-reader':altered['native_read_installation_version']='1.7'if role=='Bundle2'else'9.9'
        else:altered['registry_snapshot_digest']=digest_bytes(b'foreign')
        with pytest.raises((PhaseError,RuntimeError)):functions['fixed_admission'](config,altered,raw)


@pytest.mark.parametrize('version',['2.0','3.0'])
def test_fixed_startup_shape_requires_owner_fixture_outside_operation(version):
    functions=launcher_functions();outer={key:None for key in('native_fixed_startup_version','config_base64','config_digest','manifest_base64','manifest_digest','dependency_roots','owner_directory_fixture_base64')}
    outer['native_fixed_startup_version']=version
    assert functions['fixed_startup_version'](outer)==version
    for field in('experimental_admission_base64','operation','request_policy','provider'):
        changed=deepcopy(outer);changed[field]=None
        with pytest.raises(RuntimeError):functions['fixed_startup_version'](changed)


@pytest.mark.parametrize('launch',['1.3','2.0','3.0','4.0'])
def test_launch_history3_requires_exact_startup_generation(six,launch):
    from phase_tool.mutation.ntfs.bootstrap import _accepted_launch_history
    rows,raw=six;row=rows[0];body=canonical_bytes(history(rows,raw))
    config={key:None for key in('phase_wheel','phase_wheel_digest','dependency_file_digests','windows_launcher','linux_launcher','docker_executable','core_container_id','reader_container_id','image_digest','linux_python','expected_linux_contours','artifact_graph')}
    config.update(native_launch_version=launch,history_manifest_set_base64=base64.b64encode(body).decode(),history_manifest_set_digest=digest_bytes(body))
    if launch=='3.0':assert _accepted_launch_history(config,row.manifest_bytes,row.manifest_digest)==(body,digest_bytes(body))
    else:
        with pytest.raises(PhaseError):_accepted_launch_history(config,row.manifest_bytes,row.manifest_digest)


def legacy_reader_predecessor(family,role,kind,factory):
    doc=deepcopy(ACTUAL[role]['admission']);doc['contract']=deepcopy(kind._contract)
    raw=canonical_bytes(doc);admission=kind(raw);registry=factory()
    manifest=deepcopy(ACTUAL[role]['manifest'])
    contract=registry.resolve_contract(kind._contract['id'],kind._contract['version'],kind._contract['package_digest'],core_version=manifest['core']['version'])
    profile=registry.guarantee_profile_bindings()[kind._profile];implementation=registry.resolve_guarantee_profile(profile)['implementation']
    manifest.update(native_read_installation_version=kind._manifest_version,contract=deepcopy(kind._contract),
        registry_snapshot_digest=registry.digest,installation_id=kind._installation_prefix+admission.digest[7:],
        mechanism={key:contract.document['operation']['mechanism'][key]for key in('id','version','package_digest')},
        authority={'usage':'provider_backed','profile':profile,'provider':{key:implementation[key]for key in('id','version','artifact_digest')}})
    body=canonical_bytes(manifest)
    # Genuine fixed data resolver, still no native proof/process or new Original.
    installation._native_experimental_read_binding(manifest_bytes=body,expected_manifest_digest=digest_bytes(body),admission=admission)
    return {'family':family,'role':role,'manifest_base64':base64.b64encode(body).decode(),'manifest_digest':digest_bytes(body),
        'admission_base64':base64.b64encode(raw).decode(),'admission_digest':digest_bytes(raw)}


@pytest.mark.parametrize('family,role', [('legacy-shared','File1'),('legacy-shared','Version1'),('legacy-bundle2-v1','Bundle2'),('legacy-bundle2-v2','Bundle2')])
def test_all_explicit_legacy_families_rebuild_real_old_factories_before_scan(six,family,role):
    from phase_tool.mutation.ntfs.owner_semantic_history import _kind
    factories={'legacy-shared':installation._native_experimental_history_registry,
        'legacy-bundle2-v1':installation._native_experimental_bundle2_registry,
        'legacy-bundle2-v2':installation._native_experimental_bundle2_registry_v2}
    current,raw=six;prior=legacy_reader_predecessor(family,role,_kind(family,role),factories[family])
    body=canonical_bytes(history(current,raw,[prior]));readers=installation._resolve_native_history_bindings(current[0],body,digest_bytes(body))
    assert len(readers)==7 and readers[-1].manifest_bytes==base64.b64decode(prior['manifest_base64'])
    manifest=parse_json_bytes(readers[-1].manifest_bytes)
    selected=owner3_binding_for_original(readers,run_id=readers[-1].experimental_admission.document()['run_id'],contract=manifest['contract'],core=manifest['core'],installation={'id':manifest['installation_id'],'descriptor_digest':readers[-1].manifest_digest},registry_snapshot_digest=manifest['registry_snapshot_digest'])
    assert selected is readers[-1]and selected.registry.digest==factories[family]().digest
