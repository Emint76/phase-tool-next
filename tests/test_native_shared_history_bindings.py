"""Static immutable-composition oracles and REAL closed admission guards only.

No positive native authority, worker, Windows API, target operation or G01 claim.
"""
import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError
from importlib import resources
from types import SimpleNamespace
from unittest.mock import Mock,patch
import pytest
from jsonschema.exceptions import ValidationError

from phase_tool import evidence,installation
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.bootstrap import _native_history_manifest_buffers,_accepted_launch_history,_NativeAcceptedLaunch
from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3
from phase_tool.mutation.ntfs.channel_v4 import LinuxNativeChannelV4
from phase_tool.mutation.ntfs import entrypoint
from ._native_shared_history_fixture import ROLES,manifests,set_bytes,binding


def resolve(registry,leaves,index=0):
    raw=set_bytes(leaves)
    return installation._resolve_native_history_bindings(binding(registry,leaves[index]),raw,digest_bytes(raw))


def test_v7_reuses_exact_three_current_packages_and_preserves_all_v6_resources():
    old=installation._native_file2_registry()
    new=installation._native_shared_history_registry()
    assert new.to_document()['entries'][:-1]==old.to_document()['entries']
    assert new.to_document()['trust_roots']==old.to_document()['trust_roots']
    assert all(new.contract_bindings()[role+'@1.0.0']==old.contract_bindings()[role+'@1.0.0'] for role in ROLES)
    exact=new.guarantee_profile_bindings()['phase.native.ntfs.candidate.authority.v5@1.0.0']
    descriptor=new.resolve_guarantee_profile(exact)
    assert descriptor['classification']=='qualification_candidate'
    assert descriptor['provided_guarantees']==descriptor['conformance']==[]
    actual=resources.files('phase_tool').joinpath('mutation/ntfs/authority.py').read_bytes()
    assert descriptor['implementation']['artifact_digest']==digest_bytes(actual)
    assert 'phase.native.ntfs.authority.v1@1.0.0' not in new.guarantee_profile_bindings()
    for version,expected in ((5,'52e3835f506f6a806ac846312cce1758f54b61238d87f8aeffacb4a62f773186'),
            (6,'1d7b32b3412178517eee60338fabd18e20a403bf84f8e9c495158eadf7b48ac9')):
        resource='registries/'+('native-lifecycle-candidate-v5.json' if version==5 else 'native-file2-candidate-v6.json')
        assert digest_bytes(new.resource_bytes(resource))=='sha256:'+expected


@pytest.mark.parametrize('index',[0,1,2])
def test_exact_three_immutable_roles_and_all_active_selections(index):
    registry,leaves=manifests();rows=resolve(registry,leaves,index)
    assert type(rows) is tuple and len(rows)==3
    assert [parse_json_bytes(row.manifest_bytes)['contract']['id'] for row in rows]==list(ROLES)
    assert all(row.registry is registry for row in rows)
    with pytest.raises(FrozenInstanceError):rows[0].manifest_bytes=b'{}'
    selected=binding(registry,leaves[index])
    assert installation._validate_native_history_bindings(selected,rows) is rows
    assert installation._native_registry_for_manifest(selected.manifest_bytes,selected.manifest_digest).digest==registry.digest
    with pytest.raises(PhaseError,match='ntfs.accepted_history_binding_mismatch'):
        installation._resolve_native_history_bindings(selected,None,None)


@pytest.mark.parametrize('change',['missing','extra','duplicate','reversed','version10','unknown-version',
    'leaf-version12','extra-field','bad-hash','noncanonical','bad-base64'])
def test_set_shape_order_generation_hash_and_canonical_leaf_are_closed(change):
    registry,leaves=manifests();active=binding(registry,leaves[0]);value=parse_json_bytes(set_bytes(leaves))
    if change=='missing':value['manifests'].pop()
    elif change=='extra':value['manifests'].append(deepcopy(value['manifests'][0]))
    elif change=='duplicate':value['manifests'][2]=deepcopy(value['manifests'][1])
    elif change=='reversed':value['manifests'].reverse()
    elif change in ('version10','unknown-version'):value['history_manifest_set_version']='1.0' if change=='version10' else '1.2'
    elif change=='extra-field':value['extra']=True
    elif change=='bad-hash':value['manifests'][1]['manifest_digest']='sha256:'+'f'*64
    elif change=='bad-base64':value['manifests'][1]['manifest_base64']='!!'
    else:
        leaf=deepcopy(leaves[1])
        if change=='leaf-version12':leaf['native_read_installation_version']='1.2'
        raw=canonical_bytes(leaf)+(b'\n' if change=='noncanonical' else b'')
        value['manifests'][1]={'manifest_base64':base64.b64encode(raw).decode(),'manifest_digest':digest_bytes(raw)}
    raw=canonical_bytes(value)
    with pytest.raises((PhaseError,ValueError)):
        _native_history_manifest_buffers(raw,digest_bytes(raw),active_bytes=active.manifest_bytes,active_digest=active.manifest_digest)


@pytest.mark.parametrize('field',['core','registry','authority','composition','evidence-path','evidence-stable',
    'evidence-device','evidence-inode','preparation-path','preparation-stable','preparation-device',
    'preparation-inode','device','volume-guid','serial32','component','serial64','file-id','projection','alias','mechanism'])
def test_complete_shared_domain_and_exact_role_aliases_refuse_substitution(field):
    registry,leaves=manifests();leaves=deepcopy(leaves);leaf=leaves[2]
    if field=='core':leaf['core']['package_digest']='sha256:'+'f'*64
    elif field=='registry':leaf['registry_snapshot_digest']='sha256:'+'f'*64
    elif field=='authority':leaf['authority']['provider']['artifact_digest']='sha256:'+'f'*64
    elif field=='composition':leaf['composition']['artifact_graph_digest']='sha256:'+'f'*64
    elif field=='evidence-path':leaf['evidence_root']='/synthetic/other/evidence'
    elif field=='preparation-path':leaf['preparation_root']='/synthetic/other/preparation'
    elif field.startswith(('evidence-','preparation-')):
        role,suffix=field.split('-');key='stable_id' if suffix=='stable' else suffix
        leaf[role+'_identity'][key]='synthetic.other' if key=='stable_id' else 991
    elif field=='device':leaf['root_grants'][0]['device']=leaf['root_grants'][0]['device'].replace('HarddiskVolume17','HarddiskVolume18')
    elif field=='volume-guid':leaf['root_grants'][0]['volume_guid']=leaf['root_grants'][0]['volume_guid'].replace('11111111-2222-3333-4444-555555555555','22222222-2222-2222-2222-222222222222')
    elif field=='serial32':leaf['root_grants'][0]['volume_serial32']=18
    elif field=='component':leaf['root_grants'][0]['components']=['Other']
    elif field=='serial64':leaf['root_grants'][0]['native_identity']['volume_serial']=(1<<48)+18
    elif field=='file-id':leaf['root_grants'][0]['native_identity']['file_id']='a'*32
    elif field=='projection':leaf['root_projections']={'phase_result_root':'/synthetic/other/target'}
    elif field=='alias':leaf['root_grants'][0]['root_binding']='fixture_result_root'
    else:leaf['mechanism']=deepcopy(leaves[1]['mechanism'])
    if field in {'device','volume-guid','serial32','component','serial64','file-id','projection'}:
        with pytest.raises(PhaseError,match='ntfs.original_history_domain_mismatch'):resolve(registry,leaves)
    else:
        with pytest.raises((PhaseError,ValidationError)):resolve(registry,leaves)


@pytest.mark.parametrize('part',['profile-id','profile-version','profile-sha','provider-id','provider-version','provider-sha'])
def test_same_wrong_authority_in_every_leaf_is_not_accepted_by_domain_equality(part):
    registry,leaves=manifests();leaves=deepcopy(leaves)
    group,field=part.split('-');key='descriptor_digest' if group=='profile' and field=='sha' else 'artifact_digest' if field=='sha' else field
    for leaf in leaves:
        leaf['authority'][group][key]='sha256:'+'f'*64 if field=='sha' else 'synthetic.wrong' if field=='id' else '9.0.0'
    with pytest.raises(PhaseError):resolve(registry,leaves)


def test_known_historical_contract_package_is_not_current_v7_role():
    registry,leaves=manifests();leaves=deepcopy(leaves)
    leaves[0]['contract']['package_digest']='sha256:734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09'
    with pytest.raises(PhaseError):resolve(registry,leaves)


@pytest.mark.parametrize('index',[0,1,2])
def test_manifest14_keeps_existing_worker_role_predicates_and_config11_shape(index):
    registry,leaves=manifests();selected=binding(registry,leaves[index])
    launch=object.__new__(_NativeAcceptedLaunch);launch._manifest_bytes=selected.manifest_bytes
    assert launch._version1 is (index==1)
    assert launch._file2 is (index==2)
    config={key:None for key in ('phase_wheel','phase_wheel_digest','dependency_file_digests',
        'windows_launcher','linux_launcher','docker_executable','core_container_id','reader_container_id',
        'image_digest','linux_python','expected_linux_contours','artifact_graph')}
    raw=set_bytes(leaves)
    config.update(native_launch_version='1.1',history_manifest_set_base64=base64.b64encode(raw).decode(),
        history_manifest_set_digest=digest_bytes(raw))
    assert _accepted_launch_history(config,selected.manifest_bytes,selected.manifest_digest)==(raw,digest_bytes(raw))
    with pytest.raises(PhaseError):_accepted_launch_history(config|{'allow_candidate':True},
        selected.manifest_bytes,selected.manifest_digest)


@pytest.mark.parametrize('index',[0,1,2])
@pytest.mark.parametrize('inspection',[False,True])
def test_actual_factory_guard_refuses_before_any_read_channel_snapshot_or_evidence(index,inspection):
    registry,leaves=manifests();selected=binding(registry,leaves[index]);raw=set_bytes(leaves)
    with (patch.object(installation,'_resolve_native_file_create_read_binding',side_effect=AssertionError('read binding reached')) as reader,
            patch.object(installation,'_resolve_native_history_bindings',side_effect=AssertionError('history reached')) as history,
            patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel3 reached')) as c3,
            patch.object(LinuxNativeChannelV4,'__init__',side_effect=AssertionError('channel4 reached')) as c4,
            patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('evidence reached')) as store):
        with pytest.raises(PhaseError,match='ntfs.native_profile_not_qualified'):
            installation._native_installation_for_manifest(manifest_bytes=selected.manifest_bytes,
                expected_manifest_digest=selected.manifest_digest,run_id='synthetic-refused',
                operation_nonce='a'*32,channel_id='b'*32,_inspection_only=inspection,
                history_manifest_set_bytes=raw,history_manifest_set_digest=digest_bytes(raw))
        reader.assert_not_called();history.assert_not_called();c3.assert_not_called();c4.assert_not_called();store.assert_not_called()


@pytest.mark.parametrize('index',[0,1,2])
def test_current_core_dispatch_refuses_all_roles_before_preparation_application_or_target(index):
    registry,leaves=manifests();selected=binding(registry,leaves[index])
    request={'operation':'execute','candidate_path':'/synthetic/unused.json','input_paths':{},
        'expected_inputs':None,'maximum_candidate_bytes':1024**2}
    launch=SimpleNamespace(_inspection_only=False,check_runtime=Mock(),
        invocation={'request':request},_manifest_bytes=selected.manifest_bytes,
        installation_digest=selected.manifest_digest,run_id='synthetic-refused',
        operation_nonce='a'*32,channel_id='b'*32,history_manifest_set=(set_bytes(leaves),digest_bytes(set_bytes(leaves))))
    with (patch.object(entrypoint,'_linux_stdio_identity',return_value='synthetic-stdio'),
            patch.object(entrypoint,'_deliver_linux_frame') as delivery,
            patch.object(PhaseApplication,'run',side_effect=AssertionError('application reached')) as app,
            patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('evidence reached')) as store):
        assert entrypoint.run_native_core(launch)==10
        app.assert_not_called();store.assert_not_called()
    result=delivery.call_args.args[0]['result']
    assert result['error']=='ntfs.native_profile_not_qualified'
    assert result['success'] is False and result['mutation_attempted'] is False and result['receipt_digest'] is None
