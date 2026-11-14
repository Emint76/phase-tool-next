"""Pure fixed six-role metadata from retained CI148, not an authority."""
from pathlib import Path
from copy import deepcopy
import json
from phase_tool.canonical import canonical_bytes,digest_bytes,canonical_digest
from phase_tool.core import CORE_BINDING
from phase_tool.mutation.ntfs import owner_directory_fixture as owner
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract
from phase_tool.mutation.ntfs.owner_semantic_fixture import semantic_owner_registry
ACTUAL={r['role']:r for r in json.loads((Path(__file__).parent/'fixtures/native_ci148_closed_reader_manifests_v1.json').read_bytes())['rows']}
def fixture(version):
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
            registry=semantic_owner_registry(kind);contract=semantic_owner_contract(role)
            profile=registry.guarantee_profile_bindings()['phase.native.ntfs.experiment.owner3.'+role.lower()+'.authority.v1@1.0.0']
            implementation=registry.resolve_guarantee_profile(profile)['implementation']
            authority={'usage':'provider_backed','profile':profile,'provider':{k:implementation[k]for k in('id','version','artifact_digest')}}
            registry_digest=registry.digest
        else:
            contract=deepcopy(kind._contract);authority=deepcopy(ACTUAL[role]['manifest']['authority'])
            registry_digest=ACTUAL[role]['manifest']['registry_snapshot_digest']
        value['roles'].append({'role':role,'contract':contract,'native_read_installation_version':kind._manifest_version,
            'registry_snapshot_digest':registry_digest,'authority':authority,'root_binding':ACTUAL[role]['manifest']['root_grants'][0]['root_binding']})
    return value

def prepared(version):
    doc=fixture(version);raw=canonical_bytes(doc);manifests={}
    graph={'artifact_graph_version':'1.0','phase_wheel_digest':doc['wheel_digest'],'launcher_digest':'sha256:'+'4'*64,
        'windows':{'python_version':'3.12.10','python_executable_digest':'sha256:'+'5'*64,
            'runtime_manifest_digest':'sha256:'+'6'*64,'dependency_file_digests':{},'docker_executable_digest':'sha256:'+'7'*64},
        'linux':{'python_version':'3.12.10','python_executable_digest':'sha256:'+'8'*64,
            'runtime_manifest_digest':'sha256:'+'9'*64,'dependency_file_digests':{}}}
    for role,kind in owner._kinds().items():
        row=next(r for r in doc['roles']if r['role']==role);m=deepcopy(ACTUAL[role]['manifest'])
        m.update(core=deepcopy(doc['core']),contract=deepcopy(row['contract']),registry_snapshot_digest=row['registry_snapshot_digest'],
            authority=deepcopy(row['authority']),installation_id=owner.installation_id(kind,raw))
        m['composition']['artifact_graph_digest']=canonical_digest(graph);manifests[role]=m
    return doc,raw,manifests,graph

def builders():
    return dict(fixture=fixture,prepared=prepared,ACTUAL=ACTUAL,owner=owner)
