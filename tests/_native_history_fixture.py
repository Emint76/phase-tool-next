"""Synthetic STATIC V5 pair only; no accepted native installation or I/O."""
import base64
from copy import deepcopy
from phase_tool.canonical import canonical_bytes,digest_bytes
from phase_tool.core import CORE_BINDING
from phase_tool.installation import _native_lifecycle_registry,_resolve_native_file_create_read_binding
from phase_tool.registry import BundledRegistry
from .test_native_intent_v12 import fixture
from .test_native_static_read_binding import manifest_for


def manifests(evidence='/synthetic/history/evidence',evidence_identity=None):
    registry=_native_lifecycle_registry()
    shell=fixture(BundledRegistry.load())
    first=manifest_for(shell,evidence)
    first.update(native_read_installation_version='1.2',installation_id='synthetic.history.file1',
        core=deepcopy(CORE_BINDING),registry_snapshot_digest=registry.digest,
        preparation_root='/synthetic/history/preparation',
        preparation_identity={'stable_id':'synthetic.history.preparation','device':3,'inode':4},
        root_projections={'phase_result_root':'/synthetic/history/opaque-result'})
    if evidence_identity is not None:first['evidence_identity']=deepcopy(evidence_identity)
    second=deepcopy(first);second['installation_id']='synthetic.history.version1'
    second['root_grants'][0]['root_binding']='fixture_result_root'
    second['root_projections']={'fixture_result_root':'/synthetic/history/opaque-result'}
    for role,leaf in zip(('file_create.v1','publish_new_version.v1'),(first,second)):
        leaf['contract']=registry.contract_bindings()[role+'@1.0.0']
        exact=leaf['contract']
        contract=registry.resolve_contract(exact['id'],exact['version'],exact['package_digest'],core_version=CORE_BINDING['version'])
        leaf['mechanism']={k:contract.document['operation']['mechanism'][k] for k in ('id','version','package_digest')}
    return registry,(first,second)


def set_bytes(leaves):
    return canonical_bytes({'history_manifest_set_version':'1.0','manifests':[
        {'manifest_base64':base64.b64encode(canonical_bytes(leaf)).decode('ascii'),
         'manifest_digest':digest_bytes(canonical_bytes(leaf))} for leaf in leaves]})


def binding(registry,leaf):
    raw=canonical_bytes(leaf)
    return _resolve_native_file_create_read_binding(manifest_bytes=raw,expected_manifest_digest=digest_bytes(raw),registry=registry)
