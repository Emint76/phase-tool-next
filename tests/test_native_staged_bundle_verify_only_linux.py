"""Copy into tests/ on the exact composed source. No native or Phase operation.

Requires isolated nonroot Linux/ext4 for the qualification component. Native
admission is modeled; marker/candidate/path and read/freeze I/O are the product.
"""
import os
import sys
from types import SimpleNamespace

import pytest

from phase_tool import bundle
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.installation import _NativeFileCreateInstallation
from phase_tool.mutation.ntfs import input_stage, preparation

from .test_native_input_stage_protocol import IDENTITY, record


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='real Linux staged-input fingerprint boundary')


def make_case(tmp_path, monkeypatch, role):
    prep, evidence = tmp_path/'preparation', tmp_path/'evidence'
    prep.mkdir(); evidence.mkdir()
    result = tmp_path/'opaque-result-projection'
    manifest = {'root_projections': {'current_root': str(result)}, 'evidence_root': str(evidence)}
    owner = object.__new__(_NativeFileCreateInstallation)
    registry = object()
    owner.read_binding = SimpleNamespace(registry=registry)
    namespace_checks = []
    def namespace(**kw):
        assert kw == {'root_bindings': {'current_root': result}, 'evidence_root': evidence, 'maximum_candidate_bytes': 1024**2}
        namespace_checks.append(kw)
        return manifest
    monkeypatch.setattr(_NativeFileCreateInstallation, '_check_preparation_namespace', lambda self, **kw: namespace(**kw))
    owner.authority = SimpleNamespace(_execution_required=lambda: None)
    app = SimpleNamespace(installation=owner, registry=registry)
    launch = SimpleNamespace(run_id='linux-bundle-verify-component', installation_digest=digest_bytes(b'model manifest'),
                             channel_id='1'*32, operation_nonce='2'*32, manifest=manifest)
    scope = {'scope_id':'model.inputs','root_identity':IDENTITY,'preparation_root':str(prep)}
    scope_digest = digest_bytes(canonical_bytes(scope))
    monkeypatch.setattr(input_stage, '_scope_for_launch', lambda supplied: (scope,role,scope_digest) if supplied is launch else None)
    bodies = {'a/empty.bin':b'','a/first.bin':b'ABC','b/duplicate.bin':b'ABC'}
    paths = list(bodies)
    header = input_stage._header(launch,scope,role,scope_digest,input_stage._stage_request(scope['scope_id'],'src/bundle',paths),
                                 [record(path,body) for path,body in bodies.items()])
    rows = [{'path':path,'length':len(body),'digest':digest_bytes(body)} for path,body in bodies.items()]
    bundled = canonical_bytes({'bundle_version':'1.0','members':rows,'total_length':6})
    header_digest = digest_bytes(header)
    staged = 'phase-native-input-' + header_digest[7:39]
    source = prep/staged/'payload'
    for path,body in bodies.items():
        dest = source/path
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(body)
    marker = {'native_prepared_input_version':'1.0','header_digest':header_digest,'payload_kind':'bundle','source_locator':staged+'/payload',
              'expected_digest':digest_bytes(bundled),'expected_length':len(bundled),'member_count':len(rows),'total_length':6,
              'members':rows,'source_header':parse_json_bytes(header),'telemetry_stage':'PRE_RETURN_PREPARATION_DATA','final_acceptance':None}
    marker_path = source.parent/'input-stage.json'
    marker_path.write_bytes(canonical_bytes(marker))
    request = input_stage._staged_publication_request(role=role,prepared=marker,input_scope=scope['scope_id'],request_id='small-linux-case',
        target_locator='current/item',members=paths,expected_current_digest=None)
    return SimpleNamespace(app=app,launch=launch,request=request,prep=prep,evidence=evidence,source=source,
                           marker=marker,marker_path=marker_path,bodies=bodies,bundled=bundled,result=result,checks=namespace_checks)


def stage_files(case):
    return {p.relative_to(case.source.parent).as_posix(): (p.stat().st_ino,p.read_bytes())
            for p in case.source.parent.rglob('*') if p.is_file() and not p.is_symlink()}


def call(case):
    return preparation._prepare_staged_publication(case.app,case.launch,case.request)


def require_pre_core_rejection(error):
    # This is the existing exact projection used by run_native_core's staged
    # preparation catch. We never invoke Core/run_native_core in this test.
    response = object.__new__(PhaseApplication)._failure('execute',error)
    payload = response.payload
    assert payload['exit_code']==10 and payload['execution_disposition']=='not_executed'
    assert payload['error']==error.code and payload['mutation_attempted'] is False
    assert all(payload[key] is None for key in ('run_id','intent_digest','effect_plan_digest','receipt_digest','target_verified'))


@pytest.mark.parametrize('role',['Bundle1','Bundle2'])
def test_exact_marker_and_retained_candidate_without_preparation_payload(tmp_path,monkeypatch,role):
    case = make_case(tmp_path,monkeypatch,role)
    before = stage_files(case)
    path, inputs, expected, body = call(case)
    assert path.read_bytes()==body and parse_json_bytes(body)['members']==list(case.bodies)
    assert inputs=={'payload':case.source} and expected=={'payload':(digest_bytes(case.bundled),len(case.bundled))}
    assert len(case.checks)==2 and tuple(path.parent.iterdir())==(path,)
    assert stage_files(case)==before and not case.result.exists() and not list(case.evidence.iterdir())
    frozen = bundle.freeze_bundle('payload',inputs['payload'],list(case.bodies),case.evidence/'blobs',frozen_at='2026-11-11T00:00:00Z')
    assert (frozen.digest,frozen.length)==expected['payload'] and frozen.blob_path.read_bytes()==case.bundled
    assert list(frozen.manifest)==case.marker['members'] and stage_files(case)==before


@pytest.mark.parametrize(('changed','expected_code'),[(b'ABD','input_stage.preparation_digest_mismatch'),
    (b'AB','input_stage.preparation_digest_mismatch'),(b'ABCD','input_stage.preparation_digest_mismatch'),
    (b'ABCDEFghi','stream.limit_exceeded')])
def test_member_refusal_preserves_previous_physical_cap_error(tmp_path,monkeypatch,changed,expected_code):
    case = make_case(tmp_path,monkeypatch,'Bundle1')
    # Test-local small caps at the real Bundle constants make the actual read
    # branch feasible. Full product size limits and real boundary need D07.
    monkeypatch.setattr(bundle,'FILE_LIMIT',8)
    monkeypatch.setattr(bundle,'MAX_TOTAL_BYTES',16)
    (case.source/'a/first.bin').write_bytes(changed)
    before=stage_files(case)
    with pytest.raises(PhaseError) as raised:
        call(case)
    assert raised.value.code==expected_code
    require_pre_core_rejection(raised.value)
    assert stage_files(case)==before and not case.result.exists() and not list(case.evidence.iterdir())
    assert not any(row.is_file() for scratch in case.prep.glob('phase-native-staged-*') for row in scratch.iterdir())


def test_remaining_aggregate_cap_is_used_and_first_corruption_is_sticky(tmp_path,monkeypatch):
    case = make_case(tmp_path,monkeypatch,'Bundle2')
    monkeypatch.setattr(bundle,'FILE_LIMIT',8)
    monkeypatch.setattr(bundle,'MAX_TOTAL_BYTES',6)
    late = case.source/'b/duplicate.bin'
    late.write_bytes(b'ABCD')
    with pytest.raises(PhaseError) as physical:
        call(case)
    assert physical.value.code=='stream.limit_exceeded'
    (case.source/'a/first.bin').write_bytes(b'ABD')
    with pytest.raises(PhaseError) as earliest:
        call(case)
    assert earliest.value.code=='input_stage.preparation_digest_mismatch'
    require_pre_core_rejection(earliest.value)


@pytest.mark.parametrize('position',['source','parent','leaf'])
def test_static_links_in_existing_preparation_scope_never_traversed(tmp_path,monkeypatch,position):
    case = make_case(tmp_path,monkeypatch,'Bundle2')
    outside = tmp_path/'outside';outside.mkdir()
    (outside/'sentinel').write_bytes(b'owned outside')
    path = {'source':case.source,'parent':case.source/'a','leaf':case.source/'a/first.bin'}[position]
    parked = path.with_name(path.name+'-retained')
    path.rename(parked)
    os.symlink(outside/'sentinel' if position=='leaf' else outside,path)
    with pytest.raises(PhaseError) as raised:
        call(case)
    assert raised.value.code=='path.link_forbidden'
    require_pre_core_rejection(raised.value)
    assert path.is_symlink() and parked.exists() and (outside/'sentinel').read_bytes()==b'owned outside'


def test_real_marker_binding_and_post_verification_recapture_are_distinct(tmp_path,monkeypatch):
    case = make_case(tmp_path,monkeypatch,'Bundle2')
    _, inputs, expected, _ = call(case)
    (case.source/'a/first.bin').write_bytes(b'ABD')
    frozen = bundle.freeze_bundle('payload',inputs['payload'],list(case.bodies),case.evidence/'blobs',frozen_at='2026-11-11T00:00:00Z')
    assert (frozen.digest,frozen.length)!=expected['payload']
    assert not case.result.exists()
    changed = dict(case.marker,member_count=999)
    case.marker_path.write_bytes(canonical_bytes(changed))
    with pytest.raises(PhaseError) as raised:
        call(case)
    assert raised.value.code=='input_stage.prepared_membership'
