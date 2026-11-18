"""Real Linux staged File1 and File2 hashing and Core recapture, with modeled admission.

These tests use the product marker parser and real files. They issue no Phase
command and exercise no Native authority, Worker or target mutation.
"""
import os
import sys
from types import SimpleNamespace

import pytest

from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.freeze import freeze_declared_inputs, revalidate_frozen
from phase_tool.installation import _NativeFileCreateInstallation, _linux_filesystem_type
from phase_tool.mutation.ntfs import input_stage, preparation
from phase_tool.streaming import MECHANISM_ID

from .test_native_input_stage_protocol import IDENTITY, record
from .test_native_staged_bundle_verify_only_linux import require_pre_core_rejection


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='real Linux staged File fingerprint boundary')
BODY = b'staged-input-payload\n'
TIMESTAMP = '2026-11-11T00:00:00Z'


def setup_case(tmp_path, monkeypatch, role='File2'):
    prep = tmp_path/'preparation'
    evidence = tmp_path/'evidence'
    result = tmp_path/'result-projection'
    prep.mkdir()
    evidence.mkdir()
    assert _linux_filesystem_type(prep) == 'ext4'
    roots = {'phase_result_root': result}
    manifest = {'root_projections': {'phase_result_root': str(result)}, 'evidence_root': str(evidence)}
    registry = object()
    installation = object.__new__(_NativeFileCreateInstallation)
    installation.read_binding = SimpleNamespace(registry=registry)
    installation.authority = SimpleNamespace(_execution_required=lambda: None)
    namespace_calls = []

    def check_namespace(owner, **kwargs):
        assert owner is installation
        assert kwargs == {'root_bindings': roots, 'evidence_root': evidence, 'maximum_candidate_bytes': 1024**2}
        namespace_calls.append(owner)
        return manifest

    monkeypatch.setattr(_NativeFileCreateInstallation, '_check_preparation_namespace', check_namespace)
    app = SimpleNamespace(installation=installation, registry=registry)
    launch = SimpleNamespace(run_id='file-verify-component', installation_digest=digest_bytes(b'model manifest'),
                             channel_id='1'*32, operation_nonce='2'*32, manifest=manifest)
    scope = {'scope_id':'file.inputs','root_identity':IDENTITY,'preparation_root':str(prep)}
    scope_digest = digest_bytes(canonical_bytes(scope))

    def scope_for_launch(actual):
        assert actual is launch
        return scope, role, scope_digest

    monkeypatch.setattr(input_stage, '_scope_for_launch', scope_for_launch)
    header = input_stage._header(launch, scope, role, scope_digest,
                                 input_stage._stage_request(scope['scope_id'], 'source.bin'), [record('payload', BODY)])
    header_digest = digest_bytes(header)
    staged = 'phase-native-input-'+header_digest[7:39]
    locator = staged+'/payload/payload'
    source = prep/locator
    source.parent.mkdir(parents=True)
    source.write_bytes(BODY)
    marker = {'native_prepared_input_version':'1.0','header_digest':header_digest,'payload_kind':'file',
              'source_locator':locator,'expected_digest':digest_bytes(BODY),'expected_length':len(BODY),'member_count':1,
              'total_length':len(BODY),'members':[{'path':'payload','length':len(BODY),'digest':digest_bytes(BODY)}],
              'source_header':parse_json_bytes(header),'telemetry_stage':'PRE_RETURN_PREPARATION_DATA','final_acceptance':None}
    marker_path = prep/staged/'input-stage.json'
    marker_path.write_bytes(canonical_bytes(marker))
    request = input_stage._staged_publication_request(role=role, prepared=marker, input_scope=scope['scope_id'],
        request_id='file-small', target_locator='result.bin', members=None,
        expected_current_digest=digest_bytes(b'previous') if role=='Version2' else None,
        content_utf8=BODY.decode() if role=='Version2' else None)
    return SimpleNamespace(role=role,app=app,launch=launch,request=request,prep=prep,evidence=evidence,result=result,
                           source=source,marker=marker,marker_path=marker_path,namespace_calls=namespace_calls)


@pytest.fixture(params=['File1','File2'])
def staged_file(request,tmp_path,monkeypatch):
    return setup_case(tmp_path,monkeypatch,request.param)


def prepare(case):
    return preparation._prepare_staged_publication(case.app,case.launch,case.request)


def frozen_core_input(case, inputs):
    # Execute the existing capture function the Core itself calls. Test the
    # frozen tuple at the handoff boundary without entering Core.run/Worker.
    mechanism = 'mechanism.exclusive_create_v1' if case.role == 'File1' else MECHANISM_ID
    contract = {'operation': {'mechanism':{'id':mechanism}},
                'input_bindings':[{'id':'payload','required':True,'freeze_strategy':'copy_and_hash'}]}
    frozen = freeze_declared_inputs(contract,{},inputs,{},case.evidence/'blobs',
                                    frozen_at=TIMESTAMP,maximum_structured_bytes=1024**2)['payload']
    assert frozen.streamed is (case.role == 'File2')
    return frozen


def check_stage(case):
    return tuple((item.stat().st_ino,item.read_bytes()) for item in (case.source,case.marker_path))


def test_file_reuses_retained_stage_and_core_owns_distinct_blob(staged_file):
    case = staged_file
    before = check_stage(case)
    path, inputs, expected, raw = prepare(case)
    assert path.read_bytes() == raw and tuple(path.parent.iterdir()) == (path,)
    assert inputs == {'payload':case.source} and expected == {'payload':(digest_bytes(BODY),len(BODY))}
    assert len(case.namespace_calls) == 2 and check_stage(case) == before and not list(case.evidence.iterdir())
    frozen = frozen_core_input(case,inputs)
    revalidate_frozen(frozen)
    assert (frozen.digest,frozen.length) == expected['payload'] and frozen.blob_path.read_bytes() == BODY
    assert frozen.blob_path.stat().st_ino != before[0][0]
    assert check_stage(case) == before and not case.result.exists()


@pytest.mark.parametrize(('body','code'), [(BODY[:-2]+b'X\n','input_stage.preparation_digest_mismatch'),
    (BODY[:-1],'input_stage.preparation_digest_mismatch'),(BODY+b'x','input_stage.preparation_digest_mismatch'),
    (BODY+b'xx','stream.limit_exceeded')])
def test_file_rejects_wrong_content_and_preserves_physical_limit_order(staged_file,monkeypatch,body,code):
    case = staged_file
    monkeypatch.setattr(input_stage,'_role_bounds',lambda role: (1,len(BODY)+1,len(BODY)+1))
    case.source.write_bytes(body)
    with pytest.raises(PhaseError) as caught:
        prepare(case)
    expected = 'freeze.input_too_large' if case.role == 'File1' and code == 'stream.limit_exceeded' else code
    assert caught.value.code == expected
    require_pre_core_rejection(caught.value)
    assert case.source.read_bytes() == body and not list(case.evidence.iterdir()) and not case.result.exists()


@pytest.mark.parametrize('swap',['missing','leaf-link','parent-link'])
def test_file_rejects_absent_or_redirected_stage_member(staged_file,tmp_path,swap):
    case = staged_file
    sentinel = tmp_path/'outside'
    sentinel.mkdir()
    (sentinel/'payload').write_bytes(BODY)
    path = case.source.parent if swap == 'parent-link' else case.source
    parked = path.with_name(path.name+'-retained')
    path.rename(parked)
    if swap != 'missing':
        os.symlink(sentinel if swap == 'parent-link' else sentinel/'payload',path)
    with pytest.raises(PhaseError) as caught:
        prepare(case)
    assert caught.value.code == ('path.not_found' if swap == 'missing' else 'path.link_forbidden')
    require_pre_core_rejection(caught.value)
    assert parked.exists() and (sentinel/'payload').read_bytes() == BODY and not case.result.exists()
    assert not list(case.evidence.iterdir())


def test_file_after_verification_rebind_has_different_core_tuple(staged_file):
    case = staged_file
    _,inputs,expected,_ = prepare(case)
    parked = case.source.with_name('payload-retained')
    case.source.rename(parked)
    changed = BODY[:-2]+b'X\n'
    case.source.write_bytes(changed)
    frozen = frozen_core_input(case,inputs)
    assert (frozen.digest,frozen.length) == (digest_bytes(changed),len(BODY)) != expected['payload']
    assert parked.read_bytes() == BODY and not case.result.exists()


def test_inline_version2_keeps_existing_scratch_capture(tmp_path,monkeypatch):
    case = setup_case(tmp_path,monkeypatch,'Version2')
    before = check_stage(case)
    path,inputs,expected,_ = prepare(case)
    copied = path.parent/digest_bytes(BODY)[7:]
    assert copied.read_bytes() == BODY and check_stage(case) == before
    assert inputs == expected == {}
