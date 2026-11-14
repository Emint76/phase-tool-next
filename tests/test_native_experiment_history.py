"""Accepted configuration correlation only; no NTFS/worker/qualification claims."""
import base64
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool import installation,core
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.bootstrap import (_accepted_launch_history,
    _native_history_manifest_buffers,_NativeAcceptedLaunch)
from phase_tool.mutation.ntfs.experimental_history import (
    _ExperimentalHistoryFile1Admission,_ExperimentalHistoryVersion1Admission)
from .test_native_experiment_file1 import experiment_fixture
from .test_native_experiment_version1 import version1_fixture


def history_fixture(request_ids=None):
    registry=installation._native_experimental_history_registry()
    profile=registry.guarantee_profile_bindings()[
        'phase.native.ntfs.experiment.history.authority.v1@1.0.0']
    implementation=registry.resolve_guarantee_profile(profile)['implementation']
    first=experiment_fixture()
    versions=[version1_fixture(),version1_fixture()]
    parts=[(first[0],first[2]),*( (cap,parse_json_bytes(binding.manifest_bytes))
        for cap,binding,*_ in versions)]
    payloads=(b'history zero\n',b'history one\n',b'history two\n')
    names=('history-create','history-version-a','history-version-b')
    request_ids=names if request_ids is None else request_ids
    kinds=(_ExperimentalHistoryFile1Admission,_ExperimentalHistoryVersion1Admission,
        _ExperimentalHistoryVersion1Admission)
    bindings=[]
    for index,((old,manifest),kind,name,payload,key) in enumerate(zip(parts,kinds,names,payloads,request_ids,strict=True)):
        doc=old.document()
        candidate={'operation_id':name,'idempotency_key':key,
            'target_locator':doc['target_locator'],'input_binding':'payload'}
        if index:candidate['expected_current_digest']=digest_bytes(payloads[index-1])
        doc.update(run_id=name,request_id=key,candidate_digest=digest_bytes(canonical_bytes(candidate)),
            payload_digest=digest_bytes(payload),payload_length=len(payload))
        cap=kind(canonical_bytes(doc))
        manifest.update(registry_snapshot_digest=registry.digest,
            installation_id=cap._installation_prefix+cap.digest[7:],
            authority={'usage':'provider_backed','profile':profile,
                'provider':{k:implementation[k] for k in ('id','version','artifact_digest')}})
        raw=canonical_bytes(manifest)
        bindings.append(installation._native_experimental_read_binding(manifest_bytes=raw,
            expected_manifest_digest=digest_bytes(raw),admission=cap))
    return tuple(bindings)


def history_bytes(bindings):
    return canonical_bytes({'history_manifest_set_version':'1.2','manifests':[
        {'manifest_base64':base64.b64encode(row.manifest_bytes).decode(),
            'manifest_digest':row.manifest_digest,
            'experimental_admission_base64':base64.b64encode(row.experimental_admission.raw).decode(),
            'experimental_admission_digest':row.experimental_admission.digest} for row in bindings]})


class ExperimentalHistoryTests(unittest.TestCase):
    def test_new_profile_preserves_old_registry_and_does_not_certify_or_relabel_it(self):
        old=installation._native_experimental_version1_registry()
        new=installation._native_experimental_history_registry()
        self.assertEqual(new.to_document()['entries'][:-1],old.to_document()['entries'])
        self.assertEqual(new.to_document()['trust_roots'],old.to_document()['trust_roots'])
        for selected in history_fixture():
            cap=selected.experimental_admission;profile=cap.profile(selected)
            descriptor=new.resolve_guarantee_profile(profile.as_dict())
            self.assertEqual(descriptor['provided_guarantees'],[])
            self.assertEqual(descriptor['conformance'],[])
            with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                installation._native_qualified_profile(new,profile.as_dict())
            with self.assertRaises(PhaseError):
                installation._native_registry_for_manifest(selected.manifest_bytes,selected.manifest_digest)

    def test_three_per_run_rows_include_two_versions_without_contract_only_ambiguity(self):
        rows=history_fixture();raw=history_bytes(rows)
        with patch.object(installation,'_NativeFileCreateInstallation',side_effect=AssertionError('authority reached')):
            for active in rows:
                history=installation._resolve_native_history_bindings(active,raw,digest_bytes(raw))
                self.assertEqual([r.experimental_admission.document()['run_id'] for r in history],
                    ['history-create','history-version-a','history-version-b'])
                for row in history:
                    selected=installation._native_experimental_history_binding_for_run(
                        history,row.experimental_admission.document()['run_id'])
                    self.assertIs(selected,row)
                self.assertEqual(sum(row.manifest_bytes==active.manifest_bytes for row in history),1)
        with self.assertRaises(PhaseError):
            installation._native_experimental_history_binding_for_run(rows,'unknown-other-key')

    def test_closed_shape_digest_order_and_unique_runs(self):
        rows=history_fixture();active=rows[0]
        for change in ('missing','extra','duplicate','reverse','unknown-version','bad-cap-digest','old-set'):
            value=parse_json_bytes(history_bytes(rows))
            if change=='missing':value['manifests'].pop()
            elif change=='extra':value['manifests'].append(deepcopy(value['manifests'][1]))
            elif change=='duplicate':value['manifests'][2]=deepcopy(value['manifests'][1])
            elif change=='reverse':value['manifests'].reverse()
            elif change=='unknown-version':value['history_manifest_set_version']='99.0'
            elif change=='old-set':value['history_manifest_set_version']='1.1'
            else:value['manifests'][1]['experimental_admission_digest']='sha256:'+'f'*64
            raw=canonical_bytes(value)
            with self.subTest(change=change),self.assertRaises(PhaseError):
                installation._resolve_native_history_bindings(active,raw,digest_bytes(raw))
        raw=history_bytes(rows)
        with self.assertRaises(PhaseError):
            _native_history_manifest_buffers(raw,digest_bytes(raw),
                active_bytes=active.manifest_bytes,active_digest=active.manifest_digest)

    def test_every_shared_domain_dimension_is_checked_after_valid_rebinding(self):
        for field in ('evidence_root','preparation_root','evidence_identity','preparation_identity',
                'composition','windows_root','wheel_digest','target_locator','root_projection','native_id'):
            rows=list(history_fixture());old=rows[2];capdoc=old.experimental_admission.document()
            manifest=parse_json_bytes(old.manifest_bytes)
            if field in ('evidence_root','preparation_root'):manifest[field]+='-other'
            elif field in ('evidence_identity','preparation_identity'):
                manifest[field]['inode']+=101;capdoc[field]=deepcopy(manifest[field])
            elif field=='composition':manifest['composition']['artifact_graph_digest']='sha256:'+'f'*64
            elif field=='windows_root':
                capdoc[field]=capdoc[field].replace('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222')
                capdoc['root_grant']['components'][1]='22222222-2222-4222-8222-222222222222'
                manifest['root_grants']=[deepcopy(capdoc['root_grant'])]
            elif field=='wheel_digest':capdoc[field]='sha256:'+'f'*64
            elif field=='target_locator':capdoc[field]='other.txt'
            elif field=='root_projection':manifest['root_projections']={'fixture_result_root':'/other-target'}
            else:
                identity=capdoc['root_grant']['native_identity']
                identity['file_id']=('a' if identity['file_id'][0]!='a' else 'b')+identity['file_id'][1:]
                manifest['root_grants']=[deepcopy(capdoc['root_grant'])]
            cap=_ExperimentalHistoryVersion1Admission(canonical_bytes(capdoc))
            manifest['installation_id']=cap._installation_prefix+cap.digest[7:]
            raw=canonical_bytes(manifest)
            rows[2]=replace(old,manifest_bytes=raw,manifest_digest=digest_bytes(raw),experimental_admission=cap)
            with self.subTest(field=field),self.assertRaisesRegex(PhaseError,'ntfs.original_history_domain_mismatch'):
                installation._validate_native_history_bindings(rows[0],tuple(rows))

    def test_cap_swap_and_old_standalone_context_never_become_historical_authority(self):
        rows=list(history_fixture());oldcap=version1_fixture()[0]
        for cap in (rows[1].experimental_admission,oldcap):
            changed=replace(rows[2],experimental_admission=cap)
            with self.subTest(cap=type(cap).__name__),self.assertRaises(PhaseError):
                installation._validate_native_history_bindings(rows[0],(rows[0],rows[1],changed))

    def test_admission_does_not_change_keys_or_scope_to_hide_a_core_conflict(self):
        rows=history_fixture(('history-create','same-history-key','same-history-key'))
        raw=history_bytes(rows)
        accepted=installation._resolve_native_history_bindings(rows[0],raw,digest_bytes(raw))
        a,b=(row.experimental_admission.document() for row in accepted[1:])
        self.assertEqual(a['request_id'],b['request_id'])
        self.assertNotEqual(a['candidate_digest'],b['candidate_digest'])
        self.assertEqual(a['root_grant'],b['root_grant'])
        # This permits the unchanged Core conflict check to run. It is not a
        # claim that a native conflict/replay workload has executed here.

    def test_config_requires_explicit_new_context_and_old_formats_stay_closed(self):
        rows=history_fixture();active=rows[0];raw=history_bytes(rows)
        fields=('phase_wheel','phase_wheel_digest','dependency_file_digests','windows_launcher',
            'linux_launcher','docker_executable','core_container_id','reader_container_id',
            'image_digest','linux_python','expected_linux_contours','artifact_graph')
        config={key:None for key in fields}
        config.update(native_launch_version='1.2',history_manifest_set_base64=base64.b64encode(raw).decode(),
            history_manifest_set_digest=digest_bytes(raw))
        self.assertEqual(_accepted_launch_history(config,active.manifest_bytes,active.manifest_digest),
            (raw,digest_bytes(raw)))
        for version in ('1.0','1.1'):
            with self.subTest(version=version),self.assertRaises(PhaseError):
                _accepted_launch_history(config|{'native_launch_version':version},
                    active.manifest_bytes,active.manifest_digest)
        encoded=canonical_bytes(config)
        with self.assertRaisesRegex(PhaseError,'ntfs.experimental_admission_required'):
            _NativeAcceptedLaunch(config_bytes=encoded,expected_config_digest=digest_bytes(encoded),
                manifest_bytes=active.manifest_bytes,expected_manifest_digest=active.manifest_digest,
                invocation_bytes=b'{}')

    def test_history_is_required_at_resolver_installation_and_original_guard(self):
        for row in history_fixture():
            with self.subTest(run=row.experimental_admission.document()['run_id']):
                with self.assertRaisesRegex(PhaseError,'ntfs.accepted_history_binding_mismatch'):
                    installation._resolve_native_history_bindings(row,None,None)
                with self.assertRaisesRegex(PhaseError,'ntfs.original_history_binding_mismatch'):
                    installation._NativeFileCreateInstallation(row,object(),history_bindings=None)
                with patch.object(installation,'_resolve_native_file_create_read_binding',
                        side_effect=AssertionError('root/read stage reached')) as reader:
                    with self.assertRaisesRegex(PhaseError,'ntfs.original_history_binding_mismatch'):
                        with core._guard_native_original_intents(row):self.fail('incomplete history yielded')
                    reader.assert_not_called()

    def test_unselected_history_subclasses_refuse_before_launch_fields_or_registry(self):
        for row in history_fixture()[:2]:
            kind=type('Unselected',(type(row.experimental_admission),),{})
            launch=SimpleNamespace(_experimental_admission_context=kind(row.experimental_admission.raw))
            with patch.object(installation,'_native_experimental_history_registry',
                    side_effect=AssertionError('registry reached')) as registry:
                with self.assertRaisesRegex(PhaseError,'ntfs.experimental_admission_required'):
                    installation._native_read_binding_for_launch(launch)
                registry.assert_not_called()


if __name__=='__main__':unittest.main()
