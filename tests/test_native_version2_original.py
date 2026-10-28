"""Real disposable Host/Core plan and captured blob, synthetic native claims.

No native authority, guard override or Windows effect. Linux scope only.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from importlib.resources import files
from tempfile import TemporaryDirectory
import sys
import unittest

from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.core import PhaseCore
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_experimental_version2_registry,_native_registry_for_manifest
from phase_tool.mutation.ntfs.intent import parse_original_version2,validate_planned_version2_original,parse_original_version1
from phase_tool.mutation.ntfs.handoff import ParsedNativeVersion2
from phase_tool.registry import BundledRegistry
from .test_native_intent_v12 import fixture as native_claims
if sys.platform.startswith('linux'):
    from .test_native_version1_original import arguments


@contextmanager
def original_fixture(content='new synthetic UTF-8'):
    from .test_publish_new_version_v2 import _request
    registry=_native_experimental_version2_registry()
    binding=registry.contract_bindings()['publish_new_version.v2@1.0.0']
    with TemporaryDirectory(prefix='phase-version2-original-') as directory:
        request,_,_,_,current=_request(Path(directory),run_id='version2-original',before=b'old synthetic',content=content)
        request=replace(request,contract_digest=binding['package_digest'])
        outcome=PhaseCore(registry=registry).run(request,execute=False)
        assert outcome.exit_code==0 and outcome.receipt['terminal_status']=='validated_planned'
        assert current.read_bytes()==b'old synthetic'
        intent,plan=deepcopy(outcome.intent),deepcopy(outcome.effect_plan)
        run=request.evidence_root/'.phase'/'runs'/request.run_id
        pre=parse_json_bytes((run/'attachments'/'validator-results.json').read_bytes())
        payload=content.encode('utf-8')
        assert (run/'blobs'/digest_bytes(payload)[7:]).read_bytes()==payload
        shell=native_claims(BundledRegistry.load())
        roots=[]
        for role,leaf,identifier in [('current_root','current','a'),('objects_root','objects','b')]:
            row=deepcopy(shell['idempotency']['root_identities'][0])
            row['root_binding']=role;row['components']+= [leaf]
            row['native_identity']['file_id']=identifier*32
            roots.append(row)
        intent.update(phase_intent_version='1.2',execution_requested=True,native_binding=shell['native_binding'])
        intent['implementation_binding']=deepcopy(shell['implementation_binding'])
        intent['implementation_binding']['mechanism']=deepcopy(plan['mechanism'])
        root_digest=profile_digest('native-root-identity-v1',roots)
        value=intent['candidate']['storage']['value']
        scope={'contract':intent['contract'],'result_locator':value['target_locator'],
            'root_identity_digest':root_digest,'operation_intent':'publish_new_version'}
        intent['idempotency'].update(root_identities=roots,root_identity_digest=root_digest,
            scope_digest=profile_digest('idempotency-scope',scope),request_digest=profile_digest('request',{
                'scope':scope,'candidate_digest':intent['candidate']['digest'],'inputs':intent['inputs']}))
        yield registry,intent,plan,pre,payload


class Version2AdmissionBoundaryTests(unittest.TestCase):
    def test_historical_authority_artifact_is_the_exact_original_file(self):
        from phase_tool.installation import _native_shared_history_registry
        registry=_native_shared_history_registry()
        bindings=registry.guarantee_profile_bindings()
        keys=[key for key in bindings if key.startswith('phase.native.ntfs.candidate.authority.v5@')]
        self.assertEqual(len(keys),1)
        descriptor=registry.resolve_guarantee_profile(bindings[keys[0]])
        raw=files('phase_tool').joinpath('mutation','ntfs','authority.py').read_bytes()
        self.assertEqual(len(raw),30346)
        self.assertEqual(digest_bytes(raw),'sha256:a568ea8fe3a05369e044725f6f12f8b803b076206ddeb9d8d777944f0bffde13')
        self.assertEqual(descriptor['implementation']['artifact_digest'],digest_bytes(raw))

    def test_new_provider_generation_matches_artifact_and_preserves_v1(self):
        registry=_native_experimental_version2_registry();bindings=registry.guarantee_profile_bindings()
        old=registry.resolve_guarantee_profile(bindings['phase.native.ntfs.experiment.version2.authority.v1@1.0.0'])
        new=registry.resolve_guarantee_profile(bindings['phase.native.ntfs.experiment.version2.authority.v2@1.0.0'])
        old_raw=files('phase_tool').joinpath('mutation','ntfs','experimental_version2_authority.py').read_bytes()
        new_raw=files('phase_tool').joinpath('mutation','ntfs','experimental_version2_authority_v2.py').read_bytes()
        self.assertEqual(digest_bytes(old_raw),'sha256:e7c91eb99777202de8f4e8fc8e684695da1b1e6aafe0616e0fe1180421ae4464')
        self.assertEqual(old['implementation']['artifact_digest'],digest_bytes(old_raw))
        self.assertEqual(new['implementation']['artifact_digest'],digest_bytes(new_raw))
        self.assertEqual(new['implementation']['version'],'2.0.0')
        self.assertEqual(new['provided_guarantees'],[])
        self.assertEqual(new['conformance'],[])

    def test_normal_startup_still_refuses_new_experimental_generation(self):
        registry=_native_experimental_version2_registry()
        raw=canonical_bytes({'native_read_installation_version':'1.5','registry_snapshot_digest':registry.digest})
        with self.assertRaisesRegex(PhaseError,'ntfs.original_installation_version_unsupported'):
            _native_registry_for_manifest(raw,digest_bytes(raw))
        # The new registry preserves every historical contract package.
        old=BundledRegistry.load()
        for entry in old.to_document()['entries']:
            if entry.get('kind')=='contract':
                registry.resolve_contract(entry['id'],entry['version'],entry['package_digest'],core_version='1.2.0-rc.1')


@unittest.skipUnless(sys.platform.startswith('linux'),'Actual Host/Core fixture requires Linux')
class Version2OriginalTests(unittest.TestCase):
    def test_rehashed_saved_states_and_post_status_cannot_manufacture_pass(self):
        with original_fixture() as values:
            registry,intent,plan,pre,content=values
            self.assertIs(type(parse_original_version2(**arguments(*values))),ParsedNativeVersion2)
            index=next(i for i,row in enumerate(pre) if row['validator']['id']=='publish_new_version.preconditions_v2')
            changes=[('current','exists',False),('current','digest','sha256:'+'f'*64),
                ('current','length',True),('old_object','length',0),('new_object','exists',True)]
            for name,field,bad in changes:
                with self.subTest(name=name,field=field):
                    changed=deepcopy(pre);changed[index]['actual'][name][field]=bad
                    with self.assertRaises((PhaseError,ValidationError,ValueError)):
                        parse_original_version2(**arguments(registry,intent,plan,changed,content))
            changed=deepcopy(pre);post=next(row for row in changed if row['phase']=='post_operation')
            post.update(status='pass',code='validation.pass',actual='prior_phases_pass')
            with self.assertRaises((PhaseError,ValidationError,ValueError)):
                parse_original_version2(**arguments(registry,intent,plan,changed,content))
            changed=deepcopy(plan);changed['effects'][0]['archive_length']+=1
            with self.assertRaises((PhaseError,ValidationError,ValueError)):
                parse_original_version2(**arguments(registry,intent,changed,pre,content))

    def test_rehashed_inline_lineage_requires_captured_content_without_frozen_input(self):
        with original_fixture() as values:
            registry,intent,plan,pre,content=values
            self.assertIs(type(parse_original_version2(**arguments(*values))),ParsedNativeVersion2)
            for field,bad in [('input_binding','payload'),
                ('content_source',{'kind':'frozen_input','binding_id':'payload','source_digest':digest_bytes(content)}),
                ('content_blob_digest','sha256:'+'f'*64),('content_length',True)]:
                with self.subTest(field=field):
                    changed=deepcopy(plan);changed['effects'][0][field]=bad
                    with self.assertRaises((PhaseError,ValidationError,ValueError)):
                        parse_original_version2(**arguments(registry,intent,changed,pre,content))
            changed=deepcopy(intent);changed['evidence']['content_blob_digests']=['sha256:'+'f'*64]
            with self.assertRaises((PhaseError,ValidationError,ValueError)):
                parse_original_version2(**arguments(registry,changed,plan,pre,content))

    def test_actual_core_blob_and_full_parser_zero_unicode_and_contract_bound(self):
        for content in ('','synthetic \u03b1\n','x'*(512*1024)):
            with self.subTest(length=len(content)),original_fixture(content) as values:
                parsed=parse_original_version2(**arguments(*values))
                self.assertIs(type(parsed),ParsedNativeVersion2)
                self.assertEqual(parsed.content_bytes,content.encode())
                self.assertEqual([r['root_binding'] for r in parse_json_bytes(parsed.grant_bytes)],
                    ['current_root','objects_root'])

    def test_blob_tamper_and_legacy_role_refuse_without_synthetic_frozen_input(self):
        with original_fixture() as values:
            args=arguments(*values)
            self.assertEqual(values[1]['inputs'],[])
            with self.assertRaises(PhaseError):parse_original_version2(**(args|{'blob_bytes':b'wrong'}))
            with self.assertRaises(PhaseError):parse_original_version1(**args)
            registry,intent,plan,pre,content=values
            plan=deepcopy(plan);plan['effects'][0]['content_bytes_b64']=''
            with self.assertRaises((PhaseError,ValidationError)):
                parse_original_version2(**arguments(registry,intent,plan,pre,content))

    def test_planned_wrapper_never_returns_executing_handoff(self):
        with original_fixture() as values:
            registry,intent,plan,pre,content=values
            intent=deepcopy(intent);intent['execution_requested']=False
            args=arguments(registry,intent,plan,pre,content)
            self.assertIsNone(validate_planned_version2_original(**args))
            with self.assertRaises(PhaseError):parse_original_version2(**args)


if __name__=='__main__':unittest.main()
