"""Actual disposable Host plans plus EXPLICIT synthetic native original claims.

The native parser and saved-result verifier are real. Reusing a Host plan does
not authenticate a native installation, original producer, roots, durability,
worker, admission or G01. No native authority is constructed or guard patched.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes,canonical_digest,digest_bytes,parse_json_bytes,profile_digest
from phase_tool.core import PhaseCore
from phase_tool.errors import PhaseError
from phase_tool.installation import _native_lifecycle_registry,_native_registry_for_manifest
from phase_tool.mutation.ntfs.intent import parse_original_version1,validate_planned_version1_original,parse_original_file_create
from phase_tool.mutation.ntfs.handoff import ParsedNativeVersion1
from phase_tool.preconditions import verify_saved_precondition_results
from phase_tool.registry import BundledRegistry
from .test_native_intent_v12 import fixture as native_claims
from .test_publish_new_version import _request


@contextmanager
def original_fixture(content=b'new synthetic payload'):
    registry=_native_lifecycle_registry()
    binding=registry.contract_bindings()['publish_new_version.v1@1.0.0']
    with TemporaryDirectory(prefix='phase-version1-original-') as directory:
        request,target,_,current,before,_=_request(Path(directory),run_id='version1-original',after=content)
        request=replace(request,contract_digest=binding['package_digest'])
        # Genuine Host lifecycle and saved validators, before the explicit
        # synthetic view below. Target bytes remain the original Host fixture.
        outcome=PhaseCore(registry=registry).run(request,execute=False)
        assert outcome.exit_code==0 and outcome.receipt['terminal_status']=='validated_planned'
        assert current.read_bytes()==before
        intent=deepcopy(outcome.intent);plan=deepcopy(outcome.effect_plan)
        raw=(request.evidence_root/'.phase'/'runs'/request.run_id/'attachments'/'validator-results.json').read_bytes()
        pre=parse_json_bytes(raw)
        shell=native_claims(BundledRegistry.load())
        roots=deepcopy(shell['idempotency']['root_identities'])
        roots[0]['root_binding']='fixture_result_root'
        intent.update(phase_intent_version='1.2',execution_requested=True,native_binding=shell['native_binding'])
        intent['implementation_binding']=deepcopy(shell['implementation_binding'])
        intent['implementation_binding']['mechanism']=deepcopy(plan['mechanism'])
        root_digest=profile_digest('native-root-identity-v1',roots)
        candidate=intent['candidate']['storage']['value']
        scope={'contract':intent['contract'],'result_locator':candidate['target_locator'],
            'root_identity_digest':root_digest,'operation_intent':'publish_new_version'}
        intent['idempotency'].update(root_identities=roots,root_identity_digest=root_digest,
            scope_digest=profile_digest('idempotency-scope',scope),
            request_digest=profile_digest('request',{'scope':scope,'candidate_digest':intent['candidate']['digest'],'inputs':intent['inputs']}))
        yield registry,intent,plan,pre,content


def arguments(registry,intent,plan,pre,content):
    intent=deepcopy(intent)
    intent['effect_plan_digest']=profile_digest('effect-plan',plan)
    intent['implementation_binding']['effect_plan_digest']=intent['effect_plan_digest']
    intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(plan))
    intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(pre))
    return dict(intent_bytes=canonical_bytes(intent),plan_bytes=canonical_bytes(plan),
        pre_validator_bytes=canonical_bytes(pre),blob_bytes=content,registry=registry,
        expected_run_id=intent['run_id'],expected_intent_digest=profile_digest('intent',intent),
        installed_core_binding=canonical_bytes(intent['core']),
        installed_native_binding=canonical_bytes(intent['native_binding']),
        installed_root_grants=canonical_bytes(intent['idempotency']['root_identities']),
        installed_implementation_binding=canonical_bytes(intent['implementation_binding']))


@unittest.skipUnless(sys.platform.startswith('linux'),'Host fixture scope requires Linux')
class Version1OriginalTests(unittest.TestCase):
    def test_real_host_saved_claims_and_native_full_binding_parse_zero_and_large_tail(self):
        for content in (b'',b'x'*(1024**2)+b'tail',b'x'*(16*1024**2-1)+b'z'):
            with self.subTest(length=len(content)),original_fixture(content) as values:
                parsed=parse_original_version1(**arguments(*values))
                self.assertIs(type(parsed),ParsedNativeVersion1)
                self.assertEqual(parsed.content_bytes,content)
                effect=parse_json_bytes(parsed.effect_bytes)
                self.assertEqual(effect['content_digest'],digest_bytes(content))
                self.assertEqual(effect['target']['root_binding'],'fixture_result_root')
                self.assertEqual(effect['archive_target']['root_binding'],'fixture_result_root')

    def test_planned_original_is_not_an_executing_original(self):
        with original_fixture() as values:
            registry,intent,plan,pre,content=values
            intent=deepcopy(intent);intent['execution_requested']=False
            args=arguments(registry,intent,plan,pre,content)
            self.assertIsNone(validate_planned_version1_original(**args))
            with self.assertRaisesRegex(PhaseError,'ntfs.original_execution_binding_mismatch'):
                parse_original_version1(**args)

    def test_rehashed_native_plan_cannot_change_archive_identity_or_effect_semantics(self):
        changes=[('archive_length',True),('archive_digest','sha256:'+'f'*64),
            ('archive_target',{'root_binding':'fixture_result_root','relative_locator':'other'}),
            ('request_digest','sha256:'+'f'*64),('ordinal',True),('operation_identity','other')]
        with original_fixture() as values:
            registry,intent,plan,pre,content=values
            for field,bad in changes:
                with self.subTest(field=field):
                    changed=deepcopy(plan);changed['effects'][0][field]=bad
                    with self.assertRaises((PhaseError,ValidationError,ValueError)):
                        parse_original_version1(**arguments(registry,intent,changed,pre,content))

    def test_real_saved_preconditions_reject_changed_states_after_outer_hash_rebinding(self):
        with original_fixture() as values:
            registry,intent,plan,pre,content=values
            index=next(i for i,row in enumerate(pre) if row['validator']['id']=='publish_new_version.preconditions_v1')
            for field,bad in [('exists',False),('digest','sha256:'+'f'*64),('length',True)]:
                with self.subTest(field=field):
                    changed=deepcopy(pre);changed[index]['actual']['current'][field]=bad
                    with self.assertRaises((PhaseError,ValidationError,ValueError)):
                        parse_original_version1(**arguments(registry,intent,plan,changed,content))

    def test_full_payload_hash_checks_tail_and_file1_role_separation(self):
        with original_fixture(b'x'*(1024**2)+b'z') as values:
            args=arguments(*values)
            with self.assertRaisesRegex(PhaseError,'ntfs.original_content_binding_mismatch'):
                parse_original_version1(**(args|{'blob_bytes':args['blob_bytes'][:-1]+b'y'}))
            with self.assertRaisesRegex(PhaseError,'mechanism.content_too_large'):
                parse_original_version1(**(args|{'blob_bytes':b'x'*(16*1024**2+1)}))
            # Exact role mismatch refuses; this is not a new file1 size allowance.
            with self.assertRaises(PhaseError):parse_original_file_create(**args)

    def test_static_registry_selector_has_only_two_fixed_generations_and_exact_bytes(self):
        registry=_native_lifecycle_registry()
        document={'native_read_installation_version':'1.2','registry_snapshot_digest':registry.digest}
        raw=canonical_bytes(document)
        self.assertEqual(_native_registry_for_manifest(raw,digest_bytes(raw)).digest,registry.digest)
        for altered in (raw+b' ',canonical_bytes(document|{'native_read_installation_version':'1.3'}),
                        canonical_bytes(document|{'registry_snapshot_digest':'sha256:'+'f'*64})):
            with self.subTest(raw=altered),self.assertRaises(PhaseError):
                _native_registry_for_manifest(altered,digest_bytes(altered))
        with self.assertRaises(PhaseError):_native_registry_for_manifest(raw,'sha256:'+'f'*64)

    def test_new_generation_real_guard_refuses_before_read_binding_channel_or_evidence(self):
        from unittest.mock import patch
        from phase_tool import installation,evidence
        from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3
        registry=_native_lifecycle_registry()
        raw=canonical_bytes({'native_read_installation_version':'1.2','registry_snapshot_digest':registry.digest})
        with (patch.object(installation,'_resolve_native_file_create_read_binding',side_effect=AssertionError('read binding reached')) as binding,
              patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel reached')) as channel,
              patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('store reached')) as store):
            with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                installation._native_lifecycle_installation(manifest_bytes=raw,expected_manifest_digest=digest_bytes(raw),
                    run_id='synthetic-no-go',operation_nonce='a'*32,channel_id='b'*32)
            binding.assert_not_called();channel.assert_not_called();store.assert_not_called()
