"""Static correlation and actual ext4 RO fixtures; never native admission.

No Core native execution, successful guard mock, worker, target write or GO.
Synthetic manifests/intents are structural claims, not installation credentials.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.installation import (_resolve_native_file_create_read_binding,
    _linux_filesystem_type, qualify_host_authority_roots)
from phase_tool.mutation.ntfs import reader
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers


def manifest_for(intent, evidence_root):
    native=intent['native_binding'];implementation=intent['implementation_binding']
    return {'native_read_installation_version':'1.0', 'installation_id':native['installation']['id'],
        'core':deepcopy(intent['core']), 'contract':deepcopy(intent['contract']),
        'registry_snapshot_digest':intent['registry_snapshot_digest'],
        'authority':deepcopy(implementation['authority']), 'mechanism':deepcopy(implementation['mechanism']),
        'composition':deepcopy(native['composition']), 'evidence_root':str(evidence_root),
        'evidence_identity':deepcopy(native['evidence_identity']),
        'root_grants':deepcopy(intent['idempotency']['root_identities'])}


class StaticNativeReadBindingTests(unittest.TestCase):
    def setUp(self):
        self.registry=BundledRegistry.load()
        self.intent,_,_,_,_=buffers(self.registry)
        self.manifest=manifest_for(self.intent,'/synthetic/evidence')

    def resolve(self, raw=None, **changes):
        raw=canonical_bytes(self.manifest) if raw is None else raw
        args={'manifest_bytes':raw,'expected_manifest_digest':digest_bytes(raw),'registry':self.registry}
        args.update(changes)
        return _resolve_native_file_create_read_binding(**args)

    def assert_code(self,code,**changes):
        with self.assertRaises(PhaseError) as caught:self.resolve(**changes)
        self.assertEqual(caught.exception.code,code)

    def test_exact_static_configuration_is_frozen_without_reading_or_authority(self):
        with patch.object(reader,'read_original_file_create_buffers') as read:
            binding=self.resolve()
            read.assert_not_called()
        self.assertEqual(binding.manifest_bytes,canonical_bytes(self.manifest))
        self.assertEqual(binding.manifest_digest,digest_bytes(binding.manifest_bytes))
        self.assertIs(binding.registry,self.registry)
        with self.assertRaises(FrozenInstanceError):binding.manifest_bytes=b'{}'
        for method in ('execute','dispatch','write','grant_go','qualify_authority_roots'):
            self.assertFalse(hasattr(binding,method))
        self.assertNotIn('operation_nonce',self.manifest)
        self.assertNotIn('effect_plan_digest',self.manifest)
        self.assertNotIn('descriptor_digest',self.manifest)

    def test_external_manifest_hash_and_immutable_bound_precede_json(self):
        self.assert_code('ntfs.original_installation_digest_mismatch',expected_manifest_digest='sha256:'+'f'*64)
        for value in (True,None,'f'*64,'sha256:'+'A'*64):
            with self.subTest(value=value):self.assert_code('ntfs.original_installation_digest_required',expected_manifest_digest=value)
        for value in (bytearray(canonical_bytes(self.manifest)), b' '*(2*1024**2+1)):
            with self.subTest(length=len(value)):self.assert_code('ntfs.original_installation_bytes_required',raw=value)
        self.assert_code('ntfs.original_registry_required',registry=self.registry.to_document())

    def test_noncanonical_closed_versioned_manifest_rejects_with_rebound_hash(self):
        self.assert_code('ntfs.original_installation_shape',raw=canonical_bytes(self.manifest)+b'\n')
        original=deepcopy(self.manifest)
        for key,value in [('extra',True),('native_read_installation_version','2.0'),
            ('operation_nonce','a'*32),('effect_plan_digest','sha256:'+'0'*64),
            ('descriptor_digest','sha256:'+'0'*64),('command',['arbitrary'])]:
            with self.subTest(key=key):
                self.manifest=deepcopy(original);self.manifest[key]=value
                if key=='native_read_installation_version':
                    self.assert_code('ntfs.original_installation_version_unsupported')
                else:
                    with self.assertRaises(ValidationError):self.resolve()
        self.manifest=deepcopy(original);del self.manifest['installation_id']
        with self.assertRaises(ValidationError):self.resolve()

    def test_registry_and_exact_contract_package_are_required(self):
        self.manifest['registry_snapshot_digest']='sha256:'+'f'*64
        self.assert_code('ntfs.original_registry_mismatch')
        self.manifest['registry_snapshot_digest']=self.registry.digest
        self.manifest['contract']['package_digest']='sha256:e3231b5f97bb49c499a82fd1d003ddde081c9cbe31b7b10b87435526c1e15870'
        self.assert_code('intent.schema_unbound')
        self.manifest['contract']['id']='bundle_create.v1'
        self.assert_code('ntfs.original_single_effect_required')

    def test_exact_binding_shapes_reject_before_package_resolution(self):
        original=deepcopy(self.manifest)
        for key,value in [('core',None),('contract',{}),('core',{**original['core'],'version':True}),
            ('contract',{**original['contract'],'extra':True})]:
            with self.subTest(key=key,value=value):
                self.manifest=deepcopy(original);self.manifest[key]=value
                self.assert_code('ntfs.original_installation_shape')

    def test_pinned_nested_shapes_and_existing_full_identity_checks_are_reused(self):
        original=deepcopy(self.manifest)
        for mutate in (
            lambda m:m['composition'].update(extra=True),
            lambda m:m['authority']['provider'].update(extra=True),
            lambda m:m['authority'].update(provider=None),
            lambda m:m['root_grants'][0]['native_identity'].update(file_id='1'*16),
            lambda m:m['root_grants'][0]['native_identity'].update(volume_serial=2**64),
            lambda m:m['root_grants'][0].update(volume_serial32=True),
            lambda m:m['evidence_identity'].update(inode=True),
            lambda m:m['root_grants'][0].update(components=['CON']),
        ):
            self.manifest=deepcopy(original);mutate(self.manifest)
            with self.assertRaises((PhaseError,ValidationError)):self.resolve()

    def test_lexical_linux_evidence_root_and_contract_native_root_scope_are_closed(self):
        for root in ('relative','/','/a/../b','/a//b','/a/./b','/a/b/',r'C:\synthetic'):
            with self.subTest(root=root):
                self.manifest['evidence_root']=root
                self.assert_code('ntfs.original_evidence_root_required')
        self.manifest['evidence_root']='/synthetic/evidence'
        self.manifest['root_grants'][0]['root_binding']='phase_input_root'
        self.assert_code('ntfs.original_root_binding_mismatch')

    def test_existing_mechanism_and_provider_backed_shape_are_required(self):
        self.manifest['mechanism']['package_digest']='sha256:'+'f'*64
        self.assert_code('ntfs.original_implementation_mismatch')
        self.manifest['mechanism']=deepcopy(self.intent['operation']['mechanism'])
        self.manifest['authority']={'usage':'mechanism_managed','profile':None,'provider':None}
        self.assert_code('ntfs.original_implementation_mismatch')

    def test_registry_drift_after_resolution_rejects_before_any_reader_call(self):
        binding=self.resolve();self.registry.digest='sha256:'+'f'*64
        with patch.object(reader,'read_original_file_create_buffers') as read:
            with self.assertRaisesRegex(PhaseError,'ntfs.original_registry_mismatch'):
                binding.read(run_id=self.intent['run_id'],intent_digest=profile_digest('intent',self.intent))
            read.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: Linux/ext4 component required')
class StaticNativeReadBindingExt4Tests(unittest.TestCase):
    def setUp(self):
        temporary=TemporaryDirectory(prefix='phase-static-reader-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'evidence';self.root.mkdir()
        try:
            qualify_host_authority_roots({'phase_evidence_root':self.root})
            filesystem=_linux_filesystem_type(self.root)
        except PhaseError as error:self.skipTest('NOT_VERIFIED: actual qualification unavailable: '+error.code)
        if filesystem!='ext4':self.skipTest('NOT_VERIFIED: actual evidence filesystem is '+filesystem)
        self.registry=BundledRegistry.load()
        self.intent,self.plan,self.pre,self.content,_=buffers(self.registry)
        info=self.root.stat()
        self.intent['native_binding']['evidence_identity']={'stable_id':'synthetic.static.ext4','device':info.st_dev,'inode':info.st_ino}
        self.manifest=manifest_for(self.intent,self.root)
        raw=canonical_bytes(self.manifest)
        self.binding=_resolve_native_file_create_read_binding(manifest_bytes=raw,expected_manifest_digest=digest_bytes(raw),registry=self.registry)
        self.intent['native_binding']['installation']['descriptor_digest']=digest_bytes(raw)
        self.run=self.root/'.phase'/'runs'/self.intent['run_id']
        self.paths=(self.run/'intent.json',self.run/'attachments'/'effect-plan.json',
            self.run/'attachments'/'pre-validator-results.json',self.run/'blobs'/digest_bytes(self.content).removeprefix('sha256:'))
        for p in self.paths:p.parent.mkdir(parents=True,exist_ok=True)
        self.refresh()

    def refresh(self):
        self.intent['effect_plan_digest']=profile_digest('effect-plan',self.plan)
        self.intent['implementation_binding']['effect_plan_digest']=self.intent['effect_plan_digest']
        self.intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(self.plan))
        self.intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(self.pre))
        for p,raw in zip(self.paths,(canonical_bytes(self.intent),canonical_bytes(self.plan),canonical_bytes(self.pre),self.content)):
            p.write_bytes(raw)

    def read(self):return self.binding.read(run_id=self.intent['run_id'],intent_digest=profile_digest('intent',self.intent))

    def inventory(self):return {p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def test_one_static_manifest_reuses_reader_and_parser_without_writes_or_dynamic_configuration(self):
        frozen_manifest=self.binding.manifest_bytes
        for nonce,plan_id in [('a'*32,'plan.synthetic.first'),('b'*32,'plan.synthetic.second')]:
            self.intent['native_binding']['operation_nonce']=nonce;self.plan['plan_id']=plan_id;self.refresh()
            before=self.inventory()
            with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as read:
                parsed=self.read()
            self.assertEqual(parsed.content_bytes,self.content)
            context=parse_json_bytes(parsed.context_bytes)
            self.assertEqual(context['operation_nonce'],nonce)
            self.assertEqual(context['effect_plan_digest'],profile_digest('effect-plan',self.plan))
            self.assertEqual(context['installation_digest'],digest_bytes(frozen_manifest))
            self.assertEqual([call.args[0] for call in read.call_args_list],list(self.paths))
            self.assertEqual(before,self.inventory())
            self.assertEqual(self.binding.manifest_bytes,frozen_manifest)

    def test_static_original_claim_drift_never_returns_parsed_task(self):
        original=deepcopy(self.intent)
        for mutate in (
            lambda i:i['core'].update(package_digest='sha256:'+'f'*64),
            lambda i:i['native_binding']['installation'].update(id='synthetic.other'),
            lambda i:i['native_binding']['installation'].update(descriptor_digest='sha256:'+'f'*64),
            lambda i:i['native_binding']['composition'].update(artifact_graph_digest='sha256:'+'f'*64),
            lambda i:i['implementation_binding']['authority']['provider'].update(artifact_digest='sha256:'+'f'*64),
            lambda i:i['idempotency']['root_identities'][0]['native_identity'].update(file_id='f'*32),
        ):
            self.intent=deepcopy(original);mutate(self.intent);self.refresh();before=self.inventory()
            with self.assertRaisesRegex(PhaseError,'ntfs.original_(installation_binding|installed_roots)_mismatch'):
                self.read()
            self.assertEqual(before,self.inventory())

    def test_unchanged_parser_still_rejects_rebound_false_preconditions(self):
        self.pre[3]['actual']='present';self.refresh();before=self.inventory()
        with self.assertRaisesRegex(ValueError,'result content'):self.read()
        self.assertEqual(before,self.inventory())

    def test_unmatched_static_manifest_digest_cannot_read_evidence(self):
        with patch.object(reader,'read_original_file_create_buffers') as read:
            with self.assertRaisesRegex(PhaseError,'ntfs.original_installation_digest_mismatch'):
                _resolve_native_file_create_read_binding(manifest_bytes=canonical_bytes(self.manifest),
                    expected_manifest_digest='sha256:'+'f'*64,registry=self.registry)
            read.assert_not_called()


if __name__=='__main__':unittest.main()
