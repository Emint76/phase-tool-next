"""Immutable candidate selection and real negative Core; no native admission.

Pure resource fixtures grant no authority. Linux tests use concrete unchanged
Host qualification and deliberately have no authority profile. Actual ext4 is
required; a missing fixture is NOT_VERIFIED, never a positive native result.
"""
from copy import deepcopy
import hashlib
from importlib import resources as package_resources
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from phase_tool import __version__, installation as installation_module
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.core import PhaseCore, PhaseRequest
from phase_tool.errors import PhaseError
from phase_tool.evidence import validate_receipt
from phase_tool.installation import (Installation,
    _native_file_create_candidate_registry, _linux_filesystem_type,
    qualify_host_authority_roots)
from phase_tool.mutation.platform import HostAuthorityProvider
from phase_tool.registry import BundledRegistry, RegistrySnapshot


RESOURCE = 'registries/native-file-create-candidate-v1.json'
RAW_DIGEST = 'sha256:fa2a9aff5f576d15b5a71574a11bd3a7a994a38346540ff6d7e7a74335cfa2c7'
OLD = 'sha256:e3231b5f97bb49c499a82fd1d003ddde081c9cbe31b7b10b87435526c1e15870'
NEW = 'sha256:734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09'
BINDING = {'id':'file_create.v1', 'version':'1.0.0', 'package_digest':NEW}


class NativeCandidateRegistryTests(unittest.TestCase):
    def setUp(self):
        self.default = BundledRegistry.load()
        self.resources = BundledRegistry.resources()

    def assert_loader_error(self, code, resources):
        # Faulty package bytes are inputs to a refusal test, never a successful
        # substitution of provider, qualification, registry trust or coverage.
        with patch.object(BundledRegistry, 'resources', return_value=resources):
            with self.assertRaises(PhaseError) as caught:
                _native_file_create_candidate_registry()
        self.assertEqual(caught.exception.code, code)

    def test_new_artifact_is_canonical_pinned_and_distinct_from_unchanged_default(self):
        raw = self.resources[RESOURCE]
        self.assertEqual(digest_bytes(raw), RAW_DIGEST)
        self.assertEqual(canonical_bytes(parse_json_bytes(raw)), raw)
        registry = _native_file_create_candidate_registry()
        self.assertIs(type(registry), RegistrySnapshot)
        self.assertEqual(registry.digest, RAW_DIGEST)
        self.assertNotEqual(registry.digest, self.default.digest)
        old_raw = package_resources.files('phase_tool').joinpath('data/registry.json').read_bytes()
        self.assertEqual(digest_bytes(old_raw),
            'sha256:bdfcd2909c40ab554e0abe5aa7d40fbb7032b9176f96e34293b2b6e90221f41b')
        self.assertEqual(self.default.to_document(), parse_json_bytes(old_raw))

    def test_complete_snapshot_diff_is_exactly_two_current_flags(self):
        original = self.default.to_document()
        expected = deepcopy(original)
        self.assertEqual(len(expected['entries']), 139)
        changed = []
        for entry in expected['entries']:
            if (entry.get('kind'),entry.get('id'),entry.get('version')) != ('contract','file_create.v1','1.0.0'):
                continue
            if entry['package_digest'] == OLD:
                self.assertIs(entry['current'], True)
                entry['current'] = False; changed.append(OLD)
            elif entry['package_digest'] == NEW:
                self.assertIs(entry['current'], False)
                entry['current'] = True; changed.append(NEW)
        self.assertEqual(sorted(changed), sorted([OLD,NEW]))
        registry = _native_file_create_candidate_registry()
        self.assertEqual(registry.to_document(), expected)
        self.assertEqual(self.default.to_document(), original)
        self.assertEqual(registry.to_document()['trust_roots'], original['trust_roots'])

    def test_other_current_contracts_profiles_and_every_existing_resource_are_unchanged(self):
        registry = _native_file_create_candidate_registry()
        expected = self.default.contract_bindings()
        self.assertEqual(expected['file_create.v1@1.0.0']['package_digest'], OLD)
        expected['file_create.v1@1.0.0'] = BINDING
        self.assertEqual(registry.contract_bindings(), expected)
        self.assertEqual(registry.guarantee_profile_bindings(), self.default.guarantee_profile_bindings())
        for name, raw in self.resources.items():
            with self.subTest(resource=name):
                self.assertEqual(registry.resource_bytes(name), raw)
        # This one new package resource is unreferenced by the old registry;
        # no historical descriptor is rewritten to refer to it.
        self.assertNotIn(RESOURCE, json.dumps(self.default.to_document()))

    def test_exact_resolver_still_verifies_both_historical_generations_and_core_compatibility(self):
        registry = _native_file_create_candidate_registry()
        for pin in (OLD,NEW):
            with self.subTest(package_digest=pin):
                old = self.default.resolve_contract('file_create.v1','1.0.0',pin,core_version=__version__)
                new = registry.resolve_contract('file_create.v1','1.0.0',pin,core_version=__version__)
                self.assertEqual(new.document, old.document)
                self.assertEqual(new.package_digest, pin)
                self.assertEqual(new.registry_snapshot_digest, registry.digest)
                mechanism = new.document['operation']['mechanism']
                self.assertEqual(dict(registry.resolve_mechanism(mechanism)), dict(self.default.resolve_mechanism(mechanism)))
        resource = 'schemas/phase-intent-1.2.schema.json'
        exact = registry.resolve_contract('file_create.v1','1.0.0',NEW,core_version=__version__)
        pin = next(row['digest'] for row in exact.entry['package_artifacts'] if row['resource']==resource)
        self.assertEqual(registry.schema_document('https://phase-tool.local/'+resource,pin),
            self.default.schema_document('https://phase-tool.local/'+resource,pin))
        with self.assertRaises(PhaseError) as caught:
            registry.resolve_contract('file_create.v1','1.0.0',NEW,core_version='0.0.0')
        self.assertEqual(caught.exception.code, 'contract.core_incompatible')

    def test_loader_has_no_caller_selected_document_path_digest_or_environment(self):
        self.assertEqual(len(inspect.signature(_native_file_create_candidate_registry).parameters), 0)
        with self.assertRaises(TypeError):
            _native_file_create_candidate_registry(self.default.to_document())
        with self.assertRaises(TypeError):
            _native_file_create_candidate_registry(path='synthetic.json')
        with patch.dict(os.environ, {'PHASE_REGISTRY':'synthetic-untrusted.json'}):
            self.assertEqual(_native_file_create_candidate_registry().digest, RAW_DIGEST)
        self.assertEqual(BundledRegistry.load().contract_bindings()['file_create.v1@1.0.0']['package_digest'], OLD)

    def test_missing_and_changed_candidate_resource_refuse_before_loading(self):
        missing = dict(self.resources); del missing[RESOURCE]
        self.assert_loader_error('ntfs.native_registry_missing', missing)
        for raw in (b'{}',self.resources[RESOURCE]+b'\n',self.resources[RESOURCE].replace(b'"current":true',b'"current":false',1)):
            with self.subTest(digest=digest_bytes(raw)):
                changed = dict(self.resources); changed[RESOURCE] = raw
                self.assert_loader_error('ntfs.native_registry_digest_mismatch', changed)

    def test_corrupted_bound_contract_or_schema_resource_still_fails_existing_trust_checks(self):
        entry = next(row for row in self.default.to_document()['entries'] if row.get('kind')=='contract' and row.get('package_digest')==NEW)
        for resource in (entry.get('archive_resource',entry['artifact']), 'schemas/phase-intent-1.2.schema.json'):
            with self.subTest(resource=resource):
                changed = dict(self.resources); changed[resource] += b'\n'
                self.assert_loader_error('registry.digest_mismatch', changed)


FRESH_INSPECT = '''
import hashlib,json,sys
from pathlib import Path
from phase_tool import installation as module
from phase_tool.installation import _native_file_create_candidate_registry
from phase_tool.inspection import inspect_run
from phase_tool.registry import BundledRegistry
registry = _native_file_create_candidate_registry() if sys.argv[1]=='candidate' else BundledRegistry.load()
observation = inspect_run(Path(sys.argv[2]),sys.argv[3],registry,root_bindings={'phase_result_root':Path(sys.argv[4])})
print(json.dumps({'inspection':observation,'registry_snapshot_digest':registry.digest,
 'installation_module_sha256':hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()}))
'''


@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: actual Linux/ext4 Core required')
class NativeCandidateRegistryCoreExt4Tests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix='phase-native-registry-'); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root/'target'; self.target.mkdir()
        self.evidence = self.root/'evidence'; self.evidence.mkdir()
        for path in (self.target,self.evidence):
            try:
                qualify_host_authority_roots({'synthetic_owned_root':path})
                filesystem = _linux_filesystem_type(path)
            except PhaseError as error:
                self.skipTest('NOT_VERIFIED: actual qualification unavailable: '+error.code)
            if filesystem != 'ext4':
                self.skipTest('NOT_VERIFIED: actual filesystem is '+filesystem)
        (self.target/'sentinel.bin').write_bytes(b'synthetic-unchanged\x00\xff\r\n')
        self.installation = Installation(authority_provider=HostAuthorityProvider(), authority_profile_binding=None)
        self.assertIs(type(self.installation), Installation)
        self.assertIs(type(self.installation.authority_provider), HostAuthorityProvider)
        self.assertIsNone(self.installation.authority_profile_binding)

    @staticmethod
    def files(root):
        return {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}

    def rejected_before_capture(self, lane, registry, blocker, lifecycle):
        before = self.files(self.target)
        request = PhaseRequest('file_create.v1','1.0.0',NEW,self.root/'MISSING-candidate.json',
            self.evidence,'synthetic-'+lane,{'payload':self.root/'MISSING-input.bin'},
            {'phase_result_root':self.target},timestamp='2026-10-22T00:00:00Z')
        outcome = PhaseCore(registry, self.installation).run(request,execute=True)
        self.assertEqual(outcome.lifecycle, lifecycle)
        self.assertEqual(outcome.exit_code,10)
        self.assertIsNone(outcome.intent); self.assertIsNone(outcome.effect_plan)
        receipt = outcome.receipt
        self.assertEqual(receipt['contract'], BINDING)
        self.assertEqual(receipt['blockers'],[blocker])
        self.assertEqual(receipt['terminal_status'],'rejected')
        self.assertEqual(receipt['execution_disposition'],'not_executed')
        self.assertIs(receipt['mutation_attempted'],False)
        self.assertEqual(receipt['result_state'],'none')
        self.assertIsNone(receipt['canonical_result'])
        self.assertEqual(receipt['effect_receipts'],[])
        self.assertEqual(receipt['evidence']['finalization_status'],'finalized')
        self.assertIsNone(receipt['evidence']['intent_digest'])
        self.assertIs(receipt['recovery_required'],False)
        validate_receipt(receipt,registry)
        run = self.evidence/'.phase/runs'/request.run_id
        raw = (run/'receipt.json').read_bytes()
        self.assertEqual(raw,canonical_bytes(receipt))
        self.assertFalse((run/'intent.json').exists())
        self.assertFalse((run/'blobs').exists())
        self.assertFalse(request.candidate_path.exists())
        self.assertFalse(request.input_paths['payload'].exists())
        self.assertEqual(self.files(self.target),before)
        frozen_evidence = self.files(self.evidence)
        completed = subprocess.run([sys.executable,'-B','-c',FRESH_INSPECT,lane,
            str(self.evidence),request.run_id,str(self.target)],check=True,capture_output=True,text=True,timeout=60)
        observed = json.loads(completed.stdout)
        self.assertEqual(observed['registry_snapshot_digest'],registry.digest)
        self.assertEqual(observed['installation_module_sha256'],hashlib.sha256(Path(installation_module.__file__).read_bytes()).hexdigest())
        inspected = observed['inspection']
        self.assertEqual(inspected['receipt_digest'],outcome.receipt_digest)
        self.assertEqual(inspected['contract'],BINDING)
        self.assertEqual(inspected['terminal_status'],'rejected')
        self.assertEqual(inspected['execution_disposition'],'not_executed')
        self.assertIs(inspected['mutation_attempted'],False)
        self.assertIsNone(inspected['target_verified'])
        self.assertIsNone(inspected['intent_digest'])
        self.assertEqual(self.files(self.evidence),frozen_evidence)
        self.assertEqual(self.files(self.target),before)
        report_root = os.environ.get('EVIDENCE')
        if report_root:
            report = {'kind':'native_candidate_registry_negative_core','lane':lane,
                'claim':'negative Core/ext4 only; native G01/E2E/MIX not verified',
                'blocker':blocker,'lifecycle':list(outcome.lifecycle),'receipt':receipt,
                'receipt_digest':outcome.receipt_digest,'inspection':observed,
                'candidate_present':False,'input_present':False,'intent_present':False,
                'frozen_blobs':0,'target_unchanged':True,'inspect_evidence_unchanged':True,
                'evidence_files':[{'name':name,'length':len(data),'sha256':hashlib.sha256(data).hexdigest()}
                    for name,data in sorted(frozen_evidence.items())],
                'target_files':[{'name':name,'length':len(data),'sha256':hashlib.sha256(data).hexdigest()}
                    for name,data in sorted(before.items())]}
            path = Path(report_root)/('native-registry-negative-'+lane+'.json')
            with path.open('xb') as stream:stream.write(canonical_bytes(report))

    def test_default_snapshot_rejects_inactive_generation_before_guarantees_or_capture(self):
        self.rejected_before_capture('default',BundledRegistry.load(),
            'registry.contract_generation_inactive',('resolve','receipt'))

    def test_candidate_snapshot_still_rejects_missing_authority_profile_after_real_qualification(self):
        self.rejected_before_capture('candidate',_native_file_create_candidate_registry(),
            'authority.guarantee_profile_unavailable',('resolve','guarantees','receipt'))


if __name__=='__main__':unittest.main()
