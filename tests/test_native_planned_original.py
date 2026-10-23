"""Unexecuted regression source: planned originals reuse existing Core artifacts.
Synthetic actual-ext4 fixtures only, no authority/profile override, Core native
execution, Windows API or positive storage qualification. Other FS is a skip.
"""
from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes, digest_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.installation import _linux_filesystem_type, qualify_host_authority_roots
from phase_tool.mutation.ntfs import reader
from phase_tool.mutation.ntfs.intent import (parse_original_file_create,
    validate_planned_file_create_original)
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers


@unittest.skipUnless(sys.platform.startswith('linux'), 'NOT_VERIFIED: Linux/ext4 required')
class NativePlannedOriginalTests(unittest.TestCase):
    def setUp(self):
        temporary=TemporaryDirectory(prefix='phase-native-planned-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'evidence';self.root.mkdir()
        try:
            qualify_host_authority_roots({'phase_evidence_root':self.root})
            filesystem=_linux_filesystem_type(self.root)
        except PhaseError as error:
            self.skipTest('NOT_VERIFIED: actual qualification: '+error.code)
        if filesystem!='ext4':self.skipTest('NOT_VERIFIED: actual filesystem '+filesystem)
        self.registry=BundledRegistry.load()
        self.intent,self.plan,self.pre,self.content,_=buffers(self.registry)
        self.intent['execution_requested']=False
        info=self.root.stat()
        self.identity={'stable_id':'synthetic.planned.ext4','device':info.st_dev,'inode':info.st_ino}
        self.intent['native_binding']['evidence_identity']=deepcopy(self.identity)
        self.run=self.root/'.phase'/'runs'/self.intent['run_id']
        self.paths=(self.run/'intent.json',self.run/'attachments'/'effect-plan.json',
            self.run/'attachments'/'validator-results.json',
            self.run/'blobs'/digest_bytes(self.content).removeprefix('sha256:'))
        for path in self.paths:path.parent.mkdir(parents=True,exist_ok=True)
        self.refresh()

    def refresh(self):
        self.intent['effect_plan_digest']=profile_digest('effect-plan',self.plan)
        self.intent['implementation_binding']['effect_plan_digest']=self.intent['effect_plan_digest']
        self.intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(self.plan))
        self.intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(self.pre))
        raw=(canonical_bytes(self.intent),canonical_bytes(self.plan),canonical_bytes(self.pre),self.content)
        for path,data in zip(self.paths,raw):path.write_bytes(data)
        return raw

    def read(self):
        return reader.read_original_file_create_buffers(evidence_root=self.root,
            installed_evidence_identity=canonical_bytes(self.identity),registry=self.registry,
            run_id=self.intent['run_id'],expected_intent_digest=profile_digest('intent',self.intent))

    def arguments(self,raw):
        return dict(intent_bytes=raw[0],plan_bytes=raw[1],pre_validator_bytes=raw[2],blob_bytes=raw[3],
            registry=self.registry,expected_run_id=self.intent['run_id'],
            expected_intent_digest=profile_digest('intent',self.intent),
            installed_core_binding=canonical_bytes(self.intent['core']),
            installed_native_binding=canonical_bytes(self.intent['native_binding']),
            installed_root_grants=canonical_bytes(self.intent['idempotency']['root_identities']),
            installed_implementation_binding=canonical_bytes(self.intent['implementation_binding']))

    def test_planned_only_existing_artifact_reads_without_mutation_and_returns_no_handoff(self):
        self.assertFalse((self.run/'attachments'/'pre-validator-results.json').exists())
        before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as observed:
            raw=self.read()
        self.assertEqual([call.args[0] for call in observed.call_args_list],list(self.paths))
        self.assertEqual(raw,tuple(path.read_bytes() for path in self.paths))
        self.assertIsNone(validate_planned_file_create_original(**self.arguments(raw)))
        after={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before,after)

    def test_executing_entrypoint_refuses_exact_planned_original(self):
        with self.assertRaises(PhaseError) as caught:parse_original_file_create(**self.arguments(self.read()))
        self.assertEqual(caught.exception.code,'ntfs.original_execution_binding_mismatch')

    def test_planned_wrapper_refuses_executing_original_even_with_rebound_hash(self):
        self.intent['execution_requested']=True
        raw=self.refresh()
        with self.assertRaises(PhaseError) as caught:validate_planned_file_create_original(**self.arguments(raw))
        self.assertEqual(caught.exception.code,'ntfs.original_execution_binding_mismatch')

    def test_rehashed_semantic_plan_change_refuses_in_planned_parser(self):
        self.plan['effects'][0]['content_length']+=1
        self.refresh()  # All outer attachment/intent digests are current.
        raw=self.read()
        with self.assertRaises((PhaseError,ValidationError)):
            validate_planned_file_create_original(**self.arguments(raw))

    def test_executing_reader_cannot_fall_back_to_planned_filename(self):
        self.intent['execution_requested']=True
        self.refresh()
        with self.assertRaises(FileNotFoundError):self.read()

    def test_missing_planned_file_cannot_fall_back_to_executing_filename(self):
        self.paths[2].rename(self.run/'attachments'/'pre-validator-results.json')
        with self.assertRaises(FileNotFoundError):self.read()
