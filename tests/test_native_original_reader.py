"""Actual Linux/ext4 read-only component tests, never Windows qualification.

Fixtures write synthetic claimed intents only inside an owned TemporaryDirectory.
They do not use Core dispatch, qualify an installation or grant native authority.
No successful root qualification is mocked; other environments are NOT_VERIFIED.
"""
from copy import deepcopy
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.installation import _linux_filesystem_type, qualify_host_authority_roots
from phase_tool.mutation.ntfs import reader
from phase_tool.mutation.ntfs.intent import parse_original_file_create
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers


@unittest.skipUnless(sys.platform.startswith('linux'), 'NOT_VERIFIED: Linux/ext4 component required')
class OriginalNativeReaderTests(unittest.TestCase):
    def setUp(self):
        temporary=TemporaryDirectory(prefix='phase-original-reader-')
        self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name)
        self.root=self.base/'evidence';self.root.mkdir()
        try:
            qualify_host_authority_roots({'phase_evidence_root':self.root})
            filesystem=_linux_filesystem_type(self.root)
        except PhaseError as error:
            self.skipTest('NOT_VERIFIED: actual root qualification unavailable: '+error.code)
        if filesystem!='ext4':self.skipTest('NOT_VERIFIED: actual evidence filesystem is '+filesystem)
        self.registry=BundledRegistry.load()
        self.intent,self.plan,self.pre,self.content,_=buffers(self.registry)
        info=self.root.stat()
        self.identity={'stable_id':'synthetic.reader.ext4','device':info.st_dev,'inode':info.st_ino}
        self.intent['native_binding']['evidence_identity']=deepcopy(self.identity)
        self.run=self.root/'.phase'/'runs'/self.intent['run_id']
        self.intent_path=self.run/'intent.json'
        self.plan_path=self.run/'attachments'/'effect-plan.json'
        self.pre_path=self.run/'attachments'/'pre-validator-results.json'
        self.blob_path=self.run/'blobs'/digest_bytes(self.content).removeprefix('sha256:')
        for path in (self.intent_path,self.plan_path,self.pre_path,self.blob_path):path.parent.mkdir(parents=True,exist_ok=True)
        self.refresh()

    def refresh(self):
        self.intent['effect_plan_digest']=profile_digest('effect-plan',self.plan)
        self.intent['implementation_binding']['effect_plan_digest']=self.intent['effect_plan_digest']
        self.intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(self.plan))
        self.intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(self.pre))
        self.originals=(canonical_bytes(self.intent),canonical_bytes(self.plan),canonical_bytes(self.pre),self.content)
        for path,raw in zip(self.paths(),self.originals):path.write_bytes(raw)

    def paths(self):return (self.intent_path,self.plan_path,self.pre_path,self.blob_path)

    def arguments(self):
        return {'evidence_root':self.root,'installed_evidence_identity':canonical_bytes(self.identity),
            'registry':self.registry,'run_id':self.intent['run_id'],
            'expected_intent_digest':profile_digest('intent',self.intent)}

    def assert_code(self,code,**changes):
        args=self.arguments();args.update(changes)
        with self.assertRaises(PhaseError) as caught:reader.read_original_file_create_buffers(**args)
        self.assertEqual(caught.exception.code,code)

    def test_exact_four_original_buffers_roundtrip_through_existing_parser_without_writes(self):
        before={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as read:
            result=reader.read_original_file_create_buffers(**self.arguments())
        self.assertEqual(type(result),tuple);self.assertEqual(result,self.originals)
        self.assertTrue(all(type(value) is bytes for value in result))
        self.assertEqual([call.args[0] for call in read.call_args_list],list(self.paths()))
        self.assertEqual([call.args[1] for call in read.call_args_list],[2*1024**2]*3+[1024**2])
        parsed=parse_original_file_create(intent_bytes=result[0],plan_bytes=result[1],pre_validator_bytes=result[2],
            blob_bytes=result[3],registry=self.registry,expected_run_id=self.intent['run_id'],
            expected_intent_digest=profile_digest('intent',self.intent),
            installed_core_binding=canonical_bytes(self.intent['core']),
            installed_native_binding=canonical_bytes(self.intent['native_binding']),
            installed_root_grants=canonical_bytes(self.intent['idempotency']['root_identities']),
            installed_implementation_binding=canonical_bytes(self.intent['implementation_binding']))
        self.assertEqual(parsed.content_bytes,self.content)
        after={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before,after)

    def test_invalid_run_ids_reject_before_any_file_read(self):
        for run in ('../other','/absolute','a/b','a\\b','.', '..','', 'a'*129,True,None):
            with self.subTest(run=run),patch.object(reader,'read_bounded_file') as read:
                self.assert_code('evidence.invalid_run_id',run_id=run)
                read.assert_not_called()

    def test_invalid_expected_digest_rejects_before_any_file_read(self):
        for digest in ('f'*64,'sha256:'+'A'*64,'sha256:'+'f'*63,True,None):
            with self.subTest(digest=digest),patch.object(reader,'read_bounded_file') as read:
                self.assert_code('ntfs.original_intent_digest_required',expected_intent_digest=digest)
                read.assert_not_called()

    def test_registry_must_be_the_installed_snapshot_type_before_any_read(self):
        with patch.object(reader,'read_bounded_file') as read:
            self.assert_code('ntfs.original_registry_required',registry=self.registry.to_document())
            read.assert_not_called()

    def test_identity_is_closed_canonical_immutable_and_rejects_boolean_ids(self):
        original=canonical_bytes(self.identity)
        bad=[bytearray(original),original+b'\n',b' '*4097,canonical_bytes({**self.identity,'extra':True}),
            canonical_bytes({**self.identity,'device':True}),canonical_bytes({**self.identity,'inode':False}),
            canonical_bytes({**self.identity,'inode':0}),canonical_bytes({**self.identity,'stable_id':'../other'})]
        for raw in bad:
            with self.subTest(raw=raw[:80]),patch.object(reader,'read_bounded_file') as read:
                self.assert_code('ntfs.original_evidence_identity_required',installed_evidence_identity=raw)
                read.assert_not_called()

    def test_wrong_actual_root_identity_rejects_before_any_file_read(self):
        foreign=self.base/'foreign';foreign.mkdir()
        other={**self.identity,'inode':foreign.stat().st_ino}
        with patch.object(reader,'read_bounded_file') as read:
            self.assert_code('ntfs.original_evidence_identity_mismatch',installed_evidence_identity=canonical_bytes(other))
            read.assert_not_called()

    def test_relative_and_symlink_roots_are_rejected_without_reading_intent(self):
        with patch.object(reader,'read_bounded_file') as read:
            self.assert_code('ntfs.original_evidence_root_required',evidence_root=Path('relative'))
            read.assert_not_called()
        alias=self.base/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with patch.object(reader,'read_bounded_file') as read:
            self.assert_code('guarantee.profile_scope_unsupported',evidence_root=alias)
            read.assert_not_called()

    def test_intent_evidence_identity_must_match_the_actual_installed_root(self):
        self.intent['native_binding']['evidence_identity']['stable_id']='synthetic.other'
        self.refresh()
        with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as read:
            self.assert_code('ntfs.original_evidence_identity_mismatch')
        self.assertEqual([call.args[0] for call in read.call_args_list],[self.intent_path])

    def test_intent_canonical_bytes_and_native_version_are_required(self):
        self.intent_path.write_bytes(self.originals[0]+b'\n')
        self.assert_code('ntfs.original_native_intent_required')
        self.intent['phase_intent_version']='1.1';self.refresh()
        self.assert_code('ntfs.original_native_intent_required')

    def test_valid_shape_wrong_run_registry_and_profile_digest_are_rejected(self):
        original=deepcopy(self.intent)
        for field,value in [('run_id','synthetic.other'),('registry_snapshot_digest','sha256:'+'f'*64)]:
            with self.subTest(field=field):
                self.intent=deepcopy(original);self.intent[field]=value;self.refresh()
                args=self.arguments();args['run_id']=original['run_id']
                with self.assertRaises(PhaseError) as caught:reader.read_original_file_create_buffers(**args)
                self.assertEqual(caught.exception.code,'ntfs.original_intent_mismatch')
        self.intent=deepcopy(original);self.refresh()
        self.assert_code('ntfs.original_intent_mismatch',expected_intent_digest=digest_bytes(self.originals[0]))

    def test_non_single_frozen_inputs_never_derive_a_blob_path(self):
        original=deepcopy(self.intent['inputs'])
        other={**original[0],'binding_id':'other'}
        noncopy={**original[0],'freeze_strategy':'value_snapshot'}
        for inputs in ([],[*original,other],[noncopy]):
            with self.subTest(count=len(inputs)):
                self.intent['inputs']=inputs;self.refresh()
                with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as read:
                    self.assert_code('ntfs.original_frozen_input_required')
                self.assertEqual([call.args[0] for call in read.call_args_list],[self.intent_path])

    def test_malformed_blob_digest_is_schema_rejected_before_path_derivation(self):
        self.intent['inputs'][0]['blob_digest']='../../outside';self.refresh()
        with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as read:
            with self.assertRaises(ValidationError):reader.read_original_file_create_buffers(**self.arguments())
        self.assertEqual([call.args[0] for call in read.call_args_list],[self.intent_path])

    def test_raw_attachment_and_blob_byte_drift_reject_with_exact_error(self):
        for path,raw in zip(self.paths()[1:],self.originals[1:]):
            with self.subTest(name=path.name):
                path.write_bytes(raw+b'\n')
                try:self.assert_code('ntfs.original_evidence_bytes_mismatch')
                finally:path.write_bytes(raw)

    def test_each_control_and_blob_bound_rejects_before_hash_or_json_fallback(self):
        for path,raw,limit in zip(self.paths(),self.originals,[2*1024**2]*3+[1024**2]):
            with self.subTest(name=path.name):
                path.write_bytes(b' '*(limit+1))
                try:self.assert_code('stream.limit_exceeded')
                finally:path.write_bytes(raw)

    def test_linux_links_at_leaf_and_attachment_ancestor_reject(self):
        # Linux symlinks only: no coverage claim for Windows SYMLINK/A05.
        for path in (self.intent_path,self.plan_path.parent,self.blob_path):
            with self.subTest(name=path.name):
                retained=path.with_name(path.name+'.retained');path.rename(retained)
                path.symlink_to(retained,target_is_directory=retained.is_dir())
                try:self.assert_code('path.link_forbidden')
                finally:path.unlink();retained.rename(path)

    def test_fifo_and_directory_blob_are_nonblocking_nonregular_rejections(self):
        self.blob_path.unlink();os.mkfifo(self.blob_path)
        self.assert_code('stream.not_regular_file')
        self.blob_path.unlink();self.blob_path.mkdir()
        self.assert_code('stream.not_regular_file')

    def test_missing_original_attachment_has_no_reconstruction_or_fallback(self):
        self.plan_path.unlink()
        with self.assertRaises(FileNotFoundError):reader.read_original_file_create_buffers(**self.arguments())
        self.assertFalse(self.plan_path.exists())

    def test_root_replacement_after_last_read_cannot_return_buffers(self):
        real_read=reader.read_bounded_file;retained=self.base/'retained-evidence';calls=[]
        def observe(path,limit):
            raw=real_read(path,limit);calls.append(path)
            if path==self.blob_path:
                self.root.rename(retained);self.root.mkdir()
            return raw
        # Deterministic owned-namespace fault; not proof of hostile-namespace fencing.
        with patch.object(reader,'read_bounded_file',side_effect=observe):
            self.assert_code('ntfs.original_evidence_identity_mismatch')
        self.assertEqual(calls,list(self.paths()))
        self.assertEqual((retained/'.phase'/'runs'/self.intent['run_id']/'intent.json').read_bytes(),self.originals[0])


    def test_control_reader_returns_only_exact_three_originals_without_blob_io_or_writes(self):
        before={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as read:
            controls=reader._read_original_control_buffers(**self.arguments())
        self.assertEqual(controls,self.originals[:3])
        self.assertEqual(type(controls),tuple)
        self.assertTrue(all(type(raw) is bytes for raw in controls))
        self.assertEqual([call.args[0] for call in read.call_args_list],list(self.paths()[:3]))
        self.assertEqual([call.args[1] for call in read.call_args_list],[2*1024**2]*3)
        after={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before,after)

    def test_control_tuple_is_available_without_blob_but_full_reader_cannot_return_handoff_bytes(self):
        self.blob_path.unlink()
        self.assertEqual(reader._read_original_control_buffers(**self.arguments()),self.originals[:3])
        with self.assertRaises(FileNotFoundError):
            reader.read_original_file_create_buffers(**self.arguments())
        self.assertFalse(self.blob_path.exists())

    def test_control_corruption_precedes_missing_blob_and_never_falls_back_to_content(self):
        self.blob_path.unlink()
        for path,raw in zip(self.paths()[1:3],self.originals[1:3]):
            with self.subTest(name=path.name):
                path.write_bytes(raw+b'\n')
                try:
                    with patch.object(reader,'read_bounded_file',wraps=reader.read_bounded_file) as read:
                        self.assert_code('ntfs.original_evidence_bytes_mismatch')
                    self.assertEqual([call.args[0] for call in read.call_args_list],list(self.paths()[:3]))
                finally:
                    path.write_bytes(raw)
        with self.assertRaises(FileNotFoundError):
            reader.read_original_file_create_buffers(**self.arguments())

    def test_root_replacement_during_control_read_rejects_before_blob_io(self):
        actual=reader.read_bounded_file
        retained=self.base/'control-retained-evidence'
        def replace_root(path,limit):
            raw=actual(path,limit)
            if path==self.pre_path:
                self.root.rename(retained);self.root.mkdir()
            return raw
        with patch.object(reader,'read_bounded_file',side_effect=replace_root) as read:
            self.assert_code('ntfs.original_evidence_identity_mismatch')
        self.assertEqual([call.args[0] for call in read.call_args_list],list(self.paths()[:3]))
        self.assertEqual((retained/'.phase'/'runs'/self.intent['run_id']/'blobs'/self.blob_path.name).read_bytes(),
            self.content)



if __name__=='__main__':unittest.main()
