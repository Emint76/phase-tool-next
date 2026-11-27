"""Actual ext4 IO components only. Synthetic files never establish authority.

No native Core execution, successful qualification mock, worker or target IO.
The post-link interprocess closure window remains a separate mandatory case.
"""
from copy import deepcopy
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from phase_tool import evidence
from phase_tool.canonical import canonical_bytes, digest_bytes, profile_digest
from phase_tool.core import _guard_native_original_intents
from phase_tool.errors import PhaseError
from phase_tool.evidence import EvidenceStore
from phase_tool.installation import (_linux_filesystem_type, qualify_host_authority_roots,
    _native_connected_file_create_registry, _resolve_native_file_create_read_binding)
from phase_tool.mutation.ntfs.failure import make_native_parent_failure
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers
from .test_native_static_read_binding import manifest_for


@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: actual Linux/ext4 required')
class NativeConnectedEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary=TemporaryDirectory(prefix='phase-connected-evidence-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'evidence'
        self.root.mkdir(mode=0o700)
        try:
            qualify_host_authority_roots({'phase_evidence_root':self.root})
            filesystem=_linux_filesystem_type(self.root)
        except PhaseError as error:
            self.skipTest('NOT_VERIFIED: actual qualification: '+error.code)
        if filesystem!='ext4':self.skipTest('NOT_VERIFIED: actual filesystem '+filesystem)
        self.registry=_native_connected_file_create_registry()
        # Old fixture has one known inactive intent1.2 generation. Rebind it
        # explicitly to the new package; this is static data, not credentials.
        self.intent,self.plan,self.pre,self.content,_=buffers(BundledRegistry.load())
        binding=self.registry.contract_bindings()['file_create.v1@1.0.0']
        self.intent['contract']=deepcopy(binding)
        self.plan['contract']=deepcopy(binding)
        self.intent['registry_snapshot_digest']=self.registry.digest
        self.intent['effect_plan_digest']=profile_digest('effect-plan',self.plan)
        self.intent['implementation_binding']['effect_plan_digest']=self.intent['effect_plan_digest']
        self.intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(self.plan))
        self.intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(self.pre))
        info=self.root.stat()
        self.identity={'stable_id':'synthetic.connected.ext4','device':info.st_dev,'inode':info.st_ino}
        self.intent['native_binding']['evidence_identity']=deepcopy(self.identity)
        manifest=manifest_for(self.intent,self.root)
        raw=canonical_bytes(manifest)
        self.binding=_resolve_native_file_create_read_binding(manifest_bytes=raw,
            expected_manifest_digest=digest_bytes(raw),registry=self.registry)
        self.intent['native_binding']['installation']['descriptor_digest']=self.binding.manifest_digest
        self.store=EvidenceStore(self.root,self.intent['run_id'])
        self.store.write_canonical('intent.json',self.intent)
        self.store.write_canonical('attachments/effect-plan.json',self.plan)

    def failure(self):
        from phase_tool.canonical import parse_json_bytes
        return parse_json_bytes(make_native_parent_failure(self.binding,
            run_id=self.intent['run_id'],intent_digest=profile_digest('intent',self.intent),
            effect_plan_digest=self.intent['effect_plan_digest'],
            operation_nonce=self.intent['native_binding']['operation_nonce'],
            remote={'code':'ntfs.parent_execution_unresolved',
                'message':'Synthetic parent completion unresolved','details':{
                'synthetic_status':'0xC0000280','owner_exit_confirmed':False,
                'trace':{'synthetic':True}}}))

    def test_negative_attachment_is_exact_immutable_and_does_not_close_original(self):
        value=self.failure()
        original=(self.store.run_root/'intent.json').read_bytes()
        # This directly exercises the EvidenceIO component, not a native Core
        # operation. The real common guard is separately checked to refuse the
        # unresolved original even after this diagnostic has been written.
        path,digest=evidence._write_native_parent_failure(self.store,self.binding,value)
        self.assertEqual(path.read_bytes(),canonical_bytes(value))
        self.assertEqual(digest,digest_bytes(path.read_bytes()))
        self.assertEqual((self.store.run_root/'intent.json').read_bytes(),original)
        self.assertFalse((self.store.run_root/'receipt.json').exists())
        with self.assertRaises(FileExistsError):
            evidence._write_native_parent_failure(self.store,self.binding,value)
        with self.assertRaises(PhaseError) as caught:
            with _guard_native_original_intents(self.binding):self.fail('negative diagnostic discharged original')
        self.assertEqual(caught.exception.code,'ntfs.original_history_unresolved')
        self.assertEqual(path.read_bytes(),canonical_bytes(value))

    def test_wrong_nonce_or_original_digest_refuses_before_attachment_write(self):
        for key in ['operation_nonce','intent_digest','effect_plan_digest']:
            value=self.failure()
            value[key]='b'*32 if key=='operation_nonce' else 'sha256:'+'f'*64
            with self.subTest(key=key):
                with patch.object(evidence,'_write_bytes_exclusive_atomic',side_effect=AssertionError('unsafe write reached')) as write:
                    with self.assertRaisesRegex(PhaseError,'ntfs.native_failure_binding_mismatch'):
                        evidence._write_native_parent_failure(self.store,self.binding,value)
                    write.assert_not_called()

    def test_replaced_run_namespace_refuses_without_new_write(self):
        old=self.store.run_root.with_name('synthetic-owned-old')
        self.store.run_root.rename(old)
        self.store.run_root.mkdir(mode=0o700)
        (self.store.run_root/'attachments').mkdir(mode=0o700)
        with patch.object(evidence,'_write_bytes_exclusive_atomic',side_effect=AssertionError('replacement write reached')) as write:
            with self.assertRaisesRegex(PhaseError,'ntfs.original_evidence_identity_mismatch'):
                evidence._write_native_parent_failure(self.store,self.binding,self.failure())
            write.assert_not_called()
        self.assertTrue((old/'intent.json').exists())
        self.assertEqual(list((self.store.run_root/'attachments').iterdir()),[])

    def durability_files(self):
        # Deliberately NON-authentic proof/receipt bytes for IO-only coverage.
        self.store.write_canonical('attachments/native-terminal-proof.json',{'synthetic_io_only':True})
        self.store.write_canonical('receipt.json',{'synthetic_io_only':True})
        return {path.relative_to(self.store.run_root).as_posix():
            (digest_bytes(path.read_bytes()),path.stat().st_size)
            for path in self.store.run_root.rglob('*') if path.is_file()}

    def confirm(self,expected):
        return evidence._confirm_native_immutable_files_durable(self.root,
            (self.identity['device'],self.identity['inode']),self.intent['run_id'],expected)

    def test_durability_confirms_actual_files_then_directories_without_changing_bytes(self):
        expected=self.durability_files()
        calls=[]
        real=os.fsync
        def observed(fd):
            info=os.fstat(fd)
            calls.append('directory' if stat.S_ISDIR(info.st_mode) else 'file')
            return real(fd)
        before={p:p.read_bytes() for p in self.store.run_root.rglob('*') if p.is_file()}
        with patch.object(evidence.os,'fsync',observed):self.confirm(expected)
        self.assertEqual(calls,['file']*len(expected)+['directory']*5)
        self.assertEqual(before,{p:p.read_bytes() for p in before})

    def test_each_file_and_directory_fsync_failure_is_not_success(self):
        expected=self.durability_files()
        count=len(expected)+5  # root/.phase/runs/run/attachments
        for fail_at in range(count):
            primary=OSError('synthetic fsync '+str(fail_at))
            calls=[]
            real=os.fsync
            def fail(fd):
                index=len(calls);calls.append(fd)
                if index==fail_at:raise primary
                return real(fd)
            with self.subTest(index=fail_at):
                with patch.object(evidence.os,'fsync',fail):
                    with self.assertRaises(OSError) as caught:self.confirm(expected)
                self.assertIs(caught.exception,primary)
                self.assertEqual(len(calls),fail_at+1)
        self.confirm(expected)  # Later safe component confirmation, no closure claim.

    def test_primary_fsync_failure_survives_close_error_and_each_owned_fd_closes_once(self):
        expected=self.durability_files()
        primary=OSError('synthetic primary fsync failure')
        closed=[]
        real=os.close
        def close(fd):
            self.assertNotIn(fd,closed)
            closed.append(fd)
            real(fd)
            if len(closed)==1:raise OSError('synthetic secondary post-close failure')
        with patch.object(evidence.os,'fsync',side_effect=primary),patch.object(evidence.os,'close',close):
            with self.assertRaises(OSError) as caught:self.confirm(expected)
        self.assertIs(caught.exception,primary)
        self.assertEqual(len(closed),len(expected)+5)
        self.assertTrue(any('secondary close' in note for note in primary.__notes__))

    def test_rehashed_expected_inventory_must_not_omit_an_actual_dependency(self):
        expected=self.durability_files()
        del expected['attachments/effect-plan.json']
        with patch.object(evidence.os,'fsync',side_effect=AssertionError('incomplete inventory reached fsync')) as sync:
            with self.assertRaisesRegex(PhaseError,'ntfs.native_durability_dependency_mismatch'):
                self.confirm(expected)
            sync.assert_not_called()

    def test_changed_file_bytes_refuse_before_any_durability_acknowledgment(self):
        expected=self.durability_files()
        (self.store.run_root/'attachments/effect-plan.json').write_bytes(b'changed')
        with patch.object(evidence.os,'fsync',side_effect=AssertionError('bad bytes reached fsync')) as sync:
            with self.assertRaisesRegex(PhaseError,'ntfs.native_durability_bytes_mismatch'):
                self.confirm(expected)
            sync.assert_not_called()


    def test_terminal_write_before_pin_refuses_replaced_run_without_staging(self):
        old=self.store.run_root.with_name('synthetic-old-terminal')
        self.store.run_root.rename(old)
        self.store.run_root.mkdir(mode=0o700)
        with patch.object(evidence,'_write_bytes_exclusive_atomic',
                side_effect=AssertionError('replacement reached staging')) as write:
            with self.assertRaisesRegex(PhaseError,'ntfs.original_evidence_identity_mismatch'):
                evidence._write_native_canonical(self.store,self.binding,'receipt.json',{'synthetic_io_only':True})
            write.assert_not_called()
        self.assertEqual(list(self.store.run_root.iterdir()),[])
        self.assertTrue((old/'intent.json').exists())

    def test_rename_after_pin_cannot_redirect_terminal_bytes_to_replacement(self):
        old=self.store.run_root.with_name('synthetic-pinned-terminal')
        real=evidence._write_bytes_exclusive_at
        calls=[]
        def renamed(parent,path,data,label):
            calls.append((os.fstat(parent).st_dev,os.fstat(parent).st_ino))
            self.store.run_root.rename(old)
            self.store.run_root.mkdir(mode=0o700)
            (self.store.run_root/'attachments').mkdir(mode=0o700)
            return real(parent,path,data,label)
        value={'synthetic_io_only':True}
        with patch.object(evidence,'_write_bytes_exclusive_at',renamed):
            with self.assertRaises(OSError):
                evidence._write_native_canonical(self.store,self.binding,
                    'attachments/native-terminal-proof.json',value)
        self.assertEqual(len(calls),1)
        self.assertEqual((old/'attachments/native-terminal-proof.json').read_bytes(),canonical_bytes(value))
        self.assertFalse((self.store.run_root/'attachments/native-terminal-proof.json').exists())
        self.assertFalse((self.store.run_root/'receipt.json').exists())

    def test_owned_anchored_receipt_write_uses_existing_exclusive_primitive_once(self):
        evidence._write_native_canonical(self.store,self.binding,
            'attachments/native-terminal-proof.json',{'synthetic_io_only':True})
        real=evidence._write_bytes_exclusive_atomic
        value={'synthetic_io_only':True}
        with patch.object(evidence,'_write_bytes_exclusive_atomic',wraps=real) as write:
            path,digest=evidence._write_native_canonical(self.store,self.binding,'receipt.json',value)
            write.assert_called_once()
            self.assertIs(type(write.call_args.kwargs['_parent_descriptor']),int)
        self.assertEqual(path.read_bytes(),canonical_bytes(value))
        self.assertEqual(digest,digest_bytes(path.read_bytes()))
        with self.assertRaises(FileExistsError):
            evidence._write_native_canonical(self.store,self.binding,'receipt.json',value)


    def test_post_open_attachment_enoent_never_creates_a_replacement_directory(self):
        real=os.stat
        primary=FileNotFoundError('synthetic named edge disappeared after open')
        def missing(name,*args,**kwargs):
            if name=='attachments' and kwargs.get('dir_fd') is not None:raise primary
            return real(name,*args,**kwargs)
        with (patch.object(evidence.os,'stat',missing),
                patch.object(evidence.os,'mkdir',side_effect=AssertionError('ambiguous mkdir reached')) as mkdir,
                patch.object(evidence,'_write_bytes_exclusive_atomic',
                    side_effect=AssertionError('ambiguous namespace staged bytes')) as write):
            with self.assertRaises(FileNotFoundError) as caught:
                evidence._write_native_canonical(self.store,self.binding,
                    'attachments/native-terminal-proof.json',{'synthetic_io_only':True})
            self.assertIs(caught.exception,primary)
            mkdir.assert_not_called()
            write.assert_not_called()

    def test_visible_receipt_stage_close_failure_remains_error_without_republication(self):
        evidence._write_native_canonical(self.store,self.binding,
            'attachments/native-terminal-proof.json',{'synthetic_io_only':True})
        before_flag=self.store._authoritative_evidence_published
        real=os.close
        primary=OSError('synthetic stage close failure after actual close')
        closes=[]
        def fail_stage_once(fd):
            stage=stat.S_ISREG(os.fstat(fd).st_mode)
            closes.append(fd)
            real(fd)
            if stage:raise primary
        real_write=evidence._write_bytes_exclusive_atomic
        value={'synthetic_io_only':True}
        with (patch.object(evidence.os,'close',fail_stage_once),
                patch.object(evidence,'_write_bytes_exclusive_atomic',wraps=real_write) as write):
            with self.assertRaises(OSError) as caught:
                evidence._write_native_canonical(self.store,self.binding,'receipt.json',value)
            self.assertIs(caught.exception,primary)
            write.assert_called_once()
        self.assertEqual(len(closes),6)  # root/.phase/runs/run/attachments plus stage
        self.assertEqual(len(set(closes)),6)
        self.assertEqual((self.store.run_root/'receipt.json').read_bytes(),canonical_bytes(value))
        self.assertEqual(self.store._authoritative_evidence_published,before_flag)


    def test_receipt_refuses_replaced_owned_attachments_before_staging(self):
        evidence._write_native_canonical(self.store,self.binding,
            'attachments/native-terminal-proof.json',{'synthetic_io_only':True})
        old=self.store.attachment_root.with_name('synthetic-owned-attachments')
        self.store.attachment_root.rename(old)
        self.store.attachment_root.mkdir(mode=0o700)
        with patch.object(evidence,'_write_bytes_exclusive_atomic',
                side_effect=AssertionError('replacement parent reached staging')) as write:
            with self.assertRaisesRegex(PhaseError,'ntfs.original_evidence_identity_mismatch'):
                evidence._write_native_canonical(self.store,self.binding,'receipt.json',{'synthetic_io_only':True})
            write.assert_not_called()
        self.assertTrue((old/'native-terminal-proof.json').exists())
        self.assertEqual(list(self.store.attachment_root.iterdir()),[])
        self.assertFalse((self.store.run_root/'receipt.json').exists())

    def test_receipt_without_owned_native_attachment_parent_refuses_before_staging(self):
        with patch.object(evidence,'_write_bytes_exclusive_atomic',
                side_effect=AssertionError('unowned receipt reached staging')) as write:
            with self.assertRaisesRegex(PhaseError,'ntfs.native_terminal_attachment_unowned'):
                evidence._write_native_canonical(self.store,self.binding,'receipt.json',{'synthetic_io_only':True})
            write.assert_not_called()
        self.assertFalse((self.store.run_root/'receipt.json').exists())
