"""Actual qualified ext4 refusal/lock component; no native route or guard mock."""
from copy import deepcopy
import errno
import json
import multiprocessing
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from jsonschema.exceptions import ValidationError
import uuid

from phase_tool import core as core_module
from phase_tool.canonical import canonical_bytes, digest_bytes, profile_digest
from phase_tool.core import (CORE_BINDING, PhaseCore, PhaseRequest,
    _guard_native_original_intents)
from phase_tool.errors import PhaseError
from phase_tool.evidence import EvidenceStore
from phase_tool.installation import (_resolve_native_file_create_read_binding,
    _linux_filesystem_type, qualify_host_authority_roots)
from phase_tool.registry import BundledRegistry
from .test_native_original_intent import buffers
from .test_native_static_read_binding import manifest_for


def competing_guard(raw,digest,pipe):
    """Wrap the real syscall only to report ACTUAL contention before release."""
    import fcntl
    real=fcntl.flock
    observed=False
    def observe(fd,operation):
        nonlocal observed
        try:return real(fd,operation)
        except OSError as error:
            if operation==fcntl.LOCK_EX|fcntl.LOCK_NB and error.errno in {errno.EAGAIN,errno.EACCES,errno.EWOULDBLOCK} and not observed:
                info=os.fstat(fd)
                pipe.send(('contended',info.st_dev,info.st_ino,error.errno));observed=True
            raise
    try:
        binding=_resolve_native_file_create_read_binding(manifest_bytes=raw,
            expected_manifest_digest=digest,registry=BundledRegistry.load())
        with patch.object(fcntl,'flock',observe):
            with _guard_native_original_intents(binding) as value:
                pipe.send(('entered',value))
        pipe.send(('done',observed))
    except BaseException as error:
        pipe.send(('error',type(error).__name__,str(error)));raise
    finally:pipe.close()


@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: actual Linux/ext4 component required')
class NativeCoreOriginalGateExt4Tests(unittest.TestCase):
    def setUp(self):
        temporary=TemporaryDirectory(prefix='phase-native-original-gate-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'evidence';self.root.mkdir(mode=0o700)
        try:
            qualify_host_authority_roots({'phase_evidence_root':self.root})
            filesystem=_linux_filesystem_type(self.root)
        except PhaseError as error:self.skipTest('NOT_VERIFIED: actual qualification unavailable: '+error.code)
        if filesystem!='ext4':self.skipTest('NOT_VERIFIED: actual evidence filesystem is '+filesystem)
        self.phase=self.root/'.phase';self.phase.mkdir(mode=0o700)
        self.runs=self.phase/'runs';self.runs.mkdir(mode=0o700)
        self.registry=BundledRegistry.load()
        self.intent,self.plan,self.pre,self.content,_=buffers(self.registry)
        self.intent['core']=deepcopy(CORE_BINDING)
        info=self.root.stat()
        self.intent['native_binding']['evidence_identity']={'stable_id':'synthetic.original.gate','device':info.st_dev,'inode':info.st_ino}
        self.manifest=manifest_for(self.intent,self.root)
        self.binding=self.resolve()
        self.intent['native_binding']['installation']['descriptor_digest']=self.binding.manifest_digest

    def resolve(self):
        raw=canonical_bytes(self.manifest)
        return _resolve_native_file_create_read_binding(manifest_bytes=raw,
            expected_manifest_digest=digest_bytes(raw),registry=self.registry)

    def run_root(self,name=None):
        run=self.runs/(name or self.intent['run_id']);run.mkdir(mode=0o700);return run

    def save_original(self,run=None):
        run=self.run_root() if run is None else run
        self.intent['run_id']=run.name;self.plan['run_id']=run.name
        self.intent['effect_plan_digest']=profile_digest('effect-plan',self.plan)
        self.intent['implementation_binding']['effect_plan_digest']=self.intent['effect_plan_digest']
        self.intent['evidence']['effect_plan_attachment_digest']=digest_bytes(canonical_bytes(self.plan))
        self.intent['evidence']['pre_validator_results_digest']=digest_bytes(canonical_bytes(self.pre))
        (run/'intent.json').write_bytes(canonical_bytes(self.intent))
        for folder in ('attachments','blobs'):(run/folder).mkdir(exist_ok=True,mode=0o700)
        (run/'attachments'/'effect-plan.json').write_bytes(canonical_bytes(self.plan))
        name='pre-validator-results.json' if self.intent['execution_requested'] else 'validator-results.json'
        (run/'attachments'/name).write_bytes(canonical_bytes(self.pre))
        (run/'blobs'/digest_bytes(self.content).removeprefix('sha256:')).write_bytes(self.content)
        return run

    def rejection(self,run_id):
        b=self.manifest['contract']
        request=PhaseRequest(b['id'],b['version'],b['package_digest'],self.root/'unused.json',
            self.root,run_id,{}, {},timestamp='2026-10-22T00:00:00Z')
        return PhaseCore(self.registry)._rejection_receipt(request,[],request.timestamp,'synthetic.rejected')

    def planned_receipt(self,run):
        b=self.manifest['contract']
        request=PhaseRequest(b['id'],b['version'],b['package_digest'],self.root/'unused.json',
            self.root,run.name,{}, {},timestamp='2026-10-22T00:00:00Z')
        attachments=[digest_bytes(path.read_bytes()) for path in (run/'attachments').iterdir()]
        receipt=PhaseCore(self.registry)._planned_receipt(request,self.pre,request.timestamp,
            profile_digest('intent',self.intent),attachments,self.intent['implementation_binding'])
        (run/'receipt.json').write_bytes(canonical_bytes(receipt))

    def refused(self,code,binding=None):
        with self.assertRaisesRegex(PhaseError,code):
            with _guard_native_original_intents(binding or self.binding):
                self.fail('refused guard reached its body')

    def test_empty_preprovisioned_history_yields_none_before_reservation_and_reuses_existing_lock(self):
        with _guard_native_original_intents(self.binding) as value:
            self.assertIsNone(value)
            self.assertEqual(list(self.runs.iterdir()),[])
            store=EvidenceStore(self.root,'synthetic-inside-guard')
            self.assertTrue(store.release_unpublished_run())
        before={p:p.stat().st_ino for p in (self.phase/'locks').iterdir()}
        with _guard_native_original_intents(self.binding):pass
        self.assertEqual(before,{p:p.stat().st_ino for p in (self.phase/'locks').iterdir()})
        self.assertEqual(len(before),1)

    def test_actual_two_process_contention_across_distinct_static_installation_labels(self):
        other=deepcopy(self.manifest);other['installation_id']='synthetic.other.installation'
        raw=canonical_bytes(other);context=multiprocessing.get_context('spawn')
        parent,child=context.Pipe();process=context.Process(target=competing_guard,args=(raw,digest_bytes(raw),child))
        observations=[]
        try:
            with _guard_native_original_intents(self.binding):
                process.start();child.close()
                self.assertTrue(parent.poll(10),'child did not reach ACTUAL kernel contention')
                first=parent.recv();observations.append(first)
                self.assertEqual(first[0],'contended')
                lock=next((self.phase/'locks').iterdir()).stat()
                self.assertEqual(first[1:3],(lock.st_dev,lock.st_ino))
                self.assertIn(first[3],{errno.EAGAIN,errno.EACCES,errno.EWOULDBLOCK})
            self.assertTrue(parent.poll(10),'child failed to enter after release')
            entered=parent.recv();observations.append(entered);self.assertEqual(entered,('entered',None))
            self.assertTrue(parent.poll(10),'child did not complete')
            done=parent.recv();observations.append(done);self.assertEqual(done,('done',True))
            process.join(10);self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
            output=os.environ.get('EVIDENCE')
            if output:
                with (Path(output)/'native-core-original-gate-contention.json').open('x',encoding='utf-8') as stream:
                    json.dump({'scope':'actual ext4 lock component, NOT native qualification',
                        'observations':observations,'child_exit':process.exitcode},stream,sort_keys=True)
        finally:
            if process.pid is not None and process.is_alive():process.terminate();process.join(10)
            parent.close();child.close()

    def test_missing_established_history_is_not_recreated(self):
        self.runs.rmdir();self.refused('ntfs.original_evidence_unavailable')
        self.assertFalse(self.runs.exists());self.assertFalse((self.phase/'locks').exists())

    def test_installed_identity_drift_refuses_before_creating_lock(self):
        self.manifest['evidence_identity']['inode']+=1
        self.refused('ntfs.original_evidence_identity_mismatch',self.resolve())
        self.assertFalse((self.phase/'locks').exists())

    def test_run_link_special_and_malformed_names_are_not_skipped(self):
        for kind in ('link','fifo','bad-name'):
            with self.subTest(kind=kind):
                path=self.runs/('bad name' if kind=='bad-name' else 'synthetic-object')
                if kind=='link':path.symlink_to(self.root,target_is_directory=True)
                elif kind=='fifo':os.mkfifo(path)
                else:path.mkdir()
                try:
                    with self.assertRaises(PhaseError):
                        with _guard_native_original_intents(self.binding):self.fail('unsafe entry skipped')
                finally:
                    if kind=='bad-name':path.rmdir()
                    else:path.unlink()

    def test_orphan_reservation_blocks_without_publishing_or_deleting_anything(self):
        run=self.run_root('synthetic-orphan')
        self.refused('ntfs.original_history_unresolved')
        self.assertEqual(list(run.iterdir()),[]);self.assertTrue(run.is_dir())

    def test_existing_core_quarantine_requires_exact_uuid4_and_no_authoritative_file(self):
        name='.abandoned-synthetic-prior-'+uuid.uuid4().hex
        run=self.run_root(name)
        with _guard_native_original_intents(self.binding):pass
        (run/'intent.json').write_bytes(b'{}')
        self.refused('ntfs.original_history_unresolved')

    def test_non_uuid4_quarantine_prefix_cannot_hide_a_reservation(self):
        self.run_root('.abandoned-synthetic-prior-'+'a'*32)
        with self.assertRaises(PhaseError):
            with _guard_native_original_intents(self.binding):self.fail('invalid quarantine accepted')

    def test_real_core_preintent_rejection_is_inspected_without_target_authority(self):
        run=self.run_root('synthetic-rejected');receipt=self.rejection(run.name)
        (run/'receipt.json').write_bytes(canonical_bytes(receipt))
        with patch('phase_tool.core.inspect_run',side_effect=AssertionError('preintent rejection needs no target inspector')):
            with _guard_native_original_intents(self.binding):pass
        self.assertEqual((run/'receipt.json').read_bytes(),canonical_bytes(receipt))

    def test_preintent_rejection_requires_present_hash_exact_attachments(self):
        run=self.run_root('synthetic-rejected');receipt=self.rejection(run.name)
        folder=run/'attachments';folder.mkdir(mode=0o700);raw=canonical_bytes([])
        attachment=folder/'validator-results.json';attachment.write_bytes(raw)
        receipt['evidence'].update(attachment_digests=[digest_bytes(raw)],required_attachments_present=True)
        (run/'receipt.json').write_bytes(canonical_bytes(receipt))
        with _guard_native_original_intents(self.binding):pass
        attachment.write_bytes(canonical_bytes([{}]));self.refused('ntfs.original_attachment_mismatch')
        attachment.unlink();self.refused('ntfs.original_attachment_mismatch')

    def test_rejection_cannot_hide_executed_unknown_reused_or_orphan_effects(self):
        run=self.run_root('synthetic-rejected');original=self.rejection(run.name)
        for mutate in (
            lambda r:r.update(execution_disposition='executed'),
            lambda r:r.update(prior_verified_receipt_digest='sha256:'+'f'*64),
            lambda r:r.update(blockers=['broker.dispatch_outcome_unknown']),
            lambda r:r['evidence'].update(intent_digest='sha256:'+'f'*64),
            lambda r:r['contract'].update(package_digest='sha256:'+'f'*64),
        ):
            receipt=deepcopy(original);mutate(receipt);(run/'receipt.json').write_bytes(canonical_bytes(receipt))
            with self.assertRaises((PhaseError,ValidationError)):
                with _guard_native_original_intents(self.binding):self.fail('contradictory receipt accepted')
        (run/'receipt.json').write_bytes(canonical_bytes(original))
        attachments=run/'attachments';attachments.mkdir(mode=0o700)
        (attachments/'effect-receipts.json').write_bytes(b'[]')
        self.refused('ntfs.original_history_unresolved')

    def test_executed_original_blocks_all_changed_keys_and_terminal_looking_receipts(self):
        run=self.save_original()
        for key in ('different-one','different-two'):
            self.intent['idempotency']['key']=key;self.save_original(run)
            for terminal in (False,True):
                receipt=run/'receipt.json'
                if terminal:receipt.write_bytes(canonical_bytes(self.rejection(run.name)))
                elif receipt.exists():receipt.unlink()
                with patch('phase_tool.core.inspect_run',side_effect=AssertionError('native target reached POSIX inspection')):
                    self.refused('ntfs.original_history_unresolved')
        self.assertTrue((run/'intent.json').exists())

    def test_false_planned_original_does_not_bypass_unavailable_profile_coverage(self):
        self.intent['execution_requested']=False;run=self.save_original();self.planned_receipt(run)
        self.refused('inspection.native_installation_required')

    def test_corrupt_noncanonical_and_linked_originals_never_reach_body(self):
        run=self.run_root()
        for raw in (b'{}',b'{}\n',b'not json'):
            (run/'intent.json').write_bytes(raw)
            with self.assertRaises((PhaseError,ValueError)):
                with _guard_native_original_intents(self.binding):self.fail('corrupt original accepted')
        (run/'intent.json').unlink();(run/'intent.json').symlink_to(run/'missing')
        self.refused('ntfs.original_evidence_object_unsafe')

    def test_identity_replacement_is_detected_and_primary_body_error_is_preserved(self):
        original=OSError('synthetic primary body error')
        with self.assertRaises(OSError) as caught:
            with _guard_native_original_intents(self.binding):
                self.runs.rename(self.phase/'original-runs');self.runs.mkdir(mode=0o700)
                raise original
        self.assertIs(caught.exception,original)
        self.assertTrue(any('secondary identity failure' in value for value in original.__notes__))

    def test_identity_replacement_after_normal_body_is_refusal(self):
        with self.assertRaisesRegex(PhaseError,'ntfs.original_evidence_identity_mismatch'):
            with _guard_native_original_intents(self.binding):
                self.runs.rename(self.phase/'original-runs');self.runs.mkdir(mode=0o700)

    def test_planned_controls_are_bounded_before_existing_metadata_inspection(self):
        self.intent['execution_requested']=False;run=self.save_original();self.planned_receipt(run)
        (run/'attachments'/'effect-plan.json').write_bytes(b' '*(2*1024**2+1))
        with patch('phase_tool.core.inspect_run',side_effect=AssertionError('unbounded inspector reached')):
            self.refused('stream.limit_exceeded')

    def test_replaced_lock_name_is_detected_before_releasing_held_inode(self):
        with self.assertRaisesRegex(PhaseError,'ntfs.original_evidence_identity_mismatch'):
            with _guard_native_original_intents(self.binding):
                lock=next((self.phase/'locks').iterdir())
                lock.unlink();lock.write_bytes(b'')

    def test_planned_original_without_receipt_never_reaches_state_or_recovery_hooks(self):
        self.intent['execution_requested']=False;self.save_original()
        with patch('phase_tool.core.inspect_run',side_effect=AssertionError('missing-receipt inspector reached')):
            self.refused('ntfs.original_history_unresolved')

    def test_primary_body_error_survives_actual_lock_cleanup_then_synthetic_exit_fault(self):
        primary=ValueError('synthetic first body error');secondary=OSError('synthetic exit fault')
        real=core_module._OperationalFileLock.__exit__
        def fail_after_cleanup(lock,*args):real(lock,*args);raise secondary
        with patch.object(core_module._OperationalFileLock,'__exit__',fail_after_cleanup):
            with self.assertRaises(ValueError) as caught:
                with _guard_native_original_intents(self.binding):raise primary
        self.assertIs(caught.exception,primary);self.assertIs(primary.__cause__,secondary)
        self.assertTrue(any('secondary lock-finalization failure' in note for note in primary.__notes__))
        with _guard_native_original_intents(self.binding):pass

    def test_primary_scan_error_survives_actual_lock_cleanup_then_synthetic_exit_fault(self):
        self.run_root('synthetic-orphan');secondary=OSError('synthetic exit fault')
        real=core_module._OperationalFileLock.__exit__
        def fail_after_cleanup(lock,*args):real(lock,*args);raise secondary
        with patch.object(core_module._OperationalFileLock,'__exit__',fail_after_cleanup):
            with self.assertRaisesRegex(PhaseError,'ntfs.original_history_unresolved') as caught:
                with _guard_native_original_intents(self.binding):self.fail('orphan admitted')
        self.assertIs(caught.exception.__cause__,secondary)
        self.assertTrue(any('secondary lock-finalization failure' in note for note in caught.exception.__notes__))

    def test_successful_body_with_synthetic_exit_fault_is_not_success(self):
        secondary=OSError('synthetic exit fault');real=core_module._OperationalFileLock.__exit__
        def fail_after_cleanup(lock,*args):real(lock,*args);raise secondary
        with patch.object(core_module._OperationalFileLock,'__exit__',fail_after_cleanup):
            with self.assertRaises(OSError) as caught:
                with _guard_native_original_intents(self.binding):pass
        self.assertIs(caught.exception,secondary)
        with _guard_native_original_intents(self.binding):pass


if __name__=='__main__':unittest.main()
