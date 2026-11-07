"""Real disposable ext4 metadata/lock refusal components, not native effects.

No qualification guard replacement, admitted proof, target authority, native
worker, Windows API or native inspect success. Proof envelopes below are
explicit synthetic correlation inputs; the real profile check MUST refuse.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from jsonschema.exceptions import ValidationError
from phase_tool import core as core_module
from phase_tool.canonical import canonical_bytes,digest_bytes,profile_digest
from phase_tool.core import PhaseCore,PhaseRequest,_guard_native_original_intents
from phase_tool.errors import PhaseError
from phase_tool.installation import (_linux_filesystem_type,qualify_host_authority_roots,
    _resolve_native_history_bindings)
from phase_tool.mutation.ntfs import proof as proof_module
from phase_tool.registry import BundledRegistry
from ._native_history_fixture import manifests,set_bytes,binding
from .test_native_original_intent import buffers


@unittest.skipUnless(sys.platform.startswith('linux'),'NOT_VERIFIED: requires actual Linux/ext4')
class NativeHistoryGuardTests(unittest.TestCase):
    def setUp(self):
        tmp=TemporaryDirectory(prefix='phase-native-history-');self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)/'evidence';self.root.mkdir(mode=0o700)
        qualify_host_authority_roots({'phase_evidence_root':self.root})
        if _linux_filesystem_type(self.root)!='ext4':self.skipTest('NOT_VERIFIED: ext4 required')
        self.phase=self.root/'.phase';self.phase.mkdir(mode=0o700)
        self.runs=self.phase/'runs';self.runs.mkdir(mode=0o700)
        info=self.root.stat()
        self.registry,self.leaves=manifests(str(self.root),{'stable_id':'synthetic.history.ext4','device':info.st_dev,'inode':info.st_ino})
        self.raw=set_bytes(self.leaves)
        self.bindings=tuple(binding(self.registry,leaf) for leaf in self.leaves)
        self.history=_resolve_native_history_bindings(self.bindings[0],self.raw,digest_bytes(self.raw))

    def rejection(self,index,name):
        b=self.leaves[index]['contract']
        request=PhaseRequest(b['id'],b['version'],b['package_digest'],self.root/'unused.json',
            self.root,name,{}, {},timestamp='2026-10-24T00:00:00Z')
        receipt=PhaseCore(self.registry)._rejection_receipt(request,[],request.timestamp,'synthetic.rejected')
        run=self.runs/name;run.mkdir(mode=0o700)
        (run/'receipt.json').write_bytes(canonical_bytes(receipt))
        return run,receipt

    def guard(self,index=0,history=True):
        return _guard_native_original_intents(self.bindings[index],
            history_bindings=self.history if history else None)

    def test_both_contract_orders_visit_all_real_core_rejections_without_target_or_new_owner(self):
        self.rejection(0,'synthetic-file1-rejected');self.rejection(1,'synthetic-version1-rejected')
        originals={p:p.read_bytes() for p in self.runs.rglob('*') if p.is_file()}
        before=None
        for index in (0,1):
            with (patch.object(core_module,'validate_receipt',wraps=core_module.validate_receipt) as verify,
                    patch.object(core_module,'inspect_run',side_effect=AssertionError('preintent target inspection'))):
                with self.guard(index) as value:self.assertIsNone(value)
                self.assertEqual({c.args[0]['contract']['id'] for c in verify.call_args_list},
                    {'file_create.v1','publish_new_version.v1'})
            locks={p.name:(p.stat().st_dev,p.stat().st_ino) for p in (self.phase/'locks').iterdir()}
            self.assertEqual(len(locks),1)
            if before is not None:self.assertEqual(locks,before)
            before=locks
        self.assertEqual(originals,{p:p.read_bytes() for p in self.runs.rglob('*') if p.is_file()})
        output=os.environ.get('EVIDENCE')
        if output:
            with (Path(output)/'native-cross-contract-noeffect-component.json').open('x',encoding='utf-8') as stream:
                json.dump({'scope':'actual ext4/Core pre-intent rejection metadata only; NOT native qualification',
                    'visited_contracts':['file_create.v1','publish_new_version.v1'],
                    'same_existing_lock':True,'preserved_receipt_hashes':{p.parent.name:digest_bytes(raw) for p,raw in originals.items()}},stream,sort_keys=True)

    def test_legacy_active_only_binding_cannot_ignore_other_contract_history(self):
        self.rejection(1,'synthetic-other-contract')
        with self.assertRaisesRegex(PhaseError,'ntfs.original_history_binding_mismatch'):
            with self.guard(history=False):self.fail('legacy guard ignored foreign history')
        with self.guard():pass

    def test_malformed_preintent_receipts_reject_before_selection_and_never_yield(self):
        run,_=self.rejection(0,'synthetic-malformed')
        for value in ([],None,'synthetic',42):
            (run/'receipt.json').write_bytes(canonical_bytes(value))
            with self.subTest(value=value),self.assertRaisesRegex(PhaseError,'ntfs.original_receipt_binding_mismatch'):
                with self.guard():self.fail('malformed rejection passed')

    def test_each_unresolved_receipt_and_foreign_orphan_blocks_entire_set(self):
        self.rejection(0,'synthetic-valid');run,receipt=self.rejection(1,'synthetic-unresolved')
        for change in (lambda r:r.update(recovery_required=True),lambda r:r.update(execution_disposition='executed'),
                lambda r:r.update(blockers=['broker.dispatch_outcome_unknown']),
                lambda r:r['evidence'].update(intent_digest='sha256:'+'f'*64)):
            bad=deepcopy(receipt);change(bad);(run/'receipt.json').write_bytes(canonical_bytes(bad))
            with self.assertRaises((PhaseError,ValidationError)):
                with self.guard():self.fail('unresolved history ignored')
        (run/'receipt.json').write_bytes(canonical_bytes(receipt))
        orphan=self.runs/'synthetic-orphan';orphan.mkdir(mode=0o700)
        with self.assertRaisesRegex(PhaseError,'ntfs.original_history_unresolved'):
            with self.guard(1):self.fail('foreign orphan ignored')
        self.assertEqual(list(orphan.iterdir()),[])

    def synthetic_proof(self,index,name):
        run,receipt=self.rejection(index,name)
        selected=self.bindings[index];leaf=self.leaves[index]
        proof={'installation':{'id':leaf['installation_id'],'descriptor_digest':selected.manifest_digest},
            'prepared_receipt_digest':profile_digest('receipt',receipt)}
        return run,receipt,proof

    def save_proof(self,run,receipt,proof):
        folder=run/'attachments';folder.mkdir(mode=0o700,exist_ok=True)
        raw=canonical_bytes(proof);(folder/'native-terminal-proof.json').write_bytes(raw)
        receipt=deepcopy(receipt);receipt['evidence']['attachment_digests']=[digest_bytes(raw)]
        (run/'receipt.json').write_bytes(canonical_bytes(receipt))

    def test_proof_role_selection_reaches_unchanged_real_unqualified_verifier_and_never_yields(self):
        for index in (0,1):
            with self.subTest(role=index):
                run,receipt,proof=self.synthetic_proof(index,'synthetic-proof-'+str(index))
                self.save_proof(run,receipt,proof)
                with patch.object(proof_module,'verify_native_terminal_proof',wraps=proof_module.verify_native_terminal_proof) as verify:
                    with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                        with self.guard(1-index):self.fail('synthetic proof admitted')
                    self.assertEqual(verify.call_args.args[0].manifest_digest,self.bindings[index].manifest_digest)
                # Keep each negative separate; this is disposable test cleanup,
                # never production history deletion or a retry workaround.
                (run/'attachments'/'native-terminal-proof.json').unlink();(run/'attachments').rmdir()
                (run/'receipt.json').unlink();run.rmdir()

    def test_unknown_malformed_proof_never_downgrades_to_contract_only_rejection(self):
        run,receipt,proof=self.synthetic_proof(1,'synthetic-bad-proof')
        for installation in (None,{},[],{'id':'synthetic.unknown','descriptor_digest':'sha256:'+'f'*64},
                {'id':self.leaves[1]['installation_id'],'descriptor_digest':self.bindings[0].manifest_digest}):
            bad=deepcopy(proof);bad['installation']=installation;self.save_proof(run,receipt,bad)
            with patch.object(proof_module,'verify_native_terminal_proof',side_effect=AssertionError('unknown selected')) as verify:
                with self.assertRaisesRegex(PhaseError,'ntfs.original_history_binding_mismatch'):
                    with self.guard():self.fail('proof downgraded to no-effect rejection')
                verify.assert_not_called()

    def test_foreign_executed_original_selects_exact_leaf_then_stays_unresolved(self):
        intent,_,_,_,_=buffers(BundledRegistry.load());leaf=self.leaves[0];selected=self.bindings[0]
        intent.update(run_id='synthetic-foreign-original',core=deepcopy(leaf['core']),
            contract=deepcopy(leaf['contract']),registry_snapshot_digest=self.registry.digest)
        intent['native_binding'].update(installation={'id':leaf['installation_id'],'descriptor_digest':selected.manifest_digest},
            composition=deepcopy(leaf['composition']),evidence_identity=deepcopy(leaf['evidence_identity']))
        intent['implementation_binding'].update(authority=deepcopy(leaf['authority']),mechanism=deepcopy(leaf['mechanism']))
        intent['idempotency']['root_identities']=deepcopy(leaf['root_grants'])
        run=self.runs/intent['run_id'];run.mkdir(mode=0o700);path=run/'intent.json';path.write_bytes(canonical_bytes(intent))
        with self.assertRaisesRegex(PhaseError,'ntfs.original_history_unresolved'):
            with self.guard(1):self.fail('executed original discharged')
        intent['native_binding']['installation']['descriptor_digest']='sha256:'+'f'*64
        path.write_bytes(canonical_bytes(intent))
        with self.assertRaisesRegex(PhaseError,'ntfs.original_history_binding_mismatch'):
            with self.guard(1):self.fail('unknown original installation selected')

    def test_primary_body_failure_preserved_and_same_lock_reusable(self):
        self.rejection(0,'synthetic-file1');self.rejection(1,'synthetic-version1')
        primary=OSError('synthetic primary')
        with self.assertRaises(OSError) as caught:
            with self.guard():raise primary
        self.assertIs(caught.exception,primary)
        with self.guard(1):pass
