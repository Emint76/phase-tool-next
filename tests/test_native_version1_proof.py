"""Pure historical consistency checks on EXPLICIT synthetic proof claims.

Calls only the inner correlation predicate, not the admitted proof verifier.
No startup/profile authentication, evidence durability, native I/O, real
worker HANDLE, inspect execution, G01 or Windows qualification is established.
"""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import proof,parent_result
from phase_tool.mutation.ntfs.handoff import ParsedNativeVersion1
from .test_native_version1_parent import fixture,grant

def facts_fixture():
    ctx,effect,content,reply=fixture()
    receipt={'run_id':ctx['run_id'],'evidence':{'intent_digest':ctx['intent_digest']},
        'effect_receipts':[reply['completion']['effect_receipt']],
        'execution_disposition':'executed','mutation_attempted':True}
    physical={'run_id':ctx['run_id'],'local_channel_sealed':True,'server_ingress_sealed':True,
        'parent_safety_established':True,'no_dispatch_safety_established':False,
        'possible_dispatch':True,'no_dispatch_finalization':None,'parent_response':reply,
        'observations':{'post_operation':{'run_id':ctx['run_id'],
            'observation':deepcopy(reply['post_observation'])}}}
    saved={'physical':physical,'common_guard_finalized':True,
        'idempotency':{'enter_started':True,'entered':True,'finalized':True}}
    manifest={'contract':{'id':'publish_new_version.v1'},'root_grants':[grant()]}
    parsed=ParsedNativeVersion1(canonical_bytes(ctx),canonical_bytes(grant()),canonical_bytes(effect),
        content,receipt['effect_receipts'][0]['started_at'])
    binding=SimpleNamespace(read=Mock(return_value=parsed))
    return binding,manifest,receipt,saved,ctx,effect

class Version1ProofCorrelationTests(unittest.TestCase):
    def test_positive_pair_returns_both_parent_full_ids(self):
        binding,manifest,receipt,saved,ctx,_=facts_fixture()
        nonce,ids=proof._facts(binding,manifest,receipt,saved)
        self.assertEqual(nonce,ctx['operation_nonce'])
        pair=saved['physical']['parent_response']['post_observation']
        self.assertEqual(ids,{k:pair[k]['native']['native_identity'] for k in ('current','archive')})
        binding.read.assert_called_once_with(run_id=ctx['run_id'],intent_digest=ctx['intent_digest'])

    def test_each_causal_full_id_substitution_rejects_even_with_identical_bytes(self):
        for name in ('current','archive'):
            with self.subTest(name=name):
                binding,manifest,receipt,saved,_,_=facts_fixture()
                pair=saved['physical']['observations']['post_operation']['observation']
                old=deepcopy(pair[name]['state'])
                pair[name]['native']['native_identity']['file_id']='6'*32
                self.assertEqual(pair[name]['state'],old)
                with self.assertRaisesRegex(PhaseError,'ntfs.native_identity_mismatch'):
                    proof._facts(binding,manifest,receipt,saved)

    def test_later_changed_bytes_on_same_ids_remain_truthful_postcondition_failure(self):
        from phase_tool.canonical import digest_bytes
        from phase_tool.contracts.publish_new_version_v1 import _postcondition_result
        binding,manifest,receipt,saved,_,effect=facts_fixture()
        pair=saved['physical']['observations']['post_operation']['observation']
        changed=b'later synthetic content'
        pair['current']['state'].update(digest=digest_bytes(changed),length=len(changed))
        pair['current']['native'].update(digest=digest_bytes(changed),length=len(changed))
        proof._facts(binding,manifest,receipt,saved)
        current,archive=({k:pair[name]['state'][k] for k in ('exists','digest','length')}
            for name in ('current','archive'))
        status,_,_,_,blockers=_postcondition_result(effect,current,archive)
        self.assertEqual(status,'fail');self.assertTrue(blockers)

    def test_shared_parent_receipt_fields_reject_independently_of_physical_claims(self):
        changes=[('attempted',False),('archive_target',{'root_binding':'phase_result_root','relative_locator':'other'}),
            ('finished_at','2026-01-02T00:00:00Z'),('error',{'code':'synthetic','message':'synthetic'}),
            ('verification_refs',[]),('verification_refs',['native.current.after'])]
        for field,bad in changes:
            with self.subTest(field=field,bad=bad):
                _,_,_,saved,ctx,effect=facts_fixture()
                reply=saved['physical']['parent_response']
                reply['completion']['effect_receipt'][field]=bad
                with self.assertRaises(PhaseError):
                    parent_result.validate_version1_parent_completion(reply,context=ctx,grant_data=grant(),effect=effect)

    def test_run_wrapping_and_duplicate_causal_slot_cannot_repair_binding(self):
        for change in ('wrong_run','pre_slot'):
            with self.subTest(change=change):
                binding,manifest,receipt,saved,_,_=facts_fixture()
                observations=saved['physical']['observations']
                if change=='wrong_run':observations['post_operation']['run_id']='other'
                else:observations['pre_operation']=deepcopy(observations['post_operation'])
                with self.assertRaises(PhaseError):proof._facts(binding,manifest,receipt,saved)
