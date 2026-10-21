"""Pure record/link checks, not disk durability or permission to finalize."""
from dataclasses import FrozenInstanceError, replace
import json
import unittest

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import pending as model


def digest(number):
    return 'sha256:'+f'{number:064x}'


def fixture():
    roots = (model.RootAccessV1('phase_object_root',digest(1),digest(11)),
             model.RootAccessV1('phase_result_root',digest(2),digest(12)))
    identity = model.LaneIdentityV1(digest(3),roots)
    intent = model.CoordinationIntentV1(identity.digest,'synthetic-run-1',digest(4),digest(5),digest(6),digest(7),roots)
    first = model.commissioned_record(identity)
    head = model.head_for(first)
    pending = model.pending_record(identity,head,first,intent,expected_head_digest=head.digest)
    refs = model.DirectResolutionReferencesV1('succeeded_verified',intent.run_id,intent.digest,
        pending.digest,digest(8),digest(9),digest(10))
    return identity,intent,first,pending,refs


class PendingModelTests(unittest.TestCase):
    def test_canonical_roundtrip_and_full_root_footprint(self):
        identity,intent,first,pending,refs = fixture()
        head = model.head_for(pending)
        final = model.finalized_record(identity,head,pending,refs,expected_head_digest=head.digest)
        self.assertEqual(model.LaneIdentityV1.parse(identity.as_dict()),identity)
        self.assertEqual(model.CoordinationIntentV1.parse(intent.as_dict()),intent)
        for entry in (first,pending,final):
            self.assertEqual(model.decode_entry(canonical_bytes(entry.as_dict())),entry)
            head = model.head_for(entry)
            self.assertEqual(model.decode_head(canonical_bytes(head.as_dict())),head)
        self.assertEqual(pending.intent.roots,identity.admitted_roots)
        self.assertEqual(pending.intent.phase_intent_digest,digest(4))

    def test_linked_lifecycle_and_new_generation(self):
        identity,intent,first,pending,refs = fixture()
        head = model.head_for(pending)
        final = model.finalized_record(identity,head,pending,refs,expected_head_digest=head.digest)
        head = model.head_for(final)
        following = model.pending_record(identity,head,final,replace(intent,run_id='synthetic-run-2'),
                                        expected_head_digest=head.digest)
        for previous,entry in ((None,first),(first,pending),(pending,final),(final,following)):
            model.validate_link(identity,previous,entry)
        self.assertEqual([entry.generation for entry in (first,pending,final,following)],[0,1,2,3])
        self.assertEqual(following.previous_entry_digest,final.digest)

    def test_pending_cannot_be_bypassed_by_new_run_or_other_admitted_root(self):
        identity,intent,_,pending,_ = fixture()
        head = model.head_for(pending)
        for operation in (intent,replace(intent,run_id='another-run'),replace(intent,roots=(intent.roots[0],))):
            with self.subTest(run=operation.run_id), self.assertRaisesRegex(PhaseError,'coordination.pending_unresolved'):
                model.pending_record(identity,head,pending,operation,expected_head_digest=head.digest)

    def test_resolution_allows_only_two_direct_reference_variants(self):
        identity,_,_,pending,refs = fixture()
        head = model.head_for(pending)
        for status in ('succeeded_verified','failed_no_effect'):
            final = model.finalized_record(identity,head,pending,replace(refs,outcome=status),
                                           expected_head_digest=head.digest)
            self.assertEqual(final.resolution.outcome,status)
        for status in ('failed_partial','committed_unverified','indeterminate','no_effect_observed',
                       'archived_not_published','published_not_finalized','recovered'):
            with self.subTest(status=status), self.assertRaisesRegex(PhaseError,'coordination.resolution_not_direct'):
                replace(refs,outcome=status)

    def test_resolution_references_must_match_original_pending_and_run(self):
        identity,_,_,pending,refs = fixture()
        head = model.head_for(pending)
        for invalid in (replace(refs,run_id='other-run'),replace(refs,pending_entry_digest=digest(111)),
                        replace(refs,coordination_intent_digest=digest(112))):
            with self.assertRaisesRegex(PhaseError,'coordination.resolution_binding_mismatch'):
                model.finalized_record(identity,head,pending,invalid,expected_head_digest=head.digest)

    def test_stale_or_altered_head_and_wrong_lane_are_rejected(self):
        identity,intent,first,_,_ = fixture()
        head = model.head_for(first)
        for changed,expected in ((head,digest(90)),(replace(head,generation=1),head.digest),
                                 (replace(head,entry_digest=digest(91)),head.digest)):
            with self.assertRaisesRegex(PhaseError,'coordination.head_precondition_failed'):
                model.pending_record(identity,changed,first,intent,expected_head_digest=expected)
        other = replace(identity,lane_id=digest(99))
        with self.assertRaisesRegex(PhaseError,'coordination.head_precondition_failed'):
            model.pending_record(other,head,first,intent,expected_head_digest=head.digest)

    def test_intent_and_root_grants_cannot_escape_lane_identity(self):
        identity,intent,first,_,_ = fixture()
        head = model.head_for(first)
        invalid = replace(intent,lane_identity_digest=digest(99))
        with self.assertRaisesRegex(PhaseError,'coordination.intent_binding_mismatch'):
            model.pending_record(identity,head,first,invalid,expected_head_digest=head.digest)
        root = replace(intent.roots[0],grant_digest=digest(92))
        with self.assertRaisesRegex(PhaseError,'coordination.root_not_in_lane'):
            model.pending_record(identity,head,first,replace(intent,roots=(root,)),expected_head_digest=head.digest)

    def test_footprint_order_duplicates_and_mutable_values_are_rejected(self):
        identity,intent,_,_,_ = fixture()
        for invalid in (list(intent.roots),tuple(reversed(intent.roots)),(),
                        (intent.roots[0],intent.roots[0]),
                        (intent.roots[0],replace(intent.roots[1],physical_root_key=intent.roots[0].physical_root_key))):
            with self.subTest(value=invalid), self.assertRaises(PhaseError):
                replace(identity,admitted_roots=invalid)

    def test_frozen_models_do_not_alias_returned_or_parsed_json(self):
        _,intent,_,pending,_ = fixture()
        with self.assertRaises(FrozenInstanceError):
            pending.state='FINALIZED'
        value = intent.as_dict()
        parsed = model.CoordinationIntentV1.parse(value)
        value['roots'][0]['grant_digest']=digest(777)
        self.assertEqual(parsed,intent)
        value = pending.as_dict()
        value['intent']['run_id']='modified'
        self.assertNotEqual(value,pending.as_dict())

    def test_closed_versions_and_extra_fields_including_fake_truth_flags(self):
        identity,intent,_,pending,refs = fixture()
        for parser,value,field in ((model.LaneIdentityV1.parse,identity.as_dict(),'identity_version'),
                (model.CoordinationIntentV1.parse,intent.as_dict(),'coordination_intent_version'),
                (model.LaneEntryV1.parse,pending.as_dict(),'entry_version'),
                (model.LaneHeadV1.parse,model.head_for(pending).as_dict(),'head_version'),
                (model.DirectResolutionReferencesV1.parse,refs.as_dict(),'resolution_version')):
            with self.assertRaisesRegex(PhaseError,'coordination.unsupported_version'):
                parser(value|{field:'2.0'})
            for extra in ('durable','verified','worker_stopped','recovery_resolution_digest'):
                with self.subTest(extra=extra), self.assertRaisesRegex(PhaseError,'coordination.invalid_record_fields'):
                    parser(value|{extra:True})

    def test_digest_integer_and_run_types_are_strict(self):
        identity,intent,_,pending,_ = fixture()
        for value in (None,1,True,'sha256:AB'+'0'*62,'0'*64):
            with self.subTest(value=value), self.assertRaises(PhaseError):
                replace(identity,lane_id=value)
        for value in (True,-1,2**63,1.0):
            with self.assertRaisesRegex(PhaseError,'coordination.invalid_generation'):
                replace(model.head_for(pending),generation=value)
        for value in ('../escape','.', '', 'a'*129,1):
            with self.assertRaisesRegex(PhaseError,'coordination.invalid_run_id'):
                replace(intent,run_id=value)

    def test_noncanonical_duplicate_unknown_and_invalid_bytes_rejected(self):
        _,_,_,pending,_ = fixture()
        value = pending.as_dict()
        for raw in (json.dumps(value).encode(),canonical_bytes(value)+b'\n',
                    b'{"entry_version":"1.0","entry_version":"1.0"}',b'['+b' '*65536+b']'):
            with self.subTest(raw_length=len(raw)), self.assertRaises(PhaseError):
                model.decode_entry(raw)
        for invalid in (None,bytearray(b'{}'),'{}'):
            with self.assertRaisesRegex(PhaseError,'coordination.invalid_record_bytes'):
                model.decode_entry(invalid)

    def test_no_finalization_without_pending_and_no_recommission_link(self):
        identity,_,first,pending,refs = fixture()
        head = model.head_for(first)
        with self.assertRaisesRegex(PhaseError,'coordination.not_pending'):
            model.finalized_record(identity,head,first,refs,expected_head_digest=head.digest)
        with self.assertRaisesRegex(PhaseError,'coordination.recommissioning_forbidden'):
            model.validate_link(identity,pending,first)
        with self.assertRaisesRegex(PhaseError,'coordination.invalid_entry_link'):
            model.validate_link(identity,None,pending)

    def test_chain_rejects_skipped_generation_or_wrong_predecessor(self):
        identity,_,first,pending,_ = fixture()
        for entry in (replace(pending,generation=3),replace(pending,previous_entry_digest=digest(98))):
            with self.assertRaisesRegex(PhaseError,'coordination.invalid_entry_link'):
                model.validate_link(identity,first,entry)

    def test_parsed_pending_with_unadmitted_root_is_rejected_when_linked(self):
        identity,intent,first,pending,_ = fixture()
        rogue = replace(intent,roots=(replace(intent.roots[0],grant_digest=digest(88)),))
        entry = replace(pending,intent=rogue)
        # Structural decode alone is not installation-authority admission.
        self.assertEqual(model.decode_entry(canonical_bytes(entry.as_dict())),entry)
        with self.assertRaisesRegex(PhaseError,'coordination.root_not_in_lane'):
            model.validate_link(identity,first,entry)

    def test_resolution_reference_shape_does_not_authorize_io_or_finalization(self):
        identity,_,_,pending,refs = fixture()
        head = model.head_for(pending)
        proposal = model.finalized_record(identity,head,pending,refs,expected_head_digest=head.digest)
        self.assertEqual(proposal.state,'FINALIZED')
        # This is only an immutable proposal. There is no store, process API,
        # receipt reader, dispatcher or new installed head in this module/test.
        self.assertEqual(pending.state,'PENDING')
        self.assertEqual(head,model.head_for(pending))


if __name__=='__main__':
    unittest.main()
