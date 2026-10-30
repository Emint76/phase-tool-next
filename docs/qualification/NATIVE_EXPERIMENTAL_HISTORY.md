Later checkpoint: the [first shared native history](FIRST_NATIVE_SHARED_HISTORY_RESULT.md)
completed File1 D0 -> Version1-A D1 -> Version1-B D2 on source0393fda2,
with current D2, full D0/D1 archives and three receipts/fresh RO inspectors.
This is one closed functional experiment; broader qualification and remaining
Version2/bundle routes are still pending. Earlier checkpoint statements below
remain historical and do not describe this subsequent result.

# Minimal shared history composition: implementation checkpoint

The first standalone native Version1 case completed at source15f2ed5, as recorded
in FIRST_NATIVE_VERSION1_RESULT.md. The next bounded experiment is one physical
domain containing File1 D0 -> Version1-A D1 -> Version1-B D2, retaining archives
D0/D1 and all original intents/proofs/receipts. This document does not report
execution or qualification of that sequence.

## Necessary changes and existing owners

| Change | Concrete need and reuse |
|---|---|
| New immutable experimental history profile | The old Version1 descriptor explicitly excludes cross-contract history and requires a disjoint domain. Its bytes/binding remain unchanged. The new candidate has no provided guarantees/conformance and uses the existing authority lifecycle and effects. |
| Accepted config1.2 / history set1.2 | Two Version1 runs have different admission/installation bindings; contract-only selection is ambiguous. Three installation-owned manifest/admission rows provide read expectations. They are not a writable journal or an index derived from evidence. Each launcher retains exactly one active write cap. |
| Data-only read-binding resolver | Recheck each row with a literal code-selected registry/profile and its complete cap. Historical rows create no authority, channel, worker or target access. Current-launch wheel checks remain on the active launcher. |
| Existing Core guard/idempotency scan selection | Choose the accepted run first, then check its own full contract/Core/installation/registry bindings. Scan every original and refuse unknown, proofless or unclosed work. Core still owns locks, intent, key/scope/request digests, receipt and recovery. |
| Fixed history startup | An immutable config chooses File1 or Version1 admission. An incoming run ID cannot select a companion or acquire dispatch authority. Existing parent/worker/core/inspect/original roles and protocols remain. |

There is no new Core, PENDING/FINALIZED protocol, mutable coordination journal,
queue, history table or document-version owner. Version1 archive naming, saved
preconditions and non-atomic/manual-handling semantics are unchanged. Contract,
intent, proof and receipt schemas do not change. Ordinary startup/qualification
guards continue to reject these unqualified candidates.

The composition checks identical physical NTFS grant except the contract-owned
root alias; identical Core/composition/wheel, evidence/preparation roots and
identities, authorization and target; three unique run/installation identities;
and exactly one active manifest/cap. Existing standalone profiles cannot be used
as the new composition merely by adding a history field.
The exact three-row set is mandatory in the resolver, installation constructor
and original guard, before lock/channel/evidence actions; no singleton fallback
is allowed for either of the two new admission types.

## Idempotency and publication window

Absence of an old experimental profile in a current registry does not itself
prove that validate_intent fails: its contract/schema may still be available.
The new scan nevertheless uses the original accepted row and exact static
bindings, rather than relying on accidental schema compatibility. No original
is filtered because its key differs. The existing scope/request formulas,
including natural input frozen_at, remain unchanged.

The positive sequence uses different keys. Reusing a Version1 key for a changed
request must reach the existing same_key_conflict check; changing a key/scope
to avoid that result is prohibited. Reuse requiring fresh observation of a prior
installation remains fail-closed pending an accepted historical RO observation
path. Immutable historical proof is not verification of current target bytes.

The common guard covers dispatch, worker quiescence and checked guard exit.
Proof/receipt publication follows outside that lock. A successor that reaches
the intervening unclosed original must refuse; absence of a receipt does not
prove absence of an executing worker. No additional marker is introduced.

After a lawful update, historical immutable closure and fresh inspect of an old
current file have distinct meanings: closure may remain valid while fresh target
verification reports changed bytes. Neither claim may overwrite the other.

## Pending acceptance

Source review, isolated correlation/regression tests, real shared-domain sequence,
attained concurrent/unclosed windows, failure/replay and historical-inspect checks
remain required. A05/full G01 and final family qualification remain NOT_VERIFIED.
This intermediate implementation does not qualify MIX/FULL, complete the other
three native contracts, authorize production deployment or permit a support release.
