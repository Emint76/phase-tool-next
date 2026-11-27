# Native terminal receipt integration component

This is an unselected lifecycle component. It does not provide an NTFS route,
installation factory, parent relay, admission, native finalizer or closure.
A05/G01, native Core end-to-end, MIX, FULL and native runtime rollback remain
NOT_VERIFIED. No supported-feature release is justified by these changes.

## Reuse of the existing Core

Public `PhaseCore.run()` keeps its API and delegates to the same lifecycle body.
Normal Host execution uses no native context and retains its existing receipt
writes and exception handling. No contract, registry, schema, profile or
historical binding changes in this component.

The private lifecycle seam can prepare a terminal outcome without publishing it.
It covers all six persisted terminal sites and the existing unsaved outcome.
Only owned canonical bytes are retained in memory; each returned view is separate.
One-use admission to this transient context occurs before EvidenceStore reservation.
Entering the inner lifecycle, attempting original-intent publication and entering
the Broker are sticky facts. Broker entry is not a proven GO or effect.

A future closed native wrapper must independently admit its actual installation,
acquire the original-intent guard before reservation, preserve original facts,
establish worker quiescence and check all operation-resource finalization. Only
then may its finalizer build proof and attempt the one immutable receipt write.
That wrapper and finalizer are not present in this component.

If a per-key context exit fails after an executed draft was prepared, the outer
handler now preserves that draft and propagates the error for the future native
finalizer. If draft serialization fails, the inner facts still prevent an outer
no-effect rejection based on its unrelated empty locals. An absent draft means
unresolved outcome. A pending draft's status is not an acknowledged durable receipt.

## Why these small additions are necessary

|Addition|Concrete failure addressed|Existing mechanism reused|
|---|---|---|
|Transient terminal context|Receipt must follow checked native-resource exits; the current lifecycle writes inside its per-key context|Same Core body, outcomes, EvidenceStore and receipt construction; no persistent state|
|Sticky inner/intent/Broker facts|Outer handler otherwise lacks inner effect state after an exit or serialization error|Original intent remains the durable uncertainty barrier|
|Checked mode of existing operational lock|Legacy unlock errors are suppressed; path rebinding and close errors cannot justify native finalization success|Same lock purpose/path and flock, with parent/leaf identity checks and one-attempt cleanup|

No PENDING/FINALIZED store, coordination journal, shared queue, mutable history
index, alternate receipt owner or document-versioning system is added. Existing
native-original guard still refuses every executed native original; no receipt
or current absence is newly accepted as closure.

## Checked-lock boundary

Checked mode is Linux control/evidence logic. Control-lock opening stays in the
existing evidence IO module; Core keeps the lifecycle and flock. The existing
architecture inventory and its module restrictions are unchanged. It opens a verified existing parent,
opens the lock leaf relative to that pinned parent with O_NOFOLLOW/O_CLOEXEC,
checks ownership/mode and parent/name identities, and reports uncertain unlock or
close rather than retrying. A namespace mismatch still triggers independent
cleanup of the proven owned descriptor. A foreign reused descriptor is not closed.

The common guard separately verifies evidence-root ancestors. O_NOFOLLOW on one
leaf does not confine all ancestors. Device/inode equality does not authenticate
an open-file-description after hostile reuse of the same inode. The future fixed
bootstrap must forbid descriptor transfer, fork and concurrent ownership. Arbitrary
asynchronous cancellation at every Python instruction is not demonstrated.

## Verification boundary

The added tests use real ordinary Host qualification, its actual registered
profile, unchanged contracts and owned synthetic ext4 roots. They exercise this
private Core component, including a real POSIX effect with receipt still pending;
they never admit a native installation or bypass a guard for NTFS. Existing child
contention tests exercise the checked common-lock path using actual kernel flock.

New fault cases cover pending-byte aliasing, reused context before reservation,
per-key exit after actual cleanup, serialization/decoding after a real POSIX effect,
checked unlock/close, parent/name rebinding, parent mode drift and FD identity loss.
Injected faults are synthetic and identified as such. No fault is a positive native
qualification result. Current execution status belongs to CI/evidence for its exact
HEAD; source review alone is not a passing test.

## Work still required in this same implementation

Connect the independently trusted startup/installed graph and Windows parent,
new immutable native profile/schema/composition where needed, native identity and
physical predicates, the whole-effect Broker handoff, late execution proof,
terminal finalizer and read-only native inspection. Evidence-only confirmation
must handle a visible receipt without publisher fsync acknowledgement under the
same guard, with exact dependencies and no second receipt publication. Preserve
the old publication/delivery error. Original unknown worker outcomes keep blocking.
