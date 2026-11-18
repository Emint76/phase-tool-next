# Native version1 lifecycle software candidate

This source slice extends the existing closed native composition to the
`publish_new_version.v1@1.0.0` contract. It is **unqualified software**: no
admitted native Core create/update/bundle, receipt or independent inspect has
executed. The new registry contains no production native authority profile;
the real qualification guard refuses before channel/evidence reservation.
A05 and G01 remain **NOT_VERIFIED**. There is no supported NTFS release.

The previous accepted Linux software checkpoint is HEAD
`217a748e35a00c0677ec51f750b05787fbf09fc5`, CI40042687515 (1281 PASS,
one existing NTFS guard skip in each Python lane). Those results apply to that
HEAD, not to this new source slice. New tests described here are source-reviewed
and **UNEXECUTED** until the changed-HEAD CI is separately captured and checked.

## Existing owners and minimal extensions

| Component | Failure or guarantee requiring it | Existing mechanism retained |
|---|---|---|
| Private native hook context at planning, validation, Core and inspect | A Linux projection cannot safely perform POSIX target observations on native objects | Existing contract planner, preconditions, postcondition projection, prior/missing-receipt classification and canonical-result owner |
| Fresh current/archive observations and one causal post pair | Two independently sampled objects must preserve their exact grants/locators/NativeIDs; substituted equal bytes are insufficient | Existing observe transport, one transient Core post-operation slot; no observation cache or pair service |
| Fixed bounded original transfer | Existing version1 permits 16 MiB, while the old single-frame file1 role is bounded at 1 MiB | Same reader/worker process and pipes; finite header/chunk/end, order/length/hash/context checks, one local handshake deadline; no spool, queue or general transport service |
| Scoped archive ancestor creation | The deterministic archive prefix may not exist; its already existing prefix must remain pinned | Existing NativeScopedTarget and same NativeMutationIO session; only declared parents after GO; errors seal the attempt |
| Version1 physical step | Old bytes must be independently verifiable in the archive before current is truncated | Existing archive-first/in-place contract, native root mutex, same pinned current HANDLE, exclusive archive create, data/namespace flushes and full readback; no parallel history owner |
| Pair completion and terminal proof | A completion frame cannot prove process exit; proof must bind both objects and causal observations | Existing actual creation-HANDLE witness, owner finalization, Core native-terminal-proof attachment, one receipt and original-intent guard |
| Fixed V5 registry and installation format1.2 | New executable/provider bytes must not rewrite historical immutable bindings | New immutable candidate descriptor/snapshot, closed trusted selection1.1→V4/1.2→V5; existing Core and admission guard; no request/environment provider selector |
| Independent native inspect | POSIX root resolution or fabricated byte streams would misrepresent the native target | Existing evidence verifier and contract inspect, current/archive full ID comparisons, existing reused-receipt recursion |

No new journal, PENDING/FINALIZED store, queue, head index or document version
system is introduced. The common ext4 lock scans existing Core intent/receipt
history; the Windows root mutex serializes the physical operation. Their
different responsibilities do not create a second record of version truth.

The bounded transfer uses no clock supplied in a wire frame. Parent and worker
have their own local deadlines. The parent compares **all five** original tuple
fields before GO, including the timestamp. Reader completion requires a real
empty binary pipe read, all prescribed identity rechecks and the separately
retained process witness. An arbitrary read exception/end token is not EOF.
Deadline checks do not cancel an already running OS mutation or establish the
lifetime of an orphan worker. G01 remains mandatory.

## Scope corrections discovered by source review

Earlier unexecuted drafts omitted the timestamp from READY correlation. A
timestamp-only changed original could therefore reach GO before a later
receipt check rejected it. The final new-role READY includes and checks that
field before GO; the old file1 key set remains unchanged.

Earlier unexecuted proof code validated the causal pair shape and byte states,
but did not compare its two NativeIDs with the independently checked parent
pair. The shared proof verifier now requires each known parent identity to
match. Later byte changes on the same objects may truthfully fail the existing
postcondition; whole-pair state equality is deliberately not invented.

All rejected drafts and source-generation failures are retained privately as
negative development evidence. These findings are source-derived, not actual
Windows execution counterexamples or successful qualification tests.

## Unfinished cross-contract history integration

**NOT_VERIFIED / implementation blocker:** an accepted startup currently holds
one immutable installation manifest. The existing common original-intent guard
requires that exact manifest/contract when checking every prior original and
terminal proof in the shared evidence root. A closed file1 create history
therefore blocks switching to version1 before evidence reservation or GO;
another manifest/registry generation has the same limitation.

The registry stores immutable contract packages, not authenticated historical
installation manifests. Their trust cannot be reconstructed from a proof's own
claims. Filtering out other contracts, rebinding their identities or switching
to a separate evidence root to evade this guard is prohibited. The guard is
retained unchanged. A subsequent minimal integration must reuse the existing
common guard/proof verifier with independently trusted static historical
bindings; it must not add a journal, history index or second evidence owner.
This source slice does not yet solve or claim create→version support.

Existing immutable root names are retained: file1 uses `phase_result_root`;
version1 uses `fixture_result_root`. Component fixtures with synthetic grants
do not demonstrate real contract installation compatibility. Original-parser
tests use the real version1 binding and genuine disposable Host plans/validators
before making an explicitly synthetic native structural view.

## Tests and acceptance still required

New source tests cover full 16 MiB tail hashing, finite two-leg transfer,
timestamp-only rejection with a paired positive GO model, causal EOF identity
faults, pair NativeIDs/receipt fields, one-shot post observation, archive flush
ordering before same-HANDLE truncate, error preservation and known contract
continuations. Native I/O, HANDLEs, process spawning and admission prerequisites
are explicitly substituted in component models; they are not native end-to-end
or safety qualification. Real Host plans/validators run only on disposable
Linux CI roots. No guard is disabled to claim native success.

The final gate still requires the complete six-contract MIX family, A05/G01
and the unchanged original repetitions, actual installed native CLI/MCP,
historical evidence compatibility, safe old→new→old runtime rollback, independent
review, exact-HEAD CI, accepted build bytes, legal merge and verified release
downloads. FULL remains NOT_VERIFIED and unavailable. Streaming file2/version2
and bundles are not implemented by this slice. Existing file1 and contract
limits remain unchanged; large binary history and an optional index remain
separate issues13 and15. Source/Knowledge/append/journal are not qualified.

Production Phase/Hermes, profile routing, installed skills, canonical volumes,
Windows privileges/policies/ACLs, global Docker/WSL and scientific work remain
unchanged. See [remaining qualification](FINAL_QUALIFICATION_REMAINING.md) and
[A05 stand requirements](A05_STAND_REQUIREMENTS.md).
