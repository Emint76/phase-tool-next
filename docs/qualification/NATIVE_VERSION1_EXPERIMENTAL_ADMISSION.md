# Closed native Version1 experiment: minimal admission

Status: implementation draft, NOT_VERIFIED. No Version1 native operation has
been performed by this source checkpoint. This document is an intended design,
not a qualification or supported release claim.

## Purpose and boundary

The existing `publish_new_version.v1@1.0.0` contract updates one current file,
preserving the previous bytes at its deterministic SHA-256 archive locator.
Its existing native mechanism uses archive-first publication and an in-place
current-file update. It has **atomicity: none** and no automatic recovery.
Failures must retain the actual current, archive and execution evidence for the
contract's documented manual decision. This experiment adds no rollback promise.

The new fixed launcher selects only manifest generation 1.2, its literal new
registry and candidate authority descriptor, and one immutable raw admission
context. The context binds the exact contract package, run, idempotency key,
candidate and frozen payload digests/length, single synthetic result-root grant,
evidence/preparation identities and candidate wheel. It is outside operation
JSON, has no plugin or profile selector, and is not a credential against an
administrator replacing the runtime.

Only the project's owned synthetic NTFS experiment roots are accepted. Evidence
and preparation remain in separate owned ext4 volumes. Normal startup and the
production qualification guard remain unchanged and must refuse this candidate.
The descriptor has empty `provided_guarantees` and `conformance`. A05/G01/G02,
qualification and supported release remain NOT_VERIFIED.

## Reused owners and necessary additions

| Component | Existing owner / reason for the small addition |
| --- | --- |
| Candidate, freeze, intent, plan, idempotency and receipt | Existing Phase Core and Version1 contract; no format or semantic change |
| Deterministic previous-content archive and current update | Existing Version1 effect and native hook; no second version store |
| Windows mutation and completion witness | Existing Version1 worker, ChannelV3 and retained creation-handle completion |
| Read-only verification | Existing parser and separate inspect role/channel, original ext4 evidence and independent Windows reads |
| Experimental admission data | Binds one exact run to generation 1.2 and the expected-current digest through the complete candidate digest; preserves the existing five required obligations without pretending they are qualified |
| Candidate authority | Inherits existing lifecycle and changes only the exact Version1 contract/profile selection |
| Fixed registry, descriptor and launcher | Give the closed installation an unambiguous identity; published historical descriptors and trust roots are not rewritten |
| Shared dispatch predicate | Accepts only literal authority classes paired with their literal admission classes; rejects request-defined subclasses |

The five Version1 obligations are `exclusive_create`, `readback_verification`,
`cross_process_serialization`, `namespace_bound_mutation` and
`namespace_metadata_flush_attempted`. Existing File1/File2 still require their
original three. Declaring and checking this set is not executable evidence that
each guarantee holds on NTFS. Existing parser, mechanism limits, preconditions
and saved-byte validation remain authoritative.

There is no additional pending/finalized state, journal, queue, lock service,
receipt store or document history mechanism.

## First functional execution and remaining history integration

The first standalone Version1 case may begin with an explicitly identified L1
synthetic before-file. The unchanged contract requires a present file with the
expected digest; it does not require a previous File1 receipt. The new payload,
archived old payload and current payload must all be independently checked.
This case must not be reported as File1-to-Version1 historical continuity.

A real mixed File1-to-Version1 history requires the existing Core guard to
verify each original run with its own exact contract/registry/authority binding
under the same physical evidence identity and lock. Current shared-history
generation 1.4 requires a common closed binding. Its rules will not be rewritten
or filtered to make an experimental single-run capability appear compatible.
Unknown, orphaned or unverifiable history must continue to block mutation.
This integration remains NOT_VERIFIED and is separate from the first functional
case; no second history store or evidence-root escape is permitted.

## Verification still required

The source-only regressions test exact contract and obligation selection, frozen
data-only context, negative generation/grant/archive bindings and subclass
refusal. Their reduced dictionaries exercise only the extra admission check
after the full existing parser; they are not genuine Core execution evidence.
The Linux authority-class predicate test is pure and explicitly skipped on
Windows, without replacing the platform or mocking a qualification PASS.

Before native execution: independently review and preserve exact source bytes,
pass affected regressions, build and audit a new candidate, review the bounded
owned canary, then execute actual Core -> worker -> current/archive -> receipt ->
fresh independent inspect. Native size boundaries, interruption, conflicts,
lost responses, mixed history, CLI/MCP and old-new-old native rollback remain
unverified until their actual corresponding tests are recorded.
