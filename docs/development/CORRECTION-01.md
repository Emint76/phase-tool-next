# PHASE-NEXT-RC01-CORRECTION-01

Correction diff base: `65471fa491d922d5dbdcffca582b801079b068d0`
(tree `5600ef9b65e61152ed79076be7540f516efadecd`). Full PR base:
`080968f4cd557b9f891a2c2a34268fa8ef11ae98`. Existing private PR #2,
`feat/unified-file-publication`; normal descendant commits only.

## B1 / source identity before effect

`publish_file` passes the initially captured digest/length into the Core request.
Core compares them to the input it actually froze before creating intent/plan or
calling a mechanism. It no longer accepts a substituted capture under a new digest.
The streaming mechanism then copies to an anonymous disk-backed private descriptor,
checks its consumed digest/length before target open, and consumes that same private
descriptor. A new hash of the old mutable pathname is not the security boundary.
Small-file broker content is already an immutable byte value checked before write.
Tests replace the preparation blob after high-level revalidation (both versions,
with/without explicit expected_digest), and replace the streaming evidence blob
between the mechanism precheck and target creation. These are actual implementation
seams; RED runs showed target writes/wrong bytes, then GREEN showed rejection or
preservation of the already-fixed input. This is not an arbitrary-source atomic
snapshot guarantee. Extra disk I/O is measured on the installed rc2, not hidden.

## B2 / nonblocking target observation

Streaming target open uses pinned parent-descriptor-relative O_NOFOLLOW|O_NONBLOCK,
then fstat regular-type and descriptor/namespace identity validation. Both opens
in observation and final mechanism identity verification use this procedure.
The historical digest-bound POSIX provider artifact is unchanged. FIFO-target
inspect/recovery tests run in child processes with external timeouts: product
self-refusal is required, timeout is RED. Target identity and lock release are checked.

## B3 / saved preconditions

Missing-receipt recovery requires the full closed validator-result 1.0 structure,
exact ordered contract declarations/validator packages, original run/timestamps,
input/plan/contract bindings, the fixed emitted expected/actual/status claims and
no unsupported observation/detail attachments. No validator results are invented
or written during recovery. Historical formats retain only the bindings they
actually contain; they are not retroactively described as digest-bound attachments.
For the new bundle route, intent 1.1 additionally pins the exact pre-validator
attachment digest before execution. Rehashing an altered attachment or changing a
preparation-side hash cannot replace the externally pinned original intent.
Negative coverage: truncation, missing result, validator identity, foreign run,
changed input digest, attachment, and new-route rehash attempts.

## B5 / explicit remaining-commit continuation

Creation opt-in: `publish-bundle --publication-version 2.0` or equivalent MCP/Python.
Recovery opt-in: `recover-publication --mode commit_prepared` with original
run/request/root and expected intent digest. Default `observe`, inspect and status
remain non-mutating. Old exact `recovery.policy=none` packages cannot resume commit.

New exact contract `bundle_create.v2@1.0.0` uses
`mechanism.bundle_create_v2@1.0.0`. Its contract document format is 1.1;
intent format is 1.1. New schema resources:
- `phase-contract-1.1.schema.json`, `phase-intent-1.1.schema.json`;
- `prepared-stage.schema.json`, `continuation-intent.schema.json` (format 1.0).
All are additive, registry-digest checked and in the new exact contract package.
No historical schema/contract resource bytes are replaced.

A fully written, byte-verified and synced stage gets `attachments/prepared-stage.json`
binding its allowed locator/inode/device, request/run/plan/contract, manifest and
original intent/precondition digest. Recovery verifies the retained frozen inputs,
full membership/member bytes, owner, stage identity and exact proofs. Under the
broker-owned root lock, it validates commit preconditions and writes durable
`recovery/commit-intent.json`; only `mutation.bundle_create.commit_prepared_bundle`
performs the remaining non-replacing directory commit. It never recreates members,
uses changed current source, or renames directly from the application recovery code.

`recovery/commit-receipt.json` and digest-addressed observations are new evidence,
linked to the original intent and preparation digest. Original failed/missing receipts
are not rewritten. Current `verified_existing` is an observation, not fictional
original success; `recovery_mutation_attempted` describes this invocation.
A subsequent recovery recognizes its exact completed directory inode/owner/bytes
without duplicating the effect, including crash immediately after recovery rename.
Matching foreign bytes alone do not establish ownership. Missing/corrupt/unbound
proof, changed members/manifest, incomplete/relocated stage, foreign target and
unsupported preconditions fail closed. No arbitrary partial-file resumption,
repair, cleanup framework or power-loss-testing claim is introduced.

## Evidence and handoff

New prerelease: `1.1.0rc2` / Core/CLI `1.1.0-rc.2`. Immutable rc1 artifacts and
`ROOT/evidence/RC01/final-65471fa491d922d5dbdcffca582b801079b068d0` are historical.
New RED/GREEN logs and source SHA manifests:
`ROOT/evidence/RC01-CORRECTION-01/<checkpoint>/`.
Final exact commit/tree, CI job/step results, packages, dependencies, installed
CLI/MCP continuation checks, read-only historical compatibility and new resource
measurements are in `ROOT/evidence/RC01-CORRECTION-01/<final-head>/` and
`ROOT/artifacts/RC01/1.1.0rc2-<final-head>/`. Staging uses a literal allowlist.
Final readiness is contingent on these executable gates, never these notes alone.

Legacy chunks/reassembly: **NOT_VERIFIED** (excluded from correction). B4 remains
closed by the separate review's requirement evidence. No claim of independent
closure of findings: next is phase-review against this correction base and affected
guarantees. No reviewer agents, merge/auto-merge, release/tag, upload to registry,
production/working installation, profiles or skills are changed. Goal/budget
telemetry: NOT_VERIFIED; no state.db or budget changes.
