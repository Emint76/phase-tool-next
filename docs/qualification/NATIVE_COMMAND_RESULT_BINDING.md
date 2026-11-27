# Fixed native delivery: contextual run correlation candidate

This is an unqualified software correction for PR #14. No native successful
execution, A05/G01, complete MIX/FULL qualification, rollout, rollback, merge or
release is claimed. The existing qualified POSIX path and production settings
are unchanged. Full native streaming/version/bundle work remains unfinished.

## Source finding, not an emitted runtime failure

The immutable command-result1.0 schema allows a nullable run_id for startup
failures. Structurally it also permits a successful or receipt-bearing payload
with run_id:null. Both the fixed Windows parent and MCP adapter previously
accepted that nested null under a correctly scoped outer envelope. Independent
source review confirmed this latent validation gap; there is no evidence that
an honest Core actually emitted that malformed success or that a native target
was changed as a result. Synthetic regression inputs must not be called Core
receipts or successful NTFS executions.

The first native prepared file_create.v1 source graph already connects the
existing application/Core, Broker, native worker, one Core evidence/receipt and
fresh read-only inspector. No additional writer, queue, journal, finalizer or
version store is required to close this correlation gap. Actual runtime
correctness and accepted namespace lifetime still need the isolated stand.

## Minimum correction and ownership

One pure private helper in existing parent_result checks result/run correlation.
A non-null result must name the exact requested run. The null1.0 exception
requires the complete existing application failure projection: explicit run_id
and nullable fields, success false, terminal rejected, not_executed, mutation
false, strict integer exit10, no receipt/intent/plan digests or target verification,
a nonempty error and its single matching blocker. Missing fields do not stand
for explicit null. The helper neither authenticates the producer nor replaces
the full existing schema validator.

The parent separately requires its existing actual no-dispatch facts before
accepting that null1.0 exception: no spawn attempt, no GO attempt, no worker and
an integer worker count of zero. A completed/finalized worker does not permit a
later unscoped mutation-false startup refusal. Existing failed/unfinished-worker
requirements for typed uncertainty remain in place.

Null1.2 preserves the existing forced uncertainty, including explicit null
original-receipt claims, exit40, inspection required and retry forbidden. Known
intent/effect-plan digests and nullable dispatch/publication facts are retained
unchanged. MCP keeps the actual launch and becomes unavailable on uncertainty
or parent/result failure. A Docker CLI exit still does not prove an orphaned
native worker ended. Neither helper nor adapter resets that state or retries.

No schema/history, contract, registry/profile/descriptor, qualification flag,
Core lifecycle, physical Windows API or canonical result/evidence owner changes.
The same fixed parent and MCP boundaries call the helper; guard admission stays
closed. Ordinary path/value publication and all existing version/recovery
contracts retain their current ownership and limits.

## Execution pending and precise boundaries

At source publication, the six new regression methods are **UNEXECUTED**.
The predicted next Linux suite is1274 unique cases:1273 PASS and one exact old
SKIP. All1268 previously accepted identities/statuses must remain unchanged;
tracked sdist Python helpers become82, product files230 and wheel RECORD236.
A changed HEAD needs its own automatic CI, raw XML, exact source/package byte
checks and installed ordinary CLI/MCP/recovery/resource regressions. Old green
results cannot accept a changed wheel or tree.

Tests feed deliberately malformed successful/evidence/partial/missing-key data
into the real parent/finalizer/strict seal and MCP owner/result validator. OS,
process creation, worker-state facts and ACKs are explicit synthetic boundaries.
They establish contextual refusal/owner retention and compatibility with exact
startup refusals and typed uncertainty; they cannot establish native filesystem
or executable immutability guarantees. No profile/qualification guard is patched,
no actual NativeIO is invoked and no fake successful Core receipt is persisted.
Existing real SDK model/stdio regressions remain in the full suite.

During source review, the first proposed failure-shape exception lacked the
parent's no-dispatch context; that draft was corrected before implementation.
The first helper draft conflated missing nullable fields with explicit null;
both reviewers required field-presence checks before execution. The first test
draft imported a TestCase class at module scope; the final draft imports its
helper module to avoid duplicate pytest collection. All rejected drafts remain
in private Phase provenance. These are source corrections, not failed or passed
native runtime experiments.

The [previous publication/Core CI result](PUBLICATION_CANDIDATE_BINDING_CI.md)
applies to its exact HEAD31890ff and accepted builds. It remains immutable.
The original negative publication CI also remains FAILED with its actual
counterexamples. New source bytes, exact maps and reviews must be saved through
official own Phase/ext4, independently restored by both agents before Git, then
checked at their actual new HEAD. Two reviewers share a host/toolchain; their
checks are not external certification or required GitHub approval.

A05 true Windows SYMLINK and G01 executable/dependency namespace lifetime remain
NOT_VERIFIED, including worker uncertainty after MCP disconnect. Native first
Core create/receipt/freshinspect, six MIX contracts, full REF, FULL, accepted
CLI/MCP canary, native old-new-old rollback and final release checks remain
NOT_VERIFIED. No production Phase/Hermes, profiles, installed skills, canonical
volumes, Windows policy/privileges/ACLs, global Docker/WSL or PCR data change.
The next independent backend slice still needs existing version-contract
semantics and native primitives; this correction does not implement that family.
