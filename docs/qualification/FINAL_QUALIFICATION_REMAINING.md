# Remaining final qualification — execution addendum

This document separates **implementation readiness** from **supported-route
acceptance**, following the human's continuation instruction. It does not edit
or waive the original program, repetitions, guarantees or acceptance criteria.
The original QUALIFICATION_PLAN SHA-256 is
`a502b958c18db8cdcf4e79c295da41393a796a47109e36621e987f2739a919f3`.

The implementation is still in progress. Internal native primitives and their
L1 evidence are not a complete Phase execution route. No new native storage
profile is admitted, no production configuration is changed, and no supported
NTFS release is approved. The intermediate objective is a preserved, reviewed
implementation ready for these final tests, not a replacement acceptance rule.

## Status and precise causes

| Item | Current verdict | Cause and next action |
|---|---|---|
| A05 literal native Windows SYMLINK, tag `0xA000000C` | NOT_VERIFIED | Both creation APIs returned 1314. No owned safe fixture or separately authorized suitable stand is available. Current Windows policies/privileges must not change. Replay on the separately provisioned stand described below. |
| Complete native MIX six-contract lifecycle | NOT_VERIFIED | Candidate source now includes fixed Core/Windows-worker/independent-inspect composition and a prepared MCP adapter; no admitted native end-to-end execution has been accepted. High-level native wrappers, streaming create, version updates and bundles remain unimplemented. Continue independent software work and accessible functional tests; missing software is not a Windows-rights or ChatGPT limitation. |
| G01 accepted runtime, executable/dependency namespace and lifetime | NOT_VERIFIED | Fixed launcher consistency checks do not establish deployment immutability. Qualify the exact accepted isolated Windows runtime, wheel/dependencies, launcher/manifest and Linux contours for their whole active lifetime, including unknown workers after MCP disconnect/server exit; retained references or Docker CLI exit do not establish that lifetime. No current policy/ACL changes or acceptance flag. |
| Complete final-build REF regression/program | NOT_VERIFIED | Linux CI and selected ext4 reference results exist; the entire original REF campaign has not been accepted for a final candidate. Run applicable unchanged reference and new implementation regressions against the exact accepted artifact. |
| Two-container native coordinator/alias domain | NOT_VERIFIED | Windows mutex L1 passed; the two Linux coordinators, common qualified ext4 evidence/operational lock and native worker have not been integrated/tested together. This is not a completed C02. |
| G06 lifecycle/failure propagation | NOT_VERIFIED | Native directory flush requests and bounded error probes exist, but final contract integration, exact pinned-parent call ordering and failure propagation are not accepted. |
| FULL | NOT_VERIFIED; unavailable | No admitted NTFS evidence/preparation implementation. Investigate separately. MIX acceptance does not imply FULL; FULL is not the minimum release scope. |
| Native installed CLI/MCP, historical compatibility and runtime rollback | NOT_VERIFIED | Pending the new complete installation and accepted artifact. Linux installed CLI/MCP evidence does not qualify the native route. |

No other case is labelled unavailable merely because it has not been implemented
or run. Record any later access/tool/environment failure with its exact error,
missing capability, attempted safe operation and affected case/build. Do not
bypass it; continue independent safe implementation and tests.

## Required final-build case ledger

All rows below currently remain **NOT_VERIFIED for the final admitted native
candidate**. Existing partial and historical L1 results remain valid only in
their documented exact-source scope, linked from `NATIVE_COMPONENT_STATUS.md`.
They must not be promoted to full case verdicts by this ledger.

| Original case IDs | Required remaining acceptance |
|---|---|
| A01–A04, A07 | Native root/parent/leaf identity, reached rebinding/leaf replacement, reopen and worker restart, through apply/inspect/recovery. Distinguish actual prevention from reached detection; no automatic rebinding. |
| A05 | Linux symlink, junction/LX and literal Windows file/directory SYMLINK at every applicable position; reached schedules and unchanged synthetic outside sentinels. Complete the missing native fixture cases on an authorized stand. |
| A06 | Existing locator/path policy, ADS/traversal/reserved names, case aliases and bundle casefold collisions. Preserve ASCII limits. |
| B01–B03 | Exclusive create/collisions, unchanged existing/hardlink aliases, byte-boundary/empty/NUL payloads and independent identities/hashes. |
| B04–B06 | Short/zero writes, I/O/access/space/flush errors, partial create/payload crashes and capture/frozen-input drift. Label injection versus actual OS behavior. Never fill the shared disk. |
| B07–B08 | Both high-level file API generations, digest/root/overlap negatives and unchanged 1 MiB/2 GiB boundaries including +1 rejection before mutation. |
| C01–C02 | Lock release/crash/timeout and aliases across two private containers of the same engine; stable common original-intent guard plus native mutex/worker. Mutex-only L1 does not complete the composed protocol. |
| C03–C06 | Same-key concurrent/completed/lost-response replay, changed-input conflicts, different-key create/version competition, and natural capture timestamps. Do not fix timestamps or change keys to hide conflicts. |
| D01 | 1000 real atomic current replacements; two continuous independent readers with at least 1000 successful samples each. Old/new-only observations; retained old-handle reads. |
| D02–D03 | Native no-replace directory commit, existing empty/nonempty targets and competition; hardlink objects, digest collisions, identities/link counts and safe private-link cleanup. Retain the historical 9p EINVAL counterexample. |
| D04–D05 | Version v1 archive-before-current and non-atomic partial semantics; version v2 immutable old/new objects, collision/precondition checks and one final atomic replace. No invented CAS claim. |
| D06–D08 | Both bundle families, exact member/owner/manifests, concurrent/existing targets, unchanged file/count/depth/aggregate/request limits and cross-volume failure without copy/delete fallback. |
| D09 | A→B→C→A and A→A, all version requests/objects/archives/receipts; historical inspect limitations and reconstructable ordering reported separately. |
| E01–E02 | Exact nonmocked file/namespace flush on the correct pinned native handles, error propagation and documented forwarding/unknown persistence. G06 promises an attempted request, not survival of power loss. |
| E03–E04 | Actual selected ext4 evidence/preparation atomic paths and failure windows in MIX; NTFS evidence/preparation only for a separately tested FULL scope. |
| E05–E08 | Request/intent/plan/effects/receipt/native root and implementation bindings, separate-process inspect, all tamper cases and honest historical status. Status is not target verification or liveness. |
| F01–F04 | Every reservation/intent/payload/staging/preparation/commit/lost-response window; full bound proof before commit_prepared and honest unknown outcomes. |
| F05–F07 | Read-only publication recovery, authorized bundle commit_prepared and concurrent/repeated recovery; release/close errors never become success even after commit. |
| F08–F09 | Exact contract-supported version continuation after independent investigation, original evidence unchanged, restart/replay with original identities and no new-key/root escape. |

New composition also requires crash tests before/after the original Core intent,
dispatch, native commit, lost response, original worker completion, receipt and
permitted recovery. Test stale IPC after completed work, two coordinators
attempting conflicting evidence bindings, overlapping grants and an orphan
native syscall. Unknown cannot be inferred away from an empty receipt list.
The former second entry/head/generation journal is superseded; original intent,
receipt, binding and recovery coverage remains mandatory. See the
[complexity decision](ARCHITECTURE_COMPLEXITY_REVIEW.md). The original 47 cases,
guarantees, counts and acceptance criteria remain unchanged.

Keep original counts: sequential 10/lane; 8 processes × 100 create races;
100 ownership transfers; 1000 replace switches and ≥1000 reads per observer;
10 repetitions per deterministic crash window plus 100 seeded random
interruptions. Boundary cases require a full run per boundary/lane. No count
reduction after a failure or missed schedule. New builds/conditions need new
identities and repetition of affected checks, not unrelated completed tests.

## Isolated stand and unavailable checks

For A05 use [A05_STAND_REQUIREMENTS.md](A05_STAND_REQUIREMENTS.md). The minimum is
an independently authorized disposable Windows/NTFS environment with a
**non-elevated** actor already capable of the required real SYMLINK operations,
safe owned targets, full native tag/identity verification and reached schedules.
Static fixtures do not cover creation-dependent races. Phase itself remains
non-elevated. Do not provision current host privileges, Developer Mode or ACLs.

Freeze the exact Windows/Python/Docker/Engine/backend/kernel/transport stack,
source/wheel/image/dependency/registry/profile/grant/harness hashes and ownership
manifest. Different stacks require their own evidence; a result on another host
does not automatically qualify this configuration. Use at most two private
nonroot constrained containers, own ext4 preparation/evidence and a separate
read-only verifier. No production mounts, secrets or Docker socket.

The 32 GiB campaign budget and reviewed free-space/peak gates remain. Boundary
workloads run sequentially after their dedicated gate, not under a small-case
allowance. Real ENOSPC requires a separately authorized bounded test filesystem;
error injection proves only the exercised propagation model. Filling shared S:
is prohibited. Host/VM restart and power-loss tests are outside the original
authorization and are not an added G06 requirement.

## Software readiness and final release gate

Before declaring **ready for final qualification**, preserve all code and
positive/negative evidence through the approved Phase route and GitHub, finish
the closed native execution/composition/contract/inspection/recovery graph,
independently review it, and run available isolated functional create/version/
receipt/inspect/recovery/CLI/MCP tests. Keep exact build provenance and this
ledger updated with every remaining case and cause. Readiness is not asserted
by the current document.

Before supported release, additionally require the full mandatory MIX family,
all mandatory safety cases including A05, final exact-HEAD CI, regression and
independent evidence review, clean accepted-package install, actual CLI/MCP,
historical evidence compatibility and executed old→new→old runtime rollback.
Code rollback uses an ordinary revert PR. Data/archives/receipts/journals remain
preserved; the old runtime cannot mutate unsupported new resources. Download
and verify published artifact bytes and perform the final synthetic smoke.

MIX does not admit FULL, Source/Knowledge/append/journal or larger binary version
features. Production Hermes/Phase/pcr-rnd remains unchanged. No supported-route
claim, merge-as-accepted or support release is authorized by partial readiness.
