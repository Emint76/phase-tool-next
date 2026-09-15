# Development state

## PHASE-NEXT-RC01 — F03 checkpoint, not release-ready

- Scope: [RC01.md](RC01.md), private PR #2 / `feat/unified-file-publication`.
  F03 checkpoint base: `d5b9b55cd97214d4747b412881a4d55f623a7ea8`.
  Exact staged/published identity belongs in `ROOT/evidence/RC01/f03-staged/`
  (avoids a self-referential commit hash in this source file).
- F02 checkpoint is published and verified: CI run `34942917723`, **631 passed
  on Python 3.11.16 and 3.12.14**; wheel/sdist and clean installed CLI/MCP gates
  passed. Both downloaded artifacts bind to tree
  `274d5a0586a26a407d28564e65f8bfcdcb1d1aeb`; 165 package files in each wheel
  and sdist equal that exact commit. These are not approvals of later changes.
- F02 resource baseline at that checkpoint: real 64 MiB / 1 GiB / 2 GiB PASS;
  peak RSS 39,989,248 / 40,280,064 / 40,128,512 bytes; 64 MiB→1 GiB growth
  290,816 bytes <=134,217,728. Original F01 and all prior evidence preserved.
- F03 local gates: **140 passed**, including **27 bundle / 20 streaming-file**
  cases and all 44 F01 cases. Shared CLI/MCP bundle operation and cross-inspect,
  unsafe/duplicate/prefix paths, missing/corrupt/extra members, FIFO metadata,
  interrupted staging, racing commit and exact partial-write counts are covered.
- Final F03 real workload: **256 files / 268,435,456 bytes**, full Phase inspect
  plus independent target-member hashing PASS; 25.60 s, peak RSS 39,399,424 bytes.
  Logical operation writes 536,960,401 bytes; retained source/evidence/target
  805,391,114 bytes. Full metrics and per-file digests are retained externally.
- F03 also fixes the newly reproduced early-observation receipt flag defect in
  the streaming-file mechanism. No old receipt schema was weakened. Final F06
  resource/CI gates must cover the final code; old resource results are scoped.
- Current evidence: `ROOT/evidence/RC01/f03-final-local/verified-summary.json`;
  logs/JUnit/source hashes/resource JSON in that directory. F02 evidence:
  `F02-local-report.json` and `ci-d5b9b55/verified-summary.json` in the same root.
- Legacy chunks: exact format/sample NOT_VERIFIED. Bounded read-only searches
  of Phase Next, Phase history and selected Phase Context exports did not expose
  a versioned reassembly sample; no legacy fields or compatibility were invented.
- Next: publish F03 checkpoint, verify its exact-head CI, then F04 recovery,
  F05 status/wait/general integration and F06 installed prerelease candidate.
  No whole-RC readiness, independent approval, merge/release/deployment claimed.
- GOAL_STATUS / BUDGET = NOT_VERIFIED from the initial check only. No state.db
  access, new goal, automatic resume/reset, settings or working-profile changes.
  No Kanban card was bound to this direct session; no board work was fabricated.

## PHASE-NEXT-F01

Bootstrap is accepted and merged. F01 starts at private main commit
`080968f4cd557b9f891a2c2a34268fa8ef11ae98`, tree
`b234a2ef481be76ab75dd2e75dda8ab57aa7987b`.
Branch: `feat/unified-file-publication`. Scope and interface: [F01.md](F01.md).

New CLI `phase publish-file` and MCP `phase_publish_file` share one application
path over the unchanged create lifecycle. Binary files are limited to 1 MiB;
existing targets are not replaced and repeat requests require explicit inspect.
New result schema is separate from historical evidence schemas.

Required final gate: exact-HEAD Python 3.11/3.12 CI, all regressions plus F01,
wheel+sdist and clean-wheel CLI/MCP/cross-inspect smoke. Per-head CI artifacts
are `phase-next-<head-sha>-py<version>`; local execution evidence is under
`../../evidence/F01/`. No test count or historical PASS is reused as final proof.
This branch prepares one open PR for independent maintainer review, not merge,
release or deployment. Main protection remains `PROTECTION_GAP`.

---

# Bootstrap state and evidence

## Immutable source and scope

- Source/tag: `Emint76/phase-tool-codex`, `v1.0.0`.
- Base commit: `c4d8285479f90678904f22e5f95927eb46daba01`.
- Base tree: `807f193a8426f9ba159cdca08076ef1adc01bb14`.
- Annotated v1.0.0 tag object: `4174a3da74a609f54361a3fcebb85827fcc3aab7`.
- Original import: 57 reachable commits, 16 branches, 2 annotated tags; live
  source/private refs matched, including peeled tag identities.
- Destination: standalone PRIVATE `Emint76/phase-tool-next`; `fork=false`.
- Work branch: `chore/private-bootstrap`, base `main`; never merge in bootstrap.

This PR changes only three development documents, the existing CI and ignore rules,
and a small bootstrap scope check. Phase source, contracts, schemas, functional
tests, package version, license and architecture documents remain at baseline.
`python scripts/private_bootstrap_check.py` checks this committed scope and base.
It does **not** prove test success, remote permissions or semantic correctness.

## Evidence locations and readiness

From the checkout, `../../evidence/bootstrap/` contains command captures and the
final exact-head verification report; `../../artifacts/baseline/` contains the
original downloaded v1.0.0 wheel, sdist and SHA256SUMS. Both original payload hashes
and all GitHub release asset digests were verified. Original release bytes are
separate from newly built private CI artifacts, despite retaining version 1.0.0.

Use the PR's exact head SHA to inspect the two Linux Python jobs and their required
steps; private Actions artifacts are named `bootstrap-<head-sha>-py<version>`.
No document or stored PASS string substitutes for live checks, parsed results,
source invariance and exact-head identity. CI unavailable/pending/failing means
NOT_VERIFIED/BLOCKED, never full READY_FOR_MAINTAINER.

The external evidence also records the local public-push guard, actual main
protection or protection gap, original asset provenance, runtime isolation and
unchanged protected configuration/source fingerprints. Existing Hermes project
association is retained rather than creating a duplicate; the desired display
name is `Phase Next — Private Development`.

## Limits and next step

The main-protection PUT and GET returned HTTP 403: GitHub requires Pro or a public
repository for this feature on the current account. This is a **PROTECTION_GAP**;
visibility, billing and memberships were not changed. Merging remains forbidden.

Local Git guard != server permission restriction. A missing private-repository
branch-protection entitlement is an explicit protection gap, not permission to
merge. No production/profile/MCP switch is part of this work.

After all gates pass, the next step is independent maintainer review of this PR.
Ready-file publication functionality requires a subsequent explicit authorization;
do not implement it as part of bootstrap or use a historical branch as a new base.
