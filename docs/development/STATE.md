# Development state

## PHASE-NEXT-RC01 — in progress (not release-ready)

- Start/last committed HEAD: `3f8c6898c61c5d7698e3e2b83f18c1486a24ecd2`;
  branch `feat/unified-file-publication`, private PR #2. No additional published
  history or foreign changes were present at preflight. Scope: [RC01.md](RC01.md).
- Stage: F02 local gates PASS; checkpoint publication, then F03. Explicit
  `publication_version="2.0"` shares the CLI/MCP/application publish-file path;
  default F01 v1 and its exact contract stay supported.
- New exact binding: `file_create.v2@1.0.0`, package
  `sha256:4f9e56531e004281342612b02a868f856a36a6524b51669f24835aa840d9e6fa`.
- Actual local execution reconciled **631 distinct passing cases**, including
  **44 F01 / 19 F02**. This is not one uninterrupted 631-case invocation: full
  run was 627 PASS / 2 packaging FAIL under network denial; the two exact package
  gates then passed with dependency access; added F02 cases passed separately.
  All checks used byte-identical runtime source. No safety test was removed.
- Final real-data gate: 64 MiB / 1 GiB / 2 GiB PASS, each with independent inspect.
  Isolated Linux peak RSS: 39,989,248 / 40,280,064 / 40,128,512 bytes;
  64 MiB→1 GiB growth **290,816 bytes <=134,217,728**. Times: 5.38 / 68.95 /
  136.89 s. Old resource output is superseded, not transferred.
- Durable report: `ROOT/evidence/RC01/F02-local-report.json`; individual logs,
  JUnit and source SHA-256 manifests are retained in its named checkpoints.
  `f02-staged/candidate.json` records the exact literal staging/tree identity.
- Limits: 1 MiB canonical request, 2 GiB/file and total, one file/operation,
  one worker/operation and one active high-level operation per target root.
  FIFO, changing/growing source, short writes, post-effect close failure,
  injected ENOSPC, corruption and old/new boundaries are covered.
- Next: commit/push F02 checkpoint; continue F03 bundles, F04 recovery, F05
  operational interface and F06 exact final prerelease/CI. No whole-RC readiness,
  independent maintainer approval, merge, release or production change claimed.
- Initial GOAL_STATUS / BUDGET = NOT_VERIFIED. No state.db access, goal reset,
  resume, new goal or budget modification. No Kanban task was bound to this
  direct session; no board work was fabricated.

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
