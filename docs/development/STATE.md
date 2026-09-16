# Development state

## Current public state — PHASE-NEXT-STABLE-1.1.0-CANDIDATE

- Stable candidate: package and Core/CLI **1.1.0**; stable release **not published**.
- Current published prerelease remains [v1.1.0rc5](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0rc5),
  accepted after independent review and canary verification (prior evidence).
- Base: `87474fb5b5a5a2b7a19c468b2ffb8afe0b1628ed`; branch `release/1.1.0`.
- Delta: version exposure/metadata plus necessary tests and current documentation.
  Inspection, recovery, streaming, bundles, effects and schemas/contracts are unchanged.
- Exact-head Python 3.11/3.12 CI, package hashes, installed smoke and source/package
  byte comparisons are required before readiness; final evidence is external under
  `ROOT/evidence/STABLE-1.1.0-CANDIDATE/` and `ROOT/artifacts/STABLE-1.1.0-CANDIDATE/`.
- Next: independent limited stable-promotion and exact-package review. No merge,
  stable tag/release, package-registry publication, deployment or working-profile install.

## Historical public cleanup snapshot — PHASE-NEXT-PUBLIC-RELEASE-CLEANUP

- `Emint76/phase-tool-next` is **PUBLIC**. The current verified prerelease is
  [v1.1.0rc5](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0rc5),
  accepted after independent review and canary verification.
- Stable **v1.1.0 has not been released**. Distribution is via GitHub Release
  assets, not a PyPI publication; this cleanup does not deploy the product.
- rc5 tag target / cleanup base: `2779c9b0cf544337539ec41c83cc74c252f939a5`.
  Reviewed package source: `0c21465e09acb12b849f2dd3238bb18c8b50427d`;
  both commits have tree `2ea2f2df1bd8cd0ae4349836eef041bbe887ea7a`.
  Published package bytes are retained unchanged, not rebuilt for this cleanup.
- The repository was private at initial rc5 publication and later became public.
  Historical reports and attached release notes preserve that original context.
- Scope: current documentation, repository description and rc5 release body only.
  A clean, green cleanup PR may use a normal merge commit; no runtime, package,
  tag, prerelease-flag or production changes. Stable candidate preparation is a
  separate next task, not a release authorization here.

## Historical development snapshots

Everything below records earlier task states and their then-applicable limits.
References to private visibility, pending gates or forbidden merge/release actions
are historical, not statements of current repository or release status.

## PHASE-NEXT-RC4-SCHEMA-CORRECTION — rc5 R1 candidate

- Start HEAD: `fefa76e11313b270e8189fb1a39aaf5c6739d6d4`; same PR #3/branch.
- `1.1.0rc5` / Core `1.1.0-rc.5`: require known run/intent/plan identifiers
  in both command-result 1.1 schema copies; no inspect/recovery runtime change.
- Schema 1.0 and valid null original-receipt facts remain unchanged.
- [Narrow scope, regression and evidence](RC4-SCHEMA-CORRECTION.md).
- Exact-head matrix/build/installed canary gates precede readiness; no merge,
  release, production/profile/skill change. rc3/rc4 artifacts are preserved.
- Prior state below is historical; next phase-review covers only the R1 diff.

## PHASE-NEXT-CANARY-DEFECT-01 — rc4 correction candidate

- Exact correction base: `12f01c83d56d281e4696c42495491aea97a556f0` (merged PR #2 / rc3).
- New branch: `fix/canary-post-recovery-inspect`; no merge or release in this task.
- `1.1.0rc4` / `1.1.0-rc.4`: additive inspect-only command-result 1.1 for missing
  original receipt; original mutation remains unknown, recovery proof is separate.
- [Semantics, proof boundary, regression and evidence](CANARY-DEFECT-01.md).
- Final readiness requires exact-head Python 3.11/3.12 CI/build/installed CLI/MCP
  and historical gates; results are retained under `ROOT/evidence/CANARY-DEFECT-01/`.
- Prior state below is historical. Published rc3 and CANARY01 evidence are preserved.

## PHASE-NEXT-RC01-CORRECTION-02 — rc3 pending exact-head gates

- Start/reviewed HEAD `13d5935a787b02f3bf24056cde89f6f77d3dce25`;
  full PR base/main `080968f4cd557b9f891a2c2a34268fa8ef11ae98` unchanged.
- Candidate `1.1.0rc3` / Core `1.1.0-rc.3`; existing private PR #2, no merge.
- C1: shared exact-version pre-validator intent binding in independent verification.
- C2: truthful progress across remaining-commit and lock finalization errors.
- C3: new exact bundle v2 contract/mechanism 1.1.0 and independent preparation
  record created before original commit. Old unbound stages are not upgraded.
- Long-path manifest completeness and programmatic capabilities are corrected.
- Scope/trust/path matrix: [CORRECTION-02.md](CORRECTION-02.md).
- Exact final gate results and readiness live outside checkout:
  `ROOT/evidence/RC01-CORRECTION-02/<final-head>/`,
  `ROOT/artifacts/RC01/1.1.0rc3-<final-head>/`. Prior candidates remain immutable.
- Full Python 3.11/3.12, installed wheel/CLI/MCP, historical and resource gates
  must pass on final HEAD before READY_FOR_REVIEW. No reviewer/production changes.

## Historical correction-01 state (superseded where stated above)

## PHASE-NEXT-RC01-CORRECTION-01 — rc2 pending exact-head gates

- Correction base: `65471fa491d922d5dbdcffca582b801079b068d0`; full PR base:
  `080968f4cd557b9f891a2c2a34268fa8ef11ae98`. Existing private PR #2 and branch.
- Candidate `1.1.0rc2` / Core `1.1.0-rc.2`; rc1 artifacts/evidence are historical
  and preserved, never replaced. Exact final hashes and verdict are external.
- B1: caller capture identity checked against Core freeze before intent; streaming
  mechanism consumes an anonymous disk-backed verified snapshot before target open.
- B2: streaming target opens nonblocking/descriptor-relative; opened regular type,
  identity and namespace checked. No historical provider digest redefinition.
- B3: complete saved validator structures, exact declarations, run/input bindings
  and fixed emitted claims verified; opt-in bundle v2 intent also binds attachment digest.
- B5: `publish-bundle --publication-version 2.0` and explicit recovery
  `--mode commit_prepared`. Prepared stage proofs, separate durable continuation
  intent/receipt, broker root-lock, mechanism-only remaining commit, no member recreation.
  Old default observation and `recovery.policy=none` never gain target-write authority.
- Targeted reproductions and command logs: `ROOT/evidence/RC01-CORRECTION-01/`.
  Final evidence: `<final-head>/`; packages: `ROOT/artifacts/RC01/1.1.0rc2-<final-head>/`.
  Final full matrix/build/install/resource/historical gates must pass before READY_FOR_REVIEW.
- Legacy NOT_VERIFIED; goal/budget telemetry NOT_VERIFIED. No review subagent,
  merge/release/deployment, history rewrite, profile/skill/working installation change.

## Historical rc1 state (superseded recovery scope below)

## PHASE-NEXT-RC01 — F06 candidate sealed for final gates

- Private `Emint76/phase-tool-next`, branch `feat/unified-file-publication`, PR #2.
  F06 base `ef8f3d217b69f59d940e0b2ea7c90ac18b638124`; version **1.1.0rc1**
  (Core/CLI SemVer **1.1.0-rc.1**). F01 remains in history and is not rerun as a task.
- Source scope/guarantees: [RC01.md](RC01.md). Usage: [RC01-INTEGRATION.md](RC01-INTEGRATION.md).
  Candidate/rollback/limitations: [RC01-RELEASE-NOTES.md](RC01-RELEASE-NOTES.md).
- F02 explicit streaming <=2 GiB; final candidate resource gate must execute real
  64 MiB/1 GiB/2 GiB with independent inspect and <=128 MiB RSS growth.
- F03 explicit bundle <=1024 files/4 GiB; final gate is >=256 files/256 MiB,
  complete member verification, non-overwriting Linux directory visibility point.
- F04 verified-completion reconciliation; no target replay/repair or automatic
  deletion. Real crashes, missing receipts, conflicts and changed evidence tested.
  Unpublished stages and unproven partial effects retain exact non-success state.
- F05 shared CLI/MCP status/wait/recovery and programmatic limits. **125 local
  passed**; real MCP timeout→status→recovery without republish; network/Popen
  forbidden inside file and bundle publication tests. This is not an LLM audit claim
  inferred only from AST. No working profiles/MCP/skills/settings changed.
- Last pre-candidate CI: `34957299839` at the F06 base, **681 passed on each of
  Python 3.11/3.12**, build and installed gates GREEN. Scope is that exact base,
  not an automatic approval of the prerelease changes.
- F06 local installed/version/package gates passed; `f06-package-local` includes
  wheel/sdist integrity and clean install/uninstall/reinstall. Original F01 **4/4
  archived runs** inspect with the candidate runtime, archive mounted read-only,
  before/after file hashes identical (`f06-historical/historical-inspect.json`).
- Final source-staging record: `ROOT/evidence/RC01/f06-staged/candidate.json`.
  Final exact-head full matrix, clean installed smoke and mandatory resource job
  are required before READY. Final verdict, actual commit/tree, artifact hashes
  and measurement totals live in `ROOT/artifacts/RC01/1.1.0rc1-<full-commit>/`
  and `ROOT/evidence/RC01/final-<full-commit>/`, avoiding self-referential commits.
- Legacy chunks/reassembly exact sample/spec unavailable in bounded local searches:
  **NOT_VERIFIED**; no fields/protocol invented. `MAIN_PROTECTION=PROTECTION_GAP`.
- GOAL_STATUS / BUDGET = **NOT_VERIFIED** from initial standard-interface check;
  no state.db inspection, new/reset/resumed goal or budget changes. No Kanban task
  is bound to this direct session. No independent maintainer approval claimed.
- FINAL ACTIONS: verify final CI/downloaded bytes, install exact retained candidate,
  preserve handoff, stop. No merge, auto-merge, release/tag, registry upload,
  production/working V1 changes or follow-on roadmap outside RC01.

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
