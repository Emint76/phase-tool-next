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
