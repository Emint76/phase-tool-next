# Phase Next — Public Development

The repository is **PUBLIC**. The current verified prerelease is
[v1.1.0rc5](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0rc5),
accepted after independent review and canary verification. Stable **v1.1.0 has
not been released**; packages are distributed through GitHub Release assets,
not as a PyPI publication. See [STATE.md](STATE.md) for current state and history.

Phase Next is the standalone public continuation at `Emint76/phase-tool-next`,
not a GitHub fork. Its original source is `Emint76/phase-tool-codex`, release/tag
`v1.0.0`, commit `c4d8285479f90678904f22e5f95927eb46daba01`.
The original history, branches, annotated tags, MIT license and copyright notices
are preserved. Public v1.0.0 remains unchanged; active future development belongs
in this repository. It was private when rc5 was first published and later became
public; historical reports and release assets retain their original wording.

`phase-dev` develops; the maintainer independently accepts or rejects the result.
A commit/push, a PR, a release, and production deployment are separate actions.
The **PHASE-NEXT-STABLE-1.1.0-CANDIDATE** task prepares stable candidate **1.1.0**
in one focused `release/1.1.0` PR from `87474fb5b5a5a2b7a19c468b2ffb8afe0b1628ed`.
Only package/product version metadata and necessary tests/current docs change.
Runtime semantics, schemas/contracts and historical rc5 evidence remain unchanged.
Exact-head tests, builds and disposable installed acceptance precede independent
review. No merge, stable tag/release, registry publication, working-profile
installation or production deployment is authorized; rc5 remains a prerelease.

## Historical bootstrap direction

The following records the original bootstrap scope, not current implementation
status or the next authorized task. Later development is recorded in [STATE.md](STATE.md).

- Phase remains universal; PCR-specific concepts do not belong in Core.
- One deterministic operation acts on an already prepared artifact. Preparation,
  execution, inspect and finalization are implemented in code.
- No internal LLM calls or autonomous content changes. Semantic choices are not
  silently promoted into deterministic guarantees.
- CLI and MCP share one application implementation.
- Agreed constraints are checked before target writes.
- Large files use end-to-end streaming; chunking is not mandatory.
- Historical evidence compatibility and honest failure statuses are preserved.

Next, separately authorize a small end-to-end ready-file publication scenario
through both CLI and MCP. Later work may extend it to large files, bundles,
recovery and operational checks. None of that functionality is in this PR.
