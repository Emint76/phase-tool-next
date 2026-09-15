# Phase Next — Private Development

Active task: **PHASE-NEXT-RC01**, scoped by [RC01.md](RC01.md) and [STATE.md](STATE.md).
It authorizes ordinary source/test/document, necessary versioned-contract, CI and
prerelease development in this private checkout. The bootstrap-specific limits
below are historical; merge, release, public publication and production/profile
changes remain forbidden.

Phase Next is the standalone private continuation at `Emint76/phase-tool-next`,
not a GitHub fork. The public source is `Emint76/phase-tool-codex`, release/tag
`v1.0.0`, commit `c4d8285479f90678904f22e5f95927eb46daba01`.
The original history, branches, annotated tags, MIT license and copyright notices
are preserved. Public v1.0.0 remains unchanged; active future development belongs
in this one private repository.

`phase-dev` develops; the maintainer independently accepts or rejects the result.
A commit/push, a PR, a release, and production deployment are separate actions.
This bootstrap authorizes a PR only: no merge, release, version change, deployment,
or changes to the installed Phase or working profiles/skills.

## Agreed direction (not implemented by this bootstrap)

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
