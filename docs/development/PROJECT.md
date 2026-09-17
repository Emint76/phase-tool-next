# Phase Next — Public Development

The repository is **PUBLIC**. Phase Tool Next **1.1.0 = PUBLIC STABLE RELEASED**;
the current stable release is
[v1.1.0](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0).
Packages are distributed through GitHub Release assets. No PyPI/TestPyPI
publication or production deployment has been performed.
See [STATE.md](STATE.md) for current state and history.

Phase Next is the standalone public continuation at `Emint76/phase-tool-next`,
not a GitHub fork. Its original source is `Emint76/phase-tool-codex`, release/tag
`v1.0.0`, commit `c4d8285479f90678904f22e5f95927eb46daba01`.
The original history, branches, annotated tags, MIT license and copyright notices
are preserved. Public v1.0.0 remains unchanged; active future development belongs
in this repository. Phase Tool Next had an initial private bootstrap/development
phase before becoming public, including the initial rc5 publication. Git history,
commits, pull requests, tags, releases and historical development records are
preserved unchanged; historical reports and release assets retain their original wording.

`phase-dev` develops; the maintainer independently accepts or rejects the result.
A commit/push, a PR, a release, and production deployment are separate actions.
The stable release passed independent review before merge, with exact-head CI
and post-merge CI **SUCCESS**. Published packages are the exact retained reviewed
bytes, not rebuilt from the merge commit. The previous verified prerelease
[v1.1.0rc5](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0rc5)
remains historical; its tag, release and assets are preserved.
The 1.1.0 release cycle is complete. Working-environment rollout/installation
and the next roadmap require separate decisions; neither is part of this cleanup.

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

The original bootstrap deferred ready-file CLI/MCP publication, large files,
bundles, recovery and operational checks to later work. Their subsequent
development is recorded in [STATE.md](STATE.md); this is not a current task list.
