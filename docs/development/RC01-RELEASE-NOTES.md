# Phase Tool 1.1.0rc3 — private RC01 candidate notes

This is a **prerelease candidate for maintainer review**, not a GitHub Release,
independent approval, merge, public package publication or deployment. Package
version is PEP 440 `1.1.0rc3`; CLI/Core evidence version is SemVer `1.1.0-rc.3`.
The normalized identifiers intentionally differ, and both are tested explicitly.

## Changes and exact compatibility

Correction base is reviewed rc2 `13d5935a787b02f3bf24056cde89f6f77d3dce25`.
C1–C3, trust boundaries and verification paths: [CORRECTION-02.md](CORRECTION-02.md).
Prior rc1/rc2 candidates remain immutable; B1/B2 regressions remain active.
Opt-in bundle v2 now selects exact contract/mechanism version 1.1.0, with an
independent prepared-proof binding created before original commit. Old v2@1.0.0
stages cannot acquire provenance retrospectively. Successful historical inspection
retains its exact-format guarantees. Only remaining commit is supported, not repair.
Pre-validator intent binding is independently checked even with a successful receipt;
late unlock/close errors retain observed effect progress and remain failed responses.

- Retain F01 `publish-file` default `1.0`, create-only <=1 MiB, its exact contract
  and receipt schemas. Add explicit streaming `2.0` (`file_create.v2@1.0.0`):
  <=2 GiB file, <=1 MiB request, bounded 1 MiB I/O blocks, one active high-level
  operation per target root. Input digest describes consumed bytes, not an
  atomic snapshot of arbitrary concurrent source changes.
- Add `publish-bundle` / `phase_publish_bundle` (`bundle_create.v1@1.0.0`):
  <=1024 explicit members, <=2 GiB/member, <=4 GiB total, depth <=32,
  <=1 MiB request/manifest. Full member-byte verification, exact membership,
  run/plan/inode owner and non-overwriting Linux directory rename. Consumer
  visibility at commit is distinct from prior physical staging and later fsync.
- Add explicit completion reconciliation, immutable recovery observations, and
  bounded saved-state query/wait for both transports. Missing final receipts
  can be reconciled when effect provenance and current bytes are proven.
  Original receipts and their statuses are never rewritten.
- Add programmatic limits and [integration instructions](RC01-INTEGRATION.md).
  Execution contains no LLM calls or generated helper programs; behavioral tests
  forbid socket connections and subprocess creation inside both publication paths.

## Known boundaries

Qualified Linux ext4/overlay only for the new mutation paths; Windows is a
source-development host, not a newly qualified mutation deployment. No atomic
snapshot of hostile/changing sources; no transaction across external resources.
No automatic target replay/repair: partial files, incomplete or unproven stages,
unproven effects and conflicting evidence are retained with explicit non-success.
Default recovery restores proven completion. Explicit `commit_prepared` additionally
commits a fully prepared bundle v2 stage through the broker/mechanism. It does not
retroactively prove original power-loss durability or fabricate success receipts.
Fast status is saved metadata, not current verification or worker liveness.

Legacy chunks/reassembly exact samples/specification were not found in bounded
local searches: **NOT_VERIFIED**, no invented compatibility protocol. Existing
V1/F01 contract/evidence generations remain supported and tested; original F01
archive inspection is read-only and compared byte-for-byte before/after.
`MAIN_PROTECTION=PROTECTION_GAP` is an unchanged repository limitation.

## Candidate installation and rollback (separate test environment)

Artifacts are retained outside checkout under
`ROOT/artifacts/RC01/1.1.0rc3-<full-commit>/` with SHA256SUMS and exact Git/package
binding manifest. Never install a differently hashed wheel merely sharing this
version label. The candidate is not published to a package index.

```sh
sha256sum --check SHA256SUMS
python3.11 -m venv /path/to/new-private-rc01-venv
/path/to/new-private-rc01-venv/bin/python -m pip install ./phase_tool-1.1.0rc3-py3-none-any.whl
/path/to/new-private-rc01-venv/bin/phase --version
/path/to/new-private-rc01-venv/bin/phase doctor
/path/to/new-private-rc01-venv/bin/phase publication-limits
```

Use candidate-only source/target/preparation/evidence roots for trials. Check
`candidate-manifest.json` and retained dependencies for the exact tested runtime.
No editable installation or PYTHONPATH is required. Roll back by stopping only
trial workers, retaining all new evidence and target data, and selecting the
previous executable/environment again. Do not overwrite or delete candidate
runs; an older installation need not understand new bundle/streaming contracts.
No working V1 installation/profile has been changed by this development run.

## Evidence and review

Mandatory final gates: full Python 3.11/3.12 matrix, build and clean installed
F01+RC01 CLI/MCP smoke, one installed-wheel Linux resource job (64 MiB/1 GiB/2 GiB,
RSS growth <=128 MiB; 256 files/256 MiB bundle), historical inspection, exact
commit/tree/runtime-package comparison, retained artifacts and maintainer handoff.
Checkpoint PASS is not final-code approval. Final measured results and exact
hashes belong in the external manifest/handoff, avoiding self-referential Git
hashes. Maintainer reviews the entire private PR #2 including F01; merge, release
and production installation require a separate decision.
