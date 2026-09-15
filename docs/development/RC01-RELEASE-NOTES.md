# Phase Tool 1.1.0rc2 — private RC01 candidate notes

This is a **prerelease candidate for maintainer review**, not a GitHub Release,
independent approval, merge, public package publication or deployment. Package
version is PEP 440 `1.1.0rc2`; CLI/Core evidence version is SemVer `1.1.0-rc.2`.
The normalized identifiers intentionally differ, and both are tested explicitly.

## Changes and exact compatibility

Correction base is reviewed rc1 `65471fa491d922d5dbdcffca582b801079b068d0`.
B1/B2/B3/B5 corrections are documented in [CORRECTION-01.md](CORRECTION-01.md).
The prior rc1 candidate remains immutable. New opt-in bundle v2 supports only
remaining-commit continuation of a fully proven stage, not partial-file repair.

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
`ROOT/artifacts/RC01/1.1.0rc2-<full-commit>/` with SHA256SUMS and exact Git/package
binding manifest. Never install a differently hashed wheel merely sharing this
version label. The candidate is not published to a package index.

```sh
sha256sum --check SHA256SUMS
python3.11 -m venv /path/to/new-private-rc01-venv
/path/to/new-private-rc01-venv/bin/python -m pip install ./phase_tool-1.1.0rc2-py3-none-any.whl
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
