# Docker Desktop NTFS qualification campaign (in progress)

This directory starts an execution of the immutable six-document qualification
program dated 2026-10-21. It is **not an NTFS support declaration**. Production
admission, Core, contracts, registry and guarantee profiles remain unchanged.

Current execution outcome: **the tested MIX composition is blocked by a real
bundle RENAME_NOREPLACE failure**. See [RESULTS.md](RESULTS.md) for measured
results and independent verification, and [ROLLBACK.md](ROLLBACK.md) for the
preserved baseline. No support release is accepted. Follow-up decisions are
tracked in [#12](https://github.com/Emint76/phase-tool-next/issues/12); the
separate large binary version gap is [#13](https://github.com/Emint76/phase-tool-next/issues/13).

Current candidate base: main `721945ce46546e82ef31134d1e1bb54802a1d027`.
Historical runtime reference: v1.1.0 `5ba874f77e9225aae29e6c84cfc3f776df557c9c`.
The runtime files in these trees are identical. Separate reference provenance
and future candidate results must still be preserved.

## Scope and gates

MIX means direct NTFS result/current/object storage with isolated ext4 evidence
and preparation. FULL is a separate scope and cannot inherit MIX acceptance.
All A01–F09, G01–G06 and R01–R12 remain applicable as specified by the program.
Tests run with nonroot UID/GID 10001, network=none, cap-drop=ALL,
no-new-privileges, at most two owned containers (2 CPU, 2 GiB, 128 pids each).
No production mounts, Docker socket, global settings or host restarts are used.

The initial harness executes early E01 and sequential D02 primitive gates, ten
repeats each, first REF and then MIX. These gates do not replace the remaining
program, concurrency tests, syscall semantics review or full Phase lifecycle.
If an essential primitive fails, dependent mutation stops and remaining cases
stay NOT_VERIFIED. The original counterexample must be retained.

This small stage allocates under 256 MiB with a 4 GiB reserve checked on the host
and relevant ext4/NTFS roots. It changes no large-workload threshold: 64 GiB host
and VM reserves are still mandatory before large cases. A short first-failure
run retains requested/completed counts and is never treated as ten passing
repeats. The image is an offline directory-only derivative of the available
v1.1.0 image, without package installs, pulls or image exports.

`transport_gates.py` has no deletion routine and no admission override. Its
fixed mount roots require campaign owner tokens. The syscall observer calls the
genuine `os.fsync`; D02 calls the installed, unchanged `_rename_noreplace`.
Primitive calls are synthetic L1 tests, never an alternative document route.
The `archive` action publishes temporary reports through unchanged Phase to
own ext4 records/evidence volumes. `inspect` must run in the independent
read-only verifier after publication. No raw stdout alone is durable evidence.

Before running this harness, an independent reviewer must assess all write
boundaries, expected outcomes and false-positive risks, including the setup
commands and ownership map. A fresh campaign UUID and ownership manifest are
mandatory. No container/volume is accepted by name alone; labels, IDs and mounts
must match. No cleanup is currently implemented: retain owned resources.

## Initial acceptance matrix

| Scope | Transport guarantees | Publication family | Release claim |
|---|---|---|---|
| REF | NOT_VERIFIED | NOT_VERIFIED | Existing release only |
| MIX | NOT_VERIFIED | NOT_VERIFIED | None |
| FULL | NOT_VERIFIED | NOT_VERIFIED | None |

## Immutable input program hashes (SHA-256)

| File | Digest |
|---|---|
| QUALIFICATION_PLAN.md | a502b958c18db8cdcf4e79c295da41393a796a47109e36621e987f2739a919f3 |
| GUARANTEE_MATRIX.md | 0fc883fb9d6ced9e7498f795e97743d8307b5c8b4155f30a719b7c5ea95aaa80 |
| TEST_ENVIRONMENT.md | c50b825d722eacaec2d3ba220bcf5e7d281fd83b75e6efbcb6127fe97f09eb9a |
| ACCEPTANCE_CRITERIA.md | 1da00be0854f0397467d568971c3d296d01a4294572dfd0034defcf75421f71c |
| IMPLEMENTATION_IMPLICATIONS.md | 84082732db5ac4dbc25d97ab6e928177d4761116a575cbe2addedc1993fb8c36 |
| EXECUTIVE_SUMMARY.md | c40a695f7c5021f63aa86e44c2e15fdf51f62b0df62430f26e4988c0967b1df1 |

## Rollback/readiness

Before any runtime change preserve v1.1.0 wheel, sdist and OCI bytes. Runtime
rollback must use exact accepted artifacts, preserve all new data/evidence, and
refuse unsupported roots. Code rollback uses a normal revert PR; tags/history
are immutable. Old→new→old execution, CLI/MCP, post-release download/install,
historical-evidence compatibility and independent implementation/evidence review
are mandatory before a support release. None have been completed yet.
