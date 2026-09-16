# PHASE-NEXT-RC4-SCHEMA-CORRECTION / 1.1.0rc5

Start HEAD: `fefa76e11313b270e8189fb1a39aaf5c6739d6d4` (rc4), PR #3,
branch `fix/canary-post-recovery-inspect`. Core/CLI: `1.1.0-rc.5`.
Candidate only: no merge, tag, GitHub Release or production installation.

## R1 — already-known identifiers cannot be null

Both canonical `stage3-command-result-1.1.schema.json` copies now require
`run_id`, `intent_digest` and `effect_plan_digest` to be non-null strings with
their existing patterns. All three were already in `required`; removing a
field remains invalid. Only this schema's two registry digest pins change.

This applies to both 1.1 states, `recovered_verified` and `indeterminate`:
`inspection.inspect_run` validates the original intent and plan before calling
`inspect_missing_recovery` and constructs these identifiers independently of
the recovery outcome. Early original-evidence failures still use the existing
1.0 rejected envelope, which can contain unknown identifiers.

Original `receipt_digest`, `terminal_status`, `execution_disposition` and
`mutation_attempted` remain null in 1.1. The recorded recovery mutation flag
keeps its separate meaning and allowed null. No runtime inspect/recovery,
streaming, bundle, cap, intent, V1 compatibility or canary mechanics change.
Both command-result 1.0 copies and their registry binding remain byte-exact.
The full rc4 semantics and trust boundary remain in [CANARY-DEFECT-01.md](CANARY-DEFECT-01.md).

## Executable regression

`tests/test_rc5_command_result_schema.py` validates real runtime envelopes
against each public schema directly (not merely runtime validation):

- both 1.1 states and both schema copies;
- each of the three identifiers set to null or omitted;
- positive envelopes retaining unknown original receipt facts;
- early inspect failure accepted by historical 1.0 with null identifiers.

Before correction: **12 failed, 18 passed**; all failures were `DID NOT RAISE`
for null identifiers. After correction: **30 passed**. The existing canary
suite separately covers ordinary/historical 1.0, failed/indeterminate recovery,
recovered success and inspect's read-only behavior.

Readiness requires exact-head Python 3.11/3.12 full regression, wheel/sdist,
clean installed CLI/MCP and crash -> recovery -> repeat -> inspect gates.
Version pins in existing CI/smoke/version tests advance to rc5 only; no gate is
removed or weakened. Heavy resource benchmarks remain scope-gated as in rc4.

Final head/tree, CI IDs, downloaded results and artifact SHA256 belong in the
external candidate manifest (avoiding a self-referential commit):
`ROOT/evidence/RC4-SCHEMA-CORRECTION/<final-head>/` and
`ROOT/artifacts/RC4-SCHEMA-CORRECTION/1.1.0rc5-<final-head>/`.
Previous rc3/rc4 artifacts and evidence are preserved, not rebuilt in place.

Next: **phase-review**, short review of R1 diff relative to Start HEAD only.
Non-blocking observations are intentionally out of scope.
