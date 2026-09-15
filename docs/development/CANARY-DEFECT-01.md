# PHASE-NEXT-CANARY-DEFECT-01 / 1.1.0rc4

Correction baseline: `12f01c83d56d281e4696c42495491aea97a556f0`
(tree `2c5c70be76eac02e88cdf734c3254d1049769587`), private `main` after PR #2.
Package identity: `1.1.0rc4`; Core/CLI identity: `1.1.0-rc.4`.
This is a candidate for **phase-review of this correction diff**, not approval,
merge, a GitHub Release, deployment, or a replacement of the published rc3.

## Root cause and exact field meaning

`PhaseCore` records the original run's mutation flag from its effect receipts
(`any(effect_receipt.attempted)`). Receipt-backed `inspect_run` copies that flag;
it does not mean that inspect mutated, nor aggregate later recovery calls.
With the original receipt absent, `inspect_run` returns unknown (`None`). rc3's
application forwarded that value in a `stage3_command_result_version=1.0`
envelope; the CLI correctly rejected it because the closed 1.0 schema requires
boolean. The MCP adapter had no equivalent envelope validation. This is a
transport/application representation defect, not a permissions failure.

## Additive missing-original-receipt result 1.1

`schemas/stage3-command-result-1.1.schema.json` is an additive, closed,
**inspect-only** format, selected by `stage3_command_result_version="1.1"`.
The original 1.0 schemas, registry entries, contract packages and evidence bytes
are unchanged. Receipt-backed ordinary/historical paths still emit 1.0.
No execution or recovery contract, guarantee vocabulary, cap, or mutation
implementation changes. Both public transports use one application response;
application inspect and CLI validate using the same exact-version selector.

In 1.1, `mutation_attempted`, `terminal_status`, `execution_disposition`, and
`receipt_digest` are **null**: no original receipt proves these original-run
facts. Reaching a prepared checkpoint does not establish the original run's
final effect-receipt aggregate. Successful continuation does not retrospectively
supply that missing receipt. Neither `None -> false` nor `None -> true` is used.

Additional fields:

- `inspection_status`: `recovered_verified` or `indeterminate`.
- `inspection_required`: false only for the supported verified continuation.
- `recovery_observations`: retained recovery-result **1.1** records, each paired
  with its verified canonical digest. They include the original per-call attempt,
  effect state, success, errors and lock-finalization facts; failures are not
  filtered out. Sorted by content-addressed filename, **not chronology**.
- `recorded_recovery_mutation_attempted`: true if at least one validated retained
  observation records a recovery attempt; otherwise null, not false. This is
  explicitly not a complete-history claim. A non-mutating repeat cannot erase
  an earlier recorded attempt. Each observation still retains its own boolean.

`recovered_verified`: `success=true`, `target_verified=true`, `exit_code=0`,
no error/blockers. This verifies the current supported recovered target, **not**
original-run `succeeded_verified`, clean process liveness, a new effect, or a
reconstructed receipt. The original terminal status remains null.

`indeterminate`: `success=false`, `target_verified=null`, `exit_code=40`,
`inspection_required=true`, explicit error/blocker. Covers no continuation,
missing observations, unsuccessful/uncertain recovery, incomplete closure,
unsupported old recovery-record formats, wrong root, and inconsistent/tampered
proof or changed target. Existing original-evidence validation failures retain
the pre-existing rejected-result behavior; invalid evidence is not reclassified
as a valid missing-receipt result. Format 1.1 adds no downgrade guarantee to V1.

## Proof boundary

Recovered success requires all of:

1. Original canonical intent, exact contract/plan/implementation bindings,
   pre-validator and frozen-input proofs pass existing independent inspection.
2. Every selected recovery observation is canonical, named by its actual digest,
   schema-valid, and bound to this run, request, intent and plan with no original
   receipt claim. At least one records completed successful recovery with
   committed/verified effect, successful lock finalization and no error.
3. Original independent preparation binding and exact prepared-stage proof;
   complete continuation-intent equality and complete commit-receipt equality,
   including preparation/intent/plan/target/contract/digest bindings.
4. Independent read-only verification of current target bytes, exact bundle
   membership, original prepared inode, plan and root identities, and saved
   preconditions. No caller source is re-read.

This uses the existing controlled-evidence trust boundary, not signatures or
protection against a privileged actor rewriting every independent record.
An absent observation cannot prove absence of a syscall; a failed recovery
record is not silently upgraded because a commit receipt exists. A later
successful recovery can be verified while earlier failed records remain visible.
There is no freshness guarantee beyond the read observations (no root lock or
claim that a different process cannot subsequently change the target).

Inspect never calls recovery, broker, lock acquisition, write, fsync, or target
publication. It does not create observations or rewrite an original receipt.

## Executable evidence and gates

- Original-source RED: `tests/test_canary_defect_inspect.py` reproduced exit 1,
  empty CLI stdout, and `ValidationError: None is not of type 'boolean'` after
  real child `os._exit(73)`, successful commit_prepared and non-mutating repeat.
- Focused worktree gate: 175 PASS, including 23 new cases, recovery/finalization,
  ordinary file/bundle v1/v2, old exclusive-create and publish-new-version paths.
- A first implementation run exposed an invalid reference to a non-existent
  historical recovery schema. It was removed, not worked around; only shipped
  recovery-result 1.1 is supported for this new continuation verifier.
- `scripts/correction_installed_smoke.py` now exercises both CLI and MCP inspect
  after actual installed-package crash/recovery/repeat. It verifies schema,
  transport equality, preserved original files, no fabricated receipt, and
  unchanged target/evidence bytes/inodes/mtimes across inspection.
- Exact final-head CI must pass full Python 3.11/3.12 suites, wheel/sdist build,
  non-editable clean installed CLI/MCP smoke and canary regression before readiness.
- Heavy resource measurements are not rerun for this inspect-only correction;
  CI checks the streaming/mutation resource-path diff and conservatively runs
  them if the resource paths changed or baseline cannot be resolved.

Task evidence: `ROOT/evidence/CANARY-DEFECT-01/`; candidate artifacts:
`ROOT/artifacts/CANARY-DEFECT-01/1.1.0rc4-<final-head>/`.
Final CI run IDs, counts, source tree, artifact hashes and retained-install facts
belong in the external exact-head report/PR handoff, not self-referential source.

## Preserved boundaries

`ROOT/scratch/CANARY01/` is read-only; its 111 files are baseline-hashed.
Published rc3 wheel remains SHA256
`e58b92b4845fa31214967d90a0c72851dd9dd84bb24da53ba742e9f329ceac31`.
No release/tag modification, production V1 change, profile/skill change,
public phase-tool-codex write, or legacy compatibility-policy change.
