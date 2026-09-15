# Local publication integration (RC01)

Use an isolated candidate installation on qualified Linux ext4/overlay. This is
not an instruction to change a working Hermes profile or enable its MCP server.
No LLM, network request, generated helper program or content review is part of a
publication. CLI and MCP call the same `PhaseApplication` and Phase Core.

## rc4 post-recovery inspection

After supported `commit_prepared` with no original receipt, CLI `inspect` and MCP
`phase_inspect` return the closed command-result **1.1**, not 1.0. Select the
schema using `stage3_command_result_version`. Original-run mutation/terminal/
receipt fields remain null; `inspection_status=recovered_verified` requires
independent current verification and bound continuation/observation proof.
`recorded_recovery_mutation_attempted=true` reports a retained recovery attempt;
per-call outcomes (including failures and non-mutating repeats) remain in
`recovery_observations`. Indeterminate inspection returns exit 40, not traceback
or verified-success. Receipt-backed ordinary/V1/F01 inspection retains 1.0.
See [the exact semantics and migration](CANARY-DEFECT-01.md). This does not
instruct installing rc4 into production or enabling a working-profile MCP.

## One request, explicit intent

```sh
phase publication-limits
phase publish-file --publication-version 2.0 \
  --source-root /data/ready --source-locator report.bin \
  --target-root /data/published --target-locator report.bin \
  --preparation-root /data/preparation --evidence-root /data/evidence \
  --request-id report-01 --run-id report-01
phase publish-bundle \
  --source-root /data/ready --member report.bin --member tables/table.csv \
  --target-root /data/published --target-locator dataset-01 \
  --preparation-root /data/preparation --evidence-root /data/evidence \
  --request-id dataset-01 --run-id dataset-01
```

Source, target, preparation and evidence roots must be separate. Source/target/
preparation directories must already exist. Source is never silently selected
again for recovery. The request key is not regenerated to evade a conflict.
Default file route `1.0` retains the exact F01 1 MiB behavior; explicit `2.0`
streams up to 2 GiB. Bundle bounds: 1024 members, 2 GiB/member, 4 GiB total,
1 MiB request/manifest, depth 32. One active high-level operation per target root.
A bundle's directory rename is the visibility point; reserved manifest/owner
files and private `phase-stage-*` directories are not ordinary published files.

## Timeout, progress and verification are different

Keep the publication worker alive when a client wait expires. For example,
start the above command with `subprocess.Popen(argv, stdout=log, stderr=errors)`
(no shell), where log files are private caller-owned files; call `wait(timeout)`.
On `TimeoutExpired`, **do not call kill or publish again**. The caller owns that
process and must eventually wait/reap it. There is no persistent queue daemon.
The tested MCP client also times out a real `phase_publish_bundle` call and then
queries/reconciles its original run without a second publish call.

```sh
phase publication-status --evidence-root /data/evidence \
  --run-id dataset-01 --wait-seconds 30
```

`publication-status` reads only bounded saved metadata. Stages are
`not_observed`, `preparing`, `intent_recorded`, `effects_recorded`,
`receipt_recorded`. It does not establish worker liveness; `recorded_*` describes
stored claims, never current byte integrity. `verification_performed=false` and
`target_verified=false` are mandatory. A wait is 0–60 seconds; expiry is not
operation failure or evidence of no mutation. Retain run/key/root references.

For full current verification use `phase inspect` with `--root
phase_result_root=/data/published`. To restore a lost completion response or
reconcile a proven effect missing its final receipt:

```sh
phase recover-publication --evidence-root /data/evidence --run-id dataset-01 \
  --target-root /data/published --request-id dataset-01 \
  --expected-intent-digest sha256:<exact-intent-digest-from-the-original-run>
```

This compares the exact intent/key/root/plan/frozen data and current target. It
adds a digest-addressed recovery observation, preserving all original evidence.
`verified_existing` is a current observation, not a rewritten original receipt.
Recovery does not replay target writes: unpublished staging, partial files,
unproven effects, changed roots/inputs/evidence, or conflicting keys produce an
explicit refusal/indeterminate result. Nothing is auto-deleted. Never treat a
private stage or an exited worker as a complete publication.

## Explicit independently bound prepared-stage continuation (rc3)

Opt in when creating a bundle: `phase publish-bundle --publication-version 2.0`
with the same explicit members and roots. Exact `bundle_create.v2@1.1.0` saves
prepared-stage proof and independent `<run>/preparation-binding.json` before its
publication syscall. Missing/invalid independent binding and older v2@1.0.0 stages
cannot be upgraded by assumption; they refuse explicit continuation. After a crash:

```sh
phase recover-publication --mode commit_prepared \
  --evidence-root /data/evidence --run-id dataset-01 \
  --target-root /data/published --request-id dataset-01 \
  --expected-intent-digest sha256:<original-exact-intent-digest>
```

This mode may mutate target, only by committing the fully verified original stage.
It does not regenerate members or reread current source; it rejects damaged stages,
missing preparation proof, conflicting target and old `recovery.policy=none` packages.
The original receipt stays unchanged. `recovery/commit-intent.json` is durable before
the commit; `commit-receipt.json` and digest-addressed observations record continuation.
`recovery_mutation_attempted` distinguishes this invocation from an idempotent repeat;
`verified_existing` describes the verified target at observation time. Default mode
`observe`, inspect and status do not gain target mutations. MCP uses `mode="commit_prepared"`
and `publication_version="2.0"` with the same semantics.

Late unlock/close failures remain non-success even after a known commit; consult
the returned effect progress and retained observations, not only the exit code.
Repeat with the same original bindings after the failed process has exited;
do not create a new publication merely because finalization failed. Trust limits
and the verifier-path matrix are in [CORRECTION-02.md](CORRECTION-02.md).

## MCP and Python mapping

Use a separate test process `phase mcp serve --stdio` with the installed MCP
1.x client. The corresponding tools are `phase_publish_file`,
`phase_publish_bundle`, `phase_publication_limits`, `phase_publication_status`,
`phase_recover_publication`, and `phase_inspect`. Arguments use underscores;
`members` is an explicit list. They transfer paths/digests/compact metadata,
not large document bytes. Unknown fields are rejected.

Python uses the same methods on `PhaseApplication`; each returns an
`ApplicationResponse` (`payload`, `exit_code`). Publication statuses distinguish
`verified`, `rejected_before_write`, `committed_unverified`, `indeterminate`.
A nonzero exit or lost response must not be interpreted as an absent target.
No semantic quality judgement is implied by byte-level publication verification.
