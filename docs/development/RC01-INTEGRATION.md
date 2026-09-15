# Local publication integration (RC01)

Use an isolated candidate installation on qualified Linux ext4/overlay. This is
not an instruction to change a working Hermes profile or enable its MCP server.
No LLM, network request, generated helper program or content review is part of a
publication. CLI and MCP call the same `PhaseApplication` and Phase Core.

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
