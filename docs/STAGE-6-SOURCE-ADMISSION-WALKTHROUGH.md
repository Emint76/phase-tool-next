# Stage 6 Source Admission Walkthrough

Status: factual committed-HEAD acceptance evidence for executable `source_admission.v1@1.0.0` on 2026-07-29. Stage 7 and `knowledge_admission.v1` are not active.

## Runtime shape

Stage 6 is an operation contract executed by the existing `PhaseCore.run`; it is not a separate source pipeline. The lifecycle is:

1. capture the candidate and exact input bytes;
2. resolve the exact registry-bound operation contract and code-owned contract hook;
3. freeze candidate/input/descriptor bytes;
4. run contract-owned validation;
5. produce one deterministic ordered effect plan;
6. durably write intent and its plan/content bindings;
7. execute and verify `effect.0.blob`;
8. execute and verify `effect.1.descriptor` only after the verified prefix;
9. persist ordered progress and effect receipts;
10. issue the canonical Phase receipt;
11. re-read and inspect the canonical source result, reference, and binding.

The ordered broker, Core, planning, and inspection surfaces contain no source-contract identifiers or source metadata vocabulary. Source semantics remain in `phase_tool.contracts.source_admission_v1`.

## Immutable authorities

The two effects are:

1. `effect.0.blob` — `content_addressed_copy@1.0.0`, locator `blobs/sha256/<first-two-hex>/<sha256>`;
2. `effect.1.descriptor` — `mechanism.exclusive_create_v1@1.0.0`, locator `r/<namespace>/<logical_source_id>/<source_result_id>.json`.

The blob is authoritative for exact bytes. The immutable canonical descriptor is the source result and owns logical identity, content digest/length, media type, original filename, provenance, placement, result ID, and source run reference. The Phase receipt remains execution evidence and does not own canonical source metadata.

Both mechanisms use the same mutation-boundary `TargetAuthority`. It validates and pins the target parent chain and prevents a parent replacement from redirecting create/readback.

## Historical pre-Linux-only CLI acceptance

> **Historical record only.** The command and output below were captured before the production/release boundary became Linux/POSIX-only. They are retained to explain the preserved evidence values, not as a supported invocation or as current release verification. The current runtime rejects Windows mutation with `platform.mutation_unsupported` before candidate capture; current acceptance is executed only on qualified Linux hosts.

Historical command (unsupported by the current runtime):

```text
env -u PYTHONPATH .venv/Scripts/python.exe scripts/stage6_cli_acceptance.py
```

Historically observed compact output:

```json
{"scenario_count":29,"success":true,"summary":"C:\\Users\\Gennady\\HermesWorkspace\\Research\\agent-task-journal\\.stage6-tmp\\final-cli\\stage6-cli-acceptance-summary.json"}
```

Structured summary:

```text
path: .stage6-tmp/final-cli/stage6-cli-acceptance-summary.json
sha256: e9c8badc7f9991b907f0b79f3e07246c182a974dd3fb886ca9e6a36d2afc8ec5
scenario_count: 29
success: true
failures: {}
target_file_count: 19
evidence_file_count: 177
```

The summary, intent, and receipt digests below are captured root-identity-bound evidence from the preserved acceptance roots used for that run. They are not a cross-root reproducibility invariant: deleting and recreating the resolved target root changes its filesystem identity, which intentionally changes `idempotency.root_identity_digest`, the intent digest, and therefore the receipt's `evidence.intent_digest`. With the resolved root identity preserved, repeated CLI runs produce byte-identical canonical receipts. The effect plan and canonical source result remain stable across equivalent roots.

All 17 cross-scenario checks are `true`: ordered plan/progress, durable intent presence, source immutability, reuse without overwrite, shared-blob reuse, recovery, fail-before-callback rejection, effect ordering, descriptor/blob binding, distinct identity result IDs, runtime inspection result/reference/binding, cleaned subprocess `PYTHONPATH`, and absence of registered knowledge admission.

### Scenario inventory

| Group | Real scenarios |
|---|---|
| Public source lifecycle | validate, plan, unchanged-target validate/plan, text execute, CLI inspect, read-only contract-result inspection |
| Reuse and identity | same operation/same request, same operation/different request, same logical identity/different content, same bytes/different filename, same bytes/different logical ID |
| Recovery and callback boundary | existing blob/missing descriptor recovery, unsafe descriptor-conflict callback rejected before mutation |
| Payload and candidate validation | binary, empty, unsafe logical ID, digest mismatch, malformed provenance |
| Ordered failure injection | post-intent plan tamper, scalar effect 0 write failure/effect 1 not started, unsafe effect 1 callback rejected before mutation |
| Stage 2–5 regressions | fixture create, fixture append, fixture copy, task journal |
| Stage boundary | exact `knowledge_admission.v1` registry lookup rejected |

Controlled helpers invoke the real `PhaseCore`, `EvidenceStore`, `EffectBroker`, and `inspect_run`. Scalar fault controls exercise bounded failures; callable fault scenarios prove fail-before-callback rejection and do not inject production mutations.

## Successful source evidence

For run `source-execute`:

```text
effect_plan_digest: sha256:a92698a224802248df661766ca28280f673407bad33831b6c42527e5d0fe1cb7
intent_digest:      sha256:dda8f8d5bb8170d827ca0a6969696bcdd9b413d3df8c1291e5e23e1a7e4da198
receipt_digest:     sha256:fed8416c31a039ecbca5d91d1b98cba342d1eb9c97074a3682aea0d11713076b
terminal_status:    succeeded_verified
execution:          executed
```

Canonical source result:

```text
source_result_id: source-result-3b280dbec22fb3ae515db55d21e497542959bbda6a04cb7e5440cfa8de077e2d
content_digest: sha256:faf7433439480c55acb3864b4b5479e5c4d7d8602c0c68ac7176cb045d1128f9
content_length: 19
blob_locator: blobs/sha256/fa/faf7433439480c55acb3864b4b5479e5c4d7d8602c0c68ac7176cb045d1128f9
descriptor_locator: r/acceptance/source-text/source-result-3b280dbec22fb3ae515db55d21e497542959bbda6a04cb7e5440cfa8de077e2d.json
descriptor_digest: sha256:be254ed39a5c9bcca8cbdf35f1b13793b56ec772d73a3f0d4eae0559b247ea04
descriptor_length: 1088
```

`inspect_run` re-read the installed descriptor and blob, returned `target_verified=true`, validated the descriptor as the source result, and produced exact source-result reference and binding documents. Both bind the descriptor digest/locator, blob digest/locator, source result ID, logical source ID, contract ID/version, run ID, and Phase receipt digest.

The descriptor itself contains only `admission_run.run_id` plus `receipt_authority: phase_evidence_by_run_id`; it does not embed the final receipt digest.

## Failure and recovery truthfulness

Observed key outcomes:

| Scenario | Exit | Terminal status | Mutation | Blocker |
|---|---:|---|---|---|
| same operation, different request | 10 | `rejected` | false | `idempotency.same_key_conflict` |
| same logical identity, different content | 10 | `rejected` | false | `source.logical_identity_conflict` |
| unsafe descriptor-conflict callback | 10 | `rejected` | false | `broker.unsafe_fault_callback` |
| post-intent ordered-plan tamper | 10 | `rejected` | false | `broker.plan_changed_after_intent` |
| effect 0 write failure | 30 | `failed_partial` | true | `mechanism.write_failed` |
| unsafe effect 1 callback | 10 | `rejected` | false | `broker.unsafe_fault_callback` |
| knowledge admission lookup | 10 | `rejected` | false | `registry.entry_not_found` |

The scalar effect-0 failure leaves `effect.1.descriptor` `not_started` and does not emit atomic success. Callable later-effect scenarios are rejected before any effect begins. Existing exact blob bytes are reused with `bytes_written=0`; a missing descriptor is then created and verified.

## Executable regression evidence

Observed during final pre-commit acceptance after review remediation:

```text
Stage 6 + Stage 3/5 targeted: 80 passed in 42.50s
Stage 2–5 proof suites:       137 passed in 57.91s
Full suite:                   164 passed in 85.16s
Shared-authority cleanup:      25 passed in 21.60s
Architecture scan:             architecture_errors=[]
Registry/package integrity:    errors=[]
Protected inventory:           8/8 exact inventories unchanged
```

The full suite reported no skipped tests. On committed tree `2a83917a4a3a9fde24dbc01f143e5d4075e3add4`, the full suite then passed `164` tests in `83.91s`. The captured receipt bytes above were reproduced while the resolved acceptance-root identity was preserved; after root recreation, only the root-bound intent linkage changes as described above.
