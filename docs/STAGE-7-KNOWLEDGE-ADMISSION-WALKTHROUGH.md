# Stage 7 — Knowledge admission walkthrough

## Boundary

Stage 7 activates `knowledge_admission.v1@1.0.0` as a contract-owned adapter over the existing `PhaseCore.run` lifecycle. It does not add a knowledge pipeline, a second Core, or a separate mutation engine.

The exact active registry binding exercised below is:

```text
knowledge_admission.v1@1.0.0
package_digest: sha256:7394231e506248070cebd9692feceb32c7466ed9bae99359fb6aaea4ed1fc2af
```

## Reused generic mechanisms

The contract reuses the accepted ordered multi-effect lifecycle:

1. capture and freeze the structured candidate and artifact input;
2. run exact contract, candidate, source-binding, provenance, identity, placement and result validators;
3. persist durable intent and ordered effect plan before mutation;
4. execute `effect.0.blob` with `content_addressed_copy`;
5. execute `effect.1.descriptor` with `mechanism.exclusive_create_v1` only after the verified prefix permits it;
6. verify the aggregate knowledge result;
7. finalize the Phase receipt;
8. reconstruct and verify the knowledge result/reference/binding through normal run inspection.

Knowledge-specific semantics remain in:

- `schemas/knowledge-*.schema.json` and their bundled mirrors;
- code-owned static validator and hook bindings;
- `src/phase_tool/contracts/knowledge_admission_v1.py`;
- contract result/reference/binding reconstruction and inspection.

The generic runtime additions are domain-neutral: contract hooks may normalize a structured candidate before request hashing, validators and brokers receive a generic evidence-root context, brokers invoke a generic pre-effect hook, and inspection passes the same evidence-root context to result verification.

## Exact source evidence

A knowledge candidate cannot rely on a bare `source_result_id`. Each source binding carries:

- exact source contract identity;
- source result and logical source identifiers;
- source blob locator and content digest;
- source descriptor locator and digest;
- source Phase run ID and receipt digest.

The contract validates the descriptor schema and canonical bytes, recomputes source provenance and source-result identity, verifies the blob, and authenticates the complete source Phase evidence set through normal read-only inspection. Receipt, descriptor, effect-receipt and binding run IDs, exact package digest, effect order/status/kind, intent/plan/attachment bindings and target state must all agree. The same evidence is rechecked before each effect. The canonical source-binding set is sorted and duplicate-free before the request digest is calculated.

## Result identity and placement

The artifact is stored at its content-addressed locator. The canonical descriptor is exclusively created at:

```text
namespaces/{namespace}/knowledge-results/{logical_knowledge_id}/{knowledge_result_id}.json
```

`knowledge_result_id` is derived from the exact contract identity, namespace, logical identity, artifact identity, artifact kind/format, provenance digest and exact `supersedes` reference. The descriptor binds the artifact and the source evidence. A changed request under the same idempotency key conflicts. An exact normalized result reuses the existing verified receipt even when the caller supplies a different operation key, but only after current candidate/source validation and complete inspection of the prior evidence and target.

## Historical pre-Linux-only CLI acceptance

> **Historical record only.** The command and output below were captured before the production/release boundary became Linux/POSIX-only. They are retained to explain the preserved evidence values, not as a supported invocation or as current release verification. The current runtime rejects Windows mutation with `platform.mutation_unsupported` before candidate capture; current acceptance is executed only on qualified Linux hosts.

The historical harness invocation (unsupported by the current runtime) was:

```bash
env -u PYTHONPATH .venv/Scripts/python.exe scripts/stage7_cli_acceptance.py \
  --tmp-root .stage7-tmp/loop5-walkthrough
```

Historically observed output:

```json
{"scenario_count":13,"success":true,"summary":"C:\\Users\\Gennady\\HermesWorkspace\\Research\\phase-tool-codex\\.stage7-tmp\\loop5-walkthrough\\stage7-cli-acceptance-summary.json"}
```

The structured summary records 13 subprocess scenarios and no failures. Public `phase` CLI commands prove source bootstrap, source inspection, knowledge validation, planning, execution, inspection, exact reuse, same-key conflict, malformed/missing source evidence and logical-identity conflict. Controlled helpers use the same `PhaseCore`, evidence store and broker only for deterministic failure boundaries unavailable as public CLI flags.

Observed result evidence:

```text
knowledge_result_id: knowledge-result-9537fd37d447b0e0afbd4f1ea52a564816a832c7fd6890bdd34e181d1b3c5d67
artifact_digest: sha256:d54268eed56a38b646fed498979912aa51209fbf6548d202445d86c93dce8767
descriptor_digest: sha256:135ccf9d5dda320ae6a2647ebb495b27b2a52827ac3a7a5c932042fb855a0b43
receipt_digest: sha256:cf9058152d59a5624fe7862866e76a5a4979af084d57f3eeedd96a6ed3753481
```

Complete evidence paths for run `knowledge-execute`, relative to `.phase/runs/knowledge-execute/`:

- `attachments/effect-plan.json`, `length=5514`, `sha256=66408910de8515921852ab16f8e8866f34bde3530e3b6bbb599287d026efe009`
- `attachments/effect-receipts.json`, `length=1086`, `sha256=a313355ce5ca7246906e374502e368dbd05509d8ae12585c01615ce8a52d7c9d`
- `attachments/ordered-effect-progress.json`, `length=1524`, `sha256=c8244d751ee3d93d4fe99f0a5fa4603e78a44d8ec4a11b28fca4078f6ac270e8`
- `attachments/pre-validator-results.json`, `length=3985`, `sha256=9620c2623f19e8c20b6c6e08f3681d8b2ac964f14dc632364a96adcc549826fa`
- `attachments/validator-results.json`, `length=7439`, `sha256=7197f1c36c3651fec1b4c8ae27478027b51a3ef4bce92266f41ab42144ae51b6`
- `blobs/135ccf9d5dda320ae6a2647ebb495b27b2a52827ac3a7a5c932042fb855a0b43`, `length=2072`, `sha256=135ccf9d5dda320ae6a2647ebb495b27b2a52827ac3a7a5c932042fb855a0b43`
- `blobs/d54268eed56a38b646fed498979912aa51209fbf6548d202445d86c93dce8767`, `length=32`, `sha256=d54268eed56a38b646fed498979912aa51209fbf6548d202445d86c93dce8767`
- `intent.json`, `length=4420`, `sha256=3fb008fe508a0c4539fec3c7dcda0819d31449e24947d39d01d0aa5a1ae8b30b`
- `receipt.json`, `length=11166`, `sha256=cf9058152d59a5624fe7862866e76a5a4979af084d57f3eeedd96a6ed3753481`

All structured checks were true:

- exact active contract binding;
- `PYTHONPATH` absent in subprocesses;
- ordered effects exactly `effect.0.blob`, then `effect.1.descriptor`;
- descriptor binds the observed artifact blob;
- exact source binding preserved;
- inspected target verified;
- result/run/receipt linkage verified;
- the scalar effect-0 write failure reported a truthful partial outcome, while an unsafe effect-1 callback was rejected before mutation.

The result, descriptor and receipt digests above are evidence from that exact root-authority-bound run; they are not asserted as cross-root constants.

## Claims not made

Phase Tool validates deterministic admission evidence; it does not determine whether a knowledge claim is true. Per-effect execution, synchronization attempts, and read-back evidence are recorded; power-loss durability is not claimed. Cross-effect atomicity is not provided. The Stage 7 result is root-authority-bound evidence and is not claimed to be a cross-root reproducibility invariant.
