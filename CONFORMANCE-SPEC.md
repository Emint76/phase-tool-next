# Stage 1 Conformance Specification

Status: executable schema/fixture specification only. Target mutation tests are catalogued but prohibited in Stage 1.

## 1. Scope

Stage 1 may execute only:

- JSON parsing;
- Draft 2020-12 meta-schema checks;
- schema validation of contracts, examples, and vectors;
- deterministic fixture/golden-vector generation and digesting;
- lexical/static semantic checks;
- read-only review.

It must not instantiate a mutation mechanism, create `.phase/runs`, write a canonical domain target, implement a CLI, or invoke admission/runtime wrappers.

## 2. Artifact classes

| Class | Paths | Stage 1 meaning |
|---|---|---|
| Core schemas | `schemas/*.schema.json` | Strict data shapes; not implementation |
| Synthetic contracts | `contracts/fixtures/*.json` | Neutral future conformance drivers |
| Domain probes | `contracts/design-probes/*.example.json` | Non-executable meta-model fit tests |
| Positive vectors | `fixtures/positive/*.json` | Expected future verified behavior |
| Negative vectors | `fixtures/negative/*.json` | Expected fail-closed behavior |
| Adversarial vectors | `fixtures/adversarial/*.json` | Race/crash/path/partial/evidence expectations |
| Golden vectors | `fixtures/golden/*.json` | Exact deterministic bytes/status invariants |
| Catalog | `fixtures/catalog.json` | Complete machine-readable vector index |
| Manifest | `fixtures/manifest.sha256` | Deterministic digest inventory generated after validation |

## 3. Stage 1 validation layers

### L1 — JSON and meta-schema

- every JSON file parses;
- every `*.schema.json` passes `Draft202012Validator.check_schema`;
- schema format checking is enabled when validating instances;
- local `$id` references are resolved from an explicit immutable in-memory registry, not fetched from the network.

### L2 — instance schema

- both synthetic contracts validate against `phase-contract.schema.json`;
- both domain probes validate against the same schema;
- every conformance vector validates against `conformance-case.schema.json`;
- fixture candidate schemas pass the Draft 2020-12 meta-schema.

Passing L2 proves shape only.

### L3 — static semantic conformance

The Stage 1 validation command must check:

1. exact IDs, semantic versions, and SHA-256-shaped package digests exist at every binding;
2. validator bindings declare validator capability;
3. path-policy bindings declare path-policy capability;
4. operation mechanisms declare mutation-mechanism capability;
5. v1 contract schema rejects `update` and `compare_and_swap_replace`; CAS remains prose-only deferred design until a future schema version;
6. all other fixture mutation mechanisms are bundled v1; design probes are deferred;
7. contract documents contain no executable field names (`command`, `shell`, `script`, `executable`, `import`, `module`, `entrypoint`, `exec`);
8. Core schema token vocabulary excludes forbidden domain/control-plane tokens;
9. synthetic contracts exclude domain vocabulary;
10. candidate/effect limits are bounded and static;
11. automatic rollback is false;
12. every catalog path exists and no case is omitted/duplicated;
13. every required coverage tag appears;
14. only `succeeded_verified` permits success exit;
15. all Stage 1 vectors prohibit target mutation;
16. partial/unverified/indeterminate vectors require inspection/recovery as specified;
17. input IDs, root binding IDs, validator IDs, effect IDs, and target locators are unique under their declared normalization policy;
18. every referenced root/input/validator/effect exists in the same frozen contract/plan boundary;
19. operation intent, mechanism availability, allowed physical effects, and recovery policy are compatible; CAS/update, generic compensation, snapshot restore, and automatic rollback are absent from v1 executable schema;
20. aggregate receipt validator/effect sets exactly match the frozen declarations and static plan;
21. every terminal status and both success dispositions have a schema-valid golden receipt;
22. multi-effect plans require a valid ordered effect-journal marker chain, or execution is rejected before mutation;
23. operational temp/lock/directory/evidence writes use separate resolved capabilities and are not counted as target effects.

L3 is a deterministic specification checker, not runtime proof.

### L4 — golden determinism

- recompute exact-byte SHA-256 vectors;
- regenerate sorted, canonical fixture JSON (`sort_keys=True`, indentation and final newline fixed for artifact generation);
- regenerate `fixtures/manifest.sha256` in path order;
- rerun and require byte-identical output.

The formatting rule is for Stage 1 artifact generation only. It does **not** yet define the general `canonical_json_v1` request digest profile. That profile remains a Stage 2 blocker/ADR.

## 4. Required coverage tags

```text
wrong_contract_digest
wrong_contract_version
untrusted_mechanism
mutated_input
traversal
symlink
reparse
reserved_windows_name
stale_concurrency_token
same_key_conflict
partial_effect
committed_result_failed_evidence_finalization
indeterminate_result_state
concurrent_append
torn_tail
same_hash_idempotency
multi_effect_partial_failure
destination_path_race
post_verification
truthful_terminal_state
```

The catalog may cover one requirement with multiple cases.

## 5. Expected validator model

Each case declares ordered expected validator summaries:

```json
{
  "validator_id": "validator-id",
  "status": "pass | fail | unknown | not_reached",
  "code": "stable_machine_code"
}
```

Future executable tests must emit full `validator-result.schema.json` objects. Stage 1 vectors intentionally record only expected semantic summaries.

Rules:

- blocking `fail` or `unknown` prevents `succeeded_verified`;
- `not_reached` is explicit, not silently omitted;
- expected and actual observations must be kept separate;
- diagnostics may point to attachments but cannot replace machine status/code;
- validator crash/timeout is `unknown`, never pass.

## 6. Future executable conformance catalog

### Registry and trust (`CT-REG-*`)

- `CT-REG-001`: exact contract ID/version/digest success;
- `CT-REG-002`: wrong digest rejected;
- `CT-REG-003`: wrong/missing/ambiguous version rejected;
- `CT-REG-004`: untrusted root/signature rejected;
- `CT-REG-005`: mutable name-only entry rejected;
- `CT-REG-006`: third-party mutation mechanism rejected;
- `CT-REG-007`: read-only validator capability cannot obtain broker handle;
- `CT-REG-008`: forbidden executable contract content rejected.

### Freeze (`CT-FRZ-*`)

- `CT-FRZ-001`: copy/hash exact frozen bytes;
- `CT-FRZ-002`: mutable input changes during copy;
- `CT-FRZ-003`: frozen blob tampering before use;
- `CT-FRZ-004`: manifest set/content drift;
- `CT-FRZ-005`: manifest-only bytes cannot feed mutation without revalidation/copy;
- `CT-FRZ-006`: stale lock snapshot token;
- `CT-FRZ-007`: value snapshot canonical bytes/digest;
- `CT-FRZ-008`: no mutable upstream read after copy/value freeze.

### Path and scope (`CT-PATH-*`)

- traversal/normalization variants;
- symlink insertion at each component;
- Windows reparse/junction insertion;
- reserved names/ADS/device/UNC/trailing-dot-space;
- case/Unicode collisions;
- parent/final identity replacement race;
- special file/hard-link/mount/cross-device cases;
- unsupported network filesystem refusal;
- independent demonstration that declared allowlist is not OS-wide write audit.

### Effect mechanisms (`CT-EFF-*`)

- exclusive create concurrent race/no replacement;
- append first create and expected-head append;
- stale and concurrent append;
- short/torn append at every byte boundary;
- frozen content-addressed copy;
- destination absent/same/different digest;
- destination publication race;
- multi-effect failure after each index;
- post-effect read-back mismatch;
- no dynamic effect added after mutation begins;
- CAS update rejected as deferred.

### Idempotency (`CT-IDEM-*`)

- same scope/key/digest reuse;
- same key/different digest conflict;
- same key across contract/scope differences;
- concurrent first use;
- intent-only crash recovery;
- partial/unverified/indeterminate previous execution;
- stale receipt index versus canonical target;
- adopted-existing versus operation-created claim.

### Evidence and terminal states (`CT-EVID-*`)

- every status-field invariant;
- effect set equals frozen plan;
- failed-no-effect target unchanged proof;
- committed result with failed receipt/attachment finalization;
- missing/corrupt attachment;
- intent without receipt at every kill point;
- successful result/receipt exact binding;
- non-success exit propagation through adapter;
- no human report as canonical outcome.

### Platform (`CT-PLAT-*`)

Execute the qualified release suite on native Linux selected local filesystems. Treat Windows, WSL-native, WSL Windows-backed mounts, and every other non-qualified runtime as unsupported: mutation must fail closed before capture and authority open. A future Windows authority requires a separate versioned profile and qualification suite.

Record environment details required by `PLATFORM-GUARANTEE-MATRIX.md`.

## 7. One pipeline criterion

Both neutral contracts must use the same Core lifecycle:

```text
resolve exact contract
→ validate candidate and bindings
→ freeze/value-bind inputs
→ write durable intent
→ construct static effect plan
→ effect broker selects exact bundled mechanism
→ execute bounded effects
→ post-verify canonical result
→ finalize canonical receipt/evidence
```

Different mechanism branches (`expected-head append` versus `content-addressed copy`) are expected inside the effect broker. A separate top-level lifecycle, status model, evidence model, registry, or adapter-specific branch is a universality failure.

## 8. Domain fit criterion

The two domain probes must validate against the unchanged meta-schema while carrying provenance/review/placement and domain-specific profile/taxonomy semantics only in instance IDs, bindings, candidate schemas, and validators.

The existing task-journal contract proposal maps to the append fixture structure. Stage 1 does not create an executable domain contract and does not claim parity.

If any probe requires adding its domain token or routing/approval/orchestration semantics to Core schema, the current meta-model fails the test.

## 9. Universality proof and falsification

Universality is **not proved in Stage 1**.

It may be supported only after:

1. lexical and dependency neutrality checks pass;
2. append and copy contracts execute through one lifecycle/state/evidence pipeline;
3. both mutation-bearing mechanisms pass shared and platform suites;
4. the task-domain vertical slice passes contract-specific tests without Core branches;
5. source and knowledge migrations later pass differential validation/execution against intended behavior without Core domain branches;
6. guarantee traceability has no unowned/unimplemented success claim;
7. independent review finds no High/Critical control-plane leakage.

Falsification conditions include:

- domain token/branch added to Core;
- separate append/copy lifecycle or terminal classifier;
- adapter writes canonical result directly;
- contract supplies executable code/path/command;
- routing/approval/scheduling/orchestration needed inside Core;
- a shared guarantee has materially different truth conditions hidden behind one label;
- two mutation-bearing implementations cannot pass the same conformance framework.

## 10. Stage 2 gate

Stage 2 remains blocked until:

- Stage 1 review High/Critical findings are resolved or explicitly accepted;
- canonical request serialization is specified;
- registry snapshot/package digest computation is specified;
- platform no-replace/path/locking test designs are concrete;
- crash/evidence finalization harness design exists;
- effect-plan/receipt aggregate semantic invariants are specified executable tests;
- repository location and runtime coding are separately authorized.
