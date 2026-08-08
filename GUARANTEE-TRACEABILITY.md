# Guarantee Traceability Matrix

Status: Historical Stage 1 specification ledger. The row statuses below record the Stage 1 baseline and are not the current implementation status.

Current executable authority-profile claims, qualification boundaries, and tests are maintained in
[`PLATFORM-GUARANTEE-MATRIX.md`](PLATFORM-GUARANTEE-MATRIX.md). Contract admission and its trust boundary are documented in
[`ADR-CONTRACT-AUTHORITY-GUARANTEES.md`](ADR-CONTRACT-AUTHORITY-GUARANTEES.md).

## Claim rules

A guarantee may be claimed only when all are bound:

1. exact implementation boundary/version/digest;
2. installation/platform/filesystem qualification;
3. positive, negative, adversarial, concurrency, and crash tests as applicable;
4. canonical receipt evidence from the actual run;
5. truthful failure propagation.

Within this preserved Stage 1 ledger, schema/prose status is `SPECIFIED`, never `IMPLEMENTED`.

| ID | Future guarantee | Owner/boundary | Evidence | Required tests | Stage 1 status |
|---|---|---|---|---|---|
| G-TRUST-001 | Exact contract ID/version/package digest is loaded from an installation-controlled snapshot | Contract resolver + registry | registry snapshot digest; resolved binding | CT-REG-001..005 | SPECIFIED/UNIMPLEMENTED |
| G-TRUST-002 | Only bundled exact-digest mutation mechanisms can obtain broker mutation capability | Registry + effect broker capability boundary | mechanism binding/capability receipt | CT-REG-003,004,006,007 | SPECIFIED/UNIMPLEMENTED |
| G-CONTRACT-001 | Contract contains declarative policy, not command/path/import execution | Schema + semantic contract validator | validator result/code | CT-REG-008 plus bypass corpus | SPECIFIED/UNIMPLEMENTED |
| G-FRZ-001 | Consumed copied bytes equal recorded frozen blob digest | `copy_and_hash` freezer + blob reader | blob digest/length/read-back, intent binding | CT-FRZ-001..003,008 | SPECIFIED/UNIMPLEMENTED |
| G-FRZ-002 | Value inputs remain exact captured canonical bytes | value snapshot codec | codec/version/digest/inline or attachment | CT-FRZ-007,008 | SPECIFIED/UNIMPLEMENTED |
| G-FRZ-003 | Manifest detects recorded set/content drift but is not a byte freeze | manifest generator/revalidator | canonical manifest/digest/errors | CT-FRZ-004,005 | SPECIFIED/UNIMPLEMENTED |
| G-CONC-001 | Cooperating append writers serialize and stale head is rejected before write | expected-head append mechanism and lock provider | lock scope; before/under-lock heads; effect receipt | CT-EFF append stale/concurrent + CT-PLAT lock | SPECIFIED/UNIMPLEMENTED |
| G-EFF-001 | Exclusive create never replaces an existing destination | exclusive-create OS boundary | before/create result/final identity | CT-EFF exclusive race + CT-PATH races | SPECIFIED/UNIMPLEMENTED |
| G-EFF-002 | Content copy consumes frozen blob and publishes no different-hash replacement | content-addressed copy mechanism | blob/destination digests, publication receipt | CT-EFF copy absent/same/conflict/race | SPECIFIED/UNIMPLEMENTED |
| G-EFF-003 | Multi-effect execution makes no all-effects transaction claim and reports partial subsets | effect broker + aggregate classifier | per-effect receipts/static plan | CT-EFF failure after each index | SPECIFIED/UNIMPLEMENTED |
| G-PATH-001 | Broker effects remain under resolved approved roots | root resolver + path policy + OS handle boundary | root/parent/final identities, effect receipts | CT-PATH full suite on each platform | SPECIFIED/UNIMPLEMENTED |
| G-PATH-002 | Symlink/reparse/traversal/reserved aliases are rejected by v1 policy | path policy + OS resolver | path validator result/identity evidence | CT-PATH traversal/link/reparse/Windows cases | SPECIFIED/UNIMPLEMENTED |
| G-SCOPE-001 | All **broker-observed** effects match the static allowed plan | plan validator + broker | intent/plan/effect receipts | CT-EFF static-plan and injected-effect denial | SPECIFIED/UNIMPLEMENTED |
| G-SCOPE-002 | No claim is made about writes outside broker observation | architecture/capability boundary | claim wording + sandbox/audit test limits | external direct-write demonstration | SPECIFIED/UNIMPLEMENTED |
| G-IDEM-001 | Same scoped key/request digest returns existing verified result without duplicate effect | idempotency coordinator + canonical lookup | intent/result/receipt bindings | CT-IDEM same/concurrent/crash cases | SPECIFIED/UNIMPLEMENTED |
| G-IDEM-002 | Same scoped key with different request digest conflicts before mutation | idempotency coordinator | conflict validator result | CT-IDEM conflict/concurrency | SPECIFIED/UNIMPLEMENTED |
| G-STATUS-001 | Exactly one truthful terminal status and success exit only for verified success | aggregate terminal classifier | phase receipt/effect/validator/evidence states | CT-EVID every status/cross-field invariant | SPECIFIED/UNIMPLEMENTED |
| G-EVID-001 | Canonical receipt binds intent, exact contract, effects, result, validators, and evidence finalization | receipt finalizer | schema-valid receipt/attachments/digests | CT-EVID missing/corrupt/finalization/kill cases | SPECIFIED/UNIMPLEMENTED |
| G-EVID-002 | Committed target with failed verification/evidence is non-success | verifier + receipt finalizer/classifier | committed_unverified receipt | evidence-finalization adversarial test | SPECIFIED/UNIMPLEMENTED |
| G-EVID-003 | Multi-effect recovery never guesses the reached subset | effect broker + durable effect journal | ordered attempt/observation marker chain and final effect receipts | kill before/after every marker/effect + corrupt/missing chain | SPECIFIED/UNIMPLEMENTED |
| G-SCOPE-003 | Broker operational writes use separate resolved capabilities and are not misclassified as target effects | effect broker + installation capability resolver | temp/lock/directory/evidence observations | injected operational-root escape and cleanup-failure tests | SPECIFIED/UNIMPLEMENTED |
| G-REC-001 | Partial/indeterminate outcomes are not blindly retried or automatically rolled back | recovery classifier/idempotency coordinator | retry disposition/recovery flag | CT-IDEM partial/unknown; CT-EVID kill points | SPECIFIED/UNIMPLEMENTED |
| G-PLAT-001 | File-data flush claim matches tested OS/filesystem boundary | mechanism platform adapter | sync call/result/environment | CT-PLAT file sync per environment | SPECIFIED/UNIMPLEMENTED |
| G-PLAT-002 | Directory-entry durability is claimed only where implemented/tested | mechanism platform adapter | directory sync/publication evidence | CT-PLAT publication crash suite | SPECIFIED/UNIMPLEMENTED |

## Explicit non-guarantees

No Stage 1 artifact proves:

- runtime availability or correctness;
- OS-wide absence of out-of-scope writes;
- multi-effect transactionality;
- automatic/executable rollback;
- third-party mutation executor safety;
- power-loss durability;
- network/remote filesystem semantics;
- privileged-user tamper prevention;
- provenance/review truth;
- source/knowledge parity;
- regulatory compliance;
- universal Phase architecture.

## Review gate

A High risk blocks Stage 2 when a future success claim lacks any one of:

- one owner;
- one implementation boundary;
- observable evidence;
- negative/adversarial test;
- platform qualification when platform-dependent;
- truthful terminal-state mapping.
