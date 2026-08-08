# ADR: Contract Authority Guarantee Admission

Status: Accepted for Loop 5

## Context

An exact mutation mechanism identity is necessary but not sufficient to admit a transition. The same mechanism can be installed behind platform authorities with materially different path, concurrency, verification, and durability properties. A provider must not be able to admit itself merely by reporting a stronger profile.

Loop 4 already binds the exact contract package, mechanism, authority provider/profile, and effect-plan digest in transition evidence. Loop 5 adds an admission decision before candidate capture and preserves the exact Loop 4 package generations for inspection.

## Decision

### Contract requirements

Every current contract declares `operation.required_guarantees`:

- `vocabulary` binds the exact guarantee vocabulary ID, version, and descriptor digest;
- each `mechanisms` entry binds one exact mechanism ID, version, and package digest;
- `all_of` names technology-neutral guarantees required from the authority used by that mechanism.

Requirements select neither an operating system nor a provider. Per-mechanism requirements are mandatory because one contract can authorize several mechanisms with different authority usage.

A mechanism-managed mechanism, currently expected-head append, declares an empty `all_of`. It does not consult `AuthorityProvider` and cannot borrow provider guarantees.

### Installation trust boundary

`Installation.authority_profile_binding` is trusted configuration selected at the composition boundary. `AuthorityProvider.guarantee_profile_binding()` is only a consistency report. For provider-backed mechanisms, Core requires exact equality between configured and reported bindings before coverage resolution.

The installation qualifies every declared target root before capture, including roots used only by mechanism-managed effects; unrelated caller-supplied bindings are excluded from authority qualification and cannot influence contract-scoped admission. Declared roots must already exist, resolve without symlink traversal, and satisfy the selected filesystem policy; missing roots are rejected with a receipt rather than inferred from an ancestor. The bundled v1 release policy admits production mutation only on Linux roots identified as `ext4` or `overlay`. Windows and every other non-Linux host select an unsupported authority provider and fail closed with `platform.mutation_unsupported` during guarantee admission, before capture, intent, authority open, or mutation. The composition selector remains isolated so a future Windows implementation can be introduced as a separately versioned profile without weakening the Linux profile. WSL remains unsupported unless a well-formed kernel release identifies Microsoft WSL and the process root is independently identified as `overlay`; Docker/Podman marker files are not treated as attestation, and malformed host metadata fails closed. Other volume classes and filesystem types fail closed with `guarantee.profile_scope_unsupported`. New intents store an immutable canonical list of the resolved identity of every declared root and bind its digest; the schema keeps that list optional only so historical evidence remains inspectable, while broker execution requires and validates the complete list. Production `PhaseCore` and `EffectBroker` execution require exact, non-subclassed `CoreFaults`, `BrokerFaults`, and mechanism-fault dataclass types without evaluating caller-object truthiness, copy only their explicitly enumerated scalar controls into fresh frozen values, and reject every callable fault field before invoking it; scalar fault controls remain available for bounded failure simulation. The public broker owns its receipt list, persists ordered progress through its fixed evidence path after every observed receipt, returns the latest durable progress digest without requiring a redundant Core rewrite, and exposes no progress callback or external receipt sink. Any finalization failure after at least one observed effect causes Core to attempt durable effect-receipt and finalization-failed receipt publication for both partial and complete prefixes. Existing immutable attachments count as present only when their canonical bytes equal the recovered document; transient publication failures can therefore finalize a truthful `committed_unverified` receipt, while missing or conflicting attachments remain explicitly incomplete. During inspection of a failed-finalization receipt, an existing progress artifact is authoritative only when its digest is claimed by that receipt; claimed progress must exactly equal the canonical ordered-progress document reconstructed from the plan and durable effect receipts. An unclaimed stale prefix from a failed atomic replacement is ignored, while finalized receipts retain strict rejection of unclaimed progress. The broker passes only the identity stored in the intent into the host authority, while current pathname observation is a consistency check. The authority compares that identity to the opened root handle before creating or opening leaf paths. Mechanism-managed append uses the same pinned-root identity check without attributing provider guarantees to the mechanism and emits a partial receipt if final namespace verification fails after bytes were written.

The registry then resolves the exact profile descriptor and verifies its bound implementation identity and artifact digest. Unknown vocabulary/profile versions, digest disagreement, unknown guarantees, incomplete/duplicate/extra mechanism mappings, provider disagreement, and insufficient profile coverage fail closed.

### Lifecycle ordering

The lifecycle is:

```text
resolve exact contract generation
→ verify target-root qualification and contract requirements against the exact installation profile
→ capture
→ freeze
→ validate
→ plan
→ reverify the actual plan mechanism closure
→ persist intent
→ broker/mutate
```

Admission failure persists an exact contract-bound rejected receipt. It creates no plan, intent, progress, attachments, blobs, broker call, or mutation. Operational evidence roots and locks may exist as empty infrastructure.

### Evidence and inspection

Requirements are not duplicated into implementation binding. The exact contract package digest already binds their bytes; implementation binding already binds the exact profile/provider/mechanism and effect-plan digest. Avoiding duplicated mutable interpretation prevents two nominal sources of truth.

Inspection independently resolves the exact contract and profile descriptors and repeats coverage validation for current generations. Historical Loop 4 contracts have no `required_guarantees`; their exact archived package and schema bytes remain resolvable and retain their historical validation semantics.

### Platform semantics

- POSIX production profile advertises only executable guarantees established by the POSIX authority implementation and its platform tests.
- Non-Linux hosts expose only the unsupported composition-boundary provider and reject mutation before capture; no Windows authority profile or implementation is bundled in the release runtime.
- Descriptor text alone is not proof. Claims remain bounded by executable platform evidence and filesystem qualification.

## Consequences

- Contract/package digests change and require a new current generation.
- Loop 4 contract and phase-contract schema bytes are archived as immutable historical resources.
- Registry invariants require exactly one current generation for each exact contract binding and schema reference.
- Adding a guarantee requires a new versioned vocabulary descriptor and executable profile evidence.
- Adding or changing mechanism requirements changes the exact contract package and cannot be hidden behind provider selection.
