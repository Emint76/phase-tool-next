# Bind a generated publication candidate at the existing Core boundary

## Status and reason for this change

Base commit: `6bad7ca42288db371149d472d82094c8d9f583d0`.
Its CI run [39984361131](https://github.com/Emint76/phase-tool-next/actions/runs/39984361131)
passed all three jobs. Each Python suite contained 1254 passes and one existing
NTFS qualification skip. The exact source, original CI archives and four build
artifacts were preserved through official Phase 1.1 on isolated ext4 storage;
two separate agents restored and checked the saved bytes. See
[the accepted component report](NATIVE_PREPARED_MCP_CI.md).

The prepared native MCP entry already calls the ordinary Core lifecycle. An
additional ready-file convenience tool is deferred: it would not remove the
remaining qualification blockers. No extra journal, queue, document-version
owner, public API or MCP tool is introduced by this change.

Source inspection identified a potential defect in the existing `publish_file`
and `publish_bundle` APIs, versions 1.0 and 2.0. These APIs receive literal
target and request identifiers, generate a temporary candidate, and pass its
path to Core. Core captures the actual file. The wrappers compare that captured
candidate with their original request after execution; `expected_inputs` binds
payload bytes, not these candidate fields. A valid substitution before capture
could therefore produce an effect before the wrapper reports a mismatch.

This is a source-derived hypothesis, **NOT_YET_REPRODUCED** at introduction of
this document. A private preparation directory does not by itself establish
immunity to a writer with the same identity. The separate native executable
namespace lifetime requirement does not prove immutability of preparation data.

## Reproduction and acceptance

Eight synthetic tests independently cover file/bundle, API 1.0/2.0, and a
target-only or request-identity-only substitution. The injected schedule changes
only the test's owned preparation candidate at the Core capture boundary, then
calls the original capture implementation. The real contract, qualifier,
validator, authority, mechanisms, evidence writer and inspector remain active.
The payload does not change. The unmocked filesystem observation must identify
exact ext4 for the owned root and all four relevant roots before any effect;
each observation retains those filesystem values.

Each test requires evidence that the real capture consumed the replacement
exactly once. The principal oracle compares the entire target tree with its
initial state. A false API result alone cannot establish absence of effects.
Bounded observations, actual synthetic target bytes and Core/Host execution
evidence are exported before assertions and disposable-root cleanup. These are
Linux Host component tests, not native NTFS safety or adversary-timing proof.

The initial prediction is eight new failures with all 1255 prior test identities
and statuses unchanged. That prediction is not an observed result. Both separate
reviews of the actual original CI archives must establish whether this is a
product defect, a harness error, or a non-reproduced hypothesis. Negative results
remain preserved. No manual rerun is needed for an expected failing regression.

Only if actual evidence confirms the defect, the proposed minimal correction is
to carry private immutable expected canonical-candidate bytes through the
existing application request. Core compares them with the actual captured bytes
immediately after capture, before normalization, schema processing, freezing,
intent or GO. File and bundle wrappers bind the same buffer they materialize;
the existing `candidate=value` path binds its once-encoded buffer too. Ordinary
path-only callers keep their current semantics. Historical schemas, contract
bindings, receipts, registry descriptors and recovery ownership remain intact.

The original eight regression identities and physical oracles must then pass
unchanged on a genuinely changed fix HEAD. Full existing CI, installed CLI/MCP
and recovery checks, resource evidence and exact source/build-byte association
are required for that HEAD. The tests and implementation are preserved through
Phase and independently restored before their normal Git transfer.

## Remaining qualification boundary

A05 (the true Windows SYMLINK case) and G01 (executable/dependency namespace
lifetime through unknown or orphaned workers) remain **NOT_VERIFIED**. The native
qualification guard remains closed. This correction would not qualify a native
Core/CLI/MCP run, the six MIX contracts, full REF, FULL or native rollback.
Native high-level streaming, version updates and bundles remain unimplemented.
No production installation or scientific data is changed. PR #14 remains draft;
merge and a supported NTFS release require the original mandatory acceptance.
