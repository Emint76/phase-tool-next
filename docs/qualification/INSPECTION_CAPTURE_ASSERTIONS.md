# Private captured-request inspection assertions

This software prerequisite reuses the existing inspect_run receipt recursion.
It adds no publication verb, history index, journal, queue, version store,
receipt field, provider, qualification exception or new Core lifecycle.

The optional private candidate digest identifies the canonical structured JSON
VALUE captured in a verified executed leaf. It is not a hash of caller JSON
formatting, source path, currently loaded code or a current source-file read.
An optional immutable (binding_id, raw digest) pair additionally requires one
unique frozen input with both recorded digest and blob_digest matching it.
Normal inspection has already verified those blob bytes.

Active assertions propagate through the existing prior_verified_receipt_digest
chain with its existing cycle, contract, provider and native FullID checks.
They compare only after ordinary intent, plan, blob, proof and target checks.
Missing receipt, planned/rejected/indeterminate and unavailable-inline captures
cannot satisfy them. A reused invocation still returns its own run and receipt,
including null current intent/plan; it does not impersonate the executed leaf.
None/None keeps the original result and call shape.

The generic inspector contains no file-publication grammar or effect semantics.
A later native file1 adapter must derive expected facts from caller literals
using the existing publication candidate helper and fixed payload binding,
then preserve the existing guard, channel sealing and uncertainty owner.
That caller wiring is not implemented in this slice. No new MCP tool is needed
for this prerequisite. Native positive lifecycle remains NOT_VERIFIED.

Twelve test methods are source-only pending the next exact-HEAD Linux CI.
They use actual qualified ext4 Host/Core fixtures and explicit fixture-only
fault overlays, plus a pure canonical boolean/integer/Unicode data oracle.
They establish no native NTFS admission, A05/G01 safety, native rollback, full
contract-family qualification or release acceptance. All remain NOT_VERIFIED.
