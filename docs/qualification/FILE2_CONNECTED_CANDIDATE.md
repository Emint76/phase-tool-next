# Unqualified file2 connected candidate

This source generation adds a fixed `file_create.v2@1.0.0` software composition.
It does **not** qualify NTFS or enable the candidate. A05 and G01 remain
`NOT_VERIFIED`. The mandatory native profile check still rejects before roots,
channels, scratch allocation or evidence reservation, including contracts with
empty guarantee requirements. No production runtime, Hermes profile or system
policy is changed.

## Minimal scope and existing owners

| Added source seam | Necessary failure/property | Reused mechanism/owner |
|---|---|---|
| Immutable registry V6, read manifest 1.3, candidate descriptor v4 | File1 and version1 have fixed 1 MiB/16 MiB bounds and historical exact bindings; interpreting them as file2 would be incorrect. | Existing registry/package trust and qualification guard; old V1–V5 bytes stay immutable. No new production guarantee. |
| File2 control projection plus mandatory actual RO full-blob hash | Passing a declared digest cannot establish the original frozen bytes; materializing a 2 GiB blob in a control frame is not bounded. | Shared original intent/schema/precondition semantics and existing stable bounded `hash_file`. Projection is data only. |
| One file2 stream exchange and bounded native chunk consumer | A worker must verify the full first pass before NativeIO and each replay chunk before writing; late failures must not lose a received completion. | Existing anonymous verified snapshot/SAME FD, pipe framing, channel gate, retained creation HANDLE, physical exclusive-create algorithm and Core interruption attachments. No pump, queue or retry. |
| File2 observation/proof dispatch | Existing observer/wire bounds cannot truthfully prove a large payload; worker self-report is insufficient. | Same native scoped RO reader, existing Core terminal attachment, receipt schema/classifier, independent inspect and evidence store. No second receipt/version owner. |

Core continues to own capture/freeze, intent, plan, preconditions, idempotency,
classification, evidence and canonical receipt. Windows parent owns at most one
worker and the only GO. The ALL-RO original reader actually exits and its owner
finalizes before worker spawn. The first pass verifies complete bytes/length/END
before native mutation; READY is compared with the retained process's PID. The
Core actually rewinds the SAME anonymous snapshot FD. One unchanged local
30-second exchange window covers stream legs and terminal delivery. It has not
been measured as a full 2 GiB native performance envelope and is not enlarged
or reset per frame to manufacture a PASS.

The physical step shares the historical create/trace/mutex/flush/readback body.
It never overwrites an existing destination. A collision drains only the same
healthy incoming replay; a poisoned receiver cannot resynchronize. A late drain
failure remains indeterminate, retaining the earlier effect error and the
acknowledged write count. No parallel document versioning was introduced.

## Deliberately closed history/domain boundary

The new factory accepts only manifest1.3/file_create.v2 and
`history_bindings=None`. Historical V5 remains the exact two-contract pair
`file_create.v1`/`publish_new_version.v1`, with its complete domain comparison.
The existing Core scanner still sees and refuses foreign contract, registry,
installation or unresolved records; completed V5 records on a shared evidence
root are also outside this new active binding.

**Never create a new evidence namespace to hide prior/unresolved operations on
the same physical NTFS root.** The initial isolated file2 composition requires
its own physically disjoint synthetic target root, evidence and preparation
domain. Sharing a physical root with V5 writers requires a later supported
shared-history/domain qualification. Request data cannot select that domain or
registry. This is a deployment acceptance requirement; metadata alone cannot
prove lifetime exclusion or rule out aliases (G01 remains unverified).

Same-contract create/reuse/planned/unknown-history behavior still needs the
complete accepted native lifecycle tests. The existing planned-history fallback
without a native terminal proof retains its 1 MiB bound; absence of the proof
is not permission to skip a record or silently admit a large planned run.
Cross-contract file2→version1 reuse/recovery is not implemented by this slice.

## Verification status and remaining tests

New tests are source-only until their exact Git HEAD has executed in ordinary
Linux CI. They use real Host Core frozen inputs, separate synthetic native
claims/RO files, real anonymous FDs and subprocess pipes with an explicitly
synthetic Windows peer. In-memory native API substitutes test algorithm error
accounting only. Unconstructed authority/parent shells exercise their bound
method bodies with explicitly modeled admission, process and transport
boundaries, including partial/malformed completions and late finalization
errors. They never construct an admitted installation or patch a real
qualification function. Available negative attachment capture is independent
of optional partial-receipt validation and remains useful without a receipt. None replaces the real qualification guard or demonstrates a
Windows write, durability, confinement, worker lifetime or qualified MIX.

Required later native tests include full first-pass/no-NativeIO ordering,
actual creation-HANDLE/PID and sole-GO checks, wrong/missing frames and corrupted
replay after a known prefix, healthy collisions, full source/target hashes,
actual worker exit and owned-resource finalization, independent observation,
late source/gate/worker/observer failures retaining valid partial receipts,
create/reuse/planned >1 MiB/unknown-original and foreign-history refusal,
30-second throughput at the contract bound, original interrupted-operation
rules and isolated rollback. A05 real Windows SYMLINK and G01 remain mandatory
on an authorized isolated stand; no policy/privilege workaround is allowed.

Use the new `native_phase_launcher_v2.py.in` template with the accepted graph
for this candidate; the original launcher template and old bindings remain
unchanged. Existing raw prepared Core/inspect entrypoints remain the integration
surface. High-level native `publish_file` remains file1, version1 remains V5,
and bundle/version2 native paths remain incomplete. FULL stays disabled.
There is no supported release claim, no native rollback claim and no statement
that the scientific experiment is unblocked.
