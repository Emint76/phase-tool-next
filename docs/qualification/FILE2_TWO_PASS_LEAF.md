# Unselected file2 two-pass byte prerequisite

This internal leaf does not enable native file2, qualify NTFS or produce a
receipt. No registry, descriptor, provider selection, qualification guard,
installation profile, Core lifecycle or historical protocol is changed.
A05/G01/G02, positive native CLI/MCP, full REF/MIX/FULL contract qualification,
native rollback and release remain NOT_VERIFIED. FULL stays disabled.

## Scope and necessity

Existing original roles materialize complete immutable file1/version1 inputs
under their fixed 1MiB/16MiB caps. Their ALLRO process exits before the Windows
worker starts. Those roles cannot simply raise a cap to2GiB or retain an FD
through a later exchange. This leaf is deliberately unselected until a future
closed file2 role validates FULL original/installation/plan/preconditions and
retains ONE existing gated execution epoch through both passes.

The producer borrows the existing Core ext4 verified anonymous snapshot. Its
owner performs one close; the borrower retains the SAME descriptor across both
passes, checks actual metadata and requires a successful actual lseek before
emitting its rewind token. The worker-side data checker verifies the full first
pass against the expected digest/length before READY, retaining only SHA256
values computed from the ACTUAL first-pass chunks. Each replay chunk must match
that vector before feed can return it to a sink. Fixed256KiB chunks and the
existing2GiB cap imply at most8192 raw32-byte hashes. No new product limit is
introduced. Header/pass/index/offset/end/tokens are exact and operations one-shot.

The transient hash vector is necessary to reject changed replay bytes BEFORE
that chunk can reach a native writer without buffering2GiB. It is no journal,
document version, queue, spool, receipt or durable coordination state. Existing
Core remains the only intent, idempotency, lifecycle and evidence owner.

## Authority and outcome boundaries

Matching context/channel/READY/rewound/GO frames authenticate DATA correspondence;
they authenticate no caller, process, grant, actual rewind in another process,
physical GO, pipe EOF or worker exit. The future trusted caller must qualify
its Linux source root and validate the complete original before construction.
The factory's Linux check alone is not filesystem or installation admission.
No arbitrary FD/iterator, caller size policy, NativeIO or target access is exposed.
Snapshot metadata checks detect ordinary drift; they are not an atomic snapshot
guarantee against a hostile writer able to manipulate the same private process.

First-pass errors release no payload. A replay failure may follow a valid
returned prefix; a future physical sink could already have created a file or
written bytes. Such an outcome must remain partial/unknown with sticky Core
dispatch and no retry. It must never become no-effect, rollback or success.
finish returns only data digest/length/count, never an operation receipt.
FD closure/exception/timeout cannot demonstrate remote worker quiescence.

Both source reviewers rejected the first unexecuted draft because resuming a
generator paused at END could revive an intervening failed state. The corrected
draft rechecks active state after that suspension and never overwrites failed
or retired state in generator finalization. Receiving END alone does not prove
that the producer has drained or finalized. The original rejected draft stays
in the private evidence lineage; it is not selected or delivered as product.

## Executable controls and limits of their evidence

The new tests use actual qualified Linux temporary roots, real anonymous
snapshots/reads/rewinds/closure and an independent literal JSON/frame oracle.
They cover boundary sizes, exact2GiB geometry and over-cap refusal before
snapshot, binding/token/order/end errors, corrupt replay at first/middle/short
last chunk, paused-END poison/retirement, duplicate producer calls, failed real
rewind, short reads, actual copy mismatch, snapshot drift and primary plus
secondary finalization errors. No test mocks a qualification guard or executes
NativeIO. Fault injection replaces only the specific read/lseek/close boundary
being tested, and is not evidence for the real fault's probability.

One test streams actual4MiB and32MiB through both passes into a hash-only sink
and gates the difference in traced Python peak allocation at4MiB. It neither
measures whole-process RSS nor proves2GiB native throughput/backpressure/deadline.
The2GiB geometry test allocates no2GiB payload and claims only header/count bounds.
All new tests are UNEXECUTED when this source document is first checkpointed;
their first execution belongs to ordinary GitHub Linux CI after preservation.
Later CI outcomes must be bound to exact source/build bytes separately.

## Remaining integration

The existing one-response channel, parent READY/GO, process owner, Windows pipe
framing and worker roles are untouched. Native file2 needs a distinct exact
original role and effect/observation/proof binding; Core retains the verified FD
through ONE gate, actual READY -> sameFD rewind -> bound token -> ONE parent GO,
then replay, flush/name/readback, real worker exit/finalization, independent
observations and ordinary Core proof/receipt. READY is not a final ACK or a
second RPC. Dispatch remains sticky from the first execute frame.

Current30s limits cannot silently reset per frame or be raised by request.
A fixed versioned end-to-end window needs real measurements at every leg,
including capture/prehash, both passes and backpressure. These are outstanding,
as are actual Windows namespace/lifetime tests. Reuse NativeMutationIO's bounded
write step and existing bounded mutation trace; add no parallel event journal.
This leaf alone does not resolve historical0xC0000280 or worker-finalization
counterexamples and must not be used to claim the six-contract MIX route.
