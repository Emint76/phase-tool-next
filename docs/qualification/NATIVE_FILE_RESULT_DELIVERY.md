# Closed CURRENT result delivery for native file1

This source slice extends the existing native transport with a closed inspection
request generation 1.1 and command-frame generation 1.1. The frame adds one
required nullable canonical_result. Existing request/frame generation1.0,
CommandResult, contracts, historical registry bindings, receipts and proof
formats are unchanged. Existing public raw MCP tool signatures remain unchanged.

## Why these changes are necessary

The raw CommandResult omits content digest and length. The existing Core receipt
already owns those facts in its canonical result, and the existing inspector
already verifies the target and CURRENT receipt lineage. The private application
projection obtains this reference during that same inspection. Its transient
delivery permits a later high-level result correlator to reuse those facts
without reading the evidence again or creating a parallel document history.

Two shared data validators in the existing parent-result module check the closed
frame, caller request, run/channel, CURRENT execute-ACK receipt and exact fixed
manifest/contract. The existing static binding resolver and result-reference
schema are reused. Owner, root binding, locator, contract, authority rule, state,
strict bounded length and optional caller digest must agree. A contradictory
success with error or blockers cannot carry a reference. Failed results have a
null reference and keep their original raw failure fields.

The existing sealed inspection function validates the reference before channel
seal completes. The existing parent checks it before marking delivery finished,
and the existing MCP owner checks before clearing its retained launch. A late
validation, transport or finalization failure therefore retains the same
unavailable owner. There is no hidden retry or independent cleanup worker.

These changes add no backend, durable journal, queue, PENDING/FINALIZED system,
receipt owner, document version store or recovery path. The existing MCP gate
still covers one invocation. A later high-level execute-then-inspect operation
must reuse that same gate over its finite sequence; that correlator is not
implemented or claimed in this slice.

## Boundary and evidence

The test source distinguishes synthetic protocol/model data from real Host/Core
receipts on qualified Linux/ext4. Process/OS/launcher facts are synthetic in
transport composition tests. They cannot prove Windows handles, NTFS behavior,
G01 lifetime, A05 reparse confinement or native admission. The real qualification
guard is not replaced; its unqualified refusal is checked separately.

The multihop fixture-history oracle deliberately edits only a disposable receipt
fixture, creates an explicit prior link and distinct CURRENT metadata, then
recomputes its receipt pin. This distinguishes CURRENT from a prior projection;
it is not a new receipt emitted by Core or authentication of that edited history.

Historical owner/head/observed_at fields retain historical meaning. Equality of
delivered fields is correlation under the accepted producer and lifetime, never
authentication of a producer or an assertion that the caller source was reread.

No candidate was run locally during source preparation. New test execution and
independent exact-HEAD artifact verification are required. Native positive CLI/
MCP, complete high-level PublishFileResult, file2/bundle integration and the full
contract family remain unfinished or NOT_VERIFIED. A05/G01 remain NOT_VERIFIED;
FULL stays disabled and no supported NTFS release is claimed.
