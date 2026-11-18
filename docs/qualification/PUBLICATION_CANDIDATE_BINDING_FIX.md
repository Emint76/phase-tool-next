# Bind literal publication requests before effects

## Confirmed existing defect

The original CI [40005416960](https://github.com/Emint76/phase-tool-next/actions/runs/40005416960),
attempt1, tested commit `5f9b6e28063dd097a2fdd8ba497f41c4d8944535` and tree
`c0a3f96b8492b46d5181a244665431d2be8ceb6d`. Both Python XMLs contained
1263 distinct tests: 1254 passes, eight new failures and one prior qualification
skip. All 1255 prior test identities and statuses were unchanged. All eight new
failures occurred at the physical target-tree oracle, not a setup or missed
injection check. This CI remains **FAILED**; no post-suite build or installed
smoke artifact was accepted from it.

Two separate agents independently examined both original ZIPs, all 258 CRC
members, XML, full pytest logs, source provenance and 16 physical fixtures.
Each fixture used real Host/ext4 Core components and the original capture
implementation. Only an owned generated candidate was substituted immediately
before capture. Payload bytes and source/canary files remained unchanged.

In target-only cases the literal API requested `requested.bin` or
`requested-bundle`, but Core captured and wrote `changed.bin` or `changed-bundle`.
In request-only cases it wrote the requested target under the substituted
operation and idempotency key. All actual Core receipts correctly reported
`succeeded_verified`/`executed`, exit0. The wrappers then correctly reported
`committed_unverified`, `mutation_attempted=true`, `evidence_mismatch`, exit30,
after detecting disagreement with their literal API parameters. The defect is
the missing comparison before effects, not a false successful wrapper result.

The four exact existing contract generations were verified: file v1/v2 at
`file_create.v1@1.0.0` and `file_create.v2@1.0.0`; bundle v1/v2 at
`bundle_create.v1@1.0.0` and `bundle_create.v2@1.1.0`. Actual receipt/intent/plan,
raw attachment, frozen blob, manifest/member and owner bindings were checked.
Bundle v2's existing operational prepared-stage evidence was verified separately
from the four canonical receipt-listed attachments. An overly broad additional
read-only reviewer assertion was corrected; product and stored bytes did not
change during that verification.

This proves a literal-request binding defect under the controlled substitution
schedule. It is not arbitrary-adversary timing, native NTFS confinement or G01
proof. The exporter observes an owned synthetic fixture with no concurrent
replacement of other namespaces. Independence is separate agents on the same
host/toolchain, not external certification or GitHub reviewer approval.

## Durable evidence identity

Official Phase1.1 on own qualified ext4 preserved both raw ZIPs, all new sources
and rejected drafts in `g-ni-pub-negative-40005416960`:

- Payload SHA-256 `380e10e173c452152de028f75a43518efd1f9660ad9f137e5f0e2baf5d528f31`,543720 B.
- Native receipt `sha256:b157e5e4301a3d71f1c78f810ab775d59e9d17d98125a3f9752489024627b04f`.
- py3.12 ZIP12524960860: `ca52d839a68b9bb399105b74ee9335b66c25753d825b5eef7e264cd0d4b01255`,138141 B.
- py3.11 ZIP12523768122: `79c54d3ec891f13ba211d720c21f3fa986caf3f6564ca931f57c76cef8f38849`,137893 B.
- XML3.12 `023651b76f252e9e64bdc827b51c3d04b46dac98325536560c6e2806cdf5b22b`.
- XML3.11 `1f86199c4b743e0b48a70c75252aec3dc99cfe8ba236482e3ecf0d2b3246090c`.

Both agents restored all902 source names, with zero missing/drift and all896
predecessors unchanged. A fresh separate official read-only inspect and byte
readback confirmed the exact saved payload and receipt. Storage success does
not convert this original negative CI to a successful implementation test.

## Minimal correction, execution pending

Append an optional private immutable expected canonical-candidate buffer to the
existing application/request path. Immediately after the real Core capture,
check strict `bytes`, the existing candidate-size boundary and equality with
the actual canonical bytes. A mismatch produces the existing Core rejection
receipt before hook loading, schema processing, freeze, intent or GO.

`publish_file` passes its existing encoded buffer. `publish_bundle` encodes once
and uses that same buffer for materialization and expectation. The existing
`candidate=value` API binds its own once-encoded bytes through recursion and
rejects a contradictory private expectation before materializing a temporary
file. Default `None` preserves the capture semantics of ordinary path-only
callers. The native mapping-input refusal remains in its original early place.

No public CLI/MCP option, schema, result format, contract binding, registry,
authority profile, lifecycle, receipt owner, journal, queue or document-version
system is added. Existing version and recovery contracts remain their owners.

The original eight regression bodies and identities remain unchanged. Five new
focused tests cover strict immutable type/size rejection, path-only compatibility,
canonical equality despite raw JSON formatting, actual substitution on the
value-input path, and a contradictory expectation rejected before materialization.
The predicted next suite is1268 distinct cases:1267 PASS and the one existing
SKIP. This is **UNEXECUTED**, not an observed result. Exact source review,
Phase preservation/restoration, a genuinely changed fix HEAD, full existing CI,
installed CLI/MCP/recovery/resource checks and build-byte audits are still needed.

## Native qualification boundary

A05/G01 remain **NOT_VERIFIED** and the native qualification guard remains closed.
This fix does not qualify native Core/CLI/MCP execution, six MIX contracts, full
REF, FULL or native rollback. Native high-level streaming, new versions and
bundles remain unimplemented. Production Phase/Hermes and scientific data are
unchanged. PR #14 remains draft; this correction alone permits no supported NTFS
release or merge without the mandatory technical acceptance.
