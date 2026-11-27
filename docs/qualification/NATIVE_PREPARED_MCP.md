# Fixed prepared MCP candidate: one Core lifecycle

This is an unqualified software integration candidate, not a supported NTFS route. No native positive execution, qualification, final readiness, merge or release is claimed. A05/G01 and the complete MIX/FULL acceptance remain NOT_VERIFIED. Production Phase, Hermes, pcr-rnd and global configuration are unchanged.

## Minimal change and responsibility

The fixed Windows launcher gains the literal `execute-mcp` role before its binary initial-frame reader. It starts a separate MCP server exposing only `phase_execute_prepared` and `phase_inspect`. The existing `inspect-mcp` role still exposes only `phase_inspect` and constructs only read-only invocations. The ordinary `phase-mcp` server and POSIX publication wrappers are unchanged.

Prepared execution reuses the same existing finite MCP call owner, `_NativeAcceptedLaunch`, `run_native_parent`, Windows worker and ordinary PhaseApplication/Core path. There is no new journal, queue, receipt, version store, preparation service or recovery owner. The owner is transient process-lifetime bookkeeping, not a durable operation record.

The adapter accepts a run ID, prepared Linux candidate/input paths, optional expected input digest/length pairs and maximum candidate bytes. Fixed installation supplies contract/registry/roots/evidence and all executable bindings. A request cannot select a provider, executable, operation, contract, registry, root or evidence directory. Strict SDK types and closed argument schemas reject coercion and extra selectors. Digest syntax, roles, capture/freeze, preconditions and contract semantics remain Core responsibilities.

The adapter performs no Path resolution, stat, source read, copy, staging or deletion. Input bytes enter through existing Core capture/freeze. The current native software remains limited to `file_create.v1@1.0.0`, one exclusive create with existing parents, and the unchanged 1 MiB maximum. Prepared execution adds no high-level `publish_file` route, stream, version update or bundle support.

## Unknown outcomes and inspection

Before creating any child, the owner retains the actual launch. Immediate concurrency fails without a queue. Exceptions, result-schema failures and binding mismatches make that owner unavailable and retain any created launch. Primary errors and secondary cleanup notes survive.

A normally delivered command result version1.2, `inspection_required: true` or exit40 is also unresolved. The adapter returns that same validated result unchanged, keeps the actual launch and becomes unavailable before returning. A Docker CLI HANDLE being closed or a finalization attempt being recorded is insufficient proof that an unknown native worker ended. Neither tool on that owner may launch another operation afterward. No retry is authorized. References are retained only while the MCP server lives. Server/session exit or disconnect is not worker quiescence; the accepted external deployment must preserve executable/dependency namespace immutability while any worker may still be active. Actual disconnect/orphan lifetime tests remain NOT_VERIFIED.

A fresh independent read-only launcher/server inspects the known run using the existing Core/evidence reader. It never resets the write owner or turns absence of a receipt into a no-effect assertion. Definite outcomes release the held launch only after the existing checked parent finalizer returns. This extends the existing lifetime owner; Core intent, receipts, locks, idempotency and recovery remain the canonical mechanisms.

## Review and tests

At source publication, the new14 regression methods are **UNEXECUTED**. Their expected next Linux suite is1255 unique cases:1254 PASS and one exact prior NTFS skip; this is an expectation requiring actual XML, not an observed result. Product files remain230; tracked Python tests/helpers become80. Existing architecture inventory, historical descriptors/registries/channel and qualification guard are unchanged. The launcher packaging test updates only its exact data SHA.

Tests cover exact prepared forwarding/fresh launches, shape/coercion/extra-selector rejection, nonqueued contention, unchanged typed uncertainty, schema/run/command/exit mismatch, primary/secondary faults, read-only role preservation, an actual Core qualification refusal, composed existing parent/finalizer/strict seal, fixed launcher wiring and actual SDK stdio with invalid startup. Composed OS/runtime/spawn/HANDLE boundaries are explicitly synthetic. No qualification guard is patched, no native successful receipt is manufactured, and these cases cannot establish Windows/NTFS qualification.

The prior accepted [composition CI](NATIVE_COMPOSITION_CI.md) applies only to HEADa0e7421 and its exact artifacts. A new HEAD needs its own automatic CI, source/ZIP/XML/package audit and installed regressions. Old failures and rejected drafts remain preserved. Two reviewers share a host/toolchain; their reviews are not external certification or required GitHub approval.

## Future isolated deployment; not a production switch

Only after mandatory qualification, deploy the exact accepted immutable Windows CPython3.12.10 runtime, source wheel, dependency graph, launcher/config/manifest and Linux contours with their recorded hashes. Accepted namespace/lifetime immutability is an external prerequisite, not created by this launcher or by hash checks. Current G01 evidence is missing; do not treat these commands as permission to run an unqualified installation.

The fixed launcher command shapes are:

```text
<accepted-python> -I -S -B -u <accepted-launcher> execute-mcp
<accepted-python> -I -S -B -u <accepted-launcher> inspect-mcp
```

Use a distinct read-only client/process for independent inspection. A synthetic prepared call would have this argument shape, with files prepared through the accepted preparation contour:

```json
{"run_id":"synthetic-create","candidate_path":"/prepared/candidate.json","input_paths":{"source":"/prepared/source.bin"},"expected_inputs":null,"maximum_candidate_bytes":1048576}
```

This shape is not a canary result. No working pcr-rnd settings or installed skill are changed. Eventual Hermes instructions must bind the accepted exact artifact, allowed grants/roots, compatible create contract and separate reader, then verify actual create/receipt/inspect. Restoring the prior runtime/config must preserve all documents/evidence and prevent old code from mutating unsupported native resources. Real native CLI/MCP, historical compatibility, contract-supported recovery and old-new-old rollback remain mandatory future tests.

High-level wrappers, binary streams, native versioning and bundles are separate remaining implementation work; A05 requires the authorized [isolated stand](A05_STAND_REQUIREMENTS.md). No permission/system-policy workaround or guard exception is provided.
