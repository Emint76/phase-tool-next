# Retained process witness: two synthetic Windows cases

This internal unselected helper observes an exact `SpawnProcess` creation handle
retained by its trusted owner. It queries PID/times, waits and reads exit code;
it never starts a process, opens a process by PID, duplicates/closes a handle,
terminates work or changes privileges. No entrypoint or profile selects it.

It supplies one missing observation for the future native executor: a response
or EOF cannot prove that a process has stopped writing. Only positive wait on
the retained process object can establish this process's exit. It is an execution
component, with no journal, queue, persistence, recovery or document-version state.
Core's original intent and receipts remain the sole operation/evidence owners.

The owner must retain the handle throughout the call, forbid concurrent close,
replacement, field mutation and callbacks. Initialization is one-time; a rejected
repeat does not reset active state. Creation FILETIME is diagnostic, not a unique
birth identifier. Exit evidence concerns this process only: no descendant or
transferred mutable handle is covered. A fixed worker must forbid those separately.

`WAIT_TIMEOUT` supplies no exit proof. The helper accepts `WAIT_OBJECT_0` before
reading exit code. A nonzero exit code is retained as data, never effect success.
In particular259 after a positive wait must not be mistaken for a live process.
See [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
and [GetExitCodeProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess).

## Exact implementation and actual observations

Helper SHA-256 `bcce30bbb713b852388e9a2b25af1b851aa2b87e22c557a14804e882072c337c`.
Harness SHA-256 `d7a021d006167c29b56f1db3dc90b1a485891ac1f3cf2f4c52a5229a0d7b969f`.
The source graph was201 Git files at `e897a1785bad21660718a9395eeb4af6c4e5d81e`
plus the exact private helper overlay, not an installed or qualified new package.

| Own synthetic child | Before GO | After GO | Independent wrapper | Cleanup |
|---|---|---|---|---|
| Exit0 | WAIT258; exit=false; code=null | WAIT0; exit=true; code0 | exit0 | no errors or force |
| Exit259 | WAIT258; exit=false; code=null | WAIT0; exit=true; code259 | exit259 | no errors or force |

Both first actual cases passed. Each trace has11 returned query/wait API events
with stable PID/creation time. There were no primary/finalization errors, forced
terminations, source drift or SafetyStop. A rejected reinit preserved the original
binding and a separate event snapshot; its active flag was synthetic, with no
actual reentrant syscall race claimed.

| Evidence | Run | Raw SHA-256 | Receipt SHA-256 |
|---|---|---|---|
| Sources | `g-process-witness-source-22-1792631942136845500` | `718862b1a58d807982dd50f20c917670f3e18580f831b0efcbf187638d920237` | `509f212947d3c5e4e3115025db1285df392a5bde1397ef64651e8f5fb3bea33d` |
| Before execution | `g-process-witness-start-1792631977111874500` | `e05ed411cea4e84b12df0829b2c07414bfdfb7e8c1b762a99749a387c56f0b01` | `ca402f99b205e7fe4d8c96c8e8903c41931519395dee5a8b19628e2ae83f807b` |
| Result | `g-process-witness-result-1792631982859799200` | `f6e3cc27aabb112c491f589b580339a7b731d2c0f4de430867ca2767f7997b84` | `2ed04a5a96fb6ca81ed2abe71d7112a69387cb50e506a1d446962d72b5ca04ab` |

Evidence/Raw uses unchanged isolated Phase1.1/ext4, native receipts and separate
RO inspect/readback. Two independent agents restored all181 frozen source files,
matched the201-file graph and checked raw API records/receipts. They share the
host/toolchain, not external certification or GitHub approval. They did not rerun
Windows processes or API probes. Rejected unexecuted source/harness drafts remain
preserved, including the reset-on-reinit and shallow-event-snapshot defects.

The trace is instrumented by the component, not an external kernel trace.
Most recorded calls have zero measured duration due to clock granularity; only
order/status are used. Loaded origins were asserted by the exact harness; a
separate loaded-origin manifest was not retained. API error/failure injection,
descendants, handle transfer, actual file-worker pipes, supervisor/Core integration
and target effects are outside these two cases. **NTFS/Core/MIX/FULL remain
NOT_VERIFIED**, including required A05/G01. This is not contract recovery or
permission to retry an uncertain original intent.
