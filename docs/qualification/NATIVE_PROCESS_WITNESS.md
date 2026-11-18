# Retained process witness

This internal unselected helper observes an exact `SpawnProcess`, or exact
Windows CPython3.12.10 `Popen`, creation handle retained by its trusted owner. It queries PID/times, waits and reads exit code;
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

## Current exact-Popen extension

Current helper SHA-256
`db9b9528c38c2ea1111e9c764e03e7b1b433ea732a3e4b3ef5c806cc9f9ca4db`.
It adds one closed branch to the same witness; the original SpawnProcess sentinel
and API/wait path remain. The Popen branch requires the exact CPython3.12.10
Windows class and its actual original `subprocess.Handle` object, not an
arbitrary PID, integer HANDLE, sentinel wrapper or subclass. It retains strong
owner/Handle references and checks object identity, closed/child-created flags
and PID before API use. The trusted owner must still forbid concurrent mutation.
This is not an installation or executable-artifact verifier.

Twelve first synthetic controls passed0.033s on Linux CPython3.11.16, with no
errors/skips/timeout/drift and empty fixtures. Exact205 source files=203accepted
02704 sources with witness replacement plus two test files;31 loaded origins
were recorded in the actual test process. Test SHA-256
`8dadeda6518592cc3d6784fc6ccd2a324be530ed5a15ee772440cb6ad0be90e9`.
The facades replace Win32/owner boundaries deliberately; their individual fake
API arrays are not saved, so the retained transcript plus frozen source
assertions establish the tested oracle. They are not actual HANDLE observations.

Result `g-popen-witness-pure-result-v1-1792653645248078200`: raw
`e25c446a88b2bb20a054958a2e7e705a23338607f11ee510d121aba6bc0dae3e`, receipt
`d47a31a713fae1b43af76a53816acf4881943762e331aa2ecf72ec4662e13b05`.
Source30 `g-popen-witness-source-30-1792653620860271800` and START
`g-popen-witness-pure-start-v1-1792653635550041300` precede it. Both separate
agents restored252 sources, verified205 staged bytes/31 origins, the exact
payload and12 oracles, then freshly checked all three through official Phase RO.

Two separately reviewed first actual Windows Popen observations subsequently
passed on CPython3.12.10 AMD64 with a non-elevated current token. TOKEN_QUERY
and token-handle close succeeded; no rights/policy changes. The fixed synthetic
children perform only a READY/exit barrier over pipes and exit; they never open
a target, run Phase publication or create descendants.

| Expected child exit | Before GO | After GO | Popen comparison | Finalization |
|---|---|---|---|---|
|0 | WAIT258, exit=false, code=null | WAIT0, exit=true, code0 |0 | seal/streams/creation HANDLE once |
|259 | WAIT258, exit=false, code=null | WAIT0, exit=true, code259 |259 | seal/streams/creation HANDLE once |

No primary/finalization errors, forced termination, source drift or held unknown
owners were observed. The original creation Handle object remained identical.
Full203 accepted Git files plus witness replacement were checked, and29 actual
loaded origins/lengths/hashes retained from the same executed byte buffers.
The runtime record includes interpreter and subprocess source hashes. This was
a source overlay, not an installed accepted Windows package or parent bootstrap.
Current WindowsPipeFrames is used only for this small barrier; the four earlier
pipe fault cases do not automatically qualify a changed helper.

Harness SHA-256
`172c0509c9ac72e820528a7e952960e0d20a6db2447fce301682864d3309a4a0`.
Source31 `g-popen-windows-source-31-1792655061973750100`, START
`g-popen-windows-start-v1-1792655071683338800`, result
`g-popen-windows-result-v1-1792655082359460000`: result raw
`092d397fd384cae34ba79ecafc78d46e58e70a96d919d98b212020436194f76e`, receipt
`3b81e801d5af5cd81ecef3d8b1701555c2d854b56d88d64c64ae56ba37f3a707`.
Unchanged isolated Phase1.1/ext4 retained all packets with native receipts and
separate RO inspect/readback. Both separate agents restored254 source entries,
matched203 Git sources and29 actual origins, checked the raw API sequences and
all six source/START/result bindings across pure/Windows stages, and freshly
inspected those records. Runtime bytes matched the retained hashes. This shares
the host/toolchain, not external certification or GitHub approval.
Rejected unexecuted harness/source versions remain
retained, including checked-source-buffer, early-exit fact and negative owner
lifetime corrections. Unknown failure owners are held in harness memory through
the archive attempt; interpreter finalization later may close a HANDLE without
establishing exit. This adds no persistent coordinator or product recovery path.

Peer stderr is DEVNULL, limiting diagnostics. API traces are component
instrumentation, not independent kernel tracing. The two actual cases do not
test API failure injection, hostile owner mutation, process descendants, target
IO, full worker pipes, native Core/CLI/MCP/inspect, contract recovery or rollback.
A05/G01/MIX/FULL and supported release remain NOT_VERIFIED. No new durable
intent, queue, journal, provider selection or qualification exception exists.

## Historical SpawnProcess implementation and actual observations

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
