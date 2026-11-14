# Closed worker/pipe seam: unselected implementation

This changes the existing fixed worker, without a transport framework, service,
bootstrap CLI, provider selector, journal, queue or document-version mechanism.
Core, contracts, installation and the qualification guard remain unchanged.
Original durable intent still must precede any real worker; no caller-supplied
grant/content/path becomes authoritative through this internal function.

The exact `PipeConnection` path remains. A second exact-type branch accepts
`WindowsPipeFrames`; subclasses and duck-typed peers are rejected. Both paths
share existing context/grant/READY/GO/completion validation and the single
`execute_file_create` call. Content remains <=1MiB, GO <=4096bytes and completion
<=512KiB. The framing consumer can only lower the existing2MiB control bound;
an oversized GO header is rejected before body read/allocation, poisoning frames.

Framed READY/GO uses one absolute30s handshake deadline, rechecked after GO
validation immediately before the effect. Completion has its own bounded send
window after physical execution. Neither deadline bounds a filesystem syscall
or proves cancellation. A valid frame still grants no effect success/exit proof.

Finally attempts close once for owned MP transport or seal once for borrowed
framing. Its entrypoint owns the streams' physical close; parent owns retained
process-exit proof. A poisoned channel is never revived to deliver diagnostics.
Primary operation, failed transport/serialization and finalization remain
separate. Even a completion carrying no error keeps worker_exit_established=false.

## First actual synthetic control run

Worker SHA-256 `d97e096525425252d386b32807b72f049a73b5950fc82f8d5513d81485149540`.
Pipe SHA-256 `c9c313c84874215f66bd64482052d2ddec314a2eaa4a207d029e463f174d4a23`.
Tests SHA-256 `b9e66f4caa4f3cfe669e9c00c812a494651803b1000620cde454072b89c7f8a0`.
The exact accepted203-file b4e8 wheel graph plus two overlays and three test
files produced206 staged files in owned ext4.237 own source files, including
rejected unexecuted worker/fixture/harness drafts, were frozen beforehand.

On Linux CPython3.11.16, the first nine new methods passed0.009s, without skips, failures, errors,
expected failures, timeout, truncation or source drift; fixtures stayed empty.
Old18worker/correlator cases were not replayed locally. Five new receive-cap
unit cases are source-reviewed and await their first next-HEAD CI execution.

| Control oracle | Exercised assertion |
|---|---|
| READY/GO/effect/completion | One effect, exit flagfalse, same handshake deadline and separate completion window |
| Wrong/noncanonical/oversized GO | Zero effects; oversize poisons and diagnostic send fails separately |
| Deadline after GO validation | Zero effects, retained go_deadline error, separate diagnostic window |
| EOF/timeout before GO | Zero effects, only READY sent, original and poisoned-send errors retained |
| Physical-step error | Error completion, no effect receipt or success inference |
| Send/diagnostic/seal failures | Distinct primary/transport/finalization, seal attempted once |
| Wrong type/subclass | Rejection before transport or effect |

The test object has the exact framing class but deliberately fake per-instance
I/O; the physical step is mocked. There were no Windows API, real pipe, target
file, Core receipt or process-exit qualification operations. Evidence is executed
assertions/transcript plus source provenance, not a full raw peer-state or wire
trace.37 module origins/hashes were captured in the actual test process while
executing the same checked byte buffers. Unknown/preloaded candidate imports
were refused. A separate RO process rehashed all206 staged files and empty
fixtures. This is source-overlay verification, not installed-package acceptance.

| Evidence | Run ID | Raw SHA-256 | Receipt SHA-256 |
|---|---|---|---|
| Sources | `g-worker-stdio-source-28-1792649828483247100` | `37f52433fc217a79768d49cd939d432d19fed547a9090308074f6d0033e89bf7` | `afbcbfb88d39550e3a1d9faa5f378fa10d0a55f91ebe3cf4720692965dde0b1d` |
| Before execution | `g-worker-stdio-start-v1-1792649861787767100` | `6385640d331731f285b7448cb3166cd2af6cbd65d271900a45ca58b3e263c7f2` | `4ab475448da934d12e97b75c60fd8419105450b60e6de1141b2c3b04c2b7f501` |
| Result | `g-worker-stdio-result-v1-1792649871078338600` | `850ef74908ba7f99ba73b0422a2e336a960a4911ff5d3b466198329b1f2df6d9` | `675593ff8983ef7178de8194c7832e53b7dda964d8898bbfababa85b2e38179f` |

These Evidence/Raw packets use unchanged isolated Phase1.1/ext4, native receipts
and separate RO inspect/readback. Separate agents reviewed exact source/harness
before execution, then restored237sources/206stage files/37actual loaded origins,
checked the nine oracles and performed fresh Phase RO source/start/result
readback. Same host/toolchain, not external certification or GitHub reviewer approval.

## Remaining composition

No real file-worker pipe exchange, Popen bootstrap or complete parent is provided
by this seam. The witness still accepts SpawnProcess; no Popen compatibility is
inferred. The earlier four real Windows pipe-only cases bind historical helperV3;
they are not automatically transferred to this changed helperV4 or whole worker.

Next needs trusted closed original-intent/installation binding, parent/bootstrap/
retained-exit observation, separate native RO observer and root-wide unresolved
original-intent guard. No new operation state store is required. **A05/G01,
ordinary native Core publication/receipt/inspect, version/bundle, MIX/FULL,
installed native CLI/MCP, rollback and supported release remain NOT_VERIFIED.**
Do not weaken the normal Core guard to obtain an end-to-end demonstration.
