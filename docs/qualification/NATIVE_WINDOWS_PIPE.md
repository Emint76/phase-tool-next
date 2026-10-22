# Windows borrowed pipe: bounded control exchange

Status: unselected internal component, not a native Core installation or NTFS
qualification. It supplies the Windows side of the existing executor/IPC role;
it adds no journal, queue, operation state store, recovery or document versions.
Core's original durable intent and receipts remain the operation/evidence owners.

The previous Windows `PipeConnection.poll` did not bound complete send/receive.
The exact tested CPython3.12.10 supports nonblocking Windows byte pipes through
`os.read/write` and `os.get_blocking/set_blocking`. This small framing loop uses
that existing implementation rather than a new overlapped cancellation subsystem.
See [CPython source](https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c)
and [Windows pipe modes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes).

The trusted entrypoint owns distinct exact binary `FileIO` streams, sets their
per-handle nonblocking mode, and forbids concurrent I/O, buffering, close/reuse
and mode changes. The helper borrows strong references and verifies FD/HANDLE,
owner PID/thread, pipe type, byte mode and nonblocking state before I/O. It does
not acquire, duplicate, close or change their flags. Numeric identity checks
cannot defeat a hostile owner closing and reusing the same handle. Peer trust
must come from the entrypoint and retained creation handle, not pipe type alone.

An absolute `perf_counter_ns` deadline covers the complete frame and can be
shared across handshake calls. Remaining time is checked before/after I/O and
finalization; would-block/zero progress uses bounded backoff. Partial progress
never resets the deadline. Protocol, EOF, I/O and deadline errors make the helper
unusable, retain progress/primary diagnostics, and forbid resynchronization or
resending. This bounds ordinary protocol waiting, not OS-call duration, process
lifetime or cancellation of accepted work. A logical seal cannot prove quiescence.

Framing is exactly eight lower-case hex digits, LF, 1..2MiB body, LF; reads consume
only the requested bytes. The limit concerns control metadata, not document
assets. Closed canonical JSON and READY/completion correlation remain the
existing worker validators' responsibility. The dispatcher must mark
possible_dispatch before writing any possible GO byte. An ACK, EOF or even clean
peer exit never establishes an effect receipt or contract success.

## First actual component observations

Product SHA-256 `f157da82d76d2193feea68c95229396f72161870bf2bf36d4e88fdc7120ab802`.
Harness SHA-256 `7e50fa8a553e49de830c2f0cd4b47cb2d5c8a00cdc6c5757b59939d3340cccd6`.
The exact source graph was202 accepted Git files at11d6b58 plus this frozen
overlay. The same checked byte buffers were compiled;28 loaded Phase module
origins/hashes were retained. Unknown Phase imports were refused. This was not
an installed candidate package. The runtime record pins the Python version,
not the executable binary SHA. Windows pipe fstat device/inode were0/0; they
provide no filesystem-style stable identity or hostile-owner reuse protection.

Four fixed stdlib-only owned Windows peers ran sequentially, with no target
filesystem effects, shell, service, descendants or forced termination. Newly
created Local events provided barriers; an existing event would be rejected.
Their framed stdout was separate from DEVNULL stderr. Thus raw records retain
parent errors/waits/exits, but do not claim complete peer primary/secondary
tracebacks. Every positive case required raw exit0 and independent Popen exit0.

| Case | Actual observation | Result |
|---|---|---|
| Binary echo | 524288 bytes, SHA-25633bc8aab40703678c3ebe94d2dd8f2afff285dd901f9234e841e4679f8204fd5;524298 wire bytes each direction | PASS |
| Held reader | 4096/2097162 bytes written;44 would-block; deadline error after256.1ms; barrier released afterwards | PASS |
| Partial header | Exactly7 bytes `0000001`;45 would-block; deadline error after251.9ms; barrier released afterwards | PASS |
| Truncated closure | Exactly12 bytes including valid header and3/16 body bytes; actual `ntfs.pipe_eof` after256.8ms | PASS |

All four retained creation handles observed WAIT_OBJECT_0; raw/wrapper exit0
agreed and each handle was closed once after exit. No primary controller error,
finalization error, source drift, forced cleanup or SafetyStop occurred. All
three negative protocol cases retained their real error, rejected later helper
reuse before I/O, and were never re-sent. No missed window was counted as PASS.

| Evidence | Run ID | Raw SHA-256 | Receipt SHA-256 |
|---|---|---|---|
| Frozen sources | `g-windows-pipe-source-26-1792645392721664300` | `3881061f5c3baa9a4b9a9f26bb38c3f6fdcf025396ee8ef098461456f7af3c6d` | `06b0bdfb743e9aca351861cbc2417fa32c0160de196b6ad5b80413a9534478e3` |
| Before execution | `g-windows-pipe-start-v1-1792645461824820300` | `8364a5fe5db2ca2e940a92cf859d2bb418d2af694d547fa6cf21d8b910309e3a` | `8945a13541f315e36ddb048eee6f673adbb0f388f9d85bea12c6c72b158d4dec` |
| Actual result | `g-windows-pipe-result-v1-1792645469400772100` | `b02a11cdd6690e317413c34df93c5ab0b44f9bec235b46ca1812281fd21887ec` | `5074f41e76fd976da0fd7c40bc63cf3a6ce4a8f7312bd232925ecbed2b6ddadf` |

Evidence/Raw uses unchanged isolated Phase1.1/ext4, native receipts and separate
RO inspect/readback.215 source files were frozen before execution, including
rejected unexecuted alias/reentrancy/finalization and event-ownership drafts.
Two separate agents reviewed source/harness first and independently restored
the215 sources,202-file graph and28 origins afterwards. Both performed fresh
RO Phase inspect/readback of all three packets and verified the actual negative
oracles/exit facts. They share the host/toolchain, not external certification
or GitHub approval. The13 synthetic framing/state regressions are separate from
these four actual Windows cases; their first CI execution remains pending here.

## Integration still required

The current worker still requires exact `PipeConnection`; this helper is not an
automatic replacement. The retained process witness still accepts `SpawnProcess`,
whereas these smoke peers used exact CPython `Popen` creation handles. No witness
compatibility, complete parent supervisor or file-worker exchange is claimed.

Complete the smallest explicit worker/parent seam, trusted original-intent/
installation binding, separate read-only native observer and root-wide scan of
original unresolved intents. Keep the normal Core guarantee guard closed for
missing A05/G01. **Native Core publication/receipt/inspect, versions, bundles,
MIX/FULL, installed native CLI/MCP, rollback and supported release remain
NOT_VERIFIED.** The original qualification cases and repetitions are unchanged.
