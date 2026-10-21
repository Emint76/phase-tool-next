# Internal native root coordination — no route admission

`root_lock.py` is an internal, unselected Windows primitive. It does not enable
Windows publication, change the POSIX authority, or qualify any contract. The
six-contract MIX family, FULL, A05, G06 and two-container coordinator integration
remain **NOT_VERIFIED**. Production configuration and historical bindings are
unchanged.

## Physical root mutex

The mutex name is `Global\Phase.NTFS.RootLock.v1.<sha256>`, computed from a fixed
domain separator, normalized volume GUID, native 64-bit volume serial and full
128-bit root FileId. Binding labels, path aliases, run IDs and package versions
do not partition ownership. `v1` is the stable lock protocol domain, not the
candidate package version; a future implementation cannot select another name
and thereby escape existing cooperating workers.

The component first pins the existing grant through the native namespace
barrier. It uses `CreateMutexExW` with default security, no inherited handle,
no initial owner, and only SYNCHRONIZE plus MUTEX_MODIFY_STATE. It changes no
system setting, ACL or privilege. Namespace/type/access errors fail closed;
there is no fallback to another name, session namespace or filesystem lock.
The Windows wait timeout parameter is at most 5000 ms; this is not an absolute
wall-clock deadline. Root pin/finalization still needs the operation-worker
watchdog in the future composition.

The lease is single-acquisition, nonrecursive and thread/PID-affine. A shared
process registry rejects same-thread recursion through a second instance.
`WAIT_ABANDONED` grants OS ownership but raises recovery-required, releases and
closes once, and quarantines this root in that process. It never returns a
usable Phase lease. Release and close errors remain distinct from the primary
error. Uncertain finalization quarantines the root and requires worker exit.

An independent source review found that an already-waiting thread could escape
quarantine in the first unexecuted draft (`149d4292…`). The corrected source
holds one registry barrier through finalization/retirement and ownership
acceptance, and checks quarantine again in `assert_held`. The deterministic
regression injects an OS-call failure through a **fake OS**; it is not native
Windows qualification. All five pure key/handoff tests passed locally.

## Actual L1 evidence

The existing Phase 1.1/ext4 route preserved all 61 owned development files,
re-inspected earlier source snapshots, and measured the resource gate before
the first native run. No reparse fixture was traversed while accounting.

| Executed source | SHA-256 |
|---|---|
| `src/phase_tool/mutation/ntfs/root_lock.py` | `5c18957ec54b555a38fb081557e7aa1c6ac25434728f5858ffd3f62503369178` |
| Pure key tests | `5512dc99291063a4643e17ae87b1695426c4cc59cd10f91f8da10a7240cb17aa` |
| Fake-OS handoff regression | `da0b7d99109da98632ef4b996e4164743bf23f908fce72cd789e8d9f2b665a5e` |
| V1 harness | `ff9fb8d651cfdc118871d3ef1380c771fa0883bc43750d58dd54cdae05b07fa9` |
| V2 harness | `50ad82cc474b527f1260180e142a5c920d78a13c070c2e7a11fa2a611408ec8c` |

| Binding | Value |
|---|---|
| Source checkpoint | `g-root-mutex-source-1792601069232863000` |
| Checkpoint SHA-256 | `15297af5606d9506530dc56ab995b27cb6a94f395e62609e8f7aa8cf8ce9131c` |
| Checkpoint receipt | `sha256:706080743ed3e6a185ecd34b82ccee13b1dadd9336028bd2c72ebcb3c90f9a9d` |
| V1 run | `g-native-root-mutex-1792601126879551900` |
| V1 raw SHA-256 | `acc530b9f39a5b27eb74934ad2c2a75d552ad4a1a610e4b3d42cf49aff736115` |
| V1 receipt | `sha256:472b99f76e3518764c17eae42eb46d3b2da6faadb2e3c7812f1c621ea5a5bbf5` |
| V2 source checkpoint (63 files) | `g-root-mutex-v2-source-1792601678344991500` |
| V2 checkpoint SHA-256 | `27d880e0bb649659e36ff0211aee8dd8fd1c7fc825d320f74b97e6fc3045f3d2` |
| V2 checkpoint receipt | `sha256:fde931400b21f71eab479dc04789837eb7efee71f584ece060b10147a66ef481` |
| V2 run | `g-native-root-mutex-1792601735460774300` |
| V2 raw SHA-256 | `5c130c0e4a8ee1a523ce2906ef9b491dd2270a6b014f27af041cb3d20cbafbfc` |
| V2 receipt | `sha256:dc5e076f7baf82ad935f6a064380f6d3e725b5ae90677f67c69bf1aba04b78bf` |

All four records have native receipt, separate read-only Phase inspect and exact readback.
An independent agent decoded all checkpoint/execution source bytes, audited the
full raw and independently reread the existing root/sentinel. Independence is
limited to a separate agent on the same host/toolchain; this is not external
certification or GitHub reviewer approval.

The observed single-host, same-user, non-elevated Windows L1 results were:

- Eight different process IDs, each with 100 barrier-synchronized acquisitions;
  800 critical sections, exact shared counter transitions `0→800`, and no shared
  owner violation. All create/wait/release/close events and worker exits checked.
- 100 real timeout results while a separate holder owned the mutex, followed by
  100 successful handoffs after its confirmed release.
- Ten intentional deaths with a surviving reference handle: actual
  `WAIT_ABANDONED`, fail-closed error and subsequent quarantine rejection.
- Ten deaths without any surviving handle: a newly created mutex and
  `WAIT_OBJECT_0`. The object forgot the crash; no target mutation or recovery
  authorization followed.
- Same-thread recursion and wrong-thread operations rejected before native calls.
  Normal workers exited zero; only the 20 intended crash holders had nonzero
  exits. No remaining native file handles, outside effect or sentinel change.

The V1 timestamp oracle has a retained limitation: 711/800 critical intervals
have zero recorded duration because `monotonic_ns` uses GetTickCount64 on this
Python 3.12 host (15.625 ms resolution). These timestamps only show no observed
overlap; they cannot resolve shorter overlap. Shared owner/counter/native-event
results remain, and V1 raw is unchanged. A fresh V2 uses `perf_counter_ns` with
per-process clock manifests and the same repetition counts. V2 completed all
800 acquisitions, 100 timeout/handoffs and 20 crash cases. All 800 critical
intervals have positive durations (minimum 1,032,900 ns; maximum 2,510,500 ns)
with no observed overlap; the shared owner/counter and native event checks also
pass. This is a clock-resolution-bounded observation of the exercised workload,
not a proof about every possible future interleaving.

Python documents `perf_counter` as system-wide on Windows since 3.10. This host
reports QueryPerformanceCounter and 100 ns resolution. Product native API event
timestamps still use `monotonic_ns` for status/ordering and are not the V2
critical-interval oracle. [Python 3.12 time documentation](https://docs.python.org/3.12/library/time.html#time.perf_counter)

The measured initial combined logical usage was 160,621,883 bytes. The reviewed
36 MiB pending allowance covers a checkpoint up to 2 MiB, raw up to 4 MiB,
existing archival peak `5A+1 MiB` per record, and synthetic fixtures up to 1 MiB.
The combined 256 MiB small-stage gate and 32 GiB campaign cap remain unchanged.
C: had 29.338 GiB free (31.501 GB), S: 203.094 GiB. Reported ext4 `statvfs`
capacity does not represent additional physical space independent of C:.

## Required durable coordination before IPC admission

The mutex is not a durable intent index or a recovery decision. Once the last
handle closes, the Windows object disappears. An ext4-only flock also cannot
cover a Windows syscall that outlives its Linux coordinator. Both mechanisms
must be composed, with one installation-owned pending-root index for every
alias/coordinator of the same physical root.

Required order under one stable ext4 coordinator lock (separate from the
replaceable head file):

`durable intent/frozen inputs → immutable PENDING entry → durable head → dispatch
→ original worker completion → independent inspect → durable receipt
→ immutable FINALIZED entry → durable head`.

Entries must bind generation, predecessor digest, physical root/grant/composition,
intent, plan and frozen inputs without digest cycles. Head replacement requires
the expected predecessor. Missing/corrupt/unknown-schema state and any durability
or finalization error block dispatch. A missing head of an existing index cannot
be treated as a fresh IDLE root. FINALIZED means an established outcome, including
an established failure without effect, and does not mean success only.

The installation must reject overlapping ancestor/descendant root grants or use
a separately reviewed common coordination domain. Distinct root IDs alone do
not serialize overlapping trees. The mutex helper does not implement admission.

Concrete integration obligations identified in independent architecture review:

| Source | Required change, not yet implemented |
|---|---|
| New operational index module/schema | Immutable transitions plus checked mutable head on qualified ext4; no weakening of immutable run evidence |
| `core.py` | Pending-root gate before idempotency/reuse; durable dispatch disposition; finalize index only after outcome/evidence/worker proof |
| `mutation/broker.py` | Lost IPC response after possible dispatch remains indeterminate even with zero received effect receipts |
| New native executor/IPC | One-shot fenced lease bound to root/index/generation/intent/plan/frozen/grant/composition; status-only reconnect; PID plus process creation identity/handle |
| `evidence/__init__.py` | Preserve immutable artifacts and bind index transition references; reuse durable primitives only under proven ext4/pinned-parent conditions |
| `inspection`, `recovery.py`, continuation modules | Exact new bindings; original-operation investigation without automatic replay or new-run escape |
| `installation.py`, new contracts/descriptors | One trusted index binding across aliases/coordinators; native root identities, overlap admission and exact implementation selection |

Current Core paths that continue after `no_effect_observed`, `archived_not_published`
or `published_not_finalized` cannot by themselves authorize a new native dispatch.
Likewise an empty effect-receipt list after a lost IPC response cannot be mapped
to rejected/failed-no-effect. A separate persistent `dispatch_may_have_occurred`
disposition is required. Historical POSIX bindings and semantics stay intact.

Crash qualification must cover every durable transition, IPC dispatch and lost
response, native commit, worker completion, receipt and final head update. A
stale command after a new generation and two coordinators attempting different
index bindings need explicit negative tests. None is implied by this L1 mutex
result. Installed native CLI/MCP, lifecycle, rollback and release remain pending.
