# Native bundle input prerequisite

This is an **unselected data-only prerequisite**, with no installed selector,
authority, worker, NativeIO, target effect, receipt or qualification. The full
bundle_create.v1 Core execute → independent native inspect slice is still
required. A05/G01/G02 and the full native contract family remain NOT_VERIFIED.
FULL stays disabled. This component does not enable an NTFS storage route.

## Reuse and necessity

A bundle contains an existing canonical manifest and several frozen blobs.
A single file2 stream cannot express the existing bundle limit of 4 GiB total.
The private bundle-stream module wraps the existing file2 receiver and verified
anonymous source for each member occurrence. It does not create a new gate,
process, spool, evidence journal, queue or document-version store.

The existing bundle parser remains the owner of manifest canonicalization,
membership, aliases and limits: manifest/request 1 MiB, 1024 members, 2 GiB per
member, 4 GiB aggregate, depth 32. No published descriptor or old wire is changed.

The outer header is separately bounded at 2 MiB because a legal manifest does
not fit the unchanged 512 KiB file2 leaf-frame bound. It binds the complete
canonical manifest, context and outer channel. Domain-separated member channels
include the outer-header digest, ordinal and path. Equal content at two paths
still has two separate one-shot source/receiver states.

All members complete their first SHA/length/END passes before aggregate READY.
The fixed caller must exhaust the sender generators after END; receipt of an
END token alone does not prove producer exhaustion or process exit. The source
then rewinds every retained SAME anonymous snapshot FD. Only the existing
parent's single GO may authorize later physical execution. Ordered replay
reuses the existing per-chunk first-pass vector check before releasing bytes.
Aggregate END/finish yields data facts only, without authenticating a process,
Windows namespace or physical result. Actual EOF, process ownership, deadlines,
historical conflict checks and final evidence stay with the existing Core/parent.

Any malformed frame, invalid state, failed rewind or early generator close
prevents reuse. Retiring a source blocks outstanding lazy/paused generators.
The factory attempts each previously entered context's close once, in reverse
order. Failed __enter__ owns its internal cleanup; it is never exited again.
All essential closes run before diagnostic formatting. Cause/context/group
diagnostics preserve acquisition and cleanup errors along with the initial
failure; formatter faults are explicitly marked incomplete, while in-process
original exceptions and the initial cause remain retained. No failed cleanup
or diagnostic construction is recast as positive finalization.

## Explicit resource boundary

At most 1024 anonymous snapshot FDs coexist, plus active acquisition/control
overhead. Read-only RLIMIT/current-FD observation is not a reservation; later
EMFILE remains a terminal acquisition error with cleanup. No limit or policy
is changed.

The existing snapshot helper can read up to its fixed 2 GiB cap before rejecting
a declared-length mismatch. Therefore a malformed last blob can coexist with
preceding valid snapshots: **up to 6 GiB snapshot payload**, not just the
declared 4 GiB. Future installation qualification must additionally budget
filesystem allocation overhead, original frozen blobs, target staging and
the required free-space headroom. These values are not a resource admission.
The chunk-vector estimate is at most 17408 SHA-256 entries; it is not an RSS
measurement. Native full-size throughput and deadline sufficiency are unverified.

## Ordinary verification and next integration

The accompanying tests are intended for ordinary Linux CI: actual existing
bundle freeze, anonymous snapshots and FD rewinds; zero-length and repeated
content; hostile/early/duplicate/trailing frames; late replay corruption;
acquisition/rewind/finalization faults; all-closes and initial-error preservation;
large legal outer metadata and numerical existing-limit bounds. Modeled faults
are labelled. A successful input test cannot qualify a native installation.

Next work must bind this stream to the exact original Core bundle intent and
actual RO member bytes, a new immutable native mechanism/contract binding,
one handle-relative directory staging effect with one NOREPLACE rename,
an independent complete-tree observer, exact ownership representation and
terminal proof. Existing V7/three-role history bindings remain immutable; a
future common domain needs an explicitly reviewed next composition. Bundle v2
prepared continuation and version2 objects remain distinct required work.
No parallel versioning system or coordination journal is justified.
