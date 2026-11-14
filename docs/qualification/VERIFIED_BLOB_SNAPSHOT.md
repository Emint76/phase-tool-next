# Existing verified input snapshot lifetime

Software prerequisite only; native file2/bundle/version2 remain unimplemented.
A05/G01/native positive/full REF-MIX/native rollback/release NOT_VERIFIED; FULL
disabled. This checkpoint enables no profile/provider/guard/wire or public tool.

The current Host file2 mechanism already copies its frozen blob into an anonymous
TemporaryFile under the same qualified ext4 blob parent, verifies the complete
copy before opening target, rewinds it and consumes the same FD. Extract exactly
that context into streaming._verified_blob_snapshot and immediately reuse it in
stream_create. Preserve the existing hash_file precheck, fixed2GiB cap, strict
open flags, error codes, source finally-close and snapshot context lifetime.
No new store, capture authority, result model, journal, queue or versioning.

A retained FD to a shared evidence blob is not immutable: another writer may
change that inode. The private copied-and-verified anonymous snapshot is the
existing stronger input role. The helper borrows its FD only within its context;
it authenticates neither caller nor original evidence. Trusted code must derive
the path and expected bytes through existing installation/original/plan checks.
Public candidates choose no FD/cap/trust flag and supply no executable iterator.

Future native integration must keep this descriptor inside the SAME trusted
Linux original endpoint while forwarding on the existing owned pipe/process.
This extraction does not transfer a POSIX FD into Windows, implement a bounded
wire generation, authenticate a producer, prove Windows prevalidation, or
authorize NTFS preparation/spooling. Those design and executable gates remain.

Twelve new regression methods are UNEXECUTED pending retained exact-HEAD CI.
They cover real qualifiedHost publication consuming the same live descriptor,
then separate Core inspect AFTER that descriptor closes, destination collision,
anonymous identity/path replacement, existing
precheck and full copied-byte rejection, growth/shrink/same-length drift, bounded
short writes, capture-write/rewind faults and owned descriptor closure with the
consumer primary exception intact. No native API or admission is simulated.
The preexisting after_hash/at_target_open regression hook remains unchanged.
