# Candidate all-native NTFS authority: oracle mapping proposal

Not implementation acceptance. No new Phase route is qualified by this document.
The original program and failed/missing cases remain unchanged.

## Why the bounded directory publisher may be insufficient

H01/H02 and H03B establish a viable no-replace directory primitive. Literal
native Windows SYMLINK fixtures, however, cannot currently be created by the
unprivileged host using either documented API: both return 1314 for file/dir.
The actual Linux-created links have LX tag 0xA000001D, junction has 0xA0000003.
No tag 0xA000000C exists in the two inspected owned synthetic campaigns.

This does not establish a product defect or make a different backend impossible.
The latest human instruction permits a reviewed change of platform test mechanics
while preserving the tested property. Independent review conditionally admits
an all-native, tag-independent namespace barrier as a candidate alternative.
The literal historical native-SYMLINK fixture case stays NOT_VERIFIED.

## Required property, unchanged

No managed operation traverses a reparse object, mutates an outside sentinel or
verifies a result after a failed namespace binding. All required root, parent,
leaf, archive/version-object, readback, inspection and recovery paths are covered.
No claim blocks an administrator or all unrelated external writers.

## Proposed complete barrier

1. NTFS paths are resolved component by component using native RootDirectory
   handles, OBJ_DONT_REPARSE and FILE_OPEN_REPARSE_POINT. Every returned handle
   rejects FILE_ATTRIBUTE_REPARSE_POINT without interpreting its tag or target.
2. Subsequent data operations use those handles, never a reopened absolute path.
   Every new name resolution repeats the full barrier. Rename/link/replace use
   pinned source and parent handles; create uses actual exclusive disposition.
   Existing opens must not truncate before reparse/type/identity checks.
3. Reparse/identity assertions occur before/after significant operations.
   NoDelete sharing prevents other rename/delete but **does not freeze EA or
   attributes**. Metadata conversion races therefore require explicit tests.
4. The host component derives permitted locators from exact contract/effect leases
   and installation grants. There is no arbitrary filesystem-command service.
   Unknown IPC outcomes stop mutation until independent original-identity inspect.
5. A source audit enumerates all NTFS I/O. Any remaining Python Path/open/stat,
   recursive listing or Linux NTFS leaf open is an unresolved obligation, not an
   allowed shortcut. Core evidence/preparation stay on own qualified ext4.

The proposed generic reparse oracle combines the unconditional implementation
barrier, documented all-reparse Native API semantics, real junction/LX cases at
every path position, metadata-conversion races, rename races and outside-sentinel
checks. It must be reviewed against exact code and reached schedules before
replacing the old literal test for the new backend's property coverage.

## G06 must have its own physical proof

Candidate A is a real NtFlushBuffersFileEx(flags=0) on the correct native pinned
directory handle. Microsoft describes normal flags as data+metadata flush with
synchronous IRP_MJ_FLUSH_BUFFERS; FILE_DATA_SYNC_ONLY is explicitly unsuitable
for directories. The new probe establishes only request acceptance and identity.
It does not yet establish equivalence or failure propagation, and claims no
absolute power-loss durability.

Candidate B retains Linux directory fsync only if a separate dual-identity
correspondence proof makes the exact descriptor independent of untested native
symlink interpretation. Matching path text and NoDelete pins are insufficient.
Candidate B must not be accepted as a workaround if that proof is absent.

## Implementation implications under consideration

- Keep Core lifecycle and ext4 evidence; add exact native execution context,
  six new contract generations, versioned preparation/continuation proofs and a
  composite artifact binding. Old published bindings/resources stay unchanged.
- Native TargetAuthority requires a code-owned opaque-handle I/O adapter or new
  native physical mechanisms; a Windows handle must never be passed to Linux
  os.write/fsync/fstat. Arbitrary provider/callback injection remains forbidden.
- Native streaming must preserve verified frozen input before target creation.
  One bounded option is a no-mutation verification pass over immutable ext4
  snapshot bytes, storing per-chunk hashes, followed by the actual stream with
  checked chunks/offsets. Payload goes directly to NTFS; no canonical post-copy.
  Limits remain 2 GiB/file, 4 GiB/bundle, 1024 members and existing version caps.
- Existing small version semantics, archive ordering, exact preconditions,
  content-addressed links and atomic current replace remain unchanged. Native
  bundle ownership/identity needs its own representation and inspector if it no
  longer uses producer Linux inode. That is a new version, not a relaxed verifier.
- Root identities and idempotency must bind native volume/FileId and immutable
  grant/composition; a random session nonce never changes durable request identity.
- Thin CLI/MCP adapters select the trusted installation. They do not implement
  canonical writes, validation or recovery outside Phase.

Next acceptance gate: actual native directory-flush probe and exact-code native
barrier review, then complete adversarial mapping. Missing implementations,
untested races and historical gaps remain NOT_VERIFIED.
