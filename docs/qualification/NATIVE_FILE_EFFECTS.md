# Native file effects: exact-source L1 checkpoint

These are small synthetic primitive tests, not installed-package, contract,
MIX/FULL or release qualification. The candidate route remains unselected.
A05 and G06 remain **NOT_VERIFIED**. Ten held-reader checks do not replace
the required 1000 replacements and two independent concurrent readers.

## Preserved negative results

| Revision | Run | Full cases | Result | Observed failure |
| --- | --- | ---: | --- | --- |
| V1 | `g-native-file-effects-1792594415492766800` | 0/10 | NOT_VERIFIED | Legacy class 10 replacement returned C0000022 with an open reader |
| V2 | `g-native-file-effects-1792594740360528100` | 0/10 | NOT_VERIFIED | Class 65 committed; final Python byte read raised EACCES before the DELETE-capable source handle closed |
| V3 | `g-native-file-effects-1792594948754043200` | 10/10 | SUPPORTED, primitive scope only | None observed |

V1 hardlink and owned temporary-name cleanup had completed before the failed
replacement. Its initialized zero IOSB does not override the failing return
status. Read-only audit confirmed the old current bytes and separate new source
were preserved, with no remaining module handles. The raw alone does not
uniquely identify the internal cause of ACCESS_DENIED.

V2 retained a successful class 65 event, stable old-reader identity and bytes,
fresh replacement verification, synthetic flush rejection and real subsequent
flush. Its final observer used Python's CRT sharing while a DELETE-capable
handle was still open. Independent reading after finalization matched the new
bytes. The complete V2 case nevertheless remains failed and NOT_VERIFIED.

V3 moves that independent Python read after file-handle finalization and adds a
fresh full native identity check. The checks with the old reader and a fresh
native reader held during replacement remain unchanged. V1/V2 evidence and
sources are immutable; no original case directory was reused.

## Minimal candidate change

For file replacement only, NativeMutationIO uses `FileRenameInformationEx`,
class **65**, with the 32-bit flags **3** (`REPLACE_IF_EXISTS | POSIX_SEMANTICS`).
ABI assertions require RootDirectory offset 8, FileName offset 20, sizeof 24.
Directory replacement stays forbidden. Class 10 no-replace and class 11 hardlink
are retained. There is no fallback, existence-then-rename, copy/delete or use of
class 66 (BypassAccessCheck).

Microsoft documents that these flags retain old handles on the replaced object
while later opens of the name reach the replacement. This is the intended
physical semantic; it is not CAS or proof of destination preconditions.
See [FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
and [FILE_INFORMATION_CLASS](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class).

Do not infer named-destination preservation from a NoDelete handle when using
POSIX replacement. The observed old reader used share=7. A separate actual
NoDelete destination and external replacement test is still required, along
with ancestor binding, locks, sealed leases and replacement reparse windows.

## V3 observations and build boundary

All ten cases verify exclusive creation, real file flush, no-replace hardlink,
identity-preserving removal of only the original temporary name, closed-handle
rejection before further events, replacement, old/fresh bytes and full native
IDs, namespace-flush acceptance, rejection of cleanup after rename, collision
C0000035 and independent final bytes/identity. Sentinel bytes and identity stay
unchanged; all close-error lists are empty; module handle table is empty.

There are 130 native events: 30 create, 20 write, 50 flush, and 10 each of link,
delete and replace. Exactly ten flush failures are **software-injected** C0000185;
no real flush API was called for those labelled events. The other 40 flush calls
were real and accepted. Failure propagation here is not full G06 equivalence or
power-loss durability.

The recorded base commit is `d9692ccfd0d18ee413a56d2480e0e9d092269804`.
The loaded native mutation bytes differ from that commit and are bound by the
source hashes below. These runs do not qualify that commit's wheel or a later
merge build. Final acceptance must run against the frozen delivered artifacts.

| Source | SHA-256 |
| --- | --- |
| NativeIO | `41654049dc10f1c2db0f74c847f0a36038b49295c4f02582b959b9c7a0dd0a22` |
| Mutation V1 | `3530e17ff7721d257ce5b1e6279cbbf3a4628213f26529008f6baddfa851c764` |
| Mutation V2 | `b1b19f763de31fb3b8077b595207d37ef4c921397266cba5edb53594996c379a` |
| Harness V1 | `3b0253f59df5efa45234f219391a8a6d95da44d343d32d5aaec97c9832a1f675` |
| Harness V2 | `003907d33da943a497e2a01cf58a06acbd4f642253544a7dd6fd30f5dcc43d2c` |
| Harness V3 | `f0ac5b46a6165d44ff64a3b9c1fe731cf3fbe01fcdf0d4871879a788d68e29ba` |

Historical harnesses require their exact private staging layout and fresh owned
case directories. V1 uses `product/mutating.py`; V2/V3 use
`product/mutating_v2.py`. The corresponding bytes are recorded in the private
source snapshots. See [the layout boundary](NATIVE_COMPONENT_STATUS.md#historical-harness-layout).

## Evidence and independent review

All source checkpoints and raw results use unchanged isolated Phase 1.1.0 on
own ext4, `file_create.v2@1.0.0`, with receipt and separate read-only
inspect/readback/hash verification. These saves are Evidence/Raw, not Source
admission. Full raw remains private; this report contains synthetic summaries.

| Revision | Raw SHA-256 | Receipt SHA-256 |
| --- | --- | --- |
| V1 | `126b5741ebb8809d458a9f5281f28e266aaef6ff242264405b460ace167e18c7` | `38157c42a77c69e583a65c88f410d01874ea6e8e00d8430998873b610640ed86` |
| V2 | `94fa5f467d07e3a031d4072babd1cdec749c5b016c2e31d2a9f9f7c4b91db9fa` | `6bbd919839e461bdbe063a4c10257c5c751fcc41a2e7eee2bf91684350af609e` |
| V3 | `1cc2dd8ea3a49704661cd41deb33d375c7c3112a78a8c9b4737b258900b95a34` | `0cbcd43299efa21d5fc328a00fdd3a98fa1400b2a50487f08afe58f99b7cfda7` |

Separate agents reviewed exact source before each run and audited source
snapshots, preserved receipt/inspect bindings and fresh current/sentinel bytes.
The V3 audit reread all ten files and full native identities with zero
mismatches. Independence is on the same host/toolchain, not certification or
GitHub reviewer approval.

The initial candidate CI run 39618064723 at d9692cc failed one architecture
inventory assertion on each Python version, with 852 other tests passing.
The exact native IO module inventory is corrected and native mutating API calls
outside the two reviewed modules are now detected. Runtime admission is
unchanged. Eight dependency-free architecture assertions passed by direct
invocation; full CI must run on the next committed HEAD.
