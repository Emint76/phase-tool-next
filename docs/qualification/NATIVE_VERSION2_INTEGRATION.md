# Version2 native integration candidate

This candidate connects `publish_new_version.v2@1.0.0` to the existing Phase
Core through a fixed experimental Windows worker installation. It does not
qualify a supported NTFS deployment or change ordinary startup admission.

The contract remains the owner of version semantics. Its content-addressed old
and new objects are published before the current file is replaced. Equal old
and new content may share one object. Core continues to own captured candidate
inputs, intent, plans, execution evidence, receipts and recovery decisions.
The native path contributes object identities, bounded transport, owned worker
completion and observations; it introduces no second journal or version store.

Generation 1.5 binds exactly two ordered native grants: `current_root` and
`objects_root`. Only the code-selected experimental Version2 launcher accepts
this generation. The ordinary installation selector continues to reject it.
The new candidate registry retains prior package bindings and adds native
evidence schemas to the unchanged Version2 contract document. Existing
published registries and descriptors are not edited.

The candidate handles diagnostic failures after resource adoption and attempts
cleanup before formatting errors. Unknown mutation outcomes seal further
mutation and remain indeterminate; there is no automatic rename retry or
deletion of possible orphan objects.

Source181 preserves the initial reviewed implementation, test sources and review
preimages; later corrections retain their own exact source/build identities.
Source review is not executable acceptance. Portable protocol and
failure tests use explicit substitutes and cannot establish real NTFS behavior.
The Linux-only Host/Core tests must execute on Linux, rather than count as
Windows passes. The full physical Windows contract family, failure/recovery scenarios and final
artifact acceptance remain separate required work. The isolated Version2 result
below does not complete those requirements.

A05 and applicable G01 remain `NOT_VERIFIED`. No production Phase or Hermes
configuration changes, supported release, merge or deployment are authorized
by these results.

## First physical Version2 result and correction candidate

The exact `ee99d950046af2f44921766536bcd19d9d74385c` build passed ordinary
Linux CI. Its first physical Windows Version2 operation did **not** succeed.
Both immutable content objects were created and flushed; the current file
remained at its previous 32 bytes. The final `NtSetInformationFile` class 65,
flags 3 returned `0xC0000043` (sharing violation). The current reader's own
NoDelete lease conflicted with that replacement.

Core retained an `indeterminate` receipt with `recovery_required=true` and
`retry_disposition=forbidden`. A separate inspect read that same receipt; its
successful inspection command is not a successful publication. The staging
file and both content objects remain preserved. The concrete worker's retained
creation HANDLE reported wait 0 and exit 0, and its owned handles, streams and
mutexes finalized. Worker termination does not make the effect successful.

The original collection contains 14 files / 47,186 bytes; its serialized
SHA-256 is `ac5d0f6673c1bf69e4c5ef1bd845cfa058f660556870f5d2357b61c6b03b2244`.
Receipt digest:
`sha256:707b0f3d7acc2bc8fa60fa32d4975decd09538f970577f9e656aa1c2fd1d5471`.
Two separate agents independently checked the originals, byte observations,
bindings and process witness on the shared test host/toolchain. This is not
external reviewer approval or environmental qualification.

The correction candidate explicitly opens only the Version2 current reader
with DELETE sharing. It retains the old **object**, the ancestor NoDelete
pins, both existing Phase root mutexes, identity/data/name checks, single
replacement attempt, flush and independent observations. Other readers retain
their default NoDelete mode. No close-and-blind-rename fallback is introduced.

Profile revision 3 and its new registry preserve the prior descriptors and
registry entries byte-for-byte. The unchanged provider artifact keeps its
implementation version 2.0.0; the selected wheel and complete artifact graph
identify the physical code change. Coverage and conformance remain empty.
This revision covers cooperating Phase operations using the same root mutexes.
It does not reserve the current leaf name against a noncooperating external
renamer or provide atomic compare-and-replace against the old NativeID. Such
an external race may be undetected. Those stronger properties remain
`NOT_VERIFIED`; this correction must not be represented as qualifying them.

The corrected CAC80 build subsequently passed one real Windows Version2
experiment with a separate synthetic fixture, followed by fresh independent
inspection and two independent evidence reviews. See
[FIRST_NATIVE_VERSION2_RESULT.md](FIRST_NATIVE_VERSION2_RESULT.md) for exact
build, run, receipt, object hashes and retained worker-completion evidence.
The old failed write was not retried, recovered, erased or reclassified.
Bundle integration and Windows failure/recovery, installation and rollback
acceptance remain unfinished; this is not qualification of a supported route.

The first affected portable test run recorded ten passes and four errors,
rather than a passing correction: two test doubles lacked an explicit
`assert_object` spec, and the new profile package omitted its existing schema
and vocabulary bindings. The revision 3 candidate retains
those three dependencies from revision 2, with a recomputed package and
registry digest; revisions 1 and 2 remain unchanged. The two test doubles use
an explicit interface spec. The four affected methods subsequently passed;
the ten earlier passes were not rerun. These are portable/model results, not
native replacement acceptance. The original failing output remains retained
separately. Exact-HEAD CAC80 CI subsequently passed both 1907-test suites
(1906 PASS and one unchanged SKIP) and installed resource checks; the separate
physical result above is limited to that recorded experiment and wheel.
