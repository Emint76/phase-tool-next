# Experimental native bundle1 through Phase Core

Status: one real isolated Windows create and separate inspect passed independent
review on the exact build recorded below. A05, applicable G01, native boundary,
failure/recovery coverage and supported NTFS qualification remain NOT_VERIFIED.
Ordinary startup/production guard is unchanged. No production installation or
Hermes profile is changed. This result does not authorize a supported release.

The earlier real native file1, file2, Version1 shared history and corrected
Version2 results use their separately recorded builds. Bundle2 remains unfinished.

## One existing lifecycle

The implementation connects the existing Core/EffectBroker native dispatch, original
intent reader, frozen bundle input, root coordination, owned Windows process,
EvidenceStore, standard effect receipt, terminal proof and separate inspect.
There is no additional journal, document history, operation queue or Core.

`bundle_create.v1@1.1.0` is a new exact native binding with unchanged v1
representation/semantics and recovery=none. Its package SHA256 is
`6881c1d18034a71723df68873cf7c9762d92bd456cc586614de561a6282f6743`.
The new `mechanism.bundle_create_v1@1.1.0` SHA256 is
`bb8dc72d3b6ff3d03352b3e033c714d6256d289cb452c81d03a66d7b930fee1d`.
The historical mechanism explicitly uses Linux renameat2; its descriptor and
all historical contracts/registry rows remain unchanged. The native descriptor
honestly uses a Windows directory NOREPLACE publication point and provider
binding. It is absent from the Host executor allowlist.

Only the fixed private bundle launcher can supply the exact experimental
admission. Manifest generation1.6, channel1.5 and worker1.4 extend existing
owned framing and consumed GO, not a new service. The candidate profile has
empty provided guarantees/conformance and cannot claim qualified coverage.

## Necessary bundle semantics

- `bundle_execution.py` validates a distinct immutable manifest projection and
  ordered member occurrences. The original reader checks the complete frozen
  member bytes on ext4. Existing `bundle_stream.py` supplies snapshots, first
  pass, actual rewind and checked replay within one exchange and one GO.
- `bundle_effect.py` exclusively creates one stage, writes unchanged owner1.0
  and manifest, creates every member including empty files, checks their bytes,
  flushes and verifies the entire stage, then issues one native directory
  rename with replace=false. It retains staging after failures and never uses
  copy/delete fallback or automatic retry.
- `bundle_observation.py` reads through pinned native directory/file handles,
  compares exact membership and listing IDs with opened objects, verifies each
  member and repeats membership checks. A compact member-byte/identity digest
  keeps evidence bounded. Fresh inspect physically traverses the bundle again.
- `NativeIO.directory_stat_identity` duplicates the same pinned HANDLE, obtains
  an actual CPython3.12.10 fstat and compares its complete device/128-bit inode
  with independent native FileIdInfo. It does not manufacture POSIX root IDs.
  Only the duplicate transfers to CRT; unknown acquisition/transfer/close is
  retained and forbids successful finalization. Owner1.0 need not be changed.
- The transient bundle handle scope attempts every essential close once and
  preserves body and close failures explicitly. It is needed because ordinary
  exception context is not serialized by the existing bounded diagnostics;
  it is not persistent operation coordination.

The existing limits stay 1024 members, 2 GiB/member, 4 GiB total, depth32 and
1 MiB request/manifest. Snapshots may need declared total plus2 GiB (up to6 GiB)
and up to1024 snapshot descriptors; existing source preflight remains required.
The fixed30-second experimental exchange is not a verified full-range Windows
performance envelope. No file-count or size limit is raised to get a PASS.

## First new-head CI collection result

Commit `8b3bca7f2aacfd639822c3696ed95129b9b6f89a` was pushed after canonical
source/result retention and independent restoration. CI40808474469 failed during
collection on both Python3.11/3.12, before any test bodies: the new failure-model
module used a top-level sibling import although `tests` is a package. The prior
local unittest invocation had added the tests directory to its path and masked
this error. The negative CI log is retained; resource checks were skipped.

The correction changes only that import to a relative package import. A fresh
standard Python package-aware collection resolved the real `tests` package and
helper and collected all four failure-model methods without executing them or
injecting a tests-directory path. This does not claim a pytest collection PASS:
pytest was absent on the host, so at that point the next exact-head CI still
had to verify pytest and full regressions. That later result is recorded below.
No package, product guard or environment setting changed.

## Retained correction history

Source-only review found and corrected a misspelled existing parser seam,
unproven DuplicateHandle ownership, loss of primary/close errors and an exact
byte count after an indeterminate write. Uninvoked preimages/findings remain in
private evidence. Further review caught a frozen-provider artifact change, a create/trace handle
ownership gap, lost worker exception references, stale child-module pins and an
inapplicable Host-root qualification at the bundle freeze boundary. The frozen
provider is restored byte-for-byte; the new bundle provider owns only its closed
constructor, observations, execution and checked preparation capture. That
capture calls the existing freezer after repeating the existing installation's
ext4 preparation/evidence checks; ordinary Host freeze/guard stays unchanged.

Regression sources cover handle/trace ordering, primary/transport/close failures,
indeterminate metadata readback with a lower bound, full128-bit identity,
empty/repeated members, bad END frames, historical profile resolution and
default-guard refusal. The first portable execution on Windows ran20 tests:
18 passed, while both registry-boundary tests failed before admission with
`ntfs.native_registry_noncanonical`. The new unpublished registry contained a
trailing newline; the existing exact canonical-byte guard correctly rejected it.
The correction removes only that newline and updates the new registry's literal
loader hash; no historical entry, descriptor, trust root or guard is changed.
The original failure is retained. The targeted two-method rerun passed the
historical-registry closure and exposed an invalid test-only Core version string
(`1.2.0rc1`, the Python distribution form). The last method then passed with the
actual Core SemVer (`__version__`, currently `1.2.0-rc.1`) after independent
source review. Assertions, resolver and product guards were unchanged. All20
unique methods now have a PASS as18+1+1 across three captures; both earlier
negative captures are preserved, and passed methods were not repeated. Two
independent agents verified the recorded results. These are portable models,
not physical Windows bundle evidence. At that portable-only stage, the complete
original parser still required execution coverage. The later real create below
exercises its successful path; negative/parser failure coverage remains separate.

The clean-build and first isolated create/inspect acceptance is recorded below.
Conflicts/replay, interruptions and failure paths remain unfinished. The ordinary
bind transport remains UNSUPPORTED. FULL, native MCP/install/rollback and
whole-family final-artifact qualification are unfinished.

Bundle v2 is separate unfinished work: reuse the existing prepared-stage and
independent preparation-binding on ext4 before directory commit, acknowledge in
the same execute epoch, then connect explicit native continuation to existing
recovery before any POSIX path operations. V1 grants no such recovery authority.
No second journal/queue/version subsystem is proposed.


The next exact-HEAD CI run40812232474 reached the full test suite. Both Python3.11
and Python3.12 jobs reported1927 cases each:1917 PASS,9 FAIL and one unchanged SKIP. All nine failures
are AttributeError for a missing `_bundle` field in three deliberately
unconstructed parent model shells (seven File2 parameters and two Version1
methods). The real constructor already initializes this field. The correction
only adds `_bundle=False` to those fixtures; assertions and product code remain
unchanged. This negative is retained. At that point there was no accepted
corrected build; the later CI and physical results below are separate evidence.


## Accepted build and first physical Windows result

Source commit `de8d92369e1595e3ddf5284834fcdaff5e8932ec`, tree
`4afec39db9501ccfc1190a9535efcb3fb14a801e`, passed all three jobs of
[CI 40817094533](https://github.com/Emint76/phase-tool-next/actions/runs/40817094533).
Each Python lane reported 1926 PASS, one unchanged SKIP and no failures; this
includes all 20 new bundle methods. The installed CLI/MCP, historical evidence,
ordinary ext4 publication, existing prepared recovery, package rollback and
resource checks also passed. Two separate reviewers checked original CI artifacts
and every packaged product byte against Git. These Linux results do not qualify
Windows storage. The selected wheel is 875245 bytes with SHA-256
`d84561ce7b541ec059403b8e7095e50e7569c1ce017fa94e4e62d128217ffea3`.
The selected sdist SHA-256 is
`aba0f398ab3f28d1397b08204a9337e600a48c8f6b8e8618ccc050c1a42f305e`.

One actual synthetic run, `ntfs-bundle1-74f15e4c-cb16-4704-99a2-778a29e49617`,
then completed through existing Phase Core -> owned Windows worker -> NTFS
bundle -> standard receipt -> separate inspect. The source harness was preserved
before execution with SHA-256
`d2e946f9033e4055c412d6b2dff33698a08b9ae0df8e71642705e71846ad191a`.
Preparation, cold startup checks, execute, inspect and RO collection each ran
once, with exit0 and no stderr. No physical publication was retried.

The directory contains five payload members totaling 524362 bytes: three empty
files and two distinct paths with identical 262181-byte data, one nested. The
manifest is 668 bytes, SHA-256
`43663e75e12f6294387ace3af1205962e2429ef7df775b12b4bab3e3cc572b81`;
the existing owner1.0 is 226 bytes. Independent reads matched complete membership,
all bytes, owner/stat/native identity and absence of a retained stage or extra
sibling. Native evidence shows one class10 NOREPLACE directory rename and parent
flush, complete END stream, zero remaining handles, closed mutex/session/pipes
and retained creation-HANDLE wait0/exit0. Outer launcher exit was not substituted
for worker termination.

The independent inspect returned `succeeded_verified`, `target_verified=true`
and the same original bindings:

- Receipt: `sha256:b723fdf4c6d5f696354e1fc504a8680c71fd6afa666d0c9a936cf4be0a008065`.
- Intent: `sha256:65386ee77cf171030b8fa2016d06e5c13a5b53997525847d21fb7000c8fc677d`.
- Plan: `sha256:5c505b473696de34a6f4df9028356566ed61f5dc8a6c4860db8da7c086c6d509`.
- Raw native proof: `25b4a6308982f2101d51eeff02b9ed6292bac770b9b1de1ea176d3124c791fce`.
- Full private originals collection: 1108101 bytes, SHA-256
  `d9afc55f6daa840bfad164279bd7879f8ac4efadfb15a1e4002b017021a5ec94`.

Both independent agent reviewers accepted this one functional result, checking
original Core bindings, frozen inputs, Windows bytes and resource finalization.
They share the test host/toolchain; this is not external human approval. The full
private evidence remains outside the public repository. Scientific data,
personal configuration and internal logs are not included here.

## Remaining work

Complete native bundle2 using existing preparation binding and explicit recovery,
then applicable conflicts, repeats, interruptions, recovery, historical readback,
clean installation, native MCP and runtime rollback. A05/G01 and broader safety
qualification remain NOT_VERIFIED. This small create proves neither full MIX/FULL
support nor the maximum member/size/deadline envelope. Ordinary unsupported
configurations continue to refuse; no new journal, queue or version store is added.
