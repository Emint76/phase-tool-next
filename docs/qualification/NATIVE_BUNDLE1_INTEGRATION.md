# Native bundle1 connected draft

Status: implementation draft, not yet executed or functionally accepted. A05,
applicable G01, native bundle boundary/failure/recovery coverage and supported
NTFS qualification remain NOT_VERIFIED. Ordinary startup/production guard is
unchanged. No production installation or Hermes profile is changed.

The earlier real native file1, file2, Version1 shared history and corrected
Version2 results use their recorded builds. They do not validate this draft.
CI40793668402 passed on documentation HEAD658a32e8; it does not test these new
uncommitted source changes. No native bundle receipt or inspect PASS exists yet.

## One existing lifecycle

The draft connects the existing Core/EffectBroker native dispatch, original
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
pytest is absent on the host, and the next exact-head CI must verify pytest and
the full regressions. No package, product guard or environment setting changed.

## Verification still required

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
not physical Windows bundle evidence. The complete original parser still requires execution coverage;
source review alone is not that regression result.

Next acceptance is a clean candidate build and actual isolated Core -> worker
-> NTFS bundle -> receipt -> separate inspect, followed by conflicts/replay and
failure paths. The ordinary bind transport remains UNSUPPORTED. FULL, native
MCP/install/rollback and whole-family final-artifact qualification are unfinished.

Bundle v2 is separate unfinished work: reuse the existing prepared-stage and
independent preparation-binding on ext4 before directory commit, acknowledge in
the same execute epoch, then connect explicit native continuation to existing
recovery before any POSIX path operations. V1 grants no such recovery authority.
No second journal/queue/version subsystem is proposed.
