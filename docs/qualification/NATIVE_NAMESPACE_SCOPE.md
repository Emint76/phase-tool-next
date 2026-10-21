# Native namespace pins and external replacement: L1 checkpoint

The new `mutation/ntfs/scoped.py` helper pins a granted native root and every
existing parent of one safe relative locator. It compares device/GUID/serial32,
the full native root identity and each ancestor's native identity. Reopening each
name uses the same no-reparse barrier. There is no Path I/O, parent creation,
mutation dispatcher or POSIX-fd emulation.

`NativeRootGrant` is immutable configuration data, **not authorization or a
qualification certificate**. A future trusted installation/intent composition
must authenticate it. The provider selector, registry, profiles and qualification
guard remain unchanged. The helper is internal and unselected; no route is
admitted. Its current path scope is S: and ASCII root components/relative
locators. This does not extend support to arbitrary Windows roots or transports.

The caller owns leaf handles returned by `open_file`; closing a scope closes
only its ancestor pins. Sealed effect leases, complete lifecycle cleanup and
contract preconditions remain required. Binding assertions are point
observations, not CAS or continuous protection against external writers.

## External replacement measurement

Run `g-native-destination-share-1792595934662615800` held an old reader open
while a separate process issued real class 65 / flags 3 replacement, ten fresh
cases per sharing mode:

| Old reader sharing | Actual return | Named result | Old reader |
| --- | --- | --- | --- |
| 3, no FILE_SHARE_DELETE | 10 x C0000043, IOS 0 | Current and source kept their identities/bytes | Old identity/bytes retained |
| 7 | 10 x SUCCESS, IOS 0 | Current became source; source name absent | Old identity/bytes retained |

All twenty actors exited zero, no forced termination or handles left. A separate
read-only audit reread all current files, ten remaining sources and the sentinel
with full native identities and zero mismatches. These are observations on the
recorded stack, not universal NoDelete semantics or full G03/G05 qualification.
The primitive's original `effect_state:unknown` for C0000043 is retained;
independent observation does not silently rewrite its response classification.

Ordinary Windows applications can hold handles without FILE_SHARE_DELETE.
Such sharing can deny an update; it must be reported truthfully. The measured
successful held-reader path explicitly uses share=7. This is not permission to
override another application's sharing policy.

## Scope pilot and evidence correction

V1 `g-native-scope-1792597432915609600` completed 10 normal, 10 reparse and
10 leaf-name cases. All sources and actual control flow were audited. Its normal
initial file IDs and readback hashes were checked in memory but not retained as
individual raw fields. Fresh later IDs could not be compared with missing
historical values. This limitation remains attached to V1.

V2 `g-native-scope-1792597902805937600` preserves actual observed IDs/readback
tuples and expected hashes/identities. It uses new cases and the same product
bytes; V1 sources and evidence are unchanged. All 30 cases completed:

- Ten normal cases check file bytes/name binding, wrong leaf/root/GUID,
  missing parent, partial-initialization cleanup and closed-scope rejection.
- Ten actors convert the exact pinned parent into a real junction, confirmed
  by tag and unchanged full FileID before guard/open rejection.
- Ten actors replace the current name with class 65 / flags 3 while the old
  share=7 reader is held. Stale name assertions reject with identity mismatch;
  old-reader and fresh-name hashes/identities are separately retained.

The independent V2 audit decoded seven exact source snapshots and freshly read
all twenty current files plus sentinel. All normal and new leaf identities and
bytes match retained raw. All twenty actors exited zero without forced
termination/errors; module handles zero. Old unnamed objects are substantiated
by actual held-reader observations, not a claim of later independent rereading.

These runs are L1 by exact source hash, based on checkout fd4f97f; that commit's
wheel does **not** contain the later scope helper. They do not qualify an installed
package or later merge build. Four pure grant-validation/immutability unittest
checks also passed; they make no native Windows execution claim.

## Exact retained bindings

| Source | SHA-256 |
| --- | --- |
| Scoped helper | `20180e628f17d01b81f15292c7c35313a754e64951680d645592db8f93e1e6b9` |
| Pure grant tests | `59637251fe976d406e3544cef3a4722f62c297e2a8899998737f9b84c72086fb` |
| Destination-sharing probe | `1d5763ec94085f64925329446eb3e2e1b9320a3e8eeaadff88accd7254fbc8e4` |
| Scope V1 probe | `aea9d0ead6e8acbc48354b23213657e66c85f809e00df7f9ed8792ae85b5ccea` |
| Scope V2 probe | `a2ea8ae4d1589845f43dfa270ba2d4f72bac48d312eae17f3ae7c5c55dbd1bb0` |

| Evidence | Raw SHA-256 | Receipt SHA-256 |
| --- | --- | --- |
| External sharing | `b63041d47c5ed707e88005b15888b595a9a4d399f350f2fc324cd4b36d87374d` | `8fe8a3144d13530feef168a744c72332edf8808eff526d9ac2a035fb1926c176` |
| Scope V1 | `7aeb6967da7d6cefc290914a12ffb1e85b9841981b7121038c1dcc13a6046ffb` | `a2e6faf819a04a91b0756fb074ee11d4cb35548a3e82759d70ee419a54fe05b5` |
| Scope V2 | `e05402755f7c26b2412c40c63adbbc4f141f2a5405481867835bf46141492c4d` | `d5db70558b31f4c4543607c5bc043c6ef4db33bebfd39db9b67e29bafb611eeb` |
| Full 50-file development checkpoint | `c37082f506022cb3dd0e1114b94caf022be5965640be2a9e78900f305fb13b41` | `9dbc15d31be059f67e54311268cd29358c471eea933625c5d8845fa5bf2ac625` |

All evidence uses unchanged isolated Phase 1.1.0/ext4 with native receipt,
separate read-only inspect/readback and exact hashes. These saves are
Evidence/Raw, not Source admission. Sources and harnesses received independent
pre-execution review; result audits use separate agents on the same host and
toolchain, not external certification or GitHub reviewer approval. Full raw is
retained privately; this report contains only synthetic summaries.

The historical replay-layout restriction still applies. Scope probes additionally
need exact `product/scoped.py` and `product/mutating_v2.py` in their private
staging layout, with the recorded source hashes and fresh owned cases.

## CI provenance and remaining gates

[CI run 39624601467](https://github.com/Emint76/phase-tool-next/actions/runs/39624601467)
passed at fd4f97f: both Python versions' suites, wheel/sdist build, clean installed
CLI/MCP/status/recovery/correction smoke, and the installed py3.11 wheel's
64 MiB/1 GiB/2 GiB streaming plus 256-file/256 MiB bundle resource tests. This is
Linux regression evidence. The temporary GitHub PR-head synchronization delay
resolved without a duplicate push or CI run.

All three CI ZIP downloads match GitHub's recorded digests. Actual nested wheel
and sdist SHA-256 and source bytes were checked; the resource job's byte manifest
matches py3.11's accepted wheel. Separate Python builds have distinct hashes;
they are not claimed reproducible or interchangeable qualified NTFS artifacts.

| Retained CI evidence | Run | Raw SHA-256 | Receipt SHA-256 |
| --- | --- | --- | --- |
| Complete downloaded ZIPs | `g-ci-fd4-artifacts-1792597725818833300` | `50bdae366a41c60947a3f9147348a4ebc950e23209e24166f261b1e5864a4bfd` | `1e19c79d52b5c50af30047adf9ca8fbeb8aff89e203a65a013359a3d2ab032c6` |
| Nested build/source audit | `g-ci-fd4-build-audit-1792597993917204600` | `e48559dc2866fd657296271b84d512ba23d74bcd5d52d2b47dcc149aec870cbe` | `c7c604a4342d4ca4a93b744ef8214acbf4847a0d97c611c2072e6e3d9c8fc4f6` |

**A05 remains NOT_VERIFIED** pending an authorized native Windows SYMLINK stand.
Generic junction tests do not substitute. Full REF/MIX/FULL contract qualification,
G06 lifecycle propagation, sealed leases, trusted composition/versioned bindings,
replacement syscall windows, installed native CLI/MCP and executed rollback are
outstanding. There is no merge/release acceptance or production switch.
