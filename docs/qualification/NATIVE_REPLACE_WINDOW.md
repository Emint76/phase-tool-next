# Class 65 replacement: bounded L1 reparse window

This completed synthetic test exercises internal, unselected native primitives.
It does not qualify an installed package, a contract family or an NTFS route.
MIX, FULL, A05 and G06 remain **NOT_VERIFIED**. It is not the mandatory
1000-replacement reader test or the literal Windows SYMLINK case.

The test ran once at source base `30cdf46ed451da7215cd1442cc21bc891fd9d92d`:

| Case | Count | Observation |
| --- | ---: | --- |
| Existing ordinary file | 10 | Real class 65, flags 3, succeeded; old share-7 reader kept the old full identity and bytes; fresh name reached the new object |
| Empty parent converted to junction | 10 | Conversion kept the same physical parent identity; unchanged real class 65 call returned `0xC0000280`; exact post-observation error was `ntfs.reparse_forbidden` |

All ten conversion workers returned exit code 0. No worker needed forced
termination. Primary native outcome, post-observation error and worker
finalization are recorded separately. The original kernel-window V1's
secondary EOF failure is retained in its historical evidence; it was not
relabeled as a successful result.

The junction windows test kernel prevention. They produced **zero successful
calls into a converted parent**, so post-binding detection after such a
successful call remains **NOT_VERIFIED**. Empty-parent conversion is not a
demonstration that a nonempty directory can be converted. Native events retain
`effect_state: unknown`; a zero initialized IOSB does not override C0000280.

Independent read-only observation matched the current identities and bytes of
all ten controls, all ten denied sources, the root and the synthetic outside
sentinel. Control source names were absent; denied source names remained.
The outside bytes were unchanged. Separate-agent review audited the exact
source snapshots, raw events, worker outcomes and current synthetic bytes on
the same host/toolchain. This is not external certification or GitHub approval.

| Identity | SHA-256 |
| --- | --- |
| Harness `qualification/native_replace_window_probe.py` | `fe8945e852889416625f6b98d50fc68440807c4eefcf531de8ddbcec15c54dd4` |
| NativeIO | `41654049dc10f1c2db0f74c847f0a36038b49295c4f02582b959b9c7a0dd0a22` |
| NativeMutationIO | `b1b19f763de31fb3b8077b595207d37ef4c921397266cba5edb53594996c379a` |
| NativeScopedTarget | `20180e628f17d01b81f15292c7c35313a754e64951680d645592db8f93e1e6b9` |
| NativeRootMutex | `5c18957ec54b555a38fb081557e7aa1c6ac25434728f5858ffd3f62503369178` |
| Source checkpoint raw | `a3fda0b72dfecbc750444969874e3ab1f56a2fdaff3d5a6349b8c38672665413` |
| Source checkpoint receipt | `adfc3a80f7a301d24c119fda9d520573887d238b751c116bf122d2de60b5afe8` |
| Result raw | `eb4a7034b62496b47f0c9915ab42c2dd5a37b45ecede0a059af618c62645ce8a` |
| Result receipt | `b920890647081b872969a13a5151510973178b20982a0586f0d67510a685e1db` |

Run: `g-native-replace-window-1792607940291626300`. Full private evidence and
source checkpoint use unchanged isolated Phase 1.1.0 on owned ext4,
`file_create.v2@1.0.0`, with native receipt and separate read-only
inspect/readback/hash verification. Their category is Evidence/Raw, not Source
admission. Historical harness layout and self-pinned dependencies are described
in [component status](NATIVE_COMPONENT_STATUS.md#historical-harness-layout).

See [remaining mandatory qualification](FINAL_QUALIFICATION_REMAINING.md).
No production profile, admission guard, provider or published binding changed.
