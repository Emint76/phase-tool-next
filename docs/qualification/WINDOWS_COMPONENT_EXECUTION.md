# Bounded Windows directory publisher: execution record

Status: research candidate, **no supported Phase NTFS route yet**.

This execution follows issue #12 and draft PR #11. The original negative
Linux `renameat2(RENAME_NOREPLACE)` result remains valid and unchanged. The
continuing human instruction explicitly authorizes another physical mechanism
inside Phase, including a bounded Windows component, implementation, review,
qualification and release after acceptance. It does not authorize global
Docker/WSL changes, privileged drivers, production profile changes, or weaker
contract guarantees. This document supplements the original program.

## Fixed baseline

- Development base: `4258463a674395addaf196b5bb9e443da31a0edf` (PR #11).
- Default branch observed: `721945ce46546e82ef31134d1e1bb54802a1d027`.
- Reference release: v1.1.0, `5ba874f77e9225aae29e6c84cfc3f776df557c9c`.
- Reference wheel: `9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a`.
- Reference image: `sha256:5e6f98d684b7f65e6798f2fdc23edf05ed839ed96b611de29e4930c357ce0277`.
- New campaign: `936b34d0-4f82-4558-b26e-9a206f20af88`.
- Two own nonroot, offline, read-only-root containers, four own ext4 volumes;
  each container has 2 CPU, 2 GiB RAM, 128 PID limit, all capabilities dropped.
- Own S: synthetic tree only; no scientific inputs or production write mounts.
- Freeze publication: `g-freeze-env-ecbf02af`;
  receipt `sha256:68890cdb74ce302a7b60e016e2742d4d4a2d1fd0964a757f336d0cecff7610db`;
  raw `sha256:521d89617e2431e990254f68b74bbc650b1fb57d5cfefed64e1f2cb73ad1172d`.

Full internal evidence is saved through unchanged Phase 1.1.0 in campaign-owned
ext4 volumes `phase-ntfs-q-<campaign>-records` and `-evidence`; independent
read-only inspect and raw readback are mandatory. Public summaries expose
synthetic facts and hashes, not private paths or full machine logs.

## Original program, unchanged

| Document | SHA-256 |
| --- | --- |
| EXECUTIVE_SUMMARY.md | c40a695f7c5021f63aa86e44c2e15fdf51f62b0df62430f26e4988c0967b1df1 |
| QUALIFICATION_PLAN.md | a502b958c18db8cdcf4e79c295da41393a796a47109e36621e987f2739a919f3 |
| GUARANTEE_MATRIX.md | 0fc883fb9d6ced9e7498f795e97743d8307b5c8b4155f30a719b7c5ea95aaa80 |
| TEST_ENVIRONMENT.md | c50b825d722eacaec2d3ba220bcf5e7d281fd83b75e6efbcb6127fe97f09eb9a |
| ACCEPTANCE_CRITERIA.md | 1da00be0854f0397467d568971c3d296d01a4294572dfd0034defcf75421f71c |
| IMPLEMENTATION_IMPLICATIONS.md | 84082732db5ac4dbc25d97ab6e928177d4761116a575cbe2addedc1993fb8c36 |

The newer instruction replaces organizational stop points. Original assertions,
repeat counts, limits, failure evidence, production isolation and honest
SUPPORTED/UNSUPPORTED/NOT_VERIFIED decisions remain mandatory.

## Primitive results so far

| Case | Actual result | Bound evidence |
| --- | --- | --- |
| H01/v1, DOS alias with DONT_REPARSE | NOT_VERIFIED; parent open returned c000050b before any rename | run `g-h01-native-1792575537458153600`; receipt `3498bf6f5315d1251ba735ae32a4ed0fc28c094215614b83d273fdc0f80cc3b8`; raw `9e373f37b23a9cce3d4ed21b8414c40fdec3bd5f6a0af33a3e41d6f7d027e2d8` |
| H01/v2, direct device with independent parent identity comparison | SUPPORTED for this L1 scope: 10 absent-target successes, 20 existing empty/nonempty target collisions | run `g-h01-native-v2-1792575825035602600`; receipt `585e71f19da7458c9a7420b0646b0283e8e7f85d6988860ec9fc0958c89cf41c`; raw `7ad81fd54cf090c9aed5fdbce33417cc6adf813e345b8d25ef84d9f2a6d6103f` |
| H02/v2, eight processes and 100 barriers | SUPPORTED for this L1 scope: 100 winners, 700 collisions, no unknown outcomes | run `g-h02-native-v2-1792575842199243100`; receipt `2a5f1a079bdd7b67b7caa975ea1e17d30fabb6816f1073db485a6d66c20cc59b`; raw `a0457bf02388cbcb61d38af720e525f9cda8bfe503b8d80989866d9f032301a9` |
| H03, held Linux stage directory descriptor across native rename | NOT_VERIFIED, stopped after first repeat: native commit succeeded, post-rename Linux fstat(stage_fd) returned ENOENT | run `g-h03-linux-native-1792576581638087600`; receipt `c991bf1a5d3115a42864e8a3b5bd7af04fd491fc3135cbcdf40a669f4b38c492`; raw `3bc867baddfcb8b49a9a74a5854f21d39dece7f7e10b6f66163dcea59e56f06b` |

H01/H02 exact executed harness:
`sha256:1ea04fc3e58b9cac8a9a8c5d5c0559f9739dbdb4ef9142f6d3a101b433c661a3`.
H03 exact executed harness:
`sha256:16a9f9452ef5168f1e158faff3a7bee782e496df30c5e1b68e23d4aeae70cdea`.

An independent agent reviewed harness bytes before execution and audited all
30/800 H01/H02 native events plus current Windows bytes, identities and
membership after execution: zero mismatches. This is independent agent review,
not external certification or a GitHub reviewer approval.

H03's observation construction lost an earlier verifier exception, if any, when
the separate held-fd fstat failed. Thus that run establishes neither success nor
a particular failure of `verify_bundle`. Subsequent fresh read-only checks must
be recorded separately. Its ENOENT limitation is retained. Numerical Linux and
Windows IDs are different identity domains; no numeric offset rule is inferred.

All Phase REF/MIX/FULL contract-family results remain NOT_VERIFIED in this new
campaign. Prior negative legacy-route results are not relabeled.

## Architecture selected for implementation review

Keep Linux Core, POSIX file/version primitives and ext4 evidence/preparation.
Add a Phase-owned Windows component for prepared-directory observation,
publication and read-only inspection. It is not a generic filesystem bridge.
Payload is staged and committed directly on NTFS; there is no canonical-volume
publication followed by export/copy.

The independent source/architecture review conditionally approves this direction:

1. A trusted host launcher verifies exact installed artifact bytes, immutable
   image and container identity and a read-only root grant. It opens only fixed
   Phase executables via docker exec, with private STDIO and a private Linux
   socket. No network listener, Docker socket mount or agent shell dispatch.
2. Requests carry root grant IDs and safe relative locators, never caller-supplied
   Windows absolute paths. Native traversal pins each component and rejects
   reparse points. Source and destination parent are pinned; existing-target
   refusal is performed by the native rename itself.
3. Host independently verifies manifest, exact owner bytes, all payload bytes,
   sizes, membership and absence of links/reparse. Identity includes native
   volume/FileId and separately bound Linux device/inode observations.
4. A closed protocol has version/session/frame/depth/count/key checks. Session
   nonces authenticate transport and do not enter durable operation identity.
   Lost response means unknown until independent inspect, never blind retry.
5. Before native commit, complete intent/plan/prepared proof and independent
   binding are durable on ext4. After commit, Linux namespace assertion, real
   pinned-parent fsync, readback and evidence finalization remain required.
6. New execution-context, intent/receipt/profile/preparation schema generations
   and six exact contract packages bind composition and grants. File/version
   mechanisms can remain unchanged; bundles require new mechanism generations.
   Old published descriptors, bindings, POSIX authority bytes and explicit
   execution selections remain unchanged.
7. Read-only inspect can re-observe native identities in a fresh session. Exact
   stage identity distinguishes committed publication from equal foreign bytes.
   Explicit commit_prepared performs only the one remaining authorized commit.
8. Default installations continue rejecting unqualified 9p, unknown stack or
   grants. FULL stays unavailable unless independently qualified.

H03B is a reviewed next hypothesis: close Linux stage fsync descriptor before
host commit, as the normal existing bundle mechanism already does; retain Linux
root/parent handles and lock, and use a native pinned source handle. Require
fresh Linux target identity, unchanged bundle verifier, namespace assertion and
real parent fsync afterwards. Do not claim cross-native-rename Linux stage-fid
stability. Recovery needs the corresponding new native path, not ignored errors.

## Resources, release and rollback gates

Source audit establishes a 2 GiB file peak of 8 GiB ext4 REF / 6 GiB ext4 MIX,
and a 4 GiB unique-member bundle peak of 8 GiB ext4 REF / 4 GiB ext4 MIX.
Source and direct target copies on S: are counted separately. Private open,
unlinked stream snapshots count even though a directory walk cannot see them.

The human permits a reviewed resource revision. Before large tests, validate a
lossless compressed archive/evidence-restore pilot through supported ext4 Phase.
Preserve identity-bearing roots/bundle directories; archives do not restore
inodes. No VHDX reclamation is assumed. Proposed hard floors are C:12 GiB,
S:20 GiB, plus drift/metadata headroom and full case/archive/restore accounting;
one large case at a time, original 2/4 GiB limits and 32 GiB campaign cap retained.
These are not permission to start a large case without its exact measured gate.

The six execution stages are baseline/freeze; primitive proof; trusted minimal
implementation; complete REF/MIX qualification with FULL separately; independent
review, exact-HEAD CI/install/CLI/MCP/history/rollback; rule-compliant merge and
release with download-byte verification. A green primitive or draft PR is not
release acceptance. Runtime rollback must execute old -> new -> old while
preserving all data/evidence. Production Hermes remains unchanged.

Issue #13 (large binary versions) remains separate. This work neither raises
contract limits nor declares the HCV scientific workflow unblocked.

## Subsequent primitive results and architecture refinement

| Case | Actual narrow result | Raw SHA-256 / native archival receipt SHA-256 |
| --- | --- | --- |
| H01/V3, source also denies other DELETE opens | 10 absent successes, 20 collisions | `12a2186ceb8ee0cf70053a8e39c708754a42efc87622abe9aa49e54ff4c1fc84` / `4c603ba4c6a138659732bf5173fd01a77de912510773e45daaf6a2d6d97eab58` |
| H02/V3 | 100 rounds, 8 processes, 100 winners, 700 collisions | `6a22391b31dc7a2ced114c76fb567e76eef0c44b32ca298be405fbeecd1de98d` / `291fa6bd90325ee201779ae9d2584f0158a992bc16e64ffc981a0b67fbb44949` |
| H03B, closed Linux stage fd before native source pin | 10/10 complete Linux-staged bundles, unchanged Linux verifier, fresh identities, real parent fsync and independent Windows bytes | `00288f95906b1dab8f08832e0124edcec055f88094a94f971eaf445b277e8f6a` / `18c882304b2edc6ba7cb508dcc9b407f641091848658971db6c8f1e129a3596a` |
| H03 fresh read-only re-observation | Both worker and verifier match original READY expectations | `20ba41ad8b6dd13895882eb70f57d569cd548b83557fb83cb59132b37774ac2b` / `db89182f57d8fa16c7bcaa7ed7473ea4a71659ea3b6b4e308ac436c02d1e99ca` |
| A05 fixture pilot | Native CreateSymbolicLinkW file/dir: 1314; real junction tag 3 and Linux links tag 1D available | `7e60c23aec1e8b32d737ab2e2f574c006eeb738feb371cfc8afbcce63aaa57c1` / `5c9c9567a870f6b119682d33627a2335b65a4154855284d24d26cd6138827054` |
| A05 native tag through FSCTL | File/dir SYMLINK requests: 1314; resulting objects remain plain tag 0 | `c3d1d29055dd1e4750c4af3c59bfadb2d7738b324657ca4161ef43efdcbf8a08` / `780dbf4ff37a54728301443e2e6dbcb6e700938b88eb70998999aa0ea068ae53` |
| Native directory-flush API candidate | 10 directory/file pairs accepted real NtFlushBuffersFileEx(flags=0), correct identities/status/IO status | `3de2777127088e6097ddbaf32de620f7147da1d5d692784d6f369d45c5d86194` / `7857455f2449706b57ff7cb2ca01ba110dfa8040095198227828202797962ee9` |

Each row was archived through unchanged Phase 1.1.0/ext4 and independently
inspected/read back. Run IDs are in the retained campaign state. The independent
agent's additional raw/Windows audit of the first six new rows found zero
mismatches. It did not separately recompute canonical receipt hashes; the separate
Phase verifier performed native inspect. Independence is limited to another agent
on the same machine/toolchain, not an external laboratory.

All new L1 harnesses had exact-byte pre-execution review. The original H03
negative result remains; H03B does not claim old stage-fid stability.

Literal native-SYMLINK availability remains NOT_VERIFIED/ENVIRONMENT_GAP.
Metadata-only inventory of the two known owned campaigns (3980 entries) found
only the three declared junction/LX objects. Other private/production objects
were not searched. Changing Developer Mode/privileges is not authorized.

This gap is not an automatic end to the goal. Independent architecture review
admits development of a complete native, tag-independent reparse barrier under
the human's allowed platform-oracle mapping. The alternative must cover EVERY
NTFS root/parent/leaf read, mutation, archive/object, listing, inspect and recovery
path, with no hidden POSIX NTFS leaf access. NoDelete does not freeze reparse
metadata, so conversion races and repeated attribute/identity assertions are
mandatory. The historical literal case remains NV; a new exact-backend property
oracle must be accepted separately, with executable adversarial evidence.

Native NtFlushBuffersFileEx(flags=0) is being investigated so this alternative
does not depend on an unproven Linux directory-fd correspondence. The successful
API probe alone is **not G06 acceptance** and makes no power-loss claim.

The first native I/O source draft is temporary, unintegrated and under review.
No implementation/profile is admitted and no runtime version is released.
REF/MIX/FULL contract-family verdicts remain NOT_VERIFIED; merge/release gates
are not satisfied. Source authority/profile/descriptors and production remain
unchanged.
