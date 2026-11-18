# NTFS qualification stopped at a mandatory bundle primitive

2026-10-21. **No NTFS support release is accepted. No admission change exists.**
The support goal is blocked for the tested composition. This is a negative
qualification result, not completion of the release objective.

## Reproducible scope

- Historical runtime: Phase 1.1.0, tag commit
  `5ba874f77e9225aae29e6c84cfc3f776df557c9c`.
- Development base: `721945ce46546e82ef31134d1e1bb54802a1d027`.
  No runtime-source delta from the historical reference.
- Official wheel: SHA-256
  `9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a`.
  All 193 installed package members matched the wheel.
- Official image ID/available RepoDigest:
  `sha256:5e6f98d684b7f65e6798f2fdc23edf05ed839ed96b611de29e4930c357ce0277`.
- Directory-only offline test-image derivative:
  `sha256:3ecc2ebeb56001538ffcf158b6297df563efc3e773baa0271837e26dd7ba8a69`.
  No Phase package or dependency change.
- Gates script SHA-256:
  `b61c57cfaa97d0568acc9da35d3f26b597c3b6089f4952c8e1639e2495e72e92`.
- Host controller commit: `3434a9300a1075376f636866ec820c00a5fef3da`;
  SHA-256 `245caaf82aef4e8f0e5584405e6530ec9ef8e35aba5c2180bf92d4ce1b216eab`.
- Windows 10 Pro build 19045; Docker Desktop 4.66.1.222799, Engine 29.3.1,
  WSL2 kernel `6.18.33.2-microsoft-standard-WSL2`, linux/amd64.
- Actual result transport: S: NTFS, local fixed SATA storage, exposed to the
  test container as 9p/DrvFS with `metadata`, `cache=0x5`, `access=client`,
  `msize=65536`, `trans=fd`. This was measured on S:, not inferred from C:.
- REF, report records, native evidence and preparation: dedicated owned ext4
  volumes, separate from production. Two nonroot offline containers; the
  independent verifier has read-only mounts.

## Results and stopped work

| Lane / early gate | Requested / completed | Observation | Decision |
|---|---|---|---|
| REF E01 directory fsync acceptance | 10 / 10 | File and pinned parent fsync returned 0 | Positive subcase only; full E01/G06 NOT_VERIFIED |
| REF D02 sequential NOREPLACE | 10 / 10 | Absent commit succeeds, empty/nonempty existing targets return EEXIST unchanged | Positive subcase only; full G1/D02 concurrency NOT_VERIFIED |
| MIX E01 directory fsync acceptance | 10 / 10 | File and pinned parent fsync returned 0 | Positive subcase only; full E01/G06 NOT_VERIFIED |
| MIX D02 sequential NOREPLACE | 10 / 1 | First absent-target call returns EINVAL (22) | UNSUPPORTED primitive composition; dependent bundle mutation stopped |
| REF full publication family | Not run | Only early gates and report archival completed | NOT_VERIFIED |
| MIX mandatory family | Blocked | Both required bundle routes depend on unavailable primitive | UNSUPPORTED for unchanged mechanism on this transport |
| FULL evidence/preparation | Not run | No FULL mount or lifecycle qualification | NOT_VERIFIED; same result transport retains bundle blocker |

All other A01–F09 cases and G01–G06/R01–R12 claims remain NOT_VERIFIED unless
explicitly established above. The original ten-repeat threshold was not reduced:
one mandatory negative counterexample stopped the dependent branch under the
program's stop rule. The other nine attempts are not counted as executed or
passing. The complete original program was not executed.

The exact installed `mutation/bundle_create.py::_rename_noreplace` calls:

```text
renameat2(valid_parent_fd, "source-absent", valid_parent_fd, "target-absent", 1)
```

`1` is RENAME_NOREPLACE. Source and destination are simple ASCII leaf names in
the same pinned parent. The source is a nonempty owned synthetic directory;
the destination is absent. The genuine libc call returns -1 / errno 22. The
source member remains intact and the destination remains absent. Equivalent
REF calls succeed, including existing-target refusal assertions.

This proves failure of this exact syscall/mechanism/mount composition. Without
kernel/bridge traces, the origin of EINVAL cannot be localized further between
VFS, 9p client/server and Windows bridge. It does not prove all NTFS transports
or native Windows APIs incapable, nor that a native Windows backend is required.

## Evidence bindings

These native verified receipts certify **archival of reports on ext4**. They do
not certify successful NTFS bundle publication.

| Report run | Raw report SHA-256 | Native receipt digest |
|---|---|---|
| g-d02-mix-97455e45 | 9a5d70e0c9f59ca2f99793e0c7c60cfcc5bacbdff35e369d940c29d477c0d8d8 | ce131853822f8545dcbc744468aa18f20c867bb57a53037baa258fdd592f6d45 |
| g-d02-ref-d6532f04 | 3ae789edcfcc212b45ec552635e81197025f74df23137d0f020b75e43328670f | 3df7e277ead57de41b9f402d9a3ca72f1c680f9ee2752cf0bed22b5323e36e09 |
| g-e01-mix-66f007c5 | ea296280c05e4bec99b7ee3d414b7dca6e8b46996e9591fe201c67c9188961f6 | 0c801fb03d4e3ac2e74e2d01e17e1a45d8ca2ec9beb30b5b21eb7305a3ba2d6b |
| g-e01-ref-ebe28575 | 24a50c83443d150199232eb1c6b71b1133663815ec886fbe07f436265f3b2240 | d1167ccb7e952e59182220f31a082324bd6fc2c5c63035dedb887de10bcea808 |
| g-freeze-env-7252d372 | b87773b9715e90092a6654c06e97596844dd46e163a535fc8135e12dc3948cf2 | 76956cfb18cd8f8798a857c283c51f655af7a4a0b7f6d1a924c74bd5b0d808e8 |

The full private package additionally retains initial setup failures, ownership
and environment metadata, all native intent/plan/effect/receipt records, a
read-only Windows/Linux audit and a delivery map. No personal host paths,
scientific data, profiles, secrets or full internal logs are published here.

Independent review used a separate agent/reasoning context. The reviewer read
actual retained files and native receipts through the exact read-only verifier,
checked raw hashes and separately recomputed native canonical receipt hashes
without importing Phase. This is not an independent laboratory or vendor: the
machine, model and underlying toolchain are shared.

## Why admission cannot repair this

R06 requires a genuine atomic directory NOREPLACE commit for publish_bundle
1.0/2.0. Changing a profile cannot make the failed syscall available. An
exists-check followed by ordinary rename can overwrite an empty destination
that appears in the race window. Copy/delete, publishing a reserved empty
directory and later filling it, or publishing a link change the contract.
No such fallback is accepted. No blanket 9p allowlist or guard change is made.

Another transport, bridge correction or a new backend could be investigated
under its own authorization and full qualification. This task does not begin
that different implementation or alter global Docker/WSL settings.

Large scenarios have an additional environment gap: the host disk backing the
Docker data VHDX has about 31 GiB free, below the required 64 GiB large-test
reserve. No other data was removed and no VHDX was relocated.

## Product fit and release status

Existing limits remain: file 1.0 ≤1 MiB, file 2.0 ≤2 GiB; bundles ≤1024 members,
≤2 GiB/member, ≤4 GiB total; version v1 old/new ≤16 MiB; version v2 inline UTF-8
old/new ≤512 KiB. Large binary checkpoint versioning is not supplied by these
version contracts. Byte-addressed archives are not a complete ordered revision
index. No actual scientific workload size was inspected, and no HCV workflow
is declared unblocked.

There is no new accepted version, merge commit, package/image release, CLI/MCP
candidate acceptance or old→new→old rollback result. Production has not been
switched. See [ROLLBACK.md](ROLLBACK.md) for the preserved baseline and limits.
