# Rollback state and requirements

No Phase implementation/admission change or runtime switch occurred. The
qualification stopped on the mandatory bundle primitive before G3. **No tested
old→new→old rollback is claimed**, because there is no accepted new runtime.

## Preserved baseline

Keep the existing immutable v1.1.0 tag and all release assets available:

| Artifact | SHA-256 |
|---|---|
| wheel | 9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a |
| sdist | 2078eb4a885eff130123a2c3bfc8386c040f90739c28abc17cfb78f46c6d1f80 |
| OCI tar | c74a7acda1af0af300c63825f577d3836fb4f2378903b58a98601955b6217b38 |
| installed release image | 5e6f98d684b7f65e6798f2fdc23edf05ed839ed96b611de29e4930c357ce0277 |

The release files were downloaded and independently hashed before attempting
the owned stand. No release asset/tag, production config, installed skill or
canonical volume was modified. Nothing needs production rollback now.

## Three separate operations for a future candidate

1. Code: create a normal revert PR against the merge commit, run required checks
   and merge under the repository rules. Never reset/force-push published
   history or move a release tag. Current tooling-only draft is not merged.
2. Runtime: stop only the specifically owned canary after inspecting known
   operations; pin the exact prior image/package and the saved prior route.
   Restore the prior container/configuration in that isolated contour. Do not
   restart the host, WSL or Docker Desktop and do not touch production.
3. Data: preserve result documents, archives, objects, native evidence,
   preparation proofs and ownership manifests. Runtime rollback never silently
   deletes or rewrites data. A snapshot/copy is not automatically new authority.

Phase 1.1.0 rejects the tested NTFS roots. It must not be given permission to
mutate future resources bound to an unsupported new profile. Keep a matching
verifier/runtime for new evidence formats; old receipts retain their historical
exact descriptors and bindings.

Before accepting any future candidate, execute old→new→old on own synthetic
roots, verify unchanged data/evidence hashes after the return, prove the old
runtime refuses new unsupported resources, and re-inspect new evidence using
the compatible verifier. Those tests remain NOT_VERIFIED here. Text alone is
not their substitute.

## Present stand retention

Retain the four campaign-owned ext4 volumes and the owned NTFS source fixtures.
No deletion routine was executed. Container suspension/removal, if needed,
must first compare exact IDs, ownership labels and complete mounts against
the saved manifest and establish there are no active/unknown operations.
Never use global prune, broad name matching, production volumes or recursive
deletion of a parent. The private delivery map locates the retained native
evidence and reports.
