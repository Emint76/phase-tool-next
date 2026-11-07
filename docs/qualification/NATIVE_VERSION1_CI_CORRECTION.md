# Version1 software CI failure and minimal correction

This is an **unqualified software candidate**, not supported NTFS delivery.
A05/G01 and actual admitted native Core create, version update, bundle,
receipt and independent inspect remain **NOT_VERIFIED**. The qualification
guard, production runtime, registry trust and historical bindings remain intact.

## Preserved failed execution

[CI40064143068](https://github.com/Emint76/phase-tool-next/actions/runs/40064143068)
attempt1, HEAD `cf1e4a07f2bfd7ea25104ee3a82ad5a1423e4203`, tree
`073b1df6e04e01b85acdcd52b502359ab2a379c4`, **FAILED** on both Python3.11/3.12.
Each JUnit XML has 1348 cases: **1332 PASS,15 FAIL,1 existing guard SKIP**.
All 1282 previous identities remain:1267 unchanged, exactly15 PASS to FAIL;
66 added cases pass (58 own methods and8 architecture parameters).

| Python | Original artifact ID | ZIP SHA-256 | ZIP bytes | JUnit XML SHA-256 |
|---|---|---|---:|---|
|3.11|12549005711|211a55815f3da5e065288d063e2da346ed926e9868fba5f28ddbfd7faacb2a1b|78823|ace60ac5b00d4ab50ceeb48fc8e96cafbcc724f217f8964c9d0546542571bf6b|
|3.12|12548399989|c612b7bf87c422edb9814e599683ef0bfbb2dd24a2ff0ebb0538afe51d1470cd|79086|4576c39c2eea938faa8947b3b1bde44064f5a74215a438c9239f6c90913bb0f4|

Post-pytest workflow wheel/sdist, clean installation, CLI/MCP smoke and resource
job did not execute. No new distributions are accepted. This does not assert
that pytest-internal build/install fixtures did not execute.

The original ZIP bytes, full failed logs/XML and source manifests were preserved
through the existing official Phase1.1/ext4 route, separate from candidate code:
run `g-ni-version1-ci-40064143068`, raw SHA-256
`3c629fd3d140800f0db21aa36e91172e46f3332234c12b49438d8b4068221c0f`
(477246 bytes), receipt digest
`sha256:6bbf6442cf525eb2feaa7d801dcda89cd89d2e8e35ef215ca8a72ceb0562eed3`.
Both separate source reviewers independently restored1113 files, checked all
1106 prior files and7 new files with zero missing/drift/extras, strict capsules,
both49-member ZIPs/CRCs, actual XML statuses and previous1282-case comparison.
Each performed fresh separate official readonly inspect and exact raw readback.
These are same-host/toolchain independent agents, not external certification
or a required GitHub reviewer approval. Full internal evidence stays private;
these hashes and IDs identify it without publishing private paths or logs.
Preservation PASS does **not** relabel the failed CI.

## Exact causes and minimal corrections

1. Eleven `NativeChannelTests` fail before constructing the channel: two fixed
   child/parent expected module hashes still name the previous `channel.py`.
   The child correctly rejects the changed module origin/bytes. Replace those
   two explicit trusted expected hashes with the reviewed current channel hash
   `45fbe87261f90f49fccaf2ffcb55428a04e278c49ca1b0998f59e18cf8a6445a`.
   Keep origin, loaded-source attestation, child exit and extra-output checks;
   do not derive the expected pin from an untrusted child.
2. Four legacy `FramedNativeWorkerTests` expose a product regression. A newly
   unconditional pre-READY clock read consumes the old role's clock sequence
   and changes reached timing and primary diagnostic ordering. Restrict the
   supplied-deadline range check to the new version1 role; restore the old
   file1 clock reads/order. Keep the new role's exact framed connection, exact
   integer, finite pre-READY deadline and post-GO checks. Do not change old
   clock fixtures to hide the regression.
3. Strengthen the small noncanonical-GO test: require the actual READY, receive
   deadline and exact binding-mismatch diagnostic as well as zero effects and
   sealed I/O. Preserve all nine original method identities and clock fixtures.
4. Remove one extra final blank line in `installation.py`; its AST is unchanged.
   This corrects the previously reported `git diff --check` warning.

Both reviewers approved these exact source corrections; they remain
**UNEXECUTED** until a separately preserved changed-HEAD CI establishes their
behavior. The original failed run is never rerun or replaced. No new feature,
journal, coordination queue, history owner, guard bypass or contract-limit
increase is part of this correction. Both previous source reviews missed the
legacy clock regression and stale pins; subsequent executable results take
precedence over those reviews.

## Remaining integration and acceptance

The current one-manifest original-intent guard still refuses shared histories
from another contract/manifest. The correction does not solve create-to-version
history. Reuse the existing Core original/receipt/proof owners and trusted
immutable contract bindings; do not filter history or choose a fresh evidence
root to evade it. See [implementation scope](NATIVE_VERSION1_LIFECYCLE_IMPLEMENTATION.md)
and [remaining qualification](FINAL_QUALIFICATION_REMAINING.md).

All six MIX contracts, full REF regression, FULL, real installed native CLI/MCP,
historical native evidence, old-new-old native rollback and final review remain
unverified as applicable. A05 needs a permitted isolated real Windows SYMLINK
fixture; G01 needs the whole executable/dependency lifetime including orphan
worker after MCP exit. No policy/privilege workaround is permitted. FULL stays
unavailable; no supported release or production Hermes switch is authorized by
these software results. Source/Knowledge, append/journal and large-array/history
feature expansion are outside this qualification slice.
