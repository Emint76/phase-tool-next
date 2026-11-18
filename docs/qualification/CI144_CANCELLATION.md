# CI144: retained cancellation and ordinary CI budget

This records an unreleased development checkpoint at commit
32ddf125de6abe80edbf8bd423edc4904dc7ce4c, tree
9fdee890898d62df133806551b687b8655e31dd1, on draft PR #14.
It does not qualify an NTFS route or authorize deployment.

## Observed result

[Run40322090411, attempt1](https://github.com/Emint76/phase-tool-next/actions/runs/40322090411)
ended **cancelled**. GitHub's annotation for Python3.11 job121569299251
states that the job exceeded its maximum execution time of20m0s.
The workflow then had a20-minute POSIX job budget.
This is a CI job timeout, not evidence that native storage is safe or unsafe.

Both uploaded test XMLs contain1824 distinct cases:1823 passed and1 skipped.
All1777 previous case identities and statuses are unchanged from accepted
run40303249475. All47 added cases belong to test_native_bundle_stream and pass.
Their sorted identity-set SHA-256 is
52a08b8bb7a6549f2383be2e453e11fb6219e6e67ca6fd9b1f11c2546fe94a7a
over4751 canonical UTF-8 bytes. The intentional skipped case requires an actual
NTFS campaign bind and provides no positive NTFS evidence.

The new47 cases took0.602s on3.11 and0.413s on3.12. Overall pytest wall times
were1185.12s and675.47s. The3.11 suite alone used19m45s, leaving insufficient
time in that job for the remaining clean-install and installed checks.
The retained3.11 artifact does not establish completion of installed CLI/MCP,
Host rollback or the dependent resource job. The3.12 job completed its
installed steps; those are ordinary Linux results, not native qualification.
**Overall CI acceptance remains false.** A later green run cannot rewrite this
cancelled run or its immutable raw index.

## Exact retained artifacts

Original ZIPs, preserved once through the isolated official Phase/ext4 route:

| Lane | Bytes | SHA-256 |
|---|---:|---|
|3.11|1630097|8664e91939a603895c1a52eaf5e7da0c0c0cb60dd1c4f9fabf78b0a8852d0f6c|
|3.12|1738541|dd8a55f3be616240c8756f5baf1bf44e9ec828921c59a0e08448fb28990b3a57|

Both wheels'248 product files match the exact Git tree. Each of254 RECORD
entries was checked against actual bytes. Both sdists contain the exact248
product,114 test and87 documentation files from that tree. Build manifests
match the actual bytes below. These are retained unreleased build candidates;
package identity alone is not a qualification claim.

| Lane / artifact | Bytes | SHA-256 |
|---|---:|---|
|3.11 wheel|620519|0370e8d546713ad671a008f2979c9a745b3f32f577c0cff936c63fbd25d88c19|
|3.11 sdist|973076|3eb61fcaee00d22de016419dc9533b964c2317ebfdc99ee281685b80aa89ccc3|
|3.12 wheel|620519|1850d2825b97fa87ce489765a312aaf1f6797c1ad81150aee1ef05d6721f055c|
|3.12 sdist|973058|9f35170130f12ec08acd054f08ffec92a38b1bf0a7967049625086927604ffb0|

The covering Phase index is g-ni-bundle-ci-40322090411:
SHA-25655b4fcfbb5c2fba1d2d1f6dc0a7c972e6294c97a45db09abe5974d7e5b927ef9,
268008 bytes, native receipt SHA-256
0a58c2a05f3fc0cc446faba21a2f1963b0bbe9f09de4dcd9b2f5e25c15b09cf7.
Two distinct reviewing agents independently restored all1898 saved sources
and both raw ZIPs, checked the receipt/readback links and performed fresh
official read-only inspections. They share the host/toolchain; this is not
external certification or a GitHub reviewer approval. Full evidence is retained
privately; this report intentionally omits internal paths and complete logs.

## Minimal correction and unchanged scope

Increase only the ordinary POSIX CI job timeout from20 to30 minutes so the
existing complete suite, build, clean installation and installed checks can
finish on a slower runner. Do not remove or shorten any test, race repetition,
resource scenario or acceptance assertion. The separate resource-job timeout
remains25 minutes. A new HEAD requires its own normal CI and exact artifact
audit; neither this timeout change nor an earlier green HEAD supplies that.

A05/G01/G02, native positive CLI/MCP, the full REF/MIX/FULL contract family and
native rollback remain **NOT_VERIFIED**. FULL stays disabled, the native
qualification guard stays closed, and all existing immutable bindings stay
unchanged. No native deadline, file/member/aggregate limit, guarantee, system
policy, production runtime or Hermes setting changes.

The next product step remains the minimal whole Core bundle_create.v1
execute-to-independent-inspect integration, reusing existing intent, receipt,
idempotency and recovery ownership. No parallel journal, queue or version store
is introduced.
