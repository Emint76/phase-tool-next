# Explicit Host CI temporary roots

This CI harness adjustment does not qualify an NTFS route or change Phase storage
admission, contracts, providers, registry trust, receipts, or runtime behavior.

## Retained counterexample

At candidate `ce68fb20e9ae9ae2cd81061d342b52ab0efc78ab`, workflow run
`40167967940`, attempt 1, both Python lanes failed. Each retained JUnit document
contains 1,435 cases: 883 passed, 438 failures, 28 errors and 86 skips.
All prior 1,422 identities and the exact 13 new identities remain present.
The seven new resource-harness component tests passed; the six new result
projection tests failed in shared Host qualification setup before their bodies.

The selected fixture paths in these failures were under `/tmp`. The archived
annotations record kernel `7.0.0-1017-azure` and two `stat` lines `ext2/ext3` for
workspace and runner temporary storage. They do not identify the actual failing
`/tmp` mount. A specific filesystem cause, or a single cause for all failures,
has not been established. Later product defects can remain masked by early
qualification refusal. These failed results remain failed.

The complete raw ZIPs and index were retained through the official isolated
Phase/ext4 contour before diagnostics, with receipts, independent inspect and
SHA-256 readback. Public artifact SHA-256:

- Python 3.11: `f86094a3d00cfd725db15bc325c26bb0f924a035ca69c77e1162ea8f99b3520e`
- Python 3.12: `1e6177ccfa29da9943512e00db6055d51ebb2dbfb8035703a1a9def83efeb8ad`
- Private retained index content: `f495e4c82d77c0bdc4395645d914bd247fef12884ac073e63ff4519cc10ea093`
- Index native receipt: `2e614c335bdacf6d6cb2977eca06fd584220fe3fe62b026035d5afca8db41fe0`

## CI stand boundary

Each ordinary Linux CI job creates one fresh disposable `phase-host-test-temp`
leaf under its own runner temporary directory. An existing leaf causes failure.
`TMPDIR` is fixed before test Python starts, and pytest receives an explicit
`--basetemp` child inside that leaf. Pytest may clear that child; execution
evidence remains in a separate sibling root and is uploaded on failure.

Before pytest, the installed candidate's existing Host qualification guard checks
the actual Python-selected temporary root and workspace. The report records
lexical and resolved paths, actual mountinfo-based filesystem values, kernel,
and any qualification error. A temporary-directory fallback or alias is rejected.
The selected runner's complete mountinfo is retained as CI environment evidence.
The runner temporary directory is never assumed to be supported: an unsupported
root fails before the suite, with retained evidence and no alternate route.

This changes test placement and observability only. It adds no allowlist,
filesystem exemption, new skip, assertion relaxation, resource workload reduction,
or product storage mechanism. Subsequent exact-HEAD CI must pass; prior green
results cannot accept the changed candidate. A05, G01 and the native MIX/FULL
qualification remain NOT_VERIFIED; this harness change makes no support claim.
