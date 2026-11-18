# Safe rollback of the NTFS development candidate

No supported NTFS release is asserted. A05, G01, full REF/MIX/FULL and native
old-new-old rollback remain NOT_VERIFIED. Production Phase/Hermes stays unchanged.

## Code rollback

Use a new revert PR under the repository's normal checks and review rules.
Preserve commits, tags and published artifact bytes. Do not rewrite history,
move a tag, replace an asset or automatically roll back document contents.

## Isolated runtime rollback check

`scripts/host_rollback_smoke.py` is an executable CI-only procedure for ordinary
Linux/ext4 Host storage. It requires nonroot CPython3.11 GitHub Actions, fresh
owned children of RUNNER_TEMP, the exact candidate wheel and build identity,
and the existing hash-pinned Linux dependency lock. The CI workflow invokes it;
local developer invocation and production paths are refused. Its initial state
is NOT_EXECUTED until the exact HEAD's retained report is independently verified.

The procedure downloads the existing v1.1.0 wheel, checks317527 bytes and SHA-256
`9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a`,
then installs old -> candidate -> old into one disposable isolated virtualenv.
All dependencies remain pinned; only the exact old Phase line is removed from
the derived dependency-only lock. Each install is checked against every original
wheel source byte and pip check; stale candidate modules after downgrade fail.
Cold subprocesses perform publication, version update/archive, bundle and inspect
through the ordinary Phase CLI. Snapshots retain hashes, lengths and physical
identities of managed target/evidence regular files and directories. Downgrade, old-runtime inspect and
a resumed old-runtime publication must preserve prior objects. Its newly created
file bytes and both source files are independently compared with original bytes. No data deletion
or compensating copy is part of rollback. A sticky failure is retained as failure.

The report is `installed-host-rollback/summary.json` in the exact HEAD's Python3.11
CI artifact, with raw Phase evidence/results alongside. Linux success does not
prove a native Windows worker, Docker NTFS mount or native profile qualified.

## Deployment and data protection

A future controlled deployment must record exact previous package/image digests,
route/configuration and roots before switching. Return to those same immutable
bytes/configuration without changing existing mounts, privileges or global policy.
This task does not switch production. Old v1.1.0 has no supported native profile:
it must refuse writes to new native resources. Do not point the old runtime at
those resources or rename profiles to gain admission. Keep new documents,
archives, receipts and journals, and retain a compatible candidate reader for
later verification. Actual native rollback remains an isolated-stand acceptance
gate before any supported release; Host success cannot close that gate.
