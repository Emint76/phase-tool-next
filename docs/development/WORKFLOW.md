# Development workflow

Active task: **PHASE-NEXT-RC01**, scoped by [RC01.md](RC01.md) and [STATE.md](STATE.md).
It authorizes ordinary source/test/document, necessary versioned-contract, CI and
prerelease development in this private checkout. The bootstrap-specific limits
below are historical; merge, release, public publication and production/profile
changes remain forbidden.

Use one bounded `/goal` for one verifiable result and one substantive PR, not a
PR for every small edit. Keep the accepted task text and scope fixed. Changes to
guarantees, scope or acceptance criteria require a separate decision.

Use normal file/Patch/Git tools for authorized development; the installed Phase
lifecycle is not a prerequisite for developing Phase. Do not change runtime code
or working skills during publication. Canonical admission, release and production
deployment require their own authority and explicit approval.

## Layout and publication boundary

`ROOT` is the isolated Phase Next workspace:

- `instance/toolkit/`: this checkout, the only Git publication root;
- `instance/archive/`: empty reserve, outside this checkout;
- `preparation/`, `evidence/bootstrap/`, `artifacts/baseline/`, `scratch/`:
  preparation, command evidence, original release assets and disposable runtimes.

Never stage logs, credentials, environments or research data. Use a literal file
allowlist and verify staged paths, diff, base commit and remote before committing.
The bootstrap branch is `chore/private-bootstrap`, targeting private `main`.
After original import, no new commits go directly to `main`.

`origin` must be `https://github.com/Emint76/phase-tool-next.git`, with
`remote.pushDefault=origin` and `push.default=simple`. The bootstrap checkout has
no public upstream and a local pre-push hook allowing only that exact private URL.
The hook is tested directly against public-URL arguments without a public push.
It is local safety, not server-rights revocation: `--no-verify`, changing config,
or another checkout can bypass it. New checkouts need their own local guard.

## Verification and bounded loop

Observe -> concrete hypothesis -> bounded change -> relevant check -> record.
Repair authorized blocking infrastructure defects; optional improvements do not
extend the goal. A product baseline defect means `BLOCKED_BASELINE`, not permission
to edit Phase, remove tests or weaken warnings. Stop after two consecutive attempts
without new information/progress, or at a rights/scope/foreign-state boundary.

Check the configured and active goal budget read-only; never increase it or
resume/reset it automatically. Textual rules do not prove an enforced runtime cap.
Wait for CI with a bounded program or native process watcher, not LLM timer polls.

The authoritative final-head CI gate is Linux/POSIX, Python 3.11 and 3.12:
`python -m pytest -W error -ra`, wheel+sdist build, clean wheel installation,
`phase --version`, `phase doctor`, `phase contracts list`. Preserve per-step logs,
JUnit counts, commit identity, package hashes and installed-module location.
A checkout's editable install is not wheel evidence. Windows bind mounts do not
prove Linux mutation guarantees. Do not repeat the full local matrix unnecessarily.

CI runs on PR changes and main pushes, not feature-branch pushes; it has read-only
contents permission, a timeout and per-branch cancellation. Artifacts stay in the
private repository. No publish/deploy/release job or billing change is authorized.
Require available main protection (PR plus both checks; no force-push/deletion).
Record an explicit protection gap if the account plan cannot enforce it; do not
buy a plan or invent a second reviewer. Maintainer review is independent and is
not an automated approval or a waiting loop within this bootstrap.
