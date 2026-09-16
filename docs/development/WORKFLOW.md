# Development workflow

The repository is **PUBLIC**. Phase Tool Next **1.1.0 = PUBLIC STABLE RELEASED**;
the current stable release is
[v1.1.0](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0).
Independent review preceded merge; exact-head and post-merge CI are **SUCCESS**.
Published packages are the exact retained reviewed bytes, not rebuilt from the
merge commit. The previous verified prerelease rc5 and its evidence are historical.
Distribution is through GitHub Release assets; no PyPI/TestPyPI publication,
production deployment or working-profile installation has been performed.
See [STATE.md](STATE.md) for provenance. The release cycle is complete;
working-environment rollout/installation and the next roadmap are separate decisions.

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
For this documentation-only cleanup, use `docs/post-release-1.1.0`, targeting
`main` from exact base `5ba874f77e9225aae29e6c84cfc3f776df557c9c`.
Historically, bootstrap used `chore/private-bootstrap` while the repository was private.
After original import, no new commits go directly to `main`.

`origin` must be `https://github.com/Emint76/phase-tool-next.git`, with
`remote.pushDefault=origin` and `push.default=simple`. The bootstrap established
a local pre-push hook allowing only that exact URL, then private and now public.
It was tested against other public-URL arguments without pushing to those repositories.
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
contents permission, a timeout and per-branch cancellation. Verification artifacts
are attached to Actions runs in this public repository. Normal CI builds are test
outputs, not replacements for the frozen stable v1.1.0 or historical rc5 assets. No publish/deploy/release
job or billing change is authorized.
Require available main protection (PR plus both checks; no force-push/deletion).
Record an explicit protection gap if the account plan cannot enforce it; do not
buy a plan or invent a second reviewer. Maintainer review is independent and is
not an automated approval. This cleanup permits one focused documentation commit
and an ordinary merge commit only after a docs-only diff, **CLEAN** PR and green
exact-head CI are verified. No squash, rebase or admin bypass. Verify main and a
clean checkout after merge, with stable and rc5 tags/releases/assets unchanged.
