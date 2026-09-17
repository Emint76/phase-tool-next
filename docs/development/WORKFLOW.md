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
- `preparation/`, `evidence/<task>/`, `artifacts/<task>/`, `scratch/`:
  preparation, task-specific evidence/artifacts and disposable runtimes.
- `evidence/bootstrap/` and `artifacts/baseline/`: preserved historical bootstrap
  evidence and original release assets, not current task output locations.

Never stage logs, credentials, environments or research data. Use a literal file
allowlist and verify staged paths, diff, base commit and remote before committing.
Start a focused branch from the verified current `origin/main`, make the bounded
change, and open a PR targeting `main`. Bind the accepted scope to its exact base;
stop and reassess if that base changes. No new commits go directly to `main`.

`origin` must be `https://github.com/Emint76/phase-tool-next.git`, with
`remote.pushDefault=origin` and `push.default=simple`. Retain the existing local
pre-push guard restricting pushes to that exact URL. This is destination safety,
not a repository-visibility requirement or server-rights revocation: `--no-verify`,
changing config, or another checkout can bypass it. Verify the destination in
every checkout; do not bypass an active guard.

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
not an automated approval. After exact-head CI, review and the accepted task's
gates, use a normal merge commit only when merge is authorized, the scoped diff
is verified, and the PR is **CLEAN/MERGEABLE**. No squash, rebase or admin bypass.
Verify main, a clean checkout and post-merge CI. Development changes do not
authorize changes to existing tags, releases or assets.
