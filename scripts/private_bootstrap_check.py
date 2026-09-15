"""Check bootstrap Git identity/scope, not test success or runtime guarantees."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

BASE = "c4d8285479f90678904f22e5f95927eb46daba01"
BASE_TREE = "807f193a8426f9ba159cdca08076ef1adc01bb14"
ALLOWED = frozenset({
    ".github/workflows/ci.yml",
    ".gitignore",
    "docs/development/PROJECT.md",
    "docs/development/WORKFLOW.md",
    "docs/development/STATE.md",
    "scripts/private_bootstrap_check.py",
})
ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True, encoding="utf-8"
    ).strip()


def check(treeish: str) -> dict:
    if git("rev-parse", "v1.0.0^{commit}") != BASE:
        raise ValueError("baseline tag differs")
    if git("rev-parse", BASE + "^{tree}") != BASE_TREE:
        raise ValueError("baseline tree differs")
    git("merge-base", "--is-ancestor", BASE, "HEAD")
    tree = git("rev-parse", "--verify", treeish + "^{tree}")
    # Diff literal Git trees: worktree EOL conversion cannot hide source changes.
    changes = git("diff", "--name-status", "--no-renames", BASE, tree).splitlines()
    paths = set()
    for change in changes:
        status, path = change.split("\t", 1)
        expected_status = "M" if path in {".github/workflows/ci.yml", ".gitignore"} else "A"
        if path not in ALLOWED or status != expected_status:
            raise ValueError(f"out-of-scope change: {change}")
        paths.add(path)
    if paths != ALLOWED:
        raise ValueError(f"bootstrap path-set differs: {sorted(paths ^ ALLOWED)}")
    git("diff", "--check", BASE, tree)
    return {
        "status": "PASS", "base_commit": BASE, "candidate_tree": tree,
        "changed_paths": sorted(paths), "changed_count": len(paths),
        "product_and_license_blobs_unchanged": True,
        "proof_scope": "Git baseline and six-path bootstrap allowlist only",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--treeish", default="HEAD", help="HEAD or staged tree object")
    args = parser.parse_args()
    print(json.dumps(check(args.treeish), indent=2))


if __name__ == "__main__":
    main()
