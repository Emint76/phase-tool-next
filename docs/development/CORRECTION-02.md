# PHASE-NEXT-RC01-CORRECTION-02

Correction base: `13d5935a787b02f3bf24056cde89f6f77d3dce25`, tree
`e24aff2d52654019dbc0012b56d8e9e26789ba54`. Full PR base:
`080968f4cd557b9f891a2c2a34268fa8ef11ae98`. Private PR #2,
`feat/unified-file-publication`; descendant commits, no history rewrite.
Candidate: package `1.1.0rc3`, Core/CLI `1.1.0-rc.3`.

## Verification paths

| Path | Before commit / authorization | Existing committed result | Finalization failure |
|---|---|---|---|
| independent inspect | No commit authority; intent-only is not success | Exact-format pre-validator digest; new-format independent preparation/target identity | Does not invent an original successful receipt |
| observe (default) | No target writes; uncommitted stage remains non-success | Same inspect, or missing-receipt verifier; never bypass exact-format evidence bindings | Failed observation/finalization is not success; known effect facts retained |
| missing-receipt verification | Full saved preconditions, fixed inputs, exact plan/run/contract | Bundle bytes/owner plus independent preparation binding for new format | No retrospective original receipt |
| commit_prepared (explicit) | Full saved preconditions; independent binding; complete original stage; durable separate continuation intent; locked broker/mechanism only | Same independent identity, bytes, and continuation consistency; no duplicate rename | Attempt/commit/verification progress survives late broker return/unlock/close errors |

Fast metadata status is deliberately **not** byte-level inspect. Historical receipt
claims remain historical; current target verification requires inspect/recovery.

## C1 — one exact-format evidence binding

A receipt's attachment hash cannot replace the original intent's pre-validator
attachment binding. Intent 1.1 requires that digest in every applicable verifier.
Intent 1.0 retains its actual historical guarantee, without invented fields.
`tests/test_correction02_binding.py` changes pre-validator bytes and the matching
receipt hash while preserving the original intent bytes; inspect and observe must
not report verified success. Missing-receipt and explicit continuation negative
controls must fail without target mutation. Full saved-claim validation remains
separate from current commit-time absence checks.

## C2 — late failures do not erase effects

Progress is owned by the broker/continuation path and carried across fallible
returns and lock finalization. The target attempt is marked at the actual remaining
rename boundary, not on entering recovery. A known commit is distinct from an
attempt whose outcome is unknown, and from later byte verification. Unlock/close
errors remain errors, with original cause and cleanup failures retained; they do
not convert a commit into `attempted=false` or silently turn failure into success.
No blind retry of POSIX close is justified when descriptor ownership is uncertain.
Subprocess injection tests cover unlock and close failures before/after effect,
known commit and unknown attempt, resource cleanup, durable observations, and
safe repeat only after the first process exits. External timeouts are failures,
not product liveness evidence.

Recovery result/observation format **1.1** has `recovery_effect_state`
(`not_attempted|unknown|committed`), `lock_finalization`, and structured
`error_details`. Its additive `recovery-result-1.1.schema.json` validates real
successful/failed public responses and persisted observations. Observation self-links
are omitted to avoid recursive hashes; old observations are not rewritten.

## C3 — original independent preparation checkpoint

New exact `bundle_create.v2@1.1.0` and `mechanism.bundle_create_v2@1.1.0` retain
public `publication_version=2.0` and byte representation `phase_bundle_v1`.
All older exact resources remain unchanged and resolvable. The new package binds
`schemas/preparation-binding.schema.json` (record format 1.0).

After complete stage verification/sync and durable `attachments/prepared-stage.json`,
the original preparation path exclusively creates and syncs the independent
`<run>/preparation-binding.json` **before the original commit syscall**. It binds
the prepared proof digest, original intent digest, run/request/request digest,
plan digest, exact contract, target, and pre-validator digest. Recovery reads this
record; it never creates it or retroactively rewrites the original intent.
An interrupted preparation with missing/invalid mandatory records is not resumable.

The coordinated-substitution test replaces the whole stage with a foreign inode
holding identical member bytes, and updates both `phase-owner.json` and
`attachments/prepared-stage.json`. Original intent and independent binding remain
byte-identical. Because the independent binding pins the original prepared proof,
local self-consistency no longer establishes provenance. A missing, corrupted or
mismatched independent binding fails before target write. Inspection and completion
observation also compare new-format committed identity to this original proof.

**Trust boundary:** the installation controls original run evidence; the test grants
changes to the stage and its two local descriptions, not to the independent run
checkpoint or original intent. This is the existing controlled-evidence model,
not a signature, external trust service, or protection from a privileged adversary
rewriting the whole installation and all independent evidence. Old v2@1.0.0 stages
lack the required generation and receive an explicit unsupported-binding refusal
for `commit_prepared`; historical successful inspect retains historical guarantees.

## Final evidence and capabilities

Final evidence manifest scope is **every regular file recursively under the exact
new final-head evidence directory**, including dot directories and Windows paths
longer than MAX_PATH. The only self-exclusion is its exact root `FINAL-SHA256.json`;
a nested file with that name remains included. Enumeration/read errors fail
finalization. Independent traversal compares the complete relative-path sets, not
just hashes of listed rows, then recomputes every SHA-256. The manifest generator
and its long-path/error regression are retained in the final evidence tooling.
The rc2 manifest omission (139 of 233 files, 94 omitted) is historical and is not
rewritten or treated as complete.

Programmatic capabilities describe actual file/bundle public versions and recovery
modes, without giving status/wait default publication authority. Limits and required
CI jobs are unchanged. Existing B1/B2 and prepared-stage tests remain; B4 is not
reopened, original F04 remains, legacy chunks/reassembly is **NOT_VERIFIED**.

## Gates and handoff

RED/GREEN checkpoint logs are under `ROOT/evidence/RC01-CORRECTION-02/`.
The final exact commit/tree, Python 3.11/3.12 full matrix, wheel/sdist byte checks,
clean installed CLI/MCP smoke, read-only historical checks, measured installed-wheel
resource gates, old-candidate preservation, complete manifest and handoff are under
`ROOT/evidence/RC01-CORRECTION-02/<final-head>/` and
`ROOT/artifacts/RC01/1.1.0rc3-<final-head>/`. No earlier SHA's measurement is labelled
as this package. READY_FOR_REVIEW is conditional on executable final gates, not
this document. Final commit hashes/results remain external to avoid self-reference.

No review agent, merge, auto-merge, release/tag, registry upload, deployment,
working installation/profile/skills/MCP/configuration/budget/protection/visibility
change. Next: separate phase-review of the correction diff from reviewed rc2 and
C1–C3/directly affected guarantees; not a repeated roadmap or bootstrap audit.
