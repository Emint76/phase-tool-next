# Version1 caller-literal seam

DRAFT software component; no native qualification. This adds only closed query1.2
assertions to the existing original-reader exchange before worker dispatch.
Query1.0 and file1 query1.1 remain exact. The accepted fixed version1 manifest is
required; request data cannot select a registry, provider, profile or root.

The existing reader and full version1 parser run first. The new pure check then
compares the exact five-field candidate VALUE, idempotency key, run/intent/effect
and optional frozen payload hash with caller literals. The existing contract owns
deterministic archive/preconditions/continuation; the existing transfer, deadline,
READY/GO and finalizer remain unchanged. No new journal, receipt, queue, version
store, evidence format or recovery is introduced. recover_publication still
excludes publish_new_version.v1.

This slice is not yet selected by a high-level preparation/MCP request: that
wiring and later fresh independent inspect remain next integration work. It must
not be presented as an end-to-end update on NTFS. Seven proposed tests use actual
Host saved plans/full parser and explicitly synthetic native claims; they are
UNEXECUTED until exact new-HEAD CI. No local candidate imports/tests/installs or
Windows API execution. The real native guard is not patched.

A05/G01, native positive CLI/MCP, full REF/MIX family, native rollback and release
remain NOT_VERIFIED. FULL remains disabled. No production/scientific changes.
