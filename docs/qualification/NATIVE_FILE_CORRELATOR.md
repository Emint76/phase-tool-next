# Fixed file1 publication correlation candidate

Status: software implementation candidate; native route NOT_VERIFIED and disabled.
A05/G01 and the complete native contract-family qualification remain open.
This document adds no installation authority and is not a supported NTFS release.

The prepared MCP server adds phase_publish_file for the fixed file_create.v1@1.0.0
binding and fixed accepted installation. Its arguments are run_id, source_locator,
target_locator, request_id and optional expected_digest. It accepts no registry,
provider, roots, profile or contract selector. Locators stay within the existing
preparation and result projections; actual qualification remains mandatory before
any native channel, source/preparation access or Core operation.

The three existing raw prepared APIs retain their signatures and raw results.
The separate legacy read-only server still exposes only unary phase_inspect.
Host publish_file and its native-refusal behavior stay unchanged.

## Existing ownership reused

The same finite MCP call owner holds one nonblocking gate across execute and one
fresh read-only inspect. The existing accepted launcher, parent finalization,
framed command validators, CURRENT-reference validator and channel seal remain
responsible for native delivery. Core alone owns intent, plan, effects, durable
receipts, idempotency and recovery. There is no new durable journal, queue,
PENDING/FINALIZED protocol, history walker or document-version owner.

Two small pure functions project the validated execute ACK and correlate the
existing seven evidence fields against the fresh inspection. A single transient
reference retains the original ACK before models, serialization or another
invocation can fail. The same actual launch is retained until checked parent
completion AND high-level outcome classification. This transient reference is
necessary because a schema-valid nullable/partial ACK can still be indeterminate;
it is not durable recovery, process lifetime proof or a replacement for receipts.
G01 namespace/lifetime/orphan qualification remains NOT_VERIFIED.

Execute target_verified=None is normal. Only the fresh inspect may establish
True. The 1.1 inspection request and result frame require the CURRENT execute
receipt digest and the existing closed canonical reference; a prior reused
receipt is not substituted. The original nullable intent/plan/mutation facts are
preserved. The high-level result uses the existing PublishFileResult schema.

## Failure handling

| Observed boundary | High-level result |
| --- | --- |
| Known prewrite refusal with mutation False | rejected_before_write/10, no inspect |
| Typed uncertainty, exit40, nullable mutation or failed possible mutation | indeterminate/40, no inspect; owner unavailable and same launch retained |
| Positive ACK followed by failed inspection, correlation, seal, model or serialization | committed_unverified/30; original ACK fields retained, no success |
| All checks and gate release complete | verified/0 with fresh content digest/length |
| Secondary gate release failure | suppress verified and preserve the first error; gate error only when there was no prior error |

An unobserved SDK/stdio failure after the method returns is unknown delivery.
The adapter cannot recast that failure after its return. Inspect the known run
through a fresh accepted read-only process; never infer permission to rerun.
No new queue or journal is introduced to promise otherwise.

Optional expected_digest=None describes the verified published object. It is
not a claim that a current source was independently reread after an earlier ACK.
Core freezing and version/idempotency semantics are unchanged. File1 remains
limited to1MiB; no size/count limits or guarantee descriptors are raised.

## Software regressions and evidence limits

CI44ccd9c0 had1451 cases in both Python lanes:1446 PASS,4 FAIL,1 SKIP. All four
failures stop at the new Host CURRENT-reference fixture's strict binding predicate.
Exact-source analysis identifies a sufficient package mismatch: the default Host
contract binding differs from the fixed V5 candidate binding. The failing CURRENT
reference JSON was not separately retained; this is source-supported inference,
not a dumped runtime reference. Build/install/rollback/resource jobs
were skipped for that HEAD. Raw failed evidence is retained; a green historical
baseline is not acceptance of this HEAD or of this correction.

The corrected positive fixture constructs real Host Core/app/request using the
SAME existing fixed V5 registry and package binding. The normal Host roots still
pass actual Linux qualification. A negative regression deliberately retains the
default Host binding and requires its native-context rejection. No registry,
trust, validator or qualification guard is patched to make a positive fixture.
The initial source reviews missed that fixture incompatibility; independent
re-review and a new exact-HEAD CI are required.

New tests cover real Host create/reuse and one independent inspect per operation,
closed MCP schema, the unchanged legacy toolset, two fresh launches/four tokens,
CURRENT pinning, seven-field mismatch, typed/nullable/partial ACKs, primary and
secondary errors, model/serialization failures, guard refusal and gate contention.
Protocol/process/OS boundaries in composed tests are explicitly synthetic. A
successful such test is software evidence, not positive Windows/NTFS execution.
At this source revision the corrected/new tests are UNEXECUTED.

## Remaining integration and qualification

Native file2, bundle1/2 and version1/2 high-level integration and full REF/MIX
contract lifecycle remain incomplete. FULL remains disabled. Positive accepted
native CLI/MCP, recovery, namespace/security, real rollback and release-artifact
checks still require an authorized isolated stand. A05 requires a genuine Windows
SYMLINK fixture with safe synthetic target and permitted creation privilege or
precreated fixture; junction/LX_SYMLINK do not substitute. No system policy or
privilege changes are part of this implementation. Production Hermes/Phase are
not switched, and scientific procedures and data are untouched.
