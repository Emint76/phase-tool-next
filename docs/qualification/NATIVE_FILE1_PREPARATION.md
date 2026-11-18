# Native file1 preparation: candidate software only

This change prepares literal file-create input for the existing fixed native
Core entrypoint. It does not qualify NTFS, implement the high-level
PublishFileResult API, or establish an accepted launcher. A05 and G01 remain
NOT_VERIFIED. An unqualified profile still refuses before source/scratch I/O.

The new closed request has exactly these fields:

```json
{
  "operation": "execute",
  "native_file_publication_request_version": "1.0",
  "source_locator": "incoming/synthetic.bin",
  "target_locator": "synthetic/output.bin",
  "request_id": "synthetic-request",
  "expected_digest": null
}
```

The source namespace is the fixed installation's preparation root on qualified
ext4. No arbitrary source, evidence, preparation or target root is accepted in
the request. The file1 bound remains 1 MiB. Target projections stay lexical:
Linux preparation does not resolve, stat, open or lock an NTFS target.

The existing installation checks the real profile, root identities, ext4,
ownership/modes, descendant mounts and disjoint roots before preparation. Normal
Core admission repeats these checks against its actual prepared request. The
shared checker is on the same installation; it creates no second factory,
admission flag, cached qualification or lifecycle.

Preparation reuses copy_and_hash, revalidate_frozen and the existing canonical
candidate builder. Core receives prepared paths, expected payload digest/length
and exact expected candidate bytes. Core still owns capture, original intent,
idempotency, locking, effects, receipt and recovery. The preparation catch ends
before Core is invoked. Later failure and uncertainty remain the original Core
result, with the existing parent responsible for process/pipe finalization.

Scratch remains available as prepared input on failure or uncertainty. There is
no automatic cleanup, outcome journal, replay worker or retry path in this
wrapper. Existing evidence inspection and original-intent barriers remain
mandatory before any further operation. Namespace checks are point-in-time;
their lifetime protection depends on G01, which this change does not prove.

The original five-field prepared request, raw CommandResult and outer
phase.native.command version 1.0 envelope are unchanged. This new request returns
the raw execute result; it cannot claim high-level publication verification.
Fresh inspect uses the existing separate read-only invocation. A bounded,
explicitly versioned literal publication-facts projection and the high-level
Windows/MCP publication-verification adapter remain unfinished. Native file2 and bundle entrypoints are
also unfinished. No published descriptor, historical binding or receipt schema
is changed by these preparation sources.

New tests are negative software components using static selector/stdio shells.
The real qualification guard is never mocked. They exercise both static registry
generations, refusal before preparation/Core/channel, closed request grammar,
the distinct version name, and rejection of an ordinary Host installation.
They establish neither G01 nor positive native execution. Source review and AST
parsing are not execution; the tests require exact-HEAD CI acceptance.

## Isolated raw MCP bridge, candidate only

The existing fixed prepared MCP server additionally exposes
`phase_execute_file_publication(run_id, source_locator, target_locator,
request_id, expected_digest=null)`. It builds the exact request above and calls
the same finite owner and `_call` as `phase_execute_prepared`. It returns the
unchanged raw Core CommandResult. It is not `phase_publish_file`, does not
implement PublishFileResult and does not claim high-level verification.

Only StrictStr fields and optional null digest are accepted. Caller-selected
roots, paths to candidates, profiles, contracts, versions, operations and maxima
are forbidden MCP arguments. Semantic locator/request/digest checks remain in
existing Core preparation. The adapter performs no source or target I/O.
The legacy inspection-only server still lists only `phase_inspect`; ordinary
CLI/MCP and production Hermes configuration are unchanged.

The same nonblocking call gate refuses contention without a queue. Definite
responses use fresh launch/channel/nonce per call. Typed uncertainty or delivery
failure retains the same actual launch and makes all methods unavailable.
Disconnecting or waiting does not establish worker exit or authorize retry.
Fresh inspect uses the existing read-only invocation with a new accepted
launch/process and nonce. An uncertain owner cannot make that call; use a
separate accepted inspection-only owner/process. Waiting or disconnecting never
resets the uncertain owner. Neither execute nor inspect qualifies an unaccepted
installation or bypasses the real guard.

New tests exercise exact wire/raw-result identity, early shape rejection, both
real profile refusals and SDK StrictStr/extra-forbid/legacy toolsets. Existing
concurrency and uncertainty checks cover the new method through the same owner.
These are software and negative admission components; positive native MCP,
A05/G01, the high-level literal correlation/reuse closure, file2/bundle lifecycle
and native rollback remain NOT_VERIFIED or unfinished as stated above.


## Original reader literal assertion (source-only next slice)

The fixed file1 publication request uses original query1.1 on the same existing
read-executing exchange. Its closed publication_request contains request_id,
target_locator and nullable expected_digest. Query1.0 remains exactly seven
fields for generic prepared, version1 and no-dispatch paths. Query1.1 is forbidden
for version1, planned/no-intent and unknown generations; there is no downgrade.

After the existing real reader and binding parser verify the SAME expected
intent digest, the endpoint reuses _require_file_publication_evidence on the
FULL original intent and plan. This checks the exact candidate built by the
existing publication helper, contract, idempotency key, target and frozen content.
The parsed context/effect and optional expected digest are correlated as well.
Only the existing evidence-root/runtime tail and checked reader process/pipe
finalization permit delivery. The returned five-field tuple, worker wire,
CommandResult, Core lifecycle and receipt formats remain unchanged.

This assertion adds no metadata store, launch state, endpoint, journal, queue or
version owner. An echoed query is consistency under the accepted G01 boundary;
it does not authenticate loaded code. Component mocks exercise protocol and
finalization only. Real guard tests continue to refuse before any evidence
reader/helper. New source tests have not been executed at this draft checkpoint.

Literal assertion is a prerequisite, not a verified high-level PublishFileResult.
Fresh independent inspect and execute/receipt/context correlation are still
required. In particular reused_existing has no current intent/plan or execute
read; it remains an unfinished high-level path. Its future verification must
reuse existing historical receipt/inspect recursion, without inventing a current
original or deriving success only from matching target bytes. A05/G01 and real
positive native CLI/MCP, recovery, rollback and full family qualification remain
NOT_VERIFIED. Production installations are unchanged.


## Caller-pinned fresh inspection candidate

The prepared server keeps the same three tools. Its phase_inspect accepts either
run_id alone (unchanged known-run read) or a coherent file1 group: request_id,
target_locator, required expected_receipt_digest copied from that execute ACK,
and optional expected_digest. The legacy inspection-only server remains unary.
No installed Hermes/default MCP routing changes.

The new closed native inspection wire is version1.0. One pure validator derives
the canonical candidate VALUE profile through the existing publication helper
and optional fixed payload binding; no source/target read or authority choice.
The exact installed file1 contract binding is checked before the factory.
Actual qualification still precedes installation/channel/evidence/target reads.

The existing channel seal owner forwards generic capture assertions through
PhaseApplication and the existing receipt recursion. A successful inspect must
match the CURRENT ACK receipt, including reused_existing; a prior leaf receipt
with identical content is not the current ACK. Receipt mismatch raises inside
the existing try/finally, preserving the primary if sealing also fails. Failed
application results keep their original error. CommandResult and history/proof/
receipt formats stay unchanged. No new owner, history walk, journal or queue.

When the ACK is missing or uncertain, run_id-only inspection remains available
through a separately accepted read-only process. It does not authorize retry
or clear the original uncertain owner's retained launch. Null expected_digest
does not claim an independent read of the CURRENT source file. This remains raw
CommandResult, not PublishFileResult or a complete high-level publisher.

Nine new source-only component methods cover actual Host/Core create/reuse,
caller/content/current-receipt mismatches, primary+seal errors, both real native
guard refusals, owner poisoning, and Linux SDK strict optional arguments. Native
positive execution, A05/G01, full family/FULL and native rollback remain
NOT_VERIFIED. These test methods have not run at the source review checkpoint.
