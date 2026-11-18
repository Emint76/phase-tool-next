# Independent native inspection candidate

This is source/software integration for the unqualified native file-create candidate. It is not an NTFS storage release. A05 true Windows SYMLINK and G01 accepted executable/namespace lifetime remain NOT_VERIFIED. No production installation is switched.

## One lifecycle and one evidence owner

The executing path remains PhaseApplication -> PhaseCore -> EffectBroker -> the existing native authority/parent/worker -> existing Core evidence and receipt. Independent reading is PhaseApplication.inspect -> inspect_run -> the same authority observe method -> existing Windows NativeIO. The existing reader verifies original intent, contract, registry, immutable installation, hashes, native identity and terminal proof. Missing native receipt remains indeterminate; this role does not perform recovery, target effects, evidence fsync or receipt publication.

There is no new intent, journal, queue, document-version owner, receipt store, PENDING/FINALIZED publication service or alternative recovery path. Existing Core intent/idempotency/recovery remain authoritative. The initial implementation still covers only existing file_create.v1, one exclusive effect, existing parents and the unchanged 1MiB bound. It does not implement publish_new_version or bundle native support.

| Changed component | Required failure boundary | Existing mechanism reused |
| --- | --- | --- |
| Fixed read-only startup mode | Independent inspect has no new executing original or GO to discharge; fresh invocation nonce must not replace historical nonce. Consume GO before requests and independently deny execute/finish. | Same accepted launcher, authority type, protocol observe_file1.1 and finalcommand1.0; existing installation/parser and inspector. |
| Channel-only read seal | Read failure or failed seal must never return a positive inspect. No execution finish/original query is applicable. | Existing irreversible channel revocation and error propagation; no persistent state. |
| Transient MCP call owner | SDK can survive a tool exception while an actual Docker process owner has unknown finalization. Losing that owner and starting more calls is unsafe. Core cannot retain a caller-owned process after SDK exception handling. | Same run_native_parent and retained actual creation handle. One strong reference and a nonqueued call gate; unknown completion makes this adapter unavailable, never kills, retries or starts another owner. |
| New immutable candidate profile/snapshot | Changed authority source requires a new implementation hash without relabelling old bindings. | Existing registry/package resolver, schema, digest/trust checks and mandatory qualification guard. |

## Fixed inputs and delivery

Accepted startup selects literal Windows roles inspect-parent or inspect-mcp and Linux role inspect. The Linux process uses the already identified read-only reader contour; no new container/mount is needed. Installation bytes, roots, registry, wheel/dependencies and commands belong to the externally accepted immutable deployment, never MCP input. A one-shot initial parent request has exactly run_id and request:{operation:inspect}; existing bounded canonical pipe framing applies. Linux repeats the closed request check. The MCP adapter exposes only phase_inspect(run_id), creates a fresh read invocation per completed call, and leaves the ordinary Phase MCP server unchanged.

Both local channel and Windows parent reject execute_file_create and finish_without_execution before wire/dispatch. The bootstrap and all wrong entrypoints reject read mode before spawn/effect. Repeated current/reused historical reads do not consume an executing authority's causal observation slots. Parent validates the final inspect result with the existing command-result schema and fixed registry. Inspection primary errors survive later seal errors; failed observation, framing, transport, serialization, seal, process cleanup or final delivery cannot be reported as successful inspection.

These checks do not authenticate the accepted launcher or establish Windows executable lifetime immutability. The packaged qualified profile remains absent; factory admission fails before channel construction and evidence reservation, even with empty requirements. There is no test flag, fake qualified profile, environment selector or provider substitution.

## Immutable compatibility boundary

Default/Host registry, contracts, production profiles and historical receipts are unchanged. Candidate snapshots v1-v3 and candidate descriptor authority.v1 remain byte-exact. New v4 appends only candidate authority.v2 (implementation1.1.0) with empty guarantees/conformance; it grants no authority. Native contract packages and mechanisms are unchanged.

The registry resolver separately checks the current implementation module bytes. Therefore an old always-unqualified candidate descriptor cannot resolve against the changed authority.py in the new wheel: the correct refusal is guarantee_profile.implementation_digest_mismatch. Its exact matching old wheel remains necessary for historical candidate resolution; do not silently rebind intents/receipts or weaken the resolver. The older v2 snapshot's missing-schema refusal remains earlier and unchanged. Old candidate resolution is not positive native inspection or storage admission. Published old packages/images remain immutable and available.

The sdist now explicitly includes existing nested test helpers, correcting incomplete test-source packaging without changing product behavior.

## Verification and remaining mandatory qualification

Source review is not execution. Pure negative branches, synthetic protocol ACKs, real Linux subprocess pipes, actual SDK negative startup and ordinary Host/ext4 tests are software component checks only. No positive native execution, inspection, target-race, MCP canary or safe native runtime rollback is claimed by them. Exact CI/head/build acceptance and artifact hashes are recorded separately after execution; old green CI cannot accept changed source.

An authorized isolated stand must still execute: A05 true Windows SYMLINK, G01 accepted executable and complete namespace lifetime, native create plus independent inspect, original/reused/missing-receipt/fault cases, real accepted MCP canary, all six MIX publication/version/bundle contracts, relevant concurrency/recovery paths, old-new-old runtime rollback preserving all data, regression and post-release byte checks. FULL is independent NOT_VERIFIED. No append, journal, Source/Knowledge or large-array expansion is qualified here. Original 9p no-replace counterexample and failed native statuses remain negative evidence.

For later A05, provide an owned disposable local NTFS root, synthetic target and an actual Windows SYMLINK reparse tag0xA000000C created by an already authorized fixture owner or a stand already possessing the necessary right. Junction/LX_SYMLINK do not substitute. Record native reparse tag/target, exact NTFS/Windows/Docker transport/build, owner/root boundaries, independently observed outside-target bytes and required repeat/race counts. Use unprivileged test workers and independent observer; never use production data, alter this machine's policies/privileges/ACLs, or count unavailable windows as PASS. Preserve primary and secondary failures. A05 remains NOT_VERIFIED until actual required evidence exists.

Before any future Hermes adoption, qualify the exact deployment and full declared contract family, install in an isolated canary, verify create/update/bundle receipts and independent CLI/MCP inspect, execute the pinned old-new-old rollback, then separately approve switching pcr-rnd roots/runtime. This task does not change the live profile or scientific PCR procedure.
