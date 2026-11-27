# Native Bundle v2 recovery: known committed target

These are functional observations from one isolated synthetic Windows NTFS case using the existing Phase Core and its contract recovery path. They do not qualify a storage environment. Production configurations were not changed.

## Exact implementation and original outcome

The case used the retained candidate wheel SHA-256 `f1d8cd082df8e72243578d389ce40ea717ae09d744d5542d3da183bdb1e85128` and fixed launcher `f829270b5b1bc4cc562947138ab56f8f2332a095bbde6945a626f286384e0ec2`. This is the historical H218 artifact, not the newer CI136 wheel. Its original interrupted execution remains a negative result: exit 40 and no original receipt. The previously completed prepared-publication commit was not repeated.

The saved native commit proof file remains SHA-256 `8199083547087d626d259bf2de28bc95ee341bbd349173b1aa7c605f3854bc6d`; the continuation receipt file remains SHA-256 `1633f974d6d71ecfa5eb3271d77e82077860ff60eedc4f37a93999b3a9a427cd`. Recovery does not replace the original negative execution record with success.

## Two further real MCP calls

Each call used a separate genuine Windows MCP SDK session, including initialize, tools/list and one phase_recover_publication call, followed by closed server/client contexts and process exit 0. The original run, request and expected intent bindings were unchanged.

1. Omitted mode exercised the tool default `observe`.
2. After a successful read-only postflight, `mode=commit_prepared` exercised the existing saved-proof branch again.

Both results were `verified_existing`, target_verified=true, commit_finalization_verified=true and recovery_mutation_attempted=false. Neither returned a new mutation-worker response or an original receipt. The repeated request observed the already committed bundle through the existing recovery implementation. It did not publish a second bundle.

Full read-only snapshots before, between and after the calls confirmed that all 26 prior files (863020 logical bytes) remained byte-identical, including the saved proof and continuation receipt. The seven target bodies, full target File ID and canonical owner were unchanged; the old prepared stage remained absent. Exactly two new content-addressed observation records were added, with digests:

- `sha256:d7d6b040b02ab727c8601d7d5f9fc8c774db9be49bb76610578eb09dd73de7fa`
- `sha256:8fa8b3c0301ca45f9f89b3aff284185dc2c33024a1f340c9aaec40000d7347da`

The final read-only postflight report is SHA-256 `e8fe8b61391a709ebc908bc26e55cbc3b9481200902e3fc75b521c3e3af82a67`. Complete private evidence is preserved separately through the approved Phase/ext4 checkpoint route. The public report omits host paths, profiles and internal logs. Independent host review of the closed SDK frames, original evidence and three target snapshots passed: report SHA-256 `f538f6a5d8d9ba4049dd1a4d070ae5fac3f95cb399a495ef2757a2483e309df0`. This review used shared-host captures; it was not a second physical execution.

## Boundary

This verifies follow-up observation and a repeat request when the exact valid commit proof already exists. It does not demonstrate a second first-commit, automatic recovery under every interruption, global exclusion of privileged writers, or a native stable-1.1.0 rollback. A05, G01 and full environment qualification remain NOT_VERIFIED. No supported NTFS release or production rollout follows from this result alone.
