# Corrective native-candidate slice after the first connected CI

Automatic CI [39895056935](https://github.com/Emint76/phase-tool-next/actions/runs/39895056935)
for HEAD224844c completed with **FAILED** acceptance on both Python3.11.17 and
3.12.15. Each actual XML contains1200 unique cases:1184 PASS,15 FAIL and the
single previous unqualified-NTFS-bind skip. These results remain negative.
Workflow build/sdist and installed CLI/MCP smoke steps after pytest were skipped,
as was the resource job. The pre-pytest dependency installation did build/install
a temporary test wheel; it is not an accepted release artifact.

Both exact raw artifact ZIPs and complete XML/log bytes were preserved via the
existing isolated Phase/ext4 route before code corrections. Negative packet
SHA-256 `961b60594cda4644f7e115bbf0712ca20e4c28101d4752def268d2f8a581f852`
(325638 bytes); Phase receipt
`sha256:944ff92a86dc318639242fb3adcba01505ab8e015a204a2d18eb83574dfa7428`.
Two separate agents independently verified both raw ZIPs, all169 packet hashes,
685 source restorations without drift and fresh official read-only inspect.
This verifies preservation, not CI acceptance or native storage qualification.

| Failures | Cause | Minimal correction |
|---|---|---|
|11 control-channel tests | Child provenance harness still expected the previous e254… channel file; the reviewed installed channel is321343… . Child startup aborted before the intended protocol oracle. | Update both exact expected hash literals to the independently reviewed current bytes. Keep the origin/hash gate and all protocol assertions. |
|1 candidate-profile test | Real registry composition defect: schema1.1 file/descriptor dependency exists, but candidate-v2 has no schema entry for its URI. Raw dependency hashes alone did not prove resolver visibility. | Add one exact immutable schema entry in a new candidate-v3 snapshot; preserve default, v1, v2, profile/contract bytes and all existing bindings. |
|1 planned-original refusal test | Inspection now refuses missing native installation before reaching the unavailable profile. | Assert exact `inspection.native_installation_required`; retain the actual unresolved-original guard refusal and no-write checks. |
|1 static-manifest test | Unsupported version2.0 now fails at explicit version dispatch with PhaseError before JSON-schema validation. | Assert exact `ntfs.original_installation_version_unsupported` for that case; preserve all other closed-shape ValidationError controls. |
|1 AST mutation control | Raw whitespace anchor did not match the real Docker argv literal, so mutation was never reached. | Normalize only the test's source input with AST parse/unparse; retain parameter identities, negative mutation and inventory predicate. No synthetic code execution. |

The new snapshot adds the existing profile1.1 schema with its unchanged
`ca05146038ed82205034cdaa7f5d6d4c02fb9ef960e96a362429a69120b342dc`
raw digest. No schema, contract, guarantee descriptor, provider trust or default
registry is rewritten. Existing candidate-v2 remains byte-exact and its failed
profile resolution is an explicit regression fixture. Candidate-v3 still has no
production native profile, provided guarantees or conformance. The actual factory
must keep refusing before channel creation or evidence reservation.

The first failed run also produced positive component evidence: planned-original
6/6, uncertainty9/9, existing ext4 EvidenceIO15/15; candidate registry5 PASS/1 FAIL.
Those are component results, not connected native Core/Windows qualification.
The intended control-channel cases were not verified in that failed run.

Corrections require independent source review, canonical source preservation
before Git transfer and a new automatic CI bound to the corrected HEAD. The old
failed run is never rerun, relabelled or used as green acceptance. The additional
historical-v2 regression is new; mandatory physical repetition counts are not
reduced. No local candidate/native execution or production change is performed.

A05/G01, accepted runtime lifetime, fixed launcher native-inspect exposure,
connected native create/version/bundle/independent inspect, MCP, full six-contract
MIX, FULL and native runtime rollback/release verification remain NOT_VERIFIED.
This correction does not qualify or enable supported NTFS publication.
