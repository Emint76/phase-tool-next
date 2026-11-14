# Possible dispatch without returned effect receipts

This is a Core regression checkpoint, not NTFS route qualification. The actual
run used the audited Linux CI wheel as a source tree with three exact reviewed
overlays. It was not acceptance of an unchanged or clean-installed wheel.
A05, native Core E2E, full REF/MIX/FULL and release remain NOT_VERIFIED.

## Change and existing mechanisms

An internal `BrokerExecutionInterrupted(possible_dispatch=True)` now forces
indeterminate execution, mutation-attempted, recovery-required and retry-forbidden
evidence, even with zero received effect receipts. It retains the originating
PhaseError code when supplied and every received effect receipt. Full OS-error
detail preservation is not established here. Same-key idempotency cannot discharge the unknown
worker using an observation that no bytes are currently present. Legacy failures
before dispatch retain their previous rejected outcome.

Independent inspection strictly verifies the stored empty effect-receipt list
and pre-validation attachments for this exact indeterminate disposition. The
existing generic attachment checks remain strict. No receipt schema or historical
descriptor changes. Multi-effect possible dispatch does not invent progress1.0
`not_started` entries: incomplete finalization stays indeterminate. A native
single-effect executor and root-wide original-intent guard are still required;
this change alone admits no new profile or worker.

## Actual execution and independent verification

Twelve tests passed once in 12.624 seconds, exit zero, no skips, timeout or output
truncation. Real Core, frozen inputs, registry/provider/qualification guard,
qualified ext4 evidence and separate-process inspect were used. Only the lost
broker response was simulated at its response boundary. SourceAdmission appears
only as a synthetic two-effect ext4 regression, with no admission qualification.

Cases cover typed disposition; legacy predispatch failure; zero returned effects;
real publication followed by loss of all receipts; verified known effect with
unknown worker completion; same-key version retry after absent observation;
empty-list attachment tampering; strict generic attachment handling; ordinary
file creation; multi-effect unknown and verified-prefix behavior; and the real
unqualified 9p bind rejected before broker execution. No positive NTFS create
or native worker completion is inferred from these tests.

Separate agents checked source/start/result lineage and actual streams. A
read-only observer independently reread all 200 staged files (1,232,980 bytes)
and 138 fixture files (152,722 bytes): every hash matched the retained manifests.
The observer checked all 12 case labels, real payloads, version old-current/no
archive, rejected retry, actual guard rejection and deliberate tamper fixtures.
Fresh unchanged Phase1.1 inspect/readback of the outer result also matched.
Individual initial inspect subprocess JSON replies were asserted by the tests
but not separately persisted; outer run streams and complete retained fixtures
are the available evidence. Review independence shares host/toolchain; it is not certification or GitHub
required approval. Tests were not replayed for preservation or review.

| Identity | SHA-256 |
|---|---|
| Base Git commit | `8abc107fbd68f68d7225b2e9b1c80fd66530ec57` |
| Audited CI base wheel | `dd7ecc1168584131e3e68fb7258d8a565f885efae99066d12625ab457c46b7ba` |
| `src/phase_tool/core.py` overlay | `5d5951f80d22fb9c40f25ce68046bf47c02f71bd441c7c303690f836268099f8` |
| `src/phase_tool/mutation/broker.py` overlay | `08448ab81240d1641f5d8a5a0eadb4bfb4fa91112d04e950e2d40a50fc10663a` |
| `src/phase_tool/inspection/__init__.py` overlay | `d3c316104b90909042f76361b0cc15d23c9140e70ab68fd67b37885253d86947` |
| `tests/test_core_dispatch.py` | `bc47cc3edb534dabf836c6a3a6e71f48cc3c5622d9603bb518894d71deb2089b` |
| Source checkpoint raw | `eb0a5e378077e45e759ad94bd18e9128bc5933114114c16e443b04be493ab536` |
| Source receipt | `34dd7c74ce5b190b766974e034ce1dd9d1ac4f66793dc653deb635185c72184a` |
| Start raw | `be244ac490dff73b11b961ba892222f092173da87d38b38ae9ddba5e9a8976ac` |
| Start receipt | `dfc6bc2d8f3621c2dcebde5cfbbe57080056bc9348305c58c8b92f95cef0507d` |
| Result raw | `acc3744fb8a677e82325274eec1b878493dbc22becd898aa5748a5d7856580d1` |
| Result receipt | `9268f26b9436c5b0452bff3e6c31e7bc20186f334190f1a33c073f492d90630d` |

Runs: `g-core-dispatch-source-12-1792619539011596600`,
`g-core-dispatch-start-1792619564896455400`,
`g-core-dispatch-result-1792619585437891000`.
All full packets remain private Evidence/Raw on the already supported isolated
Phase1.1/ext4 route, with native receipt, separate read-only inspect and hashes.
The source checkpoint retains 121 file identities with recoverable exact bytes.
Rejected unexecuted drafts remain retained and are not relabelled failed runs.

The next step is the minimal exact native composition and one file publication
through normal Core, receipt and native independent inspect, followed by version
and bundle integration. See [complexity decision](ARCHITECTURE_COMPLEXITY_REVIEW.md)
and [remaining mandatory gates](FINAL_QUALIFICATION_REMAINING.md).
