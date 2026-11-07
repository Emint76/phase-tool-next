# Unqualified shared native composition

The V7 candidate composes file_create.v1, publish_new_version.v1 and
file_create.v2 within one complete physical target/evidence/preparation domain.
It is software integration, **not supported NTFS storage**. A05 and G01 remain
NOT_VERIFIED. Production admission remains closed before preparation,
channels, target access and evidence reservation. FULL remains disabled.

## Why these additions are necessary

| Addition | Required distinction | Existing mechanisms reused |
| --- | --- | --- |
| Fixed V7 registry and candidate authority V5 | The changed authority implementation needs its own raw artifact pin; V5/V6 descriptors must remain exact. | Registry trust/package/schema/vocabulary checks; unchanged three current contract packages. |
| Installation manifest 1.4 | One matching executable graph must select the existing three roles on the same physical domain. | Original intent 1.2, grants, Core lifecycle, idempotency, receipts, terminal proof and recovery policies. |
| History-set 1.1 | Historical 1.0 admits exactly two manifest1.2 roles. The new set requires exactly three ordered manifest1.4 roles, with one exact active member. | The same accepted launch-config1.1 envelope and existing original-intent barrier. |
| Launcher source template V3 | Worker context dispatch must recognize the new composition while old launcher bytes remain available. | Existing V3 channel/protocol1.2 for file1/version1 and V4/protocol1.3 for file2; unchanged worker and transfer formats. |
| Extra planned-original checks | A file2 frozen object may exceed the historical 1MiB fallback; declarations alone do not verify its bytes. | Selected full semantic reader, actual bounded hash, exact blob namespace, receipt/intent/validator links and existing inspect refusal. |

There is no new journal, queue, pending/finalized database, history index or
document version store. The existing evidence-root lock and physical-root mutex
remain responsible for their original scopes. Static equalities do not prove
external namespace exclusion, trusted startup, orphan absence or G01.

## Scope and preserved limits

The initial isolated V7 deployment requires its own physically disjoint target
domain. It cannot reuse an old physical root merely by selecting a new evidence
namespace. Old V5/V6 history is not migrated or reinterpreted. Historical
registries/descriptors/templates stay exact and need matching historical wheels.
The new wheel must reject a historical descriptor whose authority hash differs.

File1 remains bounded by 1MiB. Version1 keeps 16MiB limits for payload and
current/archive objects. File2 retains its existing 2GiB bound and bounded
first-pass/replay. Sharing history does not permit version1 over an arbitrary
2GiB file2 result, does not change conflict/timestamp semantics, and does not
qualify bundles, version2, append/journal or Source/Knowledge admission.

## Planned data is not terminal closure

The new branch verifies the exact single-payload blob namespace and calls the
selected role's complete validate_planned, including actual file2 bytes. It
then retains ordinary inspect_run and its native-installation guard.
**A proofless native original still blocks the next operation.** Successful
read-only hash validation neither establishes worker quiescence nor replaces
the existing qualified profile and terminal proof. No active authority from a
different contract is supplied to inspection.

## Verification boundary

New regression sources cover exact three-role bindings, domain/authority/package
substitution, closed real guards, actual Host/ext4 frozen bytes, corruption,
proofless refusal, original-role proof selection, and real cross-process
contention on the existing lock. Native claims projected from Host fixtures and
synthetic lock-finalization faults are labelled explicitly.

These sources are pending ordinary Linux CI execution at preparation time.
They do not execute Windows effects or demonstrate A05/G01/G02, native 2GiB
throughput within30s, positive native CLI/MCP, complete REF/MIX/FULL lifecycle,
native rollback or qualification. Mandatory checks require the later authorized
isolated stand. No merge, supported-function release or production rollout is
permitted by these component results alone.
