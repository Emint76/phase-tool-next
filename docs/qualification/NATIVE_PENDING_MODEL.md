# Archived native pending-lane prototype: superseded

**Superseded unreleased design.** The active candidate removes the model and its
16 pure tests. Exact source and results below remain in Git/Phase history.
They are historical evidence, not a required storage/coordination architecture.
See [complexity decision](ARCHITECTURE_COMPLEXITY_REVIEW.md): reuse original
Core intents and receipts, with no second intent/head/generation journal.
The following sections describe the archived prototype.

The former `mutation/ntfs/pending.py` provided internal immutable records and structural
transition checks. It does not provide a disk store, admission, dispatch,
recovery authorization or permission to install a FINALIZED head. The native
route, full lifecycle, A05, G06, MIX and FULL remain **NOT_VERIFIED**.

## One coordination lane and complete declared footprint

The first design uses one installation-owned ext4 coordination lane across all
native grants in the bounded contour. This serializes operations conservatively
and allows current and version-object roots to be covered by one PENDING record
before any dispatch. It does not change file, bundle or version limits.

The lane identity includes its admitted physical-root/grant bindings. A
separate coordination intent binds that identity, original Phase run/intent,
plan, frozen-input manifest, composition and the complete **declared** native
root footprint. The future trusted executor must compare that declaration with
the actual contract plan. Shape validation alone cannot establish completeness
or authority. Existing Phase intent/receipt schemas and historical descriptors
are unchanged; this model does not pretend they already bind the new index.

Every coordinator and alias must select the same trusted physical index.
Requests must not choose a lane, create a fresh index through a new label or
evade an unresolved operation using another root. Grant overlap and conflicting
index bindings must be rejected by admission. That enforcement is not yet
implemented by this pure model.

## Closed records and structural checks

The version 1.0 records cover lane identity, coordination intent, immutable
entry and head. Fields and versions are closed; values are frozen, input JSON
is copied into immutable types, and returned dictionaries do not alias records.
Canonical decoding rejects duplicate fields, noncanonical bytes and invalid
types. Its 64 KiB input bound concerns coordination metadata, not result data.

The checked sequence is:

`COMMISSIONED (generation 0) -> PENDING -> FINALIZED -> PENDING`.

Head digest, exact predecessor and consecutive generation are required for
each proposed transition. PENDING rejects a new operation even if it names
another run or admitted root. A commissioning record cannot be linked into an
existing chain. This does not yet prevent disk-level head rollback, orphan
generations or recommissioning a nonempty directory; the store must enforce
those properties with complete history and a stable pinned lock.

The only direct resolution reference variants are `succeeded_verified` and
`failed_no_effect`. Both must eventually be checked against the original
durable receipt, independent full-footprint observation and original-worker
completion. Partial, committed-unverified and indeterminate outcomes cannot be
represented as a direct resolution. No generic recovery-digest or boolean
truth flag closes the operation. Later permitted recovery needs its own exact
versioned proof path.

`finalized_record` builds an immutable **proposal** from references. It does not
read those artifacts or prove their truth, durability, authorization or worker
quiescence. The tests explicitly distinguish a constructed proposal from an
installed head. Digests form an acyclic chain: original Phase intent, separate
coordination intent, PENDING entry, evidence references, FINALIZED entry, head.
The receipt does not refer to a future FINALIZED digest.

## Actual pure checks and preserved evidence

Sixteen new tests passed once in 0.013 seconds. They exercise canonical
roundtrip, declared two-root footprint, linked generations, stale heads, wrong
lane/grant, unresolved PENDING, strict fields/types, immutable values, proof
reference binding and the two direct variants. Test bodies perform model/JSON
work; they do not change files or call native storage primitives. This is not
ext4 durability, IPC, worker-completion or NTFS safety evidence.

| Exact source | SHA-256 |
| --- | --- |
| `src/phase_tool/mutation/ntfs/pending.py` | `981e9e69e1a732a2e2070c316a710890725e30ef88c0802167496d6da2bf3857` |
| `tests/test_native_pending_model.py` | `9c11c1e00c50bdf2281bb8eaeb31cabaf9e396ed4d84c6ba27dbcddd4f46605f` |
| Source checkpoint raw | `5c75d4b203115cb7a36fbfdd7ff0a05697ad7f3126431871a2c302ab277652b4` |
| Source receipt | `bc174bdfc32eec559c6c44b2718f7141e69896ec246b5124fa47e6448d0854df` |
| Result raw | `c37c09ba590ec0f7a7be4d04aab3280208346fc00e9f70105ea2eed287adcfc6` |
| Result receipt | `05b0e8ae5014c1461e083657d4ccf0ad995a95bfe53d95d1ad3c5fb59475758d` |

Source run: `g-pending-model-source-1792612332001728400`; test result:
`g-pending-unit-result-1792612358056954000`. The source base was
`02efc22c91122ec96a75399e1a00fd09d3370ad9` plus the two exact reviewed files.
The source snapshot retains a 93-file manifest, new bytes and checked references
to two earlier complete byte packets. A separate agent recovered all 93 files
and audited source/start/result bindings and actual output with zero mismatches.
Independence shares host/toolchain and is not certification or GitHub approval.

All packets are Evidence/Raw saved through unchanged isolated Phase 1.1.0 on
owned ext4 with native receipt and separate read-only inspect/readback/hashes.
No completed tests were replayed for preservation. Full evidence remains
private; this document contains synthetic summaries only.

The next active integration reuses the original Core intent, receipt and qualified
ext4 EvidenceStore under one operational lock, with a root-wide unresolved-intent
scan and native worker completion proof. It does not install this prototype's
journal or mutable head. A derived performance index is a separate future task,
[issue #15](https://github.com/Emint76/phase-tool-next/issues/15), conditional on
measurement. See the [complexity decision](ARCHITECTURE_COMPLEXITY_REVIEW.md)
and [mandatory remaining tests](FINAL_QUALIFICATION_REMAINING.md). Production
Phase/Hermes and global Windows/Docker settings are unchanged.
