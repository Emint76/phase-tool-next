# NTFS extension: complexity decision and first Core path

Status: implementation work, not NTFS qualification. Reference is immutable
v1.1.0/5ba874f; this decision was reviewed against candidate HEAD8abc107.
A05, complete MIX, FULL and release acceptance remain NOT_VERIFIED. No existing
production route, descriptor, historical binding or document-version semantics
are changed by this decision.

## Decision

Keep one Phase lifecycle and one owner of execution evidence. Reuse the original
Core intent, receipt, evidence store, idempotency and contract-specific recovery.
Do not build the proposed second coordination-intent/head/generation journal,
separate ext4 store, or FIFO scheduler. The unreleased pure pending-lane model
is an archived prototype and was removed from the active candidate; its
source, 16-test result and rejected alternatives remain in Git/Phase history.
The private ext4 pin and its unexecuted test drafts are preserved research,
not prerequisites for the first native Core scenario.

Document history remains owned by existing publish_new_version contracts:
archive_then_publish and object_store_publish. Coordination never creates
document versions, a second version number, or a parallel history index.

## Component necessity and reuse

| Proposed component | Concrete guarantee / failure | Existing mechanism and smallest decision |
|---|---|---|
| Native namespace/file primitive | The exact tested 9p directory renameat2(NOREPLACE) returned EINVAL; a descriptor cannot make that primitive work. HANDLE identity/no-reparse checks must survive name replacement. | Core is a lifecycle coordinator, not an OS implementation. Retain the bounded native physical component and exact Windows root/ancestor pins; reuse existing contract plans and effect semantics. No broad 9p admission. |
| Trusted native root/composition binding | Linux path/dev/inode does not express NTFS VolumeGUID/full FileID, grant ancestry, the complete current+objects footprint or the remote implementation. An alias or another evidence root must not hide unresolved work. | Extend the ORIGINAL Phase intent through a closed versioned binding/schema selected by installation code. Bind exact artifacts and one qualified evidence identity. Do not put native IDs into legacy POSIX fields or create a second coordination intent. |
| Windows root mutex | Linux Core may die and release flock while its Windows worker is still able to write. A new key/locator must not race that worker. | Reuse the target-root-lock role with the native mutex implementation and stable physical keys; take all footprint mutexes in fixed order. Last-handle disappearance is not proof of a clean prior operation. |
| Mutation-session seal | A caught native I/O/postcheck failure must stop later mutations; revocation cannot cancel an already accepted syscall. | Keep the small internal monotonic session gate. It is neither durable recovery authority nor proof that the worker has ended. |
| Bounded native executor/IPC | EOF/timeout can occur after physical mutation but before the effect receipt reaches Core. A success response without completed worker finalization can leave a late writer. | Add one typed, bounded operation worker and a separate read-only observation operation, bound to the exact original intent/run/artifacts/roots. Reuse frozen inputs and Core receipts. No shell bridge, generic service or caller-selected provider. Completion/quiescence must be evidenced; unknown stays blocked. |
| Durable unresolved-operation guard | Current idempotency checks only the same key+scope; another key/locator bypasses it. Current absent bytes cannot prove an old worker stopped. | Under a stable installation-owned operational lock, scan ORIGINAL native intents/receipts/recovery evidence before idempotency or result reuse. An execution intent without a verified permitted resolution blocks new native work. Initially use O(n) scans, no mutable authoritative index. |
| Operational lock | Concurrent coordinators must atomically check unresolved work and begin execution across the full admitted footprint. | One bounded shared lock for the first native contour is enough. Harden the existing lock role only where required: stable owned identity, one-attempt/unknown finalization, no ignored unlock error for this new role. This is mutual exclusion, not a FIFO queue. |
| Separate PENDING/FINALIZED journal and head/generations | Would repeat dispatch/open/closed state, artifact references and lineage already held in durable Core evidence. | Do not implement it. Derive unresolved state from Core evidence. No commissioning/reset path, second truth source, manual FINALIZED proposal or head-rollback machinery in this delivery. |
| New private ext4 pin/store | No concrete deficiency in the already accepted qualified-ext4 EvidenceStore model requires another store for the first E2E. | Reuse EvidenceStore immutable publication/fsync helpers and the existing ownership boundary. Handle a reproducible store defect separately. Do not execute the optional pin's latest 25-case private test draft (V3, hash a532ceba; earlier V2 had 24) just to advance the NTFS milestone. |
| Native independent inspect | Existing inspector constructs the POSIX host authority; it cannot treat a Windows HANDLE/remote reference as an integer POSIX FD. | Add the exact native observer behind the trusted composition selector; preserve receipt/intent checks, expected hashes, native identities and name checks. Run it in a separate read-only process. |
| Global queue / generic recovery / history index | No demonstrated NTFS requirement. They add scheduling or a second product lifecycle. | Excluded. A derived performance index may be a future task only if measurement shows Core evidence scans are too expensive. It must never become authority or hide negative evidence. |

## Source evidence for the decision

- `src/phase_tool/core.py`: `_intent` binds candidate, frozen inputs, write scope,
  plan and implementation; `_run_after_idempotency_binding` saves immutable
  intent before `EffectBroker.execute`. `_check_idempotency` currently filters
  key/scope and admits some negative observations; it is not a root-wide guard.
- `src/phase_tool/evidence/__init__.py`: `EvidenceStore.write_canonical` and
  `_write_bytes_exclusive_atomic` already publish complete immutable, synced
  evidence. Reuse them instead of adding a second persistence protocol.
- `src/phase_tool/planning/__init__.py`: `root_identity_records` currently binds
  POSIX resolved path/device/inode. It must not silently become native identity.
- `src/phase_tool/mutation/authority.py`: authorities return integer descriptors;
  existing physical engines call POSIX write/fsync. The remote/native boundary
  needs an actual implementation, not duck typing around exact-provider checks.
- `src/phase_tool/inspection/__init__.py`: existing binding/attachment checks
  stay strict; native target observation needs an explicitly selected observer.

The separate reviewer checked these conclusions independently from source.
Review shares host/toolchain; it is not external certification or GitHub approval.
Source reasoning does not prove crash, race, durability or NTFS guarantees.

## Minimal implementation order

1. Fix Core's zero-receipt interruption classification and strict inspection.
   An internal possible-dispatch disposition must produce indeterminate,
   mutation-attempted, retry-forbidden, recovery-required evidence even if no
   effect receipt arrived. Inspect must verify the stored empty receipt list and
   pre-validation evidence, not mistake it for a no-effect proof. Existing
   POSIX/historical receipt formats remain valid. Test this through actual Core
   and inspect on the owned ext4 stand; only the lost response is simulated.
2. Add the smallest exact candidate composition/native intent binding, single
   file-create worker and completion proof, native inspector and the unresolved
   intent guard. Reject multi-effect dispatch initially: progress1.0 cannot
   represent an unreceipted possibly-dispatched effect as not_started. This is
   an implementation stage, not acceptance of all six publication contracts.
3. Execute one synthetic NTFS file publication through normal Core, with native
   receipt and separate inspect. Then extend the same path to version updates
   and bundles by reusing their current lifecycle and preconditions. Do not
   implement new document-version contracts or increase size/member limits.

The original qualification program permits a separate, versioned candidate
test-installation/schema (`IMPLEMENTATION_IMPLICATIONS.md`, candidate admission
section). It must be selected by closed trusted installation code, bound to its
own campaign and exact roots/artifacts, and remain externally NOT_VERIFIED.
Unknown or nonmatching native configurations must still fail their normal guard;
existing POSIX admission remains unchanged.
No monkeypatched predicate, permissive provider check, test bypass flag or
false production provided-guarantees claim is acceptable. The known failing 9p
primitive stays unsupported; A05 stays NOT_VERIFIED. Candidate measurements do
not authorize support claims, merge or release before final acceptance.

At this checkpoint, native Core E2E has NOT run: exact native composition,
binding, fenced executor/completion and independent native inspector are still
required. Existing native primitive successes are not substituted for it.

## Minimum schema changes, checked against source64d81

The current implementation-binding v1 is closed, not arbitrary JSON. Its
authority/profile/provider shape and receipt1.0 can remain unchanged. Native
grants, transport, evidence/preparation identity and installed execution/observer
roles belong in one new closed binding within originalintent1.2 and a new
contract package generation. Use genuine VolumeGUID/full native IDs for native
idempotency, never synthetic POSIX device/inode records.

The current guarantee-profile schema fixes the artifact to posix/authority.py
and classification to production; the registry resolves that schema and checks
one file. A new versioned profile schema/descriptor and explicit registry
dispatch must verify the full executable graph and loaded origins. Preserve
the old schema/bindings and the guarantee-coverage verifier. No qualification
profile may claim untested guarantees simply because it is a test profile.

The exclusive_create_v1 logical descriptor names effect_broker_builtin, so it
does not inherently need a new logical mechanism binding when semantics, limits
and authority usage stay identical. Exact Core artifact and native provider
identity distinguish the implementation. This conclusion does not admit v2,
versions or bundles; the current physical step still has the existing1MiB scope.

Completion digest does not exist before execution. Original intent binds the
expected protocol/configuration; receipt attachment_digests binds actual
completion and read-only observations, checked against run/intent/plan/effect/
native binding. Require those attachments only for the new intent/contract
generation; historical evidence retains its exact validation path. An absent
target never resolves unknown dispatch or authorizes replay.

Separate architecture review checked these source constraints. The new
[borrowed-pipe channel](NATIVE_CHANNEL.md) has no FD acquisition/finalization
subsystem, persistent state, service or queue; the entrypoint owns its pipes.
It is unselected control transport, not a completed Core installation.

## First worker and current admission boundary

Keep the ORIGINAL durable intent before one owned worker. A separate prestart
prepare frame, predeclared PID/time/boot subsystem or worker journal is unnecessary
for the first file-create/recovery_none path. Loss leaves the original intent
blocking later mutations; read-only inspection does not unlock it. Retained
process-handle exit proof is required for normal completion, and is not a second
operation lifecycle. See the unselected [worker](NATIVE_WORKER.md).

A05 belongs to G01 in the original guarantee matrix. Its unavailable Windows
SYMLINK case therefore blocks honest G01 admission as well as final qualification.
A qualification_candidate classification cannot manufacture provided guarantees.
Develop independent worker/observer/binding/refusal components meanwhile; keep
positive Core NTFS E2E NOT_VERIFIED until required evidence exists. No weaker
contract, guard exception or reassignment of A05 only to G04 is introduced.

The unselected [retained-process witness](NATIVE_PROCESS_WITNESS.md) is a small
part of the executor/completion row above. Two own synthetic Windows children
tested positive process-object exit, including raw exit259, without target writes.
It adds no persistent coordination component and does not yet compose the worker,
Core receipt or native inspector. Those integration requirements remain pending.

The unselected [Windows byte-pipe helper](NATIVE_WINDOWS_PIPE.md) fills only the
bounded-IPC part of the existing executor row. It reuses CPython nonblocking
pipe support, has no resource-acquisition/cancellation subsystem and owns no
durable operation state. Four owned pipe-only cases do not replace ordinary
Core contract execution, native inspect or missing qualification evidence.


## Bounded experiment admission correction

The closed admission document is an attachment of the existing EvidenceStore;
its hash also identifies the installation. It binds the run, target/root and
frozen inputs so an experimental result cannot be mistaken for qualified
production evidence. Normal guards do not accept it implicitly.

The experimental authority subclass reuses existing effects and finalizers.
Linux-only authority imports are separated from shared admission data because
Windows has no fcntl module; a real Windows import attempt demonstrated that
failure. This is a platform import boundary, not another backend, Core or state
owner. Exact mechanism binding uses id/version/package_digest independently of
the unchanged contract availability/capability metadata. No new journal, queue,
idempotency store, recovery path or document history system is introduced.
