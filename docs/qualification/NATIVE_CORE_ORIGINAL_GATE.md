# Original-intent refusal barrier in Core

This unselected component is preparation for native integration, not an admitted
NTFS route. Normal PhaseCore.run, Host installation, contracts, registry defaults,
qualification guard and version ownership remain unchanged. A05/G01 and native
Core E2E, MIX/FULL, native rollback and supported release remain NOT_VERIFIED.

The existing per-key idempotency check cannot exclude a late worker from a prior
operation with another key. The native entrypoint therefore needs one common
critical section before EvidenceStore reserves a run, held through original
intent, possible dispatch, retained-process quiescence and final evidence. The
private `_guard_native_original_intents(read_binding)` implements the refusal/
locking part only. It yields None and never grants GO or an authority object.

| Component | Failure addressed | Existing mechanism reused |
|---|---|---|
| Fixed common lock | Two run/key/installation labels otherwise race past a history scan | Core _OperationalFileLock and evidence.operational_lock_path, one code-owned purpose SHA |
| Strict original scan | Missing receipts, reservations or orphan evidence must not look like empty/safe history | Existing runs/intent/receipt namespaces, exact package schemas and registry, metadata-only inspect for planned originals |
| Static expectation projection | The prior intent cannot supply both the observed and independent deployment configuration | Existing frozen read binding/parser expectations, factored once; not a new installation service |
| Identity checks | Replaced/missing history must not be silently recreated or accepted | Existing actual Linux/ext4 qualification, installed evidence device/inode, no-follow safe objects |

There is no PENDING/FINALIZED database, new journal, index, queue, head, document
history or recovery protocol. Existing intents and receipts remain the original
execution evidence. EvidenceStore's exact pre-intent quarantine may remain;
ordinary unclosed reservations refuse. A known exact Core rejection without an
intent is accepted only with strict not-executed/no-mutation/no-result/no-effects/
null-intent/finalized semantics, no prior reuse or unknown dispatch, and the
complete actual SHA set of the allowed pre-operation attachments.

Every execution_requested=True native original still refuses, even with an
apparently terminal receipt. Its native observer, retained-worker quiescence,
receipt closure and contract-permitted recovery are not implemented by this
barrier. No POSIX observer is called for those native targets. Exit code, EOF,
no-effect observations or arbitrary reset cannot close them. A planned original without its exact validated_planned receipt also refuses,
because missing-receipt inspect can invoke state/recovery hooks. With its receipt
it can only pass the existing package/profile coverage checks; a synthetic missing
profile continues to reject. The True-only original task parser stays unchanged.

The evidence namespace must be preprovisioned: this helper does not recreate a
missing `.phase/runs`. Root/.phase/runs must be owned, non-writable by group/other,
actual qualified ext4 directories with stable identities. Runs and flat controls,
blobs/attachments must be owned regular objects without links, special objects or
ambiguous names. Canonical controls are bounded at 2MiB; the existing file_create.v1 frozen-input
subset remains bounded at 1MiB; no history/file-count
limit is introduced. Unsafe or unavailable history refuses, never becomes empty.

These are checks within an exclusive trusted evidence contour, not protection
against a privileged hostile evidence owner. All coordinators and aliases for
any overlapping native roots must share the same physical evidence root/lock.
The future trusted composition must exclude separately configured evidence roots
and uncoordinated Host writers. Static hashes only correlate data; they do not
authenticate startup, loaded code or a Docker daemon. There is no request flag,
provider replacement, selector, MCP endpoint or user-reset facility for this API.

The fixture tests exercise actual qualified ext4 with synthetic bytes only.
Two processes must observe a real failed nonblocking flock on the same inode
before release; a started child or missed window is not success. CI retains a
small contention observation alongside its normal evidence. These tests do not
exercise Windows syscalls, native publication or security qualification. The
regular suite continues to exercise existing ext4 lifecycle and installation.
Failure-only fixtures call real lock cleanup once, then inject an exit failure;
the original scan/body error stays primary with its secondary diagnostic. A
successful body followed by cleanup failure must still fail. These are explicit
synthetic failure oracles, not observed native failures or admission evidence.

Next integration must add the trusted selector/supervision and genuine native
observer/receipt closure, and satisfy the unchanged admission requirements.
Missing Windows SYMLINK privileges remain a separate NOT_VERIFIED security case;
this refusal component neither substitutes for it nor enables a supported route.
