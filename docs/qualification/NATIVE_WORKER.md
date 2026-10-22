# Single-operation native worker: unselected software component

The worker is an internal fixed Windows spawn target. It adds no dispatcher,
CLI, service, queue, storage profile, journal, retry or document-version model.
It is not selected by the default installation. Native publication through Core
remains **NOT_VERIFIED**; no supported route or release is claimed.

Its concrete purpose is to keep the physical file step in one owned process,
bind READY/GO and completion to the original Core operation, and make failures
observable without pretending that a worker can prove its own termination.
The first composition must save the ORIGINAL Core intent before starting any
potential writer. A prestarted worker/PID/boot journal and prepare frame are
unnecessary for this first file-create/recovery_none path.

The future trusted parent must independently read and verify that durable intent,
plan, frozen bytes, installation/grants and complete loaded implementation graph.
It must retain the exact creation process handle, validate readiness and completion,
establish process exit and obtain separate read-only native observation. PID or
creation timestamp alone is not that proof. No such parent is installed here.
`poll(30)` bounds initial frame availability, not complete receipt or OS execution.
Frame limits do not imply cancellation or a hard deadline.

Until exact canonical GO, the worker only checks data and exchanges pipe control;
it does not open NativeIO, target handles or a root mutex. It invokes the existing
single physical file-create step once. Its context is closed and binds run,
original intent, effect plan, native/installation/artifact digests and nonce.
The execute frame carries that context, not a caller-selected implementation.
The trusted caller supplies independently authenticated frozen bytes and grant.

Operation errors, completion/serialization/send errors and endpoint-close errors
are retained separately. One outer finally attempts one endpoint close. A close
failure produces abnormal worker completion even after a preliminary response.
An error-free response or exit code zero does not establish a successful effect;
the physical receipt may be indeterminate. `worker_exit_established` stays false.
After lost Core/parent/completion, the composition must keep unresolved ORIGINAL
intent blocking further mutations across keys/aliases. Read-only inspection must
remain available. Quiescence
alone never authorizes retry or supplies contract recovery.

## Actual pure regressions

Worker SHA-256: `eaf88530d062d577582a0f6fc39b4ea8c0ff03d26965fe7e487ca5411bc2f6ac`.
Test SHA-256: `319f09c047bcb42143ba71d57dfcf4cafc3fa4c3b7d15d4ce0c48f7f1613fa15`.
Audited CI5aa wheel200sources plus worker/test overlays produced202 staged files
in owned ext4. The first run passed **10 tests in0.006s**, exit0, no skip, timeout,
truncation or source drift; fixtures remained empty. Tests used synthetic pipe
and effect results, including independent operation/send/close failures and a
failure while building diagnostic completion. Module origins were checked in
preflight. READY contents/event order were not separately verified by these tests.
This is not a real Windows pipe, process-exit, native I/O or Core qualification.

| Evidence | Run | Raw SHA-256 | Receipt SHA-256 |
|---|---|---|---|
| Source freeze | `g-native-worker-source-20-1792630616919105400` | `fa0fc421cbbca877f9204971a2f1a0c67dfb9fed00aecf8dfe31c494e1bdb064` | `f3a7fd6d0b8b3898f92379f18b5d5c6fd7c3ed147b85246fbd188655ee94582c` |
| Before execution | `g-native-worker-unit-start-1792630641518883800` | `7c3be65051dc2af8f4173665597499638046aecbdb8849c8a76214ac300d257b` | `0f2fe698bfce19f01269c45cdac98f64627ea2e4da0028f8f0b12ef0d2b3eff8` |
| Result | `g-native-worker-unit-result-1792630648848608300` | `9ffe48be2e3045ff2373a109b22c2de496cdec3851ccbc1a2fdf5790ae66e02f` | `aac7099f2dee00924f3872585798cce5ad3895a7b7edcf04f92d0ed328ac2a0c` |

Evidence/Raw is retained through unchanged isolated Phase1.1/ext4, with native
receipts and separate read-only inspect/readback. Rejected source-only drafts
remain preserved: Linux-only import failure; masked transport/close errors;
diagnostic construction bypassing close; and an unexecuted syntax error. They
are not actual native failure runs. Review uses separate agents on the same
host/toolchain, not external certification or GitHub approval.

## Admission remains closed

The original matrix maps A05 to G01 as well as namespace safety. Its missing
Windows SYMLINK fixture leaves A05/G01 **NOT_VERIFIED**; a candidate profile label
does not supply the missing proof. Do not weaken coverage or substitute a weaker
contract to obtain a positive Core demonstration. Existing Core file contracts
must still reject the native route until coverage is honestly established.
Independent software work continues. See [remaining tests](FINAL_QUALIFICATION_REMAINING.md)
and [isolated A05 stand](A05_STAND_REQUIREMENTS.md).
