# Worker lifetime: component results and remaining qualification

The worker-only JobObject component and direct-interpreter image guard have
scoped executable evidence. The composed G01 failure-window campaign and
Windows/NTFS MIX qualification remain **NOT_VERIFIED**. No qualified profile or
registry generation was activated. This report does not claim a Source248
archive: canonical preservation and independent readback remain a delivery gate.

## Existing process ownership with one transient job

The existing parent receives the actual `Popen` worker and constructs its
retained creation-HANDLE witness. Inside the parent's existing `try`,
`worker_pipe` retains an unnamed JobObject owner before fallible initialization,
sets `KILL_ON_JOB_CLOSE` and an active-process limit of one, verifies the
non-inheritable handle and process membership, and only then creates the worker
pipe. Original data, READY and GO follow this boundary. Assignment failure
therefore reaches the existing witness wait and finalization path; it cannot
start another worker or send GO.

The audited fixed physical worker has no legitimate descendant process. The job
is a transient process resource, without a name, durable record, queue or second
execution lifecycle. The Linux Core, original intent, common lock, Windows
worker, evidence, versions and receipts retain their existing owners.

Ordinary finalization requires actual exit through the same retained creation
HANDLE before closing the job and process resources. Known-open job setup
failures can be closed after that exit. A close or ownership failure remains
unknown and cannot become a successful finalization. Unknown originals retain
the existing mutation barrier. Parent death closes its non-inherited job handle
and requests termination of the assigned worker. Job closure, termination,
closed pipes and CLI exit supply neither effect completion nor retry permission.
The platform mechanism is documented in [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

## Native L1 result

The exact reviewed V4 harness completed 31 component cases:

| Case | Count | Actual observations |
| --- | ---: | --- |
| Normal exit | 10 | Worker exit zero through retained creation HANDLE; job and owners closed. |
| Owner death | 10 | Independent duplicated creation HANDLE was live before owner termination, then signalled within the ten-second bound. All ten observed exit zero. |
| Descendant attempt | 10 | Actual child creation attempt refused with WinError1816; no child `Popen` returned. |
| No-job control | 1 | Worker remained live after owner death and a one-second wait; the harness then terminated only its known worker through the same duplicated creation HANDLE and verified exit77. |

The death worker ignored pipe EOF, slept for thirty seconds and would return99.
Thus the early signalled HANDLE, exit different from99 and the no-job control
were the oracle. A nonzero job-close exit was never an API requirement. Zero is
an observed termination code, not evidence of a successful Phase operation.
Measured termination-to-exit samples were zero to sixteen milliseconds at the
available clock resolution. Every captured owner stderr/tail was empty, and all
independently duplicated creation handles were closed.

| Exact component artifact | SHA-256 |
| --- | --- |
| V4 harness | `631f4a7bd8ef10ad434f5b139f16bd4c10192af4744d66572657ddf1736c0da3` |
| V4 raw result | `a787e8aec9cb0ebacef0d374a12627c6d2aee01edf883376de1dc6040480be2d` |
| Separate saved-result assertions | `37c06506c2035b5e36440fc80a409239f73b68583b675c1b3740f2c3432e3a11` |
| Tested `worker_job.py` | `95be0a016762a840474fc90df173773038a84597e67b241b24d9b053f593217e` |

These are process-only L1 controls on the pinned base CPython3.12.10 AMD64
interpreter. They ran no Phase publication, Core intent, NTFS mutation, recovery
or Docker workload. They do not complete G01, C01/C02/C05 or MIX. The later
interpreter guard does not change the tested JobObject primitive; the component
cases were not repeated merely to add that guard.

## Preserved negative attempts

| Attempt | Original result and limitation | Raw result SHA-256 |
| --- | --- | --- |
| V1 | Overall false. Job setup APIs succeeded; the venv-launched worker failed the owner assertion. Its actual child outcome was not emitted, so this run alone does not establish that failure's cause. | `12a52c5081577faf43cb2eed6a0ffcc771e70c241b7caa23970c4faef7723783` |
| V2 | Overall false. One normal case established worker exit0 and closed job, then the harness failed decoding Windows stderr as UTF-8. Those consumed stderr bytes were not retained; this is an explicit raw-data gap. | `79b7ef186d33a4983c827e8aa95a319c7556dd9c71789da4c75ccd9855b25bac` |
| V3 | Overall false. Ten normal controls passed. The first death case reached live pre-wait and actual exit0 in94ms; the harness incorrectly required nonzero exit. No descendant cases ran. | `b5750cb6160bcbcd27b1ef0de7b97373f33f0b9e2d7cb67e7a51db8380bc3418` |

V4 retained raw error bytes as base64 before secondary decoding, bounded output
reads, matched the product's `Popen.returncode` finalization and corrected the
death oracle. Earlier files remain unchanged and false; they were not relabelled.

## Actual interpreter image and redirector refusal

An independent owned-process identity probe demonstrated that the base Python
body PID matched its retained `Popen` creation HANDLE, while the Windows venv
body PID differed from its redirector's HANDLE. Both diagnostic processes exited
zero with empty stderr. The raw result SHA-256 is
`a12e0f7524628cdbfad16c7c8554f5bde0146e10021b6e432efe8f93da4244da`.
A redirector HANDLE cannot prove the Python body's exit or contain that body in
the single-worker job.

Before any contour or worker spawn, the new guard obtains the current process's
actual image using bounded `GetModuleFileNameW(NULL)`, rejects unavailable,
truncated, unterminated and relative results, and requires physical same-file
identity with `sys.executable`. An image/stat failure is a typed refusal; there
is no fallback. This is a consistency check for the selected runtime, without
a claim against arbitrary privileged replacement. See [Microsoft's API semantics](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew).

The actual base interpreter passed. The actual venv body returned
`ntfs.worker_interpreter_redirector_forbidden`; the retained HANDLE/body PID
mismatch was independently captured again. Both probe stderr streams were empty.
Guard probe SHA-256: `52f45275d24a9478a0766a29973310fda93e3be41f316c4830c9f239d16bc10f`.
Its exact `process_witness.py` SHA-256 is
`d40f9a1bb4a3496b376bf3818faa9620356b5f4b340280d962685c3fa803e78e`;
its complete bootstrap snapshot is
`b090bc003197eaf1598daf40f2ab7a03bf61c7f67cae8c51db14e2bb385e439b`.
Later source changes retain their own build identities.

The focused Windows source suite passed **128 checks**, including image API
failure/truncation/mismatch controls, refusal before Popen, Job setup failure
inside parent finalization, delivery, retained-HANDLE and architecture checks.
These tests model native APIs where stated; they are separate from the real
process probes. JUnit SHA-256:
`b3c3c12d957e0bec6958aec725725c764cabd0aaee5bf6925c73b6f7506d15a5`.

## Environment continuity and remaining work

A separate read-only observation after the cases recorded Windows10 build19045,
CPython3.12.10 AMD64 and TokenElevation=0, using only TOKEN_QUERY and the
TokenElevation information class. The base executable SHA-256 was
`4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a`.
Environment record SHA-256:
`5546561633a29d36e8b3f9ce5c76a2d0e9744feae0e1d4fde04a60a097b8d4ee`.
This is an after-case continuity observation, not a fabricated token capture
for each earlier process.

Still required are the composed Core/worker failure windows, disconnect and
orphan behavior, common history and lock admission, exact installed artifact,
six-contract acceptance, independent receipt/inspect/recovery evidence and the
other mandatory program rows. See [remaining qualification](FINAL_QUALIFICATION_REMAINING.md)
and the [MIX checklist](NATIVE_DIRECTORY_MIX_CHECKLIST.md).
Ordinary qualification and production routing remain unchanged. No ACL, global
Windows/Docker policy, production Phase, Hermes or scientific data changed.
