# Internal native file execution and read-only observation

This is an unselected physical component for the minimal future Core path.
It is not an installation, IPC service, grant issuer, new profile, recovery
route or document-version system. Production/default selection and the normal
qualification guard are unchanged. A05, composed G01–G03, native Core E2E and
full REF/MIX/FULL remain NOT_VERIFIED.

## Physical role and limits of this checkpoint

`mutation/ntfs/file_create.py` contains a candidate physical implementation of
one existing file-create-v1 effect:
physical root mutex, native ancestor/leaf pins, FILE_CREATE, positive short-write
loop, file/namespace flush requests, readback and one-attempt handle/mutex
finalization. It reuses the existing effect receipt formatter. The trusted
caller must authenticate the original Core intent and installation grant first.
Existing parents only and the unchanged1MiB content limit apply to this internal
step. Full family support requires the remaining integration and tests.

`observe_file` constructs NativeIO, not mutable IO, and uses native handles/name
checks; there is no Linux or Win32 pathname fallback. A missing-leaf catch is
limited to that leaf's native open. Ancestor failures never become absence.

The new primitive distinguishes a failed NtCreateFile with NULL output from an
unexpected nonNULL output handle. The latter remains unknown even after one
successful close. No known-denial marker hides it. Source review found this
inherited ambiguity; it is a defensive fault model, not an observed NTFS fault.

No effect receipt is fabricated before an observed native create-call result.
Such failures retain structured physical evidence and raise outcome-unavailable;
future relay/Core integration must preserve possible-dispatch uncertainty.
A genuine exclusive-create collision supports failed_no_effect only with NULL
output, native observation and clean finalization. The execution source seals the mutation session during terminal handling.
Those full paths still require native execution/fault qualification; the eight
pure tests below do not execute the whole physical-step function. Unknown
handles/finalization are designed to prevent success, not certified here.

Diagnostic retention does not interrupt positive short writes. Every completed
recorded mutation/flush event contributes to a count and canonical-JSONL digest;
at most64prefix+64suffix records stay in memory. Omitted middle records are
explicit. Capture errors revoke completeness and the complete digest; a partial
hasher value is diagnostic only. This is not every OS syscall or a replacement
for qualification evidence. There is no second persistent journal/store/index.

The physical result explicitly says worker_exit_established=false. A future
bounded supervisor must prove termination of the exact worker before normal
Core can finalize success; EOF or successful JSON alone is insufficient.

## Actual tests, review and preserved failures

Eight new pure fault tests passed once in0.144s, exit0, no skips, timeout,
truncation or source drift. They execute real method/trace code with per-instance
fake NtCreateFile/CloseHandle and a module-local ctypes facade. They perform no
Windows API call or target publication. Cases include known NULL collision,
unexpected nonNULL create/open, failed one-attempt close, success status without
output,64/65/128/129 retention boundaries,5000record retention, serialization
failure/no rehash and bookkeeping failure. Trace tests do not prove real
short-write completion or native filesystem behavior.

The candidate was actual CIabee wheel source plus two exact overlays, not a clean
installed or unchanged wheel. Separate reviewers checked exact source before
execution and actual source/start/result afterwards. A fresh read-only observer
checked all200stagedfiles (1,226,492bytes) and empty fixtures against retained
manifests. Fresh unchanged Phase1.1 inspect/readback of source/start/result passed.
Independence shares host/toolchain; it is not certification or GitHub approval.

Rejected unexecuted executorV1/V2 and runner drafts remain privately preserved.
An initial harness invocation stopped before start/staging because it parsed
GNU binary checksum names incorrectly. That prestart error is retained separately,
not called a failed or successful product test. It did not reduce any repeat count.

| Exact identity | SHA-256 |
|---|---|
| Base commit | `abeece74f966bc6e79e06d6cc136e070747b684a` |
| CI base wheel | `42578e45083418f1ace2954370f157fb8d6df4e69312669d0e062857dec0d396` |
| `mutation/ntfs/mutating.py` | `7151b9c42856fa90b99da877993727276b96595a5a562a6f75b8a2b7067d5c02` |
| `mutation/ntfs/file_create.py` | `d1c462d1069aeb4e4541b6c37b40a1666861726b0bf9648774ce30cce0a89f4f` |
| Tests | `5ac9073855e11b8dff558de7d8bf42023c5043a23937875a7aa1abc061165ffa` |
| Source14 raw | `a574b7cc2b6924b27160747434cfa765cd354496c4edc14311d20047b15f6976` |
| Source14 receipt | `e0a3b67d8a94c221e4be0870bc0fff6092e213b936ad63fa2fc13375ca068a99` |
| Start raw | `b5c6bad6c6476a9a4bffb724ce90e53fb76c7ed07db7720a61e566fbf186c5ec` |
| Start receipt | `b4f644a13f2464ff1e2066b0effdbe9bd04b623ebe5bb5b99a9c3eafd1685189` |
| Result raw | `9b4ae708a9f1d184f2164d777144194c47df770075adab0f72e199fba5ce6791` |
| Result receipt | `62317735da6a0c3932dc245d0fa5b5f5eb4361248f3d0d6c33a2ccf643e0135f` |

Runs: `g-native-file-source-14-1792623163701116000`,
`g-native-file-unit-start-1792623186803091800`,
`g-native-file-unit-result-1792623195095510500`.
Full private Evidence/Raw uses the existing isolated Phase1.1/ext4 route with
native receipts, independent inspect/readback and exact hashes. No raw logs,
private paths or scientific data are published here.

## Actual whole-step L1 smoke at exact source64d81

The whole physical function subsequently ran on three fresh synthetic NTFS
targets, using the exact199-source graph of
`64d81fd91f0be7a880819c53cdd82c5de9675e31` and the unchanged source hashes above.
All three cases passed:0,65,536 and1,048,576bytes. Each created the file and
attempted a genuine conflicting FILE_CREATE with different offered content.
Create returned status/IOS0, information2 and a nonNULL handle. Collisions
returned C0000035 with NULL output, no recorded WriteFile and bytes_written0.
Create-after, collision-before/after and independent full native IDs matched.

Separate Windows observer processes and parent Win32 readers verified bytes and
identity after the mutators ended. All six distinct workers exited0 without
forced termination or primary/finalization error. File/directory flush requests
were accepted and the sibling sentinel inside the synthetic case root stayed
unchanged. Two separate reviewers
read the actual packets and freshly reread all three targets and sentinel; no
test was replayed. Independence remains within the same host/toolchain.

These are three additional component smoke cases, not mandatory B01/B02/C01
completion, concurrency/crash qualification, a normal Core publication or an
installed package acceptance. Product effect receipts are physical observations;
the Phase receipts below archive their evidence through the existing ext4 route.
No Phase Core receipt for the NTFS result was produced. Original MP wire bytes
were not retained, so their recorded digest is diagnostic only; parsed results
are protected by the archived parent packet. API events are instrumentation,
not independent kernel tracing. A05 and the full route remain NOT_VERIFIED.

| Binding | Run | Raw SHA-256 | Receipt SHA-256 |
|---|---|---|---|
| Source17 | `g-native-file-l1-source-17-1792625828393662900` | `bd1bed8cc333245e1c713d65a0bf51f05be4c3bc83609b9afe44aaf8e0a56e6e` | `a4f65b45795b1dbabbaf7dc2702f342d1c0bbc669cec700b07025c5f7c478e18` |
| Start | `g-native-file-step-l1-start-1792625855951180000` | `aeaf4fa8c8d92cf2fb00aa4c79320e740d72e888964d4af4acda1042b471c449` | `670701d7cc6cce3adb4510d0880d4a59c4fbd5b08aeea31baf263b68c8d96c1e` |
| Result | `g-native-file-step-l1-result-1792625869082053500` | `4fb6fca27a0483cafe4b44d14d98ace3021787390eb418f83213bc4161023f06` | `7ac94b3790cd9f949a83f8b2af352c005e0aa386a303b0ab4d20d43099ebcdb4` |

The reviewed L1 harness is
`5d4ba1876dae77da5b8ba53675380ef6cf51403e55935c0f76991d21be8740f1`.
Fresh unchanged Phase1.1 read-only inspect/readback of source/start/result passed.
Two earlier unexecuted harness revisions remain preserved as negative source
review evidence; their finalization/oracle defects were fixed before this run.

Next is the bounded relay/completion and original-intent guard, actual composed
L1 G01–G03, then normal Core file→receipt→native independent inspect. Only proved
guarantees may enter the new qualification profile; no9p allowlist or guard bypass.
Then version/bundle integration follows existing contracts. See
[complexity decision](ARCHITECTURE_COMPLEXITY_REVIEW.md) and
[remaining mandatory cases](FINAL_QUALIFICATION_REMAINING.md).
