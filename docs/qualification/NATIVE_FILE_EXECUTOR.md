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

Next is the bounded relay/completion and original-intent guard, actual composed
L1 G01–G03, then normal Core file→receipt→native independent inspect. Only proved
guarantees may enter the new qualification profile; no9p allowlist or guard bypass.
Then version/bundle integration follows existing contracts. See
[complexity decision](ARCHITECTURE_COMPLEXITY_REVIEW.md) and
[remaining mandatory cases](FINAL_QUALIFICATION_REMAINING.md).
