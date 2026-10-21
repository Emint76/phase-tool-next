# Native component checkpoint: experimental candidate, no admitted route

Later checkpoints: [native file effects](NATIVE_FILE_EFFECTS.md),
[namespace pins/external replacement](NATIVE_NAMESPACE_SCOPE.md), and
[root coordination](NATIVE_ROOT_COORDINATION.md). The source
table below identifies the earlier kernel-window checkpoint, not every file in
the current candidate tree. No later checkpoint admits a storage route.

Candidate identity: Core SemVer **1.2.0-rc.1**, distribution PEP 440
**1.2.0rc1**. No tag/release is created by this checkpoint. Internal native
primitives are unselected: installation, profiles, registry, provider selection,
entrypoints and the qualification guard remain unchanged. The Docker recipe
still identifies the immutable 1.1.0 reference, not a new candidate container.

## Preserved development state

Before further execution, 32 local files were compared with the independently
re-inspected prior Phase source snapshot. Thirteen had preserved bytes; 19
new/changed files were retained exactly. A historical bytecode cache is Raw,
not a source or trusted implementation artifact.

- Run: `g-resume-source-1792591695662080700`.
- Raw SHA-256: `a452fb917bae40a78ff2c09ca964b204576879af4dcb8855d6853cc36e7a540a`.
- Receipt SHA-256: `27001ee43b2bb5eecd4fa7ec5a9c7c0f32b06313f17cc559fdd551a55a6df9aa`.

Evidence uses unchanged isolated Phase 1.1.0/ext4, `file_create.v2@1.0.0`, with
native receipt and separate read-only inspect/readback, exact SHA-256/length.
This verifies storage, not Source admission or the new route. Full private
evidence is retained separately; public reports exclude personal paths/logs.

## Exact code and actual results

| Artifact | SHA-256 |
| --- | --- |
| NativeIO | `41654049dc10f1c2db0f74c847f0a36038b49295c4f02582b959b9c7a0dd0a22` |
| NativeMutationIO | `3530e17ff7721d257ce5b1e6279cbbf3a4628213f26529008f6baddfa851c764` |
| Kernel V1 | `eba542320cd64783bc9db2b5c03e153240049b2107f26cf319fd99c4bf7e4945` |
| Kernel V2 | `48acdd5e062597f38b9799ad449b9eabc6011e454a8eb40f05e01b1e2b5c88ef` |

NativeIO run `g-native-io-1792583259964296500` completed ten normal checks,
ten metadata-conversion checks and three existing junction/LX fixtures.

Kernel V1 `g-native-kernel-window-1792585045071264100` stays **NOT_VERIFIED**.
The first real call returned `0xC0000280`; its oracle did not recognize that
status, then worker finalization raised a secondary error. Raw retains the
primary oracle error and worker exitcode. EOF follows from the finish/pipe
control flow; a separate worker traceback was not retained in that raw.

Microsoft identifies C0000280 as STATUS_REPARSE_POINT_NOT_RESOLVED and C0000281
as STATUS_DIRECTORY_IS_A_REPARSE_POINT. An initialized zero IOSB does not override
a failing return status. V2 adds those specific denials, per-kind counts and
finish in finalization. Arbitrary access/ABI/resource errors are not accepted.
See [MS-ERREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
and [IO_STATUS_BLOCK](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block).

New V2 run: `g-native-kernel-window-1792592201452419600`.

| Primitive | Positive controls | Reached windows | Kernel denials | Successful window calls |
| --- | ---: | ---: | ---: | ---: |
| open | 10 | 10 | 10 | 0 |
| exclusive create | 10 | 10 | 10 | 0 |
| directory rename | 10 | 10 | 10 | 0 |
| file rename | 10 | 10 | 10 | 0 |
| hardlink | 10 | 10 | 10 | 0 |

Every window returned C0000280 after a separate process converted the exact
pinned parent into a real junction. Outside membership, sentinel bytes and
identity stayed unchanged. All 50 workers exited zero, no forced terminations;
module handle table empty. This establishes prevention in these observed windows,
not post-detection after a successful call.

- Raw: 410085 bytes, SHA-256 `3b4aa737a8e038ebf7590ffe3d475bdfbbb19a2bdb21ea023de673e2bb2a55a3`.
- Receipt SHA-256: `dde4664aef5507927df432fc6da2e6970463e40994ccf1dd7bf03363d9741842`.

Separate agents reviewed exact sources before execution. A read-only result
audit found zero mismatches, decoded six source snapshots and reread 50 control
payloads plus the outside sentinel. Independence is within one host/toolchain,
not external certification or a GitHub approval. Candidate identity/CI transfer
also received separate code review. These primitive runs precede the candidate
foundation commit: they do not qualify its wheel, an executor or future merge HEAD.

## Historical harness layout

These are exact archived sources, not direct checkout execution commands. Their
private replay layout requires sibling `native_io_probe.py`,
`native_kernel_window_probe.py`, `native_rename_probe_v3.py`, `ext4_archive_v2.py`
and `product/native.py` / `product/mutating.py` with the recorded hashes. Product
sources now live in `src/phase_tool/mutation/ntfs/`.

The probes bind their historical campaign and reject existing case directories.
Do not edit old evidence or rerun there. Further execution requires a separately
identified, reviewed harness and fresh owned cases; restoring the layout for
source audit is not an execution or route authorization.

## Remaining gates

**A05 stays NOT_VERIFIED until the mandatory Windows SYMLINK case is actually
performed on an authorized suitable stand.** Generic junction/LX tests do not
replace it. See [stand requirements](A05_STAND_REQUIREMENTS.md).
Post-detection after native success, G06, complete REF/MIX/FULL contract family,
CLI/MCP integration, history compatibility and executed runtime rollback remain
outstanding. There is no release acceptance.

Integration must enforce complete ancestor/name bindings, exact grants and
composite artifacts, target preconditions, sealed effect leases and unknown-outcome
inspection. Physical rename is not CAS. Writable capabilities must not survive
a sealed contract commit. Existing Core lifecycle, limits and historical bindings
are not weakened by these drafts.
