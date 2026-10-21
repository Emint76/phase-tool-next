# Native mutation session: internal fail-closed gate

This is an internal component, not an admitted Windows storage route.
Implementation readiness, installed native CLI/MCP, contract lifecycle, A05,
G06, MIX and FULL remain **NOT_VERIFIED**. The native executor, root-wide gate derived from original Core intents and
trusted IPC are still required. No separate pending journal is planned; see
[complexity decision](ARCHITECTURE_COMPLEXITY_REVIEW.md).

`NativeMutationIO` now owns one PID/thread-affine, nonreentrant mutation session.
Every changing entry, including mutable opens and namespace flush, passes the
gate before its preconditions, syscall and postconditions. An owned method
error irrevocably seals future mutation ingress while preserving the original
exception and raw events. Reinitializing the session is rejected. Private
effect helpers require an active unsealed session.

Sealing does not cancel an already accepted syscall, erase its effect or
rewrite its result. `sealed_active` means future ingress is revoked while an
accepted call has not yet finished. That call can return its actual result,
including an owned handle. The caller must await completion, stop subsequent
mutating steps, classify the actual outcome and finalize handles once.
Capabilities are cleared when the accepted call ends; no automatic deletion,
retry, handle close or reset is performed by the gate. After the accepted call
finishes, read-only observations and ordinary one-attempt handle finalization
remain available.
State labels alone are not worker-completion or recovery authorization.

A trusted signal handler may only request seal. Reading, hashing or closing a
handle while a call is active can disturb its file pointer or finalization.
This restriction is documented, but enforcement by a complete trusted executor
is **not implemented or qualified**. Arbitrary Python callbacks are outside
this primitive's guarantee boundary.

## Review corrections and actual checks

An unexecuted initial draft deferred seal until call exit. Review found a
request could arrive after its final check but before `finally`, leaving a
pending request while the wrapper returned success. That draft is retained
privately as a rejected source revision. The monotonic implementation has no
deferred request state. An activation check also prevents starting the method
when a seal arrived between initial ingress check and activation.

Further source review corrected a synthetic namespace-flush test fixture and
added a one-time initialization guard. These were source-review findings,
not executed native counterexamples or successful test outcomes.

Eleven new pure tests passed once in 0.008 seconds. They cover owned failures
with exact primary/event retention; seal during an accepted call; rejection of
later ingress; repeated initialization; reentrancy and affinity; simulated
namespace-flush and mutable-open failures; and read-only open/single close after
seal. A deterministic trace test injects reentrant seal at each reached wrapper
source line on the selected path. It does not explore every bytecode
interleaving or constitute an actual Windows race test. No real filesystem OS
call is made through NativeIO/NativeMutationIO; the exercised I/O boundaries
are explicitly mocked or supplied with a fake kernel. The affinity test uses
a real Python thread.

| Exact source | SHA-256 |
| --- | --- |
| `src/phase_tool/mutation/ntfs/mutating.py` | `6dc6fdb2c218de11f4016ea01cad340dfb4d218735420311f7f184671b33a3d8` |
| `tests/test_native_mutation_seal.py` | `7e46645070e20dcabbc2cf13610078d5849348737e52a40dab8e904de2184fa9` |
| Unchanged NativeIO | `41654049dc10f1c2db0f74c847f0a36038b49295c4f02582b959b9c7a0dd0a22` |

The recorded source base was `14fde1d9b4b19d046243d4b8ec87a625400e4508`,
with the two reviewed product/test changes frozen before execution. The base
commit is not substituted for the loaded source hashes. All 82 source-snapshot
members, exact test output and bindings were independently audited with zero
mismatches by a separate agent on the same host/toolchain. This is not external
certification or required GitHub approval.

| Binding | Value |
| --- | --- |
| Source checkpoint | `g-sealed-io-source-1792610330916967200` |
| Source raw SHA-256 | `c5656d391a2cd22bd81a005a966a0c3ec4df2fd8ba6f5d331a4e8cc54034fd1b` |
| Source receipt SHA-256 | `c3889a73fd8dd234f16a6e62d00c2f6bf7ac8d31319af64cefc3b58a8680a848` |
| Test result | `g-seal-unit-result-1792610350879789800` |
| Result raw SHA-256 | `45a2112555800bd0d91805225cb56b0bdfb488b3196f73d2a4a1ee116ceebbef` |
| Result receipt SHA-256 | `242e1fe9f6e5a655b0d4e62481ec29ffe2725dda70c7d19ca9eea3792581b25f` |

Full source, start and result are Evidence/Raw retained through unchanged
isolated Phase 1.1.0/ext4, `file_create.v2@1.0.0`, native receipts and separate
read-only inspect/readback/hash checks. No test was repeated for archival.

Earlier native L1 evidence, including [class65 windows](NATIVE_REPLACE_WINDOW.md),
is bound to the earlier `b1b19...` mutation source. It is not qualification of
this new gate revision. Focused native execution and all
[remaining mandatory tests](FINAL_QUALIFICATION_REMAINING.md) are pending.
Existing provider selection, descriptors, historical bindings and production
Hermes/Phase configuration are unchanged.
