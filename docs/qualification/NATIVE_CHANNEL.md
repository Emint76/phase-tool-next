# Internal borrowed-pipe channel: no admitted Core route

The Linux side of a future trusted native composition needs to send a durable
original-intent reference and receive physical observations. Timeout/EOF may
follow dispatch. Reuse Core's possible-dispatch classification and evidence;
do not add another operation journal, queue, idempotency owner or version store.

`mutation/ntfs/channel.py` borrows inherited nonblocking stdin/stdout pipes from
an isolated entrypoint. It does not duplicate/close descriptors or change flags.
The entrypoint exclusively owns them: no stdout logging, competing IO, fork,
descriptor replacement or flag changes. Identity/access/nonblocking checks run
before each actual syscall; those checks cannot distinguish every close/reopen
of the same pipe and do not replace this trusted execution boundary.

One PID/thread owner and a nonreentrant guard protect each channel. Init and
execution consumption are monotonic. The channel sends closed control shapes:
observe_file, or one execute_file_create with run/intent reference only; no
asset payload, executable, grant or arbitrary command is selected by that frame.
Canonical responses must match exact channel/run/sequence/kind/intent; boolean
sequence is rejected. Remote structured errors survive wrapping. Possible
dispatch is sticky before the first possible execution-frame write; no resend.

A logical seal revokes future calls. It does not close pipes, cancel accepted
work or prove EOF/process exit. An ACK is not an effect receipt, authority or
completion proof. A future supervisor must independently authenticate original
intent/plan/frozen inputs and installed grants, establish exact worker exit,
and supply separately bound completion/observation evidence. Abnormal process
loss remains UNKNOWN even if no typed exception was serialized.

The current2MiB control-frame and30s wait bounds apply to this internal single
file protocol, not asset limits or hard OS cancellation. Large file/versions/
bundles must reuse existing streaming/contracts through their later integration;
this component does not claim them. No default CLI/MCP selects this module and
the qualification guard/provider/registry remain unchanged.

## Actual narrow verification

Eleven tests passed once in5.152s, exit0, no skip/timeout/truncation/source drift.
They use actual Linux subprocess pipes and explicitly synthetic peer ACK/errors,
never Windows IO or a Core contract. Tests check successful observe/execute,
consumption/reinit, lost response, boolean sequence, foreign binding, duplicate
JSON, structured remote error, closed payload, wrong-thread/reentrant calls,
changed flags and seal without descriptor close. The C0000280 error in this
protocol test is synthetic, separate from the historical real kernel window.

The actual base is audited CI64d81py311wheel
`7631b21dfa1f824144865adb2ede755440b1ec75bc5819b2aa40603d6daf1546`,
all199Git source files, plus the exact channel and test source (201stagedfiles).
This is source-overlay execution, not clean installed or unchanged-wheel
acceptance. Child interpreters check exact channel/native origin+SHA from fixed
candidate PYTHONPATH and fresh cache contour. Tests assert every child binding;
those per-case bindings are not separately retained as a wire audit.

Several sender writes do not prove deterministically fragmented reads. Maximum
frame, backpressure, real deadline, Windows peer/supervisor, worker completion,
native grant trust and complete Core lifecycle are NOT_VERIFIED by this suite.
Timeout would leave descendant quiescence unknown; reconcile owned processes
before dependent mutations. No timeout occurred in this run.

| Artifact/binding | SHA-256 |
|---|---|
| Channel | `e2546d5767736eb98576765b6d71f483b282ae3c748968bc1152b999ad11d570` |
| Tests | `8c315cc3a4a67345aac1c1f72a51ee68d7de56feafb68cbcb19c64be92569e77` |
| Source18 raw | `9edf1409a43fa92c9f74a3a59f90d0f137324126e7c357ee079aa37b42411318` |
| Source18 receipt | `0bcd0f3b259ead65254622b6cc9b93438ea84b81c6469e0a3d497ad25be51b9e` |
| Result raw | `063f9b21bd9722db3a6f1daa378c6deb6b70c9996e954565c7f632420245883b` |
| Result receipt | `f68bbf740528fd77c6126eb8c08f8513ea67793094e9efa6d43273eb87a35a56` |

Runs: `g-native-channel-unit-source-18-1792626897250604500` and
`g-native-channel-unit-result-1792626942506548300`. Full Evidence/Raw is private,
through unchanged isolated Phase1.1/ext4, native receipt, separate read-only
inspect/readback and hashes. Source reviews used separate agents on the same
host/toolchain; they are not external certification/GitHub approval. Rejected
unexecuted channel V1/test V1 remain privately preserved. A05, mandatory47cases,
composed G01-G03, Core E2E, MIX/FULL and release acceptance remain NOT_VERIFIED.
