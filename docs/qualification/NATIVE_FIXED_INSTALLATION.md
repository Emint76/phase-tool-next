# Fixed native CLI and MCP installation

These candidate resources connect ordinary scripts and agents to the existing native `_NativeAcceptedLaunch` and Core. They reuse the current contracts, evidence, versions, inspection and recovery rules.

Current admission remains experimental: approved synthetic roots, fixed installation bindings and already prepared per-run inputs. Filling in a request does not admit an arbitrary root, contract, executable or run. Production routes are unchanged. See the [installed functional results](NATIVE_INSTALLED_FUNCTIONAL_RESULTS.md) for the specific artifacts, callers, recovery and runtime return that were exercised. Apply those results only to the documented bindings. File and Bundle selectors may require separate result grants and evidence roots; do not split evidence for the same grant or reuse an incompatible binding. A05/G01 remain NOT_VERIFIED, and release remains an owner decision.

## Prepare one fixed installation

The accepted wheel must contain these package resources:

- `phase_tool/data/native/native_phase_candidate_launcher_v1.py.in`
- `phase_tool/data/native/native_phase_cli_v1.py.in`

The trusted operator uses the existing approved preparation procedure to materialize the launcher as `launcher.py`, the caller as `cli.py`, and the existing fixed configuration as `native-phase.json`. There is no new admission or installation API. One possible versioned layout is:

```text
<I>/artifacts/<ACCEPTED_WHEEL>
<I>/runtime/windows-sdk/site-packages/...
<I>/runtime/windows-sdk/WINDOWS_SDK_MANIFEST_v1.json
<I>/bindings/<ADMITTED_RUN>/windows/{launcher.py,cli.py,native-phase.json}
<I>/bindings/<ADMITTED_RUN>/linux/{launcher.py,native-phase.json}
<O>/<NEW_CALL_CAPTURE_DIRECTORY>
```

`<I>` is the accepted installation; `<O>` is a separate operator-approved diagnostics location outside its code, input, result and evidence roots. Each call needs a new capture directory with an existing ordinary parent. The caller's containment check excludes its own binding directory; correct placement of `<O>` remains the operator's responsibility.

The fixed configuration binds the exact wheel, launcher, accepted Python/Docker/image bytes, private dependency roots, existing container/root identities, contract, admission and prepared scope. Windows and Linux use identical launcher bytes. Relocating the private SDK requires an accepted inventory with its actual paths and the same accepted dependency bytes. Keep the old inventory and runtime available. No global PATH, site processing or dependency download is part of these callers.

The common launcher selects only the existing fixed admission families: File1, File2, Version1, Version2, Bundle1, corrected Bundle2, and the two existing history contexts. The manifest and trusted configuration determine the family. The request cannot select it. Use a newly accepted wheel containing the current adapter and both resources; historical results retain their original wheel and reader bindings.

## Call from an ordinary Windows script

Use the accepted Windows CPython 3.12.10 executable and flags. In PowerShell:

```powershell
& "<PYTHON>" -I -S -B -u "<I>/bindings/<ADMITTED_RUN>/windows/cli.py" execute "<EXECUTE_REQUEST_JSON>" "<O>/<NEW_EXECUTE_CAPTURE>"
& "<PYTHON>" -I -S -B -u "<I>/bindings/<ADMITTED_RUN>/windows/cli.py" inspect "<INSPECT_REQUEST_JSON>" "<O>/<NEW_INSPECT_CAPTURE>"
```

The execute file uses the existing envelope below. Paths name approved prepared inputs on the Linux side. Replace the input name with the name required by the fixed contract. The caller does not stage or copy inputs.

```json
{
  "run_id": "<ADMITTED_RUN>",
  "request": {
    "operation": "execute",
    "candidate_path": "<PREPARED_LINUX_CANDIDATE_JSON>",
    "input_paths": {"<INPUT_NAME>": "<PREPARED_LINUX_INPUT_PATH>"},
    "expected_inputs": null,
    "maximum_candidate_bytes": 1048576
  }
}
```

`expected_inputs` may instead map each input name to `["sha256:<EXPECTED_DIGEST>", byte_count]`, where `byte_count` is a nonnegative integer. Preserve the operator-approved expected values. The CLI envelope includes all five request fields shown. `maximum_candidate_bytes` is a positive integer at most 1048576. An inspect file is exactly:

```json
{"run_id":"<KNOWN_ADMITTED_RUN>","request":{"operation":"inspect"}}
```

Pass `-` instead of the request filename to supply one bounded JSON document on stdin, then close stdin. On complete delivery, stdout contains the actual Core command result as JSON and the process returns its exit code. Nullable, negative and uncertain fields remain unchanged. A fresh capture directory retains `request.json`, `stdout.bin`, `stderr.bin` and `delivery.json`; these are operational diagnostics, separate from canonical Core receipts.

## Call from an MCP agent

Use the genuine MCP SDK stdio client with the same accepted Python and fixed launcher:

```text
command: <PYTHON>
args: [-I, -S, -B, -u, <I>/bindings/<ADMITTED_RUN>/windows/launcher.py, execute-mcp]
```

Initialize the session and read `list_tools`. In the fixed experimental context, this server exposes `phase_execute_prepared` and `phase_inspect`:

| Tool | Arguments |
|---|---|
| `phase_execute_prepared` | Required: `run_id` (string), `candidate_path` (string), `input_paths` (string-to-string map). Optional: `expected_inputs` (the digest/count map above or null; default null), `maximum_candidate_bytes` (positive integer up to 1048576; default 1048576). |
| `phase_inspect` | Required: `run_id` (string). |

Use SDK `call_tool` with those exact argument names. The execute tool takes its arguments directly, without the CLI's outer `request` envelope or `operation` field. Decode the actual tool result; neither a declared `outputSchema` nor `structuredContent` is mandatory for this route. Do not infer success from discovery or successful SDK transport alone. Preserve the returned command fields and original receipt/intent/effect-plan digest bindings.

For a fresh read-only inspection, start a separate standard SDK session with the same command and flags, changing the final role to `inspect-mcp`. That server exposes only unary `phase_inspect(run_id)`. It uses the fixed compatible reader for the same known run.

## Recover an existing corrected Bundle2 publication

For a fixed installation already admitted to corrected Bundle2 recovery, use the same standard SDK command with final role `recovery-mcp`. It exposes `phase_recover_publication` and unary `phase_inspect` with these arguments:

```text
phase_recover_publication(
  run_id="<KNOWN_ADMITTED_RUN>",
  request_id="<RECOVERY_REQUEST_ID>",
  expected_intent_digest="sha256:<ORIGINAL_INTENT_DIGEST>",
  mode="observe"
)
phase_inspect(run_id="<KNOWN_ADMITTED_RUN>")
```

`mode` is optional and defaults to `observe`; its only values are `observe` and `commit_prepared`. Recovery observe may write the existing Core's observation evidence. Use `inspect-mcp`/`phase_inspect` for read-only inspection. `commit_prepared` requests only the existing contract-supported prepared-publication action for the bound original run and intent. Preserve its outcome and inspect the same known run before any further action. This role provides no automatic Version2 rollback or general recovery capability outside the existing corrected Bundle2 contract.

## Inspect uncertainty and return the caller

Incomplete CLI delivery returns exit 50 with diagnostics and no synthetic command result. SDK timeout, cancellation, lost delivery or context closure also does not establish whether a mutation occurred. Preserve the exact known run and captures, then use its compatible fresh read-only inspector before considering any contract-supported recovery. There is no automatic retry. Do not change the key, run, root or timestamp to hide a conflict; an exact retained request and a fresh capture have the existing distinct replay semantics.

CLI/Docker/SDK exit and closed pipes do not prove native worker completion. Keep the original receipt, native creation-HANDLE/finalization proof where applicable, and independent target verification. Standard SDK stdio teardown can use its timed process-tree termination fallback; context closure is not a graceful-exit or quiescence guarantee.

A legitimate later version can make an older run's current-target inspection report a mismatch. Preserve that result and verify retained archive/object bytes and supported history lineage with the exact compatible reader. Returning to the prior immutable caller/runtime/configuration does not undo publications or rewrite evidence. Retain both old and candidate readers, compare data and evidence across the return, and respect each reader's supported scope. A prior runtime without the native capability must retain its honest refusal. See `ROLLBACK.md` for the existing return boundary.
