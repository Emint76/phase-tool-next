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

The common launcher selects only the fixed File1, File2, Version1, Version2, Bundle1, corrected Bundle2 and historical bindings. The manifest and trusted configuration determine the family. Materialize both launcher resources from the same accepted wheel. Preserve historical wheels and their reader bindings.

## Publish from an installed Windows input scope

The staged input route is available in an accepted startup 3.0 or 4.0 installation with a bound Windows input scope. Startup 3.0 uses the existing experimental binding. The ordinary owner-directory startup 4.0 requires a qualified fixed catalogue and owner-approved grants. The candidate catalogue remains closed pending qualification.

Use the same accepted Windows executable and caller, with the `publish-input` action:

```powershell
& "<PYTHON>" -I -S -B -u "<I>/bindings/<BINDING>/windows/cli.py" publish-input "<REQUEST_JSON>" "<O>/<NEW_CAPTURE>"
```

Example request for an installed File binding:

```json
{
  "run_id": "publish-example-001",
  "request": {
    "operation": "publish_input",
    "input_scope": "owner.inputs",
    "source_locator": "incoming.bin",
    "target_locator": "results.bin",
    "request_id": "request-example-001",
    "members": null,
    "expected_current_digest": null
  }
}
```

Use the installed input scope ID. The source locator is relative to its bound Windows root. The target locator is relative to the installed result grant. Use slash-delimited relative locators such as `incoming/report.txt`. Choose a stable request ID for the operation and a run ID to identify its evidence. The installed manifest fixes the contract and grants.

| Installed contract | Source and additional arguments |
|---|---|
| File v1 or File v2 | One file, with `members` and `expected_current_digest` set to null. |
| Version v1 or Version v2 | One file, with `members` set to null and `expected_current_digest` set to the SHA-256 of the expected current file. Version v2 requires strict UTF-8 source bytes. |
| Bundle v1 or Bundle v2 | One source directory with an explicit list of relative file locators in `members` and `expected_current_digest` set to null. |

The File bindings also support `publish-file`. Use the same run, input scope, source, target and request identity. Set `operation` to `publish_file`, omit `members` and `expected_current_digest`, and supply `publication_version` (`"1.0"` or `"2.0"`), `expected_digest` for the source bytes, and `root_binding: "phase_result_root"`. The caller asserts this installed grant and digest before publication.

For the standard MCP SDK, use the same launcher with final argument `input-mcp`. Call `phase_publish_input` with `run_id` and the request fields, omitting `operation`. `members` and `expected_current_digest` default to null. File bindings also expose `phase_publish_file` with the corresponding File arguments. In a fresh `inspect-mcp` session call `phase_inspect` with the known `run_id`, or use the CLI `inspect` command below with a fresh capture directory.

### Interpret staged publication results

For `publish-input` and `phase_publish_input`, a successful result is version 1.0 with exit 0, the execute `command_ack`, and an independently verified `independent_inspection` for the same run, receipt, intent and plan. For bundles, `source_digest` and `source_length` describe the canonical bundle manifest. File and Version results use the staged file byte digest and length.

An ordinary startup 4.0 call may return result version 1.1 with `status: "committed_unverified"` and exit 30. Its `command_ack` is the original successful execute ACK with exit 0. The fresh read transport failed and the same reader's Windows process and streams closed within the operation budget. The result carries `independent_inspection: null`, `inspection_required: true` and `retry_authorized: false`. The staged File result exposes the same status and original receipt, intent and plan digests as top-level fields. Preserve the response and its run identity, then inspect it from a fresh compatible read-only caller. This response alone proves neither target readback nor Linux process closure.

A typed exit 40 reports an indeterminate result. Exit 50 or an SDK delivery error requires preserving the operation identity and any capture before independent inspection. Follow the existing contract-specific reconciliation path only after that inspection. The read-only command accepts the original run identity without a new publication.

## Prepare authorized File v2 and Bundle v1 requests

Select the contract from the operation. Resolve the directory separately from an explicit task grant or approved Hermes rules. An approved installation supplies the exact ordinary NTFS directory and its native identity, the qualified ext4 evidence and preparation identities, and the fixed Windows and Linux runtime settings. Only trusted preparation supplies these facts. A request supplies a scope name and operation data. If authority is missing or ambiguous, ask for that authority. If it is clear and the binding is admitted, prepare and continue.

Run the repository's `integrations/hermes/skills/phase-mutation-preparation/scripts/prepare_native_phase_mutation.py` using the accepted Phase package and dependencies. Supply the task's deployment-owned subset of approved scopes and an ordered intents JSON as the two arguments. Prepare one fixed deployment per batch and use a distinct startup location per run. The adapter returns candidate, startup, execute and inspect values for each selected scope. It only composes JSON.

An approved scope names the exact `contract`, `windows_root`, `root_grant`, `evidence_root`, `evidence_identity`, `preparation_root`, `preparation_identity` and `launch`. Each of `launch.windows` and `launch.linux` contains the existing `config` and `dependency_roots`. The intent fields are `scope`, `contract`, `run_id`, `target_locator`, `payload_digest`, `payload_length` and `members`. Use a canonical relative target and a stable run ID. For File v2, use the exact payload digest and byte length and set `members` to null. For Bundle v1, both the digest and byte length describe the canonical bundle manifest. Supply the exact member locators from that manifest.

Use the installation's existing preparation channel to stage the payload at the returned input path and the canonical candidate bytes at the returned candidate path. Materialize each returned startup value as `native-phase.json` beside the matching fixed launcher. Keep these writes exclusive and outside the result grant. For MCP, pass the prepared execute arguments to `phase_execute_prepared` as described below. Preserve the original result and use its own compatible reader for inspection.

The current standalone File v2 and Bundle v1 installations each bind one original run. For a sequence of these two operations, choose separately authorized, nonoverlapping NTFS grants with disjoint ext4 evidence and preparation. Keep each run's original binding available for later inspection. The shared-history manifests for File v1 and Version v1 remain separate. The current experimental admission still requires `S:\\Phase-NTFS-Qualification\\<uuid>\\results` and the existing accepted runtime.

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

## Reconcile an ordinary publication

The ordinary owner-directory installation uses `reconcile-mcp` and exposes tools according to its fixed role. Use a fresh read-only `inspect` before requesting reconciliation. Keep the original intent digest and installed binding.

- File and Bundle roles expose `phase_recover_publication(run_id, request_id, expected_intent_digest, mode)`. Use `observe` for the supported observation route. Only Bundle v2 may use `commit_prepared` with a verified prepared Original and its matching intent.
- Version roles expose `phase_continue_version(run_id, original_run_id, request_id, expected_intent_digest, candidate_path, input_paths, expected_inputs, maximum_candidate_bytes)`. Use a distinct continuation run ID. Supply the bound Original's intent digest and the approved Linux preparation paths. `expected_inputs` defaults to null and `maximum_candidate_bytes` defaults to 1048576. The installed contract validates the continuation and its lineage.

The CLI actions are `recover-publication` and `continue-version`. Use the existing request envelope with `operation: "recover_publication"` and `native_bundle_recovery_request_version: "1.0"`, or `operation: "continue_version"` and `native_version_continuation_request_version: "1.0"`. For CLI recovery include `mode` and the request ID and expected intent digest. For CLI continuation include the original run ID and all request fields listed above. Keep the top-level `run_id` in either envelope. Inspect and retain the resulting evidence with the compatible reader.

## Inspect uncertainty and return the caller

Incomplete CLI delivery returns exit 50 with diagnostics and no synthetic command result. SDK timeout, cancellation, lost delivery or context closure also does not establish whether a mutation occurred. Preserve the exact known run and captures, then use its compatible fresh read-only inspector before considering any contract-supported recovery. There is no automatic retry. Do not change the key, run, root or timestamp to hide a conflict; an exact retained request and a fresh capture have the existing distinct replay semantics.

CLI/Docker/SDK exit and closed pipes do not prove native worker completion. Keep the original receipt, native creation-HANDLE/finalization proof where applicable, and independent target verification. Standard SDK stdio teardown can use its timed process-tree termination fallback; context closure is not a graceful-exit or quiescence guarantee.

A legitimate later version can make an older run's current-target inspection report a mismatch. Preserve that result and verify retained archive/object bytes and supported history lineage with the exact compatible reader. Returning to the prior immutable caller/runtime/configuration does not undo publications or rewrite evidence. Retain both old and candidate readers, compare data and evidence across the return, and respect each reader's supported scope. A prior runtime without the native capability must retain its honest refusal. See `ROLLBACK.md` for the existing return boundary.
