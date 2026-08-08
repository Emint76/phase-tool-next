---
name: phase-verified-execution
description: "Use when a complete Phase Tool candidate, its inputs, root bindings, and exact registry contract binding are already prepared. Executes the change through Phase, immediately inspects the durable run, and returns only a minimal receipt-backed verification result."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [phase-tool, verified-execution, receipts, inspect, transport-neutral]
    related_skills: []
---

# Phase Verified Execution

## Overview

Use this skill as the domain-neutral execution boundary for an already prepared Phase request:

```text
ready candidate + exact registry binding + inputs + roots
  -> execute through a Phase transport
  -> inspect the same durable run
  -> verify receipt/inspect agreement
  -> emit a six-field result
```

The skill does not know what the candidate means. It does not create, normalize, enrich, repair, or infer candidate data. It does not write a canonical target itself. The Phase transport is the only mutation path.

The primary transport is direct MCP when the `phase_execute` and `phase_inspect` tools are available in the current Hermes session. Use those tools directly: read the prepared candidate JSON only for read-only confirmation, call `phase_execute`, then call `phase_inspect` for the same evidence root and run ID. Do not create a separate Python MCP client, do not tunnel MCP through the CLI runner, and do not call `phase_validate` or `phase_plan` by default.

The included CLI adapter at `scripts/run_phase_verified.py` is only a fallback transport. Use it when the MCP tools are unavailable or when the user explicitly requests the CLI path. It must preserve the same `execute -> inspect` lifecycle, invariants, and six-field output contract.

## When to Use

Use only when all of these already exist:

- candidate JSON;
- every required input file;
- every required target root;
- evidence root;
- run ID;
- exact registry binding `<contract-id>@<version>`;
- exact `sha256:` package digest for that binding when the selected transport requires or accepts it;
- all named input and root bindings required by the selected registry contract.

Do not use this skill to:

- choose a domain workflow;
- create or edit a candidate;
- download, extract, transform, or classify content;
- invent a contract ID, version, digest, input binding, or root binding;
- write, append, copy, replace, or delete a canonical target directly;
- adapt or invoke a legacy execution workflow;
- treat execute output alone as proof of a verified result.

If any prepared input is missing or ambiguous, stop before execute. The caller that owns candidate preparation must repair it.

## Invariants

1. **Registry binding.** Pass the exact registry binding supplied by the caller. When the transport requires or accepts a package digest, pass the exact `sha256:` digest supplied by registry discovery. Let Phase resolve and enforce the registry entry. Never select a contract by filename, domain label, or guessed version.
2. **Default lifecycle.** Run exactly `execute -> inspect`. Do not add `validate` or `plan` by default; Phase execute already performs validation and planning internally. Use separate validation/planning only when the user explicitly requests diagnostics.
3. **Single mutation owner.** Neither the skill nor `scripts/run_phase_verified.py` may create or modify any file or directory. They only read already prepared request artifacts, invoke Phase through MCP or CLI fallback, parse execute/inspect results, and print the six-field result. The external preparation layer creates the candidate, payload, evidence root, target roots, and any fixture files. Only Phase creates canonical targets and evidence.
4. **Durable proof.** A successful execute response is necessary but insufficient. Success requires a non-null receipt digest and a successful inspect of the same evidence root, run ID, and root bindings with `target_verified=true`.
5. **Cross-check.** Execute and inspect must agree on run ID, terminal status, execution disposition, and receipt digest.
6. **No stronger claim.** Never call a run verified when inspect is absent, failed, or reports `target_verified` other than `true`.
7. **Minimal output.** On success, emit only the output contract below. Do not include target paths, candidate fields, effect plans, domain summaries, prose, or raw command/tool envelopes.

## Transport Interface

A conforming transport exposes two operations:

```text
execute(request) -> result envelope
inspect(run reference) -> result envelope
```

Both result envelopes must provide or normalize to the Phase fields used by the verifier:

- `success`;
- `run_id`;
- `terminal_status`;
- `execution_disposition`;
- `receipt_digest`;
- `target_verified` for inspect;
- process/tool status.

### Primary: direct MCP transport

When the MCP tools are available, call them directly:

1. Read the prepared request and candidate JSON only read-only. Hash every named input and require exact equality with the request's `expected_input_digests`; do not execute if any input changed.
2. Call `phase_execute` with the exact registry binding, candidate object, evidence root, run ID, input path bindings, and root bindings.
3. Immediately before `phase_inspect`, hash every named input again and require exact equality with `expected_input_digests`; do not inspect or report success if any input changed.
4. Call `phase_inspect` with the same evidence root, run ID, and root bindings.
5. Verify all invariants against the two tool results.
6. Return the same six-field JSON output contract.

Do not use `phase_validate` or `phase_plan` in the default path. Do not implement a standalone MCP client in Python, shell, or another language. Do not route MCP through `scripts/run_phase_verified.py`.

### Fallback: CLI adapter

The included CLI adapter is a fallback implementation. It accepts the transport-neutral `<id>@<version>` plus digest request and translates it to the CLI's mutually compatible `--contract-id`, `--contract-version`, and `--contract-digest` arguments. Use it only when direct MCP tools are unavailable or the user explicitly requires CLI execution. It must not weaken any invariant, write canonical targets directly, or change the final output shape.

## Procedure

### 1. Confirm the prepared request

Check read-only that candidate, inputs, metadata, evidence root, and target roots already exist where required, the run ID is non-empty, and the exact binding was supplied. Check the exact digest too when the selected transport requires or accepts it.

The skill and `scripts/run_phase_verified.py` do not create or modify any files or directories. They may only read already prepared candidate, inputs, and metadata. Creation of candidate, payload, evidence root, target roots, and any fixture files belongs to an external preparation layer.

Completion criterion: every transport argument can be passed literally without inference, repair, creation, or modification.

### 2. Prefer direct MCP execute then inspect

If `phase_execute` and `phase_inspect` tools are available in the current Hermes session, use them as the default transport:

```text
read candidate JSON read-only
phase_execute(contract_binding, candidate, evidence_root, run_id, input_paths, root_bindings)
phase_inspect(evidence_root, run_id, root_bindings)
verify invariants
emit six-field JSON
```

The inspect call must use the identical evidence root and run ID from execute. Include identical root bindings whenever root bindings were supplied for execute. Do not call `phase_validate` or `phase_plan` unless the user explicitly asks for diagnostics outside the default execution path.

Completion criterion: `phase_execute` and `phase_inspect` both return successful compatible envelopes and the normalized result matches the output contract.

### 3. Use CLI fallback only when required

Use the complete request emitted by preparation when MCP tools are unavailable or the user explicitly requests CLI:

```bash
python scripts/run_phase_verified.py \
  --phase-bin /path/to/phase \
  --request /path/to/phase-request.json
```

Manual arguments remain available for diagnostics; pair each `--input` with `--input-digest '<binding>=sha256:<digest>'`. Omit `--phase-bin` when `phase` is already in `PATH` or `PHASE_BIN` is set.

The runner resolves the executable in this order:

1. explicit `--phase-bin`;
2. `PHASE_BIN` environment variable;
3. `phase` from `PATH`.

An explicit path is allowed for a locally installed virtual-environment executable. The runner removes ambient `PYTHONPATH` from the child environment so unrelated Python packages cannot shadow the installed Phase distribution.

The runner invokes no `validate` or `plan` command. It invokes inspect after execute and with the identical evidence root, run ID, and root bindings.

Completion criterion: the runner exits `0` and emits one canonical JSON object matching the output contract.

### 4. Treat only the normalized result as the user-facing result

Successful output has exactly six top-level keys:

```json
{
  "contract": "<id>@<version>",
  "run_id": "<run-id>",
  "terminal_status": "succeeded_verified",
  "execution_disposition": "executed",
  "receipt_digest": "sha256:<digest>",
  "inspect_status": {
    "success": true,
    "target_verified": true
  }
}
```

`execution_disposition` is copied from the mutually consistent Phase execute/inspect envelopes; do not rewrite it. Key order is part of the concise presentation but not of semantic verification.

Completion criterion: no extra top-level key or explanatory prose is emitted.

## Failure Handling

- If execute or inspect returns non-zero or an unsuccessful tool/process status, do not emit a success object.
- If either envelope is not valid JSON where JSON is expected, treat the transport as failed.
- If execute has no receipt digest, do not claim success.
- If inspect does not report both `success=true` and `target_verified=true`, do not claim success.
- If execute and inspect disagree, report verification failure and preserve the Phase evidence for separate investigation.
- Do not retry with a new run ID or idempotency key automatically.
- Do not repair, delete, truncate, overwrite, or clean canonical targets.
- Do not bypass Phase after a failure.

## Direct-Write Prohibition

The skill and included runner may only:

1. read already prepared candidate, inputs, and metadata;
2. invoke Phase through direct MCP or the CLI fallback;
3. parse execute and inspect results;
4. print the six-field verification result.

They must not create or modify any files or directories. This includes file creation, write, append, copy, move, replace, delete, rename, truncate, chmod, directory creation, fixture setup, payload generation, evidence-root creation, target-root creation, and canonical-target mutation.

Creation of candidate, payload, evidence root, target roots, and any fixture files is the responsibility of an external preparation layer. Only Phase creates canonical targets and evidence. Testing this skill must use already prepared disposable roots; fixture preparation is outside this skill and outside `scripts/run_phase_verified.py`.

## Common Pitfalls

1. **Routing MCP through the CLI runner.** When MCP tools exist, call `phase_execute` and `phase_inspect` directly. Do not create a Python MCP client or a CLI bridge.
2. **Running validate and plan first.** This duplicates the non-execute lifecycle and evidence. Default to execute then inspect.
3. **Passing only `<id>@<version>` to a digest-aware transport.** Exact CLI execution also requires the package digest supplied by registry discovery; never guess it.
4. **Using execute output as proof.** Canonical confirmation is the durable receipt plus successful inspect.
5. **Reformatting rich output.** The public result intentionally contains only six fields.
6. **Preparing data in this skill.** Candidate, payload, evidence root, target roots, metadata, and fixture preparation belong to an upstream preparation layer outside this execution boundary.
7. **Writing anything to help Phase.** Existing roots may be supplied, but neither the skill nor `scripts/run_phase_verified.py` may create or modify files or directories. Canonical target and evidence creation belongs exclusively to Phase.
8. **Changing behavior by transport.** MCP and CLI fallback must implement the same checks and output shape, not separate workflows.

## Verification Checklist

- [ ] Candidate, inputs, metadata, evidence root, target roots, run ID, exact binding, and any transport-required digest were supplied without inference
- [ ] Candidate, inputs, and metadata were only read; they were not rewritten or normalized
- [ ] The skill and `scripts/run_phase_verified.py` created no files or directories
- [ ] The skill and `scripts/run_phase_verified.py` modified no files or directories
- [ ] Candidate, payload, evidence root, target roots, and fixture files were prepared only by an external preparation layer
- [ ] Direct MCP `phase_execute -> phase_inspect` was used when available
- [ ] CLI adapter was used only because MCP was unavailable or the user explicitly required CLI
- [ ] No `phase_validate` or `phase_plan` ran in the default path
- [ ] Canonical target was mutated only by Phase
- [ ] Execute returned a receipt digest
- [ ] Inspect returned `success=true`
- [ ] Inspect returned `target_verified=true`
- [ ] Execute and inspect fields agree
- [ ] Output has exactly six top-level keys
- [ ] No domain terms or domain-specific candidate logic entered this skill
