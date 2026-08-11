# Phase Tool v1 public surface

This document is the compatibility contract for Phase Tool 1.x. The supported release runtime is **Linux/POSIX** on a filesystem admitted by the bundled authority profile. Windows, macOS, and WSL are not release platforms.

## Stable public contract

### Installed entrypoints and CLI

The distribution publishes exactly two console entrypoints:

- `phase` — command-line adapter;
- `phase-mcp` — local MCP stdio server.

`phase` has these stable commands:

- `doctor`;
- `contracts list`;
- `contracts describe --contract ID@VERSION`;
- `validate`, `plan`, and `execute` with `--contract` or the exact `--contract-id`/`--contract-version`/`--contract-digest` triple, plus required `--candidate`, `--evidence-root`, and `--run-id`;
- repeatable `--input NAME=PATH` and `--root NAME=PATH`, optional `--timestamp`, and `--maximum-candidate-bytes` (default `1048576`);
- `inspect --evidence-root DIR --run-id ID` with repeatable `--root NAME=PATH`;
- `mcp serve --stdio` (equivalent server path to `phase-mcp`).

`--help` and `--version` are stable discovery options. `--contract` means one exact bundled registry key; it performs no latest-version or network lookup. Duplicate binding names and mixed contract forms are rejected.

CLI process status is stable by class:

- exit 0: requested command completed successfully;
- exit 2: CLI syntax/argument parsing rejected the invocation before Phase application dispatch; argparse diagnostics are on stderr and stdout is empty;
- exit 10: the request was rejected before mutation;
- exit 20: execution failed with verified no effect;
- exit 30: execution failed with a known partial effect;
- exit 40: the effect was committed but could not be fully verified;
- exit 50: the effect is indeterminate and requires inspection before retry.

For a parsed Phase operation, the process status equals the `exit_code` in the emitted
machine-readable result. Other nonzero statuses are reserved for an entrypoint/runtime
failure before a Phase result can be produced. Human-readable help, usage, and diagnostic
prose is informational.

### MCP stdio tools

The stable MCP tool names are:

- `phase_contracts_list`;
- `phase_contract_describe`;
- `phase_validate`;
- `phase_plan`;
- `phase_execute`;
- `phase_inspect`.

`phase_contract_describe` requires string `contract_binding`. Validate/plan/execute require string `contract_binding`, object `candidate`, string `evidence_root`, and string `run_id`; optional fields are object-of-string-or-null `input_paths`, object-of-string-or-null `root_bindings`, string-or-null `timestamp`, and integer `maximum_candidate_bytes` (default `1048576`). Inspect requires string `evidence_root` and string `run_id`, with optional object-of-string-or-null `root_bindings`. For these optional mappings, explicit `null` has the same meaning as omission.

Missing, extra, or wrongly typed MCP arguments are MCP invalid-call errors. A well-typed call that Phase rejects returns the normal Phase result with `success=false`; it is not a transport failure. Invalid calls must not terminate or corrupt the long-lived server. MCP transport wrappers need not be byte-identical to CLI output.

### Machine-readable results and binding

The stable transport-neutral command envelope is `stage3-command-result.schema.json` version `1.0`. Its required fields and enum meanings are stable: `stage3_command_result_version` (the `"1.0"` discriminator), `command`, `success`, `run_id`, `terminal_status`, `execution_disposition`, `mutation_attempted`, digest fields, `blockers`, `error`, and `exit_code`; `target_verified` is present in current producers and remains optional in the schema for compatibility with earlier 1.0 producers.

`phase-intent.schema.json` and `phase-receipt.schema.json`, both version `1.0`, are stable durable evidence schemas. Their terminal statuses, execution dispositions, mutation flag, intent/receipt digest semantics, and inspection meaning are stable.

Contract candidate/result/effect schemas returned through exact registry package metadata are bound by the selected contract ID, version, package digest, and registry snapshot digest. An exact package digest identifies exact artifact bytes. A package with changed contract/schema bytes requires a different package digest; Phase fails closed on a mismatched requested digest. Phase Tool v1 has no separate protocol-version negotiation beyond package/core compatibility checks and MCP's own protocol initialization.

The unversioned discovery objects are **field-extensible discovery payloads**. Their following fields, types, and meanings are stable in 1.x:

- `doctor`: boolean `success`, string `version`, object `registry` (string `status`, string `snapshot_digest`, integer `contract_count`), and object `mcp_sdk` (string `distribution`, string-or-null `version`, string `required_range`, boolean `compatible`);
- `contracts list` / `phase_contracts_list`: array `contracts` and string `registry_snapshot_digest`; each contract item has string `contract_binding`, `id`, `version`, `package_digest`, and `operation_intent`;
- successful `contracts describe` / `phase_contract_describe`: string `contract_binding`, string `package_digest`, string `registry_snapshot_digest`, object `contract`, and array `package_artifacts`;
- rejected contract description: `success=false`, string `error`, array `blockers`, and `exit_code=10`.

Additional fields in these discovery objects are compatible additions; consumers must ignore fields they do not understand. Removing a listed field, changing its type or meaning, or making a currently optional nested detail mandatory is breaking. Collection order is non-semantic unless an exact contract artifact says otherwise.

## Public but extensible in 1.x

Compatible 1.x additions include:

- a new command or MCP tool;
- a new enum member only where the consuming schema explicitly permits extension; closed enums otherwise require a breaking version;
- a new Phase error code with a new, non-contradictory meaning;
- a new registry contract/version/package generation;
- a new field in the explicitly field-extensible discovery payloads above;
- additional entries in contract listings, blockers, or other collections where ordering is not declared semantic.

The stable result schemas are closed (`additionalProperties: false`). Adding a field to
one of those schema versions is therefore not a compatible 1.x change; it requires a new
versioned format and an explicit migration path. No current stable result schema is
designated as field-extensible. Consumers must preserve unknown error codes and may rely
on all documented required fields. Additions must not reinterpret an existing field, enum
member, error code, exit class, or exact binding.

## Stable error vocabulary

Expected Phase failures expose identifier-shaped codes in `error` and/or `blockers`; raw Python/host diagnostics do not replace them. Once a code is exposed for an expected public failure, its meaning is stable during 1.x. New codes may be added. Unexpected programmer/runtime failures may use the generic `cli.failure` or `application.failure` fallback.

The intentionally public families exercised by the v1 lifecycle are:

| Family | Representative stable codes/meaning |
|---|---|
| Adapter/application | `cli.duplicate_binding`, `cli.conflicting_contract_binding`, `cli.contract_binding_required`, `application.contract_binding_not_found` |
| Candidate/canonical | `candidate.input_unavailable`, `candidate.invalid_json`, `candidate.invalid_utf8`, `candidate.duplicate_key`, `candidate.too_large`, `candidate.schema_invalid`, `canonical.float_forbidden`, `canonical.nonfinite_forbidden` |
| Registry/contract | `registry.entry_not_found`, `registry.digest_mismatch`, `registry.entry_ambiguous`, `contract.core_incompatible`, `contract.schema_invalid` |
| Validation/planning | `validation.blocked`, `validation.target_unavailable`, `plan.root_binding_missing`, `plan.root_unavailable`, `plan.forbidden_root_binding`, `plan.operation_unsupported` |
| Platform/guarantee | `platform.mutation_unsupported`, `guarantee.profile_unsupported`, `guarantee.profile_scope_unsupported`, `guarantee.coverage_insufficient` |
| Input/freeze/evidence | `input.required_missing`, `freeze.input_unavailable`, `freeze.source_changed_during_capture`, `evidence.invalid_run_id`, `evidence.overlaps_target_root` |
| Idempotency/mutation | `idempotency.same_key_conflict`, `idempotency.prior_inspection_required`, `broker.root_identity_mismatch`, `mechanism.write_failed`, `lock.acquire_timeout` |
| Inspection/path | `inspection.run_unavailable`, `inspection.target_unavailable`, `inspection.invalid_json`, `path.invalid_locator`, `path.traversal`, `path.link_forbidden` |

Contract-specific namespaces such as `publish.*`, `source.*`, `knowledge.*`, and `task_journal.*` are public only through the exact contract package that emits them; their meaning is governed by that exact package binding.

## Not semver-stable

The following are informational or internal and are not frozen by this contract:

- wording, whitespace, ordering, and formatting of human-readable help or diagnostics;
- stderr log text from the MCP SDK;
- JSON object key order and collection order unless a schema/contract gives the order semantic meaning;
- internal Python modules, classes, functions, exceptions, dataclasses, test helpers, scripts, and fixtures;
- filesystem implementation details other than documented durable evidence and target effects;
- MCP SDK protocol wrappers owned by the MCP specification rather than Phase;
- historical/non-current registry artifacts not selected by an exact binding.

## Compatibility and deprecation

In 1.x, removing or renaming an existing command/tool/required argument, changing a required argument type or meaning, removing a required JSON field, changing a closed-enum or existing error-code meaning, changing exit-code class meaning, or weakening exact contract binding is breaking and requires the next major version.

A compatible deprecation keeps the old surface working for at least one 1.x minor release, documents the replacement, and may add a human-readable warning without contaminating machine-readable stdout. Removal occurs only in a major release. Improving human-readable prose needs no deprecation.