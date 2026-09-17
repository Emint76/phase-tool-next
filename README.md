# Phase Tool

A file-writing job can fail after changing its destination but before reporting
success. The caller then needs to know what was actually published, whether the
bytes are intact, and whether it is safe to retry.

Phase Tool provides verified local publication of files and bundles for automation
scripts, data pipelines, and agent tooling. It records the intended operation and
its evidence, applies bounded filesystem changes, and verifies the result. Python,
CLI, and MCP callers use the same implementation. Recovery after an interruption
is limited to explicitly supported cases; an error or missing response does not
mean that nothing was written.

For example, a pipeline can publish a generated report and its CSV tables as one
bundle, retain the operation's evidence, and inspect the published bytes after a
lost completion response instead of blindly publishing again. See the
[file/bundle integration guide](docs/development/RC01-INTEGRATION.md) for commands,
limits, and recovery rules. To contribute, start with [CONTRIBUTING.md](CONTRIBUTING.md).

This repository is **PUBLIC**. The current stable release is [**v1.1.0**](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0): **PUBLIC STABLE RELEASED**. Packages are distributed through GitHub Release assets; no PyPI/TestPyPI publication or production deployment has been performed.

The stable release passed independent review before merge; exact-head CI and post-merge CI completed successfully. Published packages are the exact retained reviewed bytes, not rebuilt from the merge commit. [v1.1.0rc5](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0rc5) is the previous verified prerelease, preserved as historical evidence.

See the [file/bundle integration guide](docs/development/RC01-INTEGRATION.md) and [current development state](docs/development/STATE.md). The [RC01 candidate notes](docs/development/RC01-RELEASE-NOTES.md) are historical, not the current release description.

Phase Tool is a local, registry-driven execution product. Its CLI and MCP adapters are thin transports over one `PhaseApplication`, which resolves an exact contract binding and calls the existing `PhaseCore.run` lifecycle.

## Supported platform

The current production and release runtime is Linux/POSIX only, on filesystems admitted by the bundled authority profile. Windows, macOS, WSL, and other non-qualified hosts are not supported for mutation: Phase fails closed with `platform.mutation_unsupported` before candidate capture, intent creation, authority open, or target mutation. The platform composition boundary remains isolated so another authority implementation can be qualified and versioned separately later.

## Architecture

Phase is infrastructure for managed transitions of information state within a controlled contour.

It binds a proposed transition to an exact contract and trusted domain runtime, persists durable intent, applies bounded physical effects, verifies the resulting state, and preserves machine-verifiable transition evidence.

See:

- [Architecture north star](ARCHITECTURE.md)
- [Exclusive write contour ADR](ADR-EXCLUSIVE-WRITE-CONTOUR.md)

## Quick Start

Download `phase_tool-1.1.0-py3-none-any.whl` from the [v1.1.0 GitHub Release](https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0), then install the downloaded local wheel in a normal virtual environment on a supported Linux/POSIX host:

```console
python -m pip install ./phase_tool-1.1.0-py3-none-any.whl
phase --version
phase doctor
phase contracts list
```

No editable install, checkout, `PYTHONPATH`, internal script, or repository-specific interpreter is required.

Universal execution always names the exact registry binding:

```console
phase execute --contract source_admission.v1@1.0.0 --candidate source.json --input asset=source.txt --root admission_result_root=./results --evidence-root ./evidence --run-id source-001
phase execute --contract knowledge_admission.v1@1.0.0 --candidate knowledge.json --input asset=knowledge.json --root admission_result_root=./results --evidence-root ./evidence --run-id knowledge-001
phase inspect --evidence-root ./evidence --run-id source-001 --root admission_result_root=./results
```

Run the local MCP stdio server with either equivalent entrypoint:

```console
phase mcp serve --stdio
phase-mcp
```

MCP retains `phase_contracts_list`, `phase_contract_describe`, `phase_validate`, `phase_plan`, `phase_execute`, and `phase_inspect`. Shared high-level tools add `phase_publish_file`, `phase_publish_bundle`, `phase_publication_limits`, `phase_publication_status`, and `phase_recover_publication`; see the RC01 integration guide for limits and explicit recovery boundaries.

## Documentation

- [CLI reference](docs/CLI-REFERENCE.md)
- [MCP setup](docs/MCP-SETUP.md)
- [Phase Tool v1 public surface and compatibility](docs/PUBLIC-SURFACE-V1.md)
- [Source and Knowledge examples](docs/STAGE-8-EXAMPLES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Safety model

Contract semantics come from immutable registry/package artifacts. Validators, planning, durable evidence, mutation brokerage, receipts, and inspection remain in the single Phase lifecycle. Adding a registered contract does not require CLI or MCP routing changes.

## License

MIT; see [LICENSE](LICENSE).
