# Phase Tool

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

Install a built wheel in a normal virtual environment:

```console
python -m pip install phase_tool-1.0.0-py3-none-any.whl
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

MCP publishes only universal tools: `phase_contracts_list`, `phase_contract_describe`, `phase_validate`, `phase_plan`, `phase_execute`, and `phase_inspect`.

## Documentation

- [CLI reference](docs/CLI-REFERENCE.md)
- [MCP setup](docs/MCP-SETUP.md)
- [Source and Knowledge examples](docs/STAGE-8-EXAMPLES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Safety model

Contract semantics come from immutable registry/package artifacts. Validators, planning, durable evidence, mutation brokerage, receipts, and inspection remain in the single Phase lifecycle. Adding a registered contract does not require CLI or MCP routing changes.

## License

MIT; see [LICENSE](LICENSE).
