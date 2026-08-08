# Troubleshooting

## `phase` or `phase-mcp` is not found

Activate the environment into which the wheel was installed, then run `phase --version`. Reinstall the wheel normally; do not set `PYTHONPATH` or use an editable install as a workaround.

## `phase doctor` reports an MCP SDK mismatch

Install the product's declared dependencies from the wheel. Stage 8 requires the stable bounded range `mcp>=1.26,<2`; MCP 2.x is intentionally not accepted by this adapter version.

## Contract binding not found

Run:

```console
phase contracts list
```

Use an exact listed value with `--contract`. Phase Tool does not perform network lookup or implicit version selection.

## Candidate or binding errors

Run `phase contracts describe --contract <exact-binding>` and validate against the registry-provided candidate schema. Confirm every required `--input NAME=PATH` and `--root NAME=PATH` is present and unique.

## Inspect reports target mismatch

Do not retry mutation blindly. Preserve the evidence root and target, investigate the reported receipt/target mismatch, and restore only through an explicitly approved recovery procedure.

## MCP client cannot connect

Run `phase doctor`, then launch `phase-mcp` directly. Stdout is protocol-only; inspect stderr for SDK diagnostics. Stage 8 supports stdio, not HTTP.

## `platform.mutation_unsupported`

The current production/release mutation runtime is Linux/POSIX only. Windows, macOS, WSL, and other non-qualified hosts are rejected before candidate capture and target mutation. Do not retry or bypass this guard; run the exact wheel on a qualified Linux host. A future platform authority must be implemented and qualified as a separate versioned profile.
