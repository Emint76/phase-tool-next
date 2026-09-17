# Contributing

Small, focused fixes are welcome as a branch and pull request; an issue is not
required first for an obvious small fix. For larger changes, open an issue to
discuss scope before implementation.

## Development and verification

Use Python **3.11 or 3.12** on Linux/POSIX with a filesystem admitted by the bundled
authority profile (ext4/overlay). CI verifies both Python versions on Linux.
Windows, macOS, WSL, and other non-qualified hosts are not supported for mutation;
do not treat a test run there as Linux mutation verification.

Fork the repository on GitHub if you do not have write access, then clone your
fork (or use the upstream URL below for a local checkout):

```sh
git clone https://github.com/Emint76/phase-tool-next.git
cd phase-tool-next
git switch -c fix/short-description
python3.11 -m venv .venv  # python3.12 is also supported
. .venv/bin/activate
python -m pip install ".[test]"
python -m pytest -W error -ra
python -m build
```

Run these commands from the checkout root. The `test` extra includes pytest and
the build frontend. After editing source, rerun `python -m pip install ".[test]"`
before testing: this is a regular, not editable, install. `python -m build`
produces a wheel and source distribution in `dist/`.

To check the wheel outside the checkout, use a fresh environment:

```sh
WHEEL="$(pwd)/dist/phase_tool-1.1.0-py3-none-any.whl"
CHECK_DIR="$(mktemp -d)"
python -m venv "$CHECK_DIR/venv"
"$CHECK_DIR/venv/bin/python" -m pip install "$WHEEL"
(cd "$CHECK_DIR" && unset PYTHONPATH && \
  "$CHECK_DIR/venv/bin/phase" --version && \
  "$CHECK_DIR/venv/bin/phase" doctor && \
  "$CHECK_DIR/venv/bin/phase" contracts list)
```

## Before opening a pull request

- Keep the diff focused and run `git diff --check`.
- Run the test suite; check the build and installed wheel when packaging changes.
- Include corresponding tests for runtime, API, and contract changes. Preserve
  path/authority boundaries, evidence integrity, and explicit recovery limits.
- Update affected documentation and check its relative links.
- Describe the change and the checks you ran in a PR targeting `main`. CI also
  exercises installed CLI, MCP, and recovery behavior on both Python versions.

Start with [Architecture](ARCHITECTURE.md), the
[public surface and compatibility guide](docs/PUBLIC-SURFACE-V1.md), and the
[publication integration guide](docs/development/RC01-INTEGRATION.md).
[Development state](docs/development/STATE.md) links to detailed implementation
and verification notes; historical candidate notes are not the current release.

## Bug reports

For non-security bugs, [open an issue](https://github.com/Emint76/phase-tool-next/issues)
with the Phase and Python versions, OS/filesystem, minimal reproduction, expected
and actual behavior, and relevant errors. Remove secrets and private paths or
data from logs and evidence before sharing. Do not post vulnerability details in
a public issue; private vulnerability reporting is not currently configured.
