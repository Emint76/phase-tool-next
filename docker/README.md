# Docker distribution: Phase Tool 1.1.0

This recipe installs the **official GitHub release wheel**, not the source checkout.
It changes no Phase runtime, Core, contracts, registry, or harness adapters.
There is no prebuilt/published image implied by this recipe.

## Fixed inputs and scope

- Platform: **Linux amd64 only**, CPython 3.11. No arm64/multi-platform claim.
- Base: Docker Official Image `python:3.11.16-slim-bookworm`, selected from
  `python:3.11-slim-bookworm`, pinned to its **amd64 platform manifest**:
  `docker.io/library/python@sha256:4b4c524dc3dce996864e030c7bd9c6b0e517597189fee48f48e05b499442444b`.
  Both stages use this digest; a different target platform is refused.
- Release: <https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0>.
- Required wheel: `phase_tool-1.1.0-py3-none-any.whl`, **317527 bytes**,
  SHA256 `9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a`.
- `requirements.lock` pins the release plus all 29 transitive/direct runtime
  dependencies. It was resolved from the official wheel's METADATA on this base,
  without the test extra. `wheels.json` records each exact filename, version,
  byte size, and SHA256. It is single-platform, not a portable dependency lock.
- Python, OS packages and the base's installer tooling are fixed by the base
  digest; this Dockerfile performs **no apt installs** and no runtime downloads.

## Canonical build (staged context, never the whole checkout)

Prerequisites: Python 3.11+ for staging, a Linux Docker engine with BuildKit,
public Docker Hub/PyPI access during acquisition, and the official release wheel.
No GitHub credentials, Docker build secrets, or user profile mounts are needed.
The shell commands below are POSIX syntax. On Windows/Git Bash, use native
forward-slash absolute paths (`C:/...`) for Docker bind sources and Python paths.
Use newly allocated local directories for `WHEELHOUSE` and `CONTEXT` outside the
checkout; do not use existing working volumes or production data.

```sh
# Run from the recipe checkout; set these absolute paths for your own workspace.
RECIPE="$PWD"
WHEELHOUSE=/absolute/task-local/wheelhouse
CONTEXT=/absolute/task-local/build-input
RELEASE_WHEEL=/absolute/downloads/phase_tool-1.1.0-py3-none-any.whl
BASE=docker.io/library/python@sha256:4b4c524dc3dce996864e030c7bd9c6b0e517597189fee48f48e05b499442444b

mkdir "$WHEELHOUSE"
cp "$RELEASE_WHEEL" "$WHEELHOUSE/phase_tool-1.1.0-py3-none-any.whl"
# Inspect the immutable platform manifest and pull that same identity.
docker buildx imagetools inspect "$BASE"
docker pull --platform linux/amd64 "$BASE"
docker image inspect "$BASE"

# Download the fixed closure using the same Linux/Python/platform as the build.
# The local release wheel satisfies phase-tool; hashes forbid substitution.
# Choose unique container names if running these commands more than once.
docker run --rm --platform linux/amd64 \
  --name phase110-author-download \
  --label phase.task=PHASE-110-DOCKER-IMAGE-01 --label phase.owner=phase-dev \
  --mount "type=bind,source=$WHEELHOUSE,target=/wheels" \
  --mount "type=bind,source=$RECIPE/docker/requirements.lock,target=/requirements.lock,readonly" \
  "$BASE" python -m pip --isolated download \
  --disable-pip-version-check --no-cache-dir --index-url https://pypi.org/simple \
  --only-binary=:all: --require-hashes --find-links=/wheels \
  --dest /wheels -r /requirements.lock

python -B docker/stage.py --wheelhouse "$WHEELHOUSE" --output "$CONTEXT"
python -B docker/stage.py --verify "$CONTEXT"
docker build --platform linux/amd64 --network none --no-cache --progress plain \
  --label phase.task=PHASE-110-DOCKER-IMAGE-01 --label phase.owner=phase-dev \
  --tag phase-tool-author:1.1.0-docker01 "$CONTEXT"
```

Do not overwrite somebody else's image tag. The task tag above is author-local,
not a published image name. Preserve the wheelhouse and the recipe commit for
rebuilds. Binary inputs are deliberately **not committed to Git**. Staging copies
only `Dockerfile`, `.dockerignore`, the lock, manifest, staging verifier and the
30 listed wheels. It rejects existing output directories, missing/extra inputs,
symlinked wheels, wrong sizes/hashes and lock/manifest disagreement. An interrupted
staging directory is not reusable; choose a new empty location after investigation.

The Docker build rechecks wheel bytes before installation, installs with
`--require-hashes --no-index`, and runs `pip check`. Every `RUN` has networking
disabled. Base-image acquisition/BuildKit metadata lookup may still require
registry access; `--network none` controls build steps, not the Docker daemon.
No package index is used inside the build. The final stage copies only the
installed isolated environment plus lock/manifest into the pinned base; wheels,
build verifier, tests and source checkout are not shipped.

BuildKit may report `FromPlatformFlagConstDisallowed` for the two intentionally
fixed `FROM --platform=linux/amd64` lines. That warning is expected for this
explicitly single-platform product, not a multi-platform support promise.

## Run offline, as nonroot

The default is the ordinary harness-neutral command `phase mcp serve --stdio`.
`ENTRYPOINT` is `phase`, so pass CLI arguments rather than another `phase` token.
Use `-i`, **not `-t`**, for MCP stdio. No port, HTTP transport, Hermes helper,
routing callback or profile configuration is included.

```sh
# Use fresh unique names for each invocation.
docker run --rm --name phase110-author-version --platform linux/amd64 \
  --label phase.task=PHASE-110-DOCKER-IMAGE-01 --label phase.owner=phase-dev \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  phase-tool-author:1.1.0-docker01 --version

docker run --rm --name phase110-author-doctor --platform linux/amd64 \
  --label phase.task=PHASE-110-DOCKER-IMAGE-01 --label phase.owner=phase-dev \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  phase-tool-author:1.1.0-docker01 doctor

docker run --rm -i --name phase110-author-mcp --platform linux/amd64 \
  --label phase.task=PHASE-110-DOCKER-IMAGE-01 --label phase.owner=phase-dev \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --tmpfs /work:rw,nosuid,nodev,uid=10001,gid=10001,mode=0700 \
  phase-tool-author:1.1.0-docker01 mcp serve --stdio
```

The process UID/GID is `10001:10001`, installed packages are root-owned under
`/opt/phase`, `/home/phase` is initially empty, and the working directory is
`/work`. No host credentials, user profiles, scientific data or checkout are
needed. `--network none` is the caller's offline boundary; a Dockerfile cannot
force a runtime network policy. The image has no declared persistent volumes.

The examples use disposable roots: data/evidence disappear when containers exit.
Persistent Phase operations require separately authorized, correctly owned roots
and a supported filesystem; these smoke examples do **not** qualify arbitrary
bind mounts, production storage, scientific workflows, or mutation semantics.
The image is not an authorization boundary for Phase writes.

## Verification and reproducibility boundary

Run only the focused distribution suite (stdlib, no Phase imports):

```sh
# Direct all host-side test temporary files to your task-local directory first.
export TEMP=/absolute/task-local/tmp TMP=/absolute/task-local/tmp TMPDIR=/absolute/task-local/tmp
python -B tests/test_docker_distribution.py
```

Author verification additionally builds offline; rejects a corrupted release
wheel and a wrong target platform in actual Docker builds; checks CLI version,
`doctor`, MCP initialization and inventory; and compares installed release files
and all installed package versions with the fixed inputs. This is a distribution
smoke test, not a rerun of the historical runtime suite. The unchanged wheel's
MCP SDK may advertise its own version in `initialize.serverInfo.version`; use
`phase --version`, `doctor`, and package metadata for the Phase product version.

Rebuilding establishes **verified runtime content from fixed inputs**, not
bit-for-bit image reproducibility. Wheel byte hashes and the base digest are
stable identities; installer-generated metadata, filesystem timestamps, image
configuration/history, BuildKit version and provenance attestations can differ.
`--no-compile` and `PYTHONDONTWRITEBYTECODE=1` avoid generated bytecode but do not
make a bitwise guarantee. No second-build bitwise-equality claim is made.

Updating the wheel, base or dependency pins is a new reviewed recipe candidate:
regenerate both lock and manifest and rerun focused and image smoke tests. Do
not silently follow floating base tags or re-resolve dependencies during a build.
