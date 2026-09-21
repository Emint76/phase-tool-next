# Single-platform distribution of the official release wheel, not this checkout.
# No floating Dockerfile frontend or base tag; requires a BuildKit-capable Docker.
FROM --platform=linux/amd64 docker.io/library/python@sha256:4b4c524dc3dce996864e030c7bd9c6b0e517597189fee48f48e05b499442444b AS install
ARG TARGETPLATFORM
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /input
COPY docker/requirements.lock docker/wheels.json docker/stage.py /input/docker/
COPY wheels/ /input/wheels/
RUN --network=none test "$TARGETPLATFORM" = "linux/amd64" \
    && python docker/stage.py --verify /input \
    && python -m venv --without-pip /opt/phase \
    && python -m pip --isolated --python /opt/phase/bin/python install \
        --no-index --find-links=/input/wheels --only-binary=:all: \
        --require-hashes --no-cache-dir --no-compile -r docker/requirements.lock \
    && python -m pip --isolated --python /opt/phase/bin/python check

FROM --platform=linux/amd64 docker.io/library/python@sha256:4b4c524dc3dce996864e030c7bd9c6b0e517597189fee48f48e05b499442444b AS runtime
LABEL org.opencontainers.image.title="Phase Tool" \
      org.opencontainers.image.description="Official Phase Tool 1.1.0 wheel; harness-neutral CLI and MCP stdio; linux/amd64" \
      org.opencontainers.image.version="1.1.0" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Emint76/phase-tool-next" \
      org.opencontainers.image.url="https://github.com/Emint76/phase-tool-next/releases/tag/v1.1.0" \
      org.opencontainers.image.base.name="docker.io/library/python:3.11.16-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:4b4c524dc3dce996864e030c7bd9c6b0e517597189fee48f48e05b499442444b" \
      io.phase-tool.wheel.filename="phase_tool-1.1.0-py3-none-any.whl" \
      io.phase-tool.wheel.sha256="9f37cb13e88d1e62d9a1f7c594ecfe0338eb7714afc1da069908cae3dfcfbc5a"
ENV PATH="/opt/phase/bin:$PATH" \
    HOME=/home/phase \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN --network=none groupadd --gid 10001 phase \
    && useradd --uid 10001 --gid 10001 --no-log-init --no-create-home --shell /usr/sbin/nologin phase \
    && mkdir /home/phase /work \
    && chown 10001:10001 /home/phase /work
COPY --from=install /opt/phase /opt/phase
COPY docker/requirements.lock docker/wheels.json /usr/local/share/phase-tool/
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["phase"]
CMD ["mcp", "serve", "--stdio"]
