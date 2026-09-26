# syntax=docker/dockerfile:1

ARG PYTHON_IMAGE=python:3.11-slim

FROM ghcr.io/astral-sh/uv:0.12.19 AS uv

# Build stage: resolve and install the app into a self-contained venv.
# Nothing from this stage except /opt/venv reaches the runtime image.
FROM ${PYTHON_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
  UV_COMPILE_BYTECODE=1 \
  UV_LINK_MODE=copy \
  UV_PYTHON_DOWNLOADS=never

COPY --from=uv /uv /usr/local/bin/uv

RUN uv venv /opt/venv

WORKDIR /src

# Dependencies first so code-only changes reuse this layer. Then drop what the
# app never imports: Pillow and vacuum-map-parser (pulled in by python-roborock
# only for its map rendering; nothing else depends on them) and pycryptodome's
# bundled self-tests.
COPY pyproject.toml README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
  uv pip install --python /opt/venv/bin/python -r pyproject.toml \
  && uv pip uninstall --python /opt/venv/bin/python \
    pillow vacuum-map-parser-base vacuum-map-parser-roborock \
  && rm -rf /opt/venv/lib/python3*/site-packages/Crypto/SelfTest \
    /opt/venv/lib/python3*/site-packages/Cryptodome/SelfTest

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
  uv pip install --python /opt/venv/bin/python --no-deps .

# Fail the build if the app (or a python-roborock bump) now imports what was removed.
COPY scripts/check_import_graph.py /tmp/check_import_graph.py
RUN /opt/venv/bin/python /tmp/check_import_graph.py

# acme.sh, pinned to a release tag and verified by checksum.
FROM ${PYTHON_IMAGE} AS acme

ARG ACME_SH_VERSION=3.1.6
ARG ACME_SH_SHA256=0d3f9000ac44a6331314742a88c475f79134e24fc991997883652adc59efc486

ADD --checksum=sha256:${ACME_SH_SHA256} \
  https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz \
  /tmp/acme.sh.tar.gz

RUN mkdir -p /opt/acme.sh \
  && tar -xzf /tmp/acme.sh.tar.gz --strip-components=1 -C /opt/acme.sh \
  && chmod +x /opt/acme.sh/acme.sh

FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.source="https://github.com/python-roborock/local_roborock_server" \
  org.opencontainers.image.description="Private Roborock HTTPS and MQTT stack for local LAN use" \
  org.opencontainers.image.licenses="MIT"

# mosquitto: embedded broker. openssl + curl: required by acme.sh (and curl by
# the compose healthcheck). ca-certificates: outbound TLS to ACME/Roborock cloud.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    mosquitto \
    openssl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=acme /opt/acme.sh /opt/acme.sh
RUN ln -sf /opt/acme.sh/acme.sh /usr/local/bin/acme.sh

COPY --from=builder /opt/venv /opt/venv

# Site-packages bytecode is precompiled in the build stage, but the base image
# ships the stdlib without .pyc. Import the app once so the stdlib modules it
# loads at startup are compiled into the image too (~5 MB). Compiling them in
# memory on every start instead doubles import time and adds ~2 MB RSS, which
# is also why PYTHONDONTWRITEBYTECODE is left unset at runtime.
RUN /opt/venv/bin/python -c "import roborock_local_server.__main__, roborock_local_server.container_entrypoint"

ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

EXPOSE 555 8881

CMD ["python", "-m", "roborock_local_server.container_entrypoint"]
