# syntax=docker/dockerfile:1
# OpenWebGoggles — production image
#
# Multi-stage build:
#   builder  — installs the package into an isolated venv
#   runtime  — minimal python:3.12-slim with only the venv and a startup script
#
# Usage (standalone webview server for custom app development):
#   docker build -t openwebgoggles .
#   docker run -p 18420:18420 -p 18421:18421 \
#     -v "$(pwd)/.openwebgoggles:/app/data" \
#     openwebgoggles
#
# Usage (MCP server — typical agent workflow):
#   docker run --rm openwebgoggles openwebgoggles status

ARG PYTHON_VERSION=3.12

# ── Stage 1: builder ────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

# Copy only what pip needs to build the package
COPY pyproject.toml README.md ./
COPY scripts/ scripts/
COPY assets/ assets/

# Build into a venv for clean layer separation
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel && \
    /opt/venv/bin/pip install --no-cache-dir ".[dev]" || \
    /opt/venv/bin/pip install --no-cache-dir .

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="OpenWebGoggles" \
      org.opencontainers.image.description="Browser-based HITL UI panels for AI coding agents" \
      org.opencontainers.image.source="https://github.com/techtoboggan/openwebgoggles" \
      org.opencontainers.image.licenses="Apache-2.0"

# Copy the venv (no build tools leak into the runtime image)
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Non-root user (CIS Docker Benchmark 4.1)
RUN groupadd -r owg && useradd -r -g owg -d /app owg && \
    mkdir -p /app/data && chown -R owg:owg /app

WORKDIR /app
USER owg

# Expose HTTP and WebSocket ports
EXPOSE 18420 18421

# Health check: HTTP server must respond to the root endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18420/')" 2>/dev/null || exit 1

# Startup script: finds the installed SDK path at runtime, then starts the server
COPY --chown=owg:owg docker-entrypoint.sh /usr/local/bin/owg-entrypoint
RUN chmod +x /usr/local/bin/owg-entrypoint

ENTRYPOINT ["owg-entrypoint"]
CMD []
