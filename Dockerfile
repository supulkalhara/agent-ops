# ─────────────────────────────────────────────────────────────────────
# AetherWall: Multi-stage Dockerfile
#
# Stage 1 (builder): Install all deps in a venv with full build tools
# Stage 2 (runtime): Minimal distroless-style image with only the venv
# ─────────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ──────────────────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build

# System deps needed only at build time (e.g. for compiled wheels)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Create a venv so we can copy it cleanly to the runtime stage
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python deps first (layer cache optimisation)
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy source and install the package itself
COPY src/ src/
RUN pip install --no-cache-dir .

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM python:3.14-slim AS runtime

LABEL maintainer="AetherWall Team"
LABEL description="AetherWall — Enterprise Agent-to-[Agent/MCP] Gateway"

# Non-root user for security hardening
RUN groupadd --gid 1000 aether && \
    useradd --uid 1000 --gid aether --shell /bin/false aether

# Copy the pre-built venv from builder (includes all deps + package)
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy the config skeleton (users mount their own at runtime)
COPY aether.yaml /etc/aetherwall/aether.yaml

WORKDIR /app

# Switch to non-root
USER aether

EXPOSE 8000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

ENTRYPOINT ["uvicorn", "aetherwall.api.app:app"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
