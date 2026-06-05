# Gatewarden Bridge — Multi-stage Docker build
# Usage:
#   docker build -t gatewarden-bridge -f bridge/Dockerfile .
#   docker run -v ./bridge.toml:/app/bridge.toml -p 4760:4760 gatewarden-bridge

FROM rust:1.80-slim AS builder

WORKDIR /usr/src/gatewarden
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY bridge/ bridge/
COPY spec/ spec/

RUN cargo build --release -p gatewarden-bridge

# ─── Runtime stage ─────────────────────────────────────────────────────────────

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/gatewarden/target/release/gatewarden-bridge /usr/local/bin/gatewarden-bridge

WORKDIR /app

# Default: expects bridge.toml mounted at /app/bridge.toml
ENTRYPOINT ["gatewarden-bridge"]
CMD ["bridge.toml"]

EXPOSE 4760

LABEL org.opencontainers.image.title="gatewarden-bridge"
LABEL org.opencontainers.image.description="Language-agnostic HTTP sidecar for hardened Keygen.sh license validation"
LABEL org.opencontainers.image.source="https://github.com/Michael-A-Kuykendall/gatewarden"
LABEL org.opencontainers.image.licenses="MIT"
