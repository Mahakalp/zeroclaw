# syntax=docker/dockerfile:1.7

# ── Builder Stage (Rust + Frontend) ────────────────────────────────
FROM rust:1.93-slim@sha256:9663b80a1621253d30b146454f903de48f0af925c967be48c84745537cd35d8b AS builder

WORKDIR /app

# Install bun for frontend builds
RUN curl -fsSL https://bun.sh/install | bash && \
    ln -sf /root/.bun/bin/bun /usr/local/bin/bun

# Verify bun is installed
RUN /usr/local/bin/bun --version

# Install build dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 1. Copy manifests to cache Rust dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates/robot-kit/Cargo.toml crates/robot-kit/Cargo.toml
# Create dummy targets declared in Cargo.toml so manifest parsing succeeds.
RUN mkdir -p src benches crates/robot-kit/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > benches/agent_benchmarks.rs \
    && echo "pub fn placeholder() {}" > crates/robot-kit/src/lib.rs
RUN --mount=type=cache,id=zeroclaw-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=zeroclaw-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=zeroclaw-target,target=/app/target,sharing=locked \
    cargo build --release --locked
RUN rm -rf src benches crates/robot-kit/src

# 2. Copy frontend package files first for dependency caching
COPY web/package.json web/bun.lock web/
RUN /usr/local/bin/bun install --frozen-lockfile

# 3. Copy build.rs and trigger frontend build (runs during cargo build)
COPY build.rs ./

# 4. Copy only build-relevant source paths (avoid cache-busting on docs/tests/scripts)
COPY src/ src/
COPY benches/ benches/
COPY crates/ crates/
COPY firmware/ firmware/

# Build Rust (build.rs will also build frontend)
# Set SKIP_FRONTEND_BUILD if frontend was already built and you want to skip rebuild
ENV BUN_INSTALL="/root/.bun"
ENV PATH="$BUN_INSTALL/bin:$PATH"
RUN --mount=type=cache,id=zeroclaw-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=zeroclaw-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=zeroclaw-target,target=/app/target,sharing=locked \
    cargo build --release --locked && \
    cp target/release/zeroclaw /app/zeroclaw && \
    strip /app/zeroclaw

# Verify frontend was embedded
RUN test -f web/dist/index.html || (echo "Frontend not embedded in binary" && exit 1)

# Prepare runtime directory structure and default config inline (no extra stage)
RUN mkdir -p /zeroclaw-data/.zeroclaw /zeroclaw-data/workspace && \
    cat > /zeroclaw-data/.zeroclaw/config.toml <<EOF && \
    chown -R 65534:65534 /zeroclaw-data
workspace_dir = "/zeroclaw-data/workspace"
config_path = "/zeroclaw-data/.zeroclaw/config.toml"
api_key = ""
default_provider = "openrouter"
default_model = "anthropic/claude-sonnet-4-20250514"
default_temperature = 0.7

[gateway]
port = 42617
host = "[::]"
allow_public_bind = true
EOF

# ── Runtime Stage ─────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:nonroot

# Copy binary from builder
COPY --from=builder /app/zeroclaw /usr/local/bin/zeroclaw
COPY --chmod=755 --from=builder /app/web /app/web
COPY --from=builder /zeroclaw-data /zeroclaw-data

WORKDIR /

# Run as non-root user
USER nonroot

# Expose gateway port
EXPOSE 42617

ENTRYPOINT ["zeroclaw"]
CMD ["gateway"]
