# syntax=docker/dockerfile:1

# Base images are pinned by digest (Dependabot proposes updates). The tag
# next to each digest is informational.

# ---- build ------------------------------------------------------------------
FROM rust:1-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181 AS builder
WORKDIR /build

# Build dependencies first (cached until Cargo.toml/Cargo.lock change).
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

# Templates, stylesheet and migrations are compiled into the binary.
COPY src src
COPY templates templates
COPY static static
COPY migrations migrations
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# ---- runtime ----------------------------------------------------------------
# Distroless: glibc, CA certificates (mirror Verify checks TLS), nothing
# else: no shell, no package manager. The HEALTHCHECK uses the binary's own
# `healthcheck` subcommand.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

COPY --from=builder /build/target/release/filehost /app/filehost

# Fixed UID/GID so host directories (bind-mounted storage and incoming) can
# be chowned to match: sudo chown -R 10001:10001 data/storage
USER 10001:10001
WORKDIR /app
ENV STORAGE_PATH=/data/storage \
    INCOMING_PATH=/data/incoming \
    RUST_LOG=info,sqlx=warn
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/app/filehost", "healthcheck"]

ENTRYPOINT ["/app/filehost"]
