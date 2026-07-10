# Build stage. The tag tracks rust-toolchain.toml; rustup inside the image
# resolves the exact pinned patch release if the tag drifts ahead of it.
FROM rust:1.97-slim-bookworm AS builder
WORKDIR /app

# Static assets and migrations are embedded into the binary at compile time
# (include_str! and sqlx::migrate!), so the build needs the full source tree.
COPY . .
RUN cargo build --release --locked

# Runtime stage: a minimal image containing only the binary and TLS roots.
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/luxor /usr/local/bin/luxor

# A deployed image must never fall back to the development defaults; the
# platform still has to provide DATABASE_URL, REDIS_URL, and JWT_SECRET.
ENV APP_ENV=production

USER nobody
EXPOSE 3000
CMD ["luxor"]
