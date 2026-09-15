# syntax=docker/dockerfile:1
FROM rust:1.75-bookworm AS builder

WORKDIR /app

# Cache dependency resolution before copying full source.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p aegis-cli

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin aegis \
    && mkdir -p /app/policy /data \
    && chown -R aegis:aegis /app /data

WORKDIR /app

COPY --from=builder /app/target/release/aegis-mcp /usr/local/bin/aegis-mcp
COPY --chown=aegis:aegis policy ./policy
COPY --chown=aegis:aegis aegis.yaml ./aegis.yaml

USER aegis

EXPOSE 8787

ENTRYPOINT ["aegis-mcp"]
CMD ["serve", "--bind", "0.0.0.0:8787"]
