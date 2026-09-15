# Aegis-MCP developer workflows (just syntax; mirrors Makefile).
# Install just: https://just.systems — or use `make <target>` instead.
BIND := "127.0.0.1:8787"

help:
    @echo "Targets: dev build test security fuzz benchmark lint format docker compose-up dashboard serve clean"

dev:
    cargo build --workspace

build:
    cargo build --workspace --release

test:
    cargo test --workspace

# Full security gate: unit tests + config/policy validation + audit-chain demo.
security:
    cargo test --workspace
    cargo run -q -p aegis-cli -- config validate
    cargo run -q -p aegis-cli -- policy validate --policy ./policy
    cargo run -q -p aegis-cli -- policy validate --policy ./policy/filesystem/base.yaml
    cargo run -q -p aegis-cli -- policy validate --policy ./policy/network/base.yaml
    cargo run -q -p aegis-cli -- policy validate --policy ./policy/postgres/base.yaml
    cargo run -q -p aegis-cli -- policy validate --policy ./policy/shell/base.yaml
    cargo run -q -p aegis-cli -- policy validate --policy ./policy/base/defaults.yaml
    AEGIS_AUDIT_DB=":memory:" cargo run -q -p aegis-cli -- audit verify

# Stable-Rust fuzz harness (no nightly needed): unit corpus + short binary runs.
fuzz:
    cargo test -p aegis-fuzz
    cargo run -q -p aegis-fuzz --bin fuzz-protocol tests/fuzz/corpus 200
    cargo run -q -p aegis-fuzz --bin fuzz-security tests/fuzz/corpus 200
    cargo run -q -p aegis-fuzz --bin fuzz-policy tests/fuzz/corpus 200
    cargo run -q -p aegis-fuzz --bin fuzz-config tests/fuzz/corpus 200

benchmark:
    cargo run -q -p aegis-cli -- benchmark --json

lint:
    cargo clippy --workspace --all-targets -- -D warnings

format:
    cargo fmt --all

docker:
    docker build -f deploy/docker/Dockerfile -t aegis-mcp:0.1.0 .

compose-up:
    docker compose -f deploy/compose/docker-compose.yml up --build

# Dashboard API backend (the Next.js app in dashboard/ consumes /api/*).
dashboard: serve

serve:
    cargo run -p aegis-cli -- serve --bind {{BIND}}

clean:
    cargo clean
