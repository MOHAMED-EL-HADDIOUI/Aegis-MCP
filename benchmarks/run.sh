#!/usr/bin/env bash
# Aegis-MCP micro-benchmarks: parse / policy / fingerprint + pass/fail vs targets.
# Run from the repo root:  ./benchmarks/run.sh   (or  bash benchmarks/run.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
cargo run --release -p aegis-cli -- benchmark --json | tee benchmarks/results.json
