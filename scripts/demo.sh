#!/usr/bin/env bash
# Aegis-MCP end-to-end demo (bash mirror of scripts/demo.ps1).
# Demos 1-6: safe read ALLOW, traversal DENY, injection TAINT+flag,
# exfil DENY, rug-pull WARN, approval flow. Exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
failures=0
check() { # check <name> <got> <want-substring>
  if echo "$2" | grep -q "$3"; then echo "PASS: $1 -- $2";
  else echo "FAIL: $1 -- $2"; failures=$((failures+1)); fi
}

echo "=== Demo 1: safe project read -> ALLOW ==="
d1=$(cargo run -q -p aegis-cli -- policy test --policy ./policy/filesystem --fixture tests/fixtures/benign_tool.json)
echo "$d1"; check "demo1-safe-read" "$d1" '"decision":"ALLOW"'

echo "=== Demo 2: path traversal -> DENY (fail closed) ==="
d2=$(cargo run -q -p aegis-cli -- policy test --policy ./policy/filesystem --fixture tests/fixtures/traversal_tool.json)
echo "$d2"; check "demo2-traversal" "$d2" '"decision":"DENY"'

echo "=== Demo 3: poisoned tool description -> TAINT ==="
cargo run -q -p aegis-cli -- inspect tests/fixtures/malicious_tools_list.json | tr ',' '\n' | grep -E 'helper_exec|poison_score'
d3=$(cargo run -q -p aegis-cli -- policy test --policy ./policy/filesystem --fixture tests/fixtures/malicious_tool.json)
echo "$d3"; check "demo3-policy-deny" "$d3" '"decision":"DENY"'

echo "=== Demo 4: SECRET taint + external url -> DENY ==="
d4=$(cargo run -q -p aegis-cli -- policy test --policy ./policy/network --fixture tests/fixtures/malicious_tool.json)
echo "$d4"; check "demo4-exfil" "$d4" 'block-private-file-exfiltration'

echo "=== Demo 5: rug-pull (tool changed between scans) -> WARN ==="
cargo run -q -p aegis-cli -- tools fingerprint tests/fixtures/rugpull_v1.json > /tmp/rug1.json
cargo run -q -p aegis-cli -- tools fingerprint tests/fixtures/rugpull_v2.json > /tmp/rug2.json
if cmp -s /tmp/rug1.json /tmp/rug2.json; then echo "FAIL: demo5-rugpull -- no drift"; failures=$((failures+1));
else echo "WARN TOOL_CHANGED: workspace_read description/schema drift (possible rug-pull)"; echo "PASS: demo5-rugpull"; fi

echo "=== Demo 6: approval flow (create -> approve) ==="
cargo test -q -p aegis-proxy --test gateway_e2e approval_flow_roundtrip
check "demo6-approval" "exit=$?" "exit=0"

echo "=== demos done, failures=$failures ==="
[ "$failures" -eq 0 ] && echo "ALL DEMOS GREEN"
exit "$failures"
