# Aegis-MCP end-to-end demo (Windows / PowerShell 5.1+).
# Demos 1-6: safe read ALLOW, traversal DENY, injection TAINT+flag,
# exfil DENY, rug-pull WARN, approval flow. Exits non-zero on any failure.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
$Failures = 0

function Check($Name, $Cond, $Detail) {
  if ($Cond) { Write-Output ("PASS: {0} -- {1}" -f $Name, $Detail) }
  else { Write-Output ("FAIL: {0} -- {1}" -f $Name, $Detail); $script:Failures++ }
}

Write-Output "=== Demo 1: safe project read -> ALLOW ==="
$d1 = cargo run -q -p aegis-cli -- policy test --policy ./policy/filesystem --fixture tests/fixtures/benign_tool.json | ConvertFrom-Json
Write-Output ("decision={0} policy={1}" -f $d1.decision, $d1.policy)
Check "demo1-safe-read" ($d1.decision -eq "ALLOW" -and $d1.policy -eq "allow-read-project") "project read allowed"

Write-Output "=== Demo 2: path traversal -> DENY (fail closed) ==="
$d2 = cargo run -q -p aegis-cli -- policy test --policy ./policy/filesystem --fixture tests/fixtures/traversal_tool.json | ConvertFrom-Json
Write-Output ("decision={0} policy={1} reason={2}" -f $d2.decision, $d2.policy, $d2.reason)
Check "demo2-traversal" ($d2.decision -eq "DENY") "traversal denied"

Write-Output "=== Demo 3: poisoned tool description -> TAINT (poison_score 1.0) ==="
$tools = cargo run -q -p aegis-cli -- inspect tests/fixtures/malicious_tools_list.json --json | ConvertFrom-Json
$evil = $tools.tools | Where-Object { $_.tool -eq "helper_exec" }
Write-Output ("tool={0} poison_score={1} urls={2}" -f $evil.tool, $evil.poison_score, ($evil.urls -join ","))
Write-Output ("reasons: " + ($evil.poison_reasons -join " | "))
Check "demo3-injection" ($evil.poison_score -ge 0.5) "injection flagged, gateway would REQUIRE_APPROVAL/DENY"
$d3 = cargo run -q -p aegis-cli -- policy test --policy ./policy/filesystem --fixture tests/fixtures/malicious_tool.json | ConvertFrom-Json
Write-Output ("policy on exfil-shaped call: decision={0} policy={1}" -f $d3.decision, $d3.policy)
Check "demo3-policy-deny" ($d3.decision -eq "DENY") "no allow rule matches, fail closed"

Write-Output "=== Demo 4: SECRET taint + external url -> DENY (block-private-file-exfiltration) ==="
$d4 = cargo run -q -p aegis-cli -- policy test --policy ./policy/network --fixture tests/fixtures/malicious_tool.json | ConvertFrom-Json
Write-Output ("decision={0} policy={1}" -f $d4.decision, $d4.policy)
Check "demo4-exfil" ($d4.decision -eq "DENY" -and $d4.policy -eq "block-private-file-exfiltration") "exfil blocked by named rule"

Write-Output "=== Demo 5: rug-pull (tool changed between scans) -> WARN ==="
$v1 = cargo run -q -p aegis-cli -- tools fingerprint tests/fixtures/rugpull_v1.json --json | ConvertFrom-Json
$v2 = cargo run -q -p aegis-cli -- tools fingerprint tests/fixtures/rugpull_v2.json --json | ConvertFrom-Json
$a = $v1.tools[0]; $b = $v2.tools[0]
Write-Output ("v1 desc={0} schema={1}" -f $a.description_hash.Substring(0,12), $a.schema_hash.Substring(0,12))
Write-Output ("v2 desc={0} schema={1}" -f $b.description_hash.Substring(0,12), $b.schema_hash.Substring(0,12))
$drift = ($a.description_hash -ne $b.description_hash) -or ($a.schema_hash -ne $b.schema_hash)
if ($drift) { Write-Output "WARN TOOL_CHANGED: workspace_read description/schema drift (possible rug-pull)" }
Check "demo5-rugpull" $drift "fingerprint drift detected"

Write-Output "=== Demo 6: approval flow (create -> approve) ==="
cargo test -q -p aegis-proxy --test gateway_e2e approval_flow_roundtrip
Check "demo6-approval" ($LASTEXITCODE -eq 0) "approval roundtrip test green"

Write-Output ("=== demos done, failures={0} ===" -f $Failures)
if ($Failures -gt 0) { exit 1 }
Write-Output "ALL DEMOS GREEN"
