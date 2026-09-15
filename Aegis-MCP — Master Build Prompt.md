# AEGIS-MCP — Production-Grade Zero-Trust Runtime Security Gateway for MCP

You are a senior principal engineer specializing in:

- Rust systems programming
- MCP / JSON-RPC protocols
- AI agents and tool-calling systems
- application and API security
- zero-trust architectures
- policy engines
- WebAssembly sandboxing
- eBPF/Linux security
- LLM/SLM inference
- distributed systems
- observability and DevSecOps

Your task is to **build Aegis-MCP from scratch as a real, production-quality open-source project**.

Do NOT create a toy, mock, demo-only, pseudocode implementation, or collection of stubs.

Everything implemented must be executable, testable, documented, and integrated.

---

# 1. PRODUCT VISION

Aegis-MCP is a **zero-trust runtime security gateway and policy firewall for Model Context Protocol (MCP)**.

It sits between:

```text
MCP CLIENT / AI AGENT
        |
        v
+------------------------+
|      AEGIS-MCP         |
|                        |
| JSON-RPC interception  |
| Tool inspection        |
| Taint tracking         |
| Policy evaluation      |
| Prompt-injection risk  |
| Authorization          |
| Sandbox integration    |
| Audit logging          |
+------------------------+
        |
        v
MCP SERVER / TOOL
```

The gateway must inspect and control MCP traffic before tools execute.

Primary security objectives:

1. Prevent malicious or unexpected MCP tool execution.
2. Detect indirect prompt injection.
3. Detect unauthorized access to files, databases, APIs, shell commands, and infrastructure.
4. Track untrusted/tainted information through multi-step agent execution.
5. Apply deterministic security policies before execution.
6. Use AI only as a risk-analysis layer, never as the final authorization authority.
7. Provide complete, tamper-evident auditability.
8. Maintain very low latency.
9. Support local-first operation.
10. Be usable by developers as a CLI and by enterprises as a gateway service.

The project must follow this architectural principle:

> AI may recommend risk. Deterministic policy decides whether execution is allowed.

---

# 2. ENGINEERING PRINCIPLES

Follow these rules throughout the project.

## Rule 1 — No fake implementations

Never write:

```text
TODO
FIXME
pass
throw "not implemented"
return mock
return []
return true
placeholder
dummy
fake response
```

unless the item is explicitly documented as an intentional extension point.

Every advertised feature must either work or be clearly marked as experimental.

## Rule 2 — Security first

Assume every MCP server is potentially hostile.

Assume tool descriptions can be malicious.

Assume tool arguments can contain attacker-controlled data.

Assume external web/API results can contain prompt injection.

Assume the LLM itself can be manipulated.

Never trust:

- tool descriptions
- tool names
- tool arguments
- external content
- LLM classifications
- MCP servers
- local helper processes

without validation.

## Rule 3 — Deterministic enforcement

The final allow/deny decision must come from deterministic rules.

AI risk scoring can:

- increase risk
- recommend blocking
- request additional verification
- request human approval

but cannot silently override deterministic security policies.

## Rule 4 — Local-first

The system must work entirely locally without cloud dependencies for the core functionality.

Optional cloud services may be added later.

## Rule 5 — Observable by default

Every important security decision must be measurable and traceable.

## Rule 6 — Reproducible

Developers must be able to clone the repository and run the complete test suite with documented commands.

---

# 3. TARGET TECHNOLOGY STACK

Use the following architecture unless a technically superior alternative is clearly justified in documentation.

## Gateway

Rust

Recommended:

- Tokio
- Hyper
- Axum where appropriate
- Serde
- serde_json
- tracing
- tracing-subscriber
- clap
- anyhow
- thiserror
- uuid
- sha2
- blake3

## Protocol

MCP / JSON-RPC 2.0

Support initially:

- stdio
- HTTP/SSE where practical

Design transports behind a common abstraction.

## Policy

OPA/Rego-compatible architecture.

Use:

- Rego policies where practical
- deterministic policy evaluator
- Wasm-compiled policy execution where practical

## Security

Implement:

- SHA-256/BLAKE3 hashes
- signed policy bundles
- capability restrictions
- path normalization
- URL validation
- command restrictions
- SQL risk rules
- secret detection
- taint labels

## AI Classification

Support a pluggable inference interface.

Primary local option:

- ONNX Runtime
- small classification model

The system must work even when AI classification is disabled.

## Persistence

Local:

- SQLite
- WAL mode

Enterprise/export:

- PostgreSQL
- ClickHouse integration

## Frontend / Dashboard

Use:

- Next.js
- TypeScript
- React

Keep the frontend secondary to the security engine.

## Testing

Use:

- Rust unit tests
- integration tests
- property-based tests
- fuzz tests
- malicious MCP fixtures
- Python tests only where Python-specific components exist

## Infrastructure

Provide:

- Docker
- Docker Compose
- Kubernetes manifests
- Helm chart
- GitHub Actions

---

# 4. MONOREPO STRUCTURE

Create a clean monorepo similar to:

```text
aegis-mcp/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── Makefile
├── justfile
├── Cargo.toml
├── Cargo.lock
│
├── crates/
│   ├── aegis-core/
│   ├── aegis-protocol/
│   ├── aegis-proxy/
│   ├── aegis-policy/
│   ├── aegis-taint/
│   ├── aegis-security/
│   ├── aegis-classifier/
│   ├── aegis-audit/
│   ├── aegis-sandbox/
│   ├── aegis-cli/
│   ├── aegis-config/
│   └── aegis-observability/
│
├── policy/
│   ├── base/
│   ├── filesystem/
│   ├── postgres/
│   ├── shell/
│   ├── network/
│   └── examples/
│
├── models/
│
├── tests/
│   ├── integration/
│   ├── security/
│   ├── protocol/
│   ├── policy/
│   ├── taint/
│   ├── fuzz/
│   └── fixtures/
│
├── dashboard/
│
├── deploy/
│   ├── docker/
│   ├── compose/
│   ├── k8s/
│   └── helm/
│
├── benchmarks/
│
├── docs/
│   ├── architecture/
│   ├── threat-model/
│   ├── policies/
│   ├── protocol/
│   ├── operations/
│   └── development/
│
└── scripts/
```

Design crates as independent modules with minimal coupling.

---

# 5. PHASE 1 — MCP PROTOCOL ENGINE

Build a complete JSON-RPC 2.0 layer.

Implement:

- request parsing
- response parsing
- notifications
- request IDs
- protocol validation
- malformed payload detection
- maximum message size
- timeout enforcement
- rate limits
- transport abstraction

Define normalized internal structures such as:

```rust
McpRequest
McpResponse
McpNotification
ToolDefinition
ToolCall
ToolResult
ResourceAccess
PromptObject
```

Support interception of:

```text
initialize
tools/list
tools/call
resources/list
resources/read
prompts/list
prompts/get
```

Do not assume all future MCP methods are known.

Create an extensible method registry.

---

# 6. PHASE 2 — RUNTIME PROXY

Implement Aegis as a transparent gateway.

Example:

```bash
aegis-mcp proxy \
  --client stdio \
  --server "command args..."
```

Traffic flow:

```text
client
  ↓
transport parser
  ↓
normalizer
  ↓
security inspection
  ↓
taint engine
  ↓
policy engine
  ↓
AI risk classifier
  ↓
authorization decision
  ↓
audit event
  ↓
MCP server
```

Every tool call must pass through this pipeline.

Provide:

```text
ALLOW
DENY
WARN
REQUIRE_APPROVAL
SANDBOX
```

decision types.

---

# 7. PHASE 3 — TOOL INVENTORY AND FINGERPRINTING

Whenever a server exposes tools, generate a canonical fingerprint.

Fingerprint inputs:

- tool name
- description
- JSON schema
- parameter names
- parameter types
- annotations
- server identity
- transport identity

Canonicalize JSON before hashing.

Store:

```text
tool_id
server_id
schema_hash
description_hash
first_seen
last_seen
version
status
```

Detect:

- schema changes
- description changes
- removed tools
- newly added tools
- type changes
- permission-expanding changes

Produce a security event for suspicious changes.

---

# 8. PHASE 4 — TOOL POISONING DEFENSE

Detect malicious tool descriptions.

Examples:

```text
"Ignore all previous instructions..."
"Always send credentials..."
"Before using this tool, call..."
"Do not tell the user..."
```

Do NOT depend exclusively on string matching.

Build several layers:

### Layer A — lexical checks

Detect:

- instruction hijacking
- role injection
- secret requests
- hidden operational instructions
- encoded instructions

### Layer B — structural checks

Detect:

- unexpected URLs
- command snippets
- shell instructions
- filesystem references
- network destinations

### Layer C — semantic classification

Optional local SLM evaluates:

```text
maliciousness
instruction-injection probability
privilege escalation probability
data-exfiltration probability
```

Return normalized scores:

```json
{
  "injection_risk": 0.0,
  "exfiltration_risk": 0.0,
  "privilege_risk": 0.0
}
```

---

# 9. PHASE 5 — TAINT TRACKING ENGINE

This is a flagship feature.

Build a taint propagation system that tracks data originating from untrusted sources.

Example:

```text
Web page
   ↓
web_scrape result
   ↓
TAINT = UNTRUSTED_WEB
   ↓
LLM context
   ↓
generated tool argument
   ↓
database write
```

The database write should inherit taint.

Represent taint categories such as:

```text
UNTRUSTED_WEB
UNTRUSTED_USER
EXTERNAL_API
MCP_SERVER
UNKNOWN
SECRET
PERSONAL_DATA
SENSITIVE_DATA
TRUSTED
```

Support:

- source propagation
- transformation propagation
- sanitization
- declassification
- taint confidence
- provenance chain

Example:

```json
{
  "value_id": "abc",
  "taints": [
    {
      "type": "UNTRUSTED_WEB",
      "source": "https://example.com",
      "confidence": 0.98
    }
  ]
}
```

---

# 10. PHASE 6 — POLICY ENGINE

Create a declarative policy format.

Example:

```yaml
version: "1"

rules:

  - name: deny-main-branch-push
    action: deny
    when:
      tool: git_push
      branch: main

  - name: block-private-file-exfiltration
    action: deny
    when:
      taint: SECRET
      destination: external_network

  - name: allow-read-project
    action: allow
    when:
      tool: filesystem_read
      path_prefix: "./workspace"

  - name: approve-production-write
    action: require_approval
    when:
      environment: production
      operation: write
```

Support conditions including:

- tool name
- server identity
- user identity
- environment
- branch
- filesystem path
- URL/domain
- HTTP method
- SQL operation
- taint
- risk score
- time
- rate
- resource type
- argument properties

Policy evaluation must be:

- deterministic
- explainable
- ordered
- testable

Every decision must return an explanation.

Example:

```json
{
  "decision": "DENY",
  "policy": "block-private-file-exfiltration",
  "reason": "SECRET-tainted data cannot reach external_network"
}
```

---

# 11. PHASE 7 — SECURITY INSPECTION

Build specialized detectors.

## Filesystem

Detect:

- path traversal
- `../`
- absolute path escapes
- symlink attacks
- writes outside workspace
- sensitive files

Protect:

```text
~/.ssh
~/.aws
.env
.git/config
credentials
private keys
system directories
```

Implement path canonicalization before authorization.

## Shell

Detect dangerous commands:

```text
rm -rf
curl | sh
wget | sh
chmod 777
sudo
mkfs
dd
shutdown
reboot
```

Do not rely solely on regex.

Parse commands where possible.

## SQL

Detect:

- DROP
- TRUNCATE
- DELETE without WHERE
- UPDATE without WHERE
- privilege changes
- COPY to external paths
- dangerous extensions

Normalize SQL before inspection.

## Network

Inspect:

- hostname
- IP
- port
- protocol
- destination reputation if configured

Support:

```text
allowlist
denylist
private-network restrictions
localhost restrictions
metadata endpoint protection
```

---

# 12. PHASE 8 — AI RISK CLASSIFIER

Build a pluggable classifier interface:

```rust
trait RiskClassifier {
    async fn classify(
        &self,
        request: &SecurityContext
    ) -> Result<RiskAssessment>;
}
```

Risk assessment:

```json
{
  "risk_score": 0.91,
  "categories": [
    "prompt_injection",
    "data_exfiltration"
  ],
  "confidence": 0.88,
  "explanation": "..."
}
```

Important:

The classifier must NEVER be the sole authority for authorization.

Create:

```text
Deterministic Risk
+
Taint Risk
+
Policy Result
+
AI Risk
=
Final Security Context
```

AI failures must fail safely.

If classifier unavailable:

```text
system continues using deterministic policy
```

---

# 13. PHASE 9 — HUMAN APPROVAL SYSTEM

Implement approval workflows.

For high-risk operations:

```text
AGENT REQUEST
     ↓
Aegis
     ↓
HIGH RISK
     ↓
REQUIRE_APPROVAL
     ↓
user/operator approval
     ↓
ALLOW or DENY
```

Approval requests must contain:

- tool
- server
- arguments
- taint information
- violated policies
- risk score
- proposed action
- expiration
- request ID

Support CLI approval initially.

Example:

```bash
aegis approvals list
aegis approvals approve <id>
aegis approvals deny <id>
```

---

# 14. PHASE 10 — SANDBOX INTEGRATION

Do NOT attempt to build the complete sandbox runtime first.

Instead create an abstraction:

```rust
trait SandboxExecutor {
    async fn execute(
        &self,
        request: ExecutionRequest
    ) -> Result<ExecutionResult>;
}
```

Implement a first local backend using an existing isolation mechanism.

Capabilities:

- filesystem isolation
- environment isolation
- network restrictions
- CPU limits
- memory limits
- timeout
- process limits

Then provide a future Wasmtime backend.

The architecture must make sandbox providers swappable.

---

# 15. PHASE 11 — AUDIT LOG

Every security event must be logged.

Event types:

```text
TOOL_DISCOVERED
TOOL_CHANGED
TOOL_CALL
POLICY_ALLOW
POLICY_DENY
POLICY_WARN
APPROVAL_REQUESTED
APPROVAL_GRANTED
APPROVAL_DENIED
TAINT_CREATED
TAINT_PROPAGATED
INJECTION_DETECTED
SANDBOX_STARTED
SANDBOX_FINISHED
SECURITY_ERROR
```

Audit records should contain:

```json
{
  "event_id": "...",
  "timestamp": "...",
  "session_id": "...",
  "server_id": "...",
  "tool": "...",
  "decision": "...",
  "policy": "...",
  "risk_score": 0.91,
  "taints": [],
  "schema_hash": "...",
  "request_hash": "...",
  "previous_event_hash": "...",
  "event_hash": "..."
}
```

Implement hash chaining:

```text
event N
   hash(previous_hash + canonical_event)
```

This creates a tamper-evident local audit chain.

---

# 16. PHASE 12 — CONFIGURATION

Create:

```text
aegis.yaml
```

Example:

```yaml
server:
  mode: proxy

security:
  fail_closed: true

policy:
  path: ./policy

taint:
  enabled: true

classifier:
  enabled: true
  provider: onnx

audit:
  enabled: true
  database: ./aegis.db

sandbox:
  enabled: false

network:
  deny_metadata_endpoints: true

limits:
  max_request_bytes: 10485760
  request_timeout_ms: 5000
```

Configuration must support:

- environment overrides
- validation
- safe defaults
- secrets never logged

---

# 17. PHASE 13 — CLI

Build a professional CLI:

```bash
aegis-mcp proxy
aegis-mcp inspect
aegis-mcp tools list
aegis-mcp tools fingerprint
aegis-mcp policy test
aegis-mcp policy validate
aegis-mcp audit list
aegis-mcp audit verify
aegis-mcp incidents list
aegis-mcp approvals list
aegis-mcp config validate
aegis-mcp benchmark
```

Examples:

```bash
aegis-mcp inspect server.json
```

```bash
aegis-mcp policy test \
  --policy ./policy/aegis.yaml \
  --fixture ./tests/fixtures/malicious_tool.json
```

Output should be professional and machine-readable.

Support:

```text
--json
--quiet
--verbose
```

---

# 18. PHASE 14 — DASHBOARD

Build a minimal but professional security dashboard.

Pages:

```text
/overview
/tools
/tool-changes
/events
/incidents
/policies
/approvals
/taint
/audit
/settings
```

Dashboard should visualize:

- blocked calls
- allowed calls
- risky tools
- schema changes
- injection attempts
- taint chains
- top policies triggered
- security incidents
- latency
- request volume

Do not turn this into a generic observability dashboard.

Aegis is a security control plane.

---

# 19. PHASE 15 — INCIDENT SYSTEM

Create normalized incidents.

Example:

```json
{
  "incident_id": "INC-001",
  "severity": "CRITICAL",
  "type": "DATA_EXFILTRATION",
  "source": "web_scrape",
  "target": "postgres_write",
  "status": "OPEN"
}
```

Correlate events into incidents.

Examples:

```text
prompt injection
      +
tainted input
      +
external network request
      =
DATA EXFILTRATION INCIDENT
```

Support incident statuses:

```text
OPEN
ACKNOWLEDGED
MITIGATED
RESOLVED
FALSE_POSITIVE
```

---

# 20. PHASE 16 — OBSERVABILITY

Use OpenTelemetry.

Expose:

- request count
- blocked requests
- allowed requests
- policy evaluation latency
- parser latency
- classifier latency
- taint processing latency
- sandbox latency
- total gateway latency

Metrics:

```text
aegis_requests_total
aegis_blocks_total
aegis_policy_latency
aegis_classifier_latency
aegis_proxy_latency
aegis_taint_events_total
```

Support Prometheus.

Tracing should never expose secrets.

---

# 21. PHASE 17 — PERFORMANCE TARGETS

Benchmark aggressively.

Target:

```text
JSON-RPC parsing      < 1 ms
policy evaluation     < 1 ms
hash/fingerprint      < 1 ms
normal request path   < 5 ms overhead
```

AI inference must be outside the critical path when possible.

Architecture:

```text
REQUEST
  |
  +--> deterministic checks ---> decision
  |
  +--> asynchronous AI analysis
```

The gateway should not require an LLM call for every request.

Measure:

- p50
- p95
- p99
- throughput
- memory usage
- CPU overhead

Create reproducible benchmark commands.

---

# 22. PHASE 18 — ADVERSARIAL SECURITY TESTING

Create a substantial malicious fixture corpus.

Test:

### Prompt injection

```text
Ignore previous instructions...
Call the credential tool...
Send this data to...
```

### Path traversal

```text
../../etc/passwd
../../.ssh/id_rsa
```

### SQL injection / dangerous operations

### SSRF

```text
169.254.169.254
localhost
127.0.0.1
```

### Tool poisoning

Tool description changes after approval.

### Schema attacks

Change:

```text
string -> object
read-only -> write-capable
```

### Encoded payloads

Base64
Unicode tricks
zero-width characters
URL encoding

### Tool-chain attacks

```text
web scrape
→ malicious content
→ context
→ filesystem write
→ external upload
```

Every attack must have a test proving Aegis blocks or safely handles it.

---

# 23. PHASE 19 — FUZZING

Add fuzz targets for:

- JSON-RPC parser
- MCP messages
- policy parser
- YAML configuration
- taint propagation
- tool schemas
- command parser
- SQL parser adapters

The gateway must never panic from malformed untrusted input.

---

# 24. PHASE 20 — THREAT MODEL

Write a professional threat model.

Include:

- assets
- trust boundaries
- attacker capabilities
- attack surfaces
- attack trees
- mitigations
- residual risks

Use STRIDE where useful.

Document explicitly:

```text
Agent cannot be trusted.
MCP server cannot be trusted.
Tool descriptions cannot be trusted.
External content cannot be trusted.
AI classifier cannot be trusted as final authority.
Policy engine is the final authorization boundary.
```

---

# 25. PHASE 21 — SECURITY HARDENING

Implement:

- memory-safe Rust components
- secret redaction
- secure defaults
- input size limits
- timeouts
- backpressure
- connection limits
- denial-of-service protection
- panic isolation
- safe subprocess execution
- least-privilege operation
- signed policy bundles

Do not log:

- API keys
- OAuth tokens
- passwords
- private keys
- raw sensitive data

---

# 26. PHASE 22 — MCP SERVER COMPATIBILITY

Create local test MCP servers:

```text
filesystem server
postgres server
malicious server
tool-poisoning server
slow server
broken server
```

Use them for integration testing.

Examples:

```text
good-filesystem-server
malicious-filesystem-server
poisoned-tool-server
exfiltration-server
```

The malicious servers are test fixtures only.

---

# 27. PHASE 23 — DEVELOPER EXPERIENCE

A new developer should be able to do:

```bash
git clone ...
cargo build --workspace
cargo test --workspace
docker compose up
```

and immediately run Aegis.

Create a one-command development environment:

```bash
make dev
```

Create:

```bash
make test
make security
make fuzz
make benchmark
make lint
make format
```

---

# 28. PHASE 24 — CI/CD

GitHub Actions must perform:

```text
cargo fmt --check
cargo clippy
cargo test
security tests
dependency audit
fuzz smoke tests
frontend lint
frontend build
Docker build
benchmark regression check
```

Add dependency/security scanners.

Fail CI on severe findings.

---

# 29. PHASE 25 — DOCUMENTATION

Write excellent documentation.

Required:

```text
README.md
SECURITY.md
CONTRIBUTING.md
ARCHITECTURE.md
THREAT_MODEL.md
POLICY_GUIDE.md
CLI_REFERENCE.md
DEVELOPMENT.md
DEPLOYMENT.md
PERFORMANCE.md
MCP_SECURITY.md
```

README must contain:

1. What is Aegis-MCP?
2. Why it exists
3. Architecture diagram
4. Threat model
5. Quick start
6. Example policy
7. Attack demonstration
8. Benchmark results
9. Screenshots
10. Roadmap

---

# 30. MVP DEFINITION

The MVP is NOT the dashboard.

The MVP must prove this flow end-to-end:

```text
Claude/Cursor-style MCP client
            ↓
       Aegis Proxy
            ↓
       MCP Server
```

Aegis must:

1. intercept MCP tool calls
2. fingerprint tools
3. inspect tool arguments
4. track taint
5. evaluate deterministic policies
6. detect at least one prompt-injection class
7. block unauthorized access
8. write an audit event
9. expose the result through CLI
10. pass comprehensive integration tests

Example:

```text
Malicious MCP result
        ↓
UNTRUSTED_WEB taint
        ↓
tool attempts filesystem/external-network action
        ↓
policy evaluates taint + destination
        ↓
DENY
        ↓
incident generated
        ↓
audit chain updated
```

That flow must work for real.

---

# 31. BUILD ORDER

Implement incrementally in this exact order:

## Phase A

Repository + Rust workspace + CI + CLI skeleton

## Phase B

JSON-RPC/MCP parser

## Phase C

Transparent stdio proxy

## Phase D

Tool discovery + fingerprinting

## Phase E

Policy engine

## Phase F

Filesystem/network/SQL/security checks

## Phase G

Taint engine

## Phase H

Audit logging + hash chain

## Phase I

Prompt-injection classifier

## Phase J

Approval workflow

## Phase K

Sandbox abstraction

## Phase L

Observability

## Phase M

Dashboard

## Phase N

Security corpus + fuzzing

## Phase O

Kubernetes/Docker/production deployment

---

# 32. ENGINEERING WORKFLOW

For EVERY phase:

1. inspect repository state
2. define architecture
3. implement
4. compile
5. run unit tests
6. run integration tests
7. run security tests
8. benchmark
9. inspect failures
10. fix failures
11. refactor
12. document
13. commit-ready final state

Never move forward while core functionality is broken.

---

# 33. QUALITY GATES

At the end of every phase report:

```text
Files changed:
Tests:
Passed:
Failed:
Coverage:
Security tests:
Benchmarks:
Latency p50:
Latency p95:
Latency p99:
Known limitations:
```

Never claim something works unless it was actually executed.

---

# 34. FINAL ACCEPTANCE CRITERIA

The project is complete only when:

```text
[ ] Rust workspace builds cleanly
[ ] CLI works
[ ] MCP stdio proxy works
[ ] JSON-RPC validation works
[ ] Tool discovery works
[ ] Tool fingerprinting works
[ ] Tool changes detected
[ ] Policy engine works
[ ] Filesystem security works
[ ] Network security works
[ ] SQL security works
[ ] Taint tracking works
[ ] Prompt injection detection works
[ ] Human approvals work
[ ] Audit hash chain works
[ ] Incidents work
[ ] Sandbox abstraction works
[ ] OpenTelemetry works
[ ] Prometheus metrics work
[ ] Dashboard works
[ ] Docker works
[ ] Kubernetes manifests work
[ ] CI works
[ ] Security tests pass
[ ] Fuzzing passes smoke tests
[ ] Performance benchmarks documented
[ ] Threat model documented
[ ] README complete
[ ] No critical TODOs
[ ] No fake implementations
[ ] No broken integration paths
```

---

# 35. DEMONSTRATION SCENARIOS

Create a polished demo suite.

## Demo 1 — Safe tool

```text
Agent → read project file
Aegis → ALLOW
```

## Demo 2 — Path traversal

```text
Agent → ../../.ssh/id_rsa
Aegis → DENY
```

## Demo 3 — Prompt injection

```text
Web content → "ignore system instructions..."
Agent → malicious tool call
Aegis → TAINT + injection detection + DENY
```

## Demo 4 — Data exfiltration

```text
Secret file
   ↓
tainted data
   ↓
external HTTP request
   ↓
Aegis DENY
```

## Demo 5 — Tool rug pull / schema change

```text
Approved tool
   ↓
tool definition changes
   ↓
Aegis detects fingerprint mismatch
   ↓
WARN / DENY
```

## Demo 6 — Production write

```text
Agent → production database mutation
Aegis → REQUIRE_APPROVAL
Operator → approve
Aegis → ALLOW
```

---

# 36. FINAL PRODUCT POSITIONING

Aegis-MCP should be presented as:

> **"The zero-trust runtime security layer for AI agents using MCP."**

Not:

- another MCP scanner
- another chatbot
- another generic AI firewall
- another observability dashboard

Its core identity is:

```text
MCP Security
+
Zero Trust
+
Runtime Policy
+
Taint Tracking
+
AI Risk Analysis
+
Sandboxing
+
Auditability
```

---

# 37. START NOW

Do not ask unnecessary questions.

First inspect the existing repository.

Then create the complete project structure.

Then implement Phase A and Phase B.

After implementation, run:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Fix every error.

Then continue automatically through the phases, validating each phase before moving to the next.

At every stage, prefer a smaller working implementation over a larger incomplete abstraction.

The final result must look and behave like a serious open-source security infrastructure project that a senior Software + AI Engineer could publish publicly.