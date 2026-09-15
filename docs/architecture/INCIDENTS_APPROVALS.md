# Incidents & Approvals

## Incident correlation rules

`correlate_incident` (`crates/aegis-audit/src/lib.rs`) inspects the last 10
audit events whenever a `DENY` with `risk_score >= 0.7` occurs
(`crates/aegis-proxy/src/lib.rs`). Rules, in priority order:

| Signals present | Severity | Type | Source → target |
| --------------- | -------- | ---- | --------------- |
| `INJECTION_DETECTED` + non-empty taints + egress tool (`http`/`fetch`/`upload` in name) | CRITICAL | DATA_EXFILTRATION | `web_scrape` → `external_network` |
| `INJECTION_DETECTED` + non-empty taints | HIGH | PROMPT_INJECTION | `untrusted_content` → `tool_call` |
| otherwise | — | no incident | — |

Created incidents get sequential IDs (`INC-001`, …) with the triggering
event IDs attached for forensics.

## Lifecycle

Incident `status` (`set_incident_status` validates membership):

```
OPEN → ACKNOWLEDGED → MITIGATED → RESOLVED
  └→ FALSE_POSITIVE (terminal, from any state)
```

Invalid transitions are rejected at the CLI/DB layer
(`incidents set` errors on unknown status). Approvals move
`PENDING → APPROVED | DENIED`, with overdue `PENDING` rows auto-transitioned
to `EXPIRED` by `sweep_expired()` on every approval read/write — no
background task needed. `set_approval` fails closed on expired or unknown
ids, so an approval can never be granted after its TTL.

## Approval flow

1. A verdict of `REQUIRE_APPROVAL` (policy `require_approval` action, AI
   escalation ≥ 0.6, or deterministic review ≥ 0.5) mints (or reuses) a
   `PENDING` request (`AuditLog::create_approval`: tool, server, args,
   taints, policies, risk, proposed action, 1 h expiry). Reuse is keyed on
   server + tool + canonical args (`find_pending_request`), so a retrying
   agent does not spam the queue — the block reason carries the id
   (`… (approval <id>)`).
2. Operators triage via CLI, dashboard, or REST:

   ```sh
   cargo run -p aegis-cli -- approvals list
   cargo run -p aegis-cli -- approvals approve <id>   # or: approvals deny <id>
   ```

   ```sh
   curl -X POST localhost:8787/api/approvals/<id> \
     -H 'content-type: application/json' -d '{"action":"approve"}'
   ```

   Each decision appends `APPROVAL_GRANTED` / `APPROVAL_DENIED` to the audit
   chain, so the authorization is itself tamper-evident.
3. An `APPROVED`, unexpired grant unblocks the **identical** call:
   `find_approved_grant` matches server + tool + canonical args and the
   gateway converts the verdict to `ALLOW` with policy `approval-grant`
   (proven live: `REQUIRE_APPROVAL` → approve → `ALLOW`/`approval-grant`;
   different args stay held). Rejected or expired approvals stay queryable
   via `approvals list` (pass-through of all rows; pending-only filter
   exists in `list_approvals(true)` for API use).

## CLI examples

```sh
# Incidents
cargo run -p aegis-cli -- incidents list
cargo run -p aegis-cli -- incidents set INC-001 ACKNOWLEDGED
cargo run -p aegis-cli -- incidents set INC-001 RESOLVED

# Approvals
cargo run -p aegis-cli -- approvals list
cargo run -p aegis-cli -- approvals approve 3f9c…   # APPROVAL_GRANTED event
cargo run -p aegis-cli -- approvals deny 3f9c…      # APPROVAL_DENIED event
```

Genuine empty-state outputs (fresh DB): `{"incidents":[]}`,
`{"approvals":[]}`. On an invalid status the commands fail closed with an
error (`invalid incident status` / `invalid approval status`) and emit no
state change.
