// Typed fetch helpers for the aegis-mcp `serve` API (crates/aegis-cli/src/main.rs).
//
// Endpoints:
//   GET  /health            -> { ok: boolean; service: string }
//   GET  /api/events        -> { events: AuditEvent[] }      (newest 100)
//   GET  /api/incidents     -> { incidents: Incident[] }
//   GET  /api/approvals     -> { approvals: Approval[] }
//   POST /api/approvals/:id -> { ok, id, status }  (body { action: approve|deny })
//   POST /api/inspect       -> { ok, decision, policy, reason, risk_score, taints, latency_ms }
//   GET  /metrics           -> Prometheus text (not JSON; scraped by Prometheus)
//
// Field names below match crates/aegis-audit/src/lib.rs exactly:
//   AuditEvent: event_id, timestamp, session_id, server_id, tool, event_type,
//     decision ("ALLOW" | "DENY" | "WARN" | "REQUIRE_APPROVAL" | "SANDBOX" | null),
//     policy, reason, risk_score, taints, schema_hash, request_hash,
//     previous_event_hash, event_hash
//   Incident: incident_id, severity, incident_type, source, target, status, event_ids
//   Approval: id, tool, server, args, taints, policies, risk_score,
//     proposed_action, expires_at, status

export type Decision =
  | "ALLOW"
  | "DENY"
  | "WARN"
  | "REQUIRE_APPROVAL"
  | "SANDBOX";

export interface AuditEvent {
  event_id: string;
  timestamp: string;
  session_id: string;
  server_id: string;
  tool: string;
  event_type: string;
  decision: Decision | null;
  policy: string | null;
  reason: string | null;
  risk_score: number;
  taints: string[];
  schema_hash: string | null;
  request_hash: string;
  previous_event_hash: string;
  event_hash: string;
}

export interface Incident {
  incident_id: string;
  severity: string;
  incident_type: string;
  source: string;
  target: string;
  status: string;
  event_ids: string[];
}

export interface Approval {
  id: string;
  tool: string;
  server: string;
  args: unknown;
  taints: string[];
  policies: string[];
  risk_score: number;
  proposed_action: string;
  expires_at: string;
  status: string;
}

export interface Health {
  ok: boolean;
  service: string;
}

export function apiBase(): string {
  return (
    process.env.NEXT_PUBLIC_AEGIS_API ?? "http://127.0.0.1:8787"
  ).replace(/\/$/, "");
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${apiBase()}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`GET ${path} failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export async function getHealth(): Promise<Health> {
  return getJson<Health>("/health");
}

export async function getEvents(): Promise<AuditEvent[]> {
  const body = await getJson<{ events: AuditEvent[] }>("/api/events");
  return Array.isArray(body.events) ? body.events : [];
}

export async function getIncidents(): Promise<Incident[]> {
  const body = await getJson<{ incidents: Incident[] }>("/api/incidents");
  return Array.isArray(body.incidents) ? body.incidents : [];
}

export async function getApprovals(): Promise<Approval[]> {
  const body = await getJson<{ approvals: Approval[] }>("/api/approvals");
  return Array.isArray(body.approvals) ? body.approvals : [];
}

export interface ActionResult {
  ok: boolean;
  id?: string;
  status?: string;
  error?: string;
}

export async function decideApproval(
  id: string,
  action: "approve" | "deny",
): Promise<ActionResult> {
  const res = await fetch(`${apiBase()}/api/approvals/${encodeURIComponent(id)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action }),
    cache: "no-store",
  });
  const body = (await res.json().catch(() => ({}))) as ActionResult;
  if (!res.ok || !body.ok) {
    throw new Error(body.error ?? `POST /api/approvals/${id} failed: ${res.status}`);
  }
  return body;
}

export interface InspectResult {
  ok: boolean;
  decision: Decision;
  policy: string;
  reason: string;
  risk_score: number;
  taints: { kind: string; source: string; confidence: number }[];
  latency_ms: number;
}

export async function inspectCall(
  tool: string,
  args: unknown,
  server = "dashboard",
  session = "dashboard",
): Promise<InspectResult> {
  const res = await fetch(`${apiBase()}/api/inspect`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tool, args, server, session }),
    cache: "no-store",
  });
  const body = (await res.json().catch(() => ({}))) as InspectResult & { error?: string };
  if (!res.ok || !body.ok) {
    throw new Error(body.error ?? `POST /api/inspect failed: ${res.status}`);
  }
  return body;
}
