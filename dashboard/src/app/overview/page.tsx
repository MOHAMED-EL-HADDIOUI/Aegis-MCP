"use client";

import { useEffect, useState } from "react";
import { getEvents, getHealth, type AuditEvent, type Health } from "@/lib/api";

export default function OverviewPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        setHealth(await getHealth());
        setEvents(await getEvents());
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, []);

  const blocked = events.filter((e) => e.decision === "DENY").length;
  const allowed = events.filter((e) => e.decision === "ALLOW").length;
  const approvals = events.filter((e) => e.decision === "REQUIRE_APPROVAL").length;

  const byTool = new Map<string, number>();
  for (const e of events) {
    if (e.decision === "DENY") byTool.set(e.tool, (byTool.get(e.tool) ?? 0) + 1);
  }
  const riskyTools = Array.from(byTool.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10);

  const avgRisk =
    events.length === 0
      ? 0
      : events.reduce((s, e) => s + e.risk_score, 0) / events.length;

  return (
    <div>
      <h1>Overview</h1>
      <p className="muted">
        Live read of <code className="inline">GET /health</code> and{" "}
        <code className="inline">GET /api/events</code> (newest 100 events).
      </p>
      {error && <div className="error">{error}</div>}
      <div className="cards">
        <div className="card">
          <div className="label">Gateway</div>
          <div className="value">{health ? (health.ok ? "UP" : "DOWN") : "…"}</div>
        </div>
        <div className="card">
          <div className="label">Events seen</div>
          <div className="value">{events.length}</div>
        </div>
        <div className="card">
          <div className="label">Blocked</div>
          <div className="value">{blocked}</div>
        </div>
        <div className="card">
          <div className="label">Allowed</div>
          <div className="value">{allowed}</div>
        </div>
        <div className="card">
          <div className="label">Need approval</div>
          <div className="value">{approvals}</div>
        </div>
      </div>
      <div className="panel">
        <h3>Riskiest tools (by DENY count, client-side)</h3>
        {riskyTools.length === 0 ? (
          <p className="muted">No denied tool calls in the current window.</p>
        ) : (
          <ul>
            {riskyTools.map(([tool, n]) => (
              <li key={tool} className="mono">
                {tool}: {n} blocked
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="panel">
        <h3>Latency note</h3>
        <p className="muted">
          The serve API does not expose per-request latency. For gateway latency
          budgets see the benchmark targets: run{" "}
          <code className="inline">aegis-mcp benchmark --json</code> (parse_us,
          policy_us and fingerprint_us must each stay under 1000µs). Average
          risk_score in the current window: {avgRisk.toFixed(3)}.
        </p>
      </div>
    </div>
  );
}
