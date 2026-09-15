"use client";

import { useEffect, useState } from "react";
import { getEvents, type AuditEvent } from "@/lib/api";
import Badge from "@/components/Badge";

export default function TaintPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getEvents()
      .then((all) => setEvents(all.filter((e) => e.taints.length > 0)))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const chains = new Map<string, AuditEvent[]>();
  for (const e of events) {
    for (const t of e.taints) {
      const list = chains.get(t) ?? [];
      list.push(e);
      chains.set(t, list);
    }
  }

  return (
    <div>
      <h1>Taint</h1>
      <p className="muted">
        Taint chains built client-side from the{" "}
        <code className="inline">taints</code> array on each event in{" "}
        <code className="inline">GET /api/events</code>. {events.length} tainted
        events in the current window.
      </p>
      {error && <div className="error">{error}</div>}
      {Array.from(chains.entries())
        .sort((a, b) => b[1].length - a[1].length)
        .map(([taint, list]) => (
          <div className="panel" key={taint}>
            <h3>
              <Badge value={taint} /> <span className="muted">{list.length} events</span>
            </h3>
            <ul>
              {list.slice(0, 20).map((e) => (
                <li key={e.event_id} className="mono">
                  {new Date(e.timestamp).toLocaleString()} — {e.tool}/
                  {e.event_type}
                  {e.decision ? ` [${e.decision}]` : ""} (risk{" "}
                  {e.risk_score.toFixed(2)})
                </li>
              ))}
            </ul>
            {list.length > 20 && (
              <p className="muted">…and {list.length - 20} more</p>
            )}
          </div>
        ))}
      {chains.size === 0 && !error && <p className="muted">No tainted events.</p>}
    </div>
  );
}
