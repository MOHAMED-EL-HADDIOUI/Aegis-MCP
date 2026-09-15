"use client";

import { useEffect, useState } from "react";
import { getEvents, type AuditEvent } from "@/lib/api";
import Badge from "@/components/Badge";

export default function ToolsPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getEvents()
      .then(setEvents)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const seen = new Map<string, { calls: number; denies: number; servers: Set<string> }>();
  for (const e of events) {
    if (e.event_type !== "TOOL_DISCOVERED" && e.tool === "") continue;
    const row = seen.get(e.tool) ?? { calls: 0, denies: 0, servers: new Set<string>() };
    row.calls += 1;
    if (e.decision === "DENY") row.denies += 1;
    if (e.server_id) row.servers.add(e.server_id);
    seen.set(e.tool, row);
  }
  const rows = Array.from(seen.entries()).sort((a, b) => b[1].calls - a[1].calls);

  return (
    <div>
      <h1>Tools</h1>
      <p className="muted">
        Tools observed in <code className="inline">GET /api/events</code>. The CLI
        also offers <code className="inline">aegis-mcp tools list</code> (reads
        TOOL_DISCOVERED rows from the audit DB).
      </p>
      {error && <div className="error">{error}</div>}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Calls</th>
              <th>Denied</th>
              <th>Servers</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([tool, s]) => (
              <tr key={tool}>
                <td className="mono">{tool || "—"}</td>
                <td className="mono">{s.calls}</td>
                <td>
                  {s.denies > 0 ? <Badge value="DENY" /> : <span className="muted">0</span>}
                  <span className="mono"> {s.denies}</span>
                </td>
                <td className="mono">{Array.from(s.servers).join(", ") || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && !error && <p className="muted">No tools observed yet.</p>}
    </div>
  );
}
