"use client";

import { useEffect, useState } from "react";
import { getEvents, type AuditEvent } from "@/lib/api";

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getEvents()
      .then(setEvents)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div>
      <h1>Audit</h1>
      <p className="muted">
        Chain verification runs server-side via{" "}
        <code className="inline">aegis-mcp audit verify --config ./aegis.yaml</code>{" "}
        (returns <code className="inline">{"{checked, ok}"}</code>); the serve
        API exposes no verify endpoint, so this page shows the hash chain the
        dashboard can actually see. Verify locally before trusting this table.
      </p>
      {error && <div className="error">{error}</div>}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Event</th>
              <th>Previous hash</th>
              <th>Event hash</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.event_id}>
                <td className="mono" title={e.event_id}>
                  {e.event_id.slice(0, 8)}… ({e.event_type})
                </td>
                <td className="mono" title={e.previous_event_hash}>
                  {e.previous_event_hash.slice(0, 16)}…
                </td>
                <td className="mono" title={e.event_hash}>
                  {e.event_hash.slice(0, 16)}…
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {events.length === 0 && !error && <p className="muted">No events.</p>}
    </div>
  );
}
