"use client";

import { useEffect, useState } from "react";
import { getIncidents, type Incident } from "@/lib/api";
import Badge from "@/components/Badge";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getIncidents()
      .then(setIncidents)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div>
      <h1>Incidents</h1>
      <p className="muted">
        From <code className="inline">GET /api/incidents</code>. Status changes
        require the CLI:{" "}
        <code className="inline">aegis-mcp incidents set &lt;id&gt; RESOLVED</code>{" "}
        (valid statuses: OPEN, ACKNOWLEDGED, MITIGATED, RESOLVED, FALSE_POSITIVE).
      </p>
      {error && <div className="error">{error}</div>}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Type</th>
              <th>Source → Target</th>
              <th>Status</th>
              <th>Events</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((i) => (
              <tr key={i.incident_id}>
                <td className="mono">{i.incident_id}</td>
                <td>
                  <Badge value={i.severity} />
                </td>
                <td className="mono">{i.incident_type}</td>
                <td className="mono">
                  {i.source} → {i.target}
                </td>
                <td>
                  <Badge value={i.status} />
                </td>
                <td className="mono">{i.event_ids.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {incidents.length === 0 && !error && <p className="muted">No incidents.</p>}
    </div>
  );
}
