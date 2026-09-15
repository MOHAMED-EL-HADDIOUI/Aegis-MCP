import Badge from "./Badge";
import type { AuditEvent } from "@/lib/api";

function short(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

export default function EventsTable({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return <p className="muted">No events returned by GET /api/events.</p>;
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Tool</th>
            <th>Type</th>
            <th>Decision</th>
            <th>Risk</th>
            <th>Event</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.event_id}>
              <td className="mono">{new Date(e.timestamp).toLocaleString()}</td>
              <td className="mono">{e.tool}</td>
              <td className="mono">{e.event_type}</td>
              <td>{e.decision ? <Badge value={e.decision} /> : <span className="muted">—</span>}</td>
              <td className="mono">{e.risk_score.toFixed(2)}</td>
              <td className="mono" title={e.event_hash}>{short(e.event_id)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
