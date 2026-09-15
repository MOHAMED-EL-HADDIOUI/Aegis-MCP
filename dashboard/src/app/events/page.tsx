"use client";

import { useEffect, useState } from "react";
import { getEvents, type AuditEvent } from "@/lib/api";
import EventsTable from "@/components/EventsTable";

export default function EventsPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    getEvents()
      .then(setEvents)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const q = filter.toLowerCase();
  const shown = events.filter(
    (e) =>
      q === "" ||
      e.tool.toLowerCase().includes(q) ||
      e.event_type.toLowerCase().includes(q) ||
      (e.decision ?? "").toLowerCase().includes(q)
  );

  return (
    <div>
      <h1>Events</h1>
      <p className="muted">
        Newest 100 rows from <code className="inline">GET /api/events</code> with
        decision badges.
      </p>
      {error && <div className="error">{error}</div>}
      <input
        className="input"
        placeholder="Filter by tool, event type, or decision…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <p className="muted">
        Showing {shown.length} of {events.length}
      </p>
      <EventsTable events={shown} />
    </div>
  );
}
