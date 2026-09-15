"use client";

import { useEffect, useState } from "react";
import { getEvents, type AuditEvent } from "@/lib/api";
import EventsTable from "@/components/EventsTable";

export default function ToolChangesPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getEvents()
      .then((all) => setEvents(all.filter((e) => e.event_type === "TOOL_CHANGED")))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div>
      <h1>Tool changes</h1>
      <p className="muted">
        Events with <code className="inline">event_type == TOOL_CHANGED</code>{" "}
        (schema/description drift detected by tool fingerprinting).{" "}
        {events.length} in the current window.
      </p>
      {error && <div className="error">{error}</div>}
      <EventsTable events={events} />
    </div>
  );
}
