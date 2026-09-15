"use client";

import { useEffect, useState } from "react";
import { decideApproval, getApprovals, type Approval } from "@/lib/api";
import Badge from "@/components/Badge";

export default function ApprovalsPage() {
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  function refresh() {
    getApprovals()
      .then(setApprovals)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }

  useEffect(refresh, []);

  async function decide(id: string, action: "approve" | "deny") {
    setBusy(id + action);
    setError(null);
    try {
      await decideApproval(id, action);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <h1>Approvals</h1>
      <p className="muted">
        From <code className="inline">GET /api/approvals</code>. Decisions POST
        to <code className="inline">/api/approvals/:id</code> with{" "}
        <code className="inline">{`{"action": "approve"|"deny"}`}</code> — the
        same fail-closed semantics as the CLI (expired or unknown ids are
        rejected with 422). Approving a request unblocks the identical tool
        call via an expiring grant.
      </p>
      {error && <div className="error">{error}</div>}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Tool</th>
              <th>Risk</th>
              <th>Action</th>
              <th>Status</th>
              <th>Decide</th>
            </tr>
          </thead>
          <tbody>
            {approvals.map((a) => (
              <tr key={a.id}>
                <td className="mono" title={a.id}>
                  {a.id.slice(0, 8)}…
                </td>
                <td className="mono">{a.tool}</td>
                <td className="mono">{a.risk_score.toFixed(2)}</td>
                <td className="mono">{a.proposed_action}</td>
                <td>
                  <Badge value={a.status} />
                </td>
                <td>
                  <button
                    className="btn"
                    disabled={a.status !== "PENDING" || busy !== null}
                    title={
                      a.status !== "PENDING"
                        ? `already ${a.status.toLowerCase()}`
                        : "approve this request (creates an expiring grant)"
                    }
                    onClick={() => void decide(a.id, "approve")}
                  >
                    {busy === a.id + "approve" ? "…" : "Approve"}
                  </button>{" "}
                  <button
                    className="btn"
                    disabled={a.status !== "PENDING" || busy !== null}
                    title={
                      a.status !== "PENDING"
                        ? `already ${a.status.toLowerCase()}`
                        : "deny this request"
                    }
                    onClick={() => void decide(a.id, "deny")}
                  >
                    {busy === a.id + "deny" ? "…" : "Deny"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {approvals.length === 0 && !error && <p className="muted">No approvals.</p>}
      <div className="panel">
        <p className="mono muted">
          aegis approvals approve &lt;id&gt; / aegis approvals deny &lt;id&gt;
        </p>
      </div>
    </div>
  );
}
