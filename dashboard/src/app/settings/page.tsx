"use client";

import { useEffect, useState } from "react";
import { apiBase } from "@/lib/api";

export default function SettingsPage() {
  const [base, setBase] = useState("");
  const [saved, setSaved] = useState<string | null>(null);

  useEffect(() => {
    setBase(
      localStorage.getItem("aegis-api-base") ??
        process.env.NEXT_PUBLIC_AEGIS_API ??
        "http://127.0.0.1:8787"
    );
  }, []);

  return (
    <div>
      <h1>Settings</h1>
      <p className="muted">
        API base URL used by <code className="inline">src/lib/api.ts</code>{" "}
        (compile-time default{" "}
        <code className="inline">NEXT_PUBLIC_AEGIS_API</code>, fallback{" "}
        <code className="inline">http://127.0.0.1:8787</code>). The live base is{" "}
        <code className="inline">{apiBase()}</code>.
      </p>
      <div className="panel">
        <label htmlFor="api-base">API base URL (preview only)</label>
        <input
          id="api-base"
          className="input"
          value={base}
          onChange={(e) => setBase(e.target.value)}
          placeholder="http://127.0.0.1:8787"
        />
        <p className="muted">
          Note: the fetch helpers read the base at build time from the
          environment, so editing this field only previews the value. To point
          the dashboard at another gateway, set{" "}
          <code className="inline">NEXT_PUBLIC_AEGIS_API</code> and rebuild.
        </p>
        <button
          className="btn"
          onClick={() => {
            localStorage.setItem("aegis-api-base", base);
            setSaved(base);
          }}
        >
          Save for reference
        </button>
        {saved && <p className="muted">Saved {saved} to localStorage.</p>}
      </div>
    </div>
  );
}
