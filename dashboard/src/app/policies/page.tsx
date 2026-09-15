export default function PoliciesPage() {
  return (
    <div>
      <h1>Policies</h1>
      <p className="muted">
        The serve API is read-only and exposes no policy endpoint, so this page
        documents how policies work instead of inventing data.
      </p>
      <div className="panel">
        <h3>Where policies live</h3>
        <p>
          YAML rule files under the repository <code className="inline">policy/</code>{" "}
          directory (e.g. <code className="inline">policy/base/defaults.yaml</code>,{" "}
          <code className="inline">policy/filesystem/base.yaml</code>), loaded from
          the path in <code className="inline">aegis.yaml</code>{" "}
          (<code className="inline">policy.path</code>).
        </p>
      </div>
      <div className="panel">
        <h3>CLI workflow</h3>
        <ul className="mono">
          <li>aegis-mcp policy validate --policy ./policy</li>
          <li>aegis-mcp policy test --policy ./policy --fixture fixture.json</li>
          <li>aegis-mcp config validate --config ./aegis.yaml</li>
        </ul>
      </div>
      <div className="panel">
        <h3>Rule shape</h3>
        <p className="muted">
          Each file declares <code className="inline">version: &quot;1&quot;</code>{" "}
          and a <code className="inline">rules</code> list with{" "}
          <code className="inline">name</code>,{" "}
          <code className="inline">action</code> (allow / deny / require_approval)
          and a <code className="inline">when</code> matcher (tool, path,
          path_prefix, branch, …). Evaluation outcomes appear on events as the{" "}
          <code className="inline">policy</code>,{" "}
          <code className="inline">reason</code> and{" "}
          <code className="inline">decision</code> fields in /api/events.
        </p>
      </div>
    </div>
  );
}
