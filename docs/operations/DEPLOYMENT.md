# Deployment

Aegis-MCP deploys as a single static-ish binary (`aegis-mcp`) plus
`aegis.yaml`, `policy/`, and a SQLite file. There is no required
sidecar: the proxy, audit DB, and `serve` API all live in one process.

Intended manifest paths (kept generic — if the `deploy/` scaffolding is
still being filled in, these are the contracts to implement):

- `deploy/docker/Dockerfile` — release build image.
- `deploy/compose/docker-compose.yml` — gateway + volume for `aegis.db`.
- `deploy/k8s/*.yaml` — Deployment/Service/ConfigMap(volume for
  `aegis.yaml`+`policy/`)/PVC(volume for DB).
- `deploy/helm/*` — chart wrapping the k8s manifests with values for
  `policy.path`, `audit.database`, classifier provider, and limits.

## Local binary

```sh
cargo build --workspace --release
./target/release/aegis-mcp --config ./aegis.yaml config validate
AEGIS_AUDIT_DB=/var/lib/aegis/aegis.db ./target/release/aegis-mcp proxy \
  --server "npx -y @modelcontextprotocol/server-filesystem ./workspace"
```

Keep `policy/` next to the working directory or set `AEGIS_POLICY_PATH`.
`aegis.db*` must be writable and backed up (chain tamper-evidence does not
survive file deletion).

## Docker

```sh
make docker
# docker build -f deploy/docker/Dockerfile -t aegis-mcp:0.1.0 .
docker run --rm -v ./policy:/policy:ro -v aegis-data:/data \
  -e AEGIS_POLICY_PATH=/policy -e AEGIS_AUDIT_DB=/data/aegis.db \
  aegis-mcp:0.1.0 proxy --server "<mcp server cmd>"
```

## Compose

```sh
make compose-up
# docker compose -f deploy/compose/docker-compose.yml up --build
```

The compose file should mount `./aegis.yaml` + `./policy` read-only and a
named volume for the DB, and expose `8787` for the `serve` API.

## Kubernetes / Helm

Generic contract: one Deployment (proxy over stdio to a co-located MCP
server container, or `serve` API behind a Service), ConfigMap for
`aegis.yaml` + `policy/` contents, PVC for `/data/aegis.db`, resource
limits sized from [PERFORMANCE.md](PERFORMANCE.md) (CPU well under 1 core
for proxy workloads; memory dominated by message size, cap ~512 Mi–1 Gi).
Liveness: `serve`'s `GET /health` (`{"ok":true,"service":"aegis-mcp"}`);
readiness: `audit verify` via an exec probe or sidecar. Helm values mirror
`Config` fields (`security.fail_closed`, `policy.path`, `audit.database`,
`classifier.provider`, `network.*`, `limits.*`) — never bake secrets into
values; mount them and let redaction do its job.

## Checklist

- [ ] `config validate` + per-file `policy validate` green (`make security`).
- [ ] `audit verify` → `{"ok":true}` on the deployed DB path.
- [ ] `fail_closed: true`, metadata-endpoint denial on, `policy/` mounted ro.
- [ ] DB volume persistent + backed up; `*.db-wal`/`*.db-shm` alongside.
- [ ] `serve` bound to localhost or mTLS ingress (API has no auth layer).
- [ ] Prometheus scraping `serve` metrics / dashboard pointed at `/api/*`.
- [ ] Signed bundles: if `require_signed`, mount `bundle.json` ro, inject
  the public key via env (`AEGIS_POLICY_PUBLIC_KEY`, never baked into the
  image), and verify startup logs show `loaded verified signed policy
  bundle`. Rotate by re-signing and rolling the DaemonSet/Deployment.
- [ ] OTel: point `otlp_endpoint` at the local collector over `http://`
  (e.g. `http://otel-collector:4318`); confirm `traceparent` propagates
  through `POST /api/inspect` and spans arrive with redacted attributes
  (tool/decision/policy only).
