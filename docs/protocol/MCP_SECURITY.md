# MCP Security (protocol layer)

`crates/aegis-protocol/src/lib.rs` — JSON-RPC 2.0 validation, MCP method
registry, interception points, fingerprinting inputs, size limits, error codes.

## Validation rules (`parse_message`)

1. `raw.len() > max_bytes` → `TooLarge(len, max)` (default `max_bytes` =
   `limits.max_request_bytes` = 10 MiB from `aegis.yaml` / `AEGIS_MAX_BYTES`).
2. Body must parse as JSON → else `InvalidJson`.
3. `jsonrpc` must equal exactly `"2.0"` → else `BadVersion`.
4. `id`, when present, must be string/number/null → else `BadId`.
5. `method` missing + no `id` is tolerated as a response/notification shape;
   missing `method` on a request yields `MissingMethod` downstream. The parser
   **never panics** on malformed input (`malformed_never_panics` test feeds
   `"", "{", "null", "[]", "{\"jsonrpc\":\"2.0\"}"`).

## Method registry

Supported methods (`SUPPORTED_METHODS`):

| Method | Category (`method_params_map`) |
| ------ | ------------------------------ |
| `initialize` | handshake |
| `tools/list` | discovery |
| `tools/call` | execution |
| `resources/list` | discovery |
| `resources/read` | read |
| `prompts/list` | discovery |
| `prompts/get` | read |

`MethodRegistry::is_known` gates expectations (unknown methods are not
execution-authorized); `register` allows extension for future MCP methods.
Only `tools/call` with a non-empty `params.name` becomes a `ToolCall`;
`result.tools[]` arrays are captured as `ToolDefinition`s for fingerprinting.

## Transports (`Transport`, stdio + HTTP/SSE)

All transports move whole JSON-RPC text frames behind one trait
(`aegis-protocol::Transport::send`):

- **stdio** (primary, local): newline-delimited frames. `encode_stdio_frame`
  appends exactly one `\n`; `decode_stdio_frames` splits lossily and drops
  blanks — hostile bytes can never panic the framer.
- **HTTP** (remote servers): `HttpTransport` POSTs the frame to the base URL
  with `Accept: application/json, text/event-stream`. Responses are either
  plain JSON bodies or SSE streams unwrapped by `sse_jsonrpc_frames`.
  Only `http://` is supported (no TLS deps by design); `https://` fails
  closed. Upstream 4xx/5xx becomes an `upstream error` JSON-RPC `-32000`
  to the client — allowed calls that cannot reach upstream are errors, not
  silent drops.
- **SSE parsing** (`parse_sse_stream`): `event:`/`data:` fields, multi-line
  `data:` joined with `\n`, `:` comments skipped, CRLF tolerated. Events
  dispatch only on blank-line terminators — unterminated trailing bytes are
  buffered, not emitted (prevents split-event smuggling). Non-JSON `data:`
  lines (heartbeats) are skipped by `sse_jsonrpc_frames`.

Security properties: inspection happens **before** transport send in both
proxy modes (`proxy --server` and `proxy --upstream-url`); blocked calls
never touch the child or the network. Transport errors fail closed to the
client and are audited as `SECURITY_ERROR` paths, never forwarded.

## Interception points (`Gateway::handle_line`)

- **Parse failure** → `SECURITY_ERROR` audit event + JSON-RPC `-32700`
  (parse error), never forwarded.
- **Tool definitions** (any message carrying `result.tools`) → fingerprinted
  and recorded (`TOOL_DISCOVERED` / `TOOL_CHANGED`); message still forwarded
  (discovery is observable, not executable).
- **`tools/call`** → full `inspect_tool_call`; `ALLOW`/`WARN` forwarded
  transparently, anything else answered with `-32000`
  (`Aegis {decision}: [{policy}] {reason}`) and **not** forwarded.
- **Everything else** (notifications, `initialize`, `resources/*`,
  `prompts/*`) → forwarded after definition capture; resource reads are
  policy-relevant only insofar as their content later appears in tool args
  (taint path).

## Fingerprinting

`fingerprint_tool(server_id, name, description, schema)`:

- `schema_hash` = BLAKE3 over `canonical_json(schema)` (keys sorted
  recursively, compact encoding — key order cannot evade it).
- `description_hash` = BLAKE3 over raw description bytes.
- `tool_id` = first 16 hex chars of BLAKE3 over
  `server_id|name|schema_hash` (stable per server+tool+schema).

Genuine example (`tools fingerprint`, `--json`):

```json
{
  "tool": "helper",
  "tool_id": "e4fda54e1715cef7",
  "schema_hash": "daab8763027666431642f07715f7a023a50bec42b41650246d4603d8573bd281",
  "description_hash": "e85f756f186a4fa892e3e7bc2d855ebe1d5c5543b588da86527aa87d1bbf43b4",
  "poison_score": 1.0
}
```

## Size limits & error codes

| Limit | Default | Source |
| ----- | ------- | ------ |
| Max JSON-RPC line | 10 MiB | `limits.max_request_bytes` |
| Classifier budget | 800 ms (hard-coded) | `classify` timeout |
| Request timeout | 5 000 ms | `limits.request_timeout_ms` (validated 1–300 000) |

| Code | Meaning | Produced when |
| ---- | ------- | ------------- |
| `-32700` | Parse error | oversize / bad JSON / bad version |
| `-32603` | Internal error | error-response serialization fallback |
| `-32000` | Server error (Aegis denial) | policy/guardrail block with decision text |
