# Migration to Go — mcp-runtime-go

## Why Go Was Created

The Python proxy (`mcp-oauth-proxy`) was written as a focused, fast-to-ship implementation. It works reliably and remains production-authoritative. However, several operational concerns motivated building a Go successor:

- **Observability gap**: Python's audit log lacked per-request correlation IDs, making shadow comparison impossible without time-based heuristics.
- **Type safety**: OAuth flow logic (PKCE, redirect URI validation, token hashing) benefits from compile-time guarantees.
- **Operational hardening**: Go binaries are easier to confine with systemd (`MemoryDenyWriteExecute`, `ProtectSystem=strict`) and produce smaller, self-contained deployments.
- **Future scale**: The Go runtime is designed as a multi-domain host — it can serve both the MCP OAuth proxy and a future Hugo MCP domain from a single process with shared security and observability infrastructure.

## Go Repository

**[https://github.com/jmrGrav/mcp-runtime-go](https://github.com/jmrGrav/mcp-runtime-go)**

## Migration Strategy

The migration follows a **zero-downtime shadow deployment** approach. Python never stops until Go is verified.

```
Phase 1 — Foundation (complete)
  Go runtime built with full OAuth parity:
  RFC 6749, RFC 7591, RFC 8414, RFC 9728, PKCE S256,
  TLS backend verification, token store compatibility.

Phase 2 — Parity Validation (complete)
  - shadow-compare tool built
  - Security stress tests (invalid PKCE, path traversal, timing attacks)
  - Full test suite with race detector

Phase 3 — Shadow Deployment (active)
  - Go runs on a separate port (non-authoritative)
  - OpenResty mirrors all OAuth traffic to Go
  - Audit logs compared after 24h+ observation window
  - Cutover blocked until gate passes

Phase 4 — Cutover (pending shadow gate)
  - OpenResty upstream switched from Python to Go
  - Python stopped only after Go is verified live
  - Python files preserved (not deleted)
  - Rollback documented and tested

Phase 5 — Hugo MCP Domain (planned)
  - Hugo MCP integrated as second domain in Go runtime
  - SQLite token store for multi-domain scale
```

## Shadow Deployment in Detail

OpenResty uses nginx's `mirror` directive to send a best-effort copy of every request to the Go service:

```nginx
location / {
    proxy_pass http://python_authoritative;
    mirror /__go_shadow;
    mirror_request_body on;
}

location = /__go_shadow {
    internal;
    proxy_pass http://go_shadow;
}
```

The Go service logs every decision to a structured JSON audit log. After a 24h+ observation window, `shadow-compare` compares the Python and Go logs:

- **Match by request ID** (primary, when correlation header is available)
- **Match by time + event + source IP** (fallback, 2s window, for mirror traffic)
- **Gate criteria**: 0 critical mismatches, 0 unmatched critical events (token_issued, authorize_approved, client_registered)

## Current Recommendation

| Use case | Recommendation |
|---|---|
| Production traffic now | Python (`mcp-oauth-proxy`) — authoritative |
| New deployments | Wait for Go shadow gate to pass |
| Development / testing | Go (`mcp-runtime-go`) |
| Hugo MCP | Go (`mcp-runtime-go`) — planned |

The Python implementation is not deprecated. It remains the reference implementation and will be maintained until the Go cutover is complete and stable.
