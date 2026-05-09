# Changelog

## v2.1.0 — 2026-05-09

### Security (C6)
- `MCP_CA_CERT` env var — path to backend TLS certificate for verification
- `httpx.AsyncClient(verify=MCP_CA_CERT or True)` — verifies backend EC P-256 self-signed cert when `MCP_CA_CERT` is set; falls back to system CAs (or `True` for skip-verify) when unset
- Compatible with `GRAV_MCP_URL=https://...` (backend must run with TLS via `--ssl-certfile`)

## v2.0.0
### 07-05-2026
* **BREAKING** : suppression du cache `tools/list` — le proxy devient transparent pour toutes les requêtes MCP
* Chaque `tools/list` est désormais relayé directement au backend ; le schéma exposé est toujours celui du backend en temps réel
* Suppression de `_tools_cache`, `_fetch_tools()`, et du warm-up au démarrage
* **Bénéfice** : toute évolution du schéma backend est visible immédiatement sans redémarrage du proxy
* Migration : reconnecter le connecteur MCP côté client (Claude.ai) après la mise à jour pour rafraîchir le schéma côté session

## v1.1.0
### 03-05-2026
* RFC 7591 dynamic client registration — `POST /register` endpoint (required by Claude.ai)
* `registration_endpoint` added to `/.well-known/oauth-authorization-server` metadata
* `WWW-Authenticate` header on all 401 responses (RFC 6750 + RFC 9728)
* `resource` URL corrected to `/mcp` (was `/oauth-mcp/mcp`)
* `/.well-known/oauth-protected-resource/{path}` now accepts any path suffix
* Fix double audit logging (handler guard on module re-import)

## v1.0.0
### 17-04-2026
* Initial release
* FastAPI OAuth 2.1 proxy for Grav CMS MCP Server
* PKCE S256 support — RFC 9728 compliant
* SHA-256 token hashing — tokens never stored in plain text
* Atomic JSON writes — no state file corruption
* Hardened systemd unit (NoNewPrivileges, ProtectSystem=strict,
  IPAddressDeny=any, MemoryDenyWriteExecute)
* nginx vhost template with location /mcp
* Automated install.sh for Ubuntu 22.04/24.04 and Debian 12
* Auto-sync GRAV_TOKEN between proxy and grav-plugin-mcp-server
