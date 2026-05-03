# Changelog

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
