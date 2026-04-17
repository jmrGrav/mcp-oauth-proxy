# Changelog

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
