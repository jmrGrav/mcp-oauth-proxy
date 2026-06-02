# mcp-oauth-proxy

> FastAPI OAuth 2.1 proxy enabling Claude.ai to connect to any Grav CMS site
> via the Model Context Protocol (MCP).

## Architecture

```
Claude.ai
    │  HTTPS (OAuth 2.1 + Bearer token)
    ▼
Cloudflare
    │  HTTPS
    ▼
nginx  (mcp.your-domain.com)
    │  HTTP (loopback)
    ▼
mcp-oauth-proxy  (FastAPI, port 8083)
    │  HTTP + Bearer (GRAV_TOKEN, loopback)
    ▼
grav-plugin-mcp-server  (/api/mcp)
    │
    ▼
Grav CMS pages & tools
```

The proxy handles the full OAuth 2.1 Authorization Code + PKCE flow so that
Claude.ai can authenticate and call MCP tools exposed by
[grav-plugin-mcp-server](https://github.com/jmrGrav/grav-plugin-mcp-server).

**Design principle**: the proxy is *transparent* for MCP requests — it performs
authentication only and relays all tool calls (including `tools/list`) directly
to the backend. The backend is the single source of truth for tool schemas.
Schema changes are visible to clients immediately, without proxy restart.

## Security Features

- **OAuth 2.1** with PKCE S256 (mandatory for public clients)
- **Redirect URI whitelist** — only `*.claude.ai` and `*.anthropic.com` accepted
- **Tokens stored as SHA-256 hashes** — plain tokens never written to disk
- **Atomic token file writes** — prevents corruption under concurrent requests
- **Audit log** in JSON lines format (`/var/log/mcp-oauth/audit.log`)
- **Hardened systemd unit** — `NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, syscall filter `@system-service`, loopback-only
  network (`IPAddressDeny=any` + `IPAddressAllow=127.0.0.0/8`)
- `compare_digest` used for all credential comparisons (timing-safe)

## Prerequisites

- Ubuntu 22.04+ or Debian 12+
- nginx with SSL
- Python 3.11+
- [grav-plugin-mcp-server](https://github.com/jmrGrav/grav-plugin-mcp-server)
  installed and enabled on your Grav site
- A dedicated subdomain with a valid SSL certificate (e.g. `mcp.your-domain.com`)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/jmrGrav/mcp-oauth-proxy.git
cd mcp-oauth-proxy
```

### 2. Create the dedicated system user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcp-proxy
```

### 3. Install the proxy

```bash
sudo mkdir -p /opt/mcp-oauth-proxy /var/log/mcp-oauth /etc/mcp-oauth-proxy

# Copy source
sudo cp mcp_oauth_proxy.py /opt/mcp-oauth-proxy/

# Create virtualenv and install dependencies
sudo python3 -m venv /opt/mcp-oauth-proxy/venv
sudo /opt/mcp-oauth-proxy/venv/bin/pip install -r requirements.txt

# Set ownership
sudo chown -R mcp-proxy:mcp-proxy /opt/mcp-oauth-proxy /var/log/mcp-oauth
```

### 4. Configure secrets

```bash
sudo mkdir -p /etc/mcp-oauth-proxy
sudo cp secrets.env.example /etc/mcp-oauth-proxy/secrets.env
sudo nano /etc/mcp-oauth-proxy/secrets.env   # fill in all values
sudo chmod 600 /etc/mcp-oauth-proxy/secrets.env
sudo chown root:mcp-proxy /etc/mcp-oauth-proxy/secrets.env
```

See [Configuration](#configuration) below for the description of each variable.

### 5. Install the systemd service

```bash
sudo cp systemd/mcp-oauth-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-oauth-proxy
sudo systemctl status mcp-oauth-proxy
```

### 6. Configure nginx

```bash
# Adapt the vhost template to your domain
sudo cp nginx/mcp-vhost.conf /etc/nginx/sites-available/mcp.your-domain.com
sudo nano /etc/nginx/sites-available/mcp.your-domain.com

sudo ln -s /etc/nginx/sites-available/mcp.your-domain.com \
           /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 7. Connect Claude.ai

1. Go to **claude.ai → Settings → Integrations → Add custom integration**
2. Enter your MCP server URL: `https://mcp.your-domain.com/mcp`
3. Claude.ai will redirect to your `/authorize` endpoint
4. Complete the OAuth flow — Claude.ai stores the token automatically

## Configuration

All configuration is loaded from environment variables (via `secrets.env`).
Never hardcode secrets in `mcp_oauth_proxy.py`.

| Variable | Required | Description |
|----------|----------|-------------|
| `CLIENT_ID` | Yes | OAuth client ID registered with your MCP client |
| `CLIENT_SECRET` | Yes | OAuth client secret (min 32 chars recommended) |
| `GRAV_TOKEN` | Yes | Bearer token for the Grav MCP plugin |
| `GRAV_MCP_URL` | No | Internal URL of Grav MCP endpoint (default: `http://127.0.0.1/api/mcp`) |
| `GRAV_HOST` | No | Host header for internal Grav requests (default: `www.arleo.eu`) |
| `PROXY_BASE_URL` | No | Public base URL of this proxy (used in OAuth discovery) |
| `TOKENS_FILE` | No | Path to token storage file (default: `/opt/mcp-oauth-proxy/tokens.json`) |
| `AUDIT_LOG_FILE` | No | Path to audit log (default: `/var/log/mcp-oauth/audit.log`) |
| `LISTEN_HOST` | No | Listen address (default: `127.0.0.1`) |
| `LISTEN_PORT` | No | Listen port (default: `8083`) |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 OAuth discovery |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `GET /authorize` | OAuth authorization endpoint |
| `POST /token` | OAuth token endpoint |
| `GET /mcp` | MCP discovery (no tool list — anti-recon) |
| `POST /mcp` | Authenticated MCP proxy to Grav |

## Logs

**Application logs** (stdout → systemd journal):
```bash
journalctl -u mcp-oauth-proxy -f
```

**Audit logs** (JSON lines):
```bash
tail -f /var/log/mcp-oauth/audit.log | jq .
```

Audit events: `service_start`, `service_stop`, `authorize_approved`,
`authorize_rejected`, `token_issued`, `token_rejected`, `mcp_forward`,
`mcp_rejected`.

## Project Status

This Python implementation remains **maintained and fully functional**. It is the current production-authoritative OAuth proxy.

A next-generation Go implementation is available:

**[https://github.com/jmrGrav/mcp-runtime-go](https://github.com/jmrGrav/mcp-runtime-go)**

The Go runtime is the strategic direction for future development and provides:

- Stronger observability (structured JSON audit log with per-request correlation IDs)
- Shadow deployment support (mirror mode + `shadow-compare` audit comparison tool)
- Improved test coverage and operational tooling
- Future integration path with Hugo MCP
- Foundation for multi-domain MCP hosting

The Python implementation remains the **stable reference implementation** and will continue to serve traffic until the Go shadow deployment gate is passed. See [docs/MIGRATION_TO_GO.md](docs/MIGRATION_TO_GO.md) for the migration strategy.

## License

MIT — Jm Rohmer / [arleo.eu](https://arleo.eu)
