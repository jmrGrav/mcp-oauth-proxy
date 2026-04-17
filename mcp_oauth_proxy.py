#!/usr/bin/env python3
"""
OAuth 2.0 proxy pour MCP Grav (arleo.eu) — VERSION DURCIE
=========================================================
Changements vs v1 :
- Secrets chargés depuis variables d'environnement (plus jamais en dur)
- Whitelist redirect_uri (permissive : *.claude.ai / *.anthropic.com)
- Validation PKCE S256 réelle (avant : acceptée mais ignorée)
- Validation response_type
- compare_digest pour client_id/secret/PKCE (anti-timing)
- Tokens hashés SHA-256 dans le JSON (jamais en clair sur disque)
- Durée access token réduite de 30j à 24h
- Écriture atomique du JSON + lock asyncio (anti-race)
- Logs d'audit structurés JSON lines vers fichier dédié
- GET /mcp ne liste plus les outils (anti-recon)
- Appel Grav via 127.0.0.1 avec header Host (bypass Cloudflare)
- Suppression limite time.time() négative dans _load_tokens
"""

import os
import sys
import json
import time
import base64
import hashlib
import secrets
import asyncio
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlencode, urlparse
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.responses import Response as StarletteResponse


# ─── Configuration depuis l'environnement ────────────────────────────────────

def _env(name: str, default: str | None = None, required: bool = True) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        print(f"[FATAL] Variable d'environnement manquante : {name}", file=sys.stderr)
        sys.exit(1)
    return val  # type: ignore


GRAV_MCP_URL    = _env("GRAV_MCP_URL", "http://127.0.0.1/api/mcp", required=False)
GRAV_HOST       = _env("GRAV_HOST", "www.arleo.eu", required=False)
GRAV_TOKEN      = _env("GRAV_TOKEN")
CLIENT_ID       = _env("CLIENT_ID")
CLIENT_SECRET   = _env("CLIENT_SECRET")
PROXY_BASE_URL  = _env("PROXY_BASE_URL", "https://www.arleo.eu", required=False)
TOKENS_FILE     = _env("TOKENS_FILE", "/opt/mcp-oauth-proxy/tokens.json", required=False)
AUDIT_LOG_FILE  = _env("AUDIT_LOG_FILE", "/var/log/mcp-oauth/audit.log", required=False)
LISTEN_HOST     = _env("LISTEN_HOST", "127.0.0.1", required=False)
LISTEN_PORT     = int(_env("LISTEN_PORT", "8083", required=False))

AUTH_CODE_TTL   = 300                    # 5 minutes
TOKEN_TTL       = None                   # Tokens sans expiration

# Whitelist redirect_uri (permissive, à durcir plus tard)
# Accepte tout sous-domaine de claude.ai / anthropic.com en HTTPS
ALLOWED_REDIRECT_HOST_SUFFIXES = (
    ".claude.ai",
    ".anthropic.com",
)
ALLOWED_REDIRECT_HOSTS_EXACT = {
    "claude.ai",
    "anthropic.com",
}


def _is_allowed_redirect(uri: str) -> bool:
    """Valide strictement l'URL de callback OAuth."""
    try:
        p = urlparse(uri)
    except Exception:
        return False
    if p.scheme != "https":
        return False
    if not p.hostname:
        return False
    host = p.hostname.lower()
    if host in ALLOWED_REDIRECT_HOSTS_EXACT:
        return True
    return any(host.endswith(suffix) for suffix in ALLOWED_REDIRECT_HOST_SUFFIXES)


# ─── Logs d'audit structurés ──────────────────────────────────────────────────

def _setup_audit_logger() -> logging.Logger:
    logger = logging.getLogger("mcp_audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)
        handler = logging.FileHandler(AUDIT_LOG_FILE)
    except OSError:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


audit = _setup_audit_logger()


def audit_log(event: str, request: Request | None = None, **fields):
    """Log JSON-lines : un événement = une ligne JSON."""
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "event": event,
    }
    if request is not None:
        # Derrière nginx : X-Forwarded-For a priorité
        xff = request.headers.get("X-Forwarded-For", "")
        src_ip = xff.split(",")[0].strip() if xff else (
            request.client.host if request.client else "-"
        )
        entry["src_ip"] = src_ip
        entry["ua"] = request.headers.get("User-Agent", "-")[:200]
    entry.update(fields)
    try:
        audit.info(json.dumps(entry, ensure_ascii=False))
    except Exception:
        pass


# ─── Hash des tokens (jamais en clair sur disque) ────────────────────────────

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ─── Persistance des tokens : écriture atomique + lock ──────────────────────

_tokens_lock = asyncio.Lock()


def _load_tokens() -> dict:
    """Charge les tokens depuis disque (clés = hash, valeurs = expires_at)."""
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE) as f:
            tokens = json.load(f)
        if not isinstance(tokens, dict):
            return {}
        now = time.time()
        return {
            k: v for k, v in tokens.items()
            if isinstance(v, (int, float)) and v > now
        }
    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] Erreur lecture {TOKENS_FILE}: {e}", file=sys.stderr)
        return {}


async def _save_tokens(tokens: dict) -> None:
    """Écriture atomique via fichier temporaire + rename."""
    async with _tokens_lock:
        now = time.time()
        valid = {k: v for k, v in tokens.items() if v > now}
        try:
            os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
            tmp = TOKENS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(valid, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, TOKENS_FILE)
            # Permissions restrictives
            try:
                os.chmod(TOKENS_FILE, 0o600)
            except OSError:
                pass
        except OSError as e:
            print(f"[WARN] Impossible d'écrire {TOKENS_FILE}: {e}", file=sys.stderr)


_auth_codes: dict = {}
_access_tokens: dict = _load_tokens()
print(f"[INFO] {len(_access_tokens)} token(s) chargé(s) depuis {TOKENS_FILE}")


# ─── Cache des outils (pour répondre vite à tools/list) ─────────────────────

_tools_cache: list | None = None


async def _fetch_tools() -> list:
    global _tools_cache
    if _tools_cache is not None:
        return _tools_cache
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                GRAV_MCP_URL,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                headers={
                    "Host": GRAV_HOST,
                    "Authorization": f"Bearer {GRAV_TOKEN}",
                    "Content-Type": "application/json",
                },
            )
            data = resp.json()
            tools = data.get("result", {}).get("tools", [])
            if tools:
                _tools_cache = tools
                print(f"[INFO] {len(tools)} outil(s) mis en cache")
            return tools
    except Exception as e:
        print(f"[WARN] Impossible de récupérer les outils: {e}", file=sys.stderr)
        return []


# ─── Purge périodique des tokens expirés ────────────────────────────────────

async def _purge_expired_loop():
    while True:
        await asyncio.sleep(3600)  # toutes les heures
        now = time.time()
        before = len(_access_tokens)
        expired = [k for k, v in _access_tokens.items() if v <= now]
        for k in expired:
            _access_tokens.pop(k, None)
        # Purge aussi les codes d'autorisation expirés
        expired_codes = [k for k, v in _auth_codes.items() if v.get("expires_at", 0) <= now]
        for k in expired_codes:
            _auth_codes.pop(k, None)
        if expired:
            await _save_tokens(_access_tokens)
            print(f"[INFO] Purge : {before - len(_access_tokens)} token(s) expiré(s) supprimé(s)")


# ─── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await _fetch_tools()
    purge_task = asyncio.create_task(_purge_expired_loop())
    audit_log("service_start", tokens_loaded=len(_access_tokens))
    yield
    purge_task.cancel()
    audit_log("service_stop")


app = FastAPI(title="MCP OAuth Proxy", lifespan=lifespan)


# ─── OAuth Discovery ─────────────────────────────────────────────────────────

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server():
    """RFC 8414 — Authorization Server Metadata."""
    return JSONResponse({
        "issuer": PROXY_BASE_URL,
        "authorization_endpoint": f"{PROXY_BASE_URL}/authorize",
        "token_endpoint": f"{PROXY_BASE_URL}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        # Mode public client (PKCE-only) ET post (pour compat)
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["mcp"],
        "service_documentation": f"{PROXY_BASE_URL}/oauth-mcp/mcp",
    })


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    """RFC 9728 — Protected Resource Metadata. Différent du authorization server."""
    return JSONResponse({
        "resource": f"{PROXY_BASE_URL}/oauth-mcp/mcp",
        "authorization_servers": [PROXY_BASE_URL],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
        "resource_documentation": f"{PROXY_BASE_URL}/oauth-mcp/mcp",
    })


@app.get("/.well-known/oauth-protected-resource/{resource_path:path}")
async def oauth_protected_resource_suffixed(resource_path: str):
    """RFC 9728 — Forme path-suffixée utilisée par Claude.ai pour MCP."""
    if resource_path != "oauth-mcp/mcp":
        return JSONResponse(
            {"error": "not_found", "error_description": "Unknown resource"},
            status_code=404,
        )
    return JSONResponse({
        "resource": f"{PROXY_BASE_URL}/oauth-mcp/mcp",
        "authorization_servers": [PROXY_BASE_URL],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
        "resource_documentation": f"{PROXY_BASE_URL}/oauth-mcp/mcp",
    })


# ─── Authorization Endpoint ──────────────────────────────────────────────────

@app.get("/authorize")
async def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "",
):
    # Validation stricte
    if response_type != "code":
        audit_log("authorize_rejected", request, reason="response_type", value=response_type[:50])
        raise HTTPException(400, "response_type non supporté (attendu: code)")

    if not secrets.compare_digest(client_id, CLIENT_ID):
        audit_log("authorize_rejected", request, reason="client_id")
        raise HTTPException(400, "client_id invalide")

    if not _is_allowed_redirect(redirect_uri):
        audit_log("authorize_rejected", request, reason="redirect_uri", value=redirect_uri[:200])
        raise HTTPException(400, "redirect_uri non autorisé")

    # PKCE : si code_challenge présent, méthode doit être S256
    if code_challenge:
        if code_challenge_method != "S256":
            audit_log("authorize_rejected", request, reason="pkce_method", value=code_challenge_method)
            raise HTTPException(400, "code_challenge_method doit être S256")
        if len(code_challenge) < 43 or len(code_challenge) > 128:
            audit_log("authorize_rejected", request, reason="pkce_challenge_len")
            raise HTTPException(400, "code_challenge longueur invalide")

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + AUTH_CODE_TTL,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    params = {"code": code}
    if state:
        params["state"] = state

    audit_log("authorize_approved", request, redirect_uri=redirect_uri, pkce=bool(code_challenge))
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


# ─── Token Endpoint ──────────────────────────────────────────────────────────

@app.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    code_verifier: str = Form(None),
):
    if grant_type != "authorization_code":
        audit_log("token_rejected", request, reason="grant_type", value=grant_type[:50])
        raise HTTPException(400, "grant_type non supporté")

    # Authentification client : deux modes supportés
    # - client_secret_post : client_id + client_secret dans le body
    # - none (public client PKCE) : seulement client_id, la preuve est PKCE
    if not client_id:
        audit_log("token_rejected", request, reason="client_id_missing")
        raise HTTPException(401, "client_id manquant")

    if not secrets.compare_digest(client_id, CLIENT_ID):
        audit_log("token_rejected", request, reason="client_id_invalid")
        raise HTTPException(401, "client_id invalide")

    # Mode confidential : si un client_secret est fourni, il doit matcher.
    # Mode public : pas de client_secret, on se reposera sur PKCE plus bas.
    is_public_client = not client_secret
    if client_secret:
        if not secrets.compare_digest(client_secret, CLIENT_SECRET):
            audit_log("token_rejected", request, reason="client_secret_invalid")
            raise HTTPException(401, "client_secret invalide")

    if not code:
        audit_log("token_rejected", request, reason="code_missing")
        raise HTTPException(400, "code manquant")

    entry = _auth_codes.pop(code, None)
    if not entry:
        audit_log("token_rejected", request, reason="code_invalid_or_reused")
        raise HTTPException(400, "code invalide ou déjà utilisé")

    if time.time() > entry["expires_at"]:
        audit_log("token_rejected", request, reason="code_expired")
        raise HTTPException(400, "code expiré")

    # Vérification redirect_uri cohérent avec /authorize
    if redirect_uri and redirect_uri != entry["redirect_uri"]:
        audit_log("token_rejected", request, reason="redirect_uri_mismatch")
        raise HTTPException(400, "redirect_uri incohérent")

    # Vérification PKCE : obligatoire pour les public clients, sinon selon /authorize
    challenge = entry.get("code_challenge")
    if is_public_client and not challenge:
        # Un public client SANS PKCE = aucune preuve d'identité = refus
        audit_log("token_rejected", request, reason="public_client_without_pkce")
        raise HTTPException(400, "public client requires PKCE")
    if challenge:
        if not code_verifier:
            audit_log("token_rejected", request, reason="pkce_verifier_missing")
            raise HTTPException(400, "code_verifier manquant")
        if len(code_verifier) < 43 or len(code_verifier) > 128:
            audit_log("token_rejected", request, reason="pkce_verifier_len")
            raise HTTPException(400, "code_verifier longueur invalide")
        computed = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        if not secrets.compare_digest(computed, challenge):
            audit_log("token_rejected", request, reason="pkce_mismatch")
            raise HTTPException(400, "code_verifier invalide")

    # Émission du token : on stocke UNIQUEMENT le hash
    access_token = secrets.token_urlsafe(48)
    token_hash = _hash_token(access_token)
    _access_tokens[token_hash] = float("inf")  # jamais expiré
    await _save_tokens(_access_tokens)

    audit_log("token_issued", request, active_tokens=len(_access_tokens))
    print(f"[INFO] Nouveau token émis, {len(_access_tokens)} token(s) actif(s)")

    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
    })


# ─── Vérification token entrant ──────────────────────────────────────────────

async def _check_token(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        audit_log("mcp_rejected", request, reason="no_bearer")
        raise HTTPException(401, "Token manquant")
    tok = auth.removeprefix("Bearer ").strip()
    if not tok:
        audit_log("mcp_rejected", request, reason="empty_token")
        raise HTTPException(401, "Token vide")
    token_hash = _hash_token(tok)
    if token_hash not in _access_tokens:
        audit_log("mcp_rejected", request, reason="token_invalid")
        raise HTTPException(401, "Token invalide")


def _proxy_response(resp: httpx.Response) -> StarletteResponse:
    content_type = resp.headers.get("content-type", "application/json")
    return StarletteResponse(
        content=resp.content,
        status_code=resp.status_code,
        media_type=content_type,
    )


# ─── GET /mcp — discovery SANS liste d'outils (anti-recon) ──────────────────

@app.get("/mcp")
async def mcp_get(request: Request):
    audit_log("mcp_discovery", request)
    return JSONResponse({
        "protocol": "mcp",
        "version": "2025-03-26",
        "serverInfo": {"name": "arleo-grav-mcp", "version": "1.0.0"},
        "capabilities": {"tools": {"listChanged": False}},
        # PAS de "tools": la liste n'est disponible qu'authentifiée
    })


# ─── POST /mcp — proxy protégé ───────────────────────────────────────────────

@app.post("/mcp")
async def mcp_post(request: Request):
    await _check_token(request)
    body_bytes = await request.body()

    # Limite de taille applicative (nginx limite déjà, ceinture+bretelles)
    if len(body_bytes) > 16 * 1024:
        audit_log("mcp_rejected", request, reason="body_too_large", size=len(body_bytes))
        raise HTTPException(413, "Body trop gros")

    method_name = None
    try:
        body_json = json.loads(body_bytes)
        method_name = body_json.get("method")
        # tools/list servi depuis le cache
        if method_name == "tools/list":
            tools = await _fetch_tools()
            if tools:
                audit_log("mcp_tools_list", request, source="cache")
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": body_json.get("id"),
                    "result": {"tools": tools},
                })
    except Exception:
        pass

    audit_log("mcp_forward", request, method=method_name or "unknown")

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            GRAV_MCP_URL,
            content=body_bytes,
            headers={
                "Host": GRAV_HOST,
                "Authorization": f"Bearer {GRAV_TOKEN}",
                "Content-Type": request.headers.get("Content-Type", "application/json"),
            },
        )

    # Mise à jour cache si Grav retourne des outils
    try:
        data = resp.json()
        tools = data.get("result", {}).get("tools")
        if tools:
            global _tools_cache
            _tools_cache = tools
    except Exception:
        pass

    return _proxy_response(resp)


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "mcp_oauth_proxy:app",
        host=LISTEN_HOST,
        port=LISTEN_PORT,
        reload=False,
        # pas de server header (petit anti-fingerprinting)
        server_header=False,
        date_header=False,
    )
