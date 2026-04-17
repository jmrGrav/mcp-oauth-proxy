#!/bin/bash
set -euo pipefail

# ============================================================
# MCP Stack Installer for Grav CMS
# GitHub: https://github.com/jmrGrav/mcp-oauth-proxy
# Compatible: Ubuntu 22.04, 24.04 / Debian 12
# ============================================================

VERSION="1.0.0"
PROXY_REPO="https://github.com/jmrGrav/mcp-oauth-proxy.git"
PLUGIN_REPO="https://github.com/jmrGrav/grav-plugin-mcp-server.git"
INSTALL_DIR="/opt/mcp-oauth-proxy"
SECRETS_DIR="/etc/mcp-oauth-proxy"
GRAV_PLUGINS_DIR="/var/www/grav/user/plugins"
LOG_FILE="/var/log/mcp-install.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()     { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }
section() { echo -e "\n${BLUE}══ $1 ══${NC}\n" | tee -a "$LOG_FILE"; }

# ── 1. Root check ─────────────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root (sudo bash install.sh)"
    fi
}

# ── 2. Distribution detection ────────────────────────────────────────────────

detect_distro() {
    if [ ! -f /etc/os-release ]; then
        error "Impossible de détecter la distribution Linux"
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    DISTRO=$ID
    DISTRO_VERSION=$VERSION_ID

    case $DISTRO in
        ubuntu)
            if [[ "$DISTRO_VERSION" != "22.04" && "$DISTRO_VERSION" != "24.04" ]]; then
                warn "Ubuntu $DISTRO_VERSION non testé — continuer à vos risques"
            fi ;;
        debian)
            if [[ "$DISTRO_VERSION" != "12" ]]; then
                warn "Debian $DISTRO_VERSION non testé — continuer à vos risques"
            fi ;;
        *)
            error "Distribution non supportée : $DISTRO. Seuls Ubuntu 22.04/24.04 et Debian 12 sont supportés." ;;
    esac
    log "Distribution : $DISTRO $DISTRO_VERSION"
}

# ── 3. Dependencies ──────────────────────────────────────────────────────────

check_dependencies() {
    section "Vérification des dépendances"

    local missing=()

    for cmd in git curl openssl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    command -v nginx &>/dev/null || missing+=(nginx)

    # PHP — detect active version
    PHP_VERSION=""
    for v in 8.3 8.2 8.1; do
        if command -v "php$v" &>/dev/null || (command -v php &>/dev/null && php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null | grep -q "^$v"); then
            PHP_VERSION=$v
            break
        fi
    done
    [ -z "$PHP_VERSION" ] && missing+=(php)

    # Python 3.11+
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if python3 -c "import sys; exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
            log "Python $PY_VER"
        else
            warn "Python $PY_VER détecté — 3.11+ recommandé"
        fi
    else
        missing+=(python3)
    fi

    # python3-venv
    python3 -m venv --help &>/dev/null || missing+=(python3-venv)

    if [ ${#missing[@]} -gt 0 ]; then
        warn "Dépendances manquantes : ${missing[*]}"
        read -r -p "Installer automatiquement ? [o/N] " reply
        if [[ $reply =~ ^[Oo]$ ]]; then
            apt-get update -qq
            apt-get install -y "${missing[@]}" python3-venv python3-pip
            log "Dépendances installées"
        else
            error "Dépendances manquantes — installation annulée"
        fi
    else
        log "Toutes les dépendances sont présentes"
    fi

    # PHP extensions required by Grav
    if [ -n "$PHP_VERSION" ]; then
        for ext in curl mbstring xml; do
            if ! php -m 2>/dev/null | grep -q "^$ext$"; then
                warn "Extension PHP manquante : php${PHP_VERSION}-${ext} — installation"
                apt-get install -y "php${PHP_VERSION}-${ext}"
            fi
        done
    fi
    log "PHP ${PHP_VERSION:-détecté}"
}

# ── 4. Grav detection ────────────────────────────────────────────────────────

check_grav() {
    section "Vérification de Grav CMS"

    if [ ! -d "$GRAV_PLUGINS_DIR" ]; then
        read -r -p "Chemin vers le répertoire Grav [/var/www/grav] : " GRAV_PATH
        GRAV_PATH=${GRAV_PATH:-/var/www/grav}
        GRAV_PLUGINS_DIR="$GRAV_PATH/user/plugins"

        if [ ! -d "$GRAV_PLUGINS_DIR" ]; then
            error "Grav CMS non trouvé dans $GRAV_PATH — installer Grav d'abord"
        fi
    fi

    WEBSERVER_USER=$(stat -c '%U' "$GRAV_PLUGINS_DIR")
    log "Grav détecté — propriétaire : $WEBSERVER_USER"
}

# ── 5. Interactive configuration ─────────────────────────────────────────────

configure_secrets() {
    section "Configuration"

    echo "Les valeurs saisies seront stockées dans $SECRETS_DIR/secrets.env (chmod 600)"
    echo ""

    # OAuth client credentials (registered with Claude.ai or other MCP client)
    read -r -p "OAuth Client ID (identifiant unique pour ce serveur MCP) : " CLIENT_ID
    [ -z "$CLIENT_ID" ] && error "CLIENT_ID ne peut pas être vide"

    read -r -s -p "OAuth Client Secret (min 32 caractères recommandés) : " CLIENT_SECRET
    echo
    [ -z "$CLIENT_SECRET" ] && error "CLIENT_SECRET ne peut pas être vide"

    # Grav bearer token — generated automatically, written to plugin config
    GRAV_TOKEN=$(openssl rand -hex 32)
    log "GRAV_TOKEN généré automatiquement (64 hex chars)"

    # Grav public URL → derive GRAV_HOST
    read -r -p "URL publique de votre site Grav (ex: https://www.arleo.eu) : " GRAV_PUBLIC_URL
    [ -z "$GRAV_PUBLIC_URL" ] && error "URL Grav ne peut pas être vide"
    GRAV_HOST=$(echo "$GRAV_PUBLIC_URL" | sed 's|https\?://||' | sed 's|/.*||')

    # Public URL of this proxy
    read -r -p "URL publique du proxy MCP (ex: https://mcp.arleo.eu) : " PROXY_BASE_URL
    [ -z "$PROXY_BASE_URL" ] && error "URL proxy ne peut pas être vide"

    # Internal ports
    read -r -p "Port du proxy FastAPI [8083] : " LISTEN_PORT
    LISTEN_PORT=${LISTEN_PORT:-8083}

    read -r -p "Port du vhost interne Grav [8090] : " GRAV_INTERNAL_PORT
    GRAV_INTERNAL_PORT=${GRAV_INTERNAL_PORT:-8090}

    GRAV_MCP_URL="http://127.0.0.1:${GRAV_INTERNAL_PORT}/api/mcp"
}

# ── 6. Proxy installation ────────────────────────────────────────────────────

install_proxy() {
    section "Installation du proxy OAuth"

    # Create system user
    if ! id "mcp-proxy" &>/dev/null; then
        useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" -M mcp-proxy
        log "Utilisateur mcp-proxy créé"
    else
        log "Utilisateur mcp-proxy déjà existant"
    fi

    # Clone or update
    if [ -d "$INSTALL_DIR/.git" ]; then
        warn "$INSTALL_DIR existe déjà — mise à jour"
        git -C "$INSTALL_DIR" pull origin main
    else
        git clone "$PROXY_REPO" "$INSTALL_DIR"
        log "Proxy cloné dans $INSTALL_DIR"
    fi

    # Python virtualenv + dependencies
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
    log "Dépendances Python installées"

    # Secrets file — variable names must match mcp_oauth_proxy.py _env() calls
    mkdir -p "$SECRETS_DIR"
    cat > "$SECRETS_DIR/secrets.env" << EOF
# MCP OAuth Proxy — generated by install.sh $(date -Iseconds)
CLIENT_ID=${CLIENT_ID}
CLIENT_SECRET=${CLIENT_SECRET}
GRAV_TOKEN=${GRAV_TOKEN}
GRAV_MCP_URL=${GRAV_MCP_URL}
GRAV_HOST=${GRAV_HOST}
PROXY_BASE_URL=${PROXY_BASE_URL}
TOKENS_FILE=${INSTALL_DIR}/tokens.json
AUDIT_LOG_FILE=/var/log/mcp-oauth/audit.log
LISTEN_HOST=127.0.0.1
LISTEN_PORT=${LISTEN_PORT}
EOF
    chmod 600 "$SECRETS_DIR/secrets.env"
    chown root:mcp-proxy "$SECRETS_DIR/secrets.env"
    log "secrets.env créé (chmod 600)"

    # Logs directory
    mkdir -p /var/log/mcp-oauth
    chown mcp-proxy:mcp-proxy /var/log/mcp-oauth

    # Set ownership
    chown -R mcp-proxy:mcp-proxy "$INSTALL_DIR"

    # Systemd service
    cp "$INSTALL_DIR/systemd/mcp-oauth-proxy.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable mcp-oauth-proxy
    systemctl start mcp-oauth-proxy

    sleep 2
    if systemctl is-active --quiet mcp-oauth-proxy; then
        log "Service mcp-oauth-proxy actif"
    else
        error "Le service mcp-oauth-proxy n'a pas démarré — journalctl -u mcp-oauth-proxy"
    fi
}

# ── 7. Plugin installation ───────────────────────────────────────────────────

install_plugin() {
    section "Installation du plugin Grav"

    PLUGIN_DIR="$GRAV_PLUGINS_DIR/mcp-server"

    if [ -d "$PLUGIN_DIR/.git" ]; then
        warn "Plugin déjà installé — mise à jour"
        git -C "$PLUGIN_DIR" pull origin main
    else
        git clone "$PLUGIN_REPO" "$PLUGIN_DIR"
        log "Plugin cloné dans $PLUGIN_DIR"
    fi

    chown -R "$WEBSERVER_USER:$WEBSERVER_USER" "$PLUGIN_DIR"

    # Write GRAV_TOKEN into Grav plugin config (user/config/plugins/)
    GRAV_ROOT=$(dirname "$(dirname "$GRAV_PLUGINS_DIR")")
    PLUGIN_CONFIG_DIR="$GRAV_ROOT/user/config/plugins"
    mkdir -p "$PLUGIN_CONFIG_DIR"
    cat > "$PLUGIN_CONFIG_DIR/mcp-server.yaml" << EOF
enabled: true
token: ${GRAV_TOKEN}
EOF
    chown "$WEBSERVER_USER:$WEBSERVER_USER" "$PLUGIN_CONFIG_DIR/mcp-server.yaml"
    chmod 640 "$PLUGIN_CONFIG_DIR/mcp-server.yaml"
    log "Config plugin écrite ($PLUGIN_CONFIG_DIR/mcp-server.yaml)"

    # Clear Grav cache
    if [ -f "$GRAV_ROOT/bin/grav" ]; then
        sudo -u "$WEBSERVER_USER" php "$GRAV_ROOT/bin/grav" clearcache &>/dev/null && log "Cache Grav vidé"
    fi
}

# ── 8. Post-install summary ──────────────────────────────────────────────────

post_install() {
    section "Installation terminée"

    echo ""
    echo -e "${GREEN}✅ Stack MCP installé avec succès !${NC}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📋 Étapes suivantes :"
    echo ""
    echo "1. Configurer le vhost nginx principal (port 443) :"
    echo "   sudo cp $INSTALL_DIR/nginx/mcp-vhost.conf /etc/nginx/sites-available/mcp"
    echo "   sudo nano /etc/nginx/sites-available/mcp"
    echo "   # Remplacer mcp.your-domain.com et your-domain.com"
    echo "   sudo ln -s /etc/nginx/sites-available/mcp /etc/nginx/sites-enabled/"
    echo "   sudo nginx -t && sudo systemctl reload nginx"
    echo ""
    echo "2. Configurer le vhost interne Grav (loopback:${GRAV_INTERNAL_PORT}) :"
    echo "   Exposer uniquement /api/mcp sur 127.0.0.1:${GRAV_INTERNAL_PORT}"
    echo "   Voir README : $INSTALL_DIR/README.md"
    echo ""
    echo "3. Connecter Claude.ai :"
    echo "   Settings → Connectors → Add connector"
    echo "   URL : ${PROXY_BASE_URL}/mcp"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📁 Fichiers importants :"
    printf "   Proxy      : %s\n"   "$INSTALL_DIR"
    printf "   Secrets    : %s/secrets.env\n" "$SECRETS_DIR"
    printf "   Plugin     : %s/mcp-server\n"  "$GRAV_PLUGINS_DIR"
    echo "   Logs proxy : journalctl -u mcp-oauth-proxy -f"
    echo "   Logs audit : tail -f /var/log/mcp-oauth/audit.log | jq ."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${YELLOW}⚠  Le GRAV_TOKEN a été généré automatiquement et écrit dans :${NC}"
    echo "   $SECRETS_DIR/secrets.env  (proxy)"
    echo "   $GRAV_ROOT/user/config/plugins/mcp-server.yaml  (plugin)"
    echo "   Les deux fichiers sont synchronisés — ne pas les modifier séparément."
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     MCP Stack Installer v${VERSION}      ║${NC}"
    echo -e "${BLUE}║  github.com/jmrGrav/mcp-oauth-proxy  ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
    echo ""

    check_root
    detect_distro
    check_dependencies
    check_grav
    configure_secrets
    install_proxy
    install_plugin
    post_install
}

main "$@"
