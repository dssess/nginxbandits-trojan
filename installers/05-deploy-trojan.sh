#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

BASE_DIR="/opt/nginxbandits"
CONFIG_FILE="$BASE_DIR/core/nginxbandits.conf"
PASSWORD_FILE="$BASE_DIR/core/trojan-password.txt"
KEYS_DIR="$BASE_DIR/core/keys"
CERT_FILE="$KEYS_DIR/fullchain.cer"
KEY_FILE="$KEYS_DIR/private.key"

XRAY_DIR="/usr/local/etc/xray"
XRAY_CONF="$XRAY_DIR/nginxbandits-trojan.json"
XRAY_UNIT="/etc/systemd/system/nginxbandits-trojan.service"

NGINX_CONF="/etc/nginx/conf.d/nginxbandits-trojan.conf"
BACKUP_ROOT="$BASE_DIR/backups/trojan-ws"
WS_PATH="/trojan-ws"
BACKEND_PORT="10003"

die() {
    printf '\n[ERROR] %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[ISPBandits Trojan] %s\n' "$*"
}

[[ "$EUID" -eq 0 ]] || die "Run this installer as root."
[[ -f "$CONFIG_FILE" ]] || die "Missing $CONFIG_FILE"

# Load the existing project configuration.
# shellcheck disable=SC1090
source "$CONFIG_FILE"

DOMAIN="${TROJAN_DOMAIN:-${PRIMARY_DOMAIN:-}}"

[[ "${TROJAN_ENABLED:-no}" == "yes" ]] ||
    die "Set TROJAN_ENABLED=\"yes\" in nginxbandits.conf."

[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] ||
    die "Invalid Trojan domain."

[[ "$DOMAIN" != .* && "$DOMAIN" != *..* &&
   "$DOMAIN" != *- && "$DOMAIN" != -* ]] ||
    die "Malformed Trojan domain."

[[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] ||
    die "Missing TLS files: $CERT_FILE or $KEY_FILE"

command -v ss >/dev/null 2>&1 ||
    die "The ss command is required."

# Verify the certificate and matching private key.
openssl x509 -in "$CERT_FILE" -noout >/dev/null 2>&1 ||
    die "Invalid TLS certificate."

openssl pkey -in "$KEY_FILE" -noout >/dev/null 2>&1 ||
    die "Invalid TLS private key."

openssl x509 -in "$CERT_FILE" -noout -checkhost "$DOMAIN" \
    >/dev/null 2>&1 ||
    die "Certificate does not cover $DOMAIN."

CERT_FP="$(
    openssl x509 -in "$CERT_FILE" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    sha256sum | awk '{print $1}'
)"

KEY_FP="$(
    openssl pkey -in "$KEY_FILE" -pubout -outform DER 2>/dev/null |
    sha256sum | awk '{print $1}'
)"

[[ -n "$CERT_FP" && "$CERT_FP" == "$KEY_FP" ]] ||
    die "TLS certificate and private key do not match."

# Never take over existing public HTTP/HTTPS listeners.
PUBLIC_LISTENERS="$(
    ss -lntp | awk '
        NR > 1 && ($4 ~ /:80$/ || $4 ~ /:443$/) { print }
    '
)"

if [[ -n "$PUBLIC_LISTENERS" ]]; then
    printf '%s\n' "$PUBLIC_LISTENERS"
    die "Port 80 or 443 is occupied. No service has been stopped."
fi

log "Preparing Trojan WebSocket for $DOMAIN"
log "Public transports: WS on 80 and TLS+WS on 443"
log "Backend: 127.0.0.1:$BACKEND_PORT"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    nginx ca-certificates curl openssl python3

# Install Xray only if it is missing.
if ! command -v xray >/dev/null 2>&1; then
    log "Installing Xray."

    INSTALLER="$(mktemp)"
    trap 'rm -f "${INSTALLER:-}"' EXIT

    curl --fail --silent --show-error --location \
        https://github.com/XTLS/Xray-install/raw/main/install-release.sh \
        --output "$INSTALLER" ||
        die "Could not download the official Xray installer."

    bash "$INSTALLER" install ||
        die "Xray installation failed."

    rm -f "$INSTALLER"
    trap - EXIT
fi

XRAY_BIN="$(command -v xray)" ||
    die "Xray executable was not found."

"$XRAY_BIN" version >/dev/null 2>&1 ||
    die "Xray cannot execute."

# Preserve the current password or generate one on first installation.
if [[ ! -s "$PASSWORD_FILE" ]]; then
    install -d -m 0700 "$(dirname "$PASSWORD_FILE")"
    openssl rand -hex 32 > "$PASSWORD_FILE"
    chmod 0600 "$PASSWORD_FILE"
fi

TROJAN_PASSWORD="$(<"$PASSWORD_FILE")"
[[ -n "$TROJAN_PASSWORD" ]] || die "Trojan password is empty."
unset TROJAN_PASSWORD

# Back up existing managed configuration before replacing it.
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"
install -d -m 0700 "$BACKUP_DIR"

for FILE in "$XRAY_CONF" "$XRAY_UNIT" "$NGINX_CONF"; do
    if [[ -f "$FILE" ]]; then
        cp -a "$FILE" "$BACKUP_DIR/"
    fi
done

# Stop only the service managed by this Trojan installer.
if systemctl cat nginxbandits-trojan.service >/dev/null 2>&1; then
    systemctl stop nginxbandits-trojan.service
fi

# Ensure the backend port is free after stopping our old service.
BACKEND_LISTENER="$(
    ss -lntp | awk -v p=":$BACKEND_PORT" \
        'NR > 1 && $4 ~ (p "$") { print }'
)"

[[ -z "$BACKEND_LISTENER" ]] || {
    printf '%s\n' "$BACKEND_LISTENER"
    die "Backend port $BACKEND_PORT is occupied by another process."
}

# Ensure the dedicated Xray service account exists.
if ! getent group xray >/dev/null 2>&1; then
    groupadd --system xray
fi

if ! id xray >/dev/null 2>&1; then
    useradd --system --gid xray \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin xray
fi

install -d -o root -g xray -m 0750 "$XRAY_DIR"

# Generate an Xray Trojan inbound using WebSocket only.
# TLS terminates at Nginx; Xray listens on loopback.
TROJAN_DOMAIN="$DOMAIN" \
TROJAN_PORT="$BACKEND_PORT" \
TROJAN_WS_PATH="$WS_PATH" \
TROJAN_PASSWORD_FILE="$PASSWORD_FILE" \
python3 - <<'PY'
import json
import os
from pathlib import Path

password = Path(os.environ["TROJAN_PASSWORD_FILE"]).read_text().strip()
if not password:
    raise SystemExit("Trojan password is empty")

config = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "listen": "127.0.0.1",
        "port": int(os.environ["TROJAN_PORT"]),
        "protocol": "trojan",
        "settings": {
            "clients": [{"password": password}]
        },
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": {
                "path": os.environ["TROJAN_WS_PATH"]
            }
        }
    }],
    "outbounds": [{
        "protocol": "freedom",
        "settings": {}
    }]
}

target = Path("/usr/local/etc/xray/nginxbandits-trojan.json")
temporary = target.with_suffix(".json.tmp")
temporary.write_text(json.dumps(config, indent=2) + "\n")
temporary.chmod(0o640)
temporary.replace(target)
PY

chown root:xray "$XRAY_CONF"
chmod 0640 "$XRAY_CONF"

# Create the dedicated systemd service.
cat > "$XRAY_UNIT" <<UNIT
[Unit]
Description=ISPBandits Trojan WebSocket Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=xray
Group=xray
UMask=0027
ExecStart=$XRAY_BIN run -config $XRAY_CONF
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

chmod 0644 "$XRAY_UNIT"

# Configure Nginx as the public WebSocket reverse proxy.
cat > "$NGINX_CONF" <<NGINX
server {
    listen 80;
    server_name $DOMAIN;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri =404;
    }

    location = $WS_PATH {
        proxy_pass http://127.0.0.1:$BACKEND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        return 404;
    }
}

server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    ssl_protocols TLSv1.2 TLSv1.3;

    location = $WS_PATH {
        proxy_pass http://127.0.0.1:$BACKEND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        return 404;
    }
}
NGINX

chmod 0644 "$NGINX_CONF"

# If this certificate renews through Certbot standalone,
# temporarily stop Nginx during renewal so Certbot can use port 80.
RENEWAL_CONF="/etc/letsencrypt/renewal/$DOMAIN.conf"

if [[ -f "$RENEWAL_CONF" ]] &&
   grep -q '^authenticator *= *standalone' "$RENEWAL_CONF"; then

    grep -q '^pre_hook *= *systemctl stop nginx$' "$RENEWAL_CONF" ||
        printf '\npre_hook = systemctl stop nginx\n' >> "$RENEWAL_CONF"

    grep -q '^post_hook *= *systemctl start nginx$' "$RENEWAL_CONF" ||
        printf 'post_hook = systemctl start nginx\n' >> "$RENEWAL_CONF"

    log "Configured Certbot standalone renewal hooks."
fi

# Validate both configurations before starting services.
log "Validating Xray configuration."
"$XRAY_BIN" run -test -config "$XRAY_CONF" ||
    die "Xray configuration validation failed."

log "Validating Nginx configuration."
nginx -t || die "Nginx configuration validation failed."

systemctl daemon-reload
systemctl enable nginxbandits-trojan.service >/dev/null
systemctl enable nginx >/dev/null

systemctl restart nginxbandits-trojan.service
systemctl restart nginx

systemctl is-active --quiet nginxbandits-trojan.service ||
    die "Trojan WebSocket service failed to start."

systemctl is-active --quiet nginx ||
    die "Nginx failed to start."

# Build client-compatible Trojan WebSocket URIs.
ENCODED_PASSWORD="$(
    python3 -c \
        'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))' \
        < "$PASSWORD_FILE"
)"

TLS_LINK="trojan://${ENCODED_PASSWORD}@${DOMAIN}:443?path=%2Ftrojan-ws&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#ISPBandits-Trojan-WS-TLS"

PLAIN_LINK="trojan://${ENCODED_PASSWORD}@${DOMAIN}:80?path=%2Ftrojan-ws&security=none&host=${DOMAIN}&type=ws#ISPBandits-Trojan-WS"

printf '\n'
printf '%s\n' '========================================'
printf '%s\n' ' ISPBandits Trojan WebSocket is ready'
printf '%s\n' '========================================'
printf 'Domain:       %s\n' "$DOMAIN"
printf 'WS path:      %s\n' "$WS_PATH"
printf 'Backend:      127.0.0.1:%s\n' "$BACKEND_PORT"
printf 'TLS profile:  %s:443\n' "$DOMAIN"
printf 'Plain WS:     %s:80\n' "$DOMAIN"
printf '\n'

printf '%s\n' 'Choose the connection profiles to display:'
printf '%s\n' '1) Trojan WS + TLS (443)'
printf '%s\n' '2) Trojan WS without TLS (80)'
printf '%s\n' '3) Display both profiles'

CHOICE="3"
if [[ -t 0 ]]; then
    read -r -p 'Select [1-3, default 3]: ' INPUT_CHOICE
    CHOICE="${INPUT_CHOICE:-3}"
fi

case "$CHOICE" in
    1)
        printf '\nTLS WebSocket profile:\n%s\n' "$TLS_LINK"
        ;;
    2)
        printf '\nPlain WebSocket profile:\n%s\n' "$PLAIN_LINK"
        ;;
    3)
        printf '\nTLS WebSocket profile:\n%s\n' "$TLS_LINK"
        printf '\nPlain WebSocket profile:\n%s\n' "$PLAIN_LINK"
        ;;
    *)
        die "Invalid profile choice. Run the installer again to display the links."
        ;;
esac

printf '\n'
printf '%s\n' 'Services: nginxbandits-trojan.service, nginx'
printf 'Backup:   %s\n' "$BACKUP_DIR"
printf '%s\n' 'Trojan TCP inbound is not configured; WebSocket is used exclusively.'
