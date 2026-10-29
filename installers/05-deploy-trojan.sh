#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Safe Trojan deployment:
# - leaves SSH, Nginx, WebSocket port 80, public TLS port 443, and Stunnel unchanged
# - runs native Trojan/TCP/TLS on a separate configurable port (default 8443)
# - reuses an existing valid Let's Encrypt certificate if present; otherwise makes a
#   self-signed certificate without stopping any existing service.

BASE_DIR="/opt/nginxbandits"
CONFIG_FILE="$BASE_DIR/core/nginxbandits.conf"
PASSWORD_FILE="$BASE_DIR/core/trojan-password.txt"
XRAY_DIR="/usr/local/etc/xray"
XRAY_CONF="$XRAY_DIR/nginxbandits-trojan.json"
XRAY_UNIT="/etc/systemd/system/nginxbandits-trojan.service"
TLS_DIR="/etc/nginxbandits/tls"
CERT_DEST="$TLS_DIR/fullchain.pem"
KEY_DEST="$TLS_DIR/privkey.pem"

die() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }
log() { printf '[ISPBandits Trojan] %s\n' "$*"; }

[[ "$EUID" -eq 0 ]] || die "Run this installer as root."
[[ -s "$CONFIG_FILE" ]] || die "Missing $CONFIG_FILE"
command -v ss >/dev/null 2>&1 || die "The ss command is required."
command -v systemctl >/dev/null 2>&1 || die "systemctl is required."
for cmd in openssl curl awk grep install python3; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command missing: $cmd"
done

# shellcheck disable=SC1090
source "$CONFIG_FILE"
DOMAIN="${TROJAN_DOMAIN:-${PRIMARY_DOMAIN:-}}"
PORT="${TROJAN_PORT:-8443}"
[[ "${TROJAN_ENABLED:-no}" == "yes" ]] || die 'Set TROJAN_ENABLED="yes" in nginxbandits.conf.'
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Set a valid TROJAN_DOMAIN or PRIMARY_DOMAIN first."
[[ "$DOMAIN" != .* && "$DOMAIN" != *..* && "$DOMAIN" != *- && "$DOMAIN" != -* ]] || die "Malformed domain."
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1024 && PORT <= 65535 )) || die "TROJAN_PORT must be between 1024 and 65535 to avoid colliding with standard services."

OCCUPIED="$(ss -H -lnt "sport = :$PORT" 2>/dev/null || true)"
if [[ -n "$OCCUPIED" ]]; then
    printf '%s\n' "$OCCUPIED"
    die "TCP/$PORT is already occupied. No existing service was stopped or reconfigured."
fi

export DEBIAN_FRONTEND=noninteractive
log "Installing only the required packages; no SSH/Nginx/Stunnel packages will be removed."
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl openssl python3

LE_DIR="/etc/letsencrypt/live/$DOMAIN"
LE_FULLCHAIN="$LE_DIR/fullchain.pem"
LE_PRIVKEY="$LE_DIR/privkey.pem"
CERT_SOURCE="self-signed fallback"

cert_is_usable() {
    [[ -s "$LE_FULLCHAIN" && -s "$LE_PRIVKEY" ]] || return 1
    openssl x509 -in "$LE_FULLCHAIN" -noout -checkhost "$DOMAIN" >/dev/null 2>&1 || return 1
    openssl x509 -in "$LE_FULLCHAIN" -noout -checkend 86400 >/dev/null 2>&1 || return 1
    openssl pkey -in "$LE_PRIVKEY" -noout >/dev/null 2>&1 || return 1
    local cert_fp key_fp
    cert_fp="$(openssl x509 -in "$LE_FULLCHAIN" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    key_fp="$(openssl pkey -in "$LE_PRIVKEY" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    [[ -n "$cert_fp" && "$cert_fp" == "$key_fp" ]]
}

install -d -m 0750 "$TLS_DIR"
if cert_is_usable; then
    log "Using the existing valid Let's Encrypt certificate for $DOMAIN."
    install -o root -g root -m 0644 "$LE_FULLCHAIN" "$CERT_DEST"
    install -o root -g root -m 0600 "$LE_PRIVKEY" "$KEY_DEST"
    CERT_SOURCE="existing Let's Encrypt certificate"
else
    log "No valid existing Let's Encrypt certificate found."
    log "Generating a self-signed certificate without stopping port 80/443 or touching Nginx/SSH."
    TMP_CERT="$(mktemp)"
    TMP_KEY="$(mktemp)"
    if ! openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 3650 \
        -keyout "$TMP_KEY" -out "$TMP_CERT" \
        -subj "/C=KE/O=NginxBandits/CN=$DOMAIN" \
        -addext "subjectAltName=DNS:$DOMAIN"; then
        rm -f "$TMP_CERT" "$TMP_KEY"
        die "Could not generate the self-signed TLS certificate."
    fi
    install -o root -g root -m 0644 "$TMP_CERT" "$CERT_DEST"
    install -o root -g root -m 0600 "$TMP_KEY" "$KEY_DEST"
    rm -f "$TMP_CERT" "$TMP_KEY"
fi

if ! getent group xray >/dev/null 2>&1; then groupadd --system xray; fi
if ! id xray >/dev/null 2>&1; then
    useradd --system --gid xray --home-dir /nonexistent --shell /usr/sbin/nologin xray
fi
chown root:xray "$TLS_DIR" "$CERT_DEST" "$KEY_DEST"
chmod 0750 "$TLS_DIR"
chmod 0644 "$CERT_DEST"
chmod 0640 "$KEY_DEST"

if [[ ! -s "$PASSWORD_FILE" ]]; then
    install -d -m 0700 "$(dirname "$PASSWORD_FILE")"
    openssl rand -hex 32 > "$PASSWORD_FILE"
    chmod 0600 "$PASSWORD_FILE"
fi
[[ -s "$PASSWORD_FILE" ]] || die "Trojan password file is empty."
TROJAN_PASSWORD="$(tr -d '\r\n' < "$PASSWORD_FILE")"
[[ -n "$TROJAN_PASSWORD" ]] || die "Trojan password file is empty."

install -d -o root -g xray -m 0750 "$XRAY_DIR"
python3 - "$XRAY_CONF" "$TROJAN_PASSWORD" "$DOMAIN" "$PORT" <<'PY'
import json, sys
from pathlib import Path
target = Path(sys.argv[1])
password, domain, port = sys.argv[2], sys.argv[3], int(sys.argv[4])
config = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "trojan",
        "settings": {"clients": [{"password": password}], "fallbacks": []},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": domain,
                "certificates": [{
                    "certificateFile": "/etc/nginxbandits/tls/fullchain.pem",
                    "keyFile": "/etc/nginxbandits/tls/privkey.pem"
                }]
            }
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
    }],
    "outbounds": [{"protocol": "freedom", "settings": {}}],
    "routing": {"domainStrategy": "AsIs", "rules": []}
}
tmp = target.with_suffix(".json.tmp")
tmp.write_text(json.dumps(config, indent=2) + "\n")
tmp.chmod(0o640)
tmp.replace(target)
PY
chown root:xray "$XRAY_CONF"
chmod 0640 "$XRAY_CONF"

XRAY_BIN="$(command -v xray || true)"
if [[ -z "$XRAY_BIN" ]]; then
    INSTALLER="$(mktemp)"
    curl --fail --silent --show-error --location \
        https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$INSTALLER" \
        || { rm -f "$INSTALLER"; die "Could not download the Xray installer."; }
    bash "$INSTALLER" install || { rm -f "$INSTALLER"; die "Xray installation failed."; }
    rm -f "$INSTALLER"
    XRAY_BIN="$(command -v xray || true)"
fi
[[ -n "$XRAY_BIN" ]] || die "Xray executable was not found."
"$XRAY_BIN" version >/dev/null 2>&1 || die "Xray cannot execute."

cat > "$XRAY_UNIT" <<UNIT
[Unit]
Description=ISPBandits Trojan TLS Server on TCP/$PORT
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

systemctl daemon-reload
log "Validating the Xray configuration."
"$XRAY_BIN" run -test -config "$XRAY_CONF" || die "Xray configuration validation failed."

systemctl enable nginxbandits-trojan >/dev/null
systemctl restart nginxbandits-trojan
systemctl is-active --quiet nginxbandits-trojan || die "Trojan service did not start."
ss -H -lnt "sport = :$PORT" | grep -q . || die "Nothing is listening on TCP/$PORT."

# Persist the selected, non-conflicting port in the project's settings.
if grep -qE '^TROJAN_PORT=' "$CONFIG_FILE"; then
    sed -i "s/^TROJAN_PORT=.*/TROJAN_PORT=$PORT/" "$CONFIG_FILE"
else
    printf '\nTROJAN_PORT=%s\n' "$PORT" >> "$CONFIG_FILE"
fi
if grep -qE '^TROJAN_TRANSPORT=' "$CONFIG_FILE"; then
    sed -i 's/^TROJAN_TRANSPORT=.*/TROJAN_TRANSPORT="tcp"/' "$CONFIG_FILE"
else
    printf 'TROJAN_TRANSPORT="tcp"\n' >> "$CONFIG_FILE"
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "$PORT/tcp"
fi

ENCODED_PASSWORD="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))' <<<"$TROJAN_PASSWORD")"
if [[ "$CERT_SOURCE" == "self-signed fallback" ]]; then
    TROJAN_LINK="trojan://${ENCODED_PASSWORD}@${DOMAIN}:${PORT}?security=tls&sni=${DOMAIN}&allowInsecure=1#NginxBandits-Trojan"
else
    TROJAN_LINK="trojan://${ENCODED_PASSWORD}@${DOMAIN}:${PORT}?security=tls&sni=${DOMAIN}#NginxBandits-Trojan"
fi

printf '\n======================================================\n'
printf ' NginxBandits Trojan deployment complete\n'
printf '======================================================\n'
printf 'Domain:                 %s\n' "$DOMAIN"
printf 'Trojan TLS:             TCP/%s (separate from Nginx TCP/443)\n' "$PORT"
printf 'SSH/WebSocket:          left running; port 80 was not stopped\n'
printf 'Nginx TCP/443:          left unchanged\n'
printf 'Stunnel configuration:  left unchanged\n'
printf 'Certificate:            %s\n' "$CERT_SOURCE"
printf 'Trojan outbound:        freedom (internet access)\n'
printf '\nTrojan client profile:\n%s\n' "$TROJAN_LINK"
if [[ "$CERT_SOURCE" == "self-signed fallback" ]]; then
    printf '\nWARNING: this link enables allowInsecure because the certificate is self-signed.\n'
    printf 'Traffic is encrypted, but the client will not authenticate the server certificate.\n'
    printf 'For trusted TLS without allowInsecure, install a valid certificate for this domain later.\n'
fi
printf '\nOpen TCP/%s in the VPS provider firewall if it is enabled.\n' "$PORT"
printf 'No SSH, Nginx, WebSocket, or Stunnel service was intentionally stopped or reconfigured.\n'
