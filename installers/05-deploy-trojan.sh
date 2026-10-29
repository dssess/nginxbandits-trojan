#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# ISPBandits direct Trojan TLS deployment:
#   SSH/WebSocket stays on public TCP/80.
#   Trojan uses native TCP+TLS on public TCP/443.
#   Xray has no public high-port backend; it binds directly to 443.
#   Stunnel retains only its legacy alternate listeners on 447 and 777.

BASE_DIR="/opt/nginxbandits"
CONFIG_FILE="$BASE_DIR/core/nginxbandits.conf"
PASSWORD_FILE="$BASE_DIR/core/trojan-password.txt"
XRAY_DIR="/usr/local/etc/xray"
XRAY_CONF="$XRAY_DIR/nginxbandits-trojan.json"
XRAY_UNIT="/etc/systemd/system/nginxbandits-trojan.service"
TLS_DIR="/etc/nginxbandits/tls"
CERT_DEST="$TLS_DIR/fullchain.pem"
KEY_DEST="$TLS_DIR/privkey.pem"
STUNNEL_CONF="/etc/stunnel/stunnel.conf"
BACKUP_ROOT="$BASE_DIR/backups/trojan-direct-443"

die() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }
log() { printf '[ISPBandits Trojan 443] %s\n' "$*"; }

[[ "$EUID" -eq 0 ]] || die "Run this installer as root."
[[ -s "$CONFIG_FILE" ]] || die "Missing $CONFIG_FILE"
command -v ss >/dev/null 2>&1 || die "The ss command is required."
command -v systemctl >/dev/null 2>&1 || die "systemctl is required."

# shellcheck disable=SC1090
source "$CONFIG_FILE"
DOMAIN="${TROJAN_DOMAIN:-${PRIMARY_DOMAIN:-}}"
[[ "${TROJAN_ENABLED:-no}" == "yes" ]] || die 'Set TROJAN_ENABLED="yes" in nginxbandits.conf.'
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Set a valid TROJAN_DOMAIN or PRIMARY_DOMAIN first."
[[ "$DOMAIN" != .* && "$DOMAIN" != *..* && "$DOMAIN" != *- && "$DOMAIN" != -* ]] || die "Malformed domain."

for cmd in openssl curl awk grep install python3; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command missing: $cmd"
done

PORT80="$(ss -H -lntp 'sport = :80' 2>/dev/null || true)"
PORT443="$(ss -H -lntp 'sport = :443' 2>/dev/null || true)"
if [[ -n "$PORT80" ]] && ! grep -Eq 'python3|nginxbandits-ws' <<<"$PORT80"; then
    printf '%s\n' "$PORT80"
    die "Port 80 belongs to an unexpected process. Nothing was stopped."
fi
if [[ -n "$PORT443" ]] && ! grep -Eq 'stunnel|xray' <<<"$PORT443"; then
    printf '%s\n' "$PORT443"
    die "Port 443 belongs to an unexpected process. Nothing was stopped."
fi
if [[ "$PORT80" == *python3* ]] && ! systemctl is-active --quiet nginxbandits-ws; then
    die "Python owns port 80 but nginxbandits-ws is not active; refusing to stop an unidentified process."
fi
if [[ "$PORT443" == *stunnel* ]] && ! systemctl is-active --quiet stunnel4; then
    die "Stunnel owns port 443 but stunnel4 is not active."
fi

WS_WAS_ACTIVE=no
systemctl is-active --quiet nginxbandits-ws && WS_WAS_ACTIVE=yes || true
STUNNEL_WAS_ACTIVE=no
systemctl is-active --quiet stunnel4 && STUNNEL_WAS_ACTIVE=yes || true
XRAY_WAS_ACTIVE=no
systemctl is-active --quiet nginxbandits-trojan && XRAY_WAS_ACTIVE=yes || true

export DEBIAN_FRONTEND=noninteractive
log "Installing required packages."
apt-get update -y
apt-get install -y --no-install-recommends certbot ca-certificates curl openssl python3

# Use a Certbot-managed certificate. HTTP-01 temporarily needs port 80, so
# stop only the known WebSocket service while issuing a new certificate.
LE_DIR="/etc/letsencrypt/live/$DOMAIN"
LE_FULLCHAIN="$LE_DIR/fullchain.pem"
LE_PRIVKEY="$LE_DIR/privkey.pem"
EMAIL="${CERTBOT_EMAIL:-}"

cert_is_usable() {
    [[ -s "$LE_FULLCHAIN" && -s "$LE_PRIVKEY" ]] || return 1
    openssl x509 -in "$LE_FULLCHAIN" -noout -checkhost "$DOMAIN" >/dev/null 2>&1 || return 1
    openssl x509 -in "$LE_FULLCHAIN" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
    openssl pkey -in "$LE_PRIVKEY" -noout >/dev/null 2>&1 || return 1
    local cert_fp key_fp
    cert_fp="$(openssl x509 -in "$LE_FULLCHAIN" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    key_fp="$(openssl pkey -in "$LE_PRIVKEY" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    [[ -n "$cert_fp" && "$cert_fp" == "$key_fp" ]]
}

if ! cert_is_usable; then
    [[ -n "$EMAIL" ]] || {
        read -r -p "Email for certificate expiry notices: " EMAIL
    }
    [[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] ||
        die "A valid email address is required for certificate notifications."

    if [[ "$WS_WAS_ACTIVE" == yes ]]; then
        log "Temporarily stopping nginxbandits-ws so Certbot can validate port 80."
        systemctl stop nginxbandits-ws
    fi

    if ss -H -lnt 'sport = :80' | grep -q .; then
        [[ "$WS_WAS_ACTIVE" == yes ]] && systemctl start nginxbandits-ws || true
        die "Port 80 is still occupied; Certbot cannot safely bind for validation."
    fi

    CERTBOT_OK=no
    if certbot certonly --standalone --preferred-challenges http \
        --non-interactive --agree-tos --email "$EMAIL" \
        --cert-name "$DOMAIN" -d "$DOMAIN" --keep-until-expiring; then
        CERTBOT_OK=yes
    fi

    if [[ "$WS_WAS_ACTIVE" == yes ]]; then
        systemctl start nginxbandits-ws || die "Could not restore nginxbandits-ws after certificate request."
    fi
    [[ "$CERTBOT_OK" == yes ]] || die "Certificate issuance failed. Check DNS points to this VPS and inbound TCP/80 is reachable."
fi

cert_is_usable || die "No usable Certbot certificate was found for $DOMAIN."

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"
install -d -m 0700 "$BACKUP_DIR"

backup_file() {
    local src="$1" name="$2"
    if [[ -f "$src" ]]; then
        cp -a "$src" "$BACKUP_DIR/$name"
        printf 'yes\n' > "$BACKUP_DIR/$name.existed"
    else
        printf 'no\n' > "$BACKUP_DIR/$name.existed"
    fi
}
backup_file "$STUNNEL_CONF" stunnel.conf
backup_file "$XRAY_CONF" xray.json
backup_file "$XRAY_UNIT" trojan.service
backup_file "$CERT_DEST" tls-fullchain.pem
backup_file "$KEY_DEST" tls-privkey.pem

MIGRATION_STARTED=0
restore_file() {
    local target="$1" name="$2"
    if [[ "$(cat "$BACKUP_DIR/$name.existed")" == yes ]]; then
        install -D -m 0600 "$BACKUP_DIR/$name" "$target"
    else
        rm -f "$target"
    fi
}
rollback_on_failure() {
    local rc=$?
    if [[ "$rc" -ne 0 && "$MIGRATION_STARTED" == 1 ]]; then
        log "Deployment failed; restoring saved service configuration."
        set +e
        systemctl stop nginxbandits-trojan >/dev/null 2>&1
        restore_file "$STUNNEL_CONF" stunnel.conf
        restore_file "$XRAY_CONF" xray.json
        restore_file "$XRAY_UNIT" trojan.service
        restore_file "$CERT_DEST" tls-fullchain.pem
        restore_file "$KEY_DEST" tls-privkey.pem
        systemctl daemon-reload
        if [[ "$STUNNEL_WAS_ACTIVE" == yes ]]; then systemctl restart stunnel4 >/dev/null 2>&1; fi
        if [[ "$XRAY_WAS_ACTIVE" == yes ]]; then systemctl restart nginxbandits-trojan >/dev/null 2>&1; fi
        set -e
        printf '[WARN] Backup retained at %s\n' "$BACKUP_DIR" >&2
    fi
    if [[ "$WS_WAS_ACTIVE" == yes ]]; then systemctl start nginxbandits-ws >/dev/null 2>&1 || true; fi
    exit "$rc"
}
trap rollback_on_failure EXIT
MIGRATION_STARTED=1

log "Installing Xray if it is not already present."
if ! command -v xray >/dev/null 2>&1; then
    INSTALLER="$(mktemp)"
    trap 'rm -f "${INSTALLER:-}"' EXIT
    curl --fail --silent --show-error --location \
        https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$INSTALLER" ||
        die "Could not download the Xray installer."
    bash "$INSTALLER" install || die "Xray installation failed."
    rm -f "$INSTALLER"
    trap rollback_on_failure EXIT
fi
XRAY_BIN="$(command -v xray)" || die "Xray executable was not found."
"$XRAY_BIN" version >/dev/null 2>&1 || die "Xray cannot execute."

if ! getent group xray >/dev/null 2>&1; then groupadd --system xray; fi
if ! id xray >/dev/null 2>&1; then
    useradd --system --gid xray --home-dir /nonexistent --shell /usr/sbin/nologin xray
fi

if [[ ! -s "$PASSWORD_FILE" ]]; then
    install -d -m 0700 "$(dirname "$PASSWORD_FILE")"
    openssl rand -hex 32 > "$PASSWORD_FILE"
    chmod 0600 "$PASSWORD_FILE"
fi
[[ -s "$PASSWORD_FILE" ]] || die "Trojan password file is empty."
TROJAN_PASSWORD="$(tr -d '\r\n' < "$PASSWORD_FILE")"
[[ -n "$TROJAN_PASSWORD" ]] || die "Trojan password file is empty."

# Xray runs as its own account and reads a private copy of the Certbot key.
install -d -o root -g xray -m 0750 "$TLS_DIR"
install -o root -g xray -m 0644 "$LE_FULLCHAIN" "$CERT_DEST"
install -o root -g xray -m 0640 "$LE_PRIVKEY" "$KEY_DEST"
install -d -o root -g xray -m 0750 "$XRAY_DIR"

python3 - "$XRAY_CONF" "$TROJAN_PASSWORD" "$DOMAIN" <<'PY'
import json, sys
from pathlib import Path
target = Path(sys.argv[1])
password = sys.argv[2]
config = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "listen": "0.0.0.0",
        "port": 443,
        "protocol": "trojan",
        "settings": {"clients": [{"password": password}], "fallbacks": []},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": sys.argv[3],
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

cat > "$XRAY_UNIT" <<UNIT
[Unit]
Description=ISPBandits Trojan TLS Server on TCP/443
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

# Keep existing Stunnel services on alternate ports, releasing 443 for Xray.
if [[ -f "$STUNNEL_CONF" ]]; then
    cat > "$STUNNEL_CONF" <<STUNNEL
pid = /var/run/stunnel.pid
cert = $BASE_DIR/core/keys/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = a:SO_KEEPALIVE=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear-ssl-447]
accept = ${PORT_SSL_ALT1:-447}
connect = 127.0.0.1:${PORT_SSH:-22}
[dropbear-ssl-777]
accept = ${PORT_SSL_ALT2:-777}
connect = 127.0.0.1:${PORT_SSH:-22}
STUNNEL
fi

systemctl daemon-reload
log "Validating the Xray configuration before starting services."
"$XRAY_BIN" run -test -config "$XRAY_CONF" || die "Xray configuration validation failed."

if [[ "$STUNNEL_WAS_ACTIVE" == yes ]]; then
    log "Restarting Stunnel with only its alternate TLS ports."
    systemctl restart stunnel4
    systemctl is-active --quiet stunnel4 || die "Stunnel did not restart on alternate ports."
fi

log "Starting direct Trojan TLS listener on public TCP/443."
systemctl enable nginxbandits-trojan >/dev/null
systemctl restart nginxbandits-trojan
systemctl is-active --quiet nginxbandits-trojan || die "Trojan service did not start."

ss -H -lnt 'sport = :443' | grep -q . || die "Nothing is listening on TCP/443."
ss -H -lnt 'sport = :80' | grep -q . || die "The existing WebSocket listener on TCP/80 is missing."

# Install renewal hooks: stop only the port-80 WebSocket service for HTTP-01,
# restore it afterward, copy renewed certificates, then restart Xray.
HOOK_DIR="/etc/letsencrypt/renewal-hooks"
install -d -m 0755 "$HOOK_DIR/pre" "$HOOK_DIR/post" "$HOOK_DIR/deploy"
cat > "$HOOK_DIR/pre/20-nginxbandits-trojan-stop-ws" <<'HOOKPRE'
#!/usr/bin/env bash
set -e
if systemctl is-active --quiet nginxbandits-ws; then
    echo active > /run/nginxbandits-ws-certbot-state
    systemctl stop nginxbandits-ws
else
    echo inactive > /run/nginxbandits-ws-certbot-state
fi
HOOKPRE
cat > "$HOOK_DIR/post/20-nginxbandits-trojan-start-ws" <<'HOOKPOST'
#!/usr/bin/env bash
set -e
if [[ -f /run/nginxbandits-ws-certbot-state ]]; then
    if grep -qx active /run/nginxbandits-ws-certbot-state; then
        systemctl start nginxbandits-ws
    fi
    rm -f /run/nginxbandits-ws-certbot-state
fi
HOOKPOST
cat > "$HOOK_DIR/deploy/20-nginxbandits-trojan-copy-cert" <<HOOKDEPLOY
#!/usr/bin/env bash
set -Eeuo pipefail
DOMAIN="$DOMAIN"
LE_DIR="/etc/letsencrypt/live/$DOMAIN"
TLS_DIR="/etc/nginxbandits/tls"
install -d -o root -g xray -m 0750 "$TLS_DIR"
install -o root -g xray -m 0644 "$LE_DIR/fullchain.pem" "$TLS_DIR/fullchain.pem"
install -o root -g xray -m 0640 "$LE_DIR/privkey.pem" "$TLS_DIR/privkey.pem"
systemctl restart nginxbandits-trojan
systemctl is-active --quiet nginxbandits-trojan
HOOKDEPLOY
chmod 0750 "$HOOK_DIR/pre/20-nginxbandits-trojan-stop-ws" "$HOOK_DIR/post/20-nginxbandits-trojan-start-ws" "$HOOK_DIR/deploy/20-nginxbandits-trojan-copy-cert"

# Allow UFW when it is enabled; cloud-provider firewall rules may also be needed.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow 443/tcp
fi

ENCODED_PASSWORD="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))' <<<"$TROJAN_PASSWORD")"
TROJAN_LINK="trojan://${ENCODED_PASSWORD}@${DOMAIN}:443?security=tls&sni=${DOMAIN}#ISPBandits-Trojan-TLS"

printf '\n======================================================\n'
printf ' ISPBandits direct Trojan deployment complete\n'
printf '======================================================\n'
printf 'Domain:                 %s\n' "$DOMAIN"
printf 'SSH/WebSocket:          public TCP/80 (existing service retained)\n'
printf 'Trojan TLS:             public TCP/443 (Xray direct inbound)\n'
printf 'Trojan outbound:        freedom (internet access)\n'
printf 'Stunnel alternate:      %s, %s\n' "${PORT_SSL_ALT1:-447}" "${PORT_SSL_ALT2:-777}"
printf 'Backup directory:       %s\n' "$BACKUP_DIR"
printf '\nTrojan client profile:\n%s\n' "$TROJAN_LINK"
printf '\nTLS certificate source: %s\n' "$LE_FULLCHAIN"
printf 'Certificate renewal: Certbot timer with WebSocket stop/start hooks.\n'
printf '\nExisting WebSocket on port 80 was not moved behind a router.\n'
printf 'Note: renewing via HTTP-01 briefly interrupts port-80 WebSocket sessions.\n'
