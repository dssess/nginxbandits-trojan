#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

BASE_DIR="/opt/nginxbandits"
CONFIG_FILE="$BASE_DIR/core/nginxbandits.conf"
PASSWORD_FILE="$BASE_DIR/core/trojan-password.txt"
KEYS_DIR="$BASE_DIR/core/keys"
CERT_FILE="$KEYS_DIR/fullchain.cer"
KEY_FILE="$KEYS_DIR/private.key"
HAPROXY_PEM="$KEYS_DIR/nginxbandits-shared.pem"

XRAY_DIR="/usr/local/etc/xray"
XRAY_CONF="$XRAY_DIR/nginxbandits-trojan.json"
XRAY_UNIT="/etc/systemd/system/nginxbandits-trojan.service"
HAPROXY_CONF="/etc/haproxy/haproxy.cfg"
STUNNEL_CONF="/etc/stunnel/stunnel.conf"
WS_OVERRIDE_DIR="/etc/systemd/system/nginxbandits-ws.service.d"
WS_OVERRIDE="$WS_OVERRIDE_DIR/90-nginxbandits-shared-router.conf"

WS_PATH="/trojan-ws"
BACKEND_PORT="10003"
SSH_WS_BACKEND_PORT="8080"
BACKUP_ROOT="$BASE_DIR/backups/trojan-coexistence"

die() {
    printf '\n[ERROR] %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[ISPBandits shared router] %s\n' "$*"
}

[[ "$EUID" -eq 0 ]] || die "Run this installer as root."
[[ -s "$CONFIG_FILE" ]] || die "Missing $CONFIG_FILE"
command -v ss >/dev/null 2>&1 || die "The ss command is required."

# shellcheck disable=SC1090
source "$CONFIG_FILE"

DOMAIN="${TROJAN_DOMAIN:-${PRIMARY_DOMAIN:-}}"
[[ "${TROJAN_ENABLED:-no}" == "yes" ]] ||
    die 'Set TROJAN_ENABLED="yes" in nginxbandits.conf.'
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid Trojan domain."
[[ "$DOMAIN" != .* && "$DOMAIN" != *..* && "$DOMAIN" != *- && "$DOMAIN" != -* ]] ||
    die "Malformed Trojan domain."
[[ -s "$CERT_FILE" && -s "$KEY_FILE" ]] ||
    die "TLS files are missing. Expected $CERT_FILE and $KEY_FILE."

openssl x509 -in "$CERT_FILE" -noout >/dev/null 2>&1 ||
    die "TLS certificate is invalid."
openssl pkey -in "$KEY_FILE" -noout >/dev/null 2>&1 ||
    die "TLS private key is invalid."
openssl x509 -in "$CERT_FILE" -noout -checkhost "$DOMAIN" >/dev/null 2>&1 ||
    die "The TLS certificate does not cover $DOMAIN."

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

# Fail safely if ports belong to unrelated applications. The only expected
# existing owners during migration are the project's Python proxy and Stunnel,
# or HAProxy when this phase has already been deployed.
PORT80="$(ss -H -lntp 'sport = :80' 2>/dev/null || true)"
PORT443="$(ss -H -lntp 'sport = :443' 2>/dev/null || true)"

if [[ -n "$PORT80" ]] && ! grep -Eq 'python3|haproxy' <<<"$PORT80"; then
    printf '%s\n' "$PORT80"
    die "Port 80 is owned by an unexpected process. No listener has been stopped."
fi
if [[ -n "$PORT443" ]] && ! grep -Eq 'stunnel4|stunnel|haproxy' <<<"$PORT443"; then
    printf '%s\n' "$PORT443"
    die "Port 443 is owned by an unexpected process. No listener has been stopped."
fi
if [[ "$PORT80" == *python3* ]] && ! systemctl is-active --quiet nginxbandits-ws; then
    die "Port 80 is held by Python, but nginxbandits-ws is not active; refusing to migrate an unidentified process."
fi
if [[ "$PORT443" == *stunnel* ]] && ! systemctl is-active --quiet stunnel4; then
    die "Port 443 is held by Stunnel, but stunnel4 is not active; refusing to migrate an unidentified process."
fi

# Capture pre-install service state before apt can auto-start HAProxy.
HAPROXY_WAS_ACTIVE=no
systemctl is-active --quiet haproxy && HAPROXY_WAS_ACTIVE=yes || true

log "Installing the shared router dependency."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends haproxy ca-certificates curl openssl python3

command -v haproxy >/dev/null 2>&1 || die "HAProxy installation failed."
command -v xray >/dev/null 2>&1 || {
    log "Installing Xray."
    INSTALLER="$(mktemp)"
    trap 'rm -f "${INSTALLER:-}"' EXIT
    curl --fail --silent --show-error --location \
        https://github.com/XTLS/Xray-install/raw/main/install-release.sh \
        --output "$INSTALLER" || die "Could not download the Xray installer."
    bash "$INSTALLER" install || die "Xray installation failed."
    rm -f "$INSTALLER"
    trap - EXIT
}
XRAY_BIN="$(command -v xray)" || die "Xray executable was not found."
"$XRAY_BIN" version >/dev/null 2>&1 || die "Xray cannot execute."

if [[ ! -s "$PASSWORD_FILE" ]]; then
    install -d -m 0700 "$(dirname "$PASSWORD_FILE")"
    openssl rand -hex 32 > "$PASSWORD_FILE"
    chmod 0600 "$PASSWORD_FILE"
fi
[[ -s "$PASSWORD_FILE" ]] || die "Trojan password is empty."

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"
install -d -m 0700 "$BACKUP_DIR"

# Record whether each file existed so a failed migration can restore it.
backup_file() {
    local src="$1" name="$2"
    if [[ -f "$src" ]]; then
        cp -a "$src" "$BACKUP_DIR/$name"
        printf '%s\n' yes > "$BACKUP_DIR/$name.existed"
    else
        printf '%s\n' no > "$BACKUP_DIR/$name.existed"
    fi
}

backup_file "$HAPROXY_CONF" haproxy.cfg
backup_file "$STUNNEL_CONF" stunnel.conf
backup_file "$WS_OVERRIDE" ws-override.conf
backup_file "$XRAY_CONF" xray.json
backup_file "$XRAY_UNIT" trojan.service
backup_file "$HAPROXY_PEM" shared.pem

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
        log "Deployment failed; restoring the previous managed configuration."
        set +e
        systemctl stop haproxy >/dev/null 2>&1
        restore_file "$HAPROXY_CONF" haproxy.cfg
        restore_file "$STUNNEL_CONF" stunnel.conf
        restore_file "$WS_OVERRIDE" ws-override.conf
        restore_file "$XRAY_CONF" xray.json
        restore_file "$XRAY_UNIT" trojan.service
        restore_file "$HAPROXY_PEM" shared.pem
        systemctl daemon-reload
        systemctl restart nginxbandits-ws >/dev/null 2>&1
        systemctl restart stunnel4 >/dev/null 2>&1
        if [[ "$HAPROXY_WAS_ACTIVE" == yes ]]; then
            systemctl restart haproxy >/dev/null 2>&1
        else
            systemctl stop haproxy >/dev/null 2>&1
        fi
        if [[ -s "$BACKUP_DIR/xray.json.existed" && "$(cat "$BACKUP_DIR/xray.json.existed")" == yes ]]; then
            systemctl restart nginxbandits-trojan.service >/dev/null 2>&1
        else
            systemctl stop nginxbandits-trojan.service >/dev/null 2>&1
        fi
        set -e
        printf '[WARN] Backup retained at %s\n' "$BACKUP_DIR" >&2
    fi
    exit "$rc"
}
trap rollback_on_failure EXIT

MIGRATION_STARTED=1

# Keep a standalone copy of the cert+key for HAProxy. The original certificate
# and private key remain unchanged.
cat "$CERT_FILE" "$KEY_FILE" > "$HAPROXY_PEM"
chmod 0600 "$HAPROXY_PEM"

# Prepare the Xray Trojan-over-WebSocket backend on loopback only.
if ! getent group xray >/dev/null 2>&1; then
    groupadd --system xray
fi
if ! id xray >/dev/null 2>&1; then
    useradd --system --gid xray --home-dir /nonexistent --shell /usr/sbin/nologin xray
fi
install -d -o root -g xray -m 0750 "$XRAY_DIR"

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
        "settings": {"clients": [{"password": password}]},
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": {"path": os.environ["TROJAN_WS_PATH"]}
        }
    }],
    "outbounds": [{"protocol": "freedom", "settings": {}}]
}
target = Path("/usr/local/etc/xray/nginxbandits-trojan.json")
temporary = target.with_suffix(".json.tmp")
temporary.write_text(json.dumps(config, indent=2) + "\n")
temporary.chmod(0o640)
temporary.replace(target)
PY
chown root:xray "$XRAY_CONF"
chmod 0640 "$XRAY_CONF"

cat > "$XRAY_UNIT" <<UNIT
[Unit]
Description=ISPBandits Trojan WebSocket Backend
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

# HAProxy owns public ports 80 and 443. The exact Trojan WS path is routed to
# Xray; all other HTTP/WebSocket traffic is forwarded to the existing SSH proxy.
cat > "$HAPROXY_CONF" <<HAPROXY
global
    log /dev/log local0
    maxconn 20000
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 10s
    timeout client 1h
    timeout server 1h
    timeout tunnel 1h
    timeout http-request 15s

frontend nginxbandits_http
    bind 0.0.0.0:80
    acl is_trojan path -i $WS_PATH
    use_backend trojan_ws if is_trojan
    default_backend ssh_ws

frontend nginxbandits_https
    bind 0.0.0.0:443 ssl crt $HAPROXY_PEM alpn http/1.1
    acl is_trojan path -i $WS_PATH
    use_backend trojan_ws if is_trojan
    default_backend ssh_ws

backend ssh_ws
    server ssh_ws 127.0.0.1:$SSH_WS_BACKEND_PORT

backend trojan_ws
    server trojan_ws 127.0.0.1:$BACKEND_PORT
HAPROXY
chmod 0644 "$HAPROXY_CONF"

log "Validating HAProxy configuration."
haproxy -c -f "$HAPROXY_CONF" || die "HAProxy configuration validation failed."
log "Validating Xray configuration."
"$XRAY_BIN" run -test -config "$XRAY_CONF" || die "Xray configuration validation failed."

# Preserve Stunnel's legacy alternate TLS ports, but release public 443.
# No other service is stopped or disabled by this migration.
if [[ -f "$STUNNEL_CONF" ]]; then
    cat > "$STUNNEL_CONF" <<STUNNEL
pid = /var/run/stunnel.pid
cert = $KEYS_DIR/stunnel.pem
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

# Move only the project's Python WS listener to loopback. Port 8880 remains
# available for its existing raw/custom use.
install -d -m 0755 "$WS_OVERRIDE_DIR"
cat > "$WS_OVERRIDE" <<'OVERRIDE'
[Service]
Environment=NGINXBANDITS_WS_HTTP_HOST=127.0.0.1
Environment=NGINXBANDITS_WS_HTTP_PORT=8080
Environment=NGINXBANDITS_WS_RAW_HOST=0.0.0.0
Environment=NGINXBANDITS_WS_RAW_PORT=8880
OVERRIDE
chmod 0644 "$WS_OVERRIDE"

systemctl daemon-reload

log "Restarting the SSH WebSocket backend on 127.0.0.1:$SSH_WS_BACKEND_PORT."
systemctl restart nginxbandits-ws
systemctl is-active --quiet nginxbandits-ws ||
    die "The SSH WebSocket backend did not start."

log "Keeping Stunnel only for alternate TLS ports 447 and 777."
systemctl restart stunnel4
systemctl is-active --quiet stunnel4 ||
    die "Stunnel failed to start on its alternate ports."

log "Starting the Trojan backend."
systemctl enable nginxbandits-trojan.service >/dev/null
systemctl restart nginxbandits-trojan.service
systemctl is-active --quiet nginxbandits-trojan.service ||
    die "Trojan backend failed to start."

log "Activating the shared HTTP/HTTPS router."
systemctl enable haproxy >/dev/null
if systemctl is-active --quiet haproxy; then
    systemctl reload haproxy
else
    systemctl start haproxy
fi
systemctl is-active --quiet haproxy ||
    die "HAProxy did not start."

# Verify all expected listeners after activation.
ss -lnt | grep -Eq '127\.0\.0\.1:8080|127\.0\.0\.1:.*8080' ||
    die "SSH WebSocket backend is not listening on port 8080."
ss -lnt | grep -Eq '0\.0\.0\.0:80|\*:80' ||
    die "Shared HTTP listener is missing on port 80."
ss -lnt | grep -Eq '0\.0\.0\.0:443|\*:443' ||
    die "Shared HTTPS listener is missing on port 443."
ss -lnt | grep -Eq '127\.0\.0\.1:10003|127\.0\.0\.1:.*10003' ||
    die "Trojan backend is not listening on port 10003."

ENCODED_PASSWORD="$(
    python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))' < "$PASSWORD_FILE"
)"
TLS_LINK="trojan://${ENCODED_PASSWORD}@${DOMAIN}:443?path=%2Ftrojan-ws&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#ISPBandits-Trojan-WS-TLS"
PLAIN_LINK="trojan://${ENCODED_PASSWORD}@${DOMAIN}:80?path=%2Ftrojan-ws&security=none&host=${DOMAIN}&type=ws#ISPBandits-Trojan-WS"

printf '\n'
printf '%s\n' '======================================================'
printf '%s\n' ' NGINXBANDITS SHARED SSH + TROJAN ROUTER IS ACTIVE'
printf '%s\n' '======================================================'
printf 'Domain:                 %s\n' "$DOMAIN"
printf 'Shared HTTP:            port 80'
printf 'Shared HTTPS:           port 443'
printf 'SSH WebSocket backend:  127.0.0.1:%s\n' "$SSH_WS_BACKEND_PORT"
printf 'Trojan WS backend:      127.0.0.1:%s\n' "$BACKEND_PORT"
printf 'Trojan WS path:         %s\n' "$WS_PATH"
printf 'Stunnel alternate TLS:  %s, %s\n' "${PORT_SSL_ALT1:-447}" "${PORT_SSL_ALT2:-777}"
printf 'Backup:                 %s\n' "$BACKUP_DIR"
printf '\nTLS Trojan profile (443):\n%s\n' "$TLS_LINK"
printf '\nPlain WebSocket profile (80; not encrypted):\n%s\n' "$PLAIN_LINK"
printf '\nExisting SSH WebSocket traffic is routed to the existing proxy; Trojan path is routed to Xray.\n'
printf 'Note: the first migration restarts the WebSocket listener, so existing sessions through that listener may reconnect once.\n'
