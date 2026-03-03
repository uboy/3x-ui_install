#!/usr/bin/env bash

module_dumbproxy_install() {
    [[ "$INSTALL_DUMBPROXY" == "true" ]] || return 0

    local dp_port="${PORT_DUMBPROXY:-8080}"
    local dp_user="${VPN_USER:-vpnuser}"
    local dp_pass="${VPN_PASS}"

    # Detect existing installation
    if systemctl is-active --quiet dumbproxy 2>/dev/null || [[ -x /usr/local/bin/dumbproxy ]]; then
        if ! ui_ask_reinstall "dumbproxy"; then
            log "Пропуск установки dumbproxy."
            INSTALL_DUMBPROXY="skipped"
            return 0
        fi
        systemctl stop dumbproxy 2>/dev/null || true
        systemctl disable dumbproxy 2>/dev/null || true
        rm -f /usr/local/bin/dumbproxy /etc/systemd/system/dumbproxy.service
        rm -rf /etc/dumbproxy
    fi

    log "Установка dumbproxy..."

    # Determine architecture
    local go_arch
    case "$(dpkg --print-architecture)" in
        amd64)  go_arch="amd64" ;;
        arm64)  go_arch="arm64" ;;
        *)      error "Неподдерживаемая архитектура: $(dpkg --print-architecture)"; return 1 ;;
    esac

    # Get latest release download URL via GitHub API
    log "Получение последней версии dumbproxy..."
    local api_response download_url
    api_response=$(curl -sS --max-time 15 \
        "https://api.github.com/repos/SenseUnit/dumbproxy/releases/latest" 2>&1) || true

    # Detect API-level errors (rate limit, auth, etc.)
    if echo "$api_response" | jq -e '.message' &>/dev/null 2>&1; then
        error "GitHub API вернул ошибку: $(echo "$api_response" | jq -r '.message')"
        return 1
    fi

    # Assets are plain binaries: dumbproxy.linux-amd64 (no tarball)
    download_url=$(echo "$api_response" \
        | jq -r --arg sfx "linux-${go_arch}" \
            '.assets[] | select(.name | endswith($sfx)) | .browser_download_url' \
            2>/dev/null || true)

    if [[ -z "$download_url" || "$download_url" == "null" ]]; then
        error "Не удалось получить URL загрузки dumbproxy с GitHub API"
        log "Ответ API: $(echo "$api_response" | jq -r '[.assets[].name] | @json' 2>/dev/null || echo "$api_response" | head -c 500)"
        return 1
    fi

    log "Загрузка: ${download_url}"
    curl -fsSL --max-time 60 "$download_url" -o /usr/local/bin/dumbproxy
    chmod 755 /usr/local/bin/dumbproxy

    # htpasswd-файл для basic auth (bcrypt)
    apt-get install -y --no-install-recommends apache2-utils
    mkdir -p /etc/dumbproxy
    htpasswd -nbBC 10 "$dp_user" "$dp_pass" > /etc/dumbproxy/passwd
    chmod 640 /etc/dumbproxy/passwd

    # TLS: использовать существующий Let's Encrypt сертификат если есть
    local cert_path="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    local key_path="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    local tls_args=""
    if [[ -f "$cert_path" && -f "$key_path" ]]; then
        tls_args="-cert ${cert_path} -key ${key_path}"
        log "TLS включён (сертификат: ${cert_path})"
    else
        warn "TLS сертификат не найден — dumbproxy запускается без TLS (HTTP-only)."
    fi

    # Systemd unit
    cat > /etc/systemd/system/dumbproxy.service <<EOF
[Unit]
Description=Dumbproxy HTTP/HTTPS Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/dumbproxy -bind-address :${dp_port} -auth htpasswd:///etc/dumbproxy/passwd ${tls_args}
Restart=on-failure
RestartSec=5
User=nobody
Group=nogroup
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dumbproxy
    systemctl start dumbproxy

    sleep 2
    if ! systemctl is-active --quiet dumbproxy; then
        error "dumbproxy не запустился. Журнал:"
        journalctl -u dumbproxy --no-pager | tail -15
        return 1
    fi

    firewall_allow "${dp_port}" tcp
    success "dumbproxy запущен на порту ${dp_port} (пользователь: ${dp_user})."
}
