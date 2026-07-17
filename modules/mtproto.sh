#!/usr/bin/env bash

module_mtproto_install() {
    [[ "${INSTALL_MTPROXY:-false}" == "true" ]] || return 0

    local mt_port="${PORT_MTPROXY:-8443}"
    local mt_conf_dir="/etc/mtproxy"
    local mt_repo_dir="/opt/mtproxy"
    local mt_binary="${mt_repo_dir}/teleproxy"
    local mt_user="_mtproxy"
    # Fake-TLS masking domain must be an external popular domain, not the server's own
    # domain — using the server's own domain creates a circular probe and reveals the proxy.
    local mt_domain="${MTPROXY_DOMAIN:-}"
    if [[ -z "$mt_domain" ]]; then
        mt_domain="www.google.com"
        warn "MTPROXY_DOMAIN не задан — используется резервный домен ${mt_domain}. Задайте MTPROXY_DOMAIN явно (через UI) для маскировки, правдоподобной для IP/ASN этого сервера."
    fi
    if [[ -n "${DOMAIN:-}" && "$mt_domain" == "${DOMAIN}" ]]; then
        warn "MTPROXY_DOMAIN совпадает с DOMAIN сервера (${DOMAIN}) — это создаёт circular-probe и может выдать прокси."
    fi

    # Check for existing installation
    if systemctl is-active --quiet mtproxy 2>/dev/null || [[ -x "$mt_binary" ]] || [[ -x "/opt/mtproxy/mtg" ]] || [[ -x "/opt/mtproxy/objs/bin/mtproto-proxy" ]]; then
        if ! ui_ask_reinstall "MTProto Proxy (Teleproxy)"; then
            log "Пропуск установки MTProto Proxy."
            INSTALL_MTPROXY="skipped"
            return 0
        fi

        log "Очистка старой установки MTProto Proxy..."
        systemctl stop mtproxy 2>/dev/null || true
        systemctl disable mtproxy 2>/dev/null || true
        rm -f /etc/systemd/system/mtproxy.service
        rm -rf "$mt_repo_dir" "$mt_conf_dir"
    fi

    log "Установка MTProto Proxy (Teleproxy)..."
    apt-get install -y curl jq

    mkdir -p "$mt_repo_dir" "$mt_conf_dir"

    local arch
    case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)
            error "Неподдерживаемая архитектура: $(uname -m)"
            return 1
            ;;
    esac

    local latest_tag bin_url
    latest_tag=$(curl -fsSL https://api.github.com/repos/teleproxy/teleproxy/releases/latest | jq -r .tag_name)
    bin_url="https://github.com/teleproxy/teleproxy/releases/download/${latest_tag}/teleproxy-linux-${arch}"

    log "Загрузка Teleproxy ${latest_tag}..."
    curl -fsSL "$bin_url" -o "$mt_binary"
    chmod +x "$mt_binary"

    [[ -x "$mt_binary" ]] || {
        error "Бинарник Teleproxy не найден после загрузки: ${mt_binary}"
        return 1
    }

    # Secret handling:
    # - MTPROXY_SECRET is stored as the full ee-secret (ee + 32hex_key + hex-encoded domain).
    # - Teleproxy's [[secret]] key= wants just the 32-hex key; the domain is configured
    #   separately via the top-level `domain =` TOML key above.
    # - Only rotate (generate a brand-new key) when the disguise domain actually changes.
    #   An unchanged domain must reuse the exact stored secret untouched — reinstalling
    #   should not invalidate proxy links already handed out.
    local mt_existing="${MTPROXY_SECRET:-}"
    local mt_ee_secret="" mt_key=""
    local mt_existing_key="" mt_existing_domain=""

    if [[ "$mt_existing" =~ ^ee([a-f0-9]{32})([a-f0-9]*)$ ]]; then
        mt_existing_key="${BASH_REMATCH[1]}"
        [[ -n "${BASH_REMATCH[2]}" ]] && mt_existing_domain=$(hex_decode_ascii "${BASH_REMATCH[2]}")
    fi

    if [[ -n "$mt_existing_key" && "$mt_existing_domain" == "$mt_domain" ]]; then
        mt_ee_secret="$mt_existing"
        mt_key="$mt_existing_key"
        log "Домен маскировки не изменился, секрет не тронут."
    else
        [[ -n "$mt_existing_key" ]] && log "Домен маскировки изменился (${mt_existing_domain:-<нет>} → ${mt_domain}), ротация секрета..."
        log "Генерация Fake-TLS секрета для домена ${mt_domain}..."
        # "Secret for -S:" goes to stderr; the ee-secret itself is the only stdout line.
        # Derive the raw key from the ee-secret directly instead of parsing stderr.
        mt_ee_secret=$("$mt_binary" generate-secret "$mt_domain" 2>/dev/null)
        if [[ "$mt_ee_secret" =~ ^ee([a-f0-9]{32}) ]]; then
            mt_key="${BASH_REMATCH[1]}"
        else
            error "Не удалось сгенерировать секрет"
            return 1
        fi
    fi
    MTPROXY_SECRET="${mt_ee_secret}"

    if ! id "$mt_user" &>/dev/null; then
        useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$mt_user"
    fi

    # Config file (TOML)
    # direct = true: подключается напрямую к Telegram DC без ME relay
    # domain: Fake-TLS маскировка — трафик неотличим от HTTPS к реальному сайту
    # MSS clamp включён по умолчанию: фрагментирует ClientHello, ломая DPI-реассемблинг
    cat > "${mt_conf_dir}/config.toml" <<EOF
port = ${mt_port}
direct = true
domain = "${mt_domain}"

[[secret]]
key = "${mt_key}"
EOF
    chmod 600 "${mt_conf_dir}/config.toml"
    chown "$mt_user:$mt_user" "${mt_conf_dir}/config.toml"

    # The service runs as an unprivileged user; binding a port below 1024
    # (e.g. an explicitly chosen 443 on a dedicated IP) needs an explicit
    # capability grant or the process exits immediately with EACCES.
    local mt_cap_lines=""
    if (( mt_port < 1024 )); then
        mt_cap_lines=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n'
    fi

    cat > /etc/systemd/system/mtproxy.service <<EOF
[Unit]
Description=Teleproxy MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${mt_user}
Group=${mt_user}
WorkingDirectory=${mt_repo_dir}
ExecStart=${mt_binary} --config ${mt_conf_dir}/config.toml
${mt_cap_lines}Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mtproxy
    systemctl restart mtproxy

    local i
    for (( i=0; i<15; i++ )); do
        sleep 2
        if systemctl is-active --quiet mtproxy; then
            firewall_allow "$mt_port" tcp
            success "MTProto Proxy (Teleproxy) успешно запущен на порту ${mt_port}/TCP."
            return 0
        fi
    done

    error "Сервис mtproxy (Teleproxy) не запустился. Журнал:"
    journalctl -u mtproxy --no-pager -n 40
    return 1
}
