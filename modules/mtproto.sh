#!/usr/bin/env bash

module_mtproto_install() {
    [[ "${INSTALL_MTPROXY:-false}" == "true" ]] || return 0

    local mt_port="${PORT_MTPROXY:-443}"
    local mt_conf_dir="/etc/mtproxy"
    local mt_repo_dir="/opt/mtproxy"
    local mt_binary="${mt_repo_dir}/teleproxy"
    local mt_user="_mtproxy"
    local mt_domain="${MTPROXY_DOMAIN:-$DOMAIN}"
    [[ -n "$mt_domain" ]] || mt_domain="www.google.com"

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
    # - MTPROXY_SECRET is stored as the full ee-secret (ee + 32hex_key + hex_domain)
    # - Teleproxy config needs just the 32-char hex key (16 bytes)
    # - If we have a valid ee-secret from a previous install, extract the key from it.
    local mt_ee_secret="${MTPROXY_SECRET:-}"
    local mt_key=""

    if [[ "$mt_ee_secret" =~ ^ee([a-f0-9]{32}) ]]; then
        mt_key="${BASH_REMATCH[1]}"
        log "Повторное использование существующего секрета."
    else
        log "Генерация Fake-TLS секрета для домена ${mt_domain}..."
        local gen_output
        gen_output=$("$mt_binary" generate-secret "$mt_domain")
        # First line is the full ee-secret for the tg:// URL
        mt_ee_secret=$(echo "$gen_output" | head -1)
        # Extract the 32-hex key (after "ee" prefix, before hex domain)
        mt_key=$(echo "$gen_output" | awk '/Secret for -S:/{print $NF}')
        [[ -n "$mt_ee_secret" && -n "$mt_key" ]] || { error "Не удалось сгенерировать секрет"; return 1; }
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
ExecStart=${mt_binary} --config ${mt_conf_dir}/config.toml --allow-skip-dh
Restart=on-failure
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
