#!/usr/bin/env bash

module_mtproto_install() {
    [[ "${INSTALL_MTPROXY:-false}" == "true" ]] || return 0

    local mt_port="${PORT_MTPROXY:-443}"
    local mt_conf_dir="/etc/mtproxy"
    local mt_binary="/opt/mtproxy/objs/bin/mtproto-proxy"
    local mt_repo_dir="/opt/mtproxy"
    local mt_user="_mtproxy"

    # Normalize secret: binary needs exactly 32 hex chars (no dd prefix).
    # tg://proxy link uses dd<hex32> to signal fake-TLS to the client.
    local mt_raw_secret="${MTPROXY_SECRET:-}"
    if [[ "$mt_raw_secret" =~ ^dd([a-f0-9]{32})$ ]]; then
        mt_raw_secret="${BASH_REMATCH[1]}"
    fi
    if [[ ! "$mt_raw_secret" =~ ^[a-f0-9]{32}$ ]]; then
        mt_raw_secret="$(openssl rand -hex 16)"
    fi

    if systemctl is-active --quiet mtproxy 2>/dev/null || [[ -x "$mt_binary" ]]; then
        if ! ui_ask_reinstall "MTProto Proxy"; then
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

    log "Установка MTProto Proxy (сборка из исходников)..."
    apt-get install -y git curl build-essential libssl-dev zlib1g-dev

    rm -rf "$mt_repo_dir"
    git clone --depth 1 https://github.com/TelegramMessenger/MTProxy "$mt_repo_dir"
    make -C "$mt_repo_dir"

    [[ -x "$mt_binary" ]] || {
        error "Бинарник MTProxy не найден после сборки: ${mt_binary}"
        return 1
    }

    mkdir -p "$mt_conf_dir"
    curl -fsSL https://core.telegram.org/getProxySecret -o "${mt_conf_dir}/proxy-secret"
    curl -fsSL https://core.telegram.org/getProxyConfig  -o "${mt_conf_dir}/proxy-multi.conf"
    chmod 600 "${mt_conf_dir}/proxy-secret" "${mt_conf_dir}/proxy-multi.conf"

    # Store dd-prefixed secret for tg://proxy link
    MTPROXY_SECRET="dd${mt_raw_secret}"

    if ! id "$mt_user" &>/dev/null; then
        useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$mt_user"
    fi

    # Flags (new binary API):
    #   -p PORT        — main proxy listen port
    #   -S HEX32       — exactly 32 hex chars (no dd prefix for the binary itself)
    #   --aes-pwd FILE — ONE argument: proxy-secret file
    #   <conf-file>    — positional: proxy-multi.conf
    #   --domain HOST  — enable fake-TLS; client uses dd<secret> in tg link
    #   -M N           — worker count (--slaves)
    cat > /etc/systemd/system/mtproxy.service <<EOF
[Unit]
Description=Telegram MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${mt_repo_dir}
ExecStart=${mt_binary} \\
  -u ${mt_user} \\
  -p ${mt_port} \\
  -S ${mt_raw_secret} \\
  --aes-pwd ${mt_conf_dir}/proxy-secret \\
  --domain www.google.com \\
  ${mt_conf_dir}/proxy-multi.conf
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
            success "MTProto Proxy успешно запущен на порту ${mt_port}/TCP."
            return 0
        fi
    done

    error "Сервис mtproxy не запустился. Журнал:"
    journalctl -u mtproxy --no-pager | head -40
    return 1
}
