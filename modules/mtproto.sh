#!/usr/bin/env bash

module_mtproto_install() {
    [[ "${INSTALL_MTPROXY:-false}" == "true" ]] || return 0

    local mt_port="${PORT_MTPROXY:-443}"
    local mt_stats_port="${PORT_MTPROXY_STATS:-8888}"
    local mt_repo_dir="/opt/mtproxy"
    local mt_conf_dir="/etc/mtproxy"
    local mt_binary="${mt_repo_dir}/objs/bin/mtproto-proxy"
    local mt_secret="${MTPROXY_SECRET:-}"
    local mt_user="_mtproxy"
    local mt_hex=""

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

    log "Установка MTProto Proxy нативно из официального репозитория..."
    apt-get update
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
    curl -fsSL https://core.telegram.org/getProxyConfig -o "${mt_conf_dir}/proxy-multi.conf"
    chmod 600 "${mt_conf_dir}/proxy-secret" "${mt_conf_dir}/proxy-multi.conf"

    if [[ ! "$mt_secret" =~ ^dd[a-f0-9]{32}$ ]]; then
        mt_hex="$(generate_random_fixed 32 'abcdef0123456789' true)" || mt_hex="$(openssl rand -hex 16)"
        mt_secret="dd${mt_hex}"
    fi
    MTPROXY_SECRET="$mt_secret"

    while ! check_port_free "$mt_stats_port"; do
        mt_stats_port=$((mt_stats_port + 1))
        if (( mt_stats_port > 65535 )); then
            error "Не удалось подобрать свободный локальный порт статистики для MTProto."
            return 1
        fi
    done
    PORT_MTPROXY_STATS="$mt_stats_port"

    if ! id "$mt_user" &>/dev/null; then
        useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$mt_user"
    fi

    cat > /etc/systemd/system/mtproxy.service <<EOF
[Unit]
Description=Telegram MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${mt_repo_dir}
ExecStart=${mt_binary} -u ${mt_user} -p ${PORT_MTPROXY_STATS} -H ${mt_port} -S ${MTPROXY_SECRET} --aes-pwd ${mt_conf_dir}/proxy-secret ${mt_conf_dir}/proxy-multi.conf --multithread
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mtproxy
    systemctl restart mtproxy

    sleep 3
    if ! systemctl is-active --quiet mtproxy; then
        error "Сервис mtproxy не запустился. Журнал:"
        journalctl -u mtproxy --no-pager | tail -15
        return 1
    fi

    firewall_allow "$mt_port" tcp
    success "MTProto Proxy успешно запущен на порту ${mt_port}/TCP."
}