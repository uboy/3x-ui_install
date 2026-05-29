#!/usr/bin/env bash

module_mtproto_install() {
    [[ "${INSTALL_MTPROXY:-false}" == "true" ]] || return 0

    local mt_port="${PORT_MTPROXY:-443}"
    local mt_conf_dir="/etc/mtproxy"
    local mt_repo_dir="/opt/mtproxy"
    local mt_binary="${mt_repo_dir}/mtg"
    local mt_user="_mtproxy"
    # Use the actual server domain for masking instead of google.com
    local mt_domain="${MTPROXY_DOMAIN:-$DOMAIN}"
    [[ -n "$mt_domain" ]] || mt_domain="google.com"

    # Secret handling: mtg v2 uses ee-secrets for Fake-TLS (Generation 3)
    # Format: ee + 16 random bytes + hex-encoded domain.
    local mt_raw_secret="${MTPROXY_SECRET:-}"
    # If existing secret is not an ee-secret, we'll need to generate a new one.
    # Also regenerate if mt_domain changed compared to what might be in the secret.
    if [[ ! "$mt_raw_secret" =~ ^ee[a-f0-9]{32,} ]]; then
        mt_raw_secret=""
    fi

    # Check for existing installation (either old C version or mtg)
    if systemctl is-active --quiet mtproxy 2>/dev/null || [[ -x "$mt_binary" ]] || [[ -x "/opt/mtproxy/objs/bin/mtproto-proxy" ]]; then
        if ! ui_ask_reinstall "MTProto Proxy (mtg)"; then
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

    log "Установка MTProto Proxy (mtg v2)..."
    apt-get install -y curl jq tar

    mkdir -p "$mt_repo_dir" "$mt_conf_dir"
    
    local latest_tag tarball_url
    latest_tag=$(curl -fsSL https://api.github.com/repos/9seconds/mtg/releases/latest | jq -r .tag_name)
    tarball_url="https://github.com/9seconds/mtg/releases/download/${latest_tag}/mtg-${latest_tag#v}-linux-amd64.tar.gz"
    
    log "Загрузка mtg ${latest_tag}..."
    curl -fsSL "$tarball_url" -o "${mt_repo_dir}/mtg.tar.gz"
    tar -xzf "${mt_repo_dir}/mtg.tar.gz" -C "$mt_repo_dir" --strip-components=1
    rm -f "${mt_repo_dir}/mtg.tar.gz"

    [[ -x "$mt_binary" ]] || {
        error "Бинарник mtg не найден после распаковки: ${mt_binary}"
        return 1
    }

    # Generate secret if needed
    if [[ -z "$mt_raw_secret" ]]; then
        log "Генерация Fake-TLS секрета для домена ${mt_domain}..."
        mt_raw_secret=$("$mt_binary" generate-secret --hex "$mt_domain")
        [[ -n "$mt_raw_secret" ]] || { error "Не удалось сгенерировать секрет"; return 1; }
    fi
    MTPROXY_SECRET="${mt_raw_secret}"

    if ! id "$mt_user" &>/dev/null; then
        useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$mt_user"
    fi

    # Config file (TOML)
    cat > "${mt_conf_dir}/mtg.toml" <<EOF
secret = "${mt_raw_secret}"
bind-to = "0.0.0.0:${mt_port}"
EOF
    chmod 600 "${mt_conf_dir}/mtg.toml"
    chown "$mt_user:$mt_user" "${mt_conf_dir}/mtg.toml"

    cat > /etc/systemd/system/mtproxy.service <<EOF
[Unit]
Description=mtg MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${mt_user}
Group=${mt_user}
WorkingDirectory=${mt_repo_dir}
ExecStart=${mt_binary} run ${mt_conf_dir}/mtg.toml
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
            success "MTProto Proxy (mtg) успешно запущен на порту ${mt_port}/TCP."
            return 0
        fi
    done

    error "Сервис mtproxy (mtg) не запустился. Журнал:"
    journalctl -u mtproxy --no-pager -n 40
    return 1
}
