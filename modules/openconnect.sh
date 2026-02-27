#!/usr/bin/env bash

module_openconnect_install() {
    [[ "$INSTALL_OPENCONNECT" == "true" ]] || return 0
    
    # Детекция существующей установки (пакет ocserv)
    if dpkg -l ocserv &>/dev/null; then
        if ! ui_ask_reinstall "OpenConnect (ocserv)"; then
            log "Пропуск установки OpenConnect по желанию пользователя."
            INSTALL_OPENCONNECT="skipped"
            return 0
        fi
        log "Полное удаление старой установки ocserv..."
        systemctl stop ocserv 2>/dev/null || true
        apt-get purge -y ocserv || true
        rm -rf /etc/ocserv
        rm -rf /run/ocserv
    fi

    log "Установка OpenConnect (ocserv) нативно..."
    apt-get update && apt-get install -y ocserv
    
    # Пути сертификатов (поддержка IP и Доменов)
    local cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    local key_path="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    
    # Если сертификатов нет (например, не запускали cert_issue), создаем self-signed
    if [[ ! -f "$cert_path" ]]; then
        warn "Сертификаты не найдены в $cert_path. Создаем временные..."
        mkdir -p "/etc/letsencrypt/live/$DOMAIN"
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$key_path" -out "$cert_path" \
            -subj "/CN=$DOMAIN"
        chmod 600 "$key_path"
    fi

    # Настройка конфигурации
    log "Настройка конфигурации ocserv..."
    cat > /etc/ocserv/ocserv.conf <<EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = 4443
udp-port = 4443
run-as-user = ocserv
run-as-group = ocserv
# socket-file отключен для избежания проблем с правами в Ubuntu 24.04
# socket-file = /run/ocserv.socket
server-cert = $cert_path
server-key = $key_path
ca-cert = $cert_path
isolate-workers = true
max-clients = 16
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
idle-timeout = 1200
mobile-idle-timeout = 2400
cert-user-oid = 2.5.4.3
default-domain = $DOMAIN
ipv4-network = 192.168.10.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 1.1.1.1
route = default
cisco-client-compat = true
dtls-psk = true
EOF

    # Создание пользователя
    local oc_user="${VPN_USER:-vpnuser}"
    local oc_pass="${VPN_PASS}"
    log "DEBUG: Регистрация пользователя $oc_user в ocserv..."
    touch /etc/ocserv/ocpasswd
    (echo "$oc_pass"; echo "$oc_pass") | ocpasswd -c /etc/ocserv/ocpasswd "$oc_user"
    
    # Включаем IP Forwarding
    log "Включение IP Forwarding..."
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv.conf
    sysctl -p /etc/sysctl.d/99-ocserv.conf 2>/dev/null || true
    
    # Настройка NAT (важно для работы интернета через VPN)
    # Пытаемся определить основной интерфейс
    local eth=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -n 1)
    if [[ -n "$eth" ]]; then
        iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o "$eth" -j MASQUERADE 2>/dev/null || true
    fi

    firewall_allow 4443 tcp
    firewall_allow 4443 udp
    
    log "Запуск сервиса ocserv..."
    systemctl daemon-reload
    systemctl enable ocserv
    systemctl restart ocserv
    
    # Проверка запуска
    sleep 2
    if ! systemctl is-active --quiet ocserv; then
        error "Сервис ocserv не смог запуститься. Проверьте 'journalctl -u ocserv'"
        return 1
    fi

    success "OpenConnect успешно запущен и настроен на порту 4443."
}
