#!/usr/bin/env bash

module_openconnect_install() {
    [[ "$INSTALL_OPENCONNECT" == "true" ]] || return 0
    
    # 1. Глубокая очистка при переустановке
    if dpkg -l ocserv &>/dev/null; then
        if ! ui_ask_reinstall "OpenConnect (ocserv)"; then
            log "Пропуск установки OpenConnect."
            INSTALL_OPENCONNECT="skipped"
            return 0
        fi
        log "Полное удаление старой установки ocserv..."
        systemctl stop ocserv 2>/dev/null || true
        # Удаляем директории ДО purge, чтобы dpkg не жаловался на "not empty"
        rm -rf /etc/ocserv
        rm -rf /run/ocserv
        apt-get purge -y ocserv || true
    fi

    log "Установка OpenConnect (ocserv) нативно..."
    apt-get update && apt-get install -y ocserv
    
    # 2. Подготовка сертификатов
    local cert_dir="/etc/letsencrypt/live/$DOMAIN"
    local cert_path="${cert_dir}/fullchain.pem"
    local key_path="${cert_dir}/privkey.pem"
    
    mkdir -p "$cert_dir"
    if [[ ! -f "$cert_path" ]]; then
        warn "Сертификаты не найдены. Генерируем временные..."
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$key_path" -out "$cert_path" \
            -subj "/CN=$DOMAIN"
        chmod 600 "$key_path"
    fi

    # 3. Генерация ПРАВИЛЬНОГО конфига (исправлено для Ubuntu 24.04)
    log "Настройка конфигурации ocserv..."
    cat > /etc/ocserv/ocserv.conf <<EOF
# Способ аутентификации
auth = "plain[passwd=/etc/ocserv/ocpasswd]"

# Сетевые настройки
tcp-port = 4443
udp-port = 4443
device = vpns
socket-file = /run/ocserv.socket
run-as-user = ocserv
run-as-group = ocserv

# Сертификаты
server-cert = $cert_path
server-key = $key_path
ca-cert = $cert_path

# Лимиты и тайм-ауты
isolate-workers = true
max-clients = 64
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
idle-timeout = 1200
mobile-idle-timeout = 2400

# Настройки IP
cert-user-oid = 2.5.4.3
default-domain = $DOMAIN
ipv4-network = 192.168.10.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 1.1.1.1

# Исключения (Split Tunneling)
no-route = 192.168.0.0/255.255.0.0
no-route = 10.0.0.0/255.0.0.0
no-route = 172.16.0.0/255.240.0.0
EOF

    # Добавляем пользовательские исключения в ocserv
    if [[ -n "${VPN_EXCLUDE_ROUTES:-}" ]]; then
        IFS=',' read -ra ADDR <<< "$VPN_EXCLUDE_ROUTES"
        for i in "${ADDR[@]}"; do
            echo "no-route = $(echo "$i" | xargs)" >> /etc/ocserv/ocserv.conf
        done
    fi

    cat >> /etc/ocserv/ocserv.conf <<EOF
predictable-ips = true
ping-leases = false

# Совместимость
cisco-client-compat = true
dtls-psk = true
route = default
EOF

    # 4. Создание пользователя
    local oc_user="${VPN_USER:-vpnuser}"
    local oc_pass="${VPN_PASS}"
    touch /etc/ocserv/ocpasswd
    # Use heredoc to avoid password appearing in ps aux / shell history
    ocpasswd -c /etc/ocserv/ocpasswd "$oc_user" <<EOF
${oc_pass}
${oc_pass}
EOF
    unset oc_pass
    chmod 600 /etc/ocserv/ocpasswd
    
    # 5. Сеть (NAT через UFW)
    firewall_configure_nat "192.168.10.0/24"
    firewall_allow 4443 tcp
    firewall_allow 4443 udp
    
    # 6. Запуск и проверка
    log "Запуск сервиса ocserv..."
    mkdir -p /run/ocserv # Гарантируем наличие папки для сокета
    systemctl daemon-reload
    systemctl enable ocserv
    systemctl restart ocserv
    
    sleep 3
    if ! systemctl is-active --quiet ocserv; then
        error "Сервис ocserv не запустился. Повторная проверка логов..."
        journalctl -u ocserv --no-pager | tail -n 10
        return 1
    fi

    success "OpenConnect успешно запущен на порту 4443."
}
