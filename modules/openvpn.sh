#!/usr/bin/env bash

module_openvpn_install() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0
    
    OVPN_DIR="/opt/openvpn"

    # Детекция существующей установки
    if docker ps -a --format '{{.Names}}' | grep -q "^openvpn$"; then
        if ! ui_ask_reinstall "OpenVPN"; then
            log "Пропуск установки OpenVPN по желанию пользователя."
            INSTALL_OPENVPN="skipped"
            return 0
        fi
        log "Очистка старой установки OpenVPN..."
        cd "$OVPN_DIR" && docker compose down -v 2>/dev/null || true
        rm -rf "$OVPN_DIR"
    fi

    log "Установка OpenVPN (Docker)..."
    mkdir -p "$OVPN_DIR"
    
    # 1. Инициализация конфигурации
    log "Инициализация конфигурации OpenVPN для $DOMAIN..."
    # Генерируем конфиг с принудительным использованием Google DNS
    docker run -v "$OVPN_DIR:/etc/openvpn" --rm kylemanna/openvpn ovpn_genconfig -u "udp://$DOMAIN" -n 8.8.8.8 -n 8.8.4.4
    
    # Генерация PKI (без пароля)
    log "Генерация ключей шифрования (PKI)..."
    echo -e "\n\n\n\n\n\n\n\n" | docker run -v "$OVPN_DIR:/etc/openvpn" --rm -i kylemanna/openvpn ovpn_initpki nopass

    # 2. Создание Docker Compose
    cat > "${OVPN_DIR}/docker-compose.yml" <<EOF
services:
  openvpn:
    image: kylemanna/openvpn
    container_name: openvpn
    ports:
      - "1194:1194/udp"
    volumes:
      - .:/etc/openvpn
    cap_add:
      - NET_ADMIN
    restart: unless-stopped
EOF

    cd "$OVPN_DIR"
    docker compose up -d
    
    # 3. Настройка NAT на хосте (на всякий случай для UFW)
    local eth=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -n 1)
    if [[ -n "$eth" ]]; then
        log "Настройка NAT (Masquerade) на интерфейсе $eth..."
        iptables -t nat -A POSTROUTING -s 192.168.255.0/24 -o "$eth" -j MASQUERADE 2>/dev/null || true
    fi

    firewall_allow 1194 udp
    success "OpenVPN запущен на порту 1194/UDP."
}

module_openvpn_configure() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0
    [[ "$INSTALL_OPENVPN" == "skipped" ]] && return 0
    
    local client_name="${VPN_USER:-vpnuser}"
    log "Создание конфигурации OpenVPN для пользователя $client_name..."
    OVPN_DIR="/opt/openvpn"
    
    cd "$OVPN_DIR"
    docker compose run --rm openvpn easyrsa build-client-full "$client_name" nopass
    docker compose run --rm openvpn ovpn_getclient "$client_name" > "$OVPN_DIR/${client_name}.ovpn"
    
    success "Конфигурация клиента OpenVPN успешно создана."
}
