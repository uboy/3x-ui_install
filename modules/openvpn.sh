#!/usr/bin/env bash

module_openvpn_install() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0
    
    OVPN_DIR="/opt/openvpn"

    # Детекция и очистка
    if docker ps -a --format '{{.Names}}' | grep -q "^openvpn$"; then
        if ! ui_ask_reinstall "OpenVPN"; then
            log "Пропуск установки OpenVPN."
            INSTALL_OPENVPN="skipped"
            return 0
        fi
        log "Очистка старой установки..."
        cd "$OVPN_DIR" && docker compose down -v 2>/dev/null || true
        rm -rf "$OVPN_DIR"
    fi

    log "Установка OpenVPN (Docker)..."
    mkdir -p "$OVPN_DIR"
    
    # 1. Генерация конфига
    # Добавляем принудительный пуш DNS и топологию
    docker run -v "$OVPN_DIR:/etc/openvpn" --rm kylemanna/openvpn ovpn_genconfig -u "udp://$DOMAIN" -n 8.8.8.8 -n 1.1.1.1
    
    # Тюнинг конфига сервера
    log "Настройка параметров OpenVPN сервера..."
    {
        echo "push \"dhcp-option DNS 8.8.8.8\""
        echo "push \"dhcp-option DNS 1.1.1.1\""
        echo "push \"block-outside-dns\""
        
        # Split Tunneling (Исключения локальных сетей)
        echo 'push "route 192.168.0.0 255.255.0.0 net_gateway"'
        echo 'push "route 10.0.0.0 255.0.0.0 net_gateway"'
        echo 'push "route 172.16.0.0 255.240.0.0 net_gateway"'
        
        if [[ -n "${VPN_EXCLUDE_ROUTES:-}" ]]; then
            IFS=',' read -ra ADDR <<< "$VPN_EXCLUDE_ROUTES"
            for i in "${ADDR[@]}"; do
                local ip=$(echo "$i" | xargs | cut -d'/' -f1)
                echo "push \"route $ip 255.255.255.255 net_gateway\""
            done
        fi
    } >> "$OVPN_DIR/openvpn.conf"

    log "Генерация ключей PKI..."
    echo -e "\n\n\n\n\n\n\n\n" | docker run -v "$OVPN_DIR:/etc/openvpn" --rm -i kylemanna/openvpn ovpn_initpki nopass

    # 2. Docker Compose
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
    
    # 3. Настройка NAT в UFW (Подсеть OpenVPN по умолчанию 192.168.255.0/24)
    firewall_configure_nat "192.168.255.0/24"
    firewall_allow 1194 udp
    
    success "OpenVPN установлен и NAT настроен."
}

module_openvpn_configure() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0
    [[ "$INSTALL_OPENVPN" == "skipped" ]] && return 0
    
    local client_name="${VPN_USER:-vpnuser}"
    log "Создание конфигурации OpenVPN для $client_name..."
    OVPN_DIR="/opt/openvpn"
    
    cd "$OVPN_DIR"
    docker compose run --rm openvpn easyrsa build-client-full "$client_name" nopass
    docker compose run --rm openvpn ovpn_getclient "$client_name" > "$OVPN_DIR/${client_name}.ovpn"
    
    success "Конфигурация клиента OpenVPN готова."
}
