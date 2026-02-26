#!/usr/bin/env bash

module_openvpn_install() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0
    
    log "Установка OpenVPN (Docker)..."
    
    OVPN_DIR="/opt/openvpn"
    mkdir -p "$OVPN_DIR"
    
    # 1. Инициализация конфигурации если её нет
    if [[ ! -f "$OVPN_DIR/openvpn.conf" ]]; then
        log "Инициализация конфигурации OpenVPN для $DOMAIN..."
        docker run -v "$OVPN_DIR:/etc/openvpn" --rm kylemanna/openvpn ovpn_genconfig -u "udp://$DOMAIN"
        # Генерация PKI (без пароля для автоматизации)
        echo -e "\n\n\n\n\n\n\n\n" | docker run -v "$OVPN_DIR:/etc/openvpn" --rm -i kylemanna/openvpn ovpn_initpki nopass
    fi

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
    
    firewall_allow 1194 udp
    success "OpenVPN запущен на порту 1194/UDP."
}

module_openvpn_configure() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0
    
    local client_name="${VPN_USER:-client1}"
    log "Создание конфигурации OpenVPN для пользователя $client_name..."
    OVPN_DIR="/opt/openvpn"
    
    cd "$OVPN_DIR"
    docker compose run --rm openvpn easyrsa build-client-full "$client_name" nopass
    docker compose run --rm openvpn ovpn_getclient "$client_name" > "$OVPN_DIR/${client_name}.ovpn"
    
    success "Конфигурация клиента OpenVPN успешно создана: $OVPN_DIR/${client_name}.ovpn"
}
