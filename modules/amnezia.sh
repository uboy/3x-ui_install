#!/usr/bin/env bash

module_amnezia_install() {
    [[ "$INSTALL_AMNEZIA" == "true" ]] || return 0
    
    log "Установка AmneziaWG (Docker)..."
    
    AMN_DIR="/opt/amnezia"
    mkdir -p "$AMN_DIR"
    
    # Генерация ключей WireGuard
    local private_key=$(docker run --rm ghcr.io/amnezia-vpn/amneziawg-go wg genkey)
    local public_key=$(echo "$private_key" | docker run --rm -i ghcr.io/amnezia-vpn/amneziawg-go wg pubkey)
    
    # Создание конфигурации сервера
    cat > "${AMN_DIR}/amneziawg.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.8.0.1/24
ListenPort = 51820
# AmneziaWG specific parameters (Junk packet settings)
J1 = $(shuf -i 10-100 -n 1)
J2 = $(shuf -i 10-100 -n 1)
S1 = $(shuf -i 10-100 -n 1)
S2 = $(shuf -i 10-100 -n 1)
H1 = $(shuf -i 10000000-99999999 -n 1)
H2 = $(shuf -i 10000000-99999999 -n 1)
H3 = $(shuf -i 10000000-99999999 -n 1)
H4 = $(shuf -i 10000000-99999999 -n 1)
EOF

    # Docker Compose для AmneziaWG
    cat > "${AMN_DIR}/docker-compose.yml" <<EOF
services:
  amneziawg:
    image: ghcr.io/amnezia-vpn/amneziawg-go
    container_name: amneziawg
    cap_add:
      - NET_ADMIN
    volumes:
      - ./amneziawg.conf:/etc/amneziawg/awg0.conf
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
EOF

    cd "$AMN_DIR"
    docker compose up -d
    
    # Генерация клиентских ключей
    local client_private_key=$(docker run --rm ghcr.io/amnezia-vpn/amneziawg-go wg genkey)
    local client_public_key=$(echo "$client_private_key" | docker run --rm -i ghcr.io/amnezia-vpn/amneziawg-go wg pubkey)
    
    # Добавление пира на сервер
    docker exec amneziawg wg set awg0 peer "$client_public_key" allowed-ips 10.8.0.2/32
    
    # Создание клиентского конфига
    cat > "${AMN_DIR}/amnezia_client.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = 10.8.0.2/24
DNS = 1.1.1.1
# AmneziaWG specific
J1 = $(grep J1 amneziawg.conf | cut -d' ' -f3)
J2 = $(grep J2 amneziawg.conf | cut -d' ' -f3)
S1 = $(grep S1 amneziawg.conf | cut -d' ' -f3)
S2 = $(grep S2 amneziawg.conf | cut -d' ' -f3)
H1 = $(grep H1 amneziawg.conf | cut -d' ' -f3)
H2 = $(grep H2 amneziawg.conf | cut -d' ' -f3)
H3 = $(grep H3 amneziawg.conf | cut -d' ' -f3)
H4 = $(grep H4 amneziawg.conf | cut -d' ' -f3)

[Peer]
PublicKey = $public_key
Endpoint = $DOMAIN:51820
AllowedIPs = 0.0.0.0/0
EOF

    firewall_allow 51820 udp
    success "AmneziaWG запущен. Клиентский конфиг: ${AMN_DIR}/amnezia_client.conf"
}
