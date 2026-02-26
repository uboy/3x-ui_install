#!/usr/bin/env bash

module_amnezia_install() {
    [[ "$INSTALL_AMNEZIA" == "true" ]] || return 0
    
    AMN_DIR="/opt/amnezia"

    # Детекция существующей установки
    if docker ps -a --format '{{.Names}}' | grep -q "^amneziawg$"; then
        if ! ui_ask_reinstall "AmneziaWG"; then
            log "Пропуск установки AmneziaWG по желанию пользователя."
            INSTALL_AMNEZIA="skipped"
            return 0
        fi
        log "Очистка старой установки AmneziaWG..."
        cd "$AMN_DIR" && docker compose down -v 2>/dev/null || true
        rm -rf "$AMN_DIR"
    fi

    log "Установка AmneziaWG (Docker)..."
    mkdir -p "$AMN_DIR"
    
    local image="amneziavpn/amnezia-wg"
    
    log "Генерация ключей..."
    local private_key=$(docker run --rm $image awg genkey)
    local public_key=$(echo "$private_key" | docker run --rm -i $image awg pubkey)
    
    log "Настройка параметров обфускации..."
    cat > "${AMN_DIR}/amneziawg.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.8.0.1/24
ListenPort = 51820

# AmneziaWG Junk Settings
J1 = $(shuf -i 10-100 -n 1)
J2 = $(shuf -i 10-100 -n 1)
S1 = $(shuf -i 10-100 -n 1)
S2 = $(shuf -i 10-100 -n 1)
H1 = $(shuf -i 10000000-99999999 -n 1)
H2 = $(shuf -i 10000000-99999999 -n 1)
H3 = $(shuf -i 10000000-99999999 -n 1)
H4 = $(shuf -i 10000000-99999999 -n 1)
EOF

    cat > "${AMN_DIR}/docker-compose.yml" <<EOF
services:
  amneziawg:
    image: $image
    container_name: amneziawg
    cap_add:
      - NET_ADMIN
    volumes:
      - ./amneziawg.conf:/etc/amnezia/awg0.conf
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
EOF

    log "Запуск контейнера AmneziaWG..."
    cd "$AMN_DIR"
    docker compose up -d
    
    # Ждем подольше и проверяем статус
    log "Ожидание инициализации (10 сек)..."
    sleep 10

    if ! docker ps --format '{{.Names}} {{.Status}}' | grep "amneziawg" | grep -q "Up"; then
        error "Контейнер amneziawg не запустился (Restart loop). Логи контейнера:"
        docker logs amneziawg | tail -n 20
        return 1
    fi

    log "Создание клиентского профиля..."
    local client_private_key=$(docker run --rm $image awg genkey)
    local client_public_key=$(echo "$client_private_key" | docker run --rm -i $image awg pubkey)
    
    # Используем awg вместо wg внутри контейнера
    docker exec amneziawg awg set awg0 peer "$client_public_key" allowed-ips 10.8.0.2/32
    
    log "Генерация файла конфигурации для клиента (amnezia_client.conf)..."
    cat > "${AMN_DIR}/amnezia_client.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = 10.8.0.2/24
DNS = 1.1.1.1
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
    success "AmneziaWG успешно запущен и настроен."
}
