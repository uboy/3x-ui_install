#!/usr/bin/env bash

module_amnezia_install() {
    [[ "$INSTALL_AMNEZIA" == "true" ]] || return 0
    
    AMN_DIR="/opt/amnezia"

    # Детекция и очистка
    if docker ps -a --format '{{.Names}}' | grep -q "^amneziawg$"; then
        if ! ui_ask_reinstall "AmneziaWG"; then
            log "Пропуск установки AmneziaWG."
            INSTALL_AMNEZIA="skipped"
            return 0
        fi
        log "Удаление старой установки..."
        cd "$AMN_DIR" && docker compose down -v 2>/dev/null || true
        rm -rf "$AMN_DIR"
    fi

    log "Установка AmneziaWG (Userspace Go)..."
    mkdir -p "$AMN_DIR"
    
    # Используем проверенный образ
    local image="amneziavpn/amnezia-wg"
    
    log "Генерация ключей..."
    # Генерируем ключи локально
    local private_key=$(openssl rand -base64 32)
    # Публичный ключ через временный контейнер
    local public_key=$(echo "$private_key" | docker run --rm -i $image awg pubkey 2>/dev/null || echo "$private_key" | docker run --rm -i $image wg pubkey)
    
    if [[ -z "$public_key" ]]; then
        error "Не удалось сгенерировать публичный ключ. Проверьте доступ к Docker."
        return 1
    fi

    log "Создание конфигурации..."
    cat > "${AMN_DIR}/amneziawg.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.8.0.1/24
ListenPort = 51820

# AmneziaWG Obfuscation
J1 = $(shuf -i 10-100 -n 1)
J2 = $(shuf -i 10-100 -n 1)
S1 = $(shuf -i 10-100 -n 1)
S2 = $(shuf -i 10-100 -n 1)
H1 = $(shuf -i 10000000-99999999 -n 1)
H2 = $(shuf -i 10000000-99999999 -n 1)
H3 = $(shuf -i 10000000-99999999 -n 1)
H4 = $(shuf -i 10000000-99999999 -n 1)
EOF

    # Создаем Docker Compose с использованием AWG-GO (userspace)
    cat > "${AMN_DIR}/docker-compose.yml" <<EOF
services:
  amneziawg:
    image: $image
    container_name: amneziawg
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./amneziawg.conf:/etc/amnezia/awg0.conf
    # Принудительно запускаем в режиме userspace если ядро не поддерживает AWG
    environment:
      - WG_QUICK_USERSPACE_IMPLEMENTATION=awg-go
      - WG_THREADS=4
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
EOF

    log "Запуск AmneziaWG..."
    cd "$AMN_DIR"
    docker compose up -d
    
    log "Проверка статуса (10 сек)..."
    sleep 10

    if ! docker ps --format '{{.Names}} {{.Status}}' | grep "amneziawg" | grep -q "Up"; then
        error "Контейнер упал. Причина из инспекции:"
        docker inspect amneziawg --format '{{.State.Error}}'
        log "Логи (последние 50 строк):"
        docker logs amneziawg --tail 50
        return 1
    fi

    log "Создание клиента..."
    local client_private_key=$(openssl rand -base64 32)
    local client_public_key=$(echo "$client_private_key" | docker run --rm -i $image awg pubkey 2>/dev/null || echo "$client_private_key" | docker run --rm -i $image wg pubkey)
    
    # Добавляем пира
    docker exec amneziawg awg set awg0 peer "$client_public_key" allowed-ips 10.8.0.2/32
    
    log "Генерация клиентского файла..."
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
    success "AmneziaWG успешно запущен (в режиме userspace)."
}
