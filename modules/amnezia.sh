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

    log "Установка AmneziaWG (Aegis Edition)..."
    mkdir -p "$AMN_DIR"
    
    local image="amneziavpn/amnezia-wg"
    
    log "Генерация ключей..."
    local private_key=$(openssl rand -base64 32)
    # Прямая попытка получить публичный ключ
    local public_key=$(echo "$private_key" | docker run --rm -i --entrypoint "/usr/bin/awg" $image pubkey 2>/dev/null || echo "$private_key" | docker run --rm -i --entrypoint "/usr/bin/wg" $image pubkey)
    
    if [[ -z "$public_key" ]]; then
        error "Не удалось сгенерировать ключи. Образ $image не отвечает."
        return 1
    fi

    log "Создание конфигурации..."
    cat > "${AMN_DIR}/amneziawg.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.8.0.1/24
ListenPort = 51820
J1 = $(shuf -i 10-100 -n 1)
J2 = $(shuf -i 10-100 -n 1)
S1 = $(shuf -i 10-100 -n 1)
S2 = $(shuf -i 10-100 -n 1)
H1 = $(shuf -i 10000000-99999999 -n 1)
H2 = $(shuf -i 10000000-99999999 -n 1)
H3 = $(shuf -i 10000000-99999999 -n 1)
H4 = $(shuf -i 10000000-99999999 -n 1)
EOF

    # Создаем Docker Compose
    # Мы используем команду, которая сначала подменяет wg на awg, а потом запускает стандартный wg-quick
    cat > "${AMN_DIR}/docker-compose.yml" <<EOF
services:
  amneziawg:
    image: $image
    container_name: amneziawg
    privileged: true
    volumes:
      - ./amneziawg.conf:/etc/wireguard/wg0.conf
    entrypoint: >
      /bin/sh -c "
      [ -f /usr/bin/awg ] && ln -sf /usr/bin/awg /usr/bin/wg;
      [ -f /usr/bin/awg-quick ] && ln -sf /usr/bin/awg-quick /usr/bin/wg-quick;
      wg-quick up wg0;
      tail -f /dev/null
      "
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
EOF

    log "Запуск контейнера..."
    cd "$AMN_DIR"
    docker compose up -d
    
    log "Ожидание (15 сек)..."
    sleep 15

    if ! docker ps --format '{{.Names}} {{.Status}}' | grep "amneziawg" | grep -q "Up"; then
        error "Контейнер упал. Логи:"
        docker logs amneziawg
        return 1
    fi

    log "Создание клиента..."
    local client_private_key=$(openssl rand -base64 32)
    local client_public_key=$(echo "$client_private_key" | docker run --rm -i --entrypoint "/usr/bin/awg" $image pubkey 2>/dev/null || echo "$client_private_key" | docker run --rm -i --entrypoint "/usr/bin/wg" $image pubkey)
    
    # Регистрация пира
    docker exec amneziawg sh -c "wg set wg0 peer $client_public_key allowed-ips 10.8.0.2/32"
    
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
    success "AmneziaWG успешно настроен."
}
