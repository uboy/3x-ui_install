#!/usr/bin/env bash

module_amnezia_install() {
    [[ "$INSTALL_AMNEZIA" == "true" ]] || return 0
    
    AMN_DIR="/opt/amnezia"

    # Очистка
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

    log "Установка AmneziaWG (Aegis Multi-Image Loader)..."
    mkdir -p "$AMN_DIR"
    
    # Список образов для перебора (от самого надежного к запасному)
    local images=("nikolaydyadya/amnezia-wg:latest" "amneziavpn/amnezia-wg:master" "pantonis/amnezia-wg:latest")
    local working_image=""

    for img in "${images[@]}"; do
        log "Попытка использовать образ: $img..."
        # Skip pull if image is already cached locally
        if ! docker image inspect "$img" >/dev/null 2>&1; then
            docker pull "$img" || { warn "Не удалось загрузить образ $img"; continue; }
        fi
        if docker run --rm "$img" which awg >/dev/null 2>&1; then
            working_image="$img"
            success "Найден рабочий образ AmneziaWG: $img"
            break
        fi
        warn "Образ $img не подходит или не доступен."
    done

    if [[ -z "$working_image" ]]; then
        error "Не удалось найти рабочий Docker-образ AmneziaWG. Проверьте интернет или доступ к Docker Hub."
        return 1
    fi

    log "Генерация ключей..."
    local private_key
    private_key=$(docker run --rm --entrypoint "awg" "$working_image" genkey)
    local public_key
    public_key=$(printf '%s' "$private_key" | docker run --rm -i --entrypoint "awg" "$working_image" pubkey)
    
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
    chmod 600 "${AMN_DIR}/amneziawg.conf"

    # Docker Compose
    cat > "${AMN_DIR}/docker-compose.yml" <<EOF
services:
  amneziawg:
    image: $working_image
    container_name: amneziawg
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    volumes:
      - ./amneziawg.conf:/etc/wireguard/wg0.conf
    # Используем awg-quick для запуска
    entrypoint: /bin/sh -c "awg-quick up wg0 && tail -f /dev/null"
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
EOF

    log "Запуск контейнера..."
    cd "$AMN_DIR"
    docker compose up -d
    
    log "Ожидание инициализации (10 сек)..."
    sleep 10

    if ! docker ps --format '{{.Names}} {{.Status}}' | grep "amneziawg" | grep -q "Up"; then
        error "Контейнер упал. Логи:"
        docker logs amneziawg
        return 1
    fi

    log "Создание клиента..."
    local client_private_key
    client_private_key=$(docker run --rm --entrypoint "awg" "$working_image" genkey)
    local client_public_key
    client_public_key=$(printf '%s' "$client_private_key" | docker run --rm -i --entrypoint "awg" "$working_image" pubkey)
    
    # Добавление пира через awg
    docker exec amneziawg awg set wg0 peer "$client_public_key" allowed-ips 10.8.0.2/32
    
    log "Генерация amnezia_client.conf..."
    cat > "${AMN_DIR}/amnezia_client.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = 10.8.0.2/24
DNS = 1.1.1.1
J1 = $(grep "^J1" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)
J2 = $(grep "^J2" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)
S1 = $(grep "^S1" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)
S2 = $(grep "^S2" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)
H1 = $(grep "^H1" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)
H2 = $(grep "^H2" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)
H3 = $(grep "^H3" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)
H4 = $(grep "^H4" "${AMN_DIR}/amneziawg.conf" | cut -d' ' -f3)

[Peer]
PublicKey = $public_key
Endpoint = $DOMAIN:51820
AllowedIPs = 0.0.0.0/0
EOF

    firewall_allow 51820 udp
    success "AmneziaWG успешно настроен на базе образа ${working_image}."
}
