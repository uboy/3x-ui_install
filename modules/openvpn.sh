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
    # ovpn_genconfig уже добавляет: dhcp-option DNS, block-outside-dns, redirect-gateway def1
    # НЕ дублируем их вручную — это вызовет конфликт маршрутов
    docker run -v "$OVPN_DIR:/etc/openvpn" --rm kylemanna/openvpn ovpn_genconfig -u "udp://$DOMAIN" -n 8.8.8.8 -n 1.1.1.1

    # Добавляем пользовательские исключения маршрутов (split-tunnel для кастомных сетей)
    # ВАЖНО: net_gateway маршруты работают только при полном туннеле (redirect-gateway def1)
    # и означают "эту сеть NOT через VPN, а через локальный шлюз"
    if [[ -n "${VPN_EXCLUDE_ROUTES:-}" ]]; then
        log "Добавление пользовательских исключений маршрутов..."
        {
            IFS=',' read -ra _exclude_addrs <<< "$VPN_EXCLUDE_ROUTES"
            for _cidr in "${_exclude_addrs[@]}"; do
                _cidr="${_cidr// /}"  # trim spaces
                [[ -z "$_cidr" ]] && continue
                local _ip _prefix _mask _a _b _c _d
                _ip="${_cidr%%/*}"
                _prefix="${_cidr##*/}"
                # Convert prefix length to dotted-decimal netmask
                _mask=$(python3 -c "import ipaddress; print(str(ipaddress.IPv4Network('0.0.0.0/${_prefix}').netmask))" 2>/dev/null) || {
                    warn "Не удалось вычислить маску для ${_cidr}, пропускаем"
                    continue
                }
                echo "push \"route ${_ip} ${_mask} net_gateway\""
            done
        } >> "$OVPN_DIR/openvpn.conf"
    fi

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
