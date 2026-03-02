#!/usr/bin/env bash

module_openvpn_install() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0

    local ovpn_dir="/opt/dockovpn"
    local data_dir="/root/dockovpn_data"
    local ovpn_port="${PORT_OPENVPN:-1194}"

    # ── Detect existing installation ────────────────────────────────────────
    local _existing=false
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^dockovpn$"; then
        _existing=true
    fi
    # Also detect legacy native install
    if [[ "$_existing" == "false" ]] && \
       { systemctl is-active --quiet openvpn@server 2>/dev/null || [[ -f /etc/openvpn/server.conf ]]; }; then
        _existing=true
    fi

    if [[ "$_existing" == "true" ]]; then
        if ! ui_ask_reinstall "OpenVPN (DockOVPN)"; then
            log "Пропуск установки OpenVPN."
            INSTALL_OPENVPN="skipped"
            return 0
        fi
        log "Очистка старой установки OpenVPN..."
        [[ -f "${ovpn_dir}/docker-compose.yml" ]] && \
            ( cd "$ovpn_dir" && docker compose down -v 2>/dev/null ) || true
        docker rm -f dockovpn 2>/dev/null || true
        rm -rf "$ovpn_dir" "$data_dir"
        # Native cleanup
        systemctl stop openvpn@server 2>/dev/null || true
        systemctl disable openvpn@server 2>/dev/null || true
        rm -rf /etc/openvpn/easy-rsa
        rm -f /etc/openvpn/server.conf /etc/openvpn/ta.key
    fi

    log "Установка OpenVPN (DockOVPN)..."
    mkdir -p "$ovpn_dir" "$data_dir"
    mkdir -p /etc/openvpn

    local http_port=38080
    while ! check_port_free "$http_port"; do
        (( http_port++ ))
    done

    cat > "${ovpn_dir}/docker-compose.yml" <<EOF
services:
  dockovpn:
    image: alekslitvinenk/openvpn
    container_name: dockovpn
    cap_add:
      - NET_ADMIN
    privileged: true
    restart: always
    environment:
      - HOST_ADDR=${DOMAIN}
    ports:
      - "${ovpn_port}:1194/udp"
      - "127.0.0.1:${http_port}:8080/tcp"
    volumes:
      - ${data_dir}:/opt/Dockovpn_data
EOF

    ( cd "$ovpn_dir" && docker compose up -d )

    # ── Download .ovpn: health-check and download in one loop ───────────────
    # DockOVPN's HTTP server serves the .ovpn ONCE then shuts down —
    # a separate health-check curl would consume the file and discard it.
    # Solution: attempt the real download on every iteration; save on success.
    local ovpn_out="/etc/openvpn/${VPN_USER:-vpnuser}.ovpn"
    local attempts=0
    local downloaded=false
    log "Ожидание и загрузка конфигурации DockOVPN (макс. 60 сек)..."
    while (( attempts < 30 )); do
        if curl -sf --max-time 10 "http://127.0.0.1:${http_port}/" -o "$ovpn_out" 2>/dev/null \
           && [[ -s "$ovpn_out" ]]; then
            downloaded=true
            break
        fi
        local cstate
        cstate=$(docker inspect --format '{{.State.Status}}' dockovpn 2>/dev/null || true)
        if [[ "$cstate" == "exited" || "$cstate" == "dead" ]]; then
            error "Контейнер DockOVPN упал (State: ${cstate}). Логи:"
            docker logs dockovpn --tail=30
            return 1
        fi
        (( attempts++ )) || true
        sleep 2
    done

    if [[ "$downloaded" != "true" ]]; then
        error "DockOVPN не отдал .ovpn за 60 секунд. Логи:"
        docker logs dockovpn --tail=30
        return 1
    fi
    chmod 600 "$ovpn_out"

    if [[ -n "${NEW_USER:-}" ]] && [[ -d "/home/${NEW_USER}" ]]; then
        cp "$ovpn_out" "/home/${NEW_USER}/${VPN_USER:-vpnuser}.ovpn"
        chown "${NEW_USER}:${NEW_USER}" "/home/${NEW_USER}/${VPN_USER:-vpnuser}.ovpn"
        chmod 600 "/home/${NEW_USER}/${VPN_USER:-vpnuser}.ovpn"
        log "Копия .ovpn: /home/${NEW_USER}/${VPN_USER:-vpnuser}.ovpn"
    fi

    # DockOVPN работает в Docker: VPN-подсеть (10.8.0.0/24) находится внутри
    # контейнера и HOST её не видит напрямую. NAT для 10.8.0.x делает сам
    # контейнер (10.8.0.x → 172.17.0.2), а NAT для Docker bridge добавляется
    # автоматически через firewall_configure_nat при установке других модулей
    # или при наличии docker0. Здесь нужно только открыть порт.
    firewall_allow "${ovpn_port}" udp
    success "OpenVPN (DockOVPN) установлен и запущен на порту ${ovpn_port}/UDP."

    echo ""
    echo "====== .ovpn (base64) — скопируйте всё между линиями ======"
    base64 "$ovpn_out"
    echo "============================================================"
    echo "Декодирование на Windows (PowerShell):"
    echo "  \$b64 = '<вставьте base64 одной строкой>'"
    echo "  [System.Convert]::FromBase64String(\$b64) | Set-Content -Path vpnuser.ovpn -Encoding Byte"
    echo ""
}

module_openvpn_configure() {
    # DockOVPN generates the client config automatically on first start.
    # The .ovpn is downloaded during module_openvpn_install.
    return 0
}
