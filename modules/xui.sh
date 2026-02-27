#!/usr/bin/env bash

# Подключаем API библиотеку внутри модуля если она еще не подключена
source "${SCRIPT_DIR}/lib/xui_api.sh"

module_xui_install() {
    [[ "$INSTALL_XUI" == "true" ]] || return 0
    
    PANEL_DIR="${PANEL_DIR:-/opt/3x-ui}"

    # Детекция существующей установки
    if docker ps -a --format '{{.Names}}' | grep -q "^3x-ui$"; then
        if ! ui_ask_reinstall "3x-ui Panel"; then
            log "Пропуск установки 3x-ui по желанию пользователя."
            INSTALL_XUI="skipped"
            return 0
        fi
        log "Очистка старой установки 3x-ui..."
        cd "$PANEL_DIR" && docker compose down -v 2>/dev/null || true
        rm -rf "$PANEL_DIR"
    fi

    log "Установка 3x-ui (через Docker)..."
    mkdir -p "$PANEL_DIR/db" "$PANEL_DIR/cert"

    # Generate credentials BEFORE writing docker-compose to avoid admin:admin window
    local new_user new_pass
    new_user="${PANEL_ADMIN_USER:-admin_$(generate_random_fixed 5 'a-z0-9' true)}"
    new_pass="${PANEL_ADMIN_PASS:-$(generate_strong_secret)}"
    PANEL_ADMIN_USER="$new_user"
    PANEL_ADMIN_PASS="$new_pass"

    # Генерация конфига Docker Compose
    cat > "${PANEL_DIR}/docker-compose.yml" <<EOF
services:
  3x-ui:
    image: ghcr.io/mhsanaei/3x-ui:latest
    container_name: 3x-ui
    volumes:
      - ./db:/etc/x-ui
      - ./cert:/root/cert
    environment:
      - X_UI_ADMIN_USER=${new_user}
      - X_UI_ADMIN_PWD=${new_pass}
    restart: unless-stopped
    network_mode: host
EOF

    cd "$PANEL_DIR"
    docker compose up -d

    log "Ожидание готовности панели..."
    local attempts=0
    until curl -sf --max-time 2 "http://127.0.0.1:2053/" >/dev/null 2>&1 || (( ++attempts >= 30 )); do
        sleep 2
    done
    if (( attempts >= 30 )); then
        error "Панель 3x-ui не ответила за 60 секунд"
        docker logs 3x-ui | tail -20
        return 1
    fi
}

module_xui_configure() {
    [[ "$INSTALL_XUI" == "true" ]] || return 0

    log "Настройка параметров 3x-ui через API..."
    local panel_url="http://127.0.0.1:2053"

    # Login with pre-generated credentials (set during module_xui_install)
    if xui_api_login "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASS" "$panel_url"; then
        success "Аутентификация в панели успешна (пользователь: $PANEL_ADMIN_USER)."
        save_install_state
    else
        error "Не удалось войти в панель с предустановленными учетными данными."
        return 1
    fi

    if [[ "${AUTO_CREATE_INBOUND:-true}" == "true" ]]; then
        log "Создание автоматического VLESS Reality инбаунда..."
        local client_id
        client_id=$(generate_uuid)
        local settings stream_settings
        settings=$(jq -cn \
            --arg id "$client_id" \
            --arg email "${VPN_USER:-vpn}@${DOMAIN}" \
            '{clients:[{id:$id,email:$email,totalGB:0,expiryTime:0,enable:true}]}')
        stream_settings=$(jq -cn \
            --arg pk "$(generate_random_fixed 32 'a-zA-Z0-9' false)" \
            --arg sid "$(generate_random_fixed 8 '0-9a-f' true)" \
            '{network:"tcp",security:"reality",realitySettings:{show:false,dest:"google.com:443",serverNames:["google.com"],privateKey:$pk,shortIds:[$sid]}}')

        if xui_api_add_inbound "Aegis_VLESS_Reality" "443" "vless" "$settings" "$stream_settings" "$panel_url"; then
            success "Инбаунд Aegis_VLESS_Reality создан на порту 443."
            firewall_allow 443
        fi
    fi
}
