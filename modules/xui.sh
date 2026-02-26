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
      - X_UI_ADMIN_USER=${PANEL_ADMIN_USER:-admin}
      - X_UI_ADMIN_PWD=${PANEL_ADMIN_PASS:-admin}
    restart: unless-stopped
    network_mode: host
EOF

    cd "$PANEL_DIR"
    docker compose up -d
    
    log "Ожидание готовности панели..."
    sleep 5
}

module_xui_configure() {
    [[ "$INSTALL_XUI" == "true" ]] || return 0
    
    log "Настройка параметров 3x-ui через API..."
    local panel_url="http://127.0.0.1:2053"
    
    if xui_api_login "admin" "admin" "$panel_url"; then
        log "Смена стандартных учетных данных администратора..."
        local new_user="${PANEL_ADMIN_USER:-admin_$(generate_random_fixed 5 'a-z0-9' true)}"
        local new_pass="${PANEL_ADMIN_PASS:-$(generate_strong_secret)}"
        
        if xui_api_update_user "admin" "admin" "$new_user" "$new_pass" "$panel_url"; then
            success "Администратор панели изменен на: $new_user"
            PANEL_ADMIN_USER="$new_user"
            PANEL_ADMIN_PASS="$new_pass"
            save_install_state
        fi
    fi

    if [[ "${AUTO_CREATE_INBOUND:-true}" == "true" ]]; then
        log "Создание автоматического VLESS Reality инбаунда..."
        local client_id=$(generate_uuid)
        local settings="{\"clients\":[{\"id\":\"$client_id\",\"email\":\"${VPN_USER:-vpn}@$DOMAIN\",\"totalGB\":0,\"expiryTime\":0,\"enable\":true}]}"
        local stream_settings="{\"network\":\"tcp\",\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"google.com:443\",\"serverNames\":[\"google.com\"],\"privateKey\":\"$(generate_random_fixed 32 'a-zA-Z0-9' false)\",\"shortIds\":[\"$(generate_random_fixed 8 '0-9a-f' true)\"]}}"
        
        if xui_api_add_inbound "Aegis_VLESS_Reality" "443" "vless" "$settings" "$stream_settings" "$panel_url"; then
            success "Инбаунд Aegis_VLESS_Reality создан на порту 443."
            firewall_allow 443
        fi
    fi
}
