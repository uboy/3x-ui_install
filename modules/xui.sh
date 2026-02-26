#!/usr/bin/env bash

# Подключаем API библиотеку внутри модуля если она еще не подключена
source "${SCRIPT_DIR}/lib/xui_api.sh"

module_xui_install() {
    [[ "$INSTALL_XUI" == "true" ]] || return 0
    
    log "Установка 3x-ui (через Docker)..."
    
    # Подготовка директорий
    PANEL_DIR="${PANEL_DIR:-/opt/3x-ui}"
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
    
    log "Настройка 3x-ui через API..."
    
    local panel_url="http://127.0.0.1:2053"
    
    # 1. Попытка входа с дефолтными кредами или новыми
    if xui_api_login "admin" "admin" "$panel_url"; then
        # Если вошли с дефолтными - меняем на сгенерированные
        local new_user="${PANEL_ADMIN_USER:-admin_$(generate_random_fixed 5 'a-z0-9' true)}"
        local new_pass="${PANEL_ADMIN_PASS:-$(generate_strong_secret)}"
        
        if xui_api_update_user "admin" "admin" "$new_user" "$new_pass" "$panel_url"; then
            success "Администратор панели обновлен: $new_user"
            PANEL_ADMIN_USER="$new_user"
            PANEL_ADMIN_PASS="$new_pass"
            save_install_state
        fi
    fi

    # 2. Если включено авто-создание входящего подключения
    if [[ "${AUTO_CREATE_INBOUND:-true}" == "true" ]]; then
        local client_id=$(generate_uuid)
        local settings="{\"clients\":[{\"id\":\"$client_id\",\"email\":\"default@$DOMAIN\",\"totalGB\":0,\"expiryTime\":0,\"enable\":true}]}"
        
        # Настройка Reality (базовый пример)
        local stream_settings="{\"network\":\"tcp\",\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"google.com:443\",\"serverNames\":[\"google.com\"],\"privateKey\":\"$(generate_random_fixed 32 'a-zA-Z0-9' false)\",\"shortIds\":[\"$(generate_random_fixed 8 '0-9a-f' true)\"]}}"
        
        if xui_api_add_inbound "VLESS_REALITY_DEFAULT" "443" "vless" "$settings" "$stream_settings" "$panel_url"; then
            success "Создано дефолтное Reality подключение на порту 443."
            firewall_allow 443
        fi
    fi
}
