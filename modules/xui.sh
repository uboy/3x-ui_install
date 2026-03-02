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
        [[ -n "${PANEL_DIR:-}" ]] || { error "PANEL_DIR не задан"; return 1; }
        ( cd "$PANEL_DIR" && docker compose down -v 2>/dev/null ) || true
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

    # Генерация конфига Docker Compose (без credentials — ставятся через API после старта)
    cat > "${PANEL_DIR}/docker-compose.yml" <<'EOF'
services:
  3x-ui:
    image: ghcr.io/mhsanaei/3x-ui:latest
    container_name: 3x-ui
    volumes:
      - ./db:/etc/x-ui
      - ./cert:/root/cert
    restart: unless-stopped
    network_mode: host
EOF

    ( cd "$PANEL_DIR" && docker compose up -d )

    log "Ожидание готовности панели (макс. 120 сек)..."
    local attempts=0
    while (( attempts < 60 )); do
        if curl -sf --max-time 2 "http://127.0.0.1:${PORT_XUI_PANEL:-2053}/" >/dev/null 2>&1; then
            break
        fi
        # Быстрый выход если контейнер упал
        local cstate
        cstate=$(docker inspect --format '{{.State.Status}}' 3x-ui 2>/dev/null || true)
        if [[ "$cstate" == "exited" || "$cstate" == "dead" ]]; then
            error "Контейнер 3x-ui упал (State: ${cstate}). Логи:"
            docker logs 3x-ui --tail=30
            return 1
        fi
        (( attempts++ )) || true
        [[ $(( attempts % 10 )) -eq 0 ]] && log "Ожидание... (попытка ${attempts}/60)"
        sleep 2
    done
    if (( attempts >= 60 )); then
        error "Панель 3x-ui не ответила за 120 секунд. Логи:"
        docker logs 3x-ui --tail=30
        return 1
    fi
}

module_xui_configure() {
    [[ "$INSTALL_XUI" == "true" ]] || return 0

    log "Настройка параметров 3x-ui через API..."
    local panel_url="http://127.0.0.1:${PORT_XUI_PANEL:-2053}"

    # Сначала пробуем уже сгенерированные учётные данные (повторный запуск скрипта)
    if ! xui_api_login "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASS" "$panel_url"; then
        # Первый запуск — панель стартует с дефолтными admin/admin
        log "Вход с дефолтными учетными данными (admin/admin)..."
        if ! xui_api_login "admin" "admin" "$panel_url"; then
            error "Не удалось войти в панель ни с предустановленными, ни с дефолтными учетными данными."
            return 1
        fi
        log "Замена дефолтных учетных данных на сгенерированные..."
        if ! xui_api_update_user "admin" "admin" "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASS" "$panel_url"; then
            error "Не удалось обновить учетные данные панели."
            return 1
        fi
        # Проверяем новые данные
        if ! xui_api_login "$PANEL_ADMIN_USER" "$PANEL_ADMIN_PASS" "$panel_url"; then
            error "Новые учетные данные не приняты панелью."
            return 1
        fi
    fi
    success "Аутентификация в панели успешна (пользователь: $PANEL_ADMIN_USER)."
    save_install_state

    if [[ "${AUTO_CREATE_INBOUND:-true}" == "true" ]]; then
        log "Создание автоматического VLESS Reality инбаунда..."
        local client_id
        client_id=$(generate_uuid)

        # Generate valid X25519 key pair for VLESS Reality via xray binary in container
        local x25519_out pk sid
        x25519_out=$(docker exec 3x-ui xray x25519 2>/dev/null) || x25519_out=""
        if [[ -n "$x25519_out" ]]; then
            pk=$(printf '%s' "$x25519_out" | awk '/Private key:/{print $NF}')
        else
            warn "xray x25519 недоступен, используем случайный ключ (Reality может не работать)"
            pk=$(generate_random_fixed 43 'a-zA-Z0-9_-' false)
        fi
        sid=$(generate_random_fixed 8 '0-9a-f' true)

        local settings stream_settings
        settings=$(jq -cn \
            --arg id "$client_id" \
            --arg email "${VPN_USER:-vpn}@${DOMAIN}" \
            '{clients:[{id:$id,email:$email,totalGB:0,expiryTime:0,enable:true}]}')
        stream_settings=$(jq -cn \
            --arg pk "$pk" \
            --arg sid "$sid" \
            '{network:"tcp",security:"reality",realitySettings:{show:false,dest:"google.com:443",serverNames:["google.com"],privateKey:$pk,shortIds:[$sid]}}')

        if xui_api_add_inbound "Aegis_VLESS_Reality" "${PORT_XUI_REALITY:-443}" "vless" "$settings" "$stream_settings" "$panel_url"; then
            success "Инбаунд Aegis_VLESS_Reality создан на порту ${PORT_XUI_REALITY:-443}."
            firewall_allow "${PORT_XUI_REALITY:-443}"
        fi
    fi
}
