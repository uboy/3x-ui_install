#!/usr/bin/env bash

# Библиотека для работы с whiptail (стандартное меню в Ubuntu)
# ANSI constants are defined in common.sh (sourced before this file)

ui_banner() {
    clear
    cat << "EOF"
    ___              _      _   __ ____  _   __
   /   | ___  ____ _(_)____| | / // __ \/ | / /
  / /| |/ _ \/ __ `/ / ___/| |/ // /_/ /  |/ /
 / ___ /  __/ /_/ / (__  ) |  // ____/ /|  /
/_/  |_\___/\__, /_/____/  |_//_/   /_/ |_/
           /____/     VPN TOOLBOX
EOF
    printf "${BLUE}${BOLD}      --- Aegis VPN Toolbox ---${NC}\n"
}

ui_select_components() {
    local choices
    choices=$(whiptail --title "Aegis VPN Toolbox - Выбор" --checklist \
    "Выберите компоненты для установки (Пробел - выбор, Enter - подтверждение):" 20 70 10 \
    "XUI" "3x-ui Panel (Xray/VLESS/Reality)" ON \
    "OpenVPN" "Классический OpenVPN сервер" OFF \
    "OpenConnect" "Cisco AnyConnect совместимый VPN" OFF \
    "AmneziaWG" "AmneziaWG (обфусцированный WireGuard)" OFF \
    "Dumbproxy" "HTTP/HTTPS прокси-сервер с авторизацией" OFF 3>&1 1>&2 2>&3) || exit 0

    # Сбрасываем флаги
    INSTALL_XUI="false"
    INSTALL_OPENVPN="false"
    INSTALL_OPENCONNECT="false"
    INSTALL_AMNEZIA="false"
    INSTALL_DUMBPROXY="false"

    for choice in $choices; do
        case $choice in
            "\"XUI\"") INSTALL_XUI="true" ;;
            "\"OpenVPN\"") INSTALL_OPENVPN="true" ;;
            "\"OpenConnect\"") INSTALL_OPENCONNECT="true" ;;
            "\"AmneziaWG\"") INSTALL_AMNEZIA="true" ;;
            "\"Dumbproxy\"") INSTALL_DUMBPROXY="true" ;;
        esac
    done

    # Если ничего не выбрано - выходим
    if [[ "$INSTALL_XUI" == "false" && "$INSTALL_OPENVPN" == "false" && "$INSTALL_OPENCONNECT" == "false" && "$INSTALL_AMNEZIA" == "false" && "$INSTALL_DUMBPROXY" == "false" ]]; then
        whiptail --title "Ошибка" --msgbox "Ничего не выбрано. Установка отменена." 10 60
        exit 0
    fi
}

ui_get_basic_info() {
    # DOMAIN — loop until valid
    while true; do
        DOMAIN=$(whiptail --title "Настройка Aegis" --inputbox "Введите домен или IP адрес сервера:" 10 60 "${DOMAIN:-}" 3>&1 1>&2 2>&3) || exit 0
        if is_valid_domain "$DOMAIN"; then
            break
        fi
        whiptail --title "Ошибка" --msgbox "Некорректный домен или IP: '${DOMAIN}'\nПример: example.com или 1.2.3.4" 10 60
    done

    # EMAIL — required only for XUI or OpenConnect (Let's Encrypt)
    if [[ "${INSTALL_XUI:-false}" == "true" || "${INSTALL_OPENCONNECT:-false}" == "true" ]]; then
        while true; do
            EMAIL=$(whiptail --title "Настройка Email" --inputbox "Введите Email для Let's Encrypt:" 10 60 "${EMAIL:-}" 3>&1 1>&2 2>&3) || exit 0
            if is_valid_email "$EMAIL"; then
                break
            fi
            whiptail --title "Ошибка" --msgbox "Некорректный email: '${EMAIL}'\nПример: user@example.com" 10 60
        done
    fi

    # VPN_USER — loop until valid
    while true; do
        VPN_USER=$(whiptail --title "VPN Пользователь" --inputbox "Введите имя пользователя для VPN (OpenConnect/OpenVPN):" 10 60 "${VPN_USER:-vpnuser}" 3>&1 1>&2 2>&3) || exit 0
        if is_valid_username "$VPN_USER"; then
            break
        fi
        whiptail --title "Ошибка" --msgbox "Некорректное имя пользователя: '${VPN_USER}'\nДопустимо: строчные буквы, цифры, _ и - (начало: буква или _). Макс. 32 символа." 12 60
    done

    # VPN_PASS — enforce minimum 12 chars if entered manually
    while true; do
        VPN_PASS=$(whiptail --title "VPN Пароль" --passwordbox "Введите пароль для VPN (оставьте пустым для автогенерации, мин. 12 символов):" 10 60 3>&1 1>&2 2>&3) || exit 0
        if [[ -z "${VPN_PASS:-}" ]]; then
            VPN_PASS=$(generate_strong_secret)
            break
        elif (( ${#VPN_PASS} >= 12 )); then
            break
        fi
        whiptail --title "Ошибка" --msgbox "Пароль слишком короткий. Минимум 12 символов, либо оставьте пустым для автогенерации." 10 60
    done

    # VPN_EXCLUDE_ROUTES — validate each CIDR token
    while true; do
        VPN_EXCLUDE_ROUTES=$(whiptail --title "Исключения маршрутов" --inputbox "Введите через запятую сети для исключения из VPN (напр. 1.1.1.1/32, 10.0.0.0/8). По умолчанию 192.168.0.0/16 уже исключена." 12 60 "${VPN_EXCLUDE_ROUTES:-}" 3>&1 1>&2 2>&3) || exit 0
        if [[ -z "${VPN_EXCLUDE_ROUTES:-}" ]]; then
            break
        fi
        local _bad_cidr="" _cidr_token=""
        IFS=',' read -ra _cidr_tokens <<< "$VPN_EXCLUDE_ROUTES"
        for _cidr_token in "${_cidr_tokens[@]}"; do
            _cidr_token="${_cidr_token// /}"  # trim spaces
            [[ -z "$_cidr_token" ]] && continue
            if ! is_valid_cidr "$_cidr_token"; then
                _bad_cidr="$_cidr_token"
                break
            fi
        done
        if [[ -z "$_bad_cidr" ]]; then
            break
        fi
        whiptail --title "Ошибка" --msgbox "Некорректный CIDR: '${_bad_cidr}'\nПример: 10.0.0.0/8" 10 60
    done

    save_install_state
}

ui_get_hardening_info() {
    # Outer loop: cancel on any sub-dialog brings back to the yes/no question
    while true; do
        if ! whiptail --title "Харденинг системы" --yesno \
            "Включить усиленную защиту сервера?\n\n  • Создание нового sudo-пользователя\n  • Запрет SSH-логина под root\n  • Смена порта SSH\n\nРекомендуется для production-серверов." \
            15 70; then
            INSTALL_MODE="simple"
            return 0
        fi
        INSTALL_MODE="super-secure"

        # --- Новый администратор ---
        local _user _user_ok=false
        while true; do
            if ! _user=$(whiptail --title "Новый sudo-пользователь" \
                --inputbox "Имя нового администратора:" \
                10 60 "${NEW_USER:-vpnadmin}" 3>&1 1>&2 2>&3); then
                break  # Cancel → back to yes/no
            fi
            if is_valid_username "$_user"; then
                NEW_USER="$_user"
                _user_ok=true
                break
            fi
            whiptail --title "Ошибка" --msgbox \
                "Некорректное имя: '${_user}'\nДопустимо: строчные буквы, цифры, _ и - (начало: буква или _). Макс. 32 символа." \
                12 60
        done
        [[ "$_user_ok" == "true" ]] || continue

        # --- Пароль администратора ---
        local _pass _pass_ok=false
        while true; do
            if ! _pass=$(whiptail --title "Пароль администратора" \
                --passwordbox "Пароль для ${NEW_USER} (мин. 12 символов, пусто = автогенерация):" \
                10 60 3>&1 1>&2 2>&3); then
                break  # Cancel → back to yes/no
            fi
            if [[ -z "${_pass:-}" ]]; then
                if [[ -z "${NEW_PASS:-}" ]]; then
                    NEW_PASS=$(generate_strong_secret)
                fi
                _pass_ok=true
                break
            elif (( ${#_pass} >= 12 )); then
                NEW_PASS="$_pass"
                _pass_ok=true
                break
            fi
            whiptail --title "Ошибка" --msgbox "Пароль слишком короткий. Минимум 12 символов." 10 60
        done
        [[ "$_pass_ok" == "true" ]] || continue

        # --- Порт SSH ---
        local _port _port_ok=false
        while true; do
            if ! _port=$(whiptail --title "Порт SSH" \
                --inputbox "Новый порт SSH (1-65535, текущий: ${SSH_PORT:-22}):" \
                10 60 "${SSH_PORT:-22}" 3>&1 1>&2 2>&3); then
                break  # Cancel → back to yes/no
            fi
            if [[ "$_port" =~ ^[0-9]+$ ]] && (( _port >= 1 && _port <= 65535 )); then
                SSH_PORT="$_port"
                _port_ok=true
                break
            fi
            whiptail --title "Ошибка" --msgbox "Некорректный порт: '${_port}'. Диапазон: 1-65535." 10 60
        done
        [[ "$_port_ok" == "true" ]] || continue

        return 0
    done
}

ui_get_ports() {
    local _labels=()
    local _vars=()
    local _defaults=()

    [[ "${INSTALL_XUI:-false}" == "true" ]] && {
        _labels+=("Порт панели 3x-ui:")
        _vars+=(PORT_XUI_PANEL)
        _defaults+=("${PORT_XUI_PANEL:-2053}")
        _labels+=("Порт VLESS Reality:")
        _vars+=(PORT_XUI_REALITY)
        _defaults+=("${PORT_XUI_REALITY:-443}")
    }
    [[ "${INSTALL_OPENVPN:-false}" == "true" ]] && {
        _labels+=("Порт OpenVPN (UDP):")
        _vars+=(PORT_OPENVPN)
        _defaults+=("${PORT_OPENVPN:-1194}")
    }
    [[ "${INSTALL_OPENCONNECT:-false}" == "true" ]] && {
        _labels+=("Порт OpenConnect:")
        _vars+=(PORT_OPENCONNECT)
        _defaults+=("${PORT_OPENCONNECT:-4443}")
    }
    [[ "${INSTALL_AMNEZIA:-false}" == "true" ]] && {
        _labels+=("Порт AmneziaWG (UDP):")
        _vars+=(PORT_AMNEZIA)
        _defaults+=("${PORT_AMNEZIA:-51820}")
    }
    [[ "${INSTALL_DUMBPROXY:-false}" == "true" ]] && {
        _labels+=("Порт Dumbproxy (TCP):")
        _vars+=(PORT_DUMBPROXY)
        _defaults+=("${PORT_DUMBPROXY:-8080}")
    }

    [[ ${#_vars[@]} -eq 0 ]] && return 0

    while true; do
        # Собираем порты по одному через inputbox (--form не поддерживается надёжно в whiptail)
        local _values=()
        local _cancelled=false
        local i
        for (( i=0; i<${#_labels[@]}; i++ )); do
            local _val
            if ! _val=$(whiptail --title "Настройка портов ($(( i+1 ))/${#_labels[@]})" \
                --inputbox "${_labels[$i]}" \
                8 52 "${_defaults[$i]}" 3>&1 1>&2 2>&3); then
                _cancelled=true
                break
            fi
            _values+=("$_val")
        done

        if [[ "$_cancelled" == "true" ]]; then
            exit 0
        fi

        local _ok=true
        local _err=""
        local j
        # Validate each port number
        for (( j=0; j<${#_vars[@]}; j++ )); do
            local p="${_values[$j]:-}"
            if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
                _ok=false
                _err="Некорректный порт '${p}' для ${_labels[$j]}\nДиапазон: 1-65535."
                break
            fi
        done

        # Check for duplicates among service ports
        if [[ "$_ok" == "true" ]]; then
            declare -A _port_seen=()
            for (( j=0; j<${#_vars[@]}; j++ )); do
                local p="${_values[$j]}"
                if [[ -n "${_port_seen[$p]+x}" ]]; then
                    _ok=false
                    _err="Конфликт: порт $p используется для '${_port_seen[$p]}' и '${_labels[$j]}'.\nКаждый сервис должен иметь уникальный порт."
                    break
                fi
                _port_seen[$p]="${_labels[$j]}"
            done
        fi

        # Check collision with SSH port
        if [[ "$_ok" == "true" ]]; then
            for (( j=0; j<${#_vars[@]}; j++ )); do
                if [[ "${_values[$j]}" == "${SSH_PORT:-22}" ]]; then
                    _ok=false
                    _err="Конфликт: порт ${_values[$j]} (${_labels[$j]}) совпадает с портом SSH (${SSH_PORT:-22})."
                    break
                fi
            done
        fi

        if [[ "$_ok" == "true" ]]; then
            for (( j=0; j<${#_vars[@]}; j++ )); do
                printf -v "${_vars[$j]}" '%s' "${_values[$j]}"
            done
            save_install_state
            return 0
        fi

        whiptail --title "Ошибка" --msgbox "$_err" 10 65
        # Preserve user-entered values as new defaults for retry
        for (( j=0; j<${#_vars[@]}; j++ )); do
            [[ -n "${_values[$j]:-}" ]] && _defaults[$j]="${_values[$j]}"
        done
    done
}

ui_confirm_install() {
    if whiptail --title "Aegis VPN Toolbox" --yesno "Начать установку выбранных компонентов?" 10 60; then
        return 0
    else
        exit 0
    fi
}

ui_ask_reinstall() {
    local service_name="$1"
    if whiptail --title "Сервис уже установлен" --yesno "Обнаружен уже установленный $service_name. Переустановить и настроить заново?\n\n(Выбор 'No' пропустит этот компонент)" 12 60; then
        return 0 # Reinstall
    else
        return 1 # Skip
    fi
}

ui_final_report() {
    local report=""
    local plain_report=""

    # Формируем отчет
    report="${BOLD}Aegis VPN Toolbox: Установка завершена успешно!${NC}\n"
    report="${report}==============================================\n\n"

    report="${report}${BLUE}${BOLD}--- ОБЩИЕ ДАННЫЕ СЕРВЕРА ---${NC}\n"
    report="${report}Домен/IP: ${DOMAIN}\n"
    if [[ "${INSTALL_MODE:-}" == "super-secure" ]]; then
        report="${report}SSH Пользователь: ${NEW_USER:-root}\n"
        report="${report}SSH Пароль: ${NEW_PASS:-unchanged}\n"
        report="${report}SSH Порт: ${SSH_PORT:-22}\n"
    fi
    report="${report}\n"

    if [[ "$INSTALL_XUI" == "true" ]]; then
        report="${report}${BLUE}${BOLD}--- 3x-ui (Xray Panel) ---${NC}\n"
        report="${report}Панель управления: http://${DOMAIN}:${PORT_XUI_PANEL:-2053}\n"
        report="${report}Логин: ${PANEL_ADMIN_USER:-admin}\n"
        report="${report}Пароль: ${PANEL_ADMIN_PASS:-admin}\n"
        report="${report}VLESS Reality порт: ${PORT_XUI_REALITY:-443}\n\n"
    elif [[ "$INSTALL_XUI" == "skipped" ]]; then
        report="${report}${YELLOW}--- 3x-ui (Пропущено) ---${NC}\n\n"
    fi

    if [[ "$INSTALL_OPENVPN" == "true" ]]; then
        report="${report}${BLUE}${BOLD}--- OpenVPN ---${NC}\n"
        report="${report}Протокол/Порт: UDP / ${PORT_OPENVPN:-1194}\n"
        report="${report}Пользователь: ${VPN_USER:-vpnuser}\n"
        report="${report}Файл конфигурации (.ovpn): /etc/openvpn/${VPN_USER:-vpnuser}.ovpn\n"
        if [[ -n "${NEW_USER:-}" ]] && [[ -d "/home/${NEW_USER}" ]]; then
            report="${report}Доступная копия (SSH): /home/${NEW_USER}/${VPN_USER:-vpnuser}.ovpn\n"
        fi
        report="${report}\n"
    elif [[ "$INSTALL_OPENVPN" == "skipped" ]]; then
        report="${report}${YELLOW}--- OpenVPN (Пропущено) ---${NC}\n\n"
    fi

    if [[ "$INSTALL_OPENCONNECT" == "true" ]]; then
        report="${report}${BLUE}${BOLD}--- OpenConnect (Cisco AnyConnect) ---${NC}\n"
        report="${report}Сервер: ${DOMAIN}:${PORT_OPENCONNECT:-4443}\n"
        report="${report}Пользователь: ${VPN_USER:-vpnuser}\n"
        report="${report}Пароль: ${VPN_PASS}\n\n"
    elif [[ "$INSTALL_OPENCONNECT" == "skipped" ]]; then
        report="${report}${YELLOW}--- OpenConnect (Пропущено) ---${NC}\n\n"
    fi

    if [[ "$INSTALL_AMNEZIA" == "true" ]]; then
        report="${report}${BLUE}${BOLD}--- AmneziaWG ---${NC}\n"
        report="${report}Endpoint: ${DOMAIN}:${PORT_AMNEZIA:-51820}/udp\n"
        report="${report}Конфиг клиента: /opt/amnezia/amnezia_client.conf\n"
        if [[ -n "${NEW_USER:-}" ]] && [[ -d "/home/${NEW_USER}" ]]; then
            report="${report}Копия (SSH): /home/${NEW_USER}/amnezia_client.conf\n"
        fi
        report="${report}\n"
    elif [[ "$INSTALL_AMNEZIA" == "skipped" ]]; then
        report="${report}${YELLOW}--- AmneziaWG (Пропущено) ---${NC}\n\n"
    fi

    if [[ "$INSTALL_DUMBPROXY" == "true" ]]; then
        report="${report}${BLUE}${BOLD}--- Dumbproxy (HTTP/HTTPS Proxy) ---${NC}\n"
        report="${report}Адрес: ${DOMAIN}:${PORT_DUMBPROXY:-8080}\n"
        report="${report}Пользователь: ${VPN_USER:-vpnuser}\n"
        report="${report}Пароль: ${VPN_PASS}\n\n"
    elif [[ "$INSTALL_DUMBPROXY" == "skipped" ]]; then
        report="${report}${YELLOW}--- Dumbproxy (Пропущено) ---${NC}\n\n"
    fi

    report="${report}${GREEN}${BOLD}Все пароли сохранены в файле состояния: /root/.aegis-vpn.state${NC}\n"

    # Создаем чистую версию без ANSI кодов для whiptail
    plain_report=$(printf '%s' "$report" | sed 's/\x1b\[[0-9;]*m//g')

    local _rows _cols
    _rows=$(( $(tput lines 2>/dev/null || echo 24) - 4 ))
    _cols=$(( $(tput cols  2>/dev/null || echo 80) - 4 ))
    (( _rows < 20 )) && _rows=20
    (( _cols < 70 )) && _cols=70
    whiptail --title "Aegis VPN Toolbox - Итоги" --scrolltext --msgbox "$plain_report" "$_rows" "$_cols"
    clear
    printf '%b' "$report"
}
