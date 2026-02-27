#!/usr/bin/env bash

# Библиотека для работы с whiptail (стандартное меню в Ubuntu)

# ANSI colors for UI
BOLD='\033[1m'
UNDERLINE='\033[4m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    sleep 1
}

ui_select_components() {
    local choices
    choices=$(whiptail --title "Aegis VPN Toolbox - Выбор" --checklist \
    "Выберите компоненты для установки (Пробел - выбор, Enter - подтверждение):" 20 70 10 \
    "XUI" "3x-ui Panel (Xray/VLESS/Reality)" ON \
    "OpenVPN" "Классический OpenVPN сервер" OFF \
    "OpenConnect" "Cisco AnyConnect совместимый VPN" OFF 3>&1 1>&2 2>&3)

    # Сбрасываем флаги
    INSTALL_XUI="false"
    INSTALL_OPENVPN="false"
    INSTALL_OPENCONNECT="false"
    INSTALL_AMNEZIA="false"

    for choice in $choices; do
        case $choice in
            "\"XUI\"") INSTALL_XUI="true" ;;
            "\"OpenVPN\"") INSTALL_OPENVPN="true" ;;
            "\"OpenConnect\"") INSTALL_OPENCONNECT="true" ;;
        esac
    done

    # Если ничего не выбрано - выходим
    if [[ "$INSTALL_XUI" == "false" && "$INSTALL_OPENVPN" == "false" && "$INSTALL_OPENCONNECT" == "false" ]]; then
        whiptail --title "Ошибка" --msgbox "Ничего не выбрано. Установка отменена." 10 60
        exit 0
    fi
}

ui_get_basic_info() {
    # DOMAIN — loop until valid
    while true; do
        DOMAIN=$(whiptail --title "Настройка Aegis" --inputbox "Введите домен или IP адрес сервера:" 10 60 "${DOMAIN:-}" 3>&1 1>&2 2>&3)
        if is_valid_domain "$DOMAIN"; then
            break
        fi
        whiptail --title "Ошибка" --msgbox "Некорректный домен или IP: '${DOMAIN}'\nПример: example.com или 1.2.3.4" 10 60
    done

    # EMAIL — required only for XUI or OpenConnect (Let's Encrypt)
    if [[ "${INSTALL_XUI:-false}" == "true" || "${INSTALL_OPENCONNECT:-false}" == "true" ]]; then
        while true; do
            EMAIL=$(whiptail --title "Настройка Email" --inputbox "Введите Email для Let's Encrypt:" 10 60 "${EMAIL:-}" 3>&1 1>&2 2>&3)
            if is_valid_email "$EMAIL"; then
                break
            fi
            whiptail --title "Ошибка" --msgbox "Некорректный email: '${EMAIL}'\nПример: user@example.com" 10 60
        done
    fi

    # VPN_USER — loop until valid
    while true; do
        VPN_USER=$(whiptail --title "VPN Пользователь" --inputbox "Введите имя пользователя для VPN (OpenConnect/OpenVPN):" 10 60 "${VPN_USER:-vpnuser}" 3>&1 1>&2 2>&3)
        if is_valid_username "$VPN_USER"; then
            break
        fi
        whiptail --title "Ошибка" --msgbox "Некорректное имя пользователя: '${VPN_USER}'\nДопустимо: строчные буквы, цифры, _ и - (начало: буква или _). Макс. 32 символа." 12 60
    done

    # VPN_PASS — enforce minimum 12 chars if entered manually
    while true; do
        VPN_PASS=$(whiptail --title "VPN Пароль" --passwordbox "Введите пароль для VPN (оставьте пустым для автогенерации, мин. 12 символов):" 10 60 3>&1 1>&2 2>&3)
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
        VPN_EXCLUDE_ROUTES=$(whiptail --title "Исключения маршрутов" --inputbox "Введите через запятую сети для исключения из VPN (напр. 1.1.1.1/32, 10.0.0.0/8). По умолчанию 192.168.0.0/16 уже исключена." 12 60 "${VPN_EXCLUDE_ROUTES:-}" 3>&1 1>&2 2>&3)
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
        report="${report}Панель управления: http://${DOMAIN}:2053\n"
        report="${report}Логин: ${PANEL_ADMIN_USER:-admin}\n"
        report="${report}Пароль: ${PANEL_ADMIN_PASS:-admin}\n"
        report="${report}VLESS Reality порт: 443\n\n"
    elif [[ "$INSTALL_XUI" == "skipped" ]]; then
        report="${report}${YELLOW}--- 3x-ui (Пропущено) ---${NC}\n\n"
    fi

    if [[ "$INSTALL_OPENVPN" == "true" ]]; then
        report="${report}${BLUE}${BOLD}--- OpenVPN ---${NC}\n"
        report="${report}Протокол/Порт: UDP / 1194\n"
        report="${report}Пользователь: ${VPN_USER:-vpnuser}\n"
        report="${report}Файл конфигурации (.ovpn): /opt/openvpn/${VPN_USER:-vpnuser}.ovpn\n\n"
    elif [[ "$INSTALL_OPENVPN" == "skipped" ]]; then
        report="${report}${YELLOW}--- OpenVPN (Пропущено) ---${NC}\n\n"
    fi

    if [[ "$INSTALL_OPENCONNECT" == "true" ]]; then
        report="${report}${BLUE}${BOLD}--- OpenConnect (Cisco AnyConnect) ---${NC}\n"
        report="${report}Сервер: ${DOMAIN}:4443\n"
        report="${report}Пользователь: ${VPN_USER:-vpnuser}\n"
        report="${report}Пароль: ${VPN_PASS}\n\n"
    elif [[ "$INSTALL_OPENCONNECT" == "skipped" ]]; then
        report="${report}${YELLOW}--- OpenConnect (Пропущено) ---${NC}\n\n"
    fi

    report="${report}${GREEN}${BOLD}Все пароли сохранены в файле состояния: /root/.aegis-vpn.state${NC}\n"

    # Создаем чистую версию без ANSI кодов для whiptail
    plain_report=$(printf "$report" | sed 's/\x1b\[[0-9;]*m//g')

    whiptail --title "Aegis VPN Toolbox - Итоги" --msgbox "$plain_report" 28 85
    clear
    printf "$report"
}
