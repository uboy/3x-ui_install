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
    "OpenConnect" "Cisco AnyConnect совместимый VPN" OFF \
    "Amnezia" "Amnezia VPN (с поддержкой AmneziaWG)" OFF 3>&1 1>&2 2>&3)

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
            "\"Amnezia\"") INSTALL_AMNEZIA="true" ;;
        esac
    done

    # Если ничего не выбрано - выходим
    if [[ "$INSTALL_XUI" == "false" && "$INSTALL_OPENVPN" == "false" && "$INSTALL_OPENCONNECT" == "false" && "$INSTALL_AMNEZIA" == "false" ]]; then
        whiptail --title "Ошибка" --msgbox "Ничего не выбрано. Установка отменена." 10 60
        exit 0
    fi
}

ui_get_basic_info() {
    DOMAIN=$(whiptail --title "Настройка Aegis" --inputbox "Введите домен или IP адрес сервера:" 10 60 "${DOMAIN:-}" 3>&1 1>&2 2>&3)
    EMAIL=$(whiptail --title "Настройка Email" --inputbox "Введите Email для Let's Encrypt:" 10 60 "${EMAIL:-}" 3>&1 1>&2 2>&3)
    
    VPN_USER=$(whiptail --title "VPN Пользователь" --inputbox "Введите имя пользователя для VPN (OpenConnect/OpenVPN):" 10 60 "${VPN_USER:-vpnuser}" 3>&1 1>&2 2>&3)
    
    VPN_PASS=$(whiptail --title "VPN Пароль" --passwordbox "Введите пароль для VPN (оставьте пустым для автогенерации):" 10 60 3>&1 1>&2 2>&3)
    if [[ -z "${VPN_PASS:-}" ]]; then
        VPN_PASS=$(generate_strong_secret)
    fi
    
    save_install_state
}

ui_confirm_install() {
    if whiptail --title "Aegis VPN Toolbox" --yesno "Начать установку выбранных компонентов?" 10 60; then
        return 0
    else
        exit 0
    fi
}

ui_final_report() {
    local report=""
    report="${BOLD}Aegis VPN Toolbox: Установка завершена!${NC}\n\n"
    report="${report}${BLUE}--- Общие данные ---${NC}\n"
    report="${report}Домен/IP: ${DOMAIN}\n"
    if [[ "$INSTALL_MODE" == "super-secure" ]]; then
        report="${report}SSH Пользователь: ${NEW_USER}\n"
        report="${report}SSH Пароль: ${NEW_PASS}\n"
        report="${report}SSH Порт: ${SSH_PORT:-22}\n"
    fi
    report="${report}\n"

    if [[ "$INSTALL_XUI" == "true" ]]; then
        report="${report}${BLUE}--- 3x-ui Panel ---${NC}\n"
        report="${report}URL: http://${DOMAIN}:2053\n"
        report="${report}Админ: ${PANEL_ADMIN_USER}\n"
        report="${report}Пароль: ${PANEL_ADMIN_PASS}\n\n"
    fi

    if [[ "$INSTALL_OPENVPN" == "true" ]]; then
        report="${report}${BLUE}--- OpenVPN ---${NC}\n"
        report="${report}Пользователь: ${VPN_USER:-vpnuser}\n"
        report="${report}Конфиг клиента: /opt/openvpn/${VPN_USER:-vpnuser}.ovpn\n"
        report="${report}Порт: 1194 (UDP)\n\n"
    fi

    if [[ "$INSTALL_OPENCONNECT" == "true" ]]; then
        report="${report}${BLUE}--- OpenConnect ---${NC}\n"
        report="${report}Сервер: ${DOMAIN}:4443\n"
        report="${report}Пользователь: ${VPN_USER:-vpnuser}\n"
        report="${report}Пароль: ${VPN_PASS}\n\n"
    fi

    if [[ "$INSTALL_AMNEZIA" == "true" ]]; then
        report="${report}${BLUE}--- Amnezia VPN ---${NC}\n"
        report="${report}Протокол: AmneziaWG\n"
        report="${report}Порт: 51820 (UDP)\n"
        report="${report}Конфиг клиента: /opt/amnezia/amnezia_client.conf\n\n"
    fi

    whiptail --title "Aegis VPN Toolbox - Итоги" --msgbox "$(printf "$report")" 25 80
    clear
    printf "$report"
}
