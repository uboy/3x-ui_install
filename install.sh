#!/usr/bin/env bash
set -Eeuo pipefail

# Root directory of the installer
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Убеждаемся, что whiptail установлен для UI
if ! command -v whiptail >/dev/null 2>&1; then
    apt-get update && apt-get install -y whiptail
fi

# Source libraries
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/state.sh"
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/ui.sh"
source "${SCRIPT_DIR}/lib/firewall.sh"
source "${SCRIPT_DIR}/lib/cert.sh"

# Source modules
source "${SCRIPT_DIR}/modules/base.sh"
source "${SCRIPT_DIR}/modules/hardening.sh"
source "${SCRIPT_DIR}/modules/xui.sh"
source "${SCRIPT_DIR}/modules/openvpn.sh"
source "${SCRIPT_DIR}/modules/openconnect.sh"
source "${SCRIPT_DIR}/modules/amnezia.sh"

on_exit() {
  local rc=$?
  save_install_state
  trap - EXIT
  exit "$rc"
}
trap on_exit EXIT

main() {
  # Инициализация переменных для предотвращения ошибок 'unbound variable'
  DOMAIN=""
  EMAIL=""
  VPN_USER="vpnuser"
  VPN_PASS=""
  INSTALL_XUI="false"
  INSTALL_OPENVPN="false"
  INSTALL_OPENCONNECT="false"
  INSTALL_AMNEZIA="false"
  INSTALL_MODE="simple"
  SSH_PORT="22"
  NEW_USER=""
  NEW_PASS=""
  PANEL_ADMIN_USER=""
  PANEL_ADMIN_PASS=""

  # 1. Начальные проверки
  module_base_check_os
  load_install_state

  # Подтягиваем значения из загруженного состояния
  resolve_var DOMAIN ""
  resolve_var EMAIL ""
  resolve_var VPN_USER "vpnuser"
  resolve_var INSTALL_MODE "simple"
  resolve_var SSH_PORT "22"
  
  # 2. Интерактивный сбор информации
  ui_select_components
  ui_get_basic_info
  
  # 3. Начало установки
  ui_confirm_install
  
  module_base_install
  firewall_init
  
  # 4. Применение безопасности (SSH, Fail2Ban)
  module_hardening_apply
  
  # 5. Получение SSL сертификата (если нужно)
  if [[ "$INSTALL_XUI" == "true" || "$INSTALL_OPENCONNECT" == "true" ]]; then
    cert_install_tools
    cert_issue_standalone "$DOMAIN" "$EMAIL"
  fi

  # 6. Установка и настройка выбранных модулей
  
  # 3x-ui
  if [[ "$INSTALL_XUI" == "true" ]]; then
    module_xui_install
    module_xui_configure
  fi
  
  # OpenVPN
  if [[ "$INSTALL_OPENVPN" == "true" ]]; then
    module_openvpn_install
    module_openvpn_configure
  fi
  
  # OpenConnect
  if [[ "$INSTALL_OPENCONNECT" == "true" ]]; then
    module_openconnect_install
  fi
  
  # Amnezia
  if [[ "$INSTALL_AMNEZIA" == "true" ]]; then
    module_amnezia_install
  fi

  # 7. Финализация фаервола
  firewall_allow "${SSH_PORT:-22}"
  firewall_enable
  
  # Перезапуск SSH если меняли настройки
  if [[ "$INSTALL_MODE" == "super-secure" ]]; then
     log "Перезапуск SSH сервиса..."
     systemctl restart ssh || warn "Не удалось перезапустить SSH автоматически. Проверьте вручную."
  fi

  # 8. Финальный отчет
  ui_final_report
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
