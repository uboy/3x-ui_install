#!/usr/bin/env bash
set -Eeuo pipefail

# Root directory of the installer
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source libraries - ПРОВЕРКА НАЛИЧИЯ
for f in common.sh state.sh utils.sh ui.sh firewall.sh cert.sh; do
    if [[ ! -f "${SCRIPT_DIR}/lib/$f" ]]; then
        echo "ERROR: Library ${SCRIPT_DIR}/lib/$f not found!"
        exit 1
    fi
    source "${SCRIPT_DIR}/lib/$f"
done

# Source modules
for f in base.sh hardening.sh xui.sh openvpn.sh openconnect.sh amnezia.sh; do
    if [[ ! -f "${SCRIPT_DIR}/modules/$f" ]]; then
        echo "ERROR: Module ${SCRIPT_DIR}/modules/$f not found!"
        exit 1
    fi
    source "${SCRIPT_DIR}/modules/$f"
done

on_exit() {
  local rc=$?
  save_install_state
  trap - EXIT
  exit "$rc"
}
trap on_exit EXIT

on_error() {
  local rc=$? line=$1
  error "Installation failed at line $line (exit code $rc)"
  [[ -f /etc/ufw/before.rules.orig ]] && \
    cp /etc/ufw/before.rules.orig /etc/ufw/before.rules
  save_install_state
  exit "$rc"
}
trap 'on_error ${LINENO}' ERR

main() {
  # Инициализация
  DOMAIN=""
  EMAIL=""
  VPN_USER="vpnuser"
  VPN_PASS=""
  VPN_EXCLUDE_ROUTES=""
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

  log "Шаг 1: Проверка ОС и загрузка состояния..."
  module_base_check_os
  load_install_state

  resolve_var DOMAIN ""
  resolve_var EMAIL ""
  resolve_var VPN_USER "vpnuser"
  resolve_var VPN_EXCLUDE_ROUTES ""
  resolve_var INSTALL_MODE "simple"
  resolve_var SSH_PORT "22"

  ui_banner
  
  log "Шаг 2: Сбор интерактивной информации..."
  ui_select_components
  ui_get_basic_info
  
  log "Шаг 3: Подтверждение и начало установки..."
  ui_confirm_install
  
  # Проверка конфликтов портов
  declare -A USED_PORTS
  USED_PORTS[443]="3x-ui Reality"
  USED_PORTS[1194]="OpenVPN"
  USED_PORTS[4443]="OpenConnect"
  USED_PORTS[51820]="AmneziaWG"
  USED_PORTS[2053]="3x-ui Panel"
  
  # Если SSH_PORT изменен — проверяем конфликты
  if [[ "${SSH_PORT:-22}" != "22" ]]; then
      if [[ -n "${USED_PORTS[$SSH_PORT]:-}" ]]; then
          error "КОНФЛИКТ ПОРТОВ: Порт $SSH_PORT занят сервисом ${USED_PORTS[$SSH_PORT]}. Смените порт SSH!"
          exit 1
      fi
      if ! check_port_free "$SSH_PORT"; then
          error "Порт $SSH_PORT уже занят запущенным сервисом (проверено через ss)"
          exit 1
      fi
  fi

  # Проверка свободного места (минимум 5 ГБ)
  check_disk_space 5

  module_base_install
  firewall_init
  
  log "Шаг 4: Настройка безопасности..."
  module_hardening_apply
  
  if [[ "$INSTALL_XUI" == "true" || "$INSTALL_OPENCONNECT" == "true" ]]; then
    log "Шаг 5: Получение сертификатов..."
    cert_install_tools
    cert_issue_standalone "$DOMAIN" "$EMAIL"
  fi

  log "Шаг 6: Установка компонентов..."
  if [[ "$INSTALL_XUI" == "true" ]]; then 
    module_xui_install
    if [[ "$INSTALL_XUI" != "skipped" ]]; then module_xui_configure; fi
  fi
  if [[ "$INSTALL_OPENVPN" == "true" ]]; then 
    module_openvpn_install
    if [[ "$INSTALL_OPENVPN" != "skipped" ]]; then module_openvpn_configure; fi
  fi
  if [[ "$INSTALL_OPENCONNECT" == "true" ]]; then module_openconnect_install; fi
  if [[ "$INSTALL_AMNEZIA" == "true" ]]; then module_amnezia_install; fi

  log "Шаг 7: Настройка фаервола..."
  firewall_allow "${SSH_PORT:-22}"
  firewall_enable
  
  if [[ "$INSTALL_MODE" == "super-secure" ]]; then
     systemctl restart ssh || true
  fi

  log "Шаг 8: Завершение..."
  ui_final_report
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
