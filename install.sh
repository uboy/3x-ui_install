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
for f in base.sh hardening.sh xui.sh openvpn.sh openconnect.sh amnezia.sh dumbproxy.sh; do
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
  trap - ERR EXIT
  error "Installation failed at line $line (exit code $rc)"
  [[ -f /etc/ufw/before.rules.orig ]] && \
    cp /etc/ufw/before.rules.orig /etc/ufw/before.rules
  save_install_state
  exit "$rc"
}
trap 'on_error ${LINENO}' ERR

main() {
  # Инициализация — все переменные пустые, чтобы resolve_var мог восстановить
  # значения из state-файла (не-пустая инициализация блокирует restore_var)
  DOMAIN=""
  EMAIL=""
  VPN_USER=""
  VPN_PASS=""
  VPN_EXCLUDE_ROUTES=""
  INSTALL_XUI="false"
  INSTALL_OPENVPN="false"
  INSTALL_OPENCONNECT="false"
  INSTALL_AMNEZIA="false"
  INSTALL_DUMBPROXY="false"
  INSTALL_HARDENING="false"
  INSTALL_MODE=""
  SSH_PORT=""
  PORT_XUI_PANEL=""
  PORT_XUI_REALITY=""
  PORT_OPENVPN=""
  PORT_OPENCONNECT=""
  PORT_AMNEZIA=""
  PORT_DUMBPROXY=""
  NEW_USER=""
  NEW_PASS=""
  PANEL_ADMIN_USER=""
  PANEL_ADMIN_PASS=""
  EXPOSE_PANEL_PUBLIC=""
  PANEL_PUBLIC_HOST=""

  log "Шаг 1: Проверка ОС и загрузка состояния..."
  module_base_check_os
  load_install_state

  resolve_var DOMAIN             ""
  resolve_var EMAIL              ""
  resolve_var VPN_USER           "vpnuser"
  resolve_var VPN_PASS           ""
  resolve_var VPN_EXCLUDE_ROUTES ""
  resolve_var INSTALL_MODE       "simple"
  resolve_var SSH_PORT           "22"
  resolve_var NEW_USER           ""
  resolve_var NEW_PASS           ""
  resolve_var PANEL_ADMIN_USER   ""
  resolve_var PANEL_ADMIN_PASS   ""
  resolve_var INSTALL_HARDENING  "false"
  resolve_var EXPOSE_PANEL_PUBLIC "false"
  resolve_var PANEL_PUBLIC_HOST   ""
  resolve_var PORT_XUI_PANEL     "2053"
  resolve_var PORT_XUI_REALITY   "443"
  resolve_var PORT_OPENVPN       "1194"
  resolve_var PORT_OPENCONNECT   "4443"
  resolve_var PORT_AMNEZIA       "51820"
  resolve_var PORT_DUMBPROXY    "8080"
  resolve_var INSTALL_DUMBPROXY "false"

  if ! command -v whiptail &>/dev/null; then
    log "Установка whiptail (интерактивный интерфейс)..."
    apt-get install -y --no-install-recommends whiptail >/dev/null 2>&1
  fi

  ui_banner

  log "Шаг 2: Сбор интерактивной информации..."
  ui_select_components
  ui_get_basic_info
  ui_get_hardening_info
  ui_get_panel_exposure_info
  ui_get_ports

  log "Шаг 3: Подтверждение и начало установки..."
  ui_confirm_install
  
  # Проверка конфликтов портов
  declare -A USED_PORTS
  [[ "${INSTALL_XUI:-false}" == "true" ]] && {
    USED_PORTS["${PORT_XUI_REALITY:-443}"]="3x-ui Reality"
    USED_PORTS["${PORT_XUI_PANEL:-2053}"]="3x-ui Panel"
  }
  [[ "${INSTALL_OPENVPN:-false}" == "true" ]] && USED_PORTS["${PORT_OPENVPN:-1194}"]="OpenVPN"
  [[ "${INSTALL_OPENCONNECT:-false}" == "true" ]] && USED_PORTS["${PORT_OPENCONNECT:-4443}"]="OpenConnect"
  [[ "${INSTALL_AMNEZIA:-false}" == "true" ]] && USED_PORTS["${PORT_AMNEZIA:-51820}"]="AmneziaWG"
  [[ "${INSTALL_DUMBPROXY:-false}" == "true" ]] && USED_PORTS["${PORT_DUMBPROXY:-8080}"]="Dumbproxy"
  
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
  
  if [[ "${INSTALL_HARDENING:-false}" == "true" ]]; then
    log "Шаг 4: Настройка безопасности..."
    module_hardening_apply
  fi
  
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
  if [[ "$INSTALL_DUMBPROXY" == "true" ]]; then module_dumbproxy_install; fi

  log "Шаг 7: Настройка фаервола..."
  firewall_allow "${SSH_PORT:-22}"
  if [[ "${INSTALL_XUI:-false}" == "true" && "${EXPOSE_PANEL_PUBLIC:-false}" == "true" && "${INSTALL_HARDENING:-false}" != "true" ]]; then
    firewall_allow "${PORT_XUI_PANEL:-2053}" tcp
  fi
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
