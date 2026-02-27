#!/usr/bin/env bash

module_base_install() {
  local packages=(adduser ca-certificates certbot curl fail2ban gnupg jq lsb-release openssl python3 sudo ufw iptables)
  log "Установка базовых пакетов: ${packages[*]}"
  apt-get update -y
  apt-get install -y --no-install-recommends "${packages[@]}"

  log "Включение IP Forwarding в ядре..."
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn-forward.conf
  sysctl -p /etc/sysctl.d/99-vpn-forward.conf || true
}

module_base_check_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
      die "This installer targets Ubuntu 24.04 (detected: ${ID:-unknown} ${VERSION_ID:-unknown})."
    fi
  fi
  
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (sudo)."
  fi
}
