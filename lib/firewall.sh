#!/usr/bin/env bash

firewall_init() {
    log "Инициализация фаервола (UFW)..."
    apt-get install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
}

firewall_allow() {
    local port="$1"
    local proto="${2:-tcp}"
    log "Открытие порта $port/$proto..."
    ufw allow "$port/$proto"
}

firewall_enable() {
    log "Включение фаервола..."
    echo "y" | ufw enable
}

firewall_status() {
    ufw status verbose
}
