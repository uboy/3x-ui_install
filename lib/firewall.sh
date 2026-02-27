#!/usr/bin/env bash

firewall_init() {
    log "Инициализация фаервола (UFW)..."
    apt-get install -y ufw
    
    # Разрешаем форвардинг трафика (нужно для VPN)
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
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
