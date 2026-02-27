#!/usr/bin/env bash

firewall_init() {
    log "Инициализация фаервола (UFW)..."
    apt-get install -y ufw
    
    # Разрешаем форвардинг трафика (нужно для VPN)
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    ufw default deny incoming
    ufw default allow outgoing
}

firewall_configure_nat() {
    local subnet="$1"
    local eth=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -n 1)
    
    if [[ -z "$eth" ]]; then
        warn "Не удалось определить сетевой интерфейс для NAT."
        return 1
    fi

    log "Настройка NAT в UFW для подсети $subnet через интерфейс $eth..."

    # Добавляем правила NAT в начало /etc/ufw/before.rules, если их там еще нет
    if ! grep -q "NAT Rules" /etc/ufw/before.rules; then
        # Создаем временный файл с правилами NAT
        cat > /tmp/ufw_nat <<EOF
# NAT Rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $subnet -o $eth -j MASQUERADE
COMMIT

EOF
        # Склеиваем с существующим файлом
        cat /tmp/ufw_nat /etc/ufw/before.rules > /etc/ufw/before.rules.tmp
        mv /etc/ufw/before.rules.tmp /etc/ufw/before.rules
        rm /tmp/ufw_nat
    else
        # Если блок NAT уже есть, просто добавляем новую подсеть, если ее нет
        if ! grep -q "$subnet" /etc/ufw/before.rules; then
            sed -i "/^COMMIT/i -A POSTROUTING -s $subnet -o $eth -j MASQUERADE" /etc/ufw/before.rules
        fi
    fi
}

firewall_allow() {
    local port="$1"
    local proto="${2:-tcp}"
    log "Открытие порта $port/$proto..."
    ufw allow "$port/$proto"
}

firewall_enable() {
    log "Включение и перезапуск фаервола..."
    echo "y" | ufw enable
    ufw reload
}

firewall_status() {
    ufw status verbose
}
