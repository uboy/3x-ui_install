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

    # Проверка поддержки NAT в ядре
    if ! iptables -t nat -L -n >/dev/null 2>&1; then
        warn "Таблица NAT не поддерживается ядром. Интернет в VPN может не работать."
        return 1
    fi

    log "Настройка NAT в UFW для подсети $subnet через интерфейс $eth..."

    # 1. Удаляем старые ошибочные блоки Aegis если они есть
    sed -i '/# START AEGIS NAT/,/# END AEGIS NAT/d' /etc/ufw/before.rules

    # 2. Подготавливаем новый блок правил
    local nat_rules=$(cat <<EOF
# START AEGIS NAT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $subnet -o $eth -j MASQUERADE
COMMIT
# END AEGIS NAT
EOF
)

    # 3. Вставляем правила в САМОЕ НАЧАЛО файла before.rules
    # Это гарантирует, что NAT сработает до любых запрещающих правил
    local temp_file=$(mktemp)
    echo "$nat_rules" > "$temp_file"
    cat /etc/ufw/before.rules >> "$temp_file"
    cp "$temp_file" /etc/ufw/before.rules
    rm -f "$temp_file"
    
    success "Правила NAT добавлены в /etc/ufw/before.rules"
}

firewall_allow() {
    local port="$1"
    local proto="${2:-tcp}"
    log "Открытие порта $port/$proto..."
    ufw allow "$port/$proto"
}

firewall_enable() {
    log "Включение и перезапуск фаервола..."
    # Проверяем синтаксис перед перезапуском
    if ! ufw status >/dev/null 2>&1; then
        error "Ошибка конфигурации UFW. Откат изменений в before.rules..."
        sed -i '/# START AEGIS NAT/,/# END AEGIS NAT/d' /etc/ufw/before.rules
    fi
    echo "y" | ufw enable
    ufw reload
}

firewall_status() {
    ufw status verbose
}
