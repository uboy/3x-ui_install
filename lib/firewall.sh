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

    # Бекап перед изменениями
    cp /etc/ufw/before.rules /etc/ufw/before.rules.bak

    # Очистка старых правил Aegis
    sed -i '/# START AEGIS NAT/,/# END AEGIS NAT/d' /etc/ufw/before.rules

    # Создаем временный файл с новыми правилами
    local temp_nat=$(mktemp)
    cat > "$temp_nat" <<EOF
# START AEGIS NAT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $subnet -o $eth -j MASQUERADE
COMMIT
# END AEGIS NAT
EOF

    # Добавляем правила в начало файла, но ПОСЛЕ заголовка (первой строки)
    local final_file=$(mktemp)
    head -n 1 /etc/ufw/before.rules > "$final_file"
    cat "$temp_nat" >> "$final_file"
    tail -n +2 /etc/ufw/before.rules >> "$final_file"
    
    mv "$final_file" /etc/ufw/before.rules
    rm -f "$temp_nat"
    
    success "Правила NAT добавлены."
}

firewall_allow() {
    local port="$1"
    local proto="${2:-tcp}"
    log "Открытие порта $port/$proto..."
    ufw allow "$port/$proto"
}

firewall_enable() {
    log "Включение и перезапуск фаервола..."
    
    # Проверка синтаксиса перед включением
    if ! ufw status >/dev/null 2>&1; then
        warn "Конфигурация UFW повреждена. Восстановление из бекапа..."
        cp /etc/ufw/before.rules.bak /etc/ufw/before.rules
    fi

    echo "y" | ufw enable
    ufw reload
}

firewall_status() {
    ufw status verbose
}
