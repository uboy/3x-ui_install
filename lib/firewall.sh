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

    # 1. Создаем резервную копию если ее еще нет
    if [[ ! -f /etc/ufw/before.rules.orig ]]; then
        cp /etc/ufw/before.rules /etc/ufw/before.rules.orig
    fi

    # 2. Если блока NAT вообще нет в файле, добавляем его в самое начало (после комментариев)
    if ! grep -q "^\*nat" /etc/ufw/before.rules; then
        log "Создание нового блока *nat в before.rules..."
        local temp_file=$(mktemp)
        cat > "$temp_file" <<EOF
*nat
:POSTROUTING ACCEPT [0:0]
COMMIT

EOF
        # Вставляем после первых комментариев (строки начинающиеся с #)
        local first_non_comment=$(grep -n -v "^#" /etc/ufw/before.rules | head -n 1 | cut -d: -f1)
        if [[ -z "$first_non_comment" ]]; then first_non_comment=1; fi
        
        sed "${first_non_comment}i $(cat $temp_file | sed ':a;N;$!ba;s/\n/\\n/g')" /etc/ufw/before.rules > "${temp_file}.final"
        mv "${temp_file}.final" /etc/ufw/before.rules
        rm -f "$temp_file"
    fi

    # 3. Добавляем правило маскарадинга, если его еще нет
    local rule="-A POSTROUTING -s $subnet -o $eth -j MASQUERADE"
    if ! grep -Fq -- "$rule" /etc/ufw/before.rules; then
        log "Добавление правила MASQUERADE для $subnet..."
        # Вставляем ПЕРЕД COMMIT в блоке *nat
        # Ищем строку COMMIT, которая идет после *nat
        sed -i "/^\*nat/,/^COMMIT/ s/^COMMIT/$rule\nCOMMIT/" /etc/ufw/before.rules
    fi
    
    success "Конфигурация NAT обновлена."
}

firewall_allow() {
    local port="$1"
    local proto="${2:-tcp}"
    log "Открытие порта $port/$proto..."
    ufw allow "$port/$proto"
}

firewall_enable() {
    log "Включение и перезапуск фаервола..."
    
    # Проверка на наличие пустых строк или дублей COMMIT в блоке nat, которые могли возникнуть
    # (чистка возможных артефактов предыдущих неудачных запусков)
    
    # Пытаемся применить
    if ! echo "y" | ufw enable; then
        error "UFW не смог включиться. Проверьте /etc/ufw/before.rules."
        warn "Пытаюсь восстановить оригинальный файл..."
        cp /etc/ufw/before.rules.orig /etc/ufw/before.rules
        echo "y" | ufw enable
        return 1
    fi
    ufw reload
}

firewall_status() {
    ufw status verbose
}
