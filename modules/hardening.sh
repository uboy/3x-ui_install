#!/usr/bin/env bash

module_hardening_apply() {
    log "--- Начало настройки безопасности (Hardening) ---"
    
    # 1. Настройка Fail2Ban
    log "Настройка Fail2Ban для защиты SSH..."
    apt-get install -y fail2ban
    cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port = ${SSH_PORT:-22}
maxretry = 5
findtime = 10m
bantime = 1h
banaction = ufw
EOF
    systemctl enable --now fail2ban
    systemctl restart fail2ban
    success "Fail2Ban настроен и запущен."

    # 2. Создание пользователя
    if [[ "$INSTALL_MODE" == "super-secure" ]]; then
        local admin_user="${NEW_USER:-vpnadmin}"
        if ! id -u "$admin_user" >/dev/null 2>&1; then
            log "Создание администратора системы: $admin_user..."
            useradd -m -s /bin/bash "$admin_user"
            local admin_pass="${NEW_PASS:-$(generate_strong_secret)}"
            echo "$admin_user:$admin_pass" | chpasswd
            usermod -aG sudo "$admin_user"
            echo "$admin_user ALL=(ALL:ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-aegis-$admin_user"
            success "Пользователь $admin_user создан и добавлен в sudoers."
            NEW_USER="$admin_user"
            NEW_PASS="$admin_pass"
        fi
        
        # 3. Харденинг SSH
        log "Применение настроек SSH (Порт: ${SSH_PORT:-22}, Root: No)..."
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        sed -i "s/^#\?Port .*/Port ${SSH_PORT:-22}/" /etc/ssh/sshd_config
        sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
        sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication yes/" /etc/ssh/sshd_config
        
        if ! grep -q "AllowUsers" /etc/ssh/sshd_config; then
            echo "AllowUsers $admin_user" >> /etc/ssh/sshd_config
        fi
        success "Конфигурация SSH обновлена (бекап в /etc/ssh/sshd_config.bak)."
    fi
}
