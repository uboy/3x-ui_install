#!/usr/bin/env bash

module_hardening_apply() {
    log "Настройка безопасности системы..."
    
    # 1. Настройка Fail2Ban
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

    # 2. Создание пользователя если нужно (супер-безопасный режим)
    if [[ "$INSTALL_MODE" == "super-secure" ]]; then
        [[ -n "$NEW_USER" ]] || NEW_USER="vpnadmin"
        if ! id -u "$NEW_USER" >/dev/null 2>&1; then
            log "Создание пользователя $NEW_USER..."
            useradd -m -s /bin/bash "$NEW_USER"
            [[ -n "$NEW_PASS" ]] || NEW_PASS=$(generate_strong_secret)
            echo "$NEW_USER:$NEW_PASS" | chpasswd
            usermod -aG sudo "$NEW_USER"
            echo "$NEW_USER ALL=(ALL:ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-3xui-$NEW_USER"
        fi
        
        # 3. Харденинг SSH
        log "Настройка SSH (порт ${SSH_PORT:-22}, запрет root)..."
        sed -i "s/^#\?Port .*/Port ${SSH_PORT:-22}/" /etc/ssh/sshd_config
        sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
        sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication yes/" /etc/ssh/sshd_config
        
        # Добавляем в AllowUsers
        if ! grep -q "AllowUsers" /etc/ssh/sshd_config; then
            echo "AllowUsers $NEW_USER" >> /etc/ssh/sshd_config
        fi
        
        # Откладываем перезапуск SSH до момента включения фаервола
    fi
}
