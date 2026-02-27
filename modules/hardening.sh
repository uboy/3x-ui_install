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

        # Validate username before any system changes
        is_valid_username "$admin_user" || die "Invalid admin username: $admin_user"

        if ! id -u "$admin_user" >/dev/null 2>&1; then
            log "Создание администратора системы: $admin_user..."
            useradd -m -s /bin/bash "$admin_user"
            local admin_pass="${NEW_PASS:-$(generate_strong_secret)}"
            echo "$admin_user:$admin_pass" | chpasswd
            usermod -aG sudo "$admin_user"
            NEW_USER="$admin_user"
            NEW_PASS="$admin_pass"
        fi

        # Restricted sudoers — specific commands only (not NOPASSWD:ALL)
        local sudoers_file="/etc/sudoers.d/90-aegis-${admin_user}"
        {
            echo "# Aegis VPN Toolbox — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "${admin_user} ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/sbin/ufw, /usr/bin/docker, /usr/bin/journalctl"
        } > "$sudoers_file"
        chmod 440 "$sudoers_file"
        visudo -c -f "$sudoers_file" || { rm -f "$sudoers_file"; die "sudoers syntax error — file removed"; }
        success "Пользователь $admin_user создан и добавлен в sudoers."

        # 3. Харденинг SSH
        log "Применение настроек SSH (Порт: ${SSH_PORT:-22}, Root: No)..."

        # Timestamped backup
        local bak_dir="/etc/ssh/backups"
        mkdir -p "$bak_dir"
        cp /etc/ssh/sshd_config "${bak_dir}/sshd_config.$(date +%Y%m%d_%H%M%S)"

        sed -i "s/^#\?Port .*/Port ${SSH_PORT:-22}/" /etc/ssh/sshd_config
        sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
        # Note: PasswordAuthentication remains yes for initial access; configure key-based auth post-install
        sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication yes/" /etc/ssh/sshd_config

        if ! grep -q "AllowUsers" /etc/ssh/sshd_config; then
            echo "AllowUsers $admin_user" >> /etc/ssh/sshd_config
        fi

        # Validate SSH config before allowing restart
        if ! sshd -t -f /etc/ssh/sshd_config 2>&1; then
            error "Конфигурация SSH содержит ошибки — восстанавливаем последний бекап"
            local last_bak
            last_bak=$(ls -1t "$bak_dir"/ | head -1)
            cp "${bak_dir}/${last_bak}" /etc/ssh/sshd_config
            die "SSH config rejected — restored from backup"
        fi

        success "Конфигурация SSH обновлена (бекапы в ${bak_dir})."
        warn "Примечание: PasswordAuthentication=yes. Настройте key-based auth и отключите пароли после входа."
    fi
}
