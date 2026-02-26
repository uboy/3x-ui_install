#!/usr/bin/env bash

cert_install_tools() {
    log "Установка Certbot..."
    apt-get install -y certbot
}

cert_issue_standalone() {
    local domain="$1"
    local email="$2"
    
    # Проверяем, является ли "domain" IP-адресом
    if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        warn "Let's Encrypt не поддерживает IP-адреса ($domain). Генерируем самоподписанный сертификат..."
        mkdir -p "/etc/letsencrypt/live/$domain"
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "/etc/letsencrypt/live/$domain/privkey.pem" \
            -out "/etc/letsencrypt/live/$domain/fullchain.pem" \
            -subj "/CN=$domain"
        success "Самоподписанный сертификат для IP $domain создан."
        return 0
    fi

    log "Получение SSL сертификата Let's Encrypt для $domain..."
    
    # Останавливаем временно службы на 80 порту если есть
    if command -v nginx >/dev/null 2>&1; then systemctl stop nginx; fi
    
    # Запуск certbot
    if certbot certonly --standalone \
        --non-interactive --agree-tos --email "$email" \
        -d "$domain"; then
        success "Сертификат для $domain успешно получен."
        return 0
    else
        error "Не удалось получить сертификат Let's Encrypt. Проверьте DNS или доступность порта 80."
        return 1
    fi
}
