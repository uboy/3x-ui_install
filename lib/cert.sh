#!/usr/bin/env bash

cert_install_tools() {
    log "Установка Certbot..."
    apt-get install -y certbot
}

cert_issue_standalone() {
    local domain="$1"
    local email="$2"
    
    log "Получение сертификата для $domain..."
    
    # Останавливаем временно службы на 80 порту если есть
    if command -v nginx >/dev/null 2>&1; then systemctl stop nginx; fi
    
    certbot certonly --standalone 
        --non-interactive --agree-tos --email "$email" 
        -d "$domain"
    
    if [[ -d "/etc/letsencrypt/live/$domain" ]]; then
        success "Сертификат для $domain успешно получен."
        return 0
    else
        error "Не удалось получить сертификат."
        return 1
    fi
}
