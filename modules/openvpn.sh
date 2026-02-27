#!/usr/bin/env bash

module_openvpn_install() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0

    local _native_active=false
    local _docker_legacy=false

    # Detect existing installations
    if systemctl is-active --quiet openvpn@server || [[ -f /etc/openvpn/server.conf ]]; then
        _native_active=true
    fi
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^openvpn$"; then
        _docker_legacy=true
    fi

    if [[ "$_native_active" == true ]] || [[ "$_docker_legacy" == true ]]; then
        if ! ui_ask_reinstall "OpenVPN"; then
            log "Пропуск установки OpenVPN."
            INSTALL_OPENVPN="skipped"
            return 0
        fi

        log "Очистка старой установки OpenVPN..."

        # Remove native install artifacts
        systemctl stop openvpn@server 2>/dev/null || true
        systemctl disable openvpn@server 2>/dev/null || true
        rm -rf /etc/openvpn/easy-rsa
        rm -f  /etc/openvpn/server.conf
        rm -f  /etc/openvpn/ta.key

        # Remove Docker legacy install
        if [[ "$_docker_legacy" == true ]]; then
            local _docker_dir="/opt/openvpn"
            if [[ -f "${_docker_dir}/docker-compose.yml" ]]; then
                ( cd "$_docker_dir" && docker compose down -v 2>/dev/null ) || true
            fi
            rm -rf "$_docker_dir"
        fi
    fi

    log "Установка пакетов openvpn и easy-rsa..."
    apt-get install -y openvpn easy-rsa

    # -------------------------------------------------------------------------
    # PKI via easy-rsa 3.x
    # -------------------------------------------------------------------------
    local OVPN_PKI="/etc/openvpn/easy-rsa"

    make-cadir "$OVPN_PKI"

    # Write vars — single-quoted delimiter, no variable expansion needed
    cat > "${OVPN_PKI}/vars" <<'VARSEOF'
set_var EASYRSA_ALGO       ec
set_var EASYRSA_CURVE      prime256v1
set_var EASYRSA_CA_EXPIRE  3650
set_var EASYRSA_CERT_EXPIRE 825
set_var EASYRSA_BATCH      1
VARSEOF

    log "Инициализация PKI..."
    export EASYRSA_BATCH=1
    (
        cd "$OVPN_PKI"
        ./easyrsa init-pki
        ./easyrsa build-ca nopass
        ./easyrsa build-server-full server nopass
        ./easyrsa gen-crl
    )

    # -------------------------------------------------------------------------
    # TLS-auth key
    # -------------------------------------------------------------------------
    log "Генерация TLS-auth ключа..."
    openvpn --genkey secret /etc/openvpn/ta.key
    chmod 600 /etc/openvpn/ta.key

    # -------------------------------------------------------------------------
    # server.conf — SRVEOF is unquoted so $OVPN_PKI expands
    # -------------------------------------------------------------------------
    log "Запись /etc/openvpn/server.conf..."
    cat > /etc/openvpn/server.conf <<SRVEOF
port 1194
proto udp
dev tun
user nobody
group nogroup

ca   ${OVPN_PKI}/pki/ca.crt
cert ${OVPN_PKI}/pki/issued/server.crt
key  ${OVPN_PKI}/pki/private/server.key
dh   none
ecdh-curve prime256v1
tls-auth /etc/openvpn/ta.key 0
crl-verify ${OVPN_PKI}/pki/crl.pem

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 1.1.1.1"

cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
auth SHA256
tls-version-min 1.2

keepalive 10 120
persist-key
persist-tun

status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
SRVEOF

    # -------------------------------------------------------------------------
    # Split-tunnel exclusion routes
    # -------------------------------------------------------------------------
    if [[ -n "${VPN_EXCLUDE_ROUTES:-}" ]]; then
        log "Добавление маршрутов исключения (split-tunnel)..."
        local _cidr _ip _prefix _mask
        IFS=',' read -ra _exclude_addrs <<< "$VPN_EXCLUDE_ROUTES"
        for _cidr in "${_exclude_addrs[@]}"; do
            _cidr="${_cidr// /}"   # trim spaces
            [[ -z "$_cidr" ]] && continue
            _ip="${_cidr%%/*}"
            _prefix="${_cidr##*/}"
            _mask=$(python3 -c "import ipaddress; print(str(ipaddress.IPv4Network('0.0.0.0/${_prefix}').netmask))" 2>/dev/null) || {
                warn "Не удалось вычислить маску для ${_cidr}, пропускаем"
                continue
            }
            echo "push \"route ${_ip} ${_mask} net_gateway\"" >> /etc/openvpn/server.conf
        done
    fi

    # -------------------------------------------------------------------------
    # Log directory, firewall, service
    # -------------------------------------------------------------------------
    mkdir -p /var/log/openvpn

    firewall_configure_nat "10.8.0.0/24"
    firewall_allow 1194 udp

    systemctl daemon-reload
    systemctl enable openvpn@server
    systemctl start openvpn@server

    sleep 3

    if ! systemctl is-active --quiet openvpn@server; then
        error "OpenVPN не запустился. Последние строки журнала:"
        journalctl -u openvpn@server -n 30 --no-pager >&2
        return 1
    fi

    success "OpenVPN нативно установлен."
}

module_openvpn_configure() {
    [[ "$INSTALL_OPENVPN" == "true" ]] || return 0
    [[ "$INSTALL_OPENVPN" == "skipped" ]] && return 0

    local client_name="${VPN_USER:-vpnuser}"
    local pki_dir="/etc/openvpn/easy-rsa"
    local ovpn_out="/etc/openvpn/${client_name}.ovpn"

    log "Создание клиентского сертификата для ${client_name}..."
    (
        cd "$pki_dir"
        EASYRSA_BATCH=1 ./easyrsa build-client-full "$client_name" nopass
    )

    log "Сборка inline .ovpn файла: ${ovpn_out}..."
    cat > "$ovpn_out" <<EOF
client
nobind
dev tun
proto udp
remote ${DOMAIN} 1194

remote-cert-tls server
key-direction 1

cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
auth SHA256
tls-version-min 1.2

resolv-retry infinite
persist-key
persist-tun
verb 3

<ca>
$(cat "${pki_dir}/pki/ca.crt")
</ca>
<cert>
$(openssl x509 -in "${pki_dir}/pki/issued/${client_name}.crt")
</cert>
<key>
$(cat "${pki_dir}/pki/private/${client_name}.key")
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF

    chmod 600 "$ovpn_out"

    success "Конфигурация клиента OpenVPN готова: ${ovpn_out}"
}
