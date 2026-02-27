#!/usr/bin/env bash

is_valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

is_valid_ipv4() {
  local ip="$1"
  local IFS='.'
  local -a octets=()
  local o=""

  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  read -r -a octets <<< "$ip"
  (( ${#octets[@]} == 4 )) || return 1
  for o in "${octets[@]}"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
}

is_valid_domain() {
  local domain="$1"
  # Accept bare IPv4 as a valid "domain"
  if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    is_valid_ipv4 "$domain" && return 0
    return 1
  fi
  [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]
}

is_valid_email() {
  local email="$1"
  [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

is_valid_username() {
  local user="$1"
  [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

is_valid_cidr() {
  local cidr="$1"
  local ip prefix
  [[ "$cidr" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$ ]] || return 1
  ip="${BASH_REMATCH[1]}"
  prefix="${BASH_REMATCH[2]}"
  is_valid_ipv4 "$ip" || return 1
  (( prefix >= 0 && prefix <= 32 ))
}

check_disk_space() {
  local required_gb="${1:-1}"
  local available_kb available_gb
  available_kb=$(df /var --output=avail 2>/dev/null | tail -1 | tr -d ' ')
  available_gb=$(( available_kb / 1024 / 1024 ))
  if (( available_gb < required_gb )); then
    error "Insufficient disk space: ${available_gb}GB available, ${required_gb}GB required in /var"
    return 1
  fi
}

check_port_free() {
  local port="$1"
  if ss -tuln 2>/dev/null | grep -qE ":${port}[[:space:]]"; then
    return 1
  fi
  return 0
}

generate_random_fixed() {
  local length="${1:-}"
  local charset="${2:-}"
  local lowercase="${3:-false}"
  local value=""
  local chunk=""
  local attempt

  [[ "$length" =~ ^[0-9]+$ ]] || return 1
  (( length > 0 )) || return 1
  [[ -n "$charset" ]] || return 1

  for (( attempt = 0; attempt < 32 && ${#value} < length; attempt++ )); do
    chunk="$(openssl rand -base64 "$((length * 3))" 2>/dev/null | tr -d '
')" || return 1
    [[ -n "$chunk" ]] || continue
    if [[ "$lowercase" == "true" ]]; then
      chunk="$(printf '%s' "$chunk" | tr '[:upper:]' '[:lower:]')"
    fi
    chunk="$(printf '%s' "$chunk" | tr -cd "$charset")"
    [[ -n "$chunk" ]] || continue
    value+="$chunk"
  done

  (( ${#value} >= length )) || return 1
  printf '%s
' "${value:0:length}"
}

generate_strong_secret() {
  generate_random_fixed 28 'A-Za-z0-9'
}

generate_uuid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
    return 0
  fi
  openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'
}
