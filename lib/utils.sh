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
